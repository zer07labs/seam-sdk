"""Phase 6 — the streamed-event authenticity surface.

Server-free unit tests over `verify_streamed_record_digest` and `KNOWN_KINDS`, driven from the runtime's
`record_digest_v2` KAT (a real digest over real columns), plus an env-gated live check that a streamed
SESSION_LIFECYCLE carries its payload and a streamed v2 DECISION_SEALED recomputes.
"""

from __future__ import annotations

import json
import os
import pathlib
import socket
import subprocess
import time

import pytest

import seam_sdk.client  # noqa: F401 — wires the generated stubs onto sys.path
from seam.api.v1 import seam_pb2 as pb  # noqa: E402
from seam_sdk import KNOWN_KINDS, SeamClient, verify_streamed_record_digest  # noqa: E402
from seam_sdk.admin import SeamAdminClient  # noqa: E402

VECTORS = json.loads(
    (pathlib.Path(__file__).parents[2] / "conformance" / "vectors.json").read_text()
)


def _kat_event() -> pb.SeamEvent:
    """A DECISION_SEALED event whose payload + wire digest are the runtime record_digest_v2 KAT."""
    v = VECTORS["record_digest_v2"]
    i = v["inputs"]
    payload = pb.DecisionSealed(
        decision_id=i["decision_id"],
        tenant=i["tenant"],
        namespace=i["namespace"],
        outcome=i["outcome"],
        sealed_at=i["sealed_at"],
        schema_version=i["schema_version"],
        ciphertext_digest=bytes.fromhex(i["ciphertext_digest_hex"]),
    )
    # mode is Some in the KAT; policy_version / supersedes are None (left unset → HasField False).
    payload.mode = i["mode"]
    return pb.SeamEvent(
        kind="DECISION_SEALED",
        payload=payload,
        digest=bytes.fromhex(v["digest_hex"]),
    )


def test_known_kinds_includes_the_a14_kinds():
    assert "SESSION_LIFECYCLE" in KNOWN_KINDS
    assert "CHAIN_HEAD_ATTESTATION" in KNOWN_KINDS
    assert len(KNOWN_KINDS) == 8


def test_streamed_record_digest_matches_for_a_genuine_event():
    assert verify_streamed_record_digest(_kat_event()) is True


def test_streamed_record_digest_catches_a_payload_rewrite():
    ev = _kat_event()
    ev.payload.outcome = "Expired"  # rewrite a structural column, keep the wire digest
    assert verify_streamed_record_digest(ev) is False


def test_streamed_record_digest_refuses_a_stripped_ciphertext_digest():
    ev = _kat_event()
    ev.payload.ClearField("ciphertext_digest")  # a v2 record with tag 10 stripped
    assert verify_streamed_record_digest(ev) is False


def test_streamed_record_digest_rejects_non_v2_and_non_sealed():
    v1 = _kat_event()
    v1.payload.schema_version = 1
    with pytest.raises(ValueError):
        verify_streamed_record_digest(v1)
    other = pb.SeamEvent(kind="SESSION_LIFECYCLE")
    with pytest.raises(ValueError):
        verify_streamed_record_digest(other)


# ── Live: a streamed SESSION_LIFECYCLE carries its payload; a streamed v2 DECISION_SEALED recomputes ──


def _wait(port: int, timeout: float = 8.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.1).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"server never came up on {port}")


@pytest.fixture
def dual_plane():
    binary = os.environ.get("SEAM_GRPC_BIN")
    if not binary:
        pytest.skip("set SEAM_GRPC_BIN to run the live streamed-decode test")
    data_port, mgmt_port = 8113, 8114
    proc = subprocess.Popen(
        [binary],
        env={
            **os.environ,
            "SEAM_GRPC_LISTEN": f"127.0.0.1:{data_port}",
            "SEAM_GRPC_MGMT_LISTEN": f"127.0.0.1:{mgmt_port}",
            "SEAM_DEV_INSECURE": "1",
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait(data_port)
        _wait(mgmt_port)
        yield f"127.0.0.1:{data_port}", f"127.0.0.1:{mgmt_port}"
    finally:
        proc.terminate()


def test_streamed_events_carry_a14_payloads_live(dual_plane):
    from seam_sdk import Agent

    data_addr, mgmt_addr = dual_plane
    data = SeamClient.connect(data_addr)
    admin = SeamAdminClient.connect(mgmt_addr)
    agent = Agent(bytes([42] * 32))

    # An interactive open emits SESSION_LIFECYCLE (CP-09); a one-shot decision seals a v2 DECISION_SEALED.
    data.open_session(agent, "p6-live", ["lead", "peer"])
    dec = data.run_decision(
        agent,
        "p6",
        ["fraud-v3", "risk-v2"],
        [("fraud-v3", "BLOCK"), ("risk-v2", "BLOCK")],
    )
    assert dec.outcome == "Resolved"

    lifecycle = None
    sealed = None
    kinds_seen = set()
    for ev in admin.stream_events(follow=False, ack=False):
        kinds_seen.add(
            ev.kind
        )  # every kind decodes; an unknown one would still iterate, never error
        if ev.kind == "SESSION_LIFECYCLE":
            lifecycle = ev
        elif ev.kind == "DECISION_SEALED" and ev.payload.decision_id == dec.decision_id:
            sealed = ev

    # Every kind seen is one the SDK knows (no opaque surprises in this stream), and the tolerant loop above
    # never errored on any of them.
    assert kinds_seen <= KNOWN_KINDS, f"unexpected kinds: {kinds_seen - KNOWN_KINDS}"

    # CP-09: the SESSION_LIFECYCLE payload (tag 21) is exposed, not kind-only.
    assert lifecycle is not None, "the interactive open must emit a SESSION_LIFECYCLE"
    assert lifecycle.session_lifecycle.phase == "opened"
    assert lifecycle.session_lifecycle.opened_at_millis > 0

    # §A14: the v2 DECISION_SEALED payload carries ciphertext_digest (tag 10), and it recomputes.
    assert sealed is not None, "the sealed decision must appear on the stream"
    assert sealed.payload.schema_version == 2
    assert len(sealed.payload.ciphertext_digest) == 32
    assert verify_streamed_record_digest(sealed) is True
