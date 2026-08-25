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

from seam_sdk._gen.seam.event.v1 import seam_event_pb2 as evpb
from seam_sdk import KNOWN_KINDS, SeamClient, verify_streamed_record_digest  # noqa: E402
from seam_sdk.crypto import RecordDigestStripError  # noqa: E402
from seam_sdk.admin import SeamAdminClient  # noqa: E402

VECTORS = json.loads(
    (pathlib.Path(__file__).parents[2] / "conformance" / "vectors.json").read_text()
)


def _kat_event() -> evpb.SeamEvent:
    """A DECISION_SEALED event whose payload + wire digest are the runtime record_digest_v2 KAT."""
    v = VECTORS["record_digest_v2"]
    i = v["inputs"]
    payload = evpb.DecisionSealed(
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
    return evpb.SeamEvent(
        kind="DECISION_SEALED",
        payload=payload,
        digest=bytes.fromhex(v["digest_hex"]),
    )


def test_known_kinds_includes_the_a14_kinds():
    assert "SESSION_LIFECYCLE" in KNOWN_KINDS
    assert "CHAIN_HEAD_ATTESTATION" in KNOWN_KINDS
    assert (
        "AUTHORIZE_EVALUATED" in KNOWN_KINDS
    )  # tag 23: one row per advisory Authorize evaluation
    assert len(KNOWN_KINDS) == 9


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


def test_streamed_record_digest_rejects_a_pre_v2_record_and_a_non_sealed_event():
    v1 = _kat_event()
    v1.payload.schema_version = 1
    with pytest.raises(ValueError):
        verify_streamed_record_digest(v1)
    other = evpb.SeamEvent(kind="SESSION_LIFECYCLE")
    with pytest.raises(ValueError):
        verify_streamed_record_digest(other)


def test_streamed_record_digest_rejects_a_future_schema_version():
    """A v4+ record is a framing this SDK does not know. Recomputing it with the v3 domain tag would
    report a spurious False on a GENUINE record — a tamper verdict fabricated by version skew — so it
    must refuse loudly like v1 does, not answer. This test read `= 3` until the v3 arm landed; the
    boundary moves with the SDK's knowledge, which is the whole point of asserting it."""
    v4 = _kat_event()
    v4.payload.schema_version = 4
    with pytest.raises(ValueError, match="not stream-recomputable"):
        verify_streamed_record_digest(v4)


# ── v3: the streamed arm, its strip refusals, and the tag-13 absence that must NOT be one ──


def _kat_v3_event(vector: str = "record_digest_v3") -> evpb.SeamEvent:
    """A v3 DECISION_SEALED whose payload + wire digest are a committed record_digest_v3 vector."""
    v = VECTORS[vector]
    i = v["inputs"]
    payload = evpb.DecisionSealed(
        decision_id=i["decision_id"],
        tenant=i["tenant"],
        namespace=i["namespace"],
        outcome=i["outcome"],
        sealed_at=i["sealed_at"],
        schema_version=i["schema_version"],
        ciphertext_digest=bytes.fromhex(i["ciphertext_digest_hex"]),
        context_digest=bytes.fromhex(i["context_digest_hex"]),
        participation_digest=bytes.fromhex(i["participation_digest_hex"]),
    )
    if i["mode"] is not None:
        payload.mode = i["mode"]
    if i["policy_version"] is not None:
        payload.policy_version = i["policy_version"]
    if i["supersedes"] is not None:
        payload.supersedes = i["supersedes"]
    if i["policy_rules_digest_hex"] is not None:
        payload.policy_rules_digest = bytes.fromhex(i["policy_rules_digest_hex"])
    return evpb.SeamEvent(
        kind="DECISION_SEALED",
        payload=payload,
        digest=bytes.fromhex(v["digest_hex"]),
    )


def test_streamed_v3_matches_for_a_genuine_event():
    assert verify_streamed_record_digest(_kat_v3_event()) is True


def test_streamed_v3_catches_a_payload_rewrite():
    ev = _kat_v3_event()
    ev.payload.outcome = "Expired"
    assert verify_streamed_record_digest(ev) is False


def test_streamed_v3_binds_the_two_new_digests():
    """The v3 arm must actually feed tags 11 and 12 into the preimage. Perturbing either has to change
    the verdict — otherwise the arm could be quietly computing v2's formula and still pass the green
    case, since v2's columns are a subset of v3's."""
    for field in ("context_digest", "participation_digest"):
        ev = _kat_v3_event()
        perturbed = bytearray(getattr(ev.payload, field))
        perturbed[0] ^= 0x01
        setattr(ev.payload, field, bytes(perturbed))
        assert verify_streamed_record_digest(ev) is False, field


@pytest.mark.parametrize(
    "field,tag", [("context_digest", 11), ("participation_digest", 12)]
)
def test_streamed_v3_refuses_a_stripped_mandatory_digest(field, tag):
    """Absent tag 11/12 on a v3 payload is a strip attack. It must RAISE — distinctly from the False a
    mismatch returns — so an operator can tell "someone removed a field" from "someone rewrote one"."""
    ev = _kat_v3_event()
    ev.payload.ClearField(field)
    with pytest.raises(RecordDigestStripError) as excinfo:
        verify_streamed_record_digest(ev)
    assert excinfo.value.field == field
    assert excinfo.value.wire_tag == tag


@pytest.mark.parametrize("field", ["context_digest", "participation_digest"])
def test_streamed_v3_refuses_an_explicitly_encoded_empty_mandatory_digest(field):
    """`len == 0` is absence however the bytes arose. proto3 obliges a decoder to ACCEPT an explicitly
    encoded zero-length field, so a hostile producer can put one on the wire even though a conforming
    one never will — it must land on the same refusal as an omitted field, not slip past it."""
    ev = _kat_v3_event()
    # Append an explicit zero-length occurrence of the field; proto3 is last-wins, so this overwrites
    # the genuine 32 bytes with empty on decode. Tag 11 -> key 0x5a, tag 12 -> key 0x62.
    key = {"context_digest": b"\x5a\x00", "participation_digest": b"\x62\x00"}[field]
    # The payload is a nested message (tag 22 on SeamEvent), so splice into the payload's own bytes.
    payload_raw = ev.payload.SerializeToString() + key
    tampered = evpb.SeamEvent()
    tampered.CopyFrom(ev)
    tampered.payload.CopyFrom(evpb.DecisionSealed.FromString(payload_raw))
    assert len(getattr(tampered.payload, field)) == 0  # the splice landed
    with pytest.raises(RecordDigestStripError):
        verify_streamed_record_digest(tampered)


@pytest.mark.parametrize("field", ["context_digest", "participation_digest"])
def test_streamed_v3_refuses_a_wrong_length_mandatory_digest(field):
    """A present-but-31-byte digest is malformed, not a mismatch. Framing it would produce a
    well-formed digest over a value no sealer ever wrote."""
    ev = _kat_v3_event()
    setattr(ev.payload, field, bytes(getattr(ev.payload, field))[:31])
    with pytest.raises(RecordDigestStripError):
        verify_streamed_record_digest(ev)


def test_streamed_v3_verifies_green_with_no_policy_rules_digest():
    """Absent tag 13 is LEGITIMATE — no policy bound, today's common case — and frames as opt(None).
    Passing the decoded empty bytes straight through would frame opt(Some(b"")), five bytes where the
    sealer wrote one, and report a mismatch on a genuine record."""
    assert (
        verify_streamed_record_digest(_kat_v3_event("record_digest_v3_absent_policy"))
        is True
    )


def test_streamed_v3_verifies_green_with_an_explicitly_encoded_empty_policy_rules_digest():
    """The tag-13 counterpart of the tag-11/12 splice above, and the case the `len == 0` rule exists
    for. A hostile producer can put `0x6a 0x00` on the wire; proto3 obliges the decoder to accept it.
    It must verify GREEN as opt(None) — identical to omission — rather than framing opt(Some(b"")).

    At the decoded-message layer this is provably the same input as omission (both yield `b""`), which
    is exactly the claim worth pinning: the test exists to prove the two forms cannot diverge, not to
    exercise a second code path."""
    ev = _kat_v3_event("record_digest_v3_absent_policy")
    payload_raw = ev.payload.SerializeToString() + b"\x6a\x00"  # tag 13, length 0
    tampered = evpb.SeamEvent()
    tampered.CopyFrom(ev)
    tampered.payload.CopyFrom(evpb.DecisionSealed.FromString(payload_raw))
    assert len(tampered.payload.policy_rules_digest) == 0  # the splice landed
    assert verify_streamed_record_digest(tampered) is True


def test_streamed_v3_absent_and_present_policy_rules_are_different_digests():
    """The guard on the guard: the two vectors must not coincidentally share a digest, or the test
    above would pass under a formula that ignores tag 13 entirely."""
    assert (
        VECTORS["record_digest_v3"]["digest_hex"]
        != VECTORS["record_digest_v3_absent_policy"]["digest_hex"]
    )


def test_streamed_v3_refuses_a_stripped_ciphertext_digest_as_false_not_a_raise():
    """Tag 10 is the older rule and keeps its older shape. The spec makes a tag-10 strip a REFUSE for
    every schema_version >= 2 — a failing verdict, which for a boolean helper is False — but attaches
    the distinct-reporting requirement only to tags 11/12. So this must NOT become a strip raise."""
    ev = _kat_v3_event()
    ev.payload.ClearField("ciphertext_digest")
    assert verify_streamed_record_digest(ev) is False


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
