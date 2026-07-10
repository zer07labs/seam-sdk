"""Live management-plane tests — GDPR erasure preview→confirm→erase + bearer auth.

The admin surface (`SeamAdmin`) is served on a SEPARATE management listener (`SEAM_GRPC_MGMT_LISTEN`) from
the data plane. These tests spawn a `seam-grpc` binary with BOTH planes up and exercise the erasure flow
against the enrolled demo tenant. Env-gated exactly like `test_integration.py`:
  * ``SEAM_GRPC_BIN`` — path to a ``seam-grpc`` binary the test spawns (both planes on distinct ports), or
  * skipped otherwise (a running server can't be assumed to have the mgmt plane bound).
"""

import os
import socket
import subprocess
import time

import grpc
import pytest

from seam_sdk import (
    Agent,
    SeamAdminClient,
    SeamClient,
    SeamRpcError,
    UnauthenticatedError,
)

TENANT = "design-partner"  # the demo tenant SEAM_DEV_INSECURE enrolls the [42;32] agent under


def _wait(port: int, timeout: float = 8.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.1).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"server never came up on {port}")


def _spawn(data_port: int, mgmt_port: int, token: str | None = None):
    binary = os.environ.get("SEAM_GRPC_BIN")
    if not binary:
        pytest.skip("set SEAM_GRPC_BIN to run the live management-plane test")
    env = {
        **os.environ,
        "SEAM_GRPC_LISTEN": f"127.0.0.1:{data_port}",
        # The mgmt plane only binds when this is set; SEAM_DEV_INSECURE lets it bind unauthenticated
        # (unless SEAM_MGMT_TOKEN is also given, which then requires a bearer token on every call).
        "SEAM_GRPC_MGMT_LISTEN": f"127.0.0.1:{mgmt_port}",
        "SEAM_DEV_INSECURE": "1",
    }
    if token:
        env["SEAM_MGMT_TOKEN"] = token
    proc = subprocess.Popen(
        [binary], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    _wait(data_port)
    _wait(mgmt_port)
    return proc


def _seal_one(data_addr: str) -> tuple[str, str]:
    """Seal a decision as the demo agent; return (agent_aid, decision_id)."""
    client = SeamClient.connect(data_addr)
    agent = Agent(bytes([42] * 32))
    dec = client.run_decision(
        agent,
        "admin-seal",
        ["fraud-v3", "risk-v2"],
        [("fraud-v3", "BLOCK"), ("risk-v2", "BLOCK")],
    )
    assert dec.outcome == "Resolved"
    return agent.aid, dec.decision_id


def test_erasure_preview_confirm_erase():
    proc = _spawn(8101, 8102)
    try:
        subject, decision_id = _seal_one("127.0.0.1:8101")
        admin = SeamAdminClient.connect(
            "127.0.0.1:8102"
        )  # unauthenticated dev mgmt plane

        # Preview is non-destructive and lists the sealed record under would_erase.
        preview = admin.preview_erasure(TENANT, subject)
        assert decision_id in preview.would_erase
        assert decision_id not in preview.already_erased

        # An empty tenant scope is refused (audit P0.1: erasure never crosses tenants). The error is a
        # typed SeamRpcError — and, being non-breaking, still a grpc.RpcError.
        with pytest.raises(SeamRpcError) as ei:
            admin.erase_subject("", subject, len(preview.would_erase))
        assert isinstance(ei.value, grpc.RpcError)

        # The wrong confirm_count is refused (must equal the preview's would_erase count).
        with pytest.raises(SeamRpcError):
            admin.erase_subject(TENANT, subject, len(preview.would_erase) + 1)

        # The right count returns a populated, signed certificate.
        cert = admin.erase_subject(TENANT, subject, len(preview.would_erase))
        assert cert.subject == subject
        assert decision_id in cert.erased
        assert cert.signature  # signed, chain-anchored
        assert cert.issuer_aid

        # A second preview now shows it already erased — no new destruction.
        after = admin.preview_erasure(TENANT, subject)
        assert decision_id in after.already_erased
        assert decision_id not in after.would_erase
    finally:
        proc.terminate()


def test_erase_subject_confirmed_convenience():
    proc = _spawn(8105, 8106)
    try:
        subject, decision_id = _seal_one("127.0.0.1:8105")
        admin = SeamAdminClient.connect("127.0.0.1:8106")
        cert = admin.erase_subject_confirmed(TENANT, subject)
        assert decision_id in cert.erased
    finally:
        proc.terminate()


def test_management_bearer_auth():
    token = "s3cr3t-operator-token"
    proc = _spawn(8103, 8104, token=token)
    try:
        subject, _ = _seal_one("127.0.0.1:8103")

        # No token → UNAUTHENTICATED, surfaced as the typed UnauthenticatedError (still exposing .code()).
        anon = SeamAdminClient.connect("127.0.0.1:8104")
        with pytest.raises(UnauthenticatedError) as ei:
            anon.preview_erasure(TENANT, subject)
        assert ei.value.code() == grpc.StatusCode.UNAUTHENTICATED

        # Wrong token → UNAUTHENTICATED.
        wrong = SeamAdminClient.connect("127.0.0.1:8104", token="nope")
        with pytest.raises(UnauthenticatedError):
            wrong.preview_erasure(TENANT, subject)

        # Right token → succeeds.
        ok = SeamAdminClient.connect("127.0.0.1:8104", token=token)
        preview = ok.preview_erasure(TENANT, subject)
        assert isinstance(list(preview.would_erase), list)
    finally:
        proc.terminate()


def test_stream_events_drains_decision_sealed():
    """Sealing a decision emits a DECISION_SEALED event to the seam-event.v1 outbox; drain mode
    (follow=False) streams the current backlog and closes."""
    proc = _spawn(8107, 8108)
    try:
        _, decision_id = _seal_one("127.0.0.1:8107")
        admin = SeamAdminClient.connect("127.0.0.1:8108")

        events = list(admin.stream_events(from_seq=0, follow=False))
        assert events, "expected at least the DECISION_SEALED event"
        sealed = [e for e in events if e.kind == "DECISION_SEALED"]
        assert sealed, f"kinds seen: {[e.kind for e in events]}"
        assert any(e.decision_id == decision_id for e in sealed)
        assert sealed[0].HasField("payload")
    finally:
        proc.terminate()
