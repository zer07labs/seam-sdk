"""Management-plane tests — server-free wrapper shapes, plus live erasure preview→confirm→erase + bearer auth.

The admin surface (`SeamAdmin`) is served on a SEPARATE management listener (`SEAM_GRPC_MGMT_LISTEN`) from
the data plane. The unit section runs an in-process recording servicer (no binary needed); the live tests
spawn a `seam-grpc` binary with BOTH planes up and exercise the erasure flow against the enrolled demo
tenant. The live tests are env-gated exactly like `test_integration.py`:
  * ``SEAM_GRPC_BIN`` — path to a ``seam-grpc`` binary the test spawns (both planes on distinct ports), or
  * skipped otherwise (a running server can't be assumed to have the mgmt plane bound).
"""

import contextlib
from concurrent import futures

import grpc
import pytest

from live_server import spawn_server

from seam_sdk import (
    Agent,
    SeamAdminClient,
    SeamClient,
    SeamRpcError,
    UnauthenticatedError,
)
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc
from seam_sdk._gen.seam.event.v1 import seam_event_pb2 as ev

TENANT = "design-partner"  # the demo tenant SEAM_DEV_INSECURE enrolls the [42;32] agent under

# ── Unit: the party/grant wrapper shapes, server-free ────────────────────────────────────────────


class RecordingAdmin(rpc.SeamAdminServicer):
    """Records each governance request; answers the minimal well-formed response."""

    def __init__(self):
        self.removed: pb.RemovePartyRequest | None = None
        self.placed: pb.PlaceGrantRequest | None = None
        self.revoked: pb.RevokeGrantRequest | None = None
        self.grants: list[pb.GrantView] = []
        self.erase_requests: list[pb.ErasureRequest] = []

    def RemoveParty(self, request, context):  # noqa: N802
        self.removed = request
        return pb.Empty()

    def PlaceGrant(self, request, context):  # noqa: N802
        self.placed = request
        return pb.Empty()

    def RevokeGrant(self, request, context):  # noqa: N802
        self.revoked = request
        return pb.Empty()

    def ListGrants(self, request, context):  # noqa: N802
        return pb.ListGrantsResponse(grants=self.grants)

    def PreviewErasure(self, request, context):  # noqa: N802
        return pb.ErasurePreview()

    def EraseSubject(self, request, context):  # noqa: N802
        self.erase_requests.append(request)
        return ev.ErasureCertificate(subject=request.subject)


@pytest.fixture
def recording_admin():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    servicer = RecordingAdmin()
    rpc.add_SeamAdminServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    yield servicer, f"127.0.0.1:{port}"
    server.stop(None)


def test_remove_party_sends_the_party_id_and_returns_none(recording_admin):
    servicer, addr = recording_admin
    with SeamAdminClient.connect(addr) as admin:
        assert admin.remove_party("bank-A") is None
    assert servicer.removed.party_id == "bank-A"


def test_place_grant_sends_every_field_and_returns_none(recording_admin):
    servicer, addr = recording_admin
    with SeamAdminClient.connect(addr) as admin:
        assert (
            admin.place_grant("acme", "ns-a", "ns-b", "op@acme", 4102444800000) is None
        )
    assert servicer.placed.tenant == "acme"
    assert servicer.placed.from_ns == "ns-a"
    assert servicer.placed.to_ns == "ns-b"
    assert servicer.placed.grantor == "op@acme"
    assert servicer.placed.expires_at == 4102444800000


def test_revoke_grant_sends_every_field_and_returns_none(recording_admin):
    servicer, addr = recording_admin
    with SeamAdminClient.connect(addr) as admin:
        assert admin.revoke_grant("acme", "ns-a", "ns-b", "op@acme") is None
    assert servicer.revoked.tenant == "acme"
    assert servicer.revoked.from_ns == "ns-a"
    assert servicer.revoked.to_ns == "ns-b"
    assert servicer.revoked.revoker == "op@acme"


def test_list_grants_returns_the_stored_views_as_a_list(recording_admin):
    servicer, addr = recording_admin
    servicer.grants = [
        pb.GrantView(
            tenant="acme",
            from_ns="ns-a",
            to_ns="ns-b",
            grantor="op@acme",
            expires_at=4102444800000,
        )
    ]
    with SeamAdminClient.connect(addr) as admin:
        grants = admin.list_grants()
    assert isinstance(grants, list)
    assert len(grants) == 1
    assert grants[0].tenant == "acme" and grants[0].to_ns == "ns-b"


def test_list_grants_empty_is_an_empty_list(recording_admin):
    _, addr = recording_admin
    with SeamAdminClient.connect(addr) as admin:
        assert admin.list_grants() == []


def test_erase_subject_now_millis_absent_by_default(recording_admin):
    """Matches ``enforce_retention``'s presence semantics: omitted ⇒ the field is never set on the
    wire, so the server falls back to its own clock rather than an explicit (and possibly stale) 0."""
    servicer, addr = recording_admin
    with SeamAdminClient.connect(addr) as admin:
        admin.erase_subject("acme", "cust-1", 0)
    assert not servicer.erase_requests[-1].HasField("now_millis")


def test_erase_subject_now_millis_set_when_given(recording_admin):
    servicer, addr = recording_admin
    with SeamAdminClient.connect(addr) as admin:
        admin.erase_subject("acme", "cust-1", 0, now_millis=1_700_000_000_000)
    req = servicer.erase_requests[-1]
    assert req.HasField("now_millis")
    assert req.now_millis == 1_700_000_000_000


def test_erase_subject_confirmed_forwards_now_millis(recording_admin):
    servicer, addr = recording_admin
    with SeamAdminClient.connect(addr) as admin:
        admin.erase_subject_confirmed("acme", "cust-1", now_millis=1_700_000_000_000)
    req = servicer.erase_requests[-1]
    assert req.HasField("now_millis")
    assert req.now_millis == 1_700_000_000_000


# ── Live: erasure preview→confirm→erase + bearer auth (env-gated) ────────────────────────────────


@contextlib.contextmanager
def _spawn(log_dir, registry_snapshot: str | None = None):
    """A live seam-grpc with BOTH planes bound, on OS-allocated ports.

    Ports, readiness, teardown and log capture all belong to ``live_server.spawn_server`` — see its
    docstring for the #85 failure that consolidated them. What stays here is only what is specific to
    the management plane: the signed-snapshot env that CLOSES the plane.
    """
    from operator_token import sign_snapshot

    env_extra: dict[str, str] = {}
    if registry_snapshot:
        # Signed, not merely handed over: a trust-bearing snapshot is refused unsigned, and the
        # runtime will not boot at all. See `sign_snapshot`.
        pubkey, sig_path = sign_snapshot(registry_snapshot)
        env_extra = {
            "SEAM_REGISTRY_SNAPSHOT": registry_snapshot,
            "SEAM_REGISTRY_SNAPSHOT_SIG": sig_path,
            "SEAM_SNAPSHOT_PUBKEY": pubkey,
        }
    # The mgmt plane binds because spawn_server(mgmt=True) sets SEAM_GRPC_MGMT_LISTEN, and
    # SEAM_DEV_INSECURE lets it bind dev-open. Installing an `operator_keys` trust root via
    # SEAM_REGISTRY_SNAPSHOT instead CLOSES the plane: every request must then carry a valid
    # compact-JWS operator token (the shared SEAM_MGMT_TOKEN bearer was removed in seam-runtime
    # #175). This path is live on both pre- and post-#175 runtimes.
    with spawn_server(mgmt=True, log_dir=log_dir, env_extra=env_extra) as srv:
        yield srv


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


def test_erasure_preview_confirm_erase(tmp_path):
    with _spawn(tmp_path) as srv:
        data_port, mgmt_port = srv.data_port, srv.mgmt_port
        subject, decision_id = _seal_one(f"127.0.0.1:{data_port}")
        admin = SeamAdminClient.connect(
            f"127.0.0.1:{mgmt_port}"
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


def test_erase_subject_confirmed_convenience(tmp_path):
    with _spawn(tmp_path) as srv:
        data_port, mgmt_port = srv.data_port, srv.mgmt_port
        subject, decision_id = _seal_one(f"127.0.0.1:{data_port}")
        admin = SeamAdminClient.connect(f"127.0.0.1:{mgmt_port}")
        cert = admin.erase_subject_confirmed(TENANT, subject)
        assert decision_id in cert.erased


def test_management_operator_token_auth(tmp_path):
    """The management plane authenticates compact-JWS operator tokens against the installed `operator_keys`
    root (rt-D / CP-18d; the shared `SEAM_MGMT_TOKEN` bearer was removed in seam-runtime #175). A missing,
    malformed, or tampered token is refused; a valid one passes. Designed to hold against BOTH pre- and
    post-#175 runtimes — the operator-token path is already live, and an operator-keys-only plane closes the
    old fallback."""
    # Sibling module (pytest prepends the test dir to sys.path) — NOT `tests.operator_token`, which only
    # resolves under `python -m pytest` (cwd on path), not the CI's bare `pytest`.
    from operator_token import (
        REGISTRY_SNAPSHOT_PATH,
        mint_operator_token,
        tamper_signature,
    )

    with _spawn(tmp_path, registry_snapshot=REGISTRY_SNAPSHOT_PATH) as srv:
        mgmt_addr = srv.mgmt_addr
        # preview_erasure requires the `erasure:preview` scope (non-destructive → no jti needed).
        token = mint_operator_token(["erasure:preview"])
        subject = (
            "aid:pubkey:ed25519:zzz"  # any subject — this pins AUTH, not the erase flow
        )

        # No token → UNAUTHENTICATED, surfaced as the typed UnauthenticatedError (still exposing .code()).
        anon = SeamAdminClient.connect(mgmt_addr)
        with pytest.raises(UnauthenticatedError) as ei:
            anon.preview_erasure(TENANT, subject)
        assert ei.value.code() == grpc.StatusCode.UNAUTHENTICATED

        # A non-JWS bearer → UNAUTHENTICATED (the operator-keys-only plane refuses the old shared-bearer shape).
        wrong = SeamAdminClient.connect(mgmt_addr, token="nope")
        with pytest.raises(UnauthenticatedError):
            wrong.preview_erasure(TENANT, subject)

        # A JWS-shaped token with a corrupted signature → UNAUTHENTICATED (a hard verification failure, never
        # a downgrade to an accepted request).
        tampered = SeamAdminClient.connect(mgmt_addr, token=tamper_signature(token))
        with pytest.raises(UnauthenticatedError):
            tampered.preview_erasure(TENANT, subject)

        # A valid operator token → succeeds.
        ok = SeamAdminClient.connect(mgmt_addr, token=token)
        preview = ok.preview_erasure(TENANT, subject)
        assert isinstance(list(preview.would_erase), list)


def test_stream_events_drains_decision_sealed(tmp_path):
    """Sealing a decision emits a DECISION_SEALED event to the seam-event.v1 outbox; drain mode
    (follow=False) streams the current backlog and closes."""
    with _spawn(tmp_path) as srv:
        data_port, mgmt_port = srv.data_port, srv.mgmt_port
        _, decision_id = _seal_one(f"127.0.0.1:{data_port}")
        admin = SeamAdminClient.connect(f"127.0.0.1:{mgmt_port}")

        events = list(admin.stream_events(from_seq=0, follow=False))
        assert events, "expected at least the DECISION_SEALED event"
        sealed = [e for e in events if e.kind == "DECISION_SEALED"]
        assert sealed, f"kinds seen: {[e.kind for e in events]}"
        assert any(e.decision_id == decision_id for e in sealed)
        assert sealed[0].HasField("payload")
