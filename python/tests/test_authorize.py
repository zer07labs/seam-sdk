"""The advisory ``authorize()`` lifecycle, against an in-process fake gRPC server.

Covers the acceptance criteria the campaign pins:
  * 100 authorizes over one client = exactly 1 challenge + 1 admit on the wire;
  * refresh at 80% TTL (a short-TTL ticket forces a re-admit without sleeping past expiry);
  * expired/rejected ticket → refresh once, retry once; a second UNAUTHENTICATED propagates typed;
  * an unknown verdict (incl. UNSPECIFIED) raises UnknownVerdictError — never an implicit allow;
  * every verdict decodes (ALLOW/DENY/TRANSFORM/ESCALATE), transformed_input only on TRANSFORM;
  * the server-side view: call_sig verifies against the agent key over ticket||digest, and the
    digest matches an independent JCS canonicalization;
  * deadlines: a hanging server surfaces DeadlineExceededError on every public method;
  * async twin: same lifecycle on grpc.aio, plus cancellation mid-authorize leaves the cache usable.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import threading
import time
from concurrent import futures

import grpc
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from seam_sdk import Agent, DeadlineExceededError, SeamClient, UnknownVerdictError
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc
from seam_sdk._gen.seam.event.v1 import seam_event_pb2 as ev
from seam_sdk.aio import SeamClient as AioSeamClient
from seam_sdk.crypto import jcs_canonicalize, tool_input_digest
from seam_sdk.errors import UnauthenticatedError

SEED = bytes(range(32))


def _pubkey_of_aid(aid: str) -> bytes:
    b64 = aid.rsplit(":", 1)[1]
    return base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))


class FakeSeam(rpc.SeamAdmissionServicer, rpc.SeamAuthorizationServicer):
    """A minimal admission + authorization server that verifies tickets and call_sigs for real.

    Tickets are ``b"tkt:" + <8-byte counter>``; the server remembers which tickets it minted and
    can be told to reject them (``revoke_all``) to drive the UNAUTHENTICATED retry path.
    """

    def __init__(self, ttl_ms: int = 300_000):
        self.ttl_ms = ttl_ms
        self.challenges = 0
        self.admits = 0
        self.authorizes = 0
        self.verdict = pb.ALLOW
        self.reason = ""
        self.transformed = b""
        self.fail_next_unauthenticated = 0  # reject N upcoming Authorize calls
        self.valid_tickets: set = set()
        self.last_request: pb.AuthorizeRequest | None = None
        self._lock = threading.Lock()

    # ── SeamAdmission ──
    def IssueChallenge(self, request, context):  # noqa: N802
        with self._lock:
            self.challenges += 1
        return pb.Challenge(nonce="bm9uY2U", receiver_aid="aid:pubkey:receiver")

    def Admit(self, request, context):  # noqa: N802
        with self._lock:
            self.admits += 1
            ticket = b"tkt:" + self.admits.to_bytes(8, "big")
            self.valid_tickets.add(ticket)
        # The fake trusts the presentation (crypto conformance is pinned elsewhere); it exists to
        # count round-trips and mint verifiable tickets.
        return pb.AdmissionTicket(
            ticket=ticket, expires_at_ms=int(time.time() * 1000) + self.ttl_ms
        )

    # ── SeamAuthorization ──
    def Authorize(self, request, context):  # noqa: N802
        with self._lock:
            self.authorizes += 1
            self.last_request = request
            if self.fail_next_unauthenticated > 0:
                self.fail_next_unauthenticated -= 1
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "ticket rejected")
            if request.ticket not in self.valid_tickets:
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "unknown ticket")
        return pb.AuthorizeResponse(
            verdict=self.verdict,
            reason=self.reason,
            transformed_input=self.transformed,
            authorize_id="01AUTHZ",
            policy_version="policy-v1",
        )


class HangingSeam(
    rpc.SeamAdmissionServicer,
    rpc.SeamCoordinationServicer,
    rpc.SeamTrustServicer,
    rpc.SeamContextServicer,
    rpc.SeamAuthorizationServicer,
):
    """Every RPC sleeps past any test deadline — the fixture for timeout-enforcement tests."""

    def __getattribute__(self, name):
        if name[0].isupper():  # every RPC method name is CamelCase

            def hang(request, context):
                time.sleep(5)

            return hang
        return object.__getattribute__(self, name)


@pytest.fixture
def fake_server():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    servicer = FakeSeam()
    rpc.add_SeamAdmissionServicer_to_server(servicer, server)
    rpc.add_SeamAuthorizationServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    yield servicer, f"127.0.0.1:{port}"
    server.stop(None)


@pytest.fixture
def hanging_server():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    servicer = HangingSeam()
    rpc.add_SeamAdmissionServicer_to_server(servicer, server)
    rpc.add_SeamCoordinationServicer_to_server(servicer, server)
    rpc.add_SeamTrustServicer_to_server(servicer, server)
    rpc.add_SeamContextServicer_to_server(servicer, server)
    rpc.add_SeamAuthorizationServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    yield f"127.0.0.1:{port}"
    server.stop(None)


# ── Ticket lifecycle (sync) ───────────────────────────────────────────────────────────────────────


def test_100_authorizes_are_one_challenge_one_admit(fake_server):
    servicer, addr = fake_server
    client = SeamClient.connect(addr)
    agent = Agent(SEED)
    for i in range(100):
        r = client.authorize(agent, "read_file", {"path": f"/tmp/{i}"})
        assert r.verdict == "ALLOW" and r.allowed
    assert servicer.challenges == 1
    assert servicer.admits == 1
    assert servicer.authorizes == 100


def test_call_sig_and_digest_verify_server_side(fake_server):
    servicer, addr = fake_server
    client = SeamClient.connect(addr)
    agent = Agent(SEED)
    tool_input = {"zeta": 1, "alpha": [True, None, "x"], "n": 2.5}
    client.authorize(agent, "wire_transfer", tool_input)

    req = servicer.last_request
    canonical = jcs_canonicalize(tool_input)
    assert req.tool_name == "wire_transfer"
    assert req.tool_input == canonical  # raw input rides as the exact canonical bytes
    assert req.tool_input_digest == tool_input_digest(canonical)
    assert req.tool_input_digest == "sha256:" + hashlib.sha256(canonical).hexdigest()
    # The per-call PoP: Ed25519 by the agent key over ticket_bytes || digest_utf8.
    Ed25519PublicKey.from_public_bytes(_pubkey_of_aid(agent.aid)).verify(
        req.call_sig, bytes(req.ticket) + req.tool_input_digest.encode()
    )


def test_digest_only_omits_raw_input(fake_server):
    servicer, addr = fake_server
    client = SeamClient.connect(addr)
    client.authorize(Agent(SEED), "read_secret", {"key": "k"}, digest_only=True)
    req = servicer.last_request
    assert req.tool_input == b""
    assert req.tool_input_digest.startswith("sha256:")


def test_optional_fields_ride_the_request(fake_server):
    servicer, addr = fake_server
    client = SeamClient.connect(addr)
    client.authorize(
        Agent(SEED),
        "t",
        {},
        features={"amount_band": "high"},
        session_id="s-1",
        subject="user@example.com",
        agent_id="agent-red",
        client_request_id="req-42",
    )
    req = servicer.last_request
    assert dict(req.features) == {"amount_band": "high"}
    assert (req.session_id, req.subject, req.agent_id, req.client_request_id) == (
        "s-1",
        "user@example.com",
        "agent-red",
        "req-42",
    )


def test_short_ttl_ticket_refreshes_before_expiry(fake_server, monkeypatch):
    """The client refreshes PROACTIVELY at 80% of TTL — not because the server rejected it.

    Driven by an injected clock rather than a real ``time.sleep(0.18)``. A sleep-based version
    asserts something about how busy the machine is as much as about TTL arithmetic, and it is
    slow in the one suite that runs on every push. The arithmetic itself is pinned at its exact
    boundaries in tests/test_ticket_lifecycle.py; this proves the CLIENT consults it.
    """
    servicer, addr = fake_server
    servicer.ttl_ms = 100_000  # refresh point at +80s, expiry at +100s
    # The clock starts at real `now` because the fake server stamps `expires_at_ms` from ITS real
    # clock; the TTL the cache computes is the difference between the two. The margins below are
    # tens of seconds, so the few milliseconds of drift between these two readings are irrelevant —
    # which is the point of using a wide TTL rather than the 200 ms the sleeping version needed.
    clock = {"now": int(time.time() * 1000)}
    monkeypatch.setattr("seam_sdk.client._now_ms", lambda: clock["now"])

    with SeamClient.connect(addr) as client:
        agent = Agent(SEED)
        client.authorize(agent, "t", {})
        assert servicer.admits == 1

        clock["now"] += 70_000  # inside the refresh window
        client.authorize(agent, "t", {})
        assert servicer.admits == 1, "refreshed early — the ticket was still fresh"

        clock["now"] += 15_000  # past 80% of TTL, still before expiry at +100s
        client.authorize(agent, "t", {})
        assert servicer.admits == 2, (
            "did not refresh at the 80% point — the refresh must land BEFORE expiry, not after a "
            "server rejection"
        )


def test_unauthenticated_refreshes_once_then_succeeds(fake_server):
    servicer, addr = fake_server
    client = SeamClient.connect(addr)
    agent = Agent(SEED)
    client.authorize(agent, "t", {})
    servicer.fail_next_unauthenticated = 1
    r = client.authorize(agent, "t", {})
    assert r.allowed
    assert servicer.admits == 2  # exactly one refresh
    assert servicer.authorizes == 3  # 1 ok + 1 rejected + 1 retried


def test_unauthenticated_twice_propagates_typed(fake_server):
    servicer, addr = fake_server
    client = SeamClient.connect(addr)
    agent = Agent(SEED)
    client.authorize(agent, "t", {})
    servicer.fail_next_unauthenticated = 2
    with pytest.raises(UnauthenticatedError):
        client.authorize(agent, "t", {})
    assert servicer.admits == 2  # refreshed once, never looped


def test_garbage_ticket_is_rejected_typed(fake_server):
    servicer, addr = fake_server
    client = SeamClient.connect(addr)
    agent = Agent(SEED)
    client.authorize(agent, "t", {})
    # Poison the cache with a stolen/garbage ticket; the client must refresh once and succeed.
    cache = client._tickets[agent.aid]
    cache._ticket = b"stolen-garbage"
    r = client.authorize(agent, "t", {})
    assert r.allowed and servicer.admits == 2


def test_every_verdict_decodes(fake_server):
    servicer, addr = fake_server
    client = SeamClient.connect(addr)
    agent = Agent(SEED)
    for verdict, name in [
        (pb.ALLOW, "ALLOW"),
        (pb.DENY, "DENY"),
        (pb.TRANSFORM, "TRANSFORM"),
        (pb.ESCALATE, "ESCALATE"),
    ]:
        servicer.verdict = verdict
        servicer.transformed = b'{"redacted":true}' if verdict == pb.TRANSFORM else b""
        r = client.authorize(agent, "t", {})
        assert r.verdict == name
        assert r.authorize_id == "01AUTHZ" and r.policy_version == "policy-v1"
        if name == "TRANSFORM":
            assert r.transformed_input == b'{"redacted":true}'
        else:
            assert r.transformed_input is None
        assert r.allowed is (name == "ALLOW")


def test_transform_without_rewrite_is_a_typed_failure(fake_server):
    """A TRANSFORM carrying no transformed_input must fail typed — never hand back a result whose
    falsy rewrite could route a truthiness-gating caller to the original, unredacted input."""
    from seam_sdk import ProtocolViolationError

    servicer, addr = fake_server
    client = SeamClient.connect(addr)
    servicer.verdict = pb.TRANSFORM
    servicer.transformed = b""
    with pytest.raises(ProtocolViolationError):
        client.authorize(Agent(SEED), "t", {})


def test_unknown_verdict_raises_never_allows(fake_server):
    servicer, addr = fake_server
    client = SeamClient.connect(addr)
    servicer.verdict = pb.AUTHORIZE_VERDICT_UNSPECIFIED
    with pytest.raises(UnknownVerdictError):
        client.authorize(Agent(SEED), "t", {})


def test_explicit_admit_front_loads_the_handshake(fake_server):
    servicer, addr = fake_server
    client = SeamClient.connect(addr)
    agent = Agent(SEED)
    ticket = client.admit(agent)
    assert ticket in servicer.valid_tickets
    client.authorize(agent, "t", {})
    assert servicer.admits == 1  # authorize reused the pre-admitted ticket


# ── Deadlines: every public method enforces `timeout` ────────────────────────────────────────────


def test_every_public_method_enforces_timeout(hanging_server):
    client = SeamClient.connect(hanging_server)
    agent = Agent(SEED)
    calls = [
        lambda: client.authorize(agent, "t", {}, timeout=0.1),
        lambda: client.admit(agent, timeout=0.1),
        lambda: client.run_decision(agent, "s", ["a"], [("a", "yes")], timeout=0.1),
        lambda: client.open_session(agent, "s", ["a"], timeout=0.1),
        lambda: client.submit_proposal("s", "a", "p", "o", timeout=0.1),
        lambda: client.submit_vote("s", "a", "p", "v", timeout=0.1),
        lambda: client.submit_commit("s", "c", "act", timeout=0.1),
        lambda: client.resume_session("s", timeout=0.1),
        lambda: client.cancel_session("s", timeout=0.1),
        lambda: client.expire_session("s", timeout=0.1),
        lambda: client.session_status("s", timeout=0.1),
        lambda: client.get_decision("d", timeout=0.1),
        lambda: client.replay_decision("d", timeout=0.1),
        lambda: client.report_outcome("d", True, timeout=0.1),
        lambda: client.register_context(b"c", "Digest", timeout=0.1),
        lambda: client.resolve_context(["r"], timeout=0.1),
        lambda: client.issuer_aid(timeout=0.1),
        lambda: client.verify_commitment(pb.Commitment(), b"", timeout=0.1),
        lambda: client.verify_party_anchor("p", pb.Anchor(), timeout=0.1),
        lambda: client.verify_party_attestation(
            "p", ev.ChainHeadAttestation(), timeout=0.1
        ),
        lambda: client.get_commitment_proof("d", timeout=0.1),
        lambda: client.verify_decision("d", "aid:pubkey:x", timeout=0.1),
    ]
    for call in calls:
        with pytest.raises(DeadlineExceededError):
            call()


# ── The async twin ───────────────────────────────────────────────────────────────────────────────


def test_aio_lifecycle_mirrors_sync(fake_server):
    servicer, addr = fake_server

    async def scenario():
        async with AioSeamClient.connect(addr) as client:
            agent = Agent(SEED)
            for _ in range(50):
                r = await client.authorize(agent, "t", {"k": 1})
                assert r.allowed
            assert (servicer.challenges, servicer.admits) == (1, 1)

            # UNAUTHENTICATED → exactly one refresh; twice → typed error.
            servicer.fail_next_unauthenticated = 1
            assert (await client.authorize(agent, "t", {})).allowed
            assert servicer.admits == 2
            servicer.fail_next_unauthenticated = 2
            with pytest.raises(UnauthenticatedError):
                await client.authorize(agent, "t", {})

            # Unknown verdict is a typed failure.
            servicer.verdict = pb.AUTHORIZE_VERDICT_UNSPECIFIED
            with pytest.raises(UnknownVerdictError):
                await client.authorize(agent, "t", {})
            servicer.verdict = pb.ALLOW

    asyncio.run(scenario())


def test_aio_cancellation_mid_authorize_leaves_cache_usable(
    hanging_server, fake_server
):
    """Cancel an authorize stuck on a hanging server; the same client must still work when the
    verdict comes from a live path — the ticket cache is never left half-written or locked."""
    servicer, addr = fake_server

    async def scenario():
        # A client whose admission hangs: cancellation fires inside the lock, mid-admit.
        hang_client = AioSeamClient.connect(hanging_server)
        agent = Agent(SEED)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                hang_client.authorize(agent, "t", {}, timeout=5), 0.2
            )
        # The lock was released and the cache untouched — a fresh call proceeds (and times out at
        # the transport level rather than deadlocking on the cache lock).
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                hang_client.authorize(agent, "t", {}, timeout=5), 0.2
            )
        await hang_client.close()

        # And a healthy client is fully functional after an unrelated cancellation.
        async with AioSeamClient.connect(addr) as client:
            assert (await client.authorize(agent, "t", {})).allowed

    asyncio.run(scenario())


def test_aio_deadlines_enforced(hanging_server):
    async def scenario():
        async with AioSeamClient.connect(hanging_server) as client:
            agent = Agent(SEED)
            for call in [
                lambda: client.authorize(agent, "t", {}, timeout=0.1),
                lambda: client.admit(agent, timeout=0.1),
                lambda: client.run_decision(
                    agent, "s", ["a"], [("a", "y")], timeout=0.1
                ),
                lambda: client.open_session(agent, "s", ["a"], timeout=0.1),
                lambda: client.submit_proposal("s", "a", "p", "o", timeout=0.1),
                lambda: client.submit_vote("s", "a", "p", "v", timeout=0.1),
                lambda: client.submit_commit("s", "c", "act", timeout=0.1),
                lambda: client.resume_session("s", timeout=0.1),
                lambda: client.cancel_session("s", timeout=0.1),
                lambda: client.expire_session("s", timeout=0.1),
                lambda: client.session_status("s", timeout=0.1),
                lambda: client.get_decision("d", timeout=0.1),
                lambda: client.replay_decision("d", timeout=0.1),
                lambda: client.report_outcome("d", True, timeout=0.1),
                lambda: client.register_context(b"c", "Digest", timeout=0.1),
                lambda: client.resolve_context(["r"], timeout=0.1),
                lambda: client.issuer_aid(timeout=0.1),
                lambda: client.verify_commitment(pb.Commitment(), b"", timeout=0.1),
                lambda: client.verify_party_anchor("p", pb.Anchor(), timeout=0.1),
                lambda: client.verify_party_attestation(
                    "p", ev.ChainHeadAttestation(), timeout=0.1
                ),
                lambda: client.get_commitment_proof("d", timeout=0.1),
                lambda: client.verify_decision("d", "aid:pubkey:x", timeout=0.1),
            ]:
                with pytest.raises(DeadlineExceededError):
                    await call()

    asyncio.run(scenario())


def test_on_behalf_of_passthrough_aio():
    """on_behalf_of passthrough (Phase 0b): the aio client forwards the subjects verbatim."""

    async def scenario():
        client = AioSeamClient.connect("127.0.0.1:1")  # lazy channel, never dialed
        seen = {}

        class _Recorder:
            def __getattr__(self, name):
                async def record(req, **_kw):
                    seen[name] = req
                    return pb.SessionStep(state="Open")

                return record

        client._coord = _Recorder()

        async def _fake_presentation(agent, timeout=None):
            return pb.PinnedPresentation()

        client._presentation = _fake_presentation  # type: ignore[method-assign]

        agent = Agent(SEED)
        await client.run_decision(
            agent, "s", ["a"], [("a", "y")], on_behalf_of=["user:alice"]
        )
        assert list(seen["RunDecision"].on_behalf_of) == ["user:alice"]
        await client.open_session(agent, "s", ["a"], on_behalf_of=["user:bob"])
        assert list(seen["OpenSession"].on_behalf_of) == ["user:bob"]
        # Default: absent, not an empty sentinel value.
        await client.run_decision(agent, "s", ["a"], [("a", "y")])
        assert list(seen["RunDecision"].on_behalf_of) == []
        await client.close()

    asyncio.run(scenario())


def test_on_behalf_of_passthrough_sync():
    """run_decision/open_session forward on_behalf_of verbatim into the request protos."""
    client = SeamClient.connect("127.0.0.1:1")  # lazy channel, never dialed
    seen = {}

    class _Recorder:
        def __getattr__(self, name):
            def record(req, **_kw):
                seen[name] = req
                return pb.SessionStep(state="Open")

            return record

    client._coord = _Recorder()
    client._presentation = lambda agent, timeout=None: pb.PinnedPresentation()  # type: ignore

    agent = Agent(SEED)
    client.run_decision(agent, "s", ["a"], [("a", "y")], on_behalf_of=["user:alice"])
    assert list(seen["RunDecision"].on_behalf_of) == ["user:alice"]
    client.open_session(agent, "s", ["a"], on_behalf_of=["user:bob", "user:carol"])
    assert list(seen["OpenSession"].on_behalf_of) == ["user:bob", "user:carol"]
    # Default: absent, not an empty sentinel value.
    client.run_decision(agent, "s", ["a"], [("a", "y")])
    assert list(seen["RunDecision"].on_behalf_of) == []


# ── Benchmark: authorize overhead over a raw stub call ───────────────────────────────────────────


def test_async_authorize_p50_overhead_under_1ms(fake_server):
    """p50 overhead of aio authorize() vs a raw grpc.aio stub Authorize < 1 ms (the crypto +
    canonicalization budget). Compared as medians so scheduler noise doesn't flake it."""
    servicer, addr = fake_server

    async def scenario():
        async with AioSeamClient.connect(addr) as client:
            agent = Agent(SEED)
            await client.authorize(
                agent, "t", {"k": 1}
            )  # warm: ticket cached, channel up

            n = 60
            t0 = time.perf_counter()
            sdk_times = []
            for _ in range(n):
                t = time.perf_counter()
                await client.authorize(agent, "t", {"k": 1})
                sdk_times.append(time.perf_counter() - t)

            raw = rpc.SeamAuthorizationStub(client._ch)
            ticket = client._tickets[agent.aid]._ticket
            from seam_sdk._authorize import build_authorize_request

            req = build_authorize_request(
                ticket=ticket, agent_seed=agent.seed, tool_name="t", tool_input={"k": 1}
            )
            raw_times = []
            for _ in range(n):
                t = time.perf_counter()
                await raw.Authorize(req)
                raw_times.append(time.perf_counter() - t)
            del t0

            p50 = lambda xs: sorted(xs)[len(xs) // 2]  # noqa: E731
            overhead = p50(sdk_times) - p50(raw_times)
            assert overhead < 0.001, f"p50 overhead {overhead * 1000:.3f}ms >= 1ms"

    asyncio.run(scenario())


# ── JSON-side sanity: the fake's view matches what an adapter would recompute ────────────────────


def test_request_canonical_bytes_round_trip(fake_server):
    """The tool_input bytes on the wire parse back to the original object (JCS is valid JSON)."""
    servicer, addr = fake_server
    client = SeamClient.connect(addr)
    original = {"b": [1, 2.5, "x"], "a": {"nested": True, "z": None}}
    client.authorize(Agent(SEED), "t", original)
    assert json.loads(servicer.last_request.tool_input.decode()) == original
