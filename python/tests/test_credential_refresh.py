"""Refresh-once on the credentialed reads, ``report_outcome`` (#275, plans/post-onboarding-sdk-asks.md
Phase 1) and the seven ``submit_*`` steps (Phase 2, D-SUBMIT-RETRY), in BOTH Python clients.

Two layers, both needed:

* **Unit** — the clients' ``_coord``/``_authz``/``_admission`` are swapped for one scripted wire that
  records every call (name, request, metadata) and refuses chosen verbs ``UNAUTHENTICATED`` a set
  number of times. A live ticket is pre-seeded into the per-AID cache, so the baseline makes NO
  admission and "one extra admit" is exactly two admission RPCs (``IssueChallenge`` + ``Admit``).
  This layer covers all 16 credentialed verbs: the thirteen that retry, and the three writes that
  must not (D-WRITES-EXCLUDED).
* **Real gRPC** — :class:`test_authorize.FakeSeam`'s coordination handlers refuse on real ticket
  state over a real channel, so the typed error mapping is exercised end to end, and the concurrency
  criteria (N=32 coalescing, aio cancellation mid-refresh) are staged on real transports rather than
  on a recorder.

What the RUNTIME does with a ``submit_*`` resend (engine dedupe, the sealed early return, the budget
not debited twice) is not modelled by these fakes; ``test_integration.py`` proves it live.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from concurrent import futures

import grpc
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from seam_sdk import (
    Agent,
    IssuerMismatchError,
    SeamClient,
    StepUsage,
    create_identity_file,
    load_identity_facts,
    load_identity_file,
)
from seam_sdk._authorize import TicketCache
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc
from seam_sdk.aio import SeamClient as AioSeamClient
from seam_sdk.crypto import request_sig_payload, tool_input_digest
from seam_sdk.errors import (
    DeadlineExceededError,
    FailedPreconditionError,
    NotFoundError,
    PermissionDeniedError,
    UnauthenticatedError,
    UnavailableError,
)

from test_authorize import FakeSeam
from test_credential_wiring import CALLS, CRED_SEED, OTHER_CRED_SEED

# The six verbs Phase 1 retries, the seven steps Phase 2 retries, and the three writes that never
# do. Asserted to partition the shared 16-verb table, so a verb added there without a decision here
# fails loudly.
READS_AND_OUTCOME = (
    "SessionStatus",
    "GetDecision",
    "ReplayDecision",
    "GetCommitmentProof",
    "GetEscalation",
    "ReportOutcome",
)
SUBMITS = (
    "SubmitProposal",
    "SubmitVote",
    "SubmitEvaluation",
    "SubmitObjection",
    "SubmitCommit",
    "SubmitApprovalRequest",
    "SubmitBallot",
)
EXCLUDED = ("OpenSession", "CancelSession", "ExpireSession")
RETRYING = READS_AND_OUTCOME + SUBMITS
assert set(RETRYING) | set(EXCLUDED) == set(CALLS) and not set(RETRYING) & set(EXCLUDED)
assert (len(READS_AND_OUTCOME), len(SUBMITS), len(EXCLUDED)) == (6, 7, 3)

OLD = b"old-ticket"
ADMISSION = ("IssueChallenge", "Admit")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _seed(client, agent: Agent, ticket: bytes = OLD) -> None:
    cache = TicketCache()
    cache.store(ticket, _now_ms() + 60_000, _now_ms())
    client._tickets[agent.aid] = cache


def _cached(client, agent: Agent):
    cache = client._tickets.get(agent.aid)
    return None if cache is None else cache.get(_now_ms())


# ── The scripted wire ─────────────────────────────────────────────────────────────────────────────


class _Wire:
    """One recorder behind every stub. ``reject[name]`` refuses that verb ``UNAUTHENTICATED`` that many
    times; ``errors[name]`` raises the given typed error on every call of that verb; ``serve[name]``
    replaces the canned success response (how a test scripts what the runtime answered)."""

    def __init__(self) -> None:
        self.calls: list = []  # (name, request, metadata-or-None)
        self.reject: dict = {}
        self.errors: dict = {}
        self.admits = 0
        self.responses: dict = {}
        self.serve: dict = {}
        self._lock = threading.Lock()

    def handle(self, name: str, req, kw: dict):
        with self._lock:
            self.calls.append((name, req, kw.get("metadata")))
            if name in self.errors:
                raise self.errors[name]
            if name == "IssueChallenge":
                return pb.Challenge(nonce="bm9uY2U", receiver_aid="aid:pubkey:receiver")
            if name == "Admit":
                self.admits += 1
                return pb.AdmissionTicket(
                    ticket=b"new-ticket-%d" % self.admits,
                    expires_at_ms=_now_ms() + 60_000,
                )
            if self.reject.get(name, 0) > 0:
                self.reject[name] -= 1
                raise UnauthenticatedError(
                    grpc.StatusCode.UNAUTHENTICATED, "unauthenticated"
                )
            if name in self.serve:
                resp = self.serve[name]
            elif name == "ReportOutcome":
                resp = pb.ReportOutcomeResponse(recorded=True)
            elif name == "GetCommitmentProof":
                resp = pb.CommitmentProof(issuer_aid="aid:served")
            else:
                resp = pb.SessionStep(state=f"served:{name}")
            self.responses[name] = resp
            return resp

    def of(self, name: str) -> list:
        return [c for c in self.calls if c[0] == name]

    def admission_rpcs(self) -> int:
        return sum(1 for c in self.calls if c[0] in ADMISSION)


class _SyncStub:
    def __init__(self, wire: _Wire) -> None:
        self._wire = wire

    def __getattr__(self, name):
        def call(req, **kw):
            return self._wire.handle(name, req, kw)

        return call


class _AioStub:
    def __init__(self, wire: _Wire) -> None:
        self._wire = wire

    def __getattr__(self, name):
        async def call(req, **kw):
            return self._wire.handle(name, req, kw)

        return call


class _Harness:
    """Drives the same scenario through the sync or the aio client. The aio client is built and used
    on ONE event loop for the whole test (its locks bind to the first loop that contends them)."""

    def __init__(self, aio: bool) -> None:
        self.aio = aio
        self.loop = asyncio.new_event_loop() if aio else None
        self._clients: list = []

    def client(self, wire: _Wire, *, agent=None):
        if self.aio:

            async def make():
                return AioSeamClient.connect("127.0.0.1:1", agent=agent)

            c = self.loop.run_until_complete(make())
            stub = _AioStub(wire)
        else:
            c = SeamClient.connect("127.0.0.1:1", agent=agent)
            stub = _SyncStub(wire)
        c._coord = c._authz = c._admission = stub
        self._clients.append(c)
        return c

    def run(self, value):
        return self.loop.run_until_complete(value) if self.aio else value

    def close(self) -> None:
        for c in self._clients:
            self.run(c.close())
        if self.loop is not None:
            self.loop.close()


@pytest.fixture(params=["sync", "aio"])
def h(request):
    harness = _Harness(request.param == "aio")
    yield harness
    harness.close()


def _invoke(h: _Harness, client, verb: str, cred):
    return h.run(CALLS[verb]["invoke"](client, cred))


def _expected_payload(verb: str, req, ticket: bytes) -> bytes:
    spec = CALLS[verb]
    digest = "" if spec["bodyless"] else tool_input_digest(req.SerializeToString())
    return request_sig_payload(ticket, spec["rpc"], spec.get("resource_id", ""), digest)


# ── Criteria 1, 2, 3: recovery, second rejection, no credential ─────────────────────────────────


@pytest.mark.parametrize("verb", RETRYING)
def test_one_rejection_is_refreshed_and_retried_once(h, verb):
    wire = _Wire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.reject[verb] = 1

    result = _invoke(h, client, verb, cred)

    if verb == "ReportOutcome":
        assert result is True
    else:
        assert result == wire.responses[verb], "must return the RETRY's response"
    assert len(wire.of(verb)) == 2, f"{verb}: exactly one retry"
    assert wire.admission_rpcs() == 2, (
        f"{verb}: exactly one extra admit (challenge + Admit)"
    )
    assert _cached(client, cred) == b"new-ticket-1"


@pytest.mark.parametrize("verb", RETRYING)
def test_a_second_rejection_propagates_typed(h, verb):
    wire = _Wire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.reject[verb] = 2

    with pytest.raises(UnauthenticatedError):
        _invoke(h, client, verb, cred)

    assert len(wire.of(verb)) == 2, f"{verb}: retried once, never looped"
    assert wire.admission_rpcs() == 2


@pytest.mark.parametrize("verb", RETRYING)
def test_no_credential_means_no_refresh_and_no_retry(h, verb):
    """D-NO-CRED-NO-RETRY: an unbound client with no ``credential=`` has no ticket to refresh."""
    wire = _Wire()
    client = h.client(wire)  # unbound
    wire.reject[verb] = 1

    with pytest.raises(UnauthenticatedError):
        _invoke(h, client, verb, None)

    assert len(wire.of(verb)) == 1
    assert wire.of(verb)[0][2] is None, "no credential may be sent"
    assert wire.admission_rpcs() == 0


def test_a_bound_client_retries_with_its_bound_agent(h):
    wire = _Wire()
    bound = Agent(CRED_SEED)
    client = h.client(wire, agent=bound)
    _seed(client, bound)
    wire.reject["GetDecision"] = 1

    _invoke(h, client, "GetDecision", None)

    assert len(wire.of("GetDecision")) == 2
    assert _cached(client, bound) == b"new-ticket-1"


@pytest.mark.parametrize("verb", ["GetDecision", "SubmitVote"])
def test_the_bootstrap_files_recorded_aid_keys_the_refreshed_ticket(h, tmp_path, verb):
    # The seam between #274 and #275: the AID a seed-free consumer reads from the bootstrap file
    # (create_identity_file → load_identity_facts) is the very key the client's refresh-once
    # retry admits as and re-caches under, for the agent the full loader hands back.
    path, created_aid = create_identity_file(
        tmp_path / "id.json", agent_id="ap-clerk", tenant="acme", endpoint="x:1"
    )
    facts = load_identity_facts(path)
    loaded = load_identity_file(path)
    assert facts.aid == created_aid == loaded.agent.aid

    wire = _Wire()
    client = h.client(wire, agent=loaded.agent)
    _seed(client, loaded.agent)
    wire.reject[verb] = 1

    _invoke(h, client, verb, None)

    assert len(wire.of(verb)) == 2
    (_, admit_req, _) = wire.of("Admit")[0]
    presentation = json.loads(admit_req.presentation_json)
    assert presentation["sender_aid"] == facts.aid, (
        "the refresh admitted as the file's AID"
    )
    assert list(client._tickets) == [facts.aid]
    assert client._tickets[facts.aid].get(_now_ms()) == b"new-ticket-1"


def test_an_explicit_credential_on_a_bound_client_refreshes_the_signer_only(h):
    wire = _Wire()
    bound, cred = Agent(OTHER_CRED_SEED), Agent(CRED_SEED)
    client = h.client(wire, agent=bound)
    _seed(client, bound, b"bound-ticket")
    _seed(client, cred)
    wire.reject["SessionStatus"] = 1

    _invoke(h, client, "SessionStatus", cred)

    assert _cached(client, cred) == b"new-ticket-1", (
        "the signer's ticket is the one refreshed"
    )
    assert _cached(client, bound) == b"bound-ticket", (
        "the bound agent's ticket is untouched"
    )


def test_verify_decision_inherits_the_refresh_through_get_commitment_proof(h):
    wire = _Wire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.reject["GetCommitmentProof"] = 1

    # The served proof names a different issuer, so verify_decision raises AFTER the fetch — which
    # proves the fetch itself recovered rather than raising UnauthenticatedError.
    with pytest.raises(IssuerMismatchError):
        h.run(client.verify_decision("d1", "aid:expected", credential=cred))
    assert len(wire.of("GetCommitmentProof")) == 2


# ── Criteria 6, 7: re-signed under the new ticket, over the identical body ─────────────────────


@pytest.mark.parametrize("verb", RETRYING)
def test_the_retry_is_re_signed_under_the_new_ticket_only(h, verb):
    wire = _Wire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.reject[verb] = 1

    _invoke(h, client, verb, cred)

    (_, req1, md1), (_, req2, md2) = wire.of(verb)
    md1, md2 = dict(md1), dict(md2)
    assert md1["x-seam-ticket-bin"] == OLD
    assert md2["x-seam-ticket-bin"] == b"new-ticket-1"
    pub = Ed25519PrivateKey.from_private_bytes(cred.seed).public_key()
    pub.verify(
        md2["x-seam-call-sig-bin"], _expected_payload(verb, req2, b"new-ticket-1")
    )
    with pytest.raises(InvalidSignature):
        pub.verify(md2["x-seam-call-sig-bin"], _expected_payload(verb, req2, OLD))
    assert req1.SerializeToString() == req2.SerializeToString(), (
        "the body must not change"
    )


def test_report_outcome_resends_a_byte_identical_body(h):
    """Criterion 7, named on its own: the retry re-signs the SAME request, idempotency key and all —
    the property that makes a resend of a report that already landed a runtime no-op."""
    wire = _Wire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.reject["ReportOutcome"] = 1

    assert h.run(
        client.report_outcome(
            "d1", False, "reviewer-9", idempotency_key="review-77", credential=cred
        )
    )

    (_, req1, md1), (_, req2, md2) = wire.of("ReportOutcome")
    assert req1.SerializeToString() == req2.SerializeToString()
    assert req2.idempotency_key == "review-77"
    assert dict(md1)["x-seam-call-sig-bin"] != dict(md2)["x-seam-call-sig-bin"]


# ── Failure paths ────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("err", "code"),
    [
        (NotFoundError, grpc.StatusCode.NOT_FOUND),
        (PermissionDeniedError, grpc.StatusCode.PERMISSION_DENIED),
        (DeadlineExceededError, grpc.StatusCode.DEADLINE_EXCEEDED),
    ],
)
def test_a_non_unauthenticated_error_is_never_retried(h, err, code):
    wire = _Wire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.errors["GetDecision"] = err(code, "nope")

    with pytest.raises(err):
        _invoke(h, client, "GetDecision", cred)

    assert len(wire.of("GetDecision")) == 1
    assert wire.admission_rpcs() == 0
    assert _cached(client, cred) == OLD, "a non-auth failure must not touch the ticket"


@pytest.mark.parametrize("verb", ("SessionStatus",) + SUBMITS)
def test_a_failed_refresh_admit_propagates_typed_and_is_not_looped(h, verb):
    """The refresh's own challenge is load-shed (``CHALLENGE_REFUSED`` is ``UNAVAILABLE``). That
    surfaces typed — never retried (DECISIONS.md 2026-10-18) — and the resend never happens. For a
    ``submit_*`` step that matters twice over: no resend means no second chance to apply."""
    wire = _Wire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.reject[verb] = 1
    wire.errors["IssueChallenge"] = UnavailableError(
        grpc.StatusCode.UNAVAILABLE, "CHALLENGE_REFUSED"
    )

    with pytest.raises(UnavailableError) as info:
        _invoke(h, client, verb, cred)

    assert isinstance(info.value.__context__, UnauthenticatedError), (
        "the rejection that triggered the refresh stays reachable"
    )
    assert len(wire.of(verb)) == 1, "no resend after a failed refresh"
    assert len(wire.of("IssueChallenge")) == 1, (
        "the refresh is attempted once, never looped"
    )
    assert _cached(client, cred) is None, (
        "the dead ticket was dropped before the re-admit"
    )


@pytest.mark.parametrize("verb", EXCLUDED)
def test_the_three_excluded_writes_still_make_exactly_one_call(h, verb):
    """Phase 2 criterion 3 (the Phase 1 guard, narrowed): ``open_session``, ``cancel_session`` and
    ``expire_session`` stay one-shot (D-WRITES-EXCLUDED). Unchanged also means the cached ticket is
    left alone and no admission is made for the credential."""
    wire = _Wire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.reject[verb] = 1

    with pytest.raises(UnauthenticatedError):
        _invoke(h, client, verb, cred)

    assert len(wire.of(verb)) == 1, f"{verb} was retried"
    assert wire.admits == 0, f"{verb} re-admitted"
    assert _cached(client, cred) == OLD


# ── Phase 2: what the SDK does with the runtime's answer to a submit_* resend ────────────────────


def test_submit_retry_after_client_seal_returns_sealed_id(h):
    """The session was sealed by a client call (here: cancelled) between the rejection and the retry.
    The runtime answers the resend from its sealed early return — ``Ok``, the sealed ``decision_id``,
    no ``collective_outcome`` — and the SDK must hand that back as a success, untouched: not raise,
    not retry again, not synthesize an outcome. (What the runtime answers is proven live in
    ``test_integration.py``; here the fake scripts it, so only the SDK's pass-through is asserted.)"""
    wire = _Wire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.reject["SubmitVote"] = 1
    wire.serve["SubmitVote"] = pb.SessionStep(
        state="Cancelled", decision_id="dec-sealed"
    )

    step = _invoke(h, client, "SubmitVote", cred)

    assert step.decision_id == "dec-sealed"
    assert step.state == "Cancelled"
    assert not step.HasField("collective_outcome")
    assert not step.HasField("policy_enforcement")
    assert len(wire.of("SubmitVote")) == 2 and wire.admission_rpcs() == 2


def test_submit_retry_failed_precondition_propagates_typed_and_is_not_retried(h):
    """The sweeper (or a pending Expire/Cancel seal) closed the session between the rejection and the
    retry: the runtime refuses the resend ``FAILED_PRECONDITION`` (``session_not_open``). The SDK
    surfaces it typed and does NOT treat it as a reason to try again."""
    wire = _Wire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    msg = "session s1 expired (sealed by the session sweeper)"

    real = wire.handle

    def handle(name, req, kw):
        if name == "SubmitVote" and len(wire.of("SubmitVote")) == 1:
            wire.calls.append((name, req, kw.get("metadata")))
            raise FailedPreconditionError(grpc.StatusCode.FAILED_PRECONDITION, msg)
        return real(name, req, kw)

    wire.handle = handle
    wire.reject["SubmitVote"] = 1

    with pytest.raises(FailedPreconditionError, match="sealed by the session sweeper"):
        _invoke(h, client, "SubmitVote", cred)
    assert len(wire.of("SubmitVote")) == 2, "one rejection, one resend, nothing more"


def test_a_duplicate_step_is_passed_through_as_all_unset(h):
    """A resend of a non-resolving step the engine already applied comes back with ``decision_id``,
    ``policy_enforcement`` and ``collective_outcome`` all unset — indistinguishable from "applied,
    not resolved" (``SessionStep`` has no disposition). The SDK returns it as-is."""
    wire = _Wire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.reject["SubmitProposal"] = 1
    wire.serve["SubmitProposal"] = pb.SessionStep(state="Open")

    step = _invoke(h, client, "SubmitProposal", cred)

    assert step == pb.SessionStep(state="Open")


def test_usage_is_carried_byte_identical_on_the_resend(h):
    """The SDK resends the SAME request, ``usage`` included — it never re-reads or re-derives a field.
    (That a caller's OWN resend with a different ``usage`` is still deduped and not debited is the
    runtime's doing — ``usage`` is outside the hashed payload — and is proven live.)"""
    wire = _Wire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.reject["SubmitVote"] = 1

    h.run(
        client.submit_vote(
            "s1",
            "a",
            "p1",
            "APPROVE",
            usage=StepUsage(tokens=600, cost_micros=7),
            credential=cred,
        )
    )

    (_, req1, md1), (_, req2, md2) = wire.of("SubmitVote")
    assert req1.SerializeToString() == req2.SerializeToString()
    assert (req2.usage.tokens, req2.usage.cost_micros) == (600, 7)
    assert dict(md1)["x-seam-call-sig-bin"] != dict(md2)["x-seam-call-sig-bin"]


@pytest.mark.parametrize("aio", [False, True], ids=["sync", "aio"])
@pytest.mark.parametrize(
    "name",
    [
        "submit_proposal",
        "submit_vote",
        "submit_evaluation",
        "submit_objection",
        "submit_commit",
        "submit_approval_request",
        "submit_ballot",
    ],
)
def test_every_submit_docstring_carries_the_resend_caveat(name, aio):
    doc = getattr(AioSeamClient if aio else SeamClient, name).__doc__
    assert "collective_outcome" in doc and "get_decision" in doc and "usage" in doc
    assert "boundary.data_flagged" in doc


def test_retry_false_invalidates_the_rejected_ticket_then_raises(h):
    """The helper's ``retry=False`` mode ("invalidate, then raise"), which Phase 2 keeps reachable."""
    wire = _Wire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred)
    wire.reject["SessionStatus"] = 1

    def send(md):
        return client._coord.SessionStatus(pb.SessionRef(session_id="s1"), metadata=md)

    with pytest.raises(UnauthenticatedError):
        h.run(
            client._credentialed_call(
                cred,
                CALLS["SessionStatus"]["rpc"],
                "s1",
                None,
                send,
                timeout=2.0,
                retry=False,
            )
        )
    assert len(wire.of("SessionStatus")) == 1
    assert wire.admission_rpcs() == 0
    assert _cached(client, cred) is None


def test_retry_false_never_drops_a_ticket_someone_else_refreshed_in(h):
    wire = _Wire()
    cred = Agent(CRED_SEED)
    client = h.client(wire)
    _seed(client, cred, b"fresher")
    h.run(client._invalidate_ticket(cred, OLD))
    assert _cached(client, cred) == b"fresher"


# ── Real gRPC: FakeSeam's coordination handlers ─────────────────────────────────────────────────

N = 32


@pytest.fixture
def coord_server():
    """FakeSeam with coordination registered and enough workers to hold N rejections at a barrier
    and still serve the re-admit."""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=N * 2 + 8))
    servicer = FakeSeam()
    rpc.add_SeamAdmissionServicer_to_server(servicer, server)
    rpc.add_SeamAuthorizationServicer_to_server(servicer, server)
    rpc.add_SeamCoordinationServicer_to_server(servicer, server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    yield servicer, f"127.0.0.1:{port}"
    if servicer.admit_hold is not None:
        servicer.admit_hold.set()
    server.stop(None)


GRPC_VERBS = {
    "SessionStatus": lambda c, cred: c.session_status("s1", credential=cred),
    "GetDecision": lambda c, cred: c.get_decision("d1", credential=cred),
    "ReportOutcome": lambda c, cred: c.report_outcome(
        "d1", True, idempotency_key="review-77", credential=cred
    ),
}
# Phase 2: the seven steps over a real channel (FakeSeam's Submit* handlers).
GRPC_SUBMITS = {verb: CALLS[verb]["invoke"] for verb in SUBMITS}
GRPC_VERBS.update(GRPC_SUBMITS)


@pytest.mark.parametrize("verb", sorted(GRPC_VERBS))
@pytest.mark.parametrize("aio", [False, True], ids=["sync", "aio"])
def test_grpc_recovery_and_second_rejection(coord_server, verb, aio):
    servicer, addr = coord_server
    cred = Agent(CRED_SEED)
    invoke = GRPC_VERBS[verb]

    def check_recovered():
        assert servicer.coord_calls[verb] == 2
        assert (servicer.challenges, servicer.admits) == (2, 2)
        (body1, t1), (body2, t2) = servicer.coord_seen[verb]
        assert body1 == body2 and t1 != t2

    if aio:

        async def scenario():
            async with AioSeamClient.connect(addr) as client:
                await client.admit(
                    cred
                )  # pre-seeded live ticket: the baseline admits nothing
                servicer.fail_next_unauthenticated = 1
                assert await invoke(client, cred)
                check_recovered()
                servicer.fail_next_unauthenticated = 2
                with pytest.raises(UnauthenticatedError):
                    await invoke(client, cred)

        asyncio.run(scenario())
    else:
        with SeamClient.connect(addr) as client:
            client.admit(cred)
            servicer.fail_next_unauthenticated = 1
            assert invoke(client, cred)
            check_recovered()
            servicer.fail_next_unauthenticated = 2
            with pytest.raises(UnauthenticatedError):
                invoke(client, cred)
    assert servicer.coord_calls[verb] == 4, (
        "the double rejection was sent exactly twice"
    )
    assert servicer.admits == 3, "and paid exactly one more admit"


@pytest.mark.parametrize("aio", [False, True], ids=["sync", "aio"])
def test_grpc_no_credential_is_one_call_zero_admits(coord_server, aio):
    servicer, addr = coord_server

    if aio:

        async def scenario():
            async with AioSeamClient.connect(addr) as client:
                with pytest.raises(UnauthenticatedError):
                    await client.session_status("s1")

        asyncio.run(scenario())
    else:
        with SeamClient.connect(addr) as client, pytest.raises(UnauthenticatedError):
            client.session_status("s1")
    assert servicer.coord_calls["SessionStatus"] == 1
    assert (servicer.challenges, servicer.admits) == (0, 0)


@pytest.mark.parametrize("aio", [False, True], ids=["sync", "aio"])
def test_grpc_refused_refresh_admit_surfaces_typed(coord_server, aio):
    servicer, addr = coord_server
    cred = Agent(CRED_SEED)

    if aio:

        async def scenario():
            async with AioSeamClient.connect(addr) as client:
                await client.admit(cred)
                servicer.revoke_all()
                servicer.admit_fail = grpc.StatusCode.UNAVAILABLE
                with pytest.raises(UnavailableError):
                    await client.get_decision("d1", credential=cred)

        asyncio.run(scenario())
    else:
        with SeamClient.connect(addr) as client:
            client.admit(cred)
            servicer.revoke_all()
            servicer.admit_fail = grpc.StatusCode.UNAVAILABLE
            with pytest.raises(UnavailableError):
                client.get_decision("d1", credential=cred)
    assert servicer.coord_calls["GetDecision"] == 1
    assert servicer.challenges == 2, "one refresh attempt, never looped"


def _assert_one_readmit(servicer) -> None:
    assert servicer.rejections == N, (
        f"only {servicer.rejections} of {N} reads were rejected — the race was not staged, so the "
        "re-admit count proves nothing"
    )
    assert servicer.admits - 1 == 1, (
        f"{N} concurrent rejected reads caused {servicer.admits - 1} re-admits; must coalesce to one"
    )


def test_grpc_n_concurrent_rejected_reads_coalesce_to_one_readmit_sync(coord_server):
    servicer, addr = coord_server
    cred = Agent(CRED_SEED)
    with SeamClient.connect(addr) as client:
        client.admit(cred)
        servicer.reject_barrier = threading.Barrier(N)
        servicer.revoke_all()
        gate = threading.Barrier(N)

        def call(_):
            gate.wait()
            return client.session_status("s1", credential=cred)

        with futures.ThreadPoolExecutor(max_workers=N) as pool:
            results = list(pool.map(call, range(N)))
    assert all(r.state == "Open" for r in results)
    _assert_one_readmit(servicer)


def test_grpc_n_concurrent_rejected_reads_coalesce_to_one_readmit_aio(coord_server):
    servicer, addr = coord_server
    cred = Agent(CRED_SEED)

    async def scenario():
        async with AioSeamClient.connect(addr) as client:
            await client.admit(cred)
            servicer.reject_barrier = threading.Barrier(N)
            servicer.revoke_all()
            results = await asyncio.gather(
                *(client.get_decision(f"d{i}", credential=cred) for i in range(N))
            )
            assert [r.decision_id for r in results] == [f"d{i}" for i in range(N)]

    asyncio.run(scenario())
    _assert_one_readmit(servicer)


def _submit_call(i: int):
    """The i-th of N concurrent steps, round-robin over the seven verbs, so one refresh is shared
    across every step kind at once."""
    return GRPC_SUBMITS[SUBMITS[i % len(SUBMITS)]]


def test_grpc_n_concurrent_rejected_submits_coalesce_to_one_readmit_sync(coord_server):
    servicer, addr = coord_server
    cred = Agent(CRED_SEED)
    with SeamClient.connect(addr) as client:
        client.admit(cred)
        servicer.reject_barrier = threading.Barrier(N)
        servicer.revoke_all()
        gate = threading.Barrier(N)

        def call(i):
            gate.wait()
            return _submit_call(i)(client, cred)

        with futures.ThreadPoolExecutor(max_workers=N) as pool:
            results = list(pool.map(call, range(N)))
    assert all(r.state == "Open" for r in results)
    _assert_one_readmit(servicer)
    for verb in SUBMITS:
        sent = servicer.coord_seen[verb]
        # Every rejected step was resent exactly once, over the SAME body, under a new ticket.
        assert len(sent) == 2 * sum(1 for i in range(N) if SUBMITS[i % 7] == verb)
        assert len({body for body, _ in sent}) == 1


def test_grpc_n_concurrent_rejected_submits_coalesce_to_one_readmit_aio(coord_server):
    servicer, addr = coord_server
    cred = Agent(CRED_SEED)

    async def scenario():
        async with AioSeamClient.connect(addr) as client:
            await client.admit(cred)
            servicer.reject_barrier = threading.Barrier(N)
            servicer.revoke_all()
            results = await asyncio.gather(
                *(_submit_call(i)(client, cred) for i in range(N))
            )
            assert all(r.state == "Open" for r in results)

    asyncio.run(scenario())
    _assert_one_readmit(servicer)
    assert sum(servicer.coord_calls[v] for v in SUBMITS) == 2 * N


def test_grpc_aio_cancel_mid_refresh_leaves_the_cache_empty_then_recovers(coord_server):
    """Criterion 8. The refresh invalidates the dead ticket BEFORE awaiting the re-admit, so a task
    cancelled while that ``Admit`` is in flight leaves the cache empty — not holding the rejected
    ticket, not half-written, its lock released — and the next call admits afresh and succeeds."""
    servicer, addr = coord_server
    cred = Agent(CRED_SEED)

    async def scenario():
        async with AioSeamClient.connect(addr) as client:
            await client.admit(cred)
            servicer.revoke_all()
            servicer.admit_hold = threading.Event()
            task = asyncio.create_task(client.session_status("s1", credential=cred))
            entered = await asyncio.to_thread(servicer.admit_entered.wait, 10)
            assert entered, "the refresh Admit never reached the server"
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert client._tickets[cred.aid].get(_now_ms()) is None
            assert not client._ticket_locks[cred.aid].locked()

            hold, servicer.admit_hold = servicer.admit_hold, None
            hold.set()  # let the abandoned server-side Admit finish
            admits_before = servicer.admits
            resp = await client.session_status("s1", credential=cred)
            assert resp.state == "Open"
            assert servicer.admits == admits_before + 1, "the next call admitted afresh"

    asyncio.run(scenario())
