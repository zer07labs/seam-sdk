"""Ergonomic Seam client over the generated gRPC stubs + the stock crypto shim.

`SeamClient.run_decision` owns the full binding path (admit via the pinned-key PoP, then decide+seal in
one call); `verify_decision` fetches a sealed decision's proof and verifies its rooted TCT locally — zero
server trust beyond the fetch.
"""

from __future__ import annotations

import json
import threading
import warnings
from dataclasses import dataclass
from typing import Dict, Mapping, Optional, Sequence

import grpc
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._authorize import (
    AuthorizeResult,
    TicketCache,
    _resolve_canonical,
    build_authorize_request,
    result_of,
)
from .crypto import aid_from_pubkey, build_presentation, verify_tct
from .errors import (  # noqa: F401  (SeamError re-exported)
    IssuerMismatchError,
    SeamError,
    UnauthenticatedError,
    _MappedStub,
)

# The generated transport stubs are ROOTED subpackages (`scripts/root_gen.py` rewrites the
# raw buf output), so they import like any other module — no sys.path injection, no global
# `seam` namespace collision with installed packages. BEHAVIOR CHANGE for anyone who
# imported `seam.api.v1` directly off the old path hack: import `seam_sdk._gen.seam.api.v1`
# (the public `seam_sdk` API is unchanged).
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc
from seam_sdk._gen.seam.event.v1 import seam_event_pb2 as ev  # noqa: F401  (re-exported)


# ``SeamError`` and ``IssuerMismatchError`` are defined in :mod:`seam_sdk.errors` and imported above; they
# stay importable from here (``from seam_sdk.client import SeamError``) for backward compatibility.


def _now_ms() -> int:
    import time

    return int(time.time() * 1000)


# ``timeout`` is PER-RPC, not an overall budget for the call. Decided, not accidental — and it has a
# consequence callers must size around, so it is stated here rather than discovered.
#
# Every public method takes ``timeout`` (seconds) and propagates it as the gRPC deadline on each
# wire call it makes. Most methods make exactly one, so per-RPC and overall coincide. Three do not:
#
#   * ``authorize`` may make up to SIX: an admit (challenge + Admit = 2) when the ticket is cold or
#     stale, the Authorize itself (1), and — on ``UNAUTHENTICATED`` — a refresh (another 2) plus one
#     retried Authorize (1). So the worst case is 6x the value passed, not the 1x it reads as.
#   * ``run_decision`` and ``open_session`` each begin with the challenge→Admit handshake.
#
# So a caller that needs a hard overall bound must impose its own outer clock; the adapters'
# ``Gate`` does exactly that with ``asyncio.wait_for`` around every call, and its ``timeout_s``
# is the number that actually bounds a gated tool call.
#
# Overall-budget semantics were considered and rejected for now: it would mean threading a
# deadline through the ticket lifecycle and deciding what a partially-spent budget means for the
# refresh, which is a contract change for every existing caller in exchange for a bound the one
# consumer that needs it already imposes. Recorded in ASSUMPTIONS.md.
#
# The SDK never retries beyond that single ticket refresh — adapters own retry semantics. A
# deadline breach surfaces as ``DeadlineExceededError``, distinct from a DENY verdict.
DEFAULT_TIMEOUT_S = 2.0


class Agent:
    """An agent identity — a 32-byte seed that derives the pinned AID and signs the admission PoP."""

    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise ValueError("agent seed must be 32 bytes")
        self.seed = seed
        self._aid: Optional[str] = None

    @property
    def aid(self) -> str:
        # Derived once — the AID keys the per-agent ticket cache on the authorize hot path.
        if self._aid is None:
            pub = (
                Ed25519PrivateKey.from_private_bytes(self.seed)
                .public_key()
                .public_bytes_raw()
            )
            self._aid = aid_from_pubkey(pub)
        return self._aid


@dataclass
class BudgetLimits:
    """Multi-dimension session budget (enterprise 6.2). Every field is optional; an unset
    dimension is unlimited. ``messages``, when set, overrides the legacy ``budget`` count.
    ``soft_pct`` is the soft-warning threshold as a percent of any limit (server default 80)."""

    messages: Optional[int] = None
    tokens: Optional[int] = None
    cost_micros: Optional[int] = None
    wall_ms: Optional[int] = None
    soft_pct: Optional[int] = None

    def to_pb(self) -> "pb.BudgetLimits":
        kwargs = {
            k: v
            for k, v in (
                ("messages", self.messages),
                ("tokens", self.tokens),
                ("cost_micros", self.cost_micros),
                ("wall_ms", self.wall_ms),
                ("soft_pct", self.soft_pct),
            )
            if v is not None
        }
        return pb.BudgetLimits(**kwargs)


@dataclass
class StepUsage:
    """Caller-reported per-step resource spend (enterprise 6.2), debited to the session ledger.
    The protocol cannot know what an agent runtime spent; the orchestrator reports it. Absent =
    zero."""

    tokens: int = 0
    cost_micros: int = 0

    def to_pb(self) -> "pb.StepUsage":
        return pb.StepUsage(tokens=self.tokens, cost_micros=self.cost_micros)


def _u32(value: int, field: str) -> int:
    """Range-check a ``uint32`` at the client boundary.

    protobuf-python raises on out-of-range assignment, but the error names the generated field and
    not the SDK argument the caller actually passed — and a ``bool`` would sail through silently as
    0/1, because ``bool`` is an ``int`` subclass. Fail here, naming the SDK argument.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an int, got {type(value).__name__}")
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"{field} must fit in a uint32 (0..4294967295), got {value}")
    return value


class SeamClient:
    """A high-level client over a gRPC channel to a Seam server."""

    def __init__(self, channel: grpc.Channel):
        self._ch = channel
        # Stubs are wrapped so server errors surface as typed ``SeamRpcError`` subclasses (still
        # ``grpc.RpcError``) instead of bare status codes.
        self._admission = _MappedStub(rpc.SeamAdmissionStub(channel))
        self._coord = _MappedStub(rpc.SeamCoordinationStub(channel))
        self._trust = _MappedStub(rpc.SeamTrustStub(channel))
        self._context = _MappedStub(rpc.SeamContextStub(channel))
        self._authz = _MappedStub(rpc.SeamAuthorizationStub(channel))
        # Admission-ticket lifecycle (advisory Authorize path): one cache AND one lock PER AGENT AID —
        # admit-once, refresh at 80% TTL, retry exactly once on UNAUTHENTICATED.
        #
        # Per-AID, not one global lock: a hung `Admit` for agent A held the single lock for its whole
        # timeout, so agent B could not even READ its own already-cached ticket. One slow identity
        # stalling every other identity's hot path is not a property a shared client should have.
        self._tickets: Dict[str, TicketCache] = {}
        self._ticket_locks: Dict[str, threading.Lock] = {}
        # Guards the two dicts above and NOTHING else. It is never held across an RPC — only across a
        # dict lookup — which is what keeps the per-AID split from collapsing back into a global lock.
        self._registry_lock = threading.Lock()

    @classmethod
    def connect(
        cls, target: str, *, credentials: Optional[grpc.ChannelCredentials] = None
    ) -> "SeamClient":
        """Connect to a Seam data-plane endpoint. Plaintext by default (the dev/loopback path); pass
        ``credentials=grpc.ssl_channel_credentials()`` (or a configured creds object) to use TLS."""
        channel = (
            grpc.secure_channel(target, credentials)
            if credentials is not None
            else grpc.insecure_channel(target)
        )
        return cls(channel)

    def close(self) -> None:
        """Close the underlying channel.

        The aio client has had this since it shipped; the sync one leaked a channel — and with it a
        connection and the ticket-refresh state keyed to it — for every client a process constructed.
        A long-lived worker that rebuilds its client on reconnect leaked one per reconnect.

        Idempotent: grpc tolerates a repeated close, so ``with`` plus an explicit ``close()`` is safe.
        """
        self._ch.close()

    def __enter__(self) -> "SeamClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _presentation(
        self, agent: Agent, timeout: float = DEFAULT_TIMEOUT_S
    ) -> pb.PinnedPresentation:
        ch = self._admission.IssueChallenge(pb.Empty(), timeout=timeout)
        body = build_presentation(agent.seed, ch.receiver_aid, ch.nonce, _now_ms())
        return pb.PinnedPresentation(presentation_json=json.dumps(body).encode())

    # ── Advisory authorization (1-RTT, unsealed) ────────────────────────────────────────────────

    def admit(self, agent: Agent, *, timeout: float = DEFAULT_TIMEOUT_S) -> bytes:
        """Run the challenge→``Admit`` handshake now and cache the resulting admission ticket.

        :meth:`authorize` calls this lazily — an explicit ``admit`` is only useful to front-load the
        2-RTT handshake (e.g. at worker startup). Returns the opaque ticket bytes."""
        cache, lock = self._cache_and_lock(agent.aid)
        with lock:
            return self._admit_locked(agent, cache, timeout)

    def _cache_and_lock(self, aid: str) -> "tuple[TicketCache, threading.Lock]":
        """The (cache, lock) pair for one agent identity, created on first use.

        Both dicts grow per distinct AID and are never evicted. That is deliberate for the shape
        this client is built for — an agent process holds one identity, occasionally a handful — and
        the entries are tiny. A gateway multiplexing thousands of identities through ONE client
        would grow them without bound; that deployment wants an LRU here, and should be treated as
        a change to make rather than a bug to discover. Noted rather than pre-solved: the eviction
        policy interacts with the refresh coalescing above (evicting a lock mid-refresh would split
        the very race it exists to serialize), so it is not a change to make speculatively.
        """
        with self._registry_lock:
            return (
                self._tickets.setdefault(aid, TicketCache()),
                self._ticket_locks.setdefault(aid, threading.Lock()),
            )

    def _admit_locked(self, agent: Agent, cache: TicketCache, timeout: float) -> bytes:
        ticket = self._admission.Admit(
            self._presentation(agent, timeout), timeout=timeout
        )
        cache.store(ticket.ticket, ticket.expires_at_ms, _now_ms())
        return ticket.ticket

    def authorize(
        self,
        agent: Agent,
        tool_name: str,
        tool_input=None,
        *,
        canonical: Optional[bytes] = None,
        digest_only: bool = False,
        features: Optional[Mapping[str, str]] = None,
        session_id: str = "",
        subject: str = "",
        subjects: Sequence[str] = (),
        agent_id: str = "",
        client_request_id: str = "",
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> AuthorizeResult:
        """Ask one advisory ``(tool_name, tool_input) -> verdict`` question — 1 RTT, seals nothing.

        ``tool_input`` is the tool call's input as a plain JSON-able object; it is JCS-canonicalized
        and digested here, and the per-call ``call_sig`` binds the ticket to that exact digest.
        ``digest_only=True`` sends the digest without the raw input (audit-grade; no guard scan or
        TRANSFORM). The ticket lifecycle is owned by the client: lazy admit, cached, refreshed at 80%
        TTL, retried exactly once on ``UNAUTHENTICATED``. An unknown verdict raises
        :class:`~seam_sdk.errors.UnknownVerdictError` — never an implicit allow. An old runtime
        without the Authorize service raises ``UnimplementedError``; adapters typically degrade to
        their Observe tier on it.

        ``canonical`` is the alternative to ``tool_input`` and the reason this parameter exists: pass
        the JCS bytes you already derived (via :func:`seam_sdk.canonicalize_tool_input`) and the value
        is derived exactly ONCE, by you. Otherwise a caller that needs the digest before the call —
        to record it on a handle row, say — canonicalizes the object, the SDK canonicalizes it again,
        and the two derivations can disagree across the gap between them (seam-sdk#60). The two
        parameters are mutually exclusive; passing both is an error rather than a precedence rule.

        ``subjects`` supersedes the deprecated singular ``subject``: the server takes the union of
        both, drops empty entries, dedupes first-wins, and caps the effective set at 16. **Today the
        server refuses an effective subject set larger than one** — supplying more than one is the
        server's ``INVALID_ARGUMENT`` until Phase B ships ``AuthorizeEvaluated.subject_digests``; this
        parameter exists now so callers can migrate off ``subject`` one at a time. It is not part of
        the signed payload (``call_sig`` does not cover ``subject`` or ``subjects``).
        """
        # Canonicalized ONCE, before the ticket is acquired and outside the closure below. Both
        # halves of that are load-bearing. Inside the closure it was re-derived on the refresh-and-
        # retry path — `build` is called twice — so a tool_input mutated during the admit RTT was
        # signed and sent with a DIFFERENT digest on the retry than on the first attempt, and the
        # request was internally consistent, so the runtime accepted it (seam-sdk#60). Before the
        # ticket, so uncanonicalizable input fails without first spending an admit round trip.
        # `ts/src/client.ts` has always hoisted it; this is the Python twin catching up.
        canonical = _resolve_canonical(tool_input, canonical)
        ticket = self._ticket_for(agent, timeout)
        build = lambda t: build_authorize_request(  # noqa: E731 — rebuilt on refresh (new call_sig)
            ticket=t,
            agent_seed=agent.seed,
            tool_name=tool_name,
            canonical=canonical,
            digest_only=digest_only,
            features=features,
            session_id=session_id,
            subject=subject,
            subjects=list(subjects),
            agent_id=agent_id,
            client_request_id=client_request_id,
        )
        try:
            resp = self._authz.Authorize(build(ticket), timeout=timeout)
        except UnauthenticatedError:
            # Expired/rejected ticket: refresh once, retry once. A second failure propagates typed.
            ticket = self._refresh_ticket(agent, ticket, timeout)
            resp = self._authz.Authorize(build(ticket), timeout=timeout)
        return result_of(resp)

    def _refresh_ticket(self, agent: Agent, failed: bytes, timeout: float) -> bytes:
        """Re-admit after an ``UNAUTHENTICATED``, coalescing concurrent refreshes to ONE.

        The re-check inside the lock is the whole point. Unconditionally invalidating and
        re-admitting meant N concurrent callers produced N re-admits: each one threw away the
        ticket the previous caller had just minted, so every caller admitted for itself. Cold start
        already coalesced correctly (they all find an empty cache and the first one fills it) —
        which is what made this easy to miss, because the obvious test passes.

        It matters under mass revocation, which is precisely when the admission endpoint is already
        the most loaded thing in the system: every in-flight call fails at once and, before this,
        every one of them stampeded it.

        So: if the cache now holds a ticket that is NOT the one we failed on, some other caller
        already refreshed and we use theirs. Only the caller still holding the dead ticket (or
        finding none) pays for the round trip.

        **What adopting costs, when the adopted ticket is also dead.** Under a revocation that kills
        every outstanding ticket rather than one, an adopter takes a ticket that the server will
        also reject. It retries once, fails, and the ``UnauthenticatedError`` propagates typed —
        there is no second refresh, because the retry in ``authorize`` is deliberately one-shot.
        Before this change that caller would have minted its own ticket and might have succeeded.
        That is a real trade and it is the right one: the alternative is re-opening the stampede on
        exactly the failure that causes it. The bound is what matters — N callers serialize behind
        the lock, each paying at most one admit attempt, with no fan-out and no retry loop.
        """
        cache, lock = self._cache_and_lock(agent.aid)
        with lock:
            current = cache.get(_now_ms())
            if current is not None and current != failed:
                return current
            cache.invalidate()
            return self._admit_locked(agent, cache, timeout)

    def _ticket_for(self, agent: Agent, timeout: float) -> bytes:
        cache, lock = self._cache_and_lock(agent.aid)
        with lock:
            ticket = cache.get(_now_ms())
            if ticket is None:
                ticket = self._admit_locked(agent, cache, timeout)
            return ticket

    def run_decision(
        self,
        agent: Agent,
        session_id: str,
        participants,
        votes,
        *,
        features: Optional[Mapping[str, str]] = None,
        on_behalf_of: Sequence[str] = (),
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.DecisionResponse:
        """Admit (the PoP handshake) → run a coordinated decision → seal, in one call.

        ``features`` are optional pre-decision request features (e.g. ``{"amount_band": "high"}``) that the
        advisory learning classifier keys ``context_class`` on. They **never** affect the sealed record —
        the decision seals identically with or without them. Absent ⇒ no features (non-breaking). Mirrors
        the Rust reference's ``run_decision_with_features``.

        ``on_behalf_of`` names the end-user data subjects this decision is made for (Phase 0b). The
        engine never reads them; the kernel folds each into the sealed record's participation as an
        inert ``subject:<i>`` declaration, which is what makes GDPR erasure find the record. The
        ``subject:`` prefix is reserved — supplying it here is the server's INVALID_ARGUMENT to raise.
        """
        req = pb.RunDecisionRequest(
            session_id=session_id,
            participants=list(participants),
            votes=[pb.Vote(agent=a, value=v) for a, v in votes],
            presentation=self._presentation(agent, timeout),
            on_behalf_of=list(on_behalf_of),
        )
        if features:
            req.features.update(features)
        return self._coord.RunDecision(req, timeout=timeout)

    # ── Incremental session lifecycle (enterprise 6.2 budget surface) ───────────────────────────
    # open → propose/vote → commit, with resume/cancel/expire/status. Budgets are first-class:
    # multi-dimension ``limits`` at open, per-step ``usage``, and the dimension-raising resume.
    # A step returns a ``SessionStep`` whose ``state == "Suspended"`` when a hard budget dimension
    # is breached (an ``Ok`` step, not an error — the R9 approver then resumes with a raise). A
    # scope-floor denial surfaces as a gRPC ``PERMISSION_DENIED`` error.

    def open_session(
        self,
        agent: Agent,
        session_id: str,
        participants: Sequence[str],
        *,
        budget: int = 0,
        limits: Optional[BudgetLimits] = None,
        mode: str = "",
        on_behalf_of: Sequence[str] = (),
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        """Admit (the PoP handshake) → open an incremental session. ``budget`` is the legacy
        message count (0 means the server default, currently 32 — the proto's semantics, so the
        server owns the number); ``limits`` adds the other 6.2 dimensions. ``on_behalf_of`` binds
        end-user data subjects to the session (see :meth:`run_decision`)."""
        req = pb.OpenSessionRequest(
            session_id=session_id,
            participants=list(participants),
            budget=budget,
            mode=mode,
            presentation=self._presentation(agent, timeout),
            on_behalf_of=list(on_behalf_of),
        )
        if limits is not None:
            req.limits.CopyFrom(limits.to_pb())
        return self._coord.OpenSession(req, timeout=timeout)

    def submit_proposal(
        self,
        session_id: str,
        proposer: str,
        proposal_id: str,
        option: str,
        *,
        usage: Optional[StepUsage] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        req = pb.ProposalRequest(
            session_id=session_id,
            proposer=proposer,
            proposal_id=proposal_id,
            option=option,
        )
        if usage is not None:
            req.usage.CopyFrom(usage.to_pb())
        return self._coord.SubmitProposal(req, timeout=timeout)

    def submit_vote(
        self,
        session_id: str,
        voter: str,
        proposal_id: str,
        value: str,
        *,
        usage: Optional[StepUsage] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        req = pb.VoteRequest(
            session_id=session_id,
            voter=voter,
            proposal_id=proposal_id,
            value=value,
        )
        if usage is not None:
            req.usage.CopyFrom(usage.to_pb())
        return self._coord.SubmitVote(req, timeout=timeout)

    def submit_evaluation(
        self,
        session_id: str,
        evaluator: str,
        proposal_id: str,
        recommendation: str,
        *,
        confidence: Optional[float] = None,
        reason: str = "",
        rationale_ref: Optional[str] = None,
        usage: Optional[StepUsage] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        """Submit a MACP evaluation for a proposal.

        ``recommendation`` is MACP's closed vocabulary: ``APPROVE | REVIEW | BLOCK | REJECT``.

        ``confidence`` is EXPLICIT PRESENCE on the wire: absent means *declined to claim* and is
        **not** ``0.0`` — the runtime never fabricates a value into the caller's intent. When
        present it must be in ``[0.0, 1.0]``; out-of-range is the server's ``INVALID_ARGUMENT``
        (MACP refuses it — ``macp-modes-0.5.0 src/mode/decision.rs:166-171``), deliberately not
        mirrored client-side.

        ``rationale_ref`` is a ``sha256:<hex>`` context ref. It is accepted and recorded on the
        request path only — it is **NOT YET SEALED**.
        """
        req = pb.EvaluationRequest(
            session_id=session_id,
            evaluator=evaluator,
            proposal_id=proposal_id,
            recommendation=recommendation,
            reason=reason,
        )
        if confidence is not None:
            req.confidence = confidence  # presence; NEVER default it to 0.0
        if rationale_ref is not None:
            req.rationale_ref = rationale_ref
        if usage is not None:
            req.usage.CopyFrom(usage.to_pb())
        return self._coord.SubmitEvaluation(req, timeout=timeout)

    def submit_objection(
        self,
        session_id: str,
        objector: str,
        proposal_id: str,
        reason: str,
        *,
        severity: str = "",
        usage: Optional[StepUsage] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        """Submit a MACP objection against a proposal.

        ``severity`` is one of ``low | medium | high | critical``; empty defaults to ``medium``
        (the MACP default, applied server-side).
        """
        req = pb.ObjectionRequest(
            session_id=session_id,
            objector=objector,
            proposal_id=proposal_id,
            reason=reason,
            severity=severity,
        )
        if usage is not None:
            req.usage.CopyFrom(usage.to_pb())
        return self._coord.SubmitObjection(req, timeout=timeout)

    def submit_commit(
        self,
        session_id: str,
        commitment_id: str,
        action: str,
        *,
        usage: Optional[StepUsage] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        req = pb.CommitRequest(
            session_id=session_id,
            commitment_id=commitment_id,
            action=action,
        )
        if usage is not None:
            req.usage.CopyFrom(usage.to_pb())
        return self._coord.SubmitCommit(req, timeout=timeout)

    # ── Quorum-mode-only steps (`macp.mode.quorum.v1`) ─────────────────────────────────────────
    # request → ballot × N → submit_commit (reused unchanged). Both verbs are rejected with a typed
    # mode-mismatch error against a session opened in any other mode. That check is the server's to
    # make and is deliberately NOT mirrored here: a client-side copy of a server-side rule is a
    # second grammar to keep in sync, and the first thing to drift.

    def submit_approval_request(
        self,
        session_id: str,
        requester: str,
        request_id: str,
        action: str,
        required_approvals: int,
        *,
        usage: Optional[StepUsage] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        """Open an N-of-M approval round. Only the session initiator may submit one (enforced by
        the mode engine, not the contract).

        ``required_approvals`` is the N: how many APPROVE ballots close the round.
        """
        req = pb.ApprovalRequestRequest(
            session_id=session_id,
            requester=requester,
            request_id=request_id,
            action=action,
            required_approvals=_u32(required_approvals, "required_approvals"),
        )
        if usage is not None:
            req.usage.CopyFrom(usage.to_pb())
        return self._coord.SubmitApprovalRequest(req, timeout=timeout)

    def submit_ballot(
        self,
        session_id: str,
        voter: str,
        request_id: str,
        choice: "pb.BallotChoice.ValueType",
        *,
        reason: str = "",
        usage: Optional[StepUsage] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        """Cast one ballot against an open approval request.

        ``choice`` is a :class:`BallotChoice` — ``BALLOT_CHOICE_APPROVE`` / ``_REJECT`` /
        ``_ABSTAIN``. One RPC covers all three: the three upstream MACP payloads are structurally
        identical, and the tag is what selects the wire envelope. ``BALLOT_CHOICE_UNSPECIFIED`` is
        not a vote — passing it is the server's INVALID_ARGUMENT to raise.
        """
        req = pb.BallotRequest(
            session_id=session_id,
            voter=voter,
            request_id=request_id,
            choice=choice,
            reason=reason,
        )
        if usage is not None:
            req.usage.CopyFrom(usage.to_pb())
        return self._coord.SubmitBallot(req, timeout=timeout)

    def resume_session(
        self,
        session_id: str,
        *,
        budget: int = 0,
        raise_: Optional[BudgetLimits] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        """**Deprecated / tombstone.** Resume moved to the **management** plane (rt-D): this data-plane RPC
        now returns ``PERMISSION_DENIED`` ("call SeamAdmin.ResumeSession"). Use
        :meth:`SeamAdminClient.resume_session` (the R9 approver action) with an operator token instead.
        Retained only so an old caller gets a clear, typed error rather than a missing attribute.
        ``budget`` follows the proto's semantics: 0 means the server default, currently 32."""
        warnings.warn(
            "SeamClient.resume_session is a tombstone: resume moved to the management plane "
            "(SeamAdmin.ResumeSession) — use SeamAdminClient.resume_session with an operator token",
            DeprecationWarning,
            stacklevel=2,
        )
        req = pb.ResumeRequest(session_id=session_id, budget=budget)
        if raise_ is not None:
            # `raise` is a Python keyword, so the generated field is reached via getattr.
            getattr(req, "raise").CopyFrom(raise_.to_pb())
        return self._coord.ResumeSession(req, timeout=timeout)

    def cancel_session(
        self, session_id: str, *, timeout: float = DEFAULT_TIMEOUT_S
    ) -> pb.TerminalResponse:
        return self._coord.CancelSession(
            pb.SessionRef(session_id=session_id), timeout=timeout
        )

    def expire_session(
        self, session_id: str, *, timeout: float = DEFAULT_TIMEOUT_S
    ) -> pb.TerminalResponse:
        return self._coord.ExpireSession(
            pb.SessionRef(session_id=session_id), timeout=timeout
        )

    def session_status(
        self, session_id: str, *, timeout: float = DEFAULT_TIMEOUT_S
    ) -> pb.SessionStatusResponse:
        return self._coord.SessionStatus(
            pb.SessionRef(session_id=session_id), timeout=timeout
        )

    def get_decision(
        self, decision_id: str, *, timeout: float = DEFAULT_TIMEOUT_S
    ) -> pb.DecisionRecordView:
        return self._coord.GetDecision(
            pb.DecisionRef(decision_id=decision_id), timeout=timeout
        )

    def replay_decision(
        self, decision_id: str, *, timeout: float = DEFAULT_TIMEOUT_S
    ) -> pb.ReplayView:
        return self._coord.ReplayDecision(
            pb.DecisionRef(decision_id=decision_id), timeout=timeout
        )

    def report_outcome(
        self,
        decision_id: str,
        correct: bool,
        verified_by: Optional[str] = None,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> bool:
        """Report a delayed correctness outcome for a sealed decision (advisory, Plan R). The sealed
        record is never mutated; this only emits a LEARNING_OUTCOME. ``verified_by`` records the source
        (downstream system / reviewer). Returns whether it was recorded. NOT_FOUND if the id is unknown."""
        req = pb.ReportOutcomeRequest(decision_id=decision_id, correct=correct)
        if verified_by is not None:
            req.verified_by = verified_by
        return self._coord.ReportOutcome(req, timeout=timeout).recorded

    # ── Context binding (data plane) ─────────────────────────────────────────────────────────────

    def register_context(
        self,
        content: bytes,
        fidelity: str,
        derived_from: Optional[Sequence[str]] = None,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> str:
        """Register context content at a given ``fidelity`` (``Digest`` | ``Reference`` | ``Value``);
        returns its content ref (a ``sha256:`` ref or an ``acdp://`` remote id)."""
        return self._context.RegisterContext(
            pb.RegisterContextRequest(
                content=content,
                fidelity=fidelity,
                derived_from=list(derived_from or []),
            ),
            timeout=timeout,
        ).content_ref

    def resolve_context(
        self, refs: Sequence[str], *, timeout: float = DEFAULT_TIMEOUT_S
    ) -> Sequence[pb.ContextBinding]:
        """Resolve context refs to their bindings.

        Returns the generated `ContextBinding` unchanged. Nothing is projected or renamed here, so
        every field the contract carries arrives — including the ACDP receipt slots (`content_hash`,
        `receipt_hash`, `key_status`, `resolved_status`) and `retraction`, which this SDK passes
        through without interpreting. `key_status` (closed, PascalCase) and `resolved_status` (open,
        lowercase) are byte-identical to what enters the `context_digest` preimage — do not
        case-fold, normalise or map them.
        """
        return list(
            self._context.ResolveContext(
                pb.ResolveContextRequest(refs=list(refs)), timeout=timeout
            ).bindings
        )

    # ── Trust / verification (data plane) ────────────────────────────────────────────────────────

    def issuer_aid(self, *, timeout: float = DEFAULT_TIMEOUT_S) -> str:
        return self._trust.IssuerAid(pb.Empty(), timeout=timeout).issuer_aid

    def verify_commitment(
        self,
        commitment: pb.Commitment,
        signed_artifact: bytes,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> bool:
        """Server-side verification of a rooted commitment (the ``SeamTrust`` path). For zero-server-trust
        verification prefer :meth:`verify_decision`, which verifies locally against a pinned issuer."""
        return self._trust.VerifyCommitment(
            pb.VerifyCommitmentRequest(
                commitment=commitment, signed_artifact=signed_artifact
            ),
            timeout=timeout,
        ).valid

    def verify_party_anchor(
        self, party_id: str, anchor: pb.Anchor, *, timeout: float = DEFAULT_TIMEOUT_S
    ) -> bool:
        """Verify a counterparty's published audit-chain anchor (network mode)."""
        return self._trust.VerifyPartyAnchor(
            pb.VerifyAnchorRequest(party_id=party_id, anchor=anchor), timeout=timeout
        ).valid

    def verify_party_attestation(
        self,
        party_id: str,
        attestation: ev.ChainHeadAttestation,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> bool:
        """Verify a counterparty's signed chain-head attestation against the registry-pinned key (A14
        network mode). Returns ``True`` iff the attestation's Ed25519 signature checks out against the
        pubkey registered for ``party_id``; ``False`` for an unknown party or any tamper (a boolean
        verdict, never an exception) — mirroring :meth:`verify_party_anchor`."""
        return self._trust.VerifyPartyAttestation(
            pb.VerifyAttestationRequest(party_id=party_id, attestation=attestation),
            timeout=timeout,
        ).valid

    def get_commitment_proof(
        self, decision_id: str, *, timeout: float = DEFAULT_TIMEOUT_S
    ) -> pb.CommitmentProof:
        return self._coord.GetCommitmentProof(
            pb.DecisionRef(decision_id=decision_id), timeout=timeout
        )

    def verify_decision(
        self,
        decision_id: str,
        expected_issuer: str,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> bool:
        """Fetch a sealed decision's proof and verify its rooted TCT locally — zero server trust.

        `expected_issuer` is the issuer AID the caller **pinned out of band** (or TOFU-cached). The TCT is
        verified against it, and the server-supplied `proof.issuer_aid` must match — so a malicious server
        cannot substitute its own key. Get the issuer once via `issuer_aid()` and pin it; never trust the
        per-response issuer as the verification anchor.

        Returns ``True`` iff the rooted TCT is cryptographically valid for the pinned issuer, ``False`` for
        an ordinary invalid decision. Raises :class:`IssuerMismatchError` when the proof's issuer AID does
        not match `expected_issuer` — a distinct security signal (an attempted key substitution), never
        downgraded to a bland ``False``. Mirrors the Rust reference's distinct ``ClientError::Crypto``.
        """
        proof = self.get_commitment_proof(decision_id, timeout=timeout)
        if proof.issuer_aid != expected_issuer:
            raise IssuerMismatchError(proof.issuer_aid, expected_issuer)
        c = proof.commitment
        commitment = {
            "id": c.id,
            "action": c.action,
            "authority": c.authority,
            "auth_method": c.auth_method,
            "trust_basis": c.trust_basis,
            "supersedes": c.supersedes or "",
        }
        return verify_tct(expected_issuer, c.signed_artifact.decode(), commitment)
