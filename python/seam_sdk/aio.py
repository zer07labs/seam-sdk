"""Async Seam client on ``grpc.aio`` — the coroutine twin of :class:`seam_sdk.SeamClient`.

Every public method mirrors the sync client's signature plus ``timeout`` (propagated as the gRPC
deadline; the SDK never retries beyond ``authorize``'s single ticket refresh). The advisory-ticket
lifecycle shares the sync client's transport-agnostic core (:mod:`seam_sdk._authorize`), guarded here
by an ``asyncio.Lock`` — cancellation mid-``authorize`` can never corrupt the cache, because cache
mutations are synchronous and happen only after their RPC await has fully returned.
"""

from __future__ import annotations

import asyncio
import json
import warnings
from typing import Mapping, Optional, Sequence

import grpc
import grpc.aio

from ._authorize import (
    AuthorizeResult,
    TicketCache,
    _resolve_canonical,
    build_authorize_request,
    result_of,
)
from .client import (
    DEFAULT_TIMEOUT_S,
    Agent,
    BudgetLimits,
    StepUsage,
    _now_ms,
    _u32,
)
from .crypto import build_presentation, verify_tct
from .errors import IssuerMismatchError, UnauthenticatedError, map_rpc_error

from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc
from seam_sdk._gen.seam.event.v1 import seam_event_pb2 as ev  # noqa: F401  (re-exported)


class _MappedStream:
    """Wrap a ``grpc.aio`` streaming call so errors raised DURING consumption map to typed
    ``SeamRpcError``s — streaming failures surface at iteration time, not call time."""

    def __init__(self, call):
        self._call = call

    def __aiter__(self):
        return self._aiter()

    async def _aiter(self):
        try:
            async for item in self._call:
                yield item
        except grpc.RpcError as e:
            raise map_rpc_error(e) from e

    def cancel(self) -> bool:
        return self._call.cancel()


class _AioMappedStub:
    """The ``grpc.aio`` twin of :class:`seam_sdk.errors._MappedStub`.

    grpc.aio call objects are BOTH awaitable and iterable, so a naive try/except await-wrapper is
    wrong for streams — it would await a stream (a type error) or let consumption-time errors escape
    unmapped. The stub therefore dispatches on the multicallable type: unary-response methods return
    a coroutine that awaits and maps; stream-response methods return a :class:`_MappedStream` that
    maps during iteration.
    """

    def __init__(self, stub):
        object.__setattr__(self, "_stub", stub)

    def __getattr__(self, name):
        attr = getattr(self._stub, name)
        if isinstance(
            attr,
            (grpc.aio.UnaryStreamMultiCallable, grpc.aio.StreamStreamMultiCallable),
        ):

            def stream_call(*args, **kwargs):
                return _MappedStream(attr(*args, **kwargs))

            return stream_call
        if not callable(attr):
            return attr

        async def call(*args, **kwargs):
            try:
                return await attr(*args, **kwargs)
            except grpc.RpcError as e:
                raise map_rpc_error(e) from e

        return call


class SeamClient:
    """A high-level async client over a ``grpc.aio`` channel to a Seam server."""

    def __init__(self, channel: grpc.aio.Channel):
        self._ch = channel
        self._admission = _AioMappedStub(rpc.SeamAdmissionStub(channel))
        self._coord = _AioMappedStub(rpc.SeamCoordinationStub(channel))
        self._trust = _AioMappedStub(rpc.SeamTrustStub(channel))
        self._context = _AioMappedStub(rpc.SeamContextStub(channel))
        self._authz = _AioMappedStub(rpc.SeamAuthorizationStub(channel))
        # One cache AND one lock per agent AID — see the sync client for why per-AID rather than
        # one global lock. The per-AID locks are created lazily inside coroutines rather than here.
        #
        # That is NOT multi-loop safety, and it would be wrong to read it as such: `_registry_lock`
        # below is constructed here and guards every lookup, so the first loop to use this client
        # pins it, and a second loop raises "bound to a different event loop" no matter how lazily
        # the per-AID locks are made. A client is single-loop, exactly as it was when there was one
        # `_ticket_lock` — this change did not regress that, and does not fix it either. The failure
        # is loud rather than silent, which is why it is acceptable to leave.
        #
        # Since 3.10 (this package's floor) `asyncio.Lock()` no longer grabs the running loop at
        # construction, so building `_registry_lock` in `__init__` is safe on its own terms.
        self._tickets: dict = {}
        self._ticket_locks: dict = {}
        self._registry_lock = asyncio.Lock()

    @classmethod
    def connect(
        cls, target: str, *, credentials: Optional[grpc.ChannelCredentials] = None
    ) -> "SeamClient":
        """Connect to a Seam data-plane endpoint. Plaintext by default (the dev/loopback path); pass
        ``credentials=grpc.ssl_channel_credentials()`` (or a configured creds object) to use TLS."""
        channel = (
            grpc.aio.secure_channel(target, credentials)
            if credentials is not None
            else grpc.aio.insecure_channel(target)
        )
        return cls(channel)

    async def close(self) -> None:
        """Close the underlying channel. Idempotent — grpc.aio tolerates a repeated close, so
        ``async with`` plus a defensive explicit ``close()`` is safe."""
        await self._ch.close()

    async def __aenter__(self) -> "SeamClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def _presentation(
        self, agent: Agent, timeout: float = DEFAULT_TIMEOUT_S
    ) -> pb.PinnedPresentation:
        ch = await self._admission.IssueChallenge(pb.Empty(), timeout=timeout)
        body = build_presentation(agent.seed, ch.receiver_aid, ch.nonce, _now_ms())
        return pb.PinnedPresentation(presentation_json=json.dumps(body).encode())

    # ── Advisory authorization (1-RTT, unsealed) ────────────────────────────────────────────────

    async def admit(self, agent: Agent, *, timeout: float = DEFAULT_TIMEOUT_S) -> bytes:
        """Run the challenge→``Admit`` handshake now and cache the resulting admission ticket.
        :meth:`authorize` calls this lazily; an explicit ``admit`` only front-loads the handshake."""
        cache, lock = await self._cache_and_lock(agent.aid)
        async with lock:
            return await self._admit_locked(agent, cache, timeout)

    async def _cache_and_lock(self, aid: str):
        """The (cache, lock) pair for one agent identity, created on first use.

        ``_registry_lock`` guards the two dicts and NOTHING else — it is never held across an
        await of an RPC, only across two dict lookups.
        """
        async with self._registry_lock:
            cache = self._tickets.setdefault(aid, TicketCache())
            lock = self._ticket_locks.get(aid)
            if lock is None:
                lock = self._ticket_locks[aid] = asyncio.Lock()
            return cache, lock

    async def _admit_locked(
        self, agent: Agent, cache: TicketCache, timeout: float
    ) -> bytes:
        presentation = await self._presentation(agent, timeout)
        ticket = await self._admission.Admit(presentation, timeout=timeout)
        # The awaits above are the cancellation points; this mutation is synchronous, so a
        # cancelled admit leaves the cache in its previous consistent state, never half-written.
        cache.store(ticket.ticket, ticket.expires_at_ms, _now_ms())
        return ticket.ticket

    async def authorize(
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
        """Async twin of :meth:`seam_sdk.SeamClient.authorize` — one advisory
        ``(tool_name, tool_input) -> verdict`` question; 1 RTT steady-state, seals nothing.
        Ticket lifecycle: lazy admit, cached, refreshed at 80% TTL, retried exactly once on
        ``UNAUTHENTICATED``. An unknown verdict raises ``UnknownVerdictError`` — never an
        implicit allow.

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
        # Canonicalized ONCE, before the admit and outside the closure — see the sync twin in
        # client.py for why. It matters MORE here: an aio client is the one most likely to have
        # hundreds of authorizes genuinely in flight, so it has the widest window for a framework to
        # mutate a tool_input dict between the first attempt and the retry (seam-sdk#60).
        canonical = _resolve_canonical(tool_input, canonical)
        cache, lock = await self._cache_and_lock(agent.aid)
        async with lock:
            ticket = cache.get(_now_ms())
            if ticket is None:
                ticket = await self._admit_locked(agent, cache, timeout)

        def build(t: bytes) -> pb.AuthorizeRequest:
            # Rebuilt after a refresh — call_sig binds the ticket bytes, so it must be re-signed.
            # The canonical bytes are NOT rebuilt; that is the fix.
            return build_authorize_request(
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
            resp = await self._authz.Authorize(build(ticket), timeout=timeout)
        except UnauthenticatedError:
            ticket = await self._refresh_ticket(agent, ticket, timeout)
            resp = await self._authz.Authorize(build(ticket), timeout=timeout)
        return result_of(resp)

    async def _refresh_ticket(
        self, agent: Agent, failed: bytes, timeout: float
    ) -> bytes:
        """Re-admit after an ``UNAUTHENTICATED``, coalescing concurrent refreshes to ONE.

        The async twin of :meth:`seam_sdk.SeamClient._refresh_ticket`, and it matters MORE here:
        an aio client is the one most likely to have hundreds of authorizes genuinely in flight
        together, so a mass revocation fanned out to hundreds of simultaneous re-admits against
        the endpoint that was already the bottleneck.

        If the cache now holds a ticket that is not the one we failed on, another caller already
        refreshed and we use theirs.
        """
        cache, lock = await self._cache_and_lock(agent.aid)
        async with lock:
            current = cache.get(_now_ms())
            if current is not None and current != failed:
                return current
            cache.invalidate()
            return await self._admit_locked(agent, cache, timeout)

    # ── Coordination ────────────────────────────────────────────────────────────────────────────

    async def run_decision(
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
        See :meth:`seam_sdk.SeamClient.run_decision` for ``features`` and ``on_behalf_of``."""
        req = pb.RunDecisionRequest(
            session_id=session_id,
            participants=list(participants),
            votes=[pb.Vote(agent=a, value=v) for a, v in votes],
            presentation=await self._presentation(agent, timeout),
            on_behalf_of=list(on_behalf_of),
        )
        if features:
            req.features.update(features)
        return await self._coord.RunDecision(req, timeout=timeout)

    async def open_session(
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
        req = pb.OpenSessionRequest(
            session_id=session_id,
            participants=list(participants),
            budget=budget,
            mode=mode,
            presentation=await self._presentation(agent, timeout),
            on_behalf_of=list(on_behalf_of),
        )
        if limits is not None:
            req.limits.CopyFrom(limits.to_pb())
        return await self._coord.OpenSession(req, timeout=timeout)

    async def submit_proposal(
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
        return await self._coord.SubmitProposal(req, timeout=timeout)

    async def submit_vote(
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
        return await self._coord.SubmitVote(req, timeout=timeout)

    async def submit_evaluation(
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
        """Async twin of :meth:`seam_sdk.SeamClient.submit_evaluation`.

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
        return await self._coord.SubmitEvaluation(req, timeout=timeout)

    async def submit_objection(
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
        """Async twin of :meth:`seam_sdk.SeamClient.submit_objection`.

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
        return await self._coord.SubmitObjection(req, timeout=timeout)

    async def submit_commit(
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
        return await self._coord.SubmitCommit(req, timeout=timeout)

    # ── Quorum-mode-only steps (`macp.mode.quorum.v1`) ─────────────────────────────────────────
    # The async mirror of the sync client's pair. These two move in lockstep with `client.py` —
    # `test_sync_async_parity` asserts the two method inventories are equal as sets, because a
    # verb landing on one client and not the other is this package's standing drift hazard.

    async def submit_approval_request(
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
        return await self._coord.SubmitApprovalRequest(req, timeout=timeout)

    async def submit_ballot(
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
        return await self._coord.SubmitBallot(req, timeout=timeout)

    async def resume_session(
        self,
        session_id: str,
        *,
        budget: int = 0,
        raise_: Optional[BudgetLimits] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        """**Deprecated / tombstone** — see :meth:`seam_sdk.SeamClient.resume_session`. ``budget``
        follows the proto's semantics: 0 means the server default, currently 32."""
        warnings.warn(
            "seam_sdk.aio.SeamClient.resume_session is a tombstone: resume moved to the management "
            "plane (SeamAdmin.ResumeSession) — use SeamAdminClient.resume_session with an operator "
            "token",
            DeprecationWarning,
            stacklevel=2,
        )
        req = pb.ResumeRequest(session_id=session_id, budget=budget)
        if raise_ is not None:
            getattr(req, "raise").CopyFrom(raise_.to_pb())
        return await self._coord.ResumeSession(req, timeout=timeout)

    async def cancel_session(
        self, session_id: str, *, timeout: float = DEFAULT_TIMEOUT_S
    ) -> pb.TerminalResponse:
        return await self._coord.CancelSession(
            pb.SessionRef(session_id=session_id), timeout=timeout
        )

    async def expire_session(
        self, session_id: str, *, timeout: float = DEFAULT_TIMEOUT_S
    ) -> pb.TerminalResponse:
        return await self._coord.ExpireSession(
            pb.SessionRef(session_id=session_id), timeout=timeout
        )

    async def session_status(
        self, session_id: str, *, timeout: float = DEFAULT_TIMEOUT_S
    ) -> pb.SessionStatusResponse:
        return await self._coord.SessionStatus(
            pb.SessionRef(session_id=session_id), timeout=timeout
        )

    async def get_decision(
        self, decision_id: str, *, timeout: float = DEFAULT_TIMEOUT_S
    ) -> pb.DecisionRecordView:
        return await self._coord.GetDecision(
            pb.DecisionRef(decision_id=decision_id), timeout=timeout
        )

    async def replay_decision(
        self, decision_id: str, *, timeout: float = DEFAULT_TIMEOUT_S
    ) -> pb.ReplayView:
        return await self._coord.ReplayDecision(
            pb.DecisionRef(decision_id=decision_id), timeout=timeout
        )

    async def report_outcome(
        self,
        decision_id: str,
        correct: bool,
        verified_by: Optional[str] = None,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> bool:
        req = pb.ReportOutcomeRequest(decision_id=decision_id, correct=correct)
        if verified_by is not None:
            req.verified_by = verified_by
        return (await self._coord.ReportOutcome(req, timeout=timeout)).recorded

    # ── Context binding ─────────────────────────────────────────────────────────────────────────

    async def register_context(
        self,
        content: bytes,
        fidelity: str,
        derived_from: Optional[Sequence[str]] = None,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> str:
        return (
            await self._context.RegisterContext(
                pb.RegisterContextRequest(
                    content=content,
                    fidelity=fidelity,
                    derived_from=list(derived_from or []),
                ),
                timeout=timeout,
            )
        ).content_ref

    async def resolve_context(
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
            (
                await self._context.ResolveContext(
                    pb.ResolveContextRequest(refs=list(refs)), timeout=timeout
                )
            ).bindings
        )

    # ── Trust / verification ────────────────────────────────────────────────────────────────────

    async def issuer_aid(self, *, timeout: float = DEFAULT_TIMEOUT_S) -> str:
        return (await self._trust.IssuerAid(pb.Empty(), timeout=timeout)).issuer_aid

    async def verify_commitment(
        self,
        commitment: pb.Commitment,
        signed_artifact: bytes,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> bool:
        return (
            await self._trust.VerifyCommitment(
                pb.VerifyCommitmentRequest(
                    commitment=commitment, signed_artifact=signed_artifact
                ),
                timeout=timeout,
            )
        ).valid

    async def verify_party_anchor(
        self, party_id: str, anchor: pb.Anchor, *, timeout: float = DEFAULT_TIMEOUT_S
    ) -> bool:
        return (
            await self._trust.VerifyPartyAnchor(
                pb.VerifyAnchorRequest(party_id=party_id, anchor=anchor),
                timeout=timeout,
            )
        ).valid

    async def verify_party_attestation(
        self,
        party_id: str,
        attestation: ev.ChainHeadAttestation,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> bool:
        return (
            await self._trust.VerifyPartyAttestation(
                pb.VerifyAttestationRequest(party_id=party_id, attestation=attestation),
                timeout=timeout,
            )
        ).valid

    async def get_commitment_proof(
        self, decision_id: str, *, timeout: float = DEFAULT_TIMEOUT_S
    ) -> pb.CommitmentProof:
        return await self._coord.GetCommitmentProof(
            pb.DecisionRef(decision_id=decision_id), timeout=timeout
        )

    async def verify_decision(
        self,
        decision_id: str,
        expected_issuer: str,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> bool:
        """Async twin of :meth:`seam_sdk.SeamClient.verify_decision` — zero-server-trust local TCT
        verification against the caller-pinned issuer; raises :class:`IssuerMismatchError` on an
        attempted key substitution."""
        proof = await self.get_commitment_proof(decision_id, timeout=timeout)
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
