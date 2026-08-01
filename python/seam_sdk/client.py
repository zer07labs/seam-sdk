"""Ergonomic Seam client over the generated gRPC stubs + the stock crypto shim.

`SeamClient.run_decision` owns the full binding path (admit via the pinned-key PoP, then decide+seal in
one call); `verify_decision` fetches a sealed decision's proof and verifies its rooted TCT locally — zero
server trust beyond the fetch.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from typing import Dict, Mapping, Optional, Sequence

import grpc
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._authorize import (
    AuthorizeResult,
    TicketCache,
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


# Every public method takes ``timeout`` (seconds) and propagates it as the gRPC deadline. The SDK never
# retries beyond the single ticket refresh in ``authorize`` — adapters own retry semantics. A deadline
# breach surfaces as ``DeadlineExceededError``, distinct from a DENY verdict.
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
        # Admission-ticket lifecycle (advisory Authorize path): one cache per agent AID, all guarded
        # by one lock — admit-once, refresh at 80% TTL, retry exactly once on UNAUTHENTICATED.
        self._tickets: Dict[str, TicketCache] = {}
        self._ticket_lock = threading.Lock()

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
        with self._ticket_lock:
            cache = self._tickets.setdefault(agent.aid, TicketCache())
            return self._admit_locked(agent, cache, timeout)

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
        digest_only: bool = False,
        features: Optional[Mapping[str, str]] = None,
        session_id: str = "",
        subject: str = "",
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
        """
        ticket = self._ticket_for(agent, timeout)
        build = lambda t: build_authorize_request(  # noqa: E731 — rebuilt on refresh (new call_sig)
            ticket=t,
            agent_seed=agent.seed,
            tool_name=tool_name,
            tool_input=tool_input,
            digest_only=digest_only,
            features=features,
            session_id=session_id,
            subject=subject,
            agent_id=agent_id,
            client_request_id=client_request_id,
        )
        try:
            resp = self._authz.Authorize(build(ticket), timeout=timeout)
        except UnauthenticatedError:
            # Expired/rejected ticket: refresh once, retry once. A second failure propagates typed.
            with self._ticket_lock:
                cache = self._tickets.setdefault(agent.aid, TicketCache())
                cache.invalidate()
                ticket = self._admit_locked(agent, cache, timeout)
            resp = self._authz.Authorize(build(ticket), timeout=timeout)
        return result_of(resp)

    def _ticket_for(self, agent: Agent, timeout: float) -> bytes:
        with self._ticket_lock:
            cache = self._tickets.setdefault(agent.aid, TicketCache())
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
        budget: int = 32,
        limits: Optional[BudgetLimits] = None,
        mode: str = "",
        on_behalf_of: Sequence[str] = (),
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        """Admit (the PoP handshake) → open an incremental session. ``budget`` is the legacy
        message count (0 ⇒ the server default 32); ``limits`` adds the other 6.2 dimensions.
        ``on_behalf_of`` binds end-user data subjects to the session (see :meth:`run_decision`)."""
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

    def resume_session(
        self,
        session_id: str,
        *,
        budget: int = 32,
        raise_: Optional[BudgetLimits] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        """**Deprecated / tombstone.** Resume moved to the **management** plane (rt-D): this data-plane RPC
        now returns ``PERMISSION_DENIED`` ("call SeamAdmin.ResumeSession"). Use
        :meth:`SeamAdminClient.resume_session` (the R9 approver action) with an operator token instead.
        Retained only so an old caller gets a clear, typed error rather than a missing attribute."""
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
        """Resolve context refs to their bindings (fidelity, classification, lineage, version)."""
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
