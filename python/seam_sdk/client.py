"""Ergonomic Seam client over the generated gRPC stubs + the stock crypto shim.

`SeamClient.run_decision` owns the full binding path (admit via the pinned-key PoP, then decide+seal in
one call); `verify_decision` fetches a sealed decision's proof and verifies its rooted TCT locally — zero
server trust beyond the fetch.
"""

from __future__ import annotations

import json
import pathlib
import sys
from dataclasses import dataclass
from typing import Optional, Sequence

import grpc
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import aid_from_pubkey, build_presentation, verify_tct

# The generated transport stubs (`buf generate` writes them into the package at `seam_sdk/_gen`, so they
# ship with the wheel). Their internal imports are rooted at that dir (`from seam.api.v1 import ...`), so
# put it on the path — works both in the source tree and once installed.
_GEN = pathlib.Path(__file__).resolve().parent / "_gen"
if str(_GEN) not in sys.path:
    sys.path.insert(0, str(_GEN))
from seam.api.v1 import seam_pb2 as pb  # noqa: E402
from seam.api.v1 import seam_pb2_grpc as rpc  # noqa: E402


def _now_ms() -> int:
    import time

    return int(time.time() * 1000)


class Agent:
    """An agent identity — a 32-byte seed that derives the pinned AID and signs the admission PoP."""

    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise ValueError("agent seed must be 32 bytes")
        self.seed = seed

    @property
    def aid(self) -> str:
        pub = (
            Ed25519PrivateKey.from_private_bytes(self.seed)
            .public_key()
            .public_bytes_raw()
        )
        return aid_from_pubkey(pub)


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
        self._admission = rpc.SeamAdmissionStub(channel)
        self._coord = rpc.SeamCoordinationStub(channel)
        self._trust = rpc.SeamTrustStub(channel)

    @classmethod
    def connect(cls, target: str) -> "SeamClient":
        return cls(grpc.insecure_channel(target))

    def _presentation(self, agent: Agent) -> pb.PinnedPresentation:
        ch = self._admission.IssueChallenge(pb.Empty())
        body = build_presentation(agent.seed, ch.receiver_aid, ch.nonce, _now_ms())
        return pb.PinnedPresentation(presentation_json=json.dumps(body).encode())

    def run_decision(
        self, agent: Agent, session_id: str, participants, votes
    ) -> pb.DecisionResponse:
        """Admit (the PoP handshake) → run a coordinated decision → seal, in one call."""
        return self._coord.RunDecision(
            pb.RunDecisionRequest(
                session_id=session_id,
                participants=list(participants),
                votes=[pb.Vote(agent=a, value=v) for a, v in votes],
                presentation=self._presentation(agent),
            )
        )

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
    ) -> pb.SessionStep:
        """Admit (the PoP handshake) → open an incremental session. ``budget`` is the legacy
        message count (0 ⇒ the server default 32); ``limits`` adds the other 6.2 dimensions."""
        req = pb.OpenSessionRequest(
            session_id=session_id,
            participants=list(participants),
            budget=budget,
            mode=mode,
            presentation=self._presentation(agent),
        )
        if limits is not None:
            req.limits.CopyFrom(limits.to_pb())
        return self._coord.OpenSession(req)

    def submit_proposal(
        self,
        session_id: str,
        proposer: str,
        proposal_id: str,
        option: str,
        *,
        usage: Optional[StepUsage] = None,
    ) -> pb.SessionStep:
        req = pb.ProposalRequest(
            session_id=session_id,
            proposer=proposer,
            proposal_id=proposal_id,
            option=option,
        )
        if usage is not None:
            req.usage.CopyFrom(usage.to_pb())
        return self._coord.SubmitProposal(req)

    def submit_vote(
        self,
        session_id: str,
        voter: str,
        proposal_id: str,
        value: str,
        *,
        usage: Optional[StepUsage] = None,
    ) -> pb.SessionStep:
        req = pb.VoteRequest(
            session_id=session_id,
            voter=voter,
            proposal_id=proposal_id,
            value=value,
        )
        if usage is not None:
            req.usage.CopyFrom(usage.to_pb())
        return self._coord.SubmitVote(req)

    def submit_commit(
        self,
        session_id: str,
        commitment_id: str,
        action: str,
        *,
        usage: Optional[StepUsage] = None,
    ) -> pb.SessionStep:
        req = pb.CommitRequest(
            session_id=session_id,
            commitment_id=commitment_id,
            action=action,
        )
        if usage is not None:
            req.usage.CopyFrom(usage.to_pb())
        return self._coord.SubmitCommit(req)

    def resume_session(
        self,
        session_id: str,
        *,
        budget: int = 32,
        raise_: Optional[BudgetLimits] = None,
    ) -> pb.SessionStep:
        """Resume a Suspended session (the R9 approver action). ``raise_`` raises any budget
        dimension; absent, ``budget`` raises the message count."""
        req = pb.ResumeRequest(session_id=session_id, budget=budget)
        if raise_ is not None:
            # `raise` is a Python keyword, so the generated field is reached via getattr.
            getattr(req, "raise").CopyFrom(raise_.to_pb())
        return self._coord.ResumeSession(req)

    def cancel_session(self, session_id: str) -> pb.TerminalResponse:
        return self._coord.CancelSession(pb.SessionRef(session_id=session_id))

    def expire_session(self, session_id: str) -> pb.TerminalResponse:
        return self._coord.ExpireSession(pb.SessionRef(session_id=session_id))

    def session_status(self, session_id: str) -> pb.SessionStatusResponse:
        return self._coord.SessionStatus(pb.SessionRef(session_id=session_id))

    def get_decision(self, decision_id: str) -> pb.DecisionRecordView:
        return self._coord.GetDecision(pb.DecisionRef(decision_id=decision_id))

    def replay_decision(self, decision_id: str) -> pb.ReplayView:
        return self._coord.ReplayDecision(pb.DecisionRef(decision_id=decision_id))

    def issuer_aid(self) -> str:
        return self._trust.IssuerAid(pb.Empty()).issuer_aid

    def get_commitment_proof(self, decision_id: str) -> pb.CommitmentProof:
        return self._coord.GetCommitmentProof(pb.DecisionRef(decision_id=decision_id))

    def verify_decision(self, decision_id: str, expected_issuer: str) -> bool:
        """Fetch a sealed decision's proof and verify its rooted TCT locally — zero server trust.

        `expected_issuer` is the issuer AID the caller **pinned out of band** (or TOFU-cached). The TCT is
        verified against it, and the server-supplied `proof.issuer_aid` must match — so a malicious server
        cannot substitute its own key. Get the issuer once via `issuer_aid()` and pin it; never trust the
        per-response issuer as the verification anchor.
        """
        proof = self.get_commitment_proof(decision_id)
        if proof.issuer_aid != expected_issuer:
            return False
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
