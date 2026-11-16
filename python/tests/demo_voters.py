"""Demo voter proofs for the LIVE suites (seam-runtime #1687, runtime 0.87.0).

A runtime since #1687 refuses every vote, ballot and objection that does not carry its voter's
``seam-voter-pop-v1`` proof — there is no flag and no dev bypass. Under ``SEAM_DEV_INSECURE`` it binds
the demo agents' **public, deterministic** demo voter keys in the demo namespace
(``seamd::voters::demo_voter_seed``, bound by ``Seam::with_demo_enrolment``) — as public as the demo
identity itself, which is why this lives in ``tests/`` and never in ``seam_sdk``. A deployment enrols each
voter's own key with ``seam-enroll-pop-v2`` (``Agent.enrolment_proof(..., participant_id=)``).

:class:`DemoVotingClient` is a :class:`SeamClient` that signs every vote it sends WITHOUT a proof with
that demo key, using only what the SDK's public API exposes: it records what each session opened with
(participants, ``on_behalf_of``, mode, and the ``SessionStep.opened_at_millis`` the runtime returns) and
what each proposal proposed, then builds the address the spec defines
(``docs/specs/voter-verification.v1.md``, "The vote address"). A vote that already carries a proof is
left alone, so a test of the refusal path passes its own (or calls the plain ``SeamClient``).
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any, Optional, Sequence

from seam_sdk import (
    SeamClient,
    VoterPopTarget,
    sign_voter_pop,
    vote_content_digest,
)

DEMO_TENANT = "design-partner"
DEMO_NAMESPACE = "design-partner/fraud"
DECISION_MODE = "macp.mode.decision.v1"


def demo_voter_seed(
    participant: str, tenant: str = DEMO_TENANT, namespace: str = DEMO_NAMESPACE
) -> bytes:
    """``seamd::voters::demo_voter_seed``: SHA-256 over u32-LE length-framed parts."""
    h = hashlib.sha256()
    for part in (
        b"seam-demo-voter-seed-v1",
        tenant.encode(),
        namespace.encode(),
        participant.encode(),
    ):
        h.update(struct.pack("<I", len(part)))
        h.update(part)
    return h.digest()


class DemoVotingClient(SeamClient):
    """A :class:`SeamClient` that signs unsigned votes with the demo voter keys (see module doc)."""

    def _demo_init(self) -> None:
        if not hasattr(self, "_demo_sessions"):
            self._demo_sessions: dict[str, dict[str, Any]] = {}
            self._demo_issuer: Optional[str] = None

    def _issuer(self) -> str:
        self._demo_init()
        if self._demo_issuer is None:
            self._demo_issuer = self.issuer_aid()
        return self._demo_issuer

    def _target(self, session_id: str, opened_at_millis: int) -> VoterPopTarget:
        return VoterPopTarget(
            issuer=self._issuer(),
            tenant=DEMO_TENANT,
            namespace=DEMO_NAMESPACE,
            session_id=session_id,
            opened_at_millis=opened_at_millis,
        )

    # ── one-shot ─────────────────────────────────────────────────────────────────────────────────

    def run_decision(self, agent, session_id, participants, votes, *args, **kwargs):  # type: ignore[override]
        votes = list(votes)
        if votes and all(isinstance(v, tuple) and len(v) in (2, 3) for v in votes):
            # Spec: a one-shot opens and seals in one call, so it is addressed `(session_id, 0)`; its
            # content is `votes[0].value`, its proposal `p1`, its mode the decision mode.
            target = self._target(session_id, 0)
            content = vote_content_digest(
                DECISION_MODE,
                "p1",
                votes[0][1],
                list(participants),
                list(kwargs.get("on_behalf_of", ())),
                # One-shot: the request features, canonical; policy 0x00 (server-resolved).
                features=dict(kwargs.get("features") or {}),
            )
            signed = []
            for v in votes:
                agent_id, value = v[0], v[1]
                reason = v[2] if len(v) == 3 else ""
                entry = {
                    "kind": "vote",
                    "participant": agent_id,
                    "proposal_id": "p1",
                    "value": value,
                    "reason": reason,
                }
                pop = sign_voter_pop(demo_voter_seed(agent_id), target, content, entry)
                signed.append((agent_id, value, reason, pop))
            votes = signed
        return super().run_decision(
            agent, session_id, participants, votes, *args, **kwargs
        )

    # ── the session path ─────────────────────────────────────────────────────────────────────────

    def open_session(
        self, agent, session_id: str, participants: Sequence[str], **kwargs
    ):  # type: ignore[override]
        step = super().open_session(agent, session_id, participants, **kwargs)
        self._demo_init()
        self._demo_sessions[session_id] = {
            "participants": list(participants),
            "on_behalf_of": list(kwargs.get("on_behalf_of", ())),
            "mode": kwargs.get("mode") or DECISION_MODE,
            "opened_at_millis": step.opened_at_millis,
            # Session path: the policy the session bound at open, exactly as the open step reports it.
            "policy": step.vote_policy if step.HasField("vote_policy") else None,
            "proposals": {},
            "proofs": {},
        }
        return step

    def submit_proposal(
        self, session_id: str, proposer: str, proposal_id: str, option: str, **kwargs
    ):  # type: ignore[override]
        step = super().submit_proposal(
            session_id, proposer, proposal_id, option, **kwargs
        )
        self._demo_init()
        if session_id in self._demo_sessions:
            self._demo_sessions[session_id]["proposals"][proposal_id] = option
        return step

    def submit_vote(
        self, session_id: str, voter: str, proposal_id: str, value: str, **kwargs
    ):  # type: ignore[override]
        self._demo_init()
        s = self._demo_sessions.get(session_id)
        if (
            kwargs.get("proof") is None
            and s is not None
            and proposal_id in s["proposals"]
        ):
            content = vote_content_digest(
                s["mode"],
                proposal_id,
                s["proposals"][proposal_id],
                s["participants"],
                s["on_behalf_of"],
                policy=s["policy"],
            )
            entry = {
                "kind": "vote",
                "participant": voter,
                "proposal_id": proposal_id,
                "value": value,
                "reason": kwargs.get("reason", ""),
            }
            # One proof per logical vote, as a real caller's retry re-sends the SAME bytes: a fresh
            # `issued_at` per call would make an app-level resend a different request, not a replay.
            key = (voter, proposal_id, value, entry["reason"])
            if key not in s["proofs"]:
                s["proofs"][key] = sign_voter_pop(
                    demo_voter_seed(voter),
                    self._target(session_id, s["opened_at_millis"]),
                    content,
                    entry,
                )
            kwargs["proof"] = s["proofs"][key]
        return super().submit_vote(session_id, voter, proposal_id, value, **kwargs)
