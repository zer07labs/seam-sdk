"""Ergonomic Seam client over the generated gRPC stubs + the stock crypto shim.

`SeamClient.run_decision` owns the full binding path (admit via the pinned-key PoP, then decide+seal in
one call); `verify_decision` fetches a sealed decision's proof and verifies its rooted TCT locally — zero
server trust beyond the fetch.
"""

from __future__ import annotations

import json
import pathlib
import sys

import grpc
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import aid_from_pubkey, build_presentation, verify_tct

# The generated transport stubs (produced by `buf generate` into ../gen/python).
_GEN = pathlib.Path(__file__).resolve().parents[2] / "gen" / "python"
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
        pub = Ed25519PrivateKey.from_private_bytes(self.seed).public_key().public_bytes_raw()
        return aid_from_pubkey(pub)


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

    def run_decision(self, agent: Agent, session_id: str, participants, votes) -> pb.DecisionResponse:
        """Admit (the PoP handshake) → run a coordinated decision → seal, in one call."""
        return self._coord.RunDecision(
            pb.RunDecisionRequest(
                session_id=session_id,
                participants=list(participants),
                votes=[pb.Vote(agent=a, value=v) for a, v in votes],
                presentation=self._presentation(agent),
            )
        )

    def get_decision(self, decision_id: str) -> pb.DecisionRecordView:
        return self._coord.GetDecision(pb.DecisionRef(decision_id=decision_id))

    def replay_decision(self, decision_id: str) -> pb.ReplayView:
        return self._coord.ReplayDecision(pb.DecisionRef(decision_id=decision_id))

    def issuer_aid(self) -> str:
        return self._trust.IssuerAid(pb.Empty()).issuer_aid

    def get_commitment_proof(self, decision_id: str) -> pb.CommitmentProof:
        return self._coord.GetCommitmentProof(pb.DecisionRef(decision_id=decision_id))

    def verify_decision(self, decision_id: str) -> bool:
        """Fetch a sealed decision's proof and verify its rooted TCT locally — zero server trust."""
        proof = self.get_commitment_proof(decision_id)
        c = proof.commitment
        commitment = {
            "id": c.id,
            "action": c.action,
            "authority": c.authority,
            "auth_method": c.auth_method,
            "trust_basis": c.trust_basis,
            "supersedes": c.supersedes or "",
        }
        return verify_tct(proof.issuer_aid, c.signed_artifact.decode(), commitment)
