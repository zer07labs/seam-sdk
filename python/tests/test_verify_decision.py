"""`verify_decision` must surface an issuer-AID mismatch as a DISTINCT signal, not a bland False.

A malicious server that swaps the issuer key (a key-substitution attempt) must be distinguishable from an
ordinary cryptographically-invalid decision — otherwise the security signal is silently downgraded. These
tests run server-free: `get_commitment_proof` is stubbed, so only the local verification contract is
exercised. Mirrors the Rust reference's distinct `ClientError::Crypto("issuer AID mismatch…")`.
"""

import json
import pathlib
from types import SimpleNamespace

import pytest

from seam_sdk import IssuerMismatchError, SeamClient, SeamError

VECTORS = json.loads(
    (pathlib.Path(__file__).parents[2] / "conformance" / "vectors.json").read_text()
)


def _client_with_proof(proof) -> SeamClient:
    """A client whose `get_commitment_proof` returns `proof` — no channel I/O ever happens."""
    client = SeamClient.connect("127.0.0.1:1")  # lazy insecure channel; never dialed
    client.get_commitment_proof = lambda _decision_id: proof  # type: ignore[method-assign]
    return client


def _proof_from_vectors(issuer_aid: str, *, action: str | None = None):
    """A stub `CommitmentProof` built from the conformance TCT vector, carrying `issuer_aid`.

    `action` overrides the committed action; a wrong value makes the commitment digest miss the TCT's
    grant, i.e. an ordinary invalid (tampered) decision — with the signature still well-formed.
    """
    t = VECTORS["tct"]
    c = t["inputs"]["commitment"]
    commitment = SimpleNamespace(
        id=c["id"],
        action=action if action is not None else c["action"],
        authority=c["authority"],
        auth_method=c["auth_method"],
        trust_basis=c["trust_basis"],
        supersedes=c.get("supersedes", ""),
        signed_artifact=t["signed_artifact_jws"].encode(),
    )
    return SimpleNamespace(issuer_aid=issuer_aid, commitment=commitment)


def test_issuer_mismatch_raises_distinct_error():
    """A swapped issuer key raises IssuerMismatchError — NOT a bland False."""
    server_issuer = VECTORS["tct"]["issuer_aid"]
    pinned = "aid:pubkey:ed25519:" + "A" * 43  # what the caller pinned out of band
    client = _client_with_proof(_proof_from_vectors(server_issuer))

    with pytest.raises(IssuerMismatchError) as ei:
        client.verify_decision("dec-1", pinned)

    # The distinct signal is typed, subclasses the SDK error base, and carries both AIDs — never a False.
    assert isinstance(ei.value, SeamError)
    assert ei.value.proof_issuer == server_issuer
    assert ei.value.expected_issuer == pinned


def test_invalid_tct_returns_false_not_raise():
    """When the issuer AID matches but the TCT is invalid, it's an ordinary False — no error."""
    issuer = VECTORS["tct"]["issuer_aid"]
    # Issuer matches the pin, so we pass the mismatch gate; the tampered action ⇒ digest miss ⇒ invalid.
    client = _client_with_proof(_proof_from_vectors(issuer, action="TAMPERED"))
    assert client.verify_decision("dec-1", issuer) is False
