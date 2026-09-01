"""`verify_party_attestation` — the A14 network-mode counterparty check.

Two layers:
  * server-free unit tests that stub `_trust`, proving the wrapper builds the right request and returns the
    server's boolean verdict (never raises on a `false`);
  * an env-gated live round-trip (register a counterparty key on the management plane, then verify a valid
    / tampered / unknown attestation on the data plane), mirroring the runtime's own A4 trio
    (`seamd/tests/grpc.rs::grpc_verify_party_attestation_trio`).

The live valid case pins the runtime's committed `chain_head_attestation` KAT (seed + precomputed
signature) so the test does not re-derive the signature framing — a known-good signature from the runtime
is the gold standard. Loaded from `conformance/vectors.json`'s `chain_head_attestation` entry — the SAME
source `test_conformance.py::test_chain_head_attestation_signature_verifies` reads — so a runtime KAT
regen updates one file and reddens both tests, instead of leaving a hand-copied literal here silently
stale.
"""

from __future__ import annotations

import json
import pathlib
from types import SimpleNamespace

import pytest

from live_server import spawn_server

from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk._gen.seam.event.v1 import seam_event_pb2 as ev
from seam_sdk import SeamAdminClient, SeamClient  # noqa: E402

# ── The runtime chain_head_attestation KAT, from conformance/vectors.json ────────────────────────────
# The counterparty signs with the ed25519 key derived from this seed; the signature is over the
# domain-separated, length-prefixed preimage in docs/specs/seam-event.v1.md §CHAIN_HEAD_ATTESTATION. We
# register the derived pubkey and submit the attestation verbatim — the `issuer_aid` string is part of the
# signed preimage, so it is passed exactly as the vector has it (short `aid:pubkey:` form).
_VECTOR = json.loads(
    (pathlib.Path(__file__).parents[2] / "conformance" / "vectors.json").read_text()
)["chain_head_attestation"]
_KAT_ISSUER_SEED = bytes.fromhex(_VECTOR["inputs"]["issuer_seed_hex"])
_KAT_ATTESTATION = dict(
    attested_len=_VECTOR["inputs"]["attested_len"],
    attested_head=bytes.fromhex(_VECTOR["inputs"]["attested_head_hex"]),
    attested_at=_VECTOR["inputs"]["attested_at"],
    issuer_aid=_VECTOR["issuer_aid"],
    digest_schema=_VECTOR["inputs"]["digest_schema"],
    signature=bytes.fromhex(_VECTOR["signature_hex"]),
)


def _kat_attestation() -> ev.ChainHeadAttestation:
    return ev.ChainHeadAttestation(**_KAT_ATTESTATION)


def _kat_pubkey() -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return (
        Ed25519PrivateKey.from_private_bytes(_KAT_ISSUER_SEED)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


# ── Unit: the wrapper contract, server-free ───────────────────────────────────────────────────────────


class _RecordingTrust:
    """A fake `SeamTrust` stub: records the request and returns a preset `valid`."""

    def __init__(self, valid: bool):
        self._valid = valid
        self.seen: pb.VerifyAttestationRequest | None = None

    def VerifyPartyAttestation(self, req, **_kw):  # noqa: N802 — mirrors the generated stub method name
        self.seen = req
        return SimpleNamespace(valid=self._valid)


def _client_with_trust(trust) -> SeamClient:
    client = SeamClient.connect("127.0.0.1:1")  # lazy insecure channel; never dialed
    client._trust = trust  # type: ignore[attr-defined]
    return client


def test_wrapper_builds_request_and_returns_true():
    trust = _RecordingTrust(valid=True)
    client = _client_with_trust(trust)
    att = _kat_attestation()

    assert client.verify_party_attestation("bank-A", att) is True
    # The wrapper wrapped the id + attestation into a VerifyAttestationRequest, unchanged.
    assert isinstance(trust.seen, pb.VerifyAttestationRequest)
    assert trust.seen.party_id == "bank-A"
    assert trust.seen.attestation.attested_len == att.attested_len
    assert trust.seen.attestation.signature == att.signature


def test_wrapper_returns_false_never_raises():
    """A `false` verdict (unknown party / tamper) is surfaced as False, not an exception."""
    client = _client_with_trust(_RecordingTrust(valid=False))
    assert client.verify_party_attestation("bank-A", _kat_attestation()) is False


# ── Live: register (mgmt plane) → verify (data plane), env-gated ─────────────────────────────────────


@pytest.fixture
def dual_plane(tmp_path):
    """Spawn seam-grpc with BOTH the data plane (VerifyPartyAttestation) and the management plane
    (RegisterParty) bound; yields (data_addr, mgmt_addr). Skips without SEAM_GRPC_BIN."""
    with spawn_server(mgmt=True, log_dir=tmp_path) as srv:
        yield srv.data_addr, srv.mgmt_addr


def test_verify_party_attestation_trio_live(dual_plane):
    """Registered party + untampered KAT → True; tampered signature / tampered field / unknown → False."""
    data_addr, mgmt_addr = dual_plane
    data = SeamClient.connect(data_addr)
    admin = SeamAdminClient.connect(mgmt_addr)

    admin.register_party("bank-A", _kat_pubkey())

    # 1. a registered party's untampered attestation verifies
    assert data.verify_party_attestation("bank-A", _kat_attestation()) is True

    # 2. a tampered signature must not verify
    bad_sig = _kat_attestation()
    tampered = bytearray(bad_sig.signature)
    tampered[0] ^= 0x01
    bad_sig.signature = bytes(tampered)
    assert data.verify_party_attestation("bank-A", bad_sig) is False

    # 3. a tampered field (the length is part of the signed preimage) must not verify
    bad_field = _kat_attestation()
    bad_field.attested_len += 1
    assert data.verify_party_attestation("bank-A", bad_field) is False

    # 4. an unknown party never verifies
    assert data.verify_party_attestation("bank-B", _kat_attestation()) is False
