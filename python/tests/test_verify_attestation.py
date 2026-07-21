"""`verify_party_attestation` — the A14 network-mode counterparty check.

Two layers:
  * server-free unit tests that stub `_trust`, proving the wrapper builds the right request and returns the
    server's boolean verdict (never raises on a `false`);
  * an env-gated live round-trip (register a counterparty key on the management plane, then verify a valid
    / tampered / unknown attestation on the data plane), mirroring the runtime's own A4 trio
    (`seamd/tests/grpc.rs::grpc_verify_party_attestation_trio`).

The live valid case pins the runtime's committed `chain_head_attestation` KAT (seed + precomputed
signature) so the test does not re-derive the signature framing — a known-good signature from the runtime
is the gold standard. Regenerated from seam-runtime conformance_vectors.json `chain_head_attestation`.
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
from types import SimpleNamespace

import pytest

import seam_sdk.client  # noqa: F401  — importing wires the generated `_gen` stubs onto sys.path
from seam.api.v1 import seam_pb2 as pb  # noqa: E402
from seam_sdk import SeamAdminClient, SeamClient  # noqa: E402

# ── The runtime chain_head_attestation KAT (seam-client/tests/conformance_vectors.json) ───────────────
# The counterparty signs with the ed25519 key derived from this seed; the signature is over the
# domain-separated, length-prefixed preimage in docs/specs/seam-event.v1.md §CHAIN_HEAD_ATTESTATION. We
# register the derived pubkey and submit the attestation verbatim — the `issuer_aid` string is part of the
# signed preimage, so it is passed exactly as the KAT has it (short `aid:pubkey:` form).
_KAT_ISSUER_SEED = bytes.fromhex("07" * 32)
_KAT_ATTESTATION = dict(
    attested_len=1000,
    attested_head=bytes.fromhex("ab" * 32),
    attested_at=1700000000000,
    issuer_aid="aid:pubkey:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw",
    digest_schema=2,
    signature=bytes.fromhex(
        "5169458689b92af81fbbfbd1bd07aff82cb68993919837232a1b54204a0e565e"
        "e58791b607c40a48dae6a9dbf8c6129e7028fdbd0e14095d7a4c0a99c775a90a"
    ),
)


def _kat_attestation() -> pb.ChainHeadAttestation:
    return pb.ChainHeadAttestation(**_KAT_ATTESTATION)


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

    def VerifyPartyAttestation(self, req):  # noqa: N802 — mirrors the generated stub method name
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


def _wait(port: int, timeout: float = 8.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.1).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"server never came up on {port}")


@pytest.fixture
def dual_plane():
    """Spawn seam-grpc with BOTH the data plane (VerifyPartyAttestation) and the management plane
    (RegisterParty) bound; yields (data_addr, mgmt_addr). Skips without SEAM_GRPC_BIN."""
    binary = os.environ.get("SEAM_GRPC_BIN")
    if not binary:
        pytest.skip("set SEAM_GRPC_BIN to run the live attestation round-trip")
    data_port, mgmt_port = 8103, 8104
    proc = subprocess.Popen(
        [binary],
        env={
            **os.environ,
            "SEAM_GRPC_LISTEN": f"127.0.0.1:{data_port}",
            "SEAM_GRPC_MGMT_LISTEN": f"127.0.0.1:{mgmt_port}",
            "SEAM_DEV_INSECURE": "1",
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait(data_port)
        _wait(mgmt_port)
        yield f"127.0.0.1:{data_port}", f"127.0.0.1:{mgmt_port}"
    finally:
        proc.terminate()


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
