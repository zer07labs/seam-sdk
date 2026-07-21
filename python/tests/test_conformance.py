"""The Python crypto shim must reproduce the Rust reference bytes exactly.

Vectors are generated from `seam-runtime` (`cargo run -p seam-client --example conformance_vectors`) and
pin the admission proof-of-possession the Seam server verifies. If this passes, the shim authenticates
against a real server.
"""

import json
import pathlib

from seam_sdk.crypto import aid_from_pubkey, build_presentation, verify_tct

VECTORS = json.loads(
    (pathlib.Path(__file__).parents[2] / "conformance" / "vectors.json").read_text()
)


def test_pinned_key_presentation_is_byte_exact():
    adm = VECTORS["admission"]
    i = adm["inputs"]
    got = build_presentation(
        bytes.fromhex(i["agent_seed_hex"]),
        i["receiver_aid"],
        i["pop_nonce"],
        i["now_ms"],
    )
    assert got == adm["presentation"]


def test_aid_derivation_matches():
    adm = VECTORS["admission"]
    seed = bytes.fromhex(adm["inputs"]["agent_seed_hex"])
    # Re-derive the public key from the seed and check the AID against the reference.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    assert aid_from_pubkey(pub) == adm["derived"]["sender_aid"]


def test_tct_verify_valid_and_tampered():
    t = VECTORS["tct"]
    c = t["inputs"]["commitment"]
    assert (
        verify_tct(t["issuer_aid"], t["signed_artifact_jws"], c, now_s=1_700_000_001)
        is True
    )
    assert (
        verify_tct(
            t["issuer_aid"],
            t["signed_artifact_jws"],
            {**c, "action": "ALLOW"},
            now_s=1_700_000_001,
        )
        is False
    )


def test_tct_verify_fails_closed():
    t = VECTORS["tct"]
    c, jws, iss = t["inputs"]["commitment"], t["signed_artifact_jws"], t["issuer_aid"]
    h, p, s = jws.split(".")
    cases = {
        "expired": (iss, jws, 9_999_999_999),
        "not-3-parts": (iss, "not.a", 1_700_000_001),
        "wrong-issuer-key": ("aid:pubkey:ed25519:" + "A" * 43, jws, 1_700_000_001),
        "unsupported-aid": ("did:web:example.com", jws, 1_700_000_001),
        "tampered-signature": (iss, f"{h}.{p}.{s[:-4]}AAAA", 1_700_000_001),
    }
    for name, (issuer, token, now) in cases.items():
        assert verify_tct(issuer, token, c, now_s=now) is False, (
            f"{name} must fail closed"
        )


def test_record_digest_v2_matches_reference():
    """The v2 record-digest framing must reproduce the Rust reference byte-for-byte (A14 design-a)."""
    from seam_sdk.crypto import record_digest_v2

    v = VECTORS["record_digest_v2"]
    i = v["inputs"]
    got = record_digest_v2(
        i["decision_id"],
        i["tenant"],
        i["namespace"],
        bytes.fromhex(i["ciphertext_digest_hex"]),
        i["sealed_at"],
        i["outcome"],
        i["mode"],
        i["policy_version"],
        i["supersedes"],
        i["schema_version"],
    )
    assert got.hex() == v["digest_hex"]


def test_chain_head_attestation_signature_verifies():
    """The chain-head attestation must verify against the pinned issuer AID, and a tamper must not (A14)."""
    from seam_sdk.crypto import verify_chain_head_attestation

    v = VECTORS["chain_head_attestation"]
    i = v["inputs"]
    ok = verify_chain_head_attestation(
        v["issuer_aid"],
        i["attested_len"],
        bytes.fromhex(i["attested_head_hex"]),
        i["attested_at"],
        i["digest_schema"],
        bytes.fromhex(v["signature_hex"]),
    )
    assert ok is True
    # A tampered length must not verify (it is bound into the signed preimage).
    assert (
        verify_chain_head_attestation(
            v["issuer_aid"],
            i["attested_len"] + 1,
            bytes.fromhex(i["attested_head_hex"]),
            i["attested_at"],
            i["digest_schema"],
            bytes.fromhex(v["signature_hex"]),
        )
        is False
    )
