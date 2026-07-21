"""Client-side crypto for the Seam SDK — pure stock primitives (Ed25519 + SHA-256), no AITP binding.

The admission proof-of-possession is Ed25519 over SHA-256 of a documented, domain-separated canonical
byte layout (RFC-AITP-0002 §3); the seed never leaves the client. Conformance vectors in
``conformance/vectors.json`` (generated from the Rust reference) pin the exact bytes.
"""

from __future__ import annotations

import base64
import hashlib
import struct
import uuid

import json
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_PROOF_DOMAIN = b"aitp-pinned-key-v1\x00"


def _b64url_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def aid_from_pubkey(pubkey: bytes) -> str:
    """The agent's ``aid:pubkey:ed25519:`` identity for a 32-byte Ed25519 public key."""
    return "aid:pubkey:ed25519:" + _b64url_nopad(pubkey)


def build_presentation(
    agent_seed: bytes, receiver_aid: str, pop_nonce: str, now_ms: int
) -> dict:
    """Build the pinned-key admission presentation the Seam server verifies.

    ``proof = base64url(Ed25519_sign( SHA256( domain || sender_aid \\0 || receiver_aid \\0 ||
    message_id \\0 || timestamp_be_i64 \\0 || b64url_decode(pop_nonce) ) ))``.
    """
    sk = Ed25519PrivateKey.from_private_bytes(agent_seed)
    pub = sk.public_key().public_bytes_raw()
    sender_aid = aid_from_pubkey(pub)

    # message_id: deterministic from the nonce (no RNG); raw 16 bytes, not version-munged.
    mid = uuid.UUID(
        bytes=hashlib.sha256(b"seam-pop-mid" + pop_nonce.encode("ascii")).digest()[:16]
    )
    timestamp = now_ms // 1000

    proof_input = (
        _PROOF_DOMAIN
        + sender_aid.encode()
        + b"\x00"
        + receiver_aid.encode()
        + b"\x00"
        + str(mid).encode()
        + b"\x00"
        + struct.pack(">q", timestamp)
        + b"\x00"
        + _b64url_decode(pop_nonce)
    )
    proof = _b64url_nopad(sk.sign(hashlib.sha256(proof_input).digest()))

    return {
        "sender_aid": sender_aid,
        "descriptor": {
            "type": "pinned_key",
            "subject": sender_aid,
            "proof": proof,
            "public_key": _b64url_nopad(pub),
        },
        "message_id": str(mid),
        "timestamp": timestamp,
        "pop_nonce": pop_nonce,
    }


def _aid_to_pubkey(aid: str) -> bytes:
    """Recover the 32-byte Ed25519 public key embedded in an `aid:pubkey:[ed25519:]<43-b64url>`."""
    for prefix in ("aid:pubkey:ed25519:", "aid:pubkey:"):
        if aid.startswith(prefix):
            return _b64url_decode(aid[len(prefix) :])
    raise ValueError(f"unsupported AID form: {aid!r}")


def _seam_commitment_digest(commitment: dict) -> str:
    """SHA-256 (hex) over a length-prefixed framing of a domain tag + the commitment fields.

    Each field is prefixed with its 8-byte big-endian byte length (no separator), so the digest is
    injective over `(domain, id, action, authority, supersedes, auth_method, trust_basis)` regardless of
    content — a `\\0` separator would let boundary-shifted fields collide. Mirrors the runtime byte-for-byte.
    """
    h = hashlib.sha256()
    for field in (
        b"seam-commitment-digest:v1",
        commitment["id"].encode(),
        commitment["action"].encode(),
        commitment["authority"].encode(),
        (commitment.get("supersedes") or "").encode(),
        commitment["auth_method"].encode(),
        commitment["trust_basis"].encode(),
    ):
        h.update(len(field).to_bytes(8, "big"))
        h.update(field)
    return h.hexdigest()


def verify_tct(
    issuer_aid: str, tct_jws: str, commitment: dict, now_s: int | None = None
) -> bool:
    """Independently verify a sealed commitment's rooted TCT — zero server trust, stock crypto only.

    Verifies the EdDSA JWS against the issuer's key (recovered from its AID), checks the self-issued
    claims (`typ`, `iss==sub==aud==issuer_aid`, `exp`), and that the bound `seam-commitment-digest` grant
    matches this exact commitment (tamper-evidence over the decided content + committer attribution).
    """
    # Any malformed/forged input must fail closed (return False), never raise.
    try:
        parts = tct_jws.split(".")
        if len(parts) != 3:
            return False
        header_b64, payload_b64, sig_b64 = parts
        Ed25519PublicKey.from_public_bytes(_aid_to_pubkey(issuer_aid)).verify(
            _b64url_decode(sig_b64), f"{header_b64}.{payload_b64}".encode("ascii")
        )
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        if header.get("alg") != "EdDSA" or header.get("typ") != "aitp-tct+jwt":
            return False
        if not (
            payload.get("iss") == payload.get("sub") == payload.get("aud") == issuer_aid
        ):
            return False
        now = now_s if now_s is not None else int(time.time())
        if now >= int(payload.get("exp", 0)):  # RFC 7519: reject at/after expiry
            return False
        want = "seam-commitment-digest:" + _seam_commitment_digest(commitment)
        return want in payload.get("grants", [])
    except Exception:
        return False


# ── A14 authenticity framing (seam-event.v1) ─────────────────────────────────────────────────────────
# frame(x) = u32le(len(x)) || x ; opt(x) = 0x00 if None else 0x01 || frame(x). Both transcribed from
# `seam-event.v1.md`; they let a client verify a chain-head attestation or recompute a v2 record digest
# in-language, from the published spec alone (the same framing the independent `verify/` tool uses).


def _frame(b: bytes) -> bytes:
    return struct.pack("<I", len(b)) + b


def _opt(s: str | None) -> bytes:
    return b"\x00" if s is None else b"\x01" + _frame(s.encode("utf-8"))


def record_digest_v2(
    decision_id: str,
    tenant: str,
    namespace: str,
    ciphertext_digest: bytes,
    sealed_at: int,
    outcome: str,
    mode: str | None,
    policy_version: str | None,
    supersedes: str | None,
    schema_version: int = 2,
) -> bytes:
    """Recompute a v2 ``DECISION_SEALED`` record digest (``seam.audit.record-digest.v2``) from its on-wire
    structural columns + ``ciphertext_digest`` (SHA256(ciphertext), tag 10). Compare to the event's wire
    ``digest`` (tag 19) to catch a payload rewrite. Preimage order is NOT wire-tag order: ``outcome``
    precedes the optional ``mode``/``policy_version``/``supersedes``; the ``opt`` presence byte is raw, so
    ``None`` and ``""`` are distinct."""
    pre = (
        _frame(b"seam.audit.record-digest.v2")
        + _frame(decision_id.encode())
        + _frame(tenant.encode())
        + _frame(namespace.encode())
        + _frame(ciphertext_digest)
        + _frame(struct.pack("<Q", sealed_at))
        + _frame(outcome.encode())
        + _opt(mode)
        + _opt(policy_version)
        + _opt(supersedes)
        + _frame(struct.pack("<I", schema_version))
    )
    return hashlib.sha256(pre).digest()


def _chain_head_attestation_digest(
    attested_len: int,
    attested_head: bytes,
    attested_at: int,
    digest_schema: int,
    issuer_aid: str,
) -> bytes:
    """The 32-byte digest a ``CHAIN_HEAD_ATTESTATION`` signs over (``seam.audit.chain-head-attestation.v1``)."""
    pre = (
        _frame(b"seam.audit.chain-head-attestation.v1")
        + _frame(struct.pack("<Q", attested_len))
        + _frame(attested_head)
        + _frame(struct.pack("<Q", attested_at))
        + _frame(struct.pack("<I", digest_schema))
        + _frame(issuer_aid.encode())
    )
    return hashlib.sha256(pre).digest()


def verify_chain_head_attestation(
    issuer_aid: str,
    attested_len: int,
    attested_head: bytes,
    attested_at: int,
    digest_schema: int,
    signature: bytes,
) -> bool:
    """Verify a chain-head attestation's Ed25519 signature against the PINNED issuer AID (A14). Returns
    ``True`` iff the signature checks out over the recomputed digest; ``False`` on any tamper. The key comes
    from ``issuer_aid`` (which the caller pinned out of band), never from the attestation itself."""
    digest = _chain_head_attestation_digest(
        attested_len, attested_head, attested_at, digest_schema, issuer_aid
    )
    try:
        Ed25519PublicKey.from_public_bytes(_aid_to_pubkey(issuer_aid)).verify(
            signature, digest
        )
        return True
    except Exception:
        return False
