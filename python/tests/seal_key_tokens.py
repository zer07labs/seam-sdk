"""Test helper: mint a seam-runtime #2031 (deep-cleanup S-4) seal-key commitment TCT.

The issuer key certifies a short-lived seal key once (``seal_key_cert``); the TCT is a self-attestation
by the seal key and carries the certificate as a second ``ext`` member. Every knob a refusal test needs
(window, ``iat``, the certificate's issuer AID, trailing bytes, the ``ext`` member) is a parameter, so a
negative changes exactly one thing over a token that otherwise verifies.
"""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CERT_EXT_KEY = "com.zer07labs.seam.seal-key-cert"
DOMAIN = b"seam.seal-key-cert.v1"
MAX_WINDOW_MS = 3_630_000


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def framed(b: bytes) -> bytes:
    return len(b).to_bytes(4, "little") + b


def pk(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def untagged_aid(seed: bytes) -> str:
    return "aid:pubkey:" + b64(pk(seed))


def seeded_seal_seed(issuer_seed: bytes) -> bytes:
    """The runtime's test derivation (``SeededSealKeys``): ``sha256("seam.seal-key.fixed.v1" ‖ seed)``."""
    return hashlib.sha256(b"seam.seal-key.fixed.v1" + issuer_seed).digest()


def jkt(key: bytes) -> str:
    jwk = '{"crv":"Ed25519","kty":"OKP","x":"' + b64(key) + '"}'
    return b64(hashlib.sha256(jwk.encode()).digest())


def cert_bytes(seal_pk: bytes, nb: int, na: int, issuer_aid: str) -> bytes:
    return (
        framed(DOMAIN)
        + framed(seal_pk)
        + nb.to_bytes(8, "little")
        + na.to_bytes(8, "little")
        + framed(issuer_aid.encode())
    )


def cert_member(
    issuer_seed: bytes,
    seal_seed: bytes,
    nb: int,
    na: int,
    issuer_aid: str | None = None,
    trailing: bytes = b"",
) -> dict:
    aid = issuer_aid if issuer_aid is not None else untagged_aid(issuer_seed)
    cert = cert_bytes(pk(seal_seed), nb, na, aid) + trailing
    sig = Ed25519PrivateKey.from_private_bytes(issuer_seed).sign(
        hashlib.sha256(cert).digest()
    )
    return {"cert": b64(cert), "sig": b64(sig)}


def sign(seed: bytes, header: dict | bytes, payload: dict | bytes) -> str:
    h = header if isinstance(header, bytes) else json.dumps(header).encode()
    p = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    si = f"{b64(h)}.{b64(p)}"
    return f"{si}.{b64(Ed25519PrivateKey.from_private_bytes(seed).sign(si.encode()))}"


def mint(
    issuer_seed: bytes,
    statement: dict,
    *,
    seal_seed: bytes | None = None,
    nb: int = 1_700_000_000_000,
    na: int = 1_700_000_900_000,
    iat: object = 1_700_000_000,
    exp: object = 4_000_000_000,
    issuer_aid: str | None = None,
    trailing: bytes = b"",
    member: dict | None = None,
    extra_ext: dict | None = None,
    edit=None,
) -> str:
    """A seal-key TCT over ``statement``; valid unless a knob says otherwise."""
    seal = seal_seed if seal_seed is not None else seeded_seal_seed(issuer_seed)
    seal_aid = untagged_aid(seal)
    m = (
        member
        if member is not None
        else cert_member(issuer_seed, seal, nb, na, issuer_aid, trailing)
    )
    payload = {
        "ver": "aitp/0.3",
        "iss": seal_aid,
        "sub": seal_aid,
        "aud": seal_aid,
        "cnf": {"jkt": jkt(pk(seal))},
        "iat": iat,
        "exp": exp,
        "grants": ["aitp.attestation"],
        "ext": {"com.zer07labs.seam": statement, CERT_EXT_KEY: m, **(extra_ext or {})},
    }
    if edit is not None:
        edit(payload)
    return sign(seal, {"alg": "EdDSA", "typ": "aitp-tct+jwt"}, payload)
