"""Test-only operator-token minter — simulates a control-plane-minted management token.

The management plane authenticates compact-JWS **operator tokens** against the `operator_keys` of the
signed governing root (seam-runtime #1156; the shared `SEAM_MGMT_TOKEN` bearer was removed in #175). This
mints one exactly as the runtime's own auth tests do, with the golden operator key whose PUBLIC half the
default root carries (`governing_root.OPERATOR_KEYS`) — so a runtime spawned by `live_server.spawn_server`
accepts these tokens and refuses everything else.

The SEED is a well-known TEST key; a real deployment's operator keys are minted by the control plane.
"""

from __future__ import annotations

import base64
import json
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# The golden operator key (seed → the public_key_hex pinned in the snapshot fixture's `operator_keys`).
# Matches seam-runtime/crates/seamd/tests/scoped_auth_grpc.rs (SEED_HEX / PUBKEY_HEX).
_SEED_HEX = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
_PUBKEY_HEX = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def mint_operator_token(
    scopes: list[str],
    *,
    aud: str = "seam-runtime",
    ttl_secs: int = 600,
    tenant: str | None = None,
) -> str:
    """A valid compact-JWS operator token carrying ``scopes``, signed by the golden operator key. Verifies
    against a runtime that installed the sibling snapshot fixture. ``aud`` defaults to the runtime audience;
    ``ttl_secs`` sets ``exp = iat + ttl_secs``.

    ``tenant``, when given, binds the token to that tenant (U-RT-6) — required since seam-runtime #903
    Phase 1 for any operator calling ``register_party``/``remove_party``, which now refuse a fleet-wide
    (no-tenant-claim) operator (seam-runtime's own `scoped_auth_grpc.rs::mint_with_tenant`). Omitted (the
    default) for a fleet-wide token, byte-identical to the pre-#903 shape."""
    iat = int(time.time())
    header = json.dumps(
        {"alg": "EdDSA", "typ": "JWT", "kid": _PUBKEY_HEX}, separators=(",", ":")
    )
    claims = {
        "sub": "op-test",
        "scopes": scopes,
        "aud": aud,
        "iat": iat,
        "exp": iat + ttl_secs,
        # A fresh jti on every mint: a destructive-scope verb requires one and burns it (seam-runtime
        # testing.rs `demo_operator_bearer`), so mint per destructive request.
        "jti": uuid.uuid4().hex,
    }
    if tenant is not None:
        claims["tenant"] = tenant
    payload = json.dumps(claims, separators=(",", ":"))
    signing = f"{_b64url(header.encode())}.{_b64url(payload.encode())}"
    sig = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(_SEED_HEX)).sign(
        signing.encode("ascii")
    )
    return f"{signing}.{_b64url(sig)}"


def tamper_signature(token: str) -> str:
    """Return ``token`` with its JWS signature corrupted — same 64-byte length (so this exercises the
    signature-VERIFICATION path, not a length check), a flipped bit making it invalid."""
    head, sig_b64 = token.rsplit(".", 1)
    sig = bytearray(base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4)))
    sig[0] ^= 0x01
    return f"{head}.{_b64url(bytes(sig))}"
