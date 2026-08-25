"""Test-only operator-token minter — simulates a control-plane-minted management token.

The management plane authenticates compact-JWS **operator tokens** against the `operator_keys` trust root
installed from a `SEAM_REGISTRY_SNAPSHOT` (rt-D / CP-18d; the shared `SEAM_MGMT_TOKEN` bearer was removed
in seam-runtime #175). This mints one exactly as the runtime's own auth tests do, with the golden operator
key whose PUBLIC half is pinned in `conformance/registry_snapshot_operator_keys.json` — so a runtime
spawned with that snapshot (and no shared token) accepts these tokens and refuses everything else.

The SEED is a well-known TEST key; a real deployment's operator keys are minted by the control plane.
"""

from __future__ import annotations

import base64
import json
import pathlib
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# The golden operator key (seed → the public_key_hex pinned in the snapshot fixture's `operator_keys`).
# Matches seam-runtime/crates/seamd/tests/scoped_auth_grpc.rs (SEED_HEX / PUBKEY_HEX).
_SEED_HEX = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
_PUBKEY_HEX = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"

#: Path to the operator-keys registry snapshot to hand the runtime via ``SEAM_REGISTRY_SNAPSHOT``.
REGISTRY_SNAPSHOT_PATH = str(
    pathlib.Path(__file__).parents[2]
    / "conformance"
    / "registry_snapshot_operator_keys.json"
)


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def mint_operator_token(
    scopes: list[str], *, aud: str = "seam-runtime", ttl_secs: int = 600
) -> str:
    """A valid compact-JWS operator token carrying ``scopes``, signed by the golden operator key. Verifies
    against a runtime that installed the sibling snapshot fixture. ``aud`` defaults to the runtime audience;
    ``ttl_secs`` sets ``exp = iat + ttl_secs``."""
    iat = int(time.time())
    header = json.dumps(
        {"alg": "EdDSA", "typ": "JWT", "kid": _PUBKEY_HEX}, separators=(",", ":")
    )
    payload = json.dumps(
        {
            "sub": "op-test",
            "scopes": scopes,
            "aud": aud,
            "iat": iat,
            "exp": iat + ttl_secs,
        },
        separators=(",", ":"),
    )
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


def sign_snapshot(snapshot_path: str) -> tuple[str, str]:
    """Detach-sign a registry snapshot so the runtime will actually install it.

    Returns ``(pubkey_hex, sig_path)`` for ``SEAM_SNAPSHOT_PUBKEY`` and
    ``SEAM_REGISTRY_SNAPSHOT_SIG``.

    **Why this exists.** A snapshot carrying a trust-bearing section — ``operator_keys``,
    ``capability_registry`` or ``namespaces`` — must be signature-verified before the runtime installs
    it, and a current runtime **refuses to boot** without that (`REFUSING TO BOOT — … carries a
    trust-bearing section but SEAM_SNAPSHOT_PUBKEY is not set`). Anyone who can influence the file
    could otherwise install their own operator key and own the management plane.

    Every fixture here spawned an UNSIGNED snapshot, so on a current runtime the server never came up
    and three tests failed. Nobody noticed because the CI job that runs these has never executed
    (see the note on `integration` in `.github/workflows/ci.yml`).

    ``SEAM_ALLOW_UNSIGNED_SNAPSHOT=1`` would also have worked and is the wrong choice: it is the
    runtime's own migration escape hatch, explicitly scoped to preserving a pre-cutover posture during
    the signing rollout. Signing here instead means these tests exercise the path production actually
    uses, and they will not break when that hatch is removed.

    The signing key is deliberately **not** the operator key. Snapshot-signature verification is
    independent of the snapshot's own ``operator_keys`` trust root, so using a separate key keeps the
    two concerns from appearing coupled — the same separation the live deployment made when it minted
    a dedicated snapshot-signing key rather than reusing the operator seed.
    """
    data = pathlib.Path(snapshot_path).read_bytes()
    sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))  # well-known TEST key
    # Written to a temp file rather than committed next to the snapshot: a checked-in signature goes
    # stale the moment anyone edits the snapshot, and a stale signature fails as `refuses to boot`,
    # which reads like this bug rather than like the edit that caused it.
    sig = pathlib.Path(tempfile.mkdtemp(prefix="seam-snap-")) / "snapshot.sig"
    sig.write_text(sk.sign(data).hex())
    return sk.public_key().public_bytes_raw().hex(), str(sig)
