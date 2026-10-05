"""`verify_party_anchor`'s `tenant` parameter (seam-sdk#172 / seam-runtime #903 Phase 3).

Two layers, mirroring `test_verify_attestation.py`:
  * server-free unit tests that stub `_trust`, proving the wrapper defaults `tenant` to `""` when
    omitted and forwards it verbatim when given — for both the sync and async clients;
  * an env-gated live round-trip (register a counterparty key on the management plane under a
    tenant-bound operator, then verify a valid / tampered / unknown / wrong-tenant anchor on the
    data plane).

Unlike `verify_party_attestation`'s `ChainHeadAttestation`, which carries its own `tenant` field,
`Anchor` is deliberately tenant-agnostic (`seam-runtime/docs/specs/audit-anchor.md`) — tenant lives on
`VerifyAnchorRequest` itself, a sibling of `party_id`/`anchor`. And unlike that KAT-pinned test, no
conformance vector exists for `Anchor` (`conformance/vectors.json` has no `anchor` key): the signing
payload — `SHA256(chain_head || little_endian_u64(timestamp_millis))`, then a detached Ed25519
signature over that digest — has no domain separator or framing ambiguity, so this test self-signs.

Because `register_party`'s gRPC/facade layer refuses a fleet-wide (no-tenant-claim) operator since
seam-runtime #903 Phase 1, a live test can no longer register an UNtenanted party at all — the
"defaults to the untenanted partition" guarantee is proven by the server-free unit tests above instead.
"""

from __future__ import annotations

import asyncio
import hashlib
import struct
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from live_server import spawn_server
from operator_token import REGISTRY_SNAPSHOT_PATH, mint_operator_token, sign_snapshot

from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk import SeamAdminClient, SeamClient
from seam_sdk.aio import SeamClient as AioSeamClient

#: Any tenant id — `register_party` takes none on the wire (the operator token's own `tenant` claim is
#: what the runtime binds to; see `RegisterPartyRequest`), so this pins AUTH, not a registration scope.
_TENANT = "verify-anchor-counterparties"


# ── A self-signed Anchor — no conformance vector needed (see module docstring) ──────────────────────


def _anchor_payload(chain_head: bytes, timestamp_millis: int) -> bytes:
    return hashlib.sha256(chain_head + struct.pack("<Q", timestamp_millis)).digest()


def _signed_anchor(
    sk: Ed25519PrivateKey,
    *,
    chain_head: bytes = b"h" * 32,
    timestamp_millis: int = 1_700_000_000_000,
) -> pb.Anchor:
    signature = sk.sign(_anchor_payload(chain_head, timestamp_millis))
    return pb.Anchor(
        chain_head=chain_head, timestamp_millis=timestamp_millis, signature=signature
    )


def _pubkey(sk: Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


# ── Unit: the wrapper contract, server-free ──────────────────────────────────────────────────────────


class _RecordingTrust:
    """A fake `SeamTrust` stub: records the request and returns a preset `valid`."""

    def __init__(self, valid: bool):
        self._valid = valid
        self.seen: pb.VerifyAnchorRequest | None = None

    def VerifyPartyAnchor(self, req, **_kw):  # noqa: N802 — mirrors the generated stub method name
        self.seen = req
        return SimpleNamespace(valid=self._valid)


class _AioRecordingTrust:
    """Async twin of `_RecordingTrust`."""

    def __init__(self, valid: bool):
        self._valid = valid
        self.seen: pb.VerifyAnchorRequest | None = None

    async def VerifyPartyAnchor(self, req, **_kw):  # noqa: N802
        self.seen = req
        return SimpleNamespace(valid=self._valid)


def _client_with_trust(trust) -> SeamClient:
    client = SeamClient.connect("127.0.0.1:1")  # lazy insecure channel; never dialed
    client._trust = trust  # type: ignore[attr-defined]
    return client


def _aio_client_with_trust(trust) -> AioSeamClient:
    client = AioSeamClient.connect("127.0.0.1:1")  # lazy insecure channel; never dialed
    client._trust = trust  # type: ignore[attr-defined]
    return client


def test_verify_party_anchor_defaults_tenant_to_empty():
    """Omitting `tenant` sends `""` — byte-identical to every pre-existing caller's wire bytes."""
    trust = _RecordingTrust(valid=True)
    client = _client_with_trust(trust)
    anchor = _signed_anchor(Ed25519PrivateKey.generate())

    assert client.verify_party_anchor("bank-A", anchor) is True
    assert isinstance(trust.seen, pb.VerifyAnchorRequest)
    assert trust.seen.party_id == "bank-A"
    assert trust.seen.tenant == ""
    assert trust.seen.anchor.chain_head == anchor.chain_head


def test_verify_party_anchor_forwards_explicit_tenant():
    trust = _RecordingTrust(valid=True)
    client = _client_with_trust(trust)
    anchor = _signed_anchor(Ed25519PrivateKey.generate())

    assert client.verify_party_anchor("bank-A", anchor, tenant="acme") is True
    assert trust.seen.tenant == "acme"


def test_verify_party_anchor_false_never_raises():
    """A `false` verdict (unknown party / tamper / wrong tenant) is surfaced as False, not raised."""
    client = _client_with_trust(_RecordingTrust(valid=False))
    anchor = _signed_anchor(Ed25519PrivateKey.generate())
    assert client.verify_party_anchor("bank-A", anchor, tenant="acme") is False


async def _aio_scenario() -> None:
    anchor = _signed_anchor(Ed25519PrivateKey.generate())

    trust = _AioRecordingTrust(valid=True)
    client = _aio_client_with_trust(trust)
    assert await client.verify_party_anchor("bank-A", anchor) is True
    assert trust.seen.tenant == ""

    trust = _AioRecordingTrust(valid=True)
    client = _aio_client_with_trust(trust)
    assert await client.verify_party_anchor("bank-A", anchor, tenant="acme") is True
    assert trust.seen.tenant == "acme"

    trust = _AioRecordingTrust(valid=False)
    client = _aio_client_with_trust(trust)
    assert await client.verify_party_anchor("bank-A", anchor, tenant="acme") is False

    await client.close()


def test_async_verify_party_anchor_default_and_explicit_tenant() -> None:
    asyncio.run(_aio_scenario())


# ── Live: register (mgmt plane) → verify (data plane), env-gated ────────────────────────────────────


@pytest.fixture
def dual_plane(tmp_path):
    """Spawn seam-grpc with BOTH the data plane (VerifyPartyAnchor, dev-open) and the management plane
    (RegisterParty) bound; yields (data_addr, mgmt_addr). Skips without SEAM_GRPC_BIN.

    The mgmt plane installs the `operator_keys` trust root (signed, since it's trust-bearing — see
    `operator_token.sign_snapshot`): `register_party` refuses a fleet-wide operator since seam-runtime
    #903 Phase 1, so a dev-open plane with no token can no longer exercise it. The data plane is
    unaffected — `operator_keys` is the trust root for the management plane only, so
    `VerifyPartyAnchor` stays dev-open as before."""
    pubkey, sig_path = sign_snapshot(REGISTRY_SNAPSHOT_PATH)
    with spawn_server(
        mgmt=True,
        log_dir=tmp_path,
        env_extra={
            "SEAM_REGISTRY_SNAPSHOT": REGISTRY_SNAPSHOT_PATH,
            "SEAM_REGISTRY_SNAPSHOT_SIG": sig_path,
            "SEAM_SNAPSHOT_PUBKEY": pubkey,
        },
    ) as srv:
        yield srv.data_addr, srv.mgmt_addr


def test_verify_party_anchor_trio_live(dual_plane):
    """Registered party + untampered anchor + matching tenant -> True; tampered signature / tampered
    field / unknown party / wrong tenant / omitted tenant -> False."""
    data_addr, mgmt_addr = dual_plane
    data = SeamClient.connect(data_addr)
    sk = Ed25519PrivateKey.generate()

    # register_party is authority-establishing (rt-D) and, since seam-runtime #903 Phase 1, refuses a
    # fleet-wide operator — it needs a tenant-bound `grant:create` token (the request itself carries no
    # tenant field; the runtime binds to the token's own `tenant` claim).
    admin = SeamAdminClient.connect(
        mgmt_addr, token=mint_operator_token(["grant:create"], tenant=_TENANT)
    )
    admin.register_party("bank-A", _pubkey(sk))

    # Unlike `verify_party_attestation` (whose tenant lives on the ATTESTATION message), `Anchor` is
    # tenant-agnostic: the tenant is the caller's own argument, a sibling of `party_id`/`anchor`. It
    # must match the registration tenant (_TENANT) or an otherwise-valid anchor still comes back False,
    # having been looked up in the wrong partition.

    # 1. a registered party's untampered anchor, with the matching tenant, verifies
    anchor = _signed_anchor(sk)
    assert data.verify_party_anchor("bank-A", anchor, tenant=_TENANT) is True

    # 2. a tampered signature must not verify
    bad_sig = _signed_anchor(sk)
    tampered = bytearray(bad_sig.signature)
    tampered[0] ^= 0x01
    bad_sig.signature = bytes(tampered)
    assert data.verify_party_anchor("bank-A", bad_sig, tenant=_TENANT) is False

    # 3. a tampered field (timestamp_millis is part of the signed preimage) must not verify
    bad_field = _signed_anchor(sk)
    bad_field.timestamp_millis += 1
    assert data.verify_party_anchor("bank-A", bad_field, tenant=_TENANT) is False

    # 4. an unknown party never verifies
    assert data.verify_party_anchor("bank-B", anchor, tenant=_TENANT) is False

    # 5. a different (registered, even) tenant never verifies this party's anchor
    assert (
        data.verify_party_anchor("bank-A", anchor, tenant="some-other-tenant") is False
    )

    # 6. omitting tenant defaults to "" (the untenanted partition) — also wrong for this party
    assert data.verify_party_anchor("bank-A", anchor) is False
