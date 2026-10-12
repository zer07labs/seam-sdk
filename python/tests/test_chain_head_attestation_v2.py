"""seam-runtime #835: the v2 chain-head attestation framing (tenant inside the signature), and the
step-4 strict dispatch — an empty tenant verifies under v1 only, a non-empty one under v2 only.

Pinned against ``conformance/chain_head_attestation_v2_vector.json``, vendored verbatim from the
runtime's ``crates/seam-client/tests/conformance_vectors_extended.json`` (``chain_head_attestation_v2``).
The shared v1 block in ``conformance/vectors.json`` is untouched — it is a byte-identity contract.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from seam_sdk.crypto import (
    CHAIN_HEAD_ATTESTATION_DOMAIN_V2,
    _chain_head_attestation_digest,
    verify_chain_head_attestation,
)

ROOT = pathlib.Path(__file__).resolve().parents[2] / "conformance"
V2 = json.loads((ROOT / "chain_head_attestation_v2_vector.json").read_text())
V1 = json.loads((ROOT / "vectors.json").read_text())["chain_head_attestation"]


def _args(v: dict) -> dict:
    i = v["inputs"]
    return dict(
        issuer_aid=v["issuer_aid"],
        attested_len=i["attested_len"],
        attested_head=bytes.fromhex(i["attested_head_hex"]),
        attested_at=i["attested_at"],
        digest_schema=i["digest_schema"],
        signature=bytes.fromhex(v["signature_hex"]),
    )


def test_the_vector_is_the_framing_this_module_implements():
    assert V2["inputs"]["domain"].encode() == CHAIN_HEAD_ATTESTATION_DOMAIN_V2
    assert V2["frame_order"] == [
        "domain",
        "attested_len",
        "attested_head",
        "attested_at",
        "digest_schema",
        "issuer_aid",
        "tenant",
    ]


def test_the_runtime_v2_signature_verifies():
    assert verify_chain_head_attestation(**_args(V2), tenant=V2["inputs"]["tenant"])


def test_the_v2_digest_matches_the_runtime():
    # The digest runtime-23 cross-checked with an independent Python verifier (#1284).
    a = _args(V2)
    assert (
        _chain_head_attestation_digest(
            a["attested_len"],
            a["attested_head"],
            a["attested_at"],
            a["digest_schema"],
            a["issuer_aid"],
            V2["inputs"]["tenant"],
        ).hex()
        == "4dd1877694966a228fefa52ebfe9a21464549c7da8802c1057f9fa974e0c3352"
    )


@pytest.mark.parametrize(
    "tenant",
    ["acmf", ""],
    ids=["relabelled", "emptied — an empty tenant is v1 only"],
)
def test_v2_binds_the_tenant(tenant):
    assert not verify_chain_head_attestation(**_args(V2), tenant=tenant)


def test_v2_signature_without_its_tenant_does_not_verify():
    # Omitting `tenant` is the empty tenant: v1 only. A v2 attestation needs its tenant passed.
    assert not verify_chain_head_attestation(**_args(V2))


@pytest.mark.parametrize("field", ["attested_len", "attested_at", "digest_schema"])
def test_any_other_tamper_still_fails(field):
    a = _args(V2)
    a[field] += 1
    assert not verify_chain_head_attestation(**a, tenant="acme")


def test_the_v1_vector_verifies_with_its_empty_tenant():
    # The shared v1 block is the system partition's framing, and is byte-identical forever.
    assert verify_chain_head_attestation(**_args(V1))
    assert verify_chain_head_attestation(**_args(V1), tenant="")


def test_the_v1_vector_relabelled_to_a_tenant_is_refused():
    # #835 step 4, mirroring the runtime's `conformance_drift` test: a v1 signature carries the tenant
    # outside the signature, so a non-empty tenant on it could have been relabelled — refused, with no
    # fallback, grace period or toggle.
    assert not verify_chain_head_attestation(**_args(V1), tenant="acme")


def test_a_v2_signature_over_the_empty_tenant_is_refused():
    # Never minted by the runtime; hand-rolled here with the vector's own seed. An empty tenant selects
    # v1 only, so a genuine v2 signature over "" does not verify — and the v1 signature over the same
    # (len, head, at, schema) does, which proves the refusal is the framing, not the key.
    key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(V2["inputs"]["issuer_seed_hex"])
    )
    a = _args(V2)
    frames = (
        a["attested_len"],
        a["attested_head"],
        a["attested_at"],
        a["digest_schema"],
        a["issuer_aid"],
    )
    v2_over_empty = key.sign(_chain_head_attestation_digest(*frames, ""))
    v1 = key.sign(_chain_head_attestation_digest(*frames, None))
    assert not verify_chain_head_attestation(**{**a, "signature": v2_over_empty})
    assert not verify_chain_head_attestation(
        **{**a, "signature": v2_over_empty}, tenant=""
    )
    assert verify_chain_head_attestation(**{**a, "signature": v1})


def test_tenant_must_be_a_str():
    with pytest.raises(TypeError, match="tenant must be a str"):
        verify_chain_head_attestation(**_args(V2), tenant=b"acme")


# ── verify_chain_head_attestation_message: the tenant comes from the artifact ───────────────────────


def _message(v: dict, tenant: str):
    from seam_sdk._gen.seam.event.v1 import seam_event_pb2 as ev

    a = _args(v)
    return ev.ChainHeadAttestation(
        attested_len=a["attested_len"],
        attested_head=a["attested_head"],
        attested_at=a["attested_at"],
        issuer_aid=a["issuer_aid"],
        digest_schema=a["digest_schema"],
        signature=a["signature"],
        tenant=tenant,
    )


def test_the_message_form_reads_the_tenant_off_the_artifact():
    from seam_sdk import verify_chain_head_attestation_message as verify_msg

    assert verify_msg(V2["issuer_aid"], _message(V2, V2["inputs"]["tenant"]))
    assert verify_msg(V1["issuer_aid"], _message(V1, ""))
    # The bypass the keyword form leaves open (#835 step 4): a v1 attestation relabelled to a tenant.
    # Calling the keyword form without `tenant=` ignores the wire tenant and says True ...
    relabelled = _message(V1, "acme")
    assert verify_chain_head_attestation(**_args(V1))
    # ... the message form cannot be called that way, and refuses it.
    assert not verify_msg(V1["issuer_aid"], relabelled)
    assert not verify_msg(V2["issuer_aid"], _message(V2, "acmf"))


def test_the_message_form_enforces_the_pin():
    from seam_sdk import verify_chain_head_attestation_message as verify_msg

    other = "aid:pubkey:_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg"
    assert not verify_msg(other, _message(V2, V2["inputs"]["tenant"]))
    with pytest.raises(TypeError):
        verify_msg(b"aid", _message(V2, V2["inputs"]["tenant"]))
    # A genuine signature over the pinned issuer, but the message names another one. Only the issuer
    # equality refuses this: the signature itself still verifies under the pin.
    relabelled = _message(V2, V2["inputs"]["tenant"])
    relabelled.issuer_aid = other
    assert not verify_msg(_args(V2)["issuer_aid"], relabelled)


def test_the_message_form_is_exported():
    import seam_sdk

    assert "verify_chain_head_attestation_message" in seam_sdk.__all__
