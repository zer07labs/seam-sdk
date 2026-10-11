"""seam-runtime #835 step 1: the v2 chain-head attestation framing (tenant inside the signature).

Pinned against ``conformance/chain_head_attestation_v2_vector.json``, vendored verbatim from the
runtime's ``crates/seam-client/tests/conformance_vectors_extended.json`` (``chain_head_attestation_v2``).
The shared v1 block in ``conformance/vectors.json`` is untouched — it is a byte-identity contract.
"""

from __future__ import annotations

import json
import pathlib

import pytest

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


def test_a_v1_attestation_with_a_tenant_still_verifies_until_step_4():
    # Every production attestation today: v1-signed, tenant stamped outside the signature.
    assert verify_chain_head_attestation(**_args(V1), tenant="acme")
    assert verify_chain_head_attestation(**_args(V1))


def test_tenant_must_be_a_str():
    with pytest.raises(TypeError, match="tenant must be a str"):
        verify_chain_head_attestation(**_args(V2), tenant=b"acme")
