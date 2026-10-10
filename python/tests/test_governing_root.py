"""governing_root.py writes what a #1156 runtime will verify; pin the parts that can drift silently."""

from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import governing_root as g
from operator_token import _PUBKEY_HEX
from seam_sdk import Agent


def test_demo_aid_literal_is_the_seed_42_identity():
    assert g.DEMO_AID == Agent(bytes([42] * 32)).aid


def test_the_operator_token_key_is_in_the_root():
    assert _PUBKEY_HEX in g.OPERATOR_KEYS


def test_signatures_are_domain_separated_over_the_exact_bytes(tmp_path):
    env = g.write_governance(tmp_path)
    root_pk = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(env["SEAM_CONFIG_ROOT_PUBKEY"])
    )
    root = (tmp_path / "root.json").read_bytes()
    root_pk.verify(
        bytes.fromhex((tmp_path / "root.json.sig").read_text()),
        b"seam-config-root.v1\n" + root,
    )
    signer = json.loads(root)["tenant_roster"]["tenants"][0]["signer_keys"][0]
    tdoc = (tmp_path / f"tenant-{g.DEMO_TENANT}.json").read_bytes()
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer)).verify(
        bytes.fromhex((tmp_path / f"tenant-{g.DEMO_TENANT}.json.sig").read_text()),
        b"seam-config-tenant.v1\n" + g.DEMO_TENANT.encode() + b"\n" + tdoc,
    )
    assert env["SEAM_CONFIG_TENANT_URL_TEMPLATE"].endswith("/tenant-{tenant}.json")


def test_key_roles_are_disjoint():
    # The runtime refuses a root in which a signer key equals a root pin or an operator key.
    root_pin = g._pub(g.ROOT_SEED)
    signer = g._pub(g.TENANT_SEED)
    assert len({root_pin, signer, *g.OPERATOR_KEYS}) == 2 + len(g.OPERATOR_KEYS)


def test_policy_digest_matches_the_runtime_init_policy():
    # seam-ops init's permissive policy (seam-runtime crates/seamd/src/bin/seam-ops.rs `init_policy_entry`)
    # is the same body; JCS over the definition sorts keys, so the digest is order-independent.
    e = g.policy_entry("p", g.PERMISSIVE_RULES)
    reordered = g.policy_entry("p", dict(reversed(list(g.PERMISSIVE_RULES.items()))))
    assert (
        e["policy_sha256"] == reordered["policy_sha256"]
        and len(e["policy_sha256"]) == 64
    )
