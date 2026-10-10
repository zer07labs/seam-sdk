"""Test-only governing config (seam-runtime #1156): a signed root + one tenant document over ``file://``.

A #1156 runtime refuses to boot without ``SEAM_CONFIG_ROOT_URL``, and the old single registry snapshot
(``SEAM_REGISTRY_SNAPSHOT`` / ``_SIG`` / ``SEAM_SNAPSHOT_PUBKEY``) is a retired variable that refuses boot
when set at all. ``SEAM_DEV_INSECURE`` still enrols the public demo identity (``[42] * 32``) into
``design-partner/fraud``, but it installs NO governance: with no root, the management plane is locked
and the data plane denies every decision. So every live spawn here is handed a root.

The default documents mirror the runtime's own demo governance (``crates/seamd/src/governing/demo.rs``)
— the same tenant, namespace, policy id, permissive body and agent roster — with one deliberate
difference: the root's ``operator_keys`` are this repo's two golden operator keys (the ones
``operator_token.mint_operator_token`` signs with), so the management plane is unlocked for the tokens
the suites already mint.

Signatures are Ed25519 over a domain prefix plus the EXACT file bytes (multi-tenant-config.md §3):

    root:   "seam-config-root.v1\\n" || bytes
    tenant: "seam-config-tenant.v1\\n" || tenant_id || "\\n" || bytes

Run as a script (``python governing_root.py <dir>``) it writes the default documents and prints the
three env assignments, one per line, for a CI step to append to ``$GITHUB_ENV`` (the TS suites inherit
them through ``...process.env``).
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
from typing import Any, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Public constants — the runtime's demo root and tenant-document seeds. Nothing here is secret.
ROOT_SEED = bytes([0xD0] * 32)
TENANT_SEED = bytes([0xD1] * 32)

DEMO_TENANT = "design-partner"
DEMO_NAMESPACE = "design-partner/fraud"
DEMO_POLICY = "pol-2026-06"
DEMO_AGENTS = [
    "lead",
    "peer",
    "a",
    "b",
    "c",
    "fraud-v3",
    "risk-v2",
    "compliance-v4",
    "proposer",
    "voter",
    "alice",
    "bob",
]
DECISION_MODE = "macp.mode.decision.v1"
DEMO_MODES = [
    DECISION_MODE,
    "macp.mode.proposal.v1",
    "macp.mode.task.v1",
    "macp.mode.handoff.v1",
    "macp.mode.quorum.v1",
]

# The golden operator keys (public halves), as pinned in conformance/registry_snapshot_operator_keys.json.
OPERATOR_KEYS = [
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
]

GENERATED_AT = 1


def _pub(seed: bytes) -> str:
    return (
        Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw().hex()
    )


def _jcs(v: Any) -> bytes:
    # RFC 8785 for the shapes used here (ASCII strings, small ints, bools, nested objects).
    return json.dumps(
        v, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def policy_entry(
    policy_id: str,
    rules: Mapping[str, Any],
    *,
    mode: str = DECISION_MODE,
    description: str = "seam-sdk test permissive policy (voting none)",
) -> dict:
    """A ``policy_rules`` entry carrying its ``policy_sha256`` (sha256 over JCS of the definition)."""
    definition = {
        "policy_id": policy_id,
        "mode": mode,
        "description": description,
        "rules": dict(rules),
        "schema_version": 1,
    }
    return {**definition, "policy_sha256": hashlib.sha256(_jcs(definition)).hexdigest()}


PERMISSIVE_RULES = {
    "voting": {"algorithm": "none"},
    "commitment": {"authority": "initiator_only", "require_vote_quorum": False},
}


#: ``Agent(bytes([42] * 32)).aid`` — the identity SEAM_DEV_INSECURE auto-enrols. A literal so this module
#: (and the CI step that runs it before the SDK is installed) needs only ``cryptography``;
#: test_governing_root.py pins it to the derivation.
DEMO_AID = "aid:pubkey:ed25519:GX9rI-FshTLGq8g4-s1ep4m-DHaykgM0A5v6iz02jWE"


def demo_aid() -> str:
    return DEMO_AID


def manifest_entry(agent: str) -> dict:
    return {
        "agent_id": agent,
        "version": "1",
        "protocol": "macp",
        "supported_modes": DEMO_MODES,
        "max_scope": {"unrestricted": True},
        "compat": {"min": 1, "max": 1},
    }


def default_root(**sections: Any) -> dict:
    """The demo root; keyword arguments add or replace root sections (e.g. ``retention_schedule``)."""
    return {
        "snapshot_id": f"sdk-test-root-{GENERATED_AT}",
        "generated_at": GENERATED_AT,
        "tenant": "default",
        "tenant_roster": {
            "schema_version": 1,
            "tenants": [{"tenant_id": DEMO_TENANT, "signer_keys": [_pub(TENANT_SEED)]}],
        },
        "operator_keys": [
            {"alg": "ed25519", "public_key_hex": k} for k in OPERATOR_KEYS
        ],
        **sections,
    }


def default_tenant_doc(**sections: Any) -> dict:
    """The demo tenant document; keyword arguments add or replace tenant sections."""
    agents = DEMO_AGENTS + [demo_aid()]
    return {
        "snapshot_id": f"sdk-test-{DEMO_TENANT}-{GENERATED_AT}",
        "generated_at": GENERATED_AT,
        "tenant": DEMO_TENANT,
        "namespaces": [
            {
                "namespace_id": DEMO_NAMESPACE,
                "active_policy": DEMO_POLICY,
                "policy_candidates": [],
            }
        ],
        "capability_registry": {
            "manifests": [manifest_entry(a) for a in agents],
            "pins": [
                {"agent_id": a, "version": "1", "status": "active"} for a in agents
            ],
        },
        "policy_rules": [policy_entry(DEMO_POLICY, PERMISSIVE_RULES)],
        **sections,
    }


def write_governance(
    directory: "str | pathlib.Path",
    *,
    root: Optional[Mapping[str, Any]] = None,
    tenant_doc: Optional[Mapping[str, Any]] = None,
) -> dict[str, str]:
    """Write and sign a root and the demo tenant's document under ``directory``; return the env.

    ``root`` / ``tenant_doc`` replace the defaults wholesale (build them from :func:`default_root` /
    :func:`default_tenant_doc` to change one section)."""
    d = pathlib.Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    root_doc = dict(root) if root is not None else default_root()
    tdoc = dict(tenant_doc) if tenant_doc is not None else default_tenant_doc()
    tenant_id = tdoc["tenant"]

    root_bytes = (json.dumps(root_doc, indent=2) + "\n").encode()
    tenant_bytes = (json.dumps(tdoc, indent=2) + "\n").encode()
    root_sk = Ed25519PrivateKey.from_private_bytes(ROOT_SEED)
    tenant_sk = Ed25519PrivateKey.from_private_bytes(TENANT_SEED)

    root_path = d / "root.json"
    tenant_path = d / f"tenant-{tenant_id}.json"
    root_path.write_bytes(root_bytes)
    tenant_path.write_bytes(tenant_bytes)
    (d / "root.json.sig").write_text(
        root_sk.sign(b"seam-config-root.v1\n" + root_bytes).hex()
    )
    (d / f"tenant-{tenant_id}.json.sig").write_text(
        tenant_sk.sign(
            b"seam-config-tenant.v1\n" + tenant_id.encode() + b"\n" + tenant_bytes
        ).hex()
    )
    base = d.resolve().as_uri()
    return {
        "SEAM_CONFIG_ROOT_URL": f"{base}/root.json",
        "SEAM_CONFIG_ROOT_PUBKEY": _pub(ROOT_SEED),
        "SEAM_CONFIG_TENANT_URL_TEMPLATE": f"{base}/tenant-{{tenant}}.json",
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: governing_root.py <dir>")
    for k, v in write_governance(sys.argv[1]).items():
        print(f"{k}={v}")
