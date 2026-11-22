"""seam-commitment-digest:v6 with sealed voter records: every row of the v6 voter vector.

Pinned against `conformance/commitment_digest_v6_voter_vector.json`, copied byte for byte from seam-runtime
`crates/seam-trust-aitp/tests/fixtures/` (seamd 0.113.0) and kept identical by its `sdk-digest-parity`.
Specs: seam-runtime `docs/specs/seam-commitment-digest.v6.md` and `docs/specs/voter-verification.v1.md`.

This is the vector the plain v6 signed vector could not be: its vote, ballot and objection entries
carry real `seam-voter-pop-v1` records, so `verify_tct` is given the entries (not just the published
explanation digest) and the commitment-level voter check runs against the vector's `decision`.

A case passes under v6 AND `verify_commitment_voters(entries, issuer_aid, decision)` with
`voters_verified` records. A negative is refused by at least one of the two. `rule` is advisory (the
vector's note says so), so no test compares it: `accepted_outside_window` carries `record_malformed`,
for one.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from seam_sdk import commitment_digest_v6, select_commitment_version, verify_tct
from seam_sdk.crypto import explanation_digest, verify_commitment_voters

ROOT = Path(__file__).resolve().parents[2] / "conformance"
V = json.loads((ROOT / "commitment_digest_v6_voter_vector.json").read_text())
ISSUER = V["issuer_aid"]
DECISION = tuple(V["decision"])
CASES = {c["name"]: c for c in V["cases"]}


def _commitment(row: dict) -> dict:
    """The row as `verify_tct` reads it: the full commitment WITH its entries, plus the raw trailers."""
    return {**row["commitment"], "trailers": row["trailers"]}


def _records(entries: list[dict]) -> int:
    return sum(1 for e in entries if e.get("voter_verification") is not None)


def test_the_vector_file_is_the_v6_voter_spec():
    assert V["commitment_digest_domain"] == "seam-commitment-digest:v6"
    assert V["explanation_digest_domain"] == "seam-explanation-digest:v2"
    assert V["gate_digest_domain"] == "seam-gate-digest:v1"
    assert len(DECISION) == 2
    assert {k for k, v in V.items() if isinstance(v, list)} == {
        "decision",
        "cases",
        "negatives",
    }
    assert len(V["cases"]) == 2 and len(V["negatives"]) == 8


@pytest.mark.parametrize("case", V["cases"], ids=lambda c: c["name"])
def test_case_verifies_with_its_voter_records(case):
    c = _commitment(case)
    entries = c["explanation"]
    assert case["expect"] == "v6" == select_commitment_version(case["ext"])
    assert explanation_digest(entries) == bytes(c["explanation_digest"])
    assert commitment_digest_v6(c) == case["commitment_digest"]
    assert verify_tct(ISSUER, case["signed_artifact"], c, now_s=0)
    assert verify_commitment_voters(entries, ISSUER, DECISION)
    assert _records(entries) == V["voters_verified"]


@pytest.mark.parametrize("row", V["negatives"], ids=lambda r: r["name"])
def test_negative_is_refused(row):
    assert row["expect"] == "refused" and row["over"] in CASES
    c = _commitment(row)
    tct_ok = verify_tct(ISSUER, row["signed_artifact"], c, now_s=0)
    voters_ok = verify_commitment_voters(c["explanation"], ISSUER, DECISION)
    assert not (tct_ok and voters_ok)


def test_the_decision_binding_is_what_refuses_wrong_decision():
    """`wrong_decision` is a well-signed TCT whose records name another decision: only the decision
    the verifier knows can refuse it, so dropping that argument must let it through."""
    row = next(r for r in V["negatives"] if r["name"] == "wrong_decision")
    c = _commitment(row)
    assert verify_tct(ISSUER, row["signed_artifact"], c, now_s=0)
    assert verify_commitment_voters(c["explanation"], ISSUER)
    assert not verify_commitment_voters(c["explanation"], ISSUER, DECISION)


def test_a_tampered_published_entry_breaks_the_signed_digest():
    """The entries and their digest were rewritten together and the old TCT kept: the records still
    re-check, so it is the commitment digest under the signature that refuses it."""
    row = next(r for r in V["negatives"] if r["name"] == "tampered_published_entry")
    c = _commitment(row)
    assert verify_commitment_voters(c["explanation"], ISSUER, DECISION)
    assert not verify_tct(ISSUER, row["signed_artifact"], c, now_s=0)
