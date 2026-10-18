"""seam-commitment-digest:v2 + seam-explanation-digest:v1 (seam-runtime#1255, #802/#804).

Pinned against the runtime's reference vector (`conformance/commitment_digest_v2_vector.json`,
copied verbatim from `crates/seam-trust-aitp/tests/fixtures/`) and the `tct` block of
`conformance/vectors.json`. Normative: seam-runtime `docs/specs/seam-commitment-digest.v2.md`.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from seam_sdk import explanation_digest, verify_tct
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk.client import commitment_view
from seam_sdk.crypto import _seam_commitment_digest

ROOT = Path(__file__).resolve().parents[2] / "conformance"
V2 = json.loads((ROOT / "commitment_digest_v2_vector.json").read_text())
TCT = json.loads((ROOT / "vectors.json").read_text())["tct"]
EMPTY = "eb7853dc086ef5385db8408cf35c9c984e845ccc03d269102f942eed7806ce40"


@pytest.mark.parametrize("case", V2["cases"], ids=lambda c: c["name"])
def test_reference_vector_digests(case):
    c = case["commitment"]
    assert explanation_digest(c["explanation"]).hex() == case["explanation_digest"]
    assert bytes(c["explanation_digest"]).hex() == case["explanation_digest"]
    assert _seam_commitment_digest(c) == case["commitment_digest"]


def test_reference_vector_signed_case_verifies():
    (case,) = [c for c in V2["cases"] if c["commitment"]["signed_artifact"]]
    c = case["commitment"]
    assert verify_tct(
        V2["issuer_aid"], bytes(c["signed_artifact"]).decode(), c, now_s=0
    )


def test_spec_worked_examples():
    assert explanation_digest([]).hex() == EMPTY
    empty = dict(id="", action="", authority="", auth_method="", trust_basis="")
    assert (
        _seam_commitment_digest(empty)
        == "78edca52ba1e88f13a78e5569742bfce0b51474ca840bf38a8dde414d5515784"
    )


def test_conformance_tct_block():
    c = TCT["inputs"]["commitment"]
    assert explanation_digest(c["explanation"]).hex() == TCT["explanation_digest_hex"]
    assert _seam_commitment_digest(c) == TCT["commitment_digest_hex"]


ENTRY = dict(
    kind="evaluation", participant="a", proposal_id="p", value="APPROVE", reason=""
)


def test_absent_confidence_is_not_zero():
    assert explanation_digest([{**ENTRY, "confidence": None}]) != explanation_digest(
        [{**ENTRY, "confidence": 0.0}]
    )


@pytest.mark.parametrize("bad", [-0.0, math.nan, math.inf, -math.inf, 1.5, -0.1, True])
def test_non_canonical_confidence_is_refused(bad):
    with pytest.raises(ValueError):
        explanation_digest([{**ENTRY, "confidence": bad}])


@pytest.mark.parametrize("kind", ["Vote", "EXPLANATION_KIND_VOTE", "", "abstain"])
def test_unknown_kind_is_refused(kind):
    with pytest.raises(ValueError):
        explanation_digest([{**ENTRY, "kind": kind}])


def test_entries_that_disagree_with_the_published_digest_fail_closed():
    c = TCT["inputs"]["commitment"]
    wrong = {**c, "explanation_digest": bytes(32)}
    assert (
        verify_tct(TCT["issuer_aid"], TCT["signed_artifact_jws"], wrong, now_s=0)
        is False
    )


def test_published_digest_alone_verifies_who_and_what():
    c = {k: v for k, v in TCT["inputs"]["commitment"].items() if k != "explanation"}
    c["explanation_digest"] = TCT["explanation_digest_hex"]
    assert verify_tct(TCT["issuer_aid"], TCT["signed_artifact_jws"], c, now_s=0) is True


def test_a_bad_entry_fails_closed_inside_verify():
    c = TCT["inputs"]["commitment"]
    bad = {**c, "explanation": [{**c["explanation"][0], "kind": "nope"}]}
    assert (
        verify_tct(TCT["issuer_aid"], TCT["signed_artifact_jws"], bad, now_s=0) is False
    )


def _proto_from_vector(c: dict) -> pb.Commitment:
    kinds = {
        "vote": pb.EXPLANATION_KIND_VOTE,
        "evaluation": pb.EXPLANATION_KIND_EVALUATION,
        "objection": pb.EXPLANATION_KIND_OBJECTION,
        "ballot": pb.EXPLANATION_KIND_BALLOT,
    }
    m = pb.Commitment(
        id=c["id"],
        action=c["action"],
        authority=c["authority"],
        auth_method=c["auth_method"],
        trust_basis=c["trust_basis"],
        committer=c["committer"],
    )
    for e in c["explanation"]:
        entry = m.explanation.add(
            kind=kinds[e["kind"]],
            participant=e["participant"],
            proposal_id=e["proposal_id"],
            value=e["value"],
            reason=e["reason"],
        )
        if e["confidence"] is not None:
            entry.confidence = e["confidence"]
        if e["rationale_ref"] is not None:
            entry.rationale_ref = e["rationale_ref"]
    return m


def test_commitment_view_of_the_served_proto_verifies():
    """verify_decision's path: proto Commitment -> commitment_view -> verify_tct. Explicit
    presence must survive (an absent confidence is not 0.0), or the digest moves."""
    m = _proto_from_vector(TCT["inputs"]["commitment"])
    m.explanation_digest = bytes.fromhex(TCT["explanation_digest_hex"])
    view = commitment_view(m)
    assert view["explanation"][0]["confidence"] is None
    assert view["explanation"][1]["confidence"] == 0.0
    assert (
        verify_tct(TCT["issuer_aid"], TCT["signed_artifact_jws"], view, now_s=0) is True
    )

    m.explanation[0].ClearField("rationale_ref")
    assert (
        verify_tct(
            TCT["issuer_aid"], TCT["signed_artifact_jws"], commitment_view(m), now_s=0
        )
        is False
    )


def test_unspecified_kind_from_the_wire_fails_closed():
    m = _proto_from_vector(TCT["inputs"]["commitment"])
    m.explanation[0].kind = pb.EXPLANATION_KIND_UNSPECIFIED
    assert (
        verify_tct(
            TCT["issuer_aid"], TCT["signed_artifact_jws"], commitment_view(m), now_s=0
        )
        is False
    )
