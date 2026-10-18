"""seam-commitment-digest:v3 + seam-explanation-digest:v1, and the RFC-AITP-0005 self-attestation TCT.

Pinned against the runtime's reference vector (`conformance/commitment_digest_v3_vector.json`,
copied verbatim from the runtime's trust-aitp test fixtures) and the `tct` block of
`conformance/vectors.json`. Framing: seam-runtime `docs/specs/seam-commitment-digest.v3.md`. The TCT
shape (`grants: ["aitp.attestation"]`, the digest under `ext["com.zer07labs.seam"]`) is taken from the
signed vectors, which are the source of truth where the pinned spec's prose still describes the
retired grants form.
"""

from __future__ import annotations

import base64
import json
import math
from pathlib import Path

import pytest

from seam_sdk import explanation_digest, verify_tct
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk.client import commitment_view
from seam_sdk.crypto import _seam_commitment_digest

ROOT = Path(__file__).resolve().parents[2] / "conformance"
V3 = json.loads((ROOT / "commitment_digest_v3_vector.json").read_text())
TCT = json.loads((ROOT / "vectors.json").read_text())["tct"]
EMPTY = "eb7853dc086ef5385db8408cf35c9c984e845ccc03d269102f942eed7806ce40"


@pytest.mark.parametrize("case", V3["cases"], ids=lambda c: c["name"])
def test_reference_vector_digests(case):
    c = case["commitment"]
    assert explanation_digest(c["explanation"]).hex() == case["explanation_digest"]
    assert bytes(c["explanation_digest"]).hex() == case["explanation_digest"]
    assert _seam_commitment_digest(c) == case["commitment_digest"]


def test_reference_vector_signed_case_verifies():
    (case,) = [c for c in V3["cases"] if c["commitment"]["signed_artifact"]]
    c = case["commitment"]
    assert verify_tct(
        V3["issuer_aid"], bytes(c["signed_artifact"]).decode(), c, now_s=0
    )


def test_spec_worked_examples():
    assert explanation_digest([]).hex() == EMPTY
    # The spec's worked example: six empty fields, an absent `supersedes`, the empty explanation.
    empty = dict(id="", action="", authority="", auth_method="", trust_basis="")
    (all_empty,) = [c for c in V3["cases"] if c["name"] == "all_empty"]
    assert _seam_commitment_digest(empty) == all_empty["commitment_digest"]


def test_absent_and_present_empty_supersedes_differ():
    """The one change v3 makes: a presence byte. v2 framed absent as the empty string."""
    by = {c["name"]: c for c in V3["cases"]}
    assert by["all_empty"]["commitment"]["supersedes"] is None
    assert by["empty_supersedes"]["commitment"]["supersedes"] == ""
    assert (
        by["all_empty"]["commitment_digest"]
        != by["empty_supersedes"]["commitment_digest"]
    )
    # A key missing entirely is the same as None: absent.
    c = {k: v for k, v in by["all_empty"]["commitment"].items() if k != "supersedes"}
    assert _seam_commitment_digest(c) == by["all_empty"]["commitment_digest"]


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


# -- The self-attestation TCT shape (RFC-AITP-0005 / owner plan B5) ---------------------------------
#
# Re-signed with the vector's own issuer key (seed `[7u8; 32]`) so the signature is valid and only
# the claim under test changes; otherwise every case below would fail on the signature and prove
# nothing about the claim checks.

_SEED = bytes([7] * 32)


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(x: str) -> bytes:
    return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))


def _sign(header: bytes, payload: bytes) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signing_input = f"{_b64(header)}.{_b64(payload)}"
    sig = Ed25519PrivateKey.from_private_bytes(_SEED).sign(signing_input.encode())
    return f"{signing_input}.{_b64(sig)}"


def _vector_claims():
    (case,) = [c for c in V3["cases"] if c["commitment"]["signed_artifact"]]
    h, p, _ = bytes(case["commitment"]["signed_artifact"]).decode().split(".")
    return case["commitment"], json.loads(_unb64(h)), json.loads(_unb64(p))


def _verify(commitment, header, payload) -> bool:
    jws = _sign(json.dumps(header).encode(), json.dumps(payload).encode())
    return verify_tct(V3["issuer_aid"], jws, commitment, now_s=0)


def test_the_resigned_vector_still_verifies():
    """The control: if re-signing alone broke verification, every refusal below would be vacuous."""
    c, h, p = _vector_claims()
    assert p["grants"] == ["aitp.attestation"]
    assert list(p["ext"]) == ["com.zer07labs.seam"]
    assert _verify(c, h, p) is True


def test_jti_is_the_derived_uuid():
    """P9: the TCT `jti` is derived, not random: `derived_uuid("seam-tct-jti-v1", ...)`."""
    from seam_sdk import derived_uuid

    blk = json.loads((ROOT / "vectors.json").read_text())["derived_uuid"]["tct_jti"]
    p = json.loads(_unb64(TCT["signed_artifact_jws"].split(".")[1]))
    assert p["jti"] == blk["uuid"]
    assert str(derived_uuid(blk["tag"], bytes.fromhex(blk["input_hex"]))) == p["jti"]


def _stmt(p):
    return p["ext"]["com.zer07labs.seam"]


_SHAPES = {
    "statement in grants (the retired v2 shape)": lambda p: p.update(
        grants=[
            "seam:commitment",
            "seam-commitment-digest:" + _stmt(p)["commitment_digest"],
        ]
    ),
    "extra grant": lambda p: p.update(grants=["aitp.attestation", "x"]),
    "no grants": lambda p: p.pop("grants"),
    "no ext": lambda p: p.pop("ext"),
    "extra ext key": lambda p: p["ext"].update({"org.example": {}}),
    "wrong statement type": lambda p: _stmt(p).update(type="seam:other"),
    "extra statement field": lambda p: _stmt(p).update(x=1),
    "uppercase digest": lambda p: _stmt(p).update(
        commitment_digest=_stmt(p)["commitment_digest"].upper()
    ),
    "aud is not iss": lambda p: p.update(aud="aid:pubkey:" + "A" * 43),
    "sub is not iss": lambda p: p.update(sub="aid:pubkey:" + "A" * 43),
}


@pytest.mark.parametrize("name", sorted(_SHAPES))
def test_a_wrong_attestation_shape_fails_closed(name):
    c, h, p = _vector_claims()
    _SHAPES[name](p)
    assert _verify(c, h, p) is False, f"{name} must fail closed"


def test_a_duplicate_json_key_fails_closed():
    """A duplicate key lets two parsers read two different statements from one signed payload.
    Refused in the payload and in the header alike."""
    c, h, p = _vector_claims()
    body = json.dumps(p)
    forged = body[:-1] + ', "grants": ["aitp.attestation"]}'
    assert (
        verify_tct(
            V3["issuer_aid"], _sign(json.dumps(h).encode(), forged.encode()), c, now_s=0
        )
        is False
    )
    dup_header = json.dumps(h)[:-1] + ', "typ": "aitp-tct+jwt"}'
    assert (
        verify_tct(
            V3["issuer_aid"], _sign(dup_header.encode(), body.encode()), c, now_s=0
        )
        is False
    )


def test_commitment_view_keeps_supersedes_presence():
    m = pb.Commitment(
        id="i", action="a", authority="x", auth_method="m", trust_basis="t"
    )
    assert commitment_view(m)["supersedes"] is None
    m.supersedes = ""
    assert commitment_view(m)["supersedes"] == ""
