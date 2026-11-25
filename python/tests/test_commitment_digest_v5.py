"""seam-commitment-digest:v5 (#1711) + seam-explanation-digest:v2 (#1687), and the RFC-AITP-0005 self-attestation TCT.

Pinned against the runtime's reference vectors, copied verbatim from its trust-aitp test fixtures:
`conformance/commitment_digest_v5_signed_vector.json` (real TCTs, one governed and one ungoverned
populated case; byte fields are JSON number arrays), `conformance/commitment_digest_v5_vector.json`
(the independent generator's field-9/10/11 slot cases; byte fields are hex), and the `tct` block of
`conformance/vectors.json`. Framing: seam-runtime `docs/specs/seam-commitment-digest.v5.md` (v4 plus
field 11, `governing_doc_sha256`). That file's `governing_trailer_refusals` pins the runtime's `0x06`
trailer DECODER, which the SDK does not have: the trailer is sealed inside the record ciphertext and
reaches a client only as the `Commitment.governing_doc_sha256` proto field, so it is not exercised here. The TCT
shape (`grants: ["aitp.attestation"]`, the digest under `ext["com.zer07labs.seam"]`) is taken from the
signed vectors, which are the source of truth where the pinned spec's prose still describes the
retired grants form.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
from pathlib import Path

import pytest

from seam_sdk import explanation_digest, verify_tct
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk.client import commitment_view
from seam_sdk.crypto import _seam_commitment_digest

ROOT = Path(__file__).resolve().parents[2] / "conformance"
V5 = json.loads((ROOT / "commitment_digest_v5_signed_vector.json").read_text())
SLOTS = json.loads((ROOT / "commitment_digest_v5_vector.json").read_text())
TCT = json.loads((ROOT / "vectors.json").read_text())["tct"]
EMPTY = "cabe83af912ea38ef4525f5a7d8580b4c4e217417edc0c93f936d2c18c4fd8f5"


@pytest.mark.parametrize("case", V5["cases"], ids=lambda c: c["name"])
def test_reference_vector_digests(case):
    c = case["commitment"]
    assert explanation_digest(c["explanation"]).hex() == case["explanation_digest"]
    assert bytes(c["explanation_digest"]).hex() == case["explanation_digest"]
    slots = {
        k: case[k] for k in ("selection_digest", "certificate_digest") if case.get(k)
    }
    assert _seam_commitment_digest({**c, **slots}) == case["commitment_digest"]


def test_reference_vector_voter_records_reverify():
    """Every voter-kind entry in the vector carries a record that re-checks offline."""
    from seam_sdk.crypto import verify_commitment_voters

    for case in V5["cases"]:
        entries = case["commitment"]["explanation"]
        assert verify_commitment_voters(entries, V5["issuer_aid"]), case["name"]


@pytest.mark.parametrize("bad", [b"", bytes(31), bytes(33)])
@pytest.mark.parametrize(
    "slot", ["selection_digest", "certificate_digest", "governing_doc_sha256"]
)
def test_digest_slot_length_is_refused(slot, bad):
    with pytest.raises(ValueError):
        _seam_commitment_digest(
            dict(
                id="",
                action="",
                authority="",
                auth_method="",
                trust_basis="",
                **{slot: bad},
            )
        )


SIGNED = [c for c in V5["cases"] if c["commitment"]["signed_artifact"]]


def test_the_signed_vector_has_one_governed_and_one_ungoverned_case():
    governed = {
        c["name"]: c["commitment"]["governing_doc_sha256"] is not None for c in SIGNED
    }
    assert sorted(governed.values()) == [False, True], governed


@pytest.mark.parametrize("case", SIGNED, ids=lambda c: c["name"])
def test_reference_vector_signed_case_verifies(case):
    c = case["commitment"]
    assert verify_tct(
        V5["issuer_aid"], bytes(c["signed_artifact"]).decode(), c, now_s=0
    )


def test_a_governed_tct_does_not_verify_with_field_11_dropped_or_changed():
    """Field 11 is TCT-bound: reading a governed record as ungoverned, or under another document,
    is a different digest and the runtime's signature does not cover it."""
    (case,) = [c for c in SIGNED if c["commitment"]["governing_doc_sha256"] is not None]
    c = case["commitment"]
    jws = bytes(c["signed_artifact"]).decode()
    assert not verify_tct(
        V5["issuer_aid"], jws, {**c, "governing_doc_sha256": None}, now_s=0
    )
    other = bytes(c["governing_doc_sha256"])[:-1] + b"\x00"
    assert not verify_tct(
        V5["issuer_aid"], jws, {**c, "governing_doc_sha256": other}, now_s=0
    )
    assert not verify_tct(
        V5["issuer_aid"], jws, {**c, "governing_doc_sha256": b""}, now_s=0
    )


def test_the_governing_document_digest_is_the_spec_test_label():
    """The spec's test document digest is SHA-256 of a fixed ASCII label; field 11 carries it raw."""
    import hashlib

    doc = hashlib.sha256(b"seam-governing-doc:test-vector").digest()
    (case,) = [c for c in SIGNED if c["commitment"]["governing_doc_sha256"] is not None]
    assert bytes(case["commitment"]["governing_doc_sha256"]) == doc
    assert (
        SLOTS["labels"]["governing_doc_sha256"]
        == 'SHA-256("seam-governing-doc:test-vector")'
    )
    by = {c["name"]: c for c in SLOTS["cases"]}
    assert by["doc_present"]["governing_doc_sha256"] == doc.hex()
    # The trailer the runtime seals it in (not decoded here): 0x06 ‖ u32le(33) ‖ 0x01 ‖ doc.
    assert (
        by["doc_present"]["governing_trailer"] == "06" + "21000000" + "01" + doc.hex()
    )


@pytest.mark.parametrize("case", SLOTS["cases"], ids=lambda c: c["name"])
def test_independent_generator_slot_cases(case):
    """The stdlib-only generator's cases: every combination of fields 9, 10 and 11, empty and populated."""
    assert SLOTS["commitment_digest_domain"] == "seam-commitment-digest:v5"
    c = dict(case["commitment"])
    for k in (
        "selection_digest",
        "certificate_digest",
        "governing_doc_sha256",
        "explanation_digest",
    ):
        if case.get(k) is not None:
            c[k] = case[k]
    assert _seam_commitment_digest(c) == case["commitment_digest"]


def test_spec_worked_examples():
    assert explanation_digest([]).hex() == EMPTY
    # The spec's worked example: six empty fields, an absent `supersedes`, the empty explanation.
    empty = dict(id="", action="", authority="", auth_method="", trust_basis="")
    (all_empty,) = [c for c in V5["cases"] if c["name"] == "all_empty"]
    assert all_empty["commitment_digest"].startswith("f31f8081")  # the spec's table
    assert _seam_commitment_digest(empty) == all_empty["commitment_digest"]


def test_absent_and_present_empty_supersedes_differ():
    """v3 added a presence byte to `supersedes` (v2 framed absent as the empty string); v4 keeps it."""
    by = {c["name"]: c for c in V5["cases"]}
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
    if c.get("supersedes") is not None:
        m.supersedes = c["supersedes"]
    if c.get("governing_doc_sha256") is not None:
        m.governing_doc_sha256 = bytes(c["governing_doc_sha256"])
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
        vv = e.get("voter_verification")
        if vv is not None:
            r = entry.voter_verification
            r.method = {
                "pop": pb.VOTER_VERIFICATION_POP,
                "cp_signed": pb.VOTER_VERIFICATION_CP_SIGNED,
            }[vv["method"]]
            for name in ("content_digest", "signature", "signer_certificate"):
                # `vectors.json` spells these as `<name>_hex`; the signed fixture as number arrays.
                raw = vv[name + "_hex"] if name + "_hex" in vv else vv[name]
                setattr(
                    r, name, bytes.fromhex(raw) if isinstance(raw, str) else bytes(raw)
                )
            for name in (
                "principal",
                "issued_at_ms",
                "expires_at_ms",
                "tenant",
                "namespace",
                "session_id",
                "opened_at_millis",
                "issuer",
                "audience",
                "accepted_at_ms",
            ):
                setattr(r, name, vv[name])
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


@pytest.mark.parametrize("case", SIGNED, ids=lambda c: c["name"])
def test_commitment_view_carries_field_11_with_explicit_presence(case):
    """The served proto's `optional bytes governing_doc_sha256 = 11` reaches the digest as served:
    absent stays absent (ungoverned, 0x00), present is the raw 32 bytes, and either way the runtime's
    TCT verifies through `commitment_view`. Clearing it on the governed case fails closed."""
    c = case["commitment"]
    m = _proto_from_vector(c)
    m.explanation_digest = bytes(c["explanation_digest"])
    view = commitment_view(m)
    governed = c["governing_doc_sha256"] is not None
    assert m.HasField("governing_doc_sha256") is governed
    assert view["governing_doc_sha256"] == (
        bytes(c["governing_doc_sha256"]) if governed else None
    )
    jws = bytes(c["signed_artifact"]).decode()
    assert verify_tct(V5["issuer_aid"], jws, view, now_s=0) is True
    if governed:
        m.ClearField("governing_doc_sha256")
        assert verify_tct(V5["issuer_aid"], jws, commitment_view(m), now_s=0) is False
        m.governing_doc_sha256 = (
            b""  # present-empty is NOT absent: refused, never hashed
        )
        assert commitment_view(m)["governing_doc_sha256"] == b""
        assert verify_tct(V5["issuer_aid"], jws, commitment_view(m), now_s=0) is False


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
# Re-signed with the vector's own SEAL key (seam-runtime #2031, S-4: the runtime's seeded test seal key
# of issuer seed `[7u8; 32]`, `sha256("seam.seal-key.fixed.v1" ‖ seed)`) so the signature is valid and
# only the claim under test changes; otherwise every case below would fail on the signature and prove
# nothing about the claim checks. The certificate member rides along unchanged.

_SEED = hashlib.sha256(b"seam.seal-key.fixed.v1" + bytes([7] * 32)).digest()


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
    (case,) = [c for c in V5["cases"] if c["name"] == "populated_signed"]
    h, p, _ = bytes(case["commitment"]["signed_artifact"]).decode().split(".")
    return case["commitment"], json.loads(_unb64(h)), json.loads(_unb64(p))


def _verify(commitment, header, payload) -> bool:
    jws = _sign(json.dumps(header).encode(), json.dumps(payload).encode())
    return verify_tct(V5["issuer_aid"], jws, commitment, now_s=0)


def test_the_resigned_vector_still_verifies():
    """The control: if re-signing alone broke verification, every refusal below would be vacuous."""
    c, h, p = _vector_claims()
    assert p["grants"] == ["aitp.attestation"]
    assert sorted(p["ext"]) == [
        "com.zer07labs.seam",
        "com.zer07labs.seam.seal-key-cert",
    ]
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
            V5["issuer_aid"], _sign(json.dumps(h).encode(), forged.encode()), c, now_s=0
        )
        is False
    )
    dup_header = json.dumps(h)[:-1] + ', "typ": "aitp-tct+jwt"}'
    assert (
        verify_tct(
            V5["issuer_aid"], _sign(dup_header.encode(), body.encode()), c, now_s=0
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


def test_commitment_view_carries_the_voter_record_and_it_reverifies():
    from seam_sdk.crypto import verify_commitment_voters

    view = commitment_view(_proto_from_vector(TCT["inputs"]["commitment"]))
    vv = view["explanation"][2]["voter_verification"]
    assert vv["method"] == "pop" and len(vv["content_digest"]) == 32
    assert verify_commitment_voters(view["explanation"], TCT["issuer_aid"])
    assert verify_commitment_voters(
        view["explanation"], TCT["issuer_aid"], ("acme", "s-conformance-0000000")
    )
    assert not verify_commitment_voters(
        view["explanation"], TCT["issuer_aid"], ("acme", "s-other")
    )
    assert not verify_commitment_voters(view["explanation"], "aid:pubkey:someone-else")


def test_an_unspecified_voter_method_fails_closed():
    m = _proto_from_vector(TCT["inputs"]["commitment"])
    m.explanation[2].voter_verification.method = pb.VOTER_VERIFICATION_UNSPECIFIED
    m.explanation_digest = bytes.fromhex(TCT["explanation_digest_hex"])
    assert (
        verify_tct(
            TCT["issuer_aid"], TCT["signed_artifact_jws"], commitment_view(m), now_s=0
        )
        is False
    )


def _voter_entries():
    return [dict(e) for e in TCT["inputs"]["commitment"]["explanation"]]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda es: es[2].update(voter_verification=None),  # a vote with no record
        lambda es: es[0].update(
            voter_verification=es[2]["voter_verification"]
        ),  # an evaluation with one
        lambda es: es[2].update(reason="other reason"),  # entry bytes no longer signed
        lambda es: es[2].update(
            voter_verification={
                **es[2]["voter_verification"],
                "accepted_at_ms": 1700000300001,
            }
        ),  # accepted after expiry
        lambda es: es[2].update(
            voter_verification={**es[2]["voter_verification"], "session_id": "s-other"}
        ),
        lambda es: es[2].update(
            voter_verification={**es[2]["voter_verification"], "method": "cp_signed"}
        ),
    ],
    ids=[
        "missing",
        "on-evaluation",
        "entry-changed",
        "late",
        "other-session",
        "cp-signed",
    ],
)
def test_the_voter_tamper_table_fails_closed(mutate):
    from seam_sdk.crypto import verify_commitment_voters

    es = _voter_entries()
    assert verify_commitment_voters(es, TCT["issuer_aid"])
    mutate(es)
    assert not verify_commitment_voters(es, TCT["issuer_aid"])
