"""seam-commitment-digest:v6 (Flows W2, readers only): every row of both v6 vector files.

Pinned against `conformance/commitment_digest_v6_vector.json` (the runtime's independent stdlib
generator) and `conformance/commitment_digest_v6_signed_vector.json` (real TCTs over v6 commitments),
copied byte for byte from seam-runtime and kept identical by its `sdk-digest-parity`. Framing:
seam-runtime `docs/specs/seam-commitment-digest.v6.md`.

Refusal rows assert the REFUSAL only. The spec makes rule names advisory (§Refusal rules: "a port's
test MUST NOT fail because it named a different applicable rule"), so no test here compares `rule`.

Sections covered: `cases` (15), `digest_input_refusals` (10), `governing_trailer_refusals` (17),
`v5_refusals` (6), `scheme_free` (7), `statement_selection` (29); signed `cases` (3) and
`negatives` (5). A guard below fails if a section grows a row kind this file does not read.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from seam_sdk import (
    gate_digest,
    served_commitment_trailers,
    CommitmentRefused,
    commitment_digest_v6,
    decode_commitment_trailers,
    select_commitment_version,
    verify_tct,
)
from seam_sdk.crypto import (
    _seam_commitment_digest,
    _tct_commitment_digest,
    _v5_commitment_input,
)

ROOT = Path(__file__).resolve().parents[2] / "conformance"
V6 = json.loads((ROOT / "commitment_digest_v6_vector.json").read_text())
SIGNED = json.loads((ROOT / "commitment_digest_v6_signed_vector.json").read_text())
V5_SIGNED = json.loads((ROOT / "commitment_digest_v5_signed_vector.json").read_text())
CASES = {c["name"]: c for c in V6["cases"]}
DOC = hashlib.sha256(b"seam-governing-doc:test-vector").digest()


def _digest_only_input(case: dict) -> dict:
    """A `digest_only` row: fields 9-12 are inputs to the digest function, no trailers back them."""
    assert case["trailers"] is None, case["name"]
    return {
        **case["commitment"],
        "selection_digest": case["selection_digest"],
        "gate_digest": case["gate_digest"],
        "governing_doc_sha256": case["governing_doc_sha256"],
        "env": case["env"],
    }


def _trailer_input(case: dict) -> dict:
    """A derived row: fields 10-12 come from `trailers` alone (field 9 stays an input, as in v5)."""
    assert isinstance(case["trailers"], str), case["name"]
    return {
        **case["commitment"],
        "selection_digest": case["selection_digest"],
        "trailers": case["trailers"],
    }


def test_the_vector_files_are_the_v6_spec():
    assert V6["commitment_digest_domain"] == "seam-commitment-digest:v6"
    assert SIGNED["commitment_digest_domain"] == "seam-commitment-digest:v6"
    assert V6["gate_digest_domain"] == "seam-gate-digest:v1"


def test_every_section_is_read():
    """Guard: a new section in either file must be read here, not silently skipped."""
    assert {k for k, v in V6.items() if isinstance(v, list)} == {
        "cases",
        "digest_input_refusals",
        "governing_trailer_refusals",
        "v5_refusals",
        "scheme_free",
        "statement_selection",
    }
    assert {k for k, v in SIGNED.items() if isinstance(v, list)} == {
        "cases",
        "negatives",
    }


# ── cases ────────────────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("case", V6["cases"], ids=lambda c: c["name"])
def test_case_digest(case):
    if case["digest_only"]:
        c = _digest_only_input(case)
    else:
        c = _trailer_input(case)
        # The derived path must not be fed the values it derives.
        assert "gate_digest" not in c and "env" not in c
        assert "governing_doc_sha256" not in case["commitment"]
    assert commitment_digest_v6(c) == case["commitment_digest"]


@pytest.mark.parametrize(
    "case", [c for c in V6["cases"] if not c["digest_only"]], ids=lambda c: c["name"]
)
def test_case_fields_10_to_12_derive_from_the_trailers(case):
    got = decode_commitment_trailers(case["trailers"], "v6")
    assert got.field_10.hex() == case["field_10"]
    assert got.field_11.hex() == case["field_11"]
    assert got.field_12.hex() == case["field_12"]
    assert (None if got.gate_digest is None else got.gate_digest.hex()) == case[
        "gate_digest"
    ]
    assert got.env == case["env"]


@pytest.mark.parametrize(
    "case", [c for c in V6["cases"] if c["digest_only"]], ids=lambda c: c["name"]
)
def test_recut_case_equals_the_v5_digest_under_v5(case):
    """Every v5 case re-cut under v6: same inputs, and its v5 digest is the v5 file's (field 10 there is
    v5's opaque `certificate_digest`)."""
    c = {
        **case["commitment"],
        "selection_digest": case["selection_digest"],
        "certificate_digest": case["gate_digest"],
        "governing_doc_sha256": case["governing_doc_sha256"],
    }
    assert _seam_commitment_digest(c) == case["v5_commitment_digest"]
    assert case["commitment_digest"] != case["v5_commitment_digest"]


def test_a_digest_only_case_has_no_trailers_to_derive_from():
    """The spec's loud-failure rule: a port that derives from `trailers` meets `null` there."""
    for case in V6["cases"]:
        assert (case["trailers"] is None) == case["digest_only"], case["name"]


def test_values_beside_the_trailers_must_agree():
    case = CASES["populated_gate_answered_env_live"]
    c = _trailer_input(case)
    assert (
        commitment_digest_v6({**c, "governing_doc_sha256": DOC, "env": "live"})
        == case["commitment_digest"]
    )
    with pytest.raises(ValueError):
        commitment_digest_v6({**c, "env": "sandbox"})
    with pytest.raises(ValueError):
        commitment_digest_v6({**c, "governing_doc_sha256": bytes(32)})
    with pytest.raises(ValueError):
        commitment_digest_v6({**c, "gate_digest": bytes(32)})


def test_v6_has_no_certificate_digest_slot():
    with pytest.raises(ValueError):
        commitment_digest_v6(
            {**_digest_only_input(CASES["all_empty"]), "certificate_digest": DOC}
        )


# ── refusals ─────────────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("row", V6["digest_input_refusals"], ids=lambda r: r["name"])
def test_digest_input_refusal(row):
    assert row["scheme"] == "v6"
    c = _digest_only_input(CASES[row["base_case"]])
    if "override" in row:
        c.update(row["override"])
    else:
        c["env"] = row["env"]
        if row["base_case"] == "all_empty":
            assert c["governing_doc_sha256"] is None
    with pytest.raises(CommitmentRefused):
        commitment_digest_v6(c)


@pytest.mark.parametrize(
    "row", V6["governing_trailer_refusals"], ids=lambda r: r["name"]
)
def test_governing_trailer_refusal(row):
    assert row["scheme"] == "v6"
    with pytest.raises(CommitmentRefused):
        decode_commitment_trailers(row["trailers"], "v6")


@pytest.mark.parametrize("row", V6["v5_refusals"], ids=lambda r: r["name"])
def test_v5_refusal(row):
    assert row["scheme"] == "v5"
    if row.get("trailers") is not None:
        with pytest.raises(CommitmentRefused):
            decode_commitment_trailers(row["trailers"], "v5")
        return
    # `env_under_v5_digest`: a v5 digest asked to frame an env.
    c = {**_digest_only_input(CASES[row["base_case"]]), "env": row["env"]}
    c.pop("gate_digest")
    with pytest.raises(CommitmentRefused):
        _v5_commitment_input(c)
    with pytest.raises(CommitmentRefused):
        _tct_commitment_digest("v5", c)


def test_v5_still_accepts_its_own_v1_body():
    """Positive control beside `v5_refusals`: `0x06 ‖ u32le(33) ‖ 0x01 ‖ doc` decodes under v5."""
    got = decode_commitment_trailers("06" + "21000000" + "01" + DOC.hex(), "v5")
    assert got.field_10 == b"\x00"
    assert got.field_11.hex() == CASES["doc_present"]["field_11"]
    assert got.field_12 is None
    assert got.governing_body_version == 1


def test_an_env_on_a_v5_tct_refuses_it():
    """`v5_refuses_env` end to end: a real v5 TCT that verifies stops verifying once an env is asked for."""
    (case,) = [
        c
        for c in V5_SIGNED["cases"]
        if c["commitment"]["signed_artifact"]
        and c["commitment"]["governing_doc_sha256"] is not None
    ]
    c = case["commitment"]
    jws = bytes(c["signed_artifact"]).decode()
    assert verify_tct(V5_SIGNED["issuer_aid"], jws, c, now_s=0)
    assert not verify_tct(V5_SIGNED["issuer_aid"], jws, {**c, "env": "live"}, now_s=0)
    v1 = "06" + "21000000" + "01" + bytes(c["governing_doc_sha256"]).hex()
    assert verify_tct(V5_SIGNED["issuer_aid"], jws, {**c, "trailers": v1}, now_s=0)
    v2 = "06" + "22000000" + "02" + bytes(c["governing_doc_sha256"]).hex() + "00"
    assert not verify_tct(V5_SIGNED["issuer_aid"], jws, {**c, "trailers": v2}, now_s=0)


# ── scheme-free ──────────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("row", V6["scheme_free"], ids=lambda r: r["name"])
def test_scheme_free(row):
    assert row["scheme"] is None
    if row["expect"] == "refused":
        with pytest.raises(CommitmentRefused):
            decode_commitment_trailers(row["trailers"], None)
        return
    got = decode_commitment_trailers(row["trailers"], None)
    want = row["expect"]
    assert got.field_10.hex() == want["field_10"]
    assert got.field_11.hex() == want["field_11"]
    assert (None if got.field_12 is None else got.field_12.hex()) == want.get(
        "field_12"
    )
    assert got.governing_body_version == want["governing_body_version"]


def test_scheme_must_be_named():
    with pytest.raises(ValueError):
        decode_commitment_trailers("", "v7")


# ── statement selection ──────────────────────────────────────────────────────────────────────────────


def _ext_of(row: dict) -> str:
    """A `statement` row is the raw statement text; it is entered as `ext`'s `com.zer07labs.seam` member,
    verbatim, so every byte of it (escapes, duplicates, malformations) reaches the parser."""
    if "ext" in row:
        return row["ext"]
    return '{"com.zer07labs.seam":' + row["statement"] + "}"


@pytest.mark.parametrize("row", V6["statement_selection"], ids=lambda r: r["name"])
def test_statement_selection(row):
    ext = _ext_of(row)
    if row["expect"] == "refused":
        with pytest.raises(CommitmentRefused):
            select_commitment_version(ext)
        with pytest.raises(CommitmentRefused):
            select_commitment_version(ext.encode("utf-8"))
    else:
        assert select_commitment_version(ext) == row["expect"]
        assert select_commitment_version(ext.encode("utf-8")) == row["expect"]


@pytest.mark.parametrize(
    "raw",
    [
        '{"com.zer07labs.seam":{"type":"seam:commitment","commitment_digest":NaN}}',
        b'{"com.zer07labs.seam":\xff}',
        "[" * 100000,
    ],
)
def test_selection_refuses_what_json_is_not(raw):
    with pytest.raises(CommitmentRefused):
        select_commitment_version(raw)


def test_duplicate_detection_reaches_every_depth():
    inner = '{"type":"seam:commitment","commitment_digest":"' + "a" * 64 + '"}'
    deep = '{"o":{"a":[{"b":{"k":1,"\\u006b":2}}]},"com.zer07labs.seam":' + inner + "}"
    with pytest.raises(CommitmentRefused):
        select_commitment_version(deep)
    assert select_commitment_version('{"com.zer07labs.seam":' + inner + "}") == "v5"


# ── the signed vector: real TCTs over v6 commitments ─────────────────────────────────────────────────

SIGNED_CASES = {c["name"]: c for c in SIGNED["cases"]}


def _signed_commitment(case: dict) -> dict:
    """The signed case as `verify_tct` reads it: its raw `trailers`, and the PUBLISHED explanation
    digest without the entries. The vector's vote and objection entries carry no `seam-voter-pop-v1`
    records, and since runtime 0.87.0 `verify_tct` checks those records whenever the entries are given
    (`test_signed_entries_without_voter_records_fail_closed`), so the entries prove *why* only with a
    vector that carries them. Field 8 is the same 32 bytes either way."""
    c = {k: v for k, v in case["commitment"].items() if k != "explanation"}
    return {**c, "trailers": case["trailers"]}


def test_signed_entries_without_voter_records_fail_closed():
    case = SIGNED["cases"][0]
    c = {**case["commitment"], "trailers": case["trailers"]}
    assert commitment_digest_v6(c) == case["commitment_digest"]
    assert any(
        e["kind"] in ("vote", "objection") and e["voter_verification"] is None
        for e in c["explanation"]
    )
    assert not verify_tct(SIGNED["issuer_aid"], case["signed_artifact"], c, now_s=0)


@pytest.mark.parametrize("case", SIGNED["cases"], ids=lambda c: c["name"])
def test_signed_case_verifies(case):
    c = _signed_commitment(case)
    assert select_commitment_version(case["ext"]) == case["expect"] == "v6"
    got = decode_commitment_trailers(case["trailers"], "v6")
    assert got.field_10.hex() == case["field_10"]
    assert got.field_11.hex() == case["field_11"]
    assert got.field_12.hex() == case["field_12"]
    assert commitment_digest_v6(c) == case["commitment_digest"]
    assert verify_tct(SIGNED["issuer_aid"], case["signed_artifact"], c, now_s=0)


def _served_projection(trailers_hex: str) -> dict:
    """What a served ``seam.api.v1.Commitment`` carries instead of raw trailers (#420): ``gate = 13``
    (the exact ``0x05`` body), ``governing_doc_sha256 = 11`` and ``env = 14``."""
    raw = bytes.fromhex(trailers_hex)
    gate_body = None
    if raw[:1] == b"\x05":
        n = int.from_bytes(raw[1:5], "little")
        gate_body = raw[5 : 5 + n]
    t = decode_commitment_trailers(raw, "v6")
    return {
        "gate_body": gate_body,
        "governing_doc_sha256": t.governing_doc_sha256,
        "env": t.env,
    }


@pytest.mark.parametrize("case", SIGNED["cases"], ids=lambda c: c["name"])
def test_served_projection_rebuilds_the_trailers_exactly(case):
    """The served projection is lossless under v6: it rebuilds the sealed trailer run byte for byte."""
    p = _served_projection(case["trailers"])
    got = served_commitment_trailers(
        p["gate_body"], p["governing_doc_sha256"], p["env"]
    )
    assert got.hex() == case["trailers"]


@pytest.mark.parametrize("case", SIGNED["cases"], ids=lambda c: c["name"])
def test_a_served_commitment_verifies(case):
    """#420: a commitment as ``GetCommitmentProof`` serves it (no raw trailers, the projection beside)
    verifies. Before the fix absent trailers read as ``b""`` and every governed record failed."""
    c = {
        **_signed_commitment(case),
        "trailers": None,
        **_served_projection(case["trailers"]),
    }
    assert verify_tct(SIGNED["issuer_aid"], case["signed_artifact"], c, now_s=0)


@pytest.mark.parametrize("case", SIGNED["cases"], ids=lambda c: c["name"])
def test_a_wrong_served_projection_fails(case):
    """Nothing served is trusted: each projected value is hashed into the digest the TCT signs."""
    c = {
        **_signed_commitment(case),
        "trailers": None,
        **_served_projection(case["trailers"]),
    }
    aid, jws = SIGNED["issuer_aid"], case["signed_artifact"]
    if c["governing_doc_sha256"] is None:
        assert not verify_tct(
            aid, jws, {**c, "governing_doc_sha256": "11" * 32}, now_s=0
        )
        return
    assert not verify_tct(aid, jws, {**c, "governing_doc_sha256": "11" * 32}, now_s=0)
    assert not verify_tct(
        aid,
        jws,
        {**c, "governing_doc_sha256": None, "env": None, "gate_body": None},
        now_s=0,
    )
    flipped = {"live": "sandbox", "sandbox": "live", None: "live"}[c["env"]]
    assert not verify_tct(aid, jws, {**c, "env": flipped}, now_s=0)
    if c["gate_body"] is not None:
        # A Gate digest is never taken from beside: without the body, a stated digest refuses.
        assert not verify_tct(
            aid,
            jws,
            {**c, "gate_body": None, "gate_digest": gate_digest(c["gate_body"])},
            now_s=0,
        )
        assert not verify_tct(aid, jws, {**c, "gate_body": None}, now_s=0)


@pytest.mark.parametrize("case", SIGNED["cases"], ids=lambda c: c["name"])
def test_signed_case_trailers_rule(case):
    """VG1, the same rule in every port: with raw trailers, fields 10-12 come from them only, so a
    different trailer run is a different digest and a value beside must agree; with neither trailers nor
    a projection, the record reads as having neither trailer."""
    c = _signed_commitment(case)
    assert verify_tct(SIGNED["issuer_aid"], case["signed_artifact"], c, now_s=0)
    bare = {**c, "trailers": None, "governing_doc_sha256": None, "env": None}
    assert verify_tct(SIGNED["issuer_aid"], case["signed_artifact"], bare, now_s=0) is (
        case["trailers"] == ""
    )
    assert not verify_tct(
        SIGNED["issuer_aid"],
        case["signed_artifact"],
        {**c, "governing_doc_sha256": "11" * 32},
        now_s=0,
    )
    other = "" if case["trailers"] else "0622000000" + "02" + bytes(32).hex() + "00"
    assert not verify_tct(
        SIGNED["issuer_aid"],
        case["signed_artifact"],
        {**c, "trailers": other, "governing_doc_sha256": None},
        now_s=0,
    )


@pytest.mark.parametrize(
    "args,rule",
    [
        ((None, None, "live"), "env_without_governing_doc"),
        ((None, b"\x01" * 31, None), "slot_length_not_32"),
        ((None, b"\x01" * 32, ""), "env_not_sandbox_or_live"),
        ((None, b"\x01" * 32, "Live"), "env_not_sandbox_or_live"),
    ],
)
def test_served_commitment_trailers_refusals(args, rule):
    with pytest.raises(CommitmentRefused) as e:
        served_commitment_trailers(*args)
    assert e.value.rule == rule


def test_a_served_gate_body_on_a_v5_statement_refuses():
    c = dict(V5_SIGNED["cases"][0]["commitment"])
    with pytest.raises(CommitmentRefused):
        _tct_commitment_digest("v5", {**c, "gate_body": b"\x01"})
    with pytest.raises(CommitmentRefused):
        _tct_commitment_digest("v5", {**c, "env": "live"})


@pytest.mark.parametrize("over", ["gate_body", "env"])
def test_a_served_projection_beside_raw_trailers_refuses(over):
    """The raw trailers are the only source: a projection beside them refuses under the same rule
    name as Go, Java and Kotlin, even when it agrees."""
    case = next(
        c
        for c in SIGNED["cases"]
        if c["trailers"].startswith("05") and "06" in c["trailers"]
    )
    raw = _signed_commitment(case)
    value = b"\x00" if over == "gate_body" else "live"
    with pytest.raises(CommitmentRefused) as e:
        _tct_commitment_digest("v6", {**raw, over: value})
    assert e.value.rule == "served_projection_beside_trailers"


@pytest.mark.parametrize("row", SIGNED["negatives"], ids=lambda r: r["name"])
def test_signed_negative_is_refused(row):
    over = SIGNED_CASES[row["over"]]
    assert row["expect"] == "refused"
    assert not verify_tct(
        SIGNED["issuer_aid"], row["signed_artifact"], _signed_commitment(over), now_s=0
    )


def test_signed_negatives_fail_where_the_spec_says():
    """The never-fall-back rule, row by row: each negative either selects v5 (and the v5 recompute
    differs, or v5 refuses the trailers) or is refused by selection itself."""
    by = {r["name"]: r for r in SIGNED["negatives"]}
    assert select_commitment_version(by["domain_absent_over_v6_digest"]["ext"]) == "v5"
    assert (
        select_commitment_version(by["v5_statement_over_env_commitment"]["ext"]) == "v5"
    )
    for name in ("domain_v5", "domain_v7", "duplicate_domain_member"):
        with pytest.raises(CommitmentRefused):
            select_commitment_version(by[name]["ext"])
    with pytest.raises(CommitmentRefused):
        _tct_commitment_digest(
            "v5", _signed_commitment(SIGNED_CASES["v6_gate_answered_env_live"])
        )
    ungoverned = _signed_commitment(SIGNED_CASES["v6_ungoverned"])
    assert _tct_commitment_digest("v5", ungoverned) != commitment_digest_v6(ungoverned)


@pytest.mark.parametrize("case", SIGNED["cases"], ids=lambda c: c["name"])
def test_commitment_view_of_a_served_proto_verifies(case):
    """#420 end to end: the ``pb.Commitment`` ``GetCommitmentProof`` serves, read by ``commitment_view``."""
    from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
    from seam_sdk.client import commitment_view

    cm = case["commitment"]
    p = _served_projection(case["trailers"])
    msg = pb.Commitment(
        id=cm["id"],
        action=cm["action"],
        authority=cm["authority"],
        auth_method=cm["auth_method"],
        trust_basis=cm["trust_basis"],
        committer=cm.get("committer") or "",
        explanation_digest=bytes(cm["explanation_digest"]),
    )
    if cm.get("supersedes") is not None:
        msg.supersedes = cm["supersedes"]
    if p["governing_doc_sha256"] is not None:
        msg.governing_doc_sha256 = p["governing_doc_sha256"]
    if p["env"] is not None:
        msg.env = p["env"]
    if p["gate_body"] is not None:
        msg.gate.body = p["gate_body"]
    view = {**commitment_view(msg), "explanation": None}
    if case.get("selection_digest"):
        view["selection_digest"] = case["selection_digest"]
    assert verify_tct(SIGNED["issuer_aid"], case["signed_artifact"], view, now_s=0)
    msg.ClearField("env") if msg.HasField("env") else setattr(msg, "env", "live")
    assert not verify_tct(
        SIGNED["issuer_aid"],
        case["signed_artifact"],
        {**commitment_view(msg), "explanation": None},
        now_s=0,
    )
