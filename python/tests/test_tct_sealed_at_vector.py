"""Evidence grade: ``verify_tct(..., sealed_at_ms=, decision_id=)`` requires ``iat == sealed_at_ms // 1000``
(S-4) and ``jti == tct_jti(decision_id, sealed_at_ms)`` (seam-runtime 0.127.0 P4).

Pinned by ``conformance/tct_sealed_at_vector.json`` (emitted by ``scripts/emit_tct_sealed_at_vector.py``
over the runtime's byte-identical ``commitment_digest_v6_signed_vector.json``), the same vector the TS,
Go, Java, Kotlin and Rust verifiers answer. Same rule as seam-verify ``verify_tct_sealed_at`` and the
runtime's ``check_commitment_sealed_for``.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys

import pytest
from seam_sdk.crypto import tct_jti, verify_tct

ROOT = pathlib.Path(__file__).resolve().parents[2]
VECTOR_PATH = ROOT / "conformance" / "tct_sealed_at_vector.json"
VECTOR = json.loads(VECTOR_PATH.read_text())
SIGNED = json.loads((ROOT / VECTOR["source"]).read_text())
CASE = next(c for c in SIGNED["cases"] if c["name"] == VECTOR["over"])
ISSUER = SIGNED["issuer_aid"]
TOKEN = CASE["signed_artifact"]
# The published explanation digest without the entries (they carry no voter records), plus the raw
# trailers: exactly how test_commitment_digest_v6 verifies the signed case.
COMMITMENT = {
    **{k: v for k, v in CASE["commitment"].items() if k != "explanation"},
    "trailers": CASE["trailers"],
}


def test_the_control_verifies_without_sealed_at():
    assert verify_tct(ISSUER, TOKEN, COMMITMENT, now_s=0)


def test_every_named_case_is_present():
    names = {c["name"] for c in VECTOR["cases"]}
    assert {
        "exact_second_boundary",
        "last_ms_of_the_second",
        "iat_plus_1s_at_boundary",
        "iat_minus_1s_at_boundary",
        "replayed_onto_another_record",
        "commitment_id_is_not_the_record_id",
    } <= names


@pytest.mark.parametrize("case", VECTOR["cases"], ids=lambda c: c["name"])
def test_case(case):
    got = verify_tct(
        ISSUER,
        TOKEN,
        COMMITMENT,
        now_s=0,
        sealed_at_ms=int(case["sealed_at_ms"]),
        decision_id=case["decision_id"],
    )
    assert got == (case["expect"] == "verified")


@pytest.mark.parametrize("bad", [-1, True, 1767225600000.0, "1767225600000"])
def test_a_sealed_at_that_is_not_a_u63_integer_is_refused(bad):
    assert not verify_tct(
        ISSUER,
        TOKEN,
        COMMITMENT,
        now_s=0,
        sealed_at_ms=bad,
        decision_id=VECTOR["decision_id"],
    )


@pytest.mark.parametrize("bad", [None, 7, b"dec:acme:s-digest-v6-vector-0000"])
def test_a_decision_id_that_is_not_a_string_is_refused(bad):
    kw = {} if bad is None else {"decision_id": bad}
    assert not verify_tct(
        ISSUER,
        TOKEN,
        COMMITMENT,
        now_s=0,
        sealed_at_ms=int(CASE_OK["sealed_at_ms"]),
        **kw,
    )


def test_a_decision_id_without_a_sealed_at_is_refused():
    """Half the evidence-grade rule is not silently checked: the inputs travel together."""
    assert not verify_tct(
        ISSUER, TOKEN, COMMITMENT, now_s=0, decision_id=VECTOR["decision_id"]
    )


def test_the_jti_derivation_matches_the_runtime_known_answer_and_the_token():
    kat = VECTOR["jti_kat"]
    assert tct_jti(kat["decision_id"], int(kat["sealed_at_ms"])) == kat["jti"]
    assert tct_jti(VECTOR["decision_id"], SIGNED["seal_ms"]) == VECTOR["jti"]


CASE_OK = next(c for c in VECTOR["cases"] if c["expect"] == "verified")


def test_the_vector_is_what_the_emitter_emits(tmp_path):
    """Run the emitter against a COPY of the repo, never the real tree."""
    shutil.copytree(ROOT / "scripts", tmp_path / "scripts")
    shutil.copytree(ROOT / "conformance", tmp_path / "conformance")
    (tmp_path / "conformance" / "tct_sealed_at_vector.json").unlink()
    subprocess.run(
        [sys.executable, str(tmp_path / "scripts" / "emit_tct_sealed_at_vector.py")],
        check=True,
        capture_output=True,
    )
    emitted = (tmp_path / "conformance" / "tct_sealed_at_vector.json").read_bytes()
    assert emitted == VECTOR_PATH.read_bytes(), (
        "conformance/tct_sealed_at_vector.json is not what scripts/emit_tct_sealed_at_vector.py "
        "emits: regenerate it, do not hand-edit it"
    )
