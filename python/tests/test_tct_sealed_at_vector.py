"""S-4 evidence grade: ``verify_tct(..., sealed_at_ms=)`` requires ``iat == sealed_at_ms // 1000``.

Pinned by ``conformance/tct_sealed_at_vector.json`` (emitted by ``scripts/emit_tct_sealed_at_vector.py``
over the runtime's byte-identical ``commitment_digest_v6_signed_vector.json``), the same vector the TS,
Go, Java, Kotlin and Rust verifiers answer. Same rule as seam-verify ``verify_tct_sealed_at`` and the
runtime's ``verify_commitment_sealed_at`` (seam-runtime #2031).
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys

import pytest
from seam_sdk.crypto import verify_tct

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
        "iat_plus_1s_at_boundary",
        "iat_minus_1s_at_boundary",
    } <= names


@pytest.mark.parametrize("case", VECTOR["cases"], ids=lambda c: c["name"])
def test_case(case):
    got = verify_tct(
        ISSUER, TOKEN, COMMITMENT, now_s=0, sealed_at_ms=int(case["sealed_at_ms"])
    )
    assert got == (case["expect"] == "verified")


@pytest.mark.parametrize("bad", [-1, True, 1767225600000.0, "1767225600000"])
def test_a_sealed_at_that_is_not_a_u63_integer_is_refused(bad):
    assert not verify_tct(ISSUER, TOKEN, COMMITMENT, now_s=0, sealed_at_ms=bad)


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
