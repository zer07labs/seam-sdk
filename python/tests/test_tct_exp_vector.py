"""`verify_tct` must decode `exp` the way Go, Java and Kotlin already did — pinned by a shared vector.

Five SDKs verified a TCT and five decoded its `exp` claim differently. Measured by running the
pre-change `verify_tct`/`verifyTct` and this tree's side by side over the same signed tokens — the
16 in the vector — rather than by reading the three implementations and reasoning about them:

    case                          Go/Java/Kotlin   Python     TypeScript
    exp = "10000000000"           refused          ACCEPTED   ACCEPTED
    exp = true,  now = 0          refused          ACCEPTED   ACCEPTED
    exp = "1e10"                  refused          refused    ACCEPTED
    exp = N + 0.5, now = N        expired          expired    ACCEPTED
    exp = {...} / [...]           refused          refused    ACCEPTED

Every one of those is a token a verifier accepted that its peers rejected — the failure mode a
capability token exists to prevent, reached by five spellings of "not a number".

`exp: true` is the one worth naming. `bool` subclasses `int` in Python and coerces to `1` in JS, so
the token verified at any clock below one second. At a realistic `now` it reads as long expired,
which means a test written with a plausible timestamp would have asserted agreement that was
entirely accidental. The vector pins `now = 0` on every type case for exactly that reason, and
`conformance/tct_exp_extended.json` says so in its own header.

The vector is SDK-owned and machine-emitted by `scripts/emit_tct_exp_vectors.py`, which derives each
`expect` from the *rule* rather than from any implementation — see that script's docstring. Go reads
the same file from `go/crypto/tct_exp_vector_test.go`, and `ts/tests/tct_exp_vector.test.ts` from
the other side, so the three languages are held to one artifact instead of three opinions.
"""

import json
import pathlib

import pytest

from seam_sdk.crypto import verify_tct

VECTOR_PATH = (
    pathlib.Path(__file__).parents[2] / "conformance" / "tct_exp_extended.json"
)
VECTOR = json.loads(VECTOR_PATH.read_text())
CASES = VECTOR["cases"]


def test_the_vector_can_actually_fail() -> None:
    """A vector of nothing-but-refusals is free: `return False` would satisfy it completely.

    At least one case must be a token that genuinely verifies, so that a regression in the signature
    check, the AID parse, or the commitment framing reddens here instead of silently converting every
    refusal below into a pass for the wrong reason.
    """
    assert CASES, "empty vector"
    accepted = [c["name"] for c in CASES if c["expect"]]
    assert accepted, (
        "no case expects acceptance; `verify_tct` stuck at False would pass this file"
    )


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_exp_shape_matches_the_shared_vector(case: dict) -> None:
    got = verify_tct(
        VECTOR["issuer_aid"], case["jws"], VECTOR["commitment"], case["now_s"]
    )
    assert got is case["expect"], (
        f"{case['name']}: verify_tct(now_s={case['now_s']}) returned {got}, "
        f"vector says {case['expect']}.\n  why this case exists: {case['why']}"
    )


def test_bool_is_refused_even_where_int_would_be_accepted() -> None:
    """The `bool` exclusion, asserted directly rather than only through the vector.

    `isinstance(True, int)` is True, so a type check written as `isinstance(exp, (int, float))`
    admits `exp: true` as `exp: 1`. The vector covers it, but only at `now = 0` — and the reason it
    has to is worth pinning where a reader of `crypto.py` will find it: at `now = 0` a truthy
    non-number is ACCEPTED by the buggy rule, and at every larger clock it is not.
    """
    boolean = next(c for c in CASES if c["name"] == "boolean_true")
    assert boolean["now_s"] == 0, (
        "the boolean case must run at now_s = 0; at any clock above 1 it passes vacuously, "
        "because `now >= 1` expires the token whether or not the type rule exists"
    )
    assert boolean["expect"] is False
    assert (
        verify_tct(VECTOR["issuer_aid"], boolean["jws"], VECTOR["commitment"], 0)
        is False
    )


def test_the_vector_is_reproducible_from_its_emitter(tmp_path: pathlib.Path) -> None:
    """Re-running the emitter must produce this exact file, byte for byte.

    The vector carries Ed25519 signatures. Regenerated from a fresh key each run it would churn on
    every commit and nobody could tell a real change from noise, so the emitter pins its seed. This
    is what keeps that true, and what catches a hand-edit of a machine-owned file.

    Runs the emitter against a COPY of the repo. The first version pointed it at the real tree and
    restored the bytes afterwards, which meant an ordinary ``pytest`` run wrote into
    ``conformance/`` — a test that mutates the working tree to check that the working tree is
    unmutated, and one interrupted run away from leaving a regenerated vector behind.
    """
    import shutil
    import subprocess
    import sys

    root = pathlib.Path(__file__).parents[2]
    shutil.copytree(root / "scripts", tmp_path / "scripts")
    (tmp_path / "conformance").mkdir()
    subprocess.run(
        [sys.executable, str(tmp_path / "scripts" / "emit_tct_exp_vectors.py")],
        check=True,
        capture_output=True,
    )
    emitted = (tmp_path / "conformance" / "tct_exp_extended.json").read_bytes()
    assert emitted == VECTOR_PATH.read_bytes(), (
        "conformance/tct_exp_extended.json is not what scripts/emit_tct_exp_vectors.py emits — "
        "regenerate it, do not hand-edit it"
    )
