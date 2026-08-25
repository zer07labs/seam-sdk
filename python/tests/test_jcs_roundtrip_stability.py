"""An integer is canonicalized as itself, or refused — never silently as a different number.

WHAT WAS WRONG
--------------
`seam-sdk#60 <https://github.com/zer07labs/seam-sdk/issues/60>`_ item 2. The int arm refused anything
above 2^53; the float arm had no magnitude check at all. ES6 renders an integral double in
[2^53, 10^21) as a bare integer literal, so `jcs_canonicalize({"t": 1e16})` emitted
`{"t":10000000000000000}` — which `json.loads` reads back as a Python `int` the int arm then refused
outright. Canonicalization was not idempotent under a JSON round trip, and the same numeric value was
accepted as a float and rejected as an int.

WHY THE OBVIOUS FIX IS WRONG, WHICH IS THE REAL POINT OF THIS FILE
------------------------------------------------------------------
"Accept an int iff it is exactly representable as an IEEE double" is the natural predicate and it
would have shipped a wrong digest. `2**60` IS exactly representable — but ES6 prints the *shortest*
round-tripping digits, so JCS renders it `1152921504606847000`. Under that predicate the SDK would
have accepted `2**60` and signed a digest over a number the caller never supplied.

The two renderings diverge from about 2^55, not at the 10^21 decimal/exponential boundary that
intuition suggests. That matters for the tests as much as for the code: a corpus of tidy boundary
values (2^53±1, 10^21±1, powers of ten) passes under BOTH predicates, because powers of ten are
exactly where shortest-digits and the exact expansion coincide. Only a randomized corpus separates
them — the wrong predicate leaves ~97% of random round trips broken. So
`test_round_trip_is_stable_over_a_random_corpus` is randomized on purpose, and its seed is fixed so a
failure is reproducible rather than a Heisenbug.

Run: `python -m pytest python/tests/test_jcs_roundtrip_stability.py -q`
"""

from __future__ import annotations

import enum
import json
import pathlib
import random

import pytest

from seam_sdk import canonicalize_tool_input
from seam_sdk.crypto import _jcs_number, jcs_canonicalize, tool_input_digest
from seam_sdk.errors import CanonicalizationError

#: Rendered as itself by ES6, so accepted. Each entry says why it is interesting.
ACCEPTED = [
    pytest.param(0, id="zero"),
    pytest.param(-1, id="negative-small"),
    pytest.param(2**53, id="2^53-boundary-inclusive"),
    pytest.param(-(2**53), id="negative-2^53"),
    pytest.param(2**53 + 2, id="2^53+2-first-representable-above"),
    pytest.param(10**16, id="10^16-the-issue-case"),
    pytest.param(-(10**16), id="negative-10^16"),
    pytest.param(10**20, id="10^20-largest-non-exponential-decade"),
]

#: Refused, each for a distinct reason.
REJECTED = [
    pytest.param(2**53 + 1, id="not-representable-rounds-to-2^53"),
    pytest.param(2**55, id="representable-but-ES6-shortens-it"),
    pytest.param(2**60, id="the-case-the-obvious-predicate-gets-wrong"),
    pytest.param(10**21, id="ES6-goes-exponential-here"),
    pytest.param(10**400, id="overflows-a-double-entirely"),
]


# ── the reported symptom ─────────────────────────────────────────────────────────────────────────


def test_the_same_numeric_value_is_accepted_as_int_and_as_float() -> None:
    assert jcs_canonicalize(10**16) == jcs_canonicalize(1e16) == b"10000000000000000"


@pytest.mark.parametrize("n", ACCEPTED)
def test_accepted_ints_render_exactly_as_the_float_arm_would(n) -> None:
    """The arms agreeing is asserted directly rather than inferred, because "they happen to agree
    on the values I thought of" is precisely how the wrong predicate looked correct."""
    assert jcs_canonicalize(n) == jcs_canonicalize(float(n))


@pytest.mark.parametrize("n", ACCEPTED)
def test_every_emitted_byte_string_was_already_producible_by_the_float_arm(n) -> None:
    """This is what makes widening the accepted set safe against a runtime this repo cannot read:
    no NEW wire shape is introduced, only values that were always emittable."""
    emitted = jcs_canonicalize(n).decode()
    assert emitted == _jcs_number(float(n))


@pytest.mark.parametrize("n", REJECTED)
def test_rejected_ints_raise_rather_than_skew(n) -> None:
    with pytest.raises(ValueError):
        jcs_canonicalize(n)
    with pytest.raises(CanonicalizationError):
        canonicalize_tool_input({"t": n})


def test_the_rejection_message_names_the_actual_reason() -> None:
    """The old message said "exceeds 2^53", which is now false for values that are still refused —
    2^60 is far past 2^53 and 10^16 is too, yet only one of them is rejected. A message that
    misdescribes the rule sends the next reader looking for the wrong thing."""
    with pytest.raises(ValueError) as exc:
        jcs_canonicalize(2**60)
    message = str(exc.value)
    assert "1152921504606847000" in message, (
        "the message must show what canonicalizing would ACTUALLY have emitted — that number is the "
        "whole argument for refusing"
    )
    assert "exceeds 2^53" not in message


# ── idempotence: the property, not a handful of examples ─────────────────────────────────────────


def test_round_trip_is_stable_over_a_random_corpus() -> None:
    """canonicalize(json.loads(canonicalize(x))) == canonicalize(x), over integral doubles drawn at
    random from the whole affected interval. Randomized deliberately — see this module's docstring."""
    rng = random.Random(60)
    corpus = [float(rng.randrange(2**53, 10**21)) for _ in range(2000)]
    corpus += [float(2**e) for e in range(53, 70)]
    corpus += [1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1.5e22, 1e-7, 0.000001, -1e16]

    broken = []
    for value in corpus:
        once = jcs_canonicalize(value)
        try:
            twice = jcs_canonicalize(json.loads(once))
        except ValueError as e:
            broken.append((value, once, f"refused on the way back: {e}"))
            continue
        if once != twice:
            broken.append((value, once, twice))

    assert not broken, (
        f"{len(broken)} of {len(corpus)} values do not survive a JSON round trip. First three: "
        f"{broken[:3]}"
    )


def test_a_boundary_only_corpus_would_not_have_caught_the_wrong_predicate() -> None:
    """Guard-the-guard. If this ever fails, the values below stopped being the tidy ones that hide
    the difference, and the randomized test above is no longer carrying the weight this file claims
    it carries."""
    tidy = [2**53, 2**53 + 2, 10**16, 10**20]
    assert all(int(float(n)) == n and jcs_canonicalize(n) for n in tidy)
    # ... while these are exactly representable too, and are still refused.
    assert all(int(float(n)) == n for n in (2**55, 2**60))


# ── the subclass hazard on the supported Python floor ────────────────────────────────────────────


class Color(enum.IntEnum):
    RED = 1


class _LyingInt(int):
    """What `IntEnum` does on Python 3.10 — this package's declared floor (`requires-python >=3.10`).

    There, `str(Color.RED)` is `"Color.RED"`, so an int arm built on `str()` emitted
    `{"c":Color.RED}`: invalid JSON, digested and signed. Reproduced here as an explicit subclass so
    the guard holds on every Python, not only on the one that happens to be running.
    """

    def __str__(self) -> str:
        return "Color.RED"

    def __repr__(self) -> str:
        return "Color.RED"


def test_an_int_subclass_cannot_forge_its_own_rendering() -> None:
    assert jcs_canonicalize({"c": Color.RED}) == b'{"c":1}'
    assert jcs_canonicalize({"c": _LyingInt(1)}) == b'{"c":1}', (
        "an int subclass overrode its own rendering into the canonical bytes — the digest would "
        "cover text the caller's value does not mean, and on Python 3.10 a plain IntEnum does this"
    )


def test_bool_is_still_json_true_and_false_not_a_number() -> None:
    """`isinstance(True, int)` is true, so the bool arms must keep preceding the int arm."""
    assert jcs_canonicalize({"a": True, "b": False}) == b'{"a":true,"b":false}'


# ── the shared cross-language pin ────────────────────────────────────────────────────────────────

INT_VECTOR = json.loads(
    (
        pathlib.Path(__file__).parents[2]
        / "conformance"
        / "authorize_jcs_int_extended.json"
    ).read_text()
)


@pytest.mark.parametrize(
    "case", INT_VECTOR["cases"], ids=[c["name"] for c in INT_VECTOR["cases"]]
)
def test_sdk_owned_integer_vector(case) -> None:
    """Python emits this vector, so passing it proves only that nothing moved — `ts/tests/` is where
    it earns its keep, against a separate implementation of the same rule. It is asserted here too
    because a change to `crypto.py` that forgot to regenerate would otherwise be caught only by the
    TypeScript suite, which reads as a TypeScript bug."""
    n = int(
        case["int"]
    )  # a STRING in the file: JSON number parsing would lose the precision
    if case.get("rejected"):
        with pytest.raises(ValueError):
            jcs_canonicalize(n)
        return
    canonical = jcs_canonicalize(n)
    assert canonical.decode() == case["canonical"]
    assert tool_input_digest(canonical) == case["digest"]


def test_the_vector_is_not_one_sided() -> None:
    """Guard-the-guard: the emitter could silently produce an all-accepted or all-refused file, and
    a parametrized loop over it would stay green while proving half of nothing."""
    accepted = sum("canonical" in c for c in INT_VECTOR["cases"])
    refused = sum(c.get("rejected", False) for c in INT_VECTOR["cases"])
    assert accepted >= 8 and refused >= 8, f"{accepted} accepted, {refused} refused"
