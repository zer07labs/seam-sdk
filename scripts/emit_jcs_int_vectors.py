"""Emit `conformance/authorize_jcs_int_extended.json` — the SDK-owned integer cases for JCS.

WHAT THIS VECTOR IS, AND WHAT IT IS NOT
---------------------------------------
It is NOT independent validation of the Python SDK: it is emitted *by* the Python SDK, so Python
reproducing it proves only that nothing changed. Its job is the other language. `ts/src/crypto.ts`
has a completely separate implementation of the same rule, and this file is what makes the two prove
byte-identity to each other rather than each being self-consistent.

`conformance/authorize_jcs_digest_vector.json` is a byte-identity contract with seam-runtime and is
never edited from here. This is the same shape as `conformance/record_digest_v3_extended.json`: an
SDK-owned superset for traps a runtime-owned fixture does not cover.

WHY INTEGERS NEED THEIR OWN CASES
---------------------------------
JCS numbers are IEEE doubles, so the only integers that can appear in canonical output are the ones
ES6 `Number::toString` prints as themselves. The trap is that "exactly representable as a double" is
NOT the same question: 2**60 is exactly representable and still renders as 1152921504606847000 — a
different number. The two answers diverge from about 2^55, and they agree on every power of ten, so
a hand-picked case list looks fine under either rule. Half the accepted cases below are therefore
machine-searched rather than chosen, precisely so they are not tidy.

Every `int` is a STRING. Parsing it as a JSON number would lose precision in JavaScript before any
implementation got a chance to be tested.

Run: `python scripts/emit_jcs_int_vectors.py` (writes the file; no digest is typed by hand).
"""

from __future__ import annotations

import json
import pathlib
import random
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from seam_sdk.crypto import jcs_canonicalize, tool_input_digest  # noqa: E402

OUT = ROOT / "conformance" / "authorize_jcs_int_extended.json"

CHOSEN: list[tuple[str, int, str]] = [
    ("zero", 0, "the degenerate case, and -0 must not appear"),
    ("one", 1, "a plain small integer takes the unchanged fast path"),
    ("negative-one", -1, "sign handling on the fast path"),
    ("max-safe", 2**53, "the 2^53 boundary is INCLUSIVE — the old rule tested >, not >="),
    ("negative-max-safe", -(2**53), "the boundary is symmetric"),
    ("max-safe-plus-one", 2**53 + 1, "rounds to 2^53; not representable at all"),
    ("max-safe-plus-two", 2**53 + 2, "the first integer above the boundary that IS renderable"),
    ("ten-to-16", 10**16, "the case reported in seam-sdk#60: accepted as 1e16, refused as an int"),
    ("negative-ten-to-16", -(10**16), "the reported case, negated"),
    ("ten-to-20", 10**20, "largest decade ES6 still prints without an exponent"),
    ("two-to-55", 2**55, "EXACTLY REPRESENTABLE and still refused — ES6 shortens it"),
    ("two-to-60", 2**60, "the case the obvious 'is it representable' predicate gets wrong"),
    ("ten-to-21", 10**21, "ES6 switches to exponential here, so no integer can match"),
    ("ten-to-21-minus-one", 10**21 - 1, "just below the exponential boundary, still not renderable"),
    ("overflows-a-double", 10**400, "float() itself overflows; must be refused, not crash"),
]


def _render(n: int) -> tuple[str | None, str | None]:
    try:
        return jcs_canonicalize(n).decode("utf-8"), None
    except ValueError as e:
        return None, str(e)


def _searched(count: int) -> list[tuple[str, int, str]]:
    """Find untidy accepted/refused pairs in (2^53, 10^21) — the interval where the two candidate
    rules disagree. Seeded so the file is reproducible; a regenerated file must be byte-identical."""
    rng = random.Random(60)
    found: list[tuple[str, int, str]] = []
    accepted = refused = 0
    while accepted < count or refused < count:
        n = rng.randrange(2**53, 10**21)
        canonical, _ = _render(n)
        if canonical is not None and accepted < count:
            accepted += 1
            found.append((f"searched-accepted-{accepted}", n, "machine-searched, deliberately not a round number"))
        elif canonical is None and refused < count:
            refused += 1
            found.append((f"searched-refused-{refused}", n, "machine-searched: representable or not, ES6 does not print it as itself"))
    return found


def main() -> None:
    cases = []
    for name, n, why in CHOSEN + _searched(4):
        canonical, error = _render(n)
        case: dict = {"name": name, "why": why, "int": str(n)}
        if canonical is None:
            case["rejected"] = True
            case["reason"] = error
        else:
            case["canonical"] = canonical
            case["digest"] = tool_input_digest(canonical.encode("utf-8"))
        cases.append(case)

    OUT.write_text(
        json.dumps(
            {
                "$comment": [
                    "seam-sdk's EXTENDED integer cases for RFC 8785 (JCS) canonicalization.",
                    "Machine-emitted by scripts/emit_jcs_int_vectors.py -- no digest here was typed by hand.",
                    "SDK-OWNED. conformance/authorize_jcs_digest_vector.json is the byte-identity contract",
                    "with seam-runtime and is not edited from this repo; this file is a superset for a trap",
                    "that fixture does not cover.",
                    "CONTRACT: an implementation MUST emit `canonical` byte-for-byte for every case that has",
                    "it, and MUST refuse every case marked `rejected` -- refusing an accepted case or",
                    "accepting a rejected one is equally a break. `digest` is tool_input_digest over the",
                    "canonical bytes.",
                    "`int` is a STRING because parsing it as a JSON number loses precision in JavaScript",
                    "before any implementation could be tested.",
                    "WHY: JCS numbers are IEEE doubles, so the only integers that can appear in canonical",
                    "output are those ES6 Number::toString prints as themselves. 'Exactly representable as a",
                    "double' is a DIFFERENT and wrong rule: 2**60 is representable and renders as",
                    "1152921504606847000. The two rules agree on every power of ten, so half the accepted",
                    "cases below are machine-searched rather than chosen.",
                ],
                "algorithm": "sha256",
                "canonicalization": "RFC 8785 (JSON Canonicalization Scheme)",
                "cases": cases,
            },
            indent=2,
        )
        + "\n"
    )
    kept = sum("canonical" in c for c in cases)
    print(f"wrote {OUT.relative_to(ROOT)}: {len(cases)} cases ({kept} accepted, {len(cases) - kept} refused)")


if __name__ == "__main__":
    main()
