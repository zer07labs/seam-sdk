#!/usr/bin/env python3
"""Emit `conformance/tct_exp_extended.json` — the cross-language `exp` decoding vector.

Five languages verify a TCT and five decoded its `exp` claim differently. Measured before this
vector existed, against real signed tokens:

    case                          Go     Java/Kotlin   Python   TypeScript
    integer                       valid  valid         valid    valid
    exp = N + 0.5, now = N        EXPIRED  EXPIRED     EXPIRED  **valid**
    exp = "10000000000"           refused  refused     **valid**  **valid**
    exp = "1e10"                  refused  refused     refused  **valid**
    exp = true,  now = 0          refused  refused     **valid**  **valid**

The last row is the one worth dwelling on. `exp: true` coerces to `1` in both Python
(`bool` subclasses `int`) and TypeScript (`now >= true`), so at any clock below 1 second the token
**verified**. At a realistic `now` it looks fine — `1000 >= 1` is expired — so a vector written with
a plausible timestamp would have asserted agreement that was accidental rather than real. **Every
type case here therefore pins `now = 0`**, the clock at which a wrongly-typed truthy `exp` is
accepted if the rule is wrong. That is the difference between a vector and a vector that can fail.

NORMATIVE RULE (Go's, adopted — see DECISIONS.md):

    `exp` MUST be a JSON number. Anything else — string, boolean, null, absent, object, array —
    refuses the token. The number is TRUNCATED TOWARD ZERO to whole seconds, then the token is
    expired iff `now >= trunc(exp)`.

Go was chosen because Java and Kotlin already implement it (`instanceof Number` + `longValue()`,
`as? Number` + `toLong()`), making it the existing 3-of-5 majority; it is the only rule with a
written rationale in the source; and it is the strictest of the three, which is the safe direction
for a token verifier.

Every `expect` below is computed from that rule by `_expected()`, never by running an SDK. A vector
whose expectations are read out of the implementation it checks cannot fail — it just writes down
whatever the code already did, which is the vacuity this repo keeps a name for.

For the same reason this script imports nothing from `seam_sdk`, including the commitment-digest
framing it re-derives in `_commitment_digest`. The cost is a copy that could drift from
`seam_sdk.crypto._seam_commitment_digest`; the protection is that the vector's `expect: true` cases
are CONTROLS — if the framing drifted, the grant would stop matching and those cases would go red
before any `expect: false` case could start passing for the wrong reason. A consumer of this vector
must therefore keep at least one `expect: true` case, or every refusal it asserts becomes free.

Run: `python scripts/emit_tct_exp_vectors.py` (writes conformance/tct_exp_extended.json)
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import pathlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = pathlib.Path(__file__).resolve().parents[1]

OUT = REPO / "conformance" / "tct_exp_extended.json"

#: A fixed seed, so the vector is reproducible: re-running this script must not churn the file.
SEED = bytes.fromhex("0909090909090909090909090909090909090909090909090909090909090909")

COMMITMENT = {
    "id": "c-exp-vector",
    "action": "transfer",
    "authority": "treasury",
    "supersedes": None,
    "auth_method": "pinned-key",
    "trust_basis": "attested",
}

#: `absent` is a sentinel distinct from a JSON `null`: one omits the claim, the other sets it to
#: null, and an implementation can easily treat them alike when it should refuse both.
ABSENT = object()

CASES: list[tuple[str, object, int, str]] = [
    # (name, exp value, now, why this case exists)
    (
        "integer_future",
        2000000000,
        1000,
        "the ordinary valid token. A CONTROL: if the commitment framing or the signature ever drifted, "
        "every refusal below would start passing for the wrong reason, and this case is what goes red first",
    ),
    ("integer_past", 500, 1000, "an ordinary expired token"),
    ("integer_exactly_now", 1000, 1000, "RFC 7519 rejects AT expiry, not only after"),
    (
        "fractional_half_second_past_now",
        1000.5,
        1000,
        "truncation, the whole point: trunc(1000.5) is 1000, so `now >= 1000` is already expired. "
        "A float-precise compare accepts it and drifts from every other shim",
    ),
    (
        "fractional_negative_truncates_toward_zero",
        -1.5,
        -2,
        "truncation must be toward ZERO, not floor -- and the CLOCK is what makes that checkable. "
        "trunc(-1.5) is -1 and floor(-1.5) is -2, so only a `now` BETWEEN them tells the two apart: "
        "at now = -2, truncation leaves the token valid and flooring expires it. At now = 0 both "
        "expire it and the case asserts nothing, which is what the first draft of this vector did",
    ),
    (
        "numeric_string_integer_form",
        "10000000000",
        0,
        "a string that Python's int() and JS's relational coercion both accept as a number, and "
        "that Go and Java refuse on type. The divergence two languages shared",
    ),
    (
        "numeric_string_exponent_form",
        "1e10",
        0,
        "the same trap one step along: JS coerces it, Python's int() raises. TS accepted, Python "
        "refused, for different reasons — neither of them the rule",
    ),
    (
        "boolean_true",
        True,
        0,
        "the case a realistic clock hides. `true` coerces to 1 in both Python (bool subclasses int) "
        "and JS, so at now = 0 the token VERIFIED. now = 1000 would have made this pass vacuously",
    ),
    (
        "boolean_false",
        False,
        -1,
        "the falsy twin -- and the CLOCK is what gives it teeth. At now = 0 the coercing rule "
        "refuses it too (`0 >= false` is `0 >= 0`, expired) and the case asserts nothing; the first "
        "draft ran it there and claimed it blocked a 'reject truthy non-numbers' fix, which it did "
        "not. At now = -1 the coercion ACCEPTS it and only a real type rule refuses it",
    ),
    (
        "null",
        None,
        -1,
        "an explicit null must refuse, and must not be confused with absent. At now = -1 for the "
        "same reason as boolean_false: both old rules defaulted a missing or null exp to 0 "
        "(`payload.exp ?? 0`, `payload.get('exp', 0)`), so at any negative clock they ACCEPTED it",
    ),
    (
        "absent",
        ABSENT,
        -1,
        "no exp claim at all; refused, and distinct from null. Same clock, same reason -- and this "
        "is the case that kills a rule reading 'refuse truthy non-numbers', which absent is not",
    ),
    (
        "zero",
        0,
        0,
        "`now >= 0` at now = 0 is expired — the boundary from the other side",
    ),
    ("negative", -1, 0, "a negative expiry is in the past at any non-negative clock"),
    (
        "float_integral",
        2000000000.0,
        1000,
        "a float that IS an integer must behave as that integer",
    ),
    (
        "beyond_int64",
        1e300,
        0,
        "the rule must be TOTAL, and Go's `int64(exp)` is not: the spec leaves the conversion "
        "implementation-defined when the value does not fit. Measured, arm64 saturates to MaxInt64 "
        "and VERIFIES this token; amd64's CVTTSD2SQ yields INT64_MIN and refuses it. A normative "
        "rule whose answer depends on the checker's architecture is not a rule, so all five bound "
        "`exp` to int64 explicitly",
    ),
    (
        "just_below_int64_max",
        9.2e18,
        0,
        "the accepting side of that bound, so it is a bound and not a blanket refusal of large exp",
    ),
    (
        "object",
        {"seconds": 2000000000},
        0,
        "a structured exp refuses; nothing reaches into it",
    ),
    (
        "array",
        [2000000000],
        0,
        "JS's BigInt/Number coercion unwraps a 1-element array; the rule does not",
    ),
]


def _expected(exp: object, now: int) -> bool:
    """The NORMATIVE rule, written once, applied to every case.

    Deliberately does not import or call any SDK. If this function and an SDK disagree, the vector
    says the SDK is wrong — which is only meaningful because this is the rule and not a recording.
    """
    if exp is ABSENT:
        return False
    # `bool` before the number test: `isinstance(True, int)` is True in Python, and JSON `true` is
    # not a number in any of the five languages.
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        return False
    if isinstance(exp, float) and not math.isfinite(exp):
        return False  # unreachable from JSON, which has no NaN/Infinity literal; stated anyway
    # Bounded to int64: Go's `int64(exp)` is implementation-defined outside it, so leaving it
    # unbounded would make the rule mean different things on different architectures.
    if not (-(2**63) <= exp < 2**63):
        return False
    return not (now >= math.trunc(exp))


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _commitment_digest(c: dict) -> str:
    h = hashlib.sha256()
    for field in (
        b"seam-commitment-digest:v1",
        c["id"].encode(),
        c["action"].encode(),
        c["authority"].encode(),
        (c["supersedes"] or "").encode(),
        c["auth_method"].encode(),
        c["trust_basis"].encode(),
    ):
        h.update(len(field).to_bytes(8, "big"))
        h.update(field)
    return h.hexdigest()


def main() -> None:
    sk = Ed25519PrivateKey.from_private_bytes(SEED)
    aid = "aid:pubkey:ed25519:" + _b64(sk.public_key().public_bytes_raw())
    grant = "seam-commitment-digest:" + _commitment_digest(COMMITMENT)

    cases = []
    for name, exp, now, why in CASES:
        payload: dict = {"iss": aid, "sub": aid, "aud": aid, "grants": [grant]}
        if exp is not ABSENT:
            payload["exp"] = exp
        h = _b64(
            json.dumps(
                {"alg": "EdDSA", "typ": "aitp-tct+jwt"}, separators=(",", ":")
            ).encode()
        )
        p = _b64(json.dumps(payload, separators=(",", ":")).encode())
        jws = f"{h}.{p}.{_b64(sk.sign(f'{h}.{p}'.encode()))}"
        cases.append(
            {
                "name": name,
                "why": why,
                "exp": None if exp is ABSENT else exp,
                "exp_absent": exp is ABSENT,
                "now_s": now,
                "jws": jws,
                "expect": _expected(exp, now),
            }
        )

    OUT.write_text(
        json.dumps(
            {
                "$comment": [
                    "seam-sdk's cross-language TCT `exp` decoding vector. SDK-OWNED, machine-emitted",
                    "by scripts/emit_tct_exp_vectors.py -- no signature here was typed by hand.",
                    "conformance/vectors.json is the byte-identity contract with seam-runtime and is",
                    "not edited from this repo; this file covers a claim that fixture does not.",
                    "",
                    "RULE (Go's, normative -- see DECISIONS.md): `exp` MUST be a JSON number. String,",
                    "boolean, null, absent, object and array all refuse the token. The number is",
                    "TRUNCATED TOWARD ZERO to whole seconds, then expired iff `now_s >= trunc(exp)`.",
                    "",
                    "CONTRACT: an implementation MUST return `expect` for every case, using `now_s` as",
                    "its clock. The signature is valid and the grant matches in EVERY case, so a",
                    "`false` is always the `exp` rule and never anything else.",
                    "",
                    "Note the `now_s` values. Every type case pins `now_s = 0` on purpose: `exp: true`",
                    "coerces to 1 in Python and JS, so at a realistic clock it reads as expired and a",
                    "vector written that way would assert agreement that was accidental. At 0 a wrongly",
                    "typed truthy `exp` is ACCEPTED unless the type rule is real.",
                ],
                "issuer_aid": aid,
                "commitment": COMMITMENT,
                "cases": cases,
            },
            indent=2,
        )
        + "\n"
    )
    valid = sum(c["expect"] for c in cases)
    print(
        f"wrote {OUT.relative_to(REPO)}: {len(cases)} cases, {valid} valid, {len(cases) - valid} refused"
    )


if __name__ == "__main__":
    main()
