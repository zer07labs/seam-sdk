// `verifyTct` must decode `exp` the way Go, Java and Kotlin already did — pinned by a shared vector.
//
// TypeScript was the loosest of the five SDKs here, and by some distance. `now >= (payload.exp ?? 0)`
// hands `exp` straight to JavaScript's relational operator, which coerces almost anything to a
// number rather than refusing it. Measured by running the pre-change build and this one over the
// same 16 signed tokens, TS ACCEPTED six shapes Go refuses:
//
//   exp = "10000000000"   ->  ToNumber("10000000000")  ->  10000000000   accepted
//   exp = "1e10"          ->  ToNumber("1e10")         ->  10000000000   accepted
//   exp = true            ->  ToNumber(true)           ->  1             accepted at now = 0
//   exp = [2000000000]    ->  ToPrimitive -> "2000000000"                accepted
//   exp = {seconds: ...}  ->  NaN, and `0 >= NaN` is false               accepted
//   exp = N + 0.5         ->  float-precise compare, no truncation       accepted at now = N
//
// Every row is a capability token a verifier honoured that its peers rejected. The object case is
// the sharpest: `exp` was garbage, the comparison was NaN, and NaN comparisons are false — so the
// "is it expired?" test answered "no" and the token sailed through. A guard whose false branch is
// the permissive one fails open on every input it cannot understand.
//
// The vector is SDK-owned and machine-emitted by `scripts/emit_tct_exp_vectors.py`, which derives
// each `expect` from the RULE rather than from any implementation. `go/crypto/tct_exp_vector_test.go`
// and `python/tests/test_tct_exp_vector.py` read the same file, so the three languages are held to
// one artifact instead of three opinions.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { type Commitment, verifyTct } from "../src/crypto.js";

type ExpCase = {
  name: string;
  why: string;
  now_s: number;
  jws: string;
  expect: boolean;
};

const vector = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "..", "..", "conformance", "tct_exp_extended.json"),
    "utf8",
  ),
) as {
  issuer_aid: string;
  // The emitter writes JSON, where an absent `supersedes` is `null`; `Commitment` spells the same
  // thing as an optional field. Normalized once, below, rather than cast away at each call.
  commitment: Omit<Commitment, "supersedes"> & { supersedes: string | null };
  cases: ExpCase[];
};

const commitment: Commitment = {
  ...vector.commitment,
  supersedes: vector.commitment.supersedes ?? undefined,
};

test("the vector can actually fail", () => {
  // A vector of nothing-but-refusals is free to satisfy: `return false` would pass all of it. At
  // least one case must be a token that genuinely verifies, so a regression in the signature check,
  // the AID parse or the commitment framing reddens here rather than quietly turning every refusal
  // below into a pass for the wrong reason.
  assert.ok(vector.cases.length > 0, "empty vector");
  assert.ok(
    vector.cases.some((c) => c.expect),
    "no case expects acceptance; a verifyTct stuck at false would pass this whole file",
  );
});

for (const c of vector.cases) {
  test(`exp shape: ${c.name}`, () => {
    const got = verifyTct(vector.issuer_aid, c.jws, commitment, c.now_s);
    assert.equal(got, c.expect, `verifyTct(now_s=${c.now_s}) disagrees with the vector.\n  ${c.why}`);
  });
}

test("the boolean case runs at a clock where the bug is visible", () => {
  // `ToNumber(true)` is 1, so `exp: true` reads as expired at any clock above 1 second and the case
  // asserts nothing. It only catches the coercion at now = 0. Pinning that here means a later edit
  // to the vector cannot quietly make this case vacuous while leaving it green.
  const boolean = vector.cases.find((c) => c.name === "boolean_true");
  assert.ok(boolean, "the vector must carry a boolean exp case");
  assert.equal(boolean.now_s, 0, "at any clock above 1 this case passes whether or not the rule exists");
  assert.equal(boolean.expect, false);
});

test("truncation is toward zero, and the vector proves it rather than assuming it", () => {
  // trunc(-1.5) is -1; floor(-1.5) is -2. Only a clock BETWEEN them tells the two apart, so the
  // case pins now = -2: truncation leaves the token valid, flooring expires it.
  const neg = vector.cases.find((c) => c.name === "fractional_negative_truncates_toward_zero");
  assert.ok(neg, "the vector must carry a negative fractional exp case");
  assert.equal(neg.now_s, -2, "at now = 0 both truncation and flooring expire it; the case would be vacuous");
  assert.equal(neg.expect, true);
});
