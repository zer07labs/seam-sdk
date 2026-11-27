// Evidence grade: `verifyTct(..., { sealedAtMs, decisionId })` requires `iat == floor(sealedAtMs / 1000)`
// (S-4) and `jti == tctJti(decisionId, sealedAtMs)` (seam-runtime 0.127.0 P4).
//
// Pinned by `conformance/tct_sealed_at_vector.json` (emitted by `scripts/emit_tct_sealed_at_vector.py` over
// the runtime's byte-identical `commitment_digest_v6_signed_vector.json`), the vector the Python, Go, Java,
// Kotlin and Rust verifiers answer too. Same rule as seam-verify `verify_tct_sealed_at` and the runtime's
// `check_commitment_sealed_for`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { type Commitment, tctJti, verifyTct } from "../src/index.js";

const conf = (name: string) => JSON.parse(readFileSync(new URL(`../../${name}`, import.meta.url), "utf8"));
const V = conf("conformance/tct_sealed_at_vector.json");
const S = conf(V.source);
const CASE = S.cases.find((c: { name: string }) => c.name === V.over);
// The published explanation digest without the entries (they carry no voter records), plus the raw
// trailers: exactly how commitment_digest_v6.test.ts verifies the signed case.
const COMMITMENT: Commitment = {
  ...(CASE.commitment as Commitment),
  explanation: undefined,
  explanation_digest: Uint8Array.from(CASE.commitment.explanation_digest),
  governing_doc_sha256:
    CASE.commitment.governing_doc_sha256 === null ? null : Uint8Array.from(CASE.commitment.governing_doc_sha256),
  trailers: CASE.trailers,
};
const verify = (sealedAtMs?: bigint | number, decisionId: string | undefined = V.decision_id) =>
  verifyTct(S.issuer_aid, CASE.signed_artifact, COMMITMENT, 0, {
    sealedAtMs,
    decisionId: sealedAtMs === undefined ? undefined : decisionId,
  });

test("tct sealed_at: the control verifies without sealedAtMs", () => {
  assert.equal(verify(), true);
});

test("tct sealed_at: every vector case answers its expect", () => {
  const names = new Set(V.cases.map((c: { name: string }) => c.name));
  for (const n of [
    "exact_second_boundary",
    "last_ms_of_the_second",
    "iat_plus_1s_at_boundary",
    "iat_minus_1s_at_boundary",
    "replayed_onto_another_record",
    "commitment_id_is_not_the_record_id",
  ])
    assert.ok(names.has(n), n);
  for (const c of V.cases)
    assert.equal(verify(BigInt(c.sealed_at_ms), c.decision_id), c.expect === "verified", c.name);
});

test("tct sealed_at: the two evidence-grade inputs travel together", () => {
  const s = BigInt(V.iat) * 1000n;
  const tok = (o: object) => verifyTct(S.issuer_aid, CASE.signed_artifact, COMMITMENT, 0, o);
  assert.equal(tok({ sealedAtMs: s }), false, "sealedAtMs without decisionId");
  assert.equal(tok({ decisionId: V.decision_id }), false, "decisionId without sealedAtMs");
  assert.equal(tok({ sealedAtMs: s, decisionId: 7 }), false, "a non-string decisionId");
});

test("tct jti: the derivation matches the runtime known answer and the token", () => {
  const k = V.jti_kat;
  assert.equal(tctJti(k.decision_id, BigInt(k.sealed_at_ms)), k.jti);
  assert.equal(tctJti(V.decision_id, BigInt(S.seal_ms)), V.jti);
});

test("tct sealed_at: a number is accepted only as a safe integer", () => {
  const s = Number(V.iat) * 1000;
  assert.equal(verify(s), true);
  assert.equal(verify(s + 0.5), false);
  assert.equal(verify(-1), false);
  assert.equal(verify(Number.MAX_SAFE_INTEGER + 1), false);
});
