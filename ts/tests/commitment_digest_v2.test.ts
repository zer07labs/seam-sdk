// `seam-commitment-digest:v2` + `seam-explanation-digest:v1` against the runtime's reference vector.
//
// `conformance/commitment_digest_v2_vector.json` is seam-runtime's
// `crates/seam-trust-aitp/tests/fixtures/commitment_digest_v2_vector.json`, vendored. Per the normative
// spec (`seam-runtime/docs/specs/seam-commitment-digest.v2.md`) an implementation is conforming iff it
// reproduces EVERY digest in that file and verifies its `signed_artifact` against its `issuer_aid`. The
// `commitment` objects are the REST projection: snake_case, byte fields as JSON number arrays, absent
// `supersedes` / `confidence` / `rationale_ref` as `null`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  type Commitment,
  type ExplanationEntryInput,
  explanationDigest,
  seamCommitmentDigest,
  verifyTct,
} from "../src/crypto.js";

interface RestCommitment {
  id: string;
  action: string;
  authority: string;
  auth_method: string;
  trust_basis: string;
  supersedes: string | null;
  signed_artifact: number[];
  committer: string;
  explanation_digest: number[];
  explanation: ExplanationEntryInput[];
}

const vector = JSON.parse(
  readFileSync(new URL("../../conformance/commitment_digest_v2_vector.json", import.meta.url), "utf8"),
) as {
  issuer_aid: string;
  cases: { name: string; commitment: RestCommitment; explanation_digest: string; commitment_digest: string }[];
};

const NOW_S = 1_760_000_001; // just after the signed case's `iat`; its `exp` is far in the future
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

function toCommitment(r: RestCommitment): Commitment {
  return {
    id: r.id,
    action: r.action,
    authority: r.authority,
    auth_method: r.auth_method,
    trust_basis: r.trust_basis,
    supersedes: r.supersedes,
    committer: r.committer,
    explanation: r.explanation,
    explanation_digest: new Uint8Array(r.explanation_digest),
  };
}

function caseNamed(name: string) {
  const c = vector.cases.find((x) => x.name === name);
  assert.ok(c, `vector case ${name} missing`);
  return c;
}

test("v2 vector: every case reproduces its explanation and commitment digests", () => {
  assert.ok(vector.cases.length >= 2, "vector has fewer cases than the spec describes");
  for (const c of vector.cases) {
    assert.equal(hex(explanationDigest(c.commitment.explanation)), c.explanation_digest, `${c.name}: explanation`);
    assert.equal(hex(new Uint8Array(c.commitment.explanation_digest)), c.explanation_digest, `${c.name}: published`);
    const cm = toCommitment(c.commitment);
    assert.equal(seamCommitmentDigest(cm), c.commitment_digest, `${c.name}: entries + published`);
    // Published digest only (verifies who/what, not why), and entries only: the same field 8.
    assert.equal(seamCommitmentDigest({ ...cm, explanation: undefined }), c.commitment_digest, `${c.name}: published only`);
    assert.equal(seamCommitmentDigest({ ...cm, explanation_digest: undefined }), c.commitment_digest, `${c.name}: entries only`);
  }
});

test("v2 spec: empty explanation and the all-empty worked example", () => {
  assert.equal(hex(explanationDigest([])), "eb7853dc086ef5385db8408cf35c9c984e845ccc03d269102f942eed7806ce40");
  // Neither entries nor a published digest → the empty explanation's digest is bound.
  assert.equal(
    seamCommitmentDigest({ id: "", action: "", authority: "", auth_method: "", trust_basis: "" }),
    "78edca52ba1e88f13a78e5569742bfce0b51474ca840bf38a8dde414d5515784",
  );
});

test("v2 vector: populated_signed verifies against issuer_aid; tampering does not", () => {
  const c = caseNamed("populated_signed");
  const jws = Buffer.from(c.commitment.signed_artifact).toString("utf8");
  const cm = toCommitment(c.commitment);
  assert.equal(verifyTct(vector.issuer_aid, jws, cm, NOW_S), true);
  assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, explanation: undefined }, NOW_S), true, "published only");
  assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, explanation_digest: undefined }, NOW_S), true, "entries only");
  assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, committer: "" }, NOW_S), false, "committer is bound");
  // No normalization: NFC-composing the decomposed `é` in `action` must break verification.
  assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, action: cm.action.normalize("NFC") }, NOW_S), false);
});

test("v2: entries disagreeing with the published digest → verifyTct false (and the digest throws)", () => {
  const c = caseNamed("populated_signed");
  const jws = Buffer.from(c.commitment.signed_artifact).toString("utf8");
  const cm = toCommitment(c.commitment);
  const tampered = cm.explanation!.map((e, i) => (i === 3 ? { ...e, value: "REJECT" } : e));
  assert.throws(() => seamCommitmentDigest({ ...cm, explanation: tampered }), /does not match/);
  assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, explanation: tampered }, NOW_S), false);
  // Withheld entries ([] is "zero entries", not "not supplied") also disagree with the published digest.
  assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, explanation: [] }, NOW_S), false);
  // A wrong published digest alone (no entries) simply misses the grant.
  const wrong = new Uint8Array(cm.explanation_digest as Uint8Array);
  wrong[0] ^= 1;
  assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, explanation: undefined, explanation_digest: wrong }, NOW_S), false);
});

test("v2: absent confidence and a stated 0.0 are different digests", () => {
  const e: ExplanationEntryInput = {
    kind: "evaluation",
    participant: "a",
    proposal_id: "p",
    value: "APPROVE",
    reason: "",
  };
  const absent = hex(explanationDigest([e]));
  assert.equal(hex(explanationDigest([{ ...e, confidence: null }])), absent, "null and undefined both mean absent");
  assert.notEqual(hex(explanationDigest([{ ...e, confidence: 0 }])), absent);
  assert.notEqual(hex(explanationDigest([{ ...e, rationale_ref: "" }])), absent, "empty ref is not absent ref");
});

test("v2: non-canonical confidence and unknown kind are refused, and verifyTct fails closed on them", () => {
  const c = caseNamed("populated_signed");
  const jws = Buffer.from(c.commitment.signed_artifact).toString("utf8");
  const cm = toCommitment(c.commitment);
  const base = cm.explanation![1]; // the evaluation with a stated 0.0
  const bad: [string, ExplanationEntryInput][] = [
    ["-0.0", { ...base, confidence: -0 }],
    ["NaN", { ...base, confidence: NaN }],
    ["+inf", { ...base, confidence: Infinity }],
    ["-inf", { ...base, confidence: -Infinity }],
    ["1.5", { ...base, confidence: 1.5 }],
    ["-0.1", { ...base, confidence: -0.1 }],
    ["string", { ...base, confidence: "0.5" as unknown as number }],
    ["unknown kind", { ...base, kind: "comment" }],
    ["enum name, not the word", { ...base, kind: "EXPLANATION_KIND_EVALUATION" }],
    ["uppercase kind", { ...base, kind: "Evaluation" }],
  ];
  for (const [name, entry] of bad) {
    assert.throws(() => explanationDigest([entry]), Error, `${name} must be refused`);
    const explanation = cm.explanation!.map((e, i) => (i === 1 ? entry : e));
    assert.equal(
      verifyTct(vector.issuer_aid, jws, { ...cm, explanation, explanation_digest: undefined }, NOW_S),
      false,
      `${name} must verify false, never throw`,
    );
  }
  // The canonical bounds themselves are accepted.
  explanationDigest([{ ...base, confidence: 0 }]);
  explanationDigest([{ ...base, confidence: 1 }]);
});
