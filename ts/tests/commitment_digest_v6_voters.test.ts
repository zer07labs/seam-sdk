// `seam-commitment-digest:v6` with sealed voter records: every row of the v6 voter vector.
//
// Pinned against `conformance/commitment_digest_v6_voter_vector.json`, copied byte for byte from seam-runtime
// `crates/seam-trust-aitp/tests/fixtures/` (seamd 0.113.0) and kept identical by its `sdk-digest-parity`.
// Specs: seam-runtime `docs/specs/seam-commitment-digest.v6.md` and `docs/specs/voter-verification.v1.md`.
// Twin of Python `tests/test_commitment_digest_v6_voters.py`.
//
// This is the vector the plain v6 signed vector could not be: its vote, ballot and objection entries carry
// real `seam-voter-pop-v1` records, so `verifyTct` is given the entries (not just the published explanation
// digest) and the commitment-level voter check runs against the vector's `decision`.
//
// A case passes under v6 AND `verifyCommitmentVoters(entries, issuerAid, decision)` with `voters_verified`
// records. A negative is refused by at least one of the two. `rule` is advisory (the vector's note says so),
// so no test compares it: `accepted_outside_window` carries `record_malformed`, for one.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  type Commitment,
  type ExplanationEntryInput,
  COMMITMENT_DIGEST_DOMAIN_V6,
  commitmentDigestUnder,
  explanationDigest,
  selectCommitmentVersion,
  verifyCommitmentVoters,
  verifyTct,
} from "../src/index.js";

type Row = Record<string, any>;

const V: Row = JSON.parse(
  readFileSync(new URL("../../conformance/commitment_digest_v6_voter_vector.json", import.meta.url), "utf8"),
);
const ISSUER: string = V.issuer_aid;
const DECISION = V.decision as [string, string];
const CASES = new Map<string, Row>((V.cases as Row[]).map((c) => [c.name, c]));
const NOW_S = 0; // every vector `exp` is far in the future (see verifyTct's `exp` comment)
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** The row as `verifyTct` reads it: the full commitment WITH its entries, plus the raw trailers. */
function commitmentOf(row: Row): Commitment {
  return { ...row.commitment, trailers: row.trailers } as Commitment;
}

const records = (entries: readonly ExplanationEntryInput[]) =>
  entries.filter((e) => e.voter_verification !== undefined && e.voter_verification !== null).length;

const negative = (name: string): Row => {
  const r = (V.negatives as Row[]).find((x) => x.name === name);
  assert.ok(r, `negative ${name} missing`);
  return r;
};

test("v6 voter vector: the file is the v6 voter spec", () => {
  assert.equal(V.commitment_digest_domain, "seam-commitment-digest:v6");
  assert.equal(V.commitment_digest_domain, COMMITMENT_DIGEST_DOMAIN_V6);
  assert.equal(V.explanation_digest_domain, "seam-explanation-digest:v2");
  assert.equal(V.gate_digest_domain, "seam-gate-digest:v1");
  assert.equal(DECISION.length, 2);
  const lists = Object.entries(V)
    .filter(([, v]) => Array.isArray(v))
    .map(([k]) => k)
    .sort();
  assert.deepEqual(lists, ["cases", "decision", "negatives"]);
  assert.equal(V.cases.length, 2);
  assert.equal(V.negatives.length, 8);
});

test("v6 voter cases: every case verifies with its voter records", () => {
  for (const c of V.cases as Row[]) {
    const cm = commitmentOf(c);
    const entries = cm.explanation!;
    assert.equal(c.expect, "v6", c.name);
    assert.equal(selectCommitmentVersion(c.ext), "v6", `${c.name}: selection`);
    assert.equal(
      hex(explanationDigest(entries)),
      hex(Uint8Array.from(c.commitment.explanation_digest)),
      `${c.name}: explanation digest`,
    );
    assert.equal(commitmentDigestUnder("v6", cm), c.commitment_digest, `${c.name}: v6 digest`);
    assert.equal(verifyTct(ISSUER, c.signed_artifact, cm, NOW_S), true, `${c.name}: verifyTct`);
    assert.equal(verifyCommitmentVoters(entries, ISSUER, DECISION), true, `${c.name}: voters`);
    assert.equal(records(entries), V.voters_verified, `${c.name}: record count`);
  }
});

test("v6 voter negatives: every row is refused by verifyTct or the voter check", () => {
  for (const row of V.negatives as Row[]) {
    assert.equal(row.expect, "refused", row.name);
    assert.ok(CASES.has(row.over), `${row.name}: over ${row.over}`);
    const cm = commitmentOf(row);
    const tctOk = verifyTct(ISSUER, row.signed_artifact, cm, NOW_S);
    const votersOk = verifyCommitmentVoters(cm.explanation!, ISSUER, DECISION);
    assert.ok(!(tctOk && votersOk), `${row.name}: expected a refusal`);
  }
});

test("v6 voter: the decision binding is what refuses wrong_decision", () => {
  // A well-signed TCT whose records name another decision: only the decision the verifier knows can
  // refuse it, so dropping that argument must let it through.
  const row = negative("wrong_decision");
  const cm = commitmentOf(row);
  assert.equal(verifyTct(ISSUER, row.signed_artifact, cm, NOW_S), true);
  assert.equal(verifyCommitmentVoters(cm.explanation!, ISSUER), true);
  assert.equal(verifyCommitmentVoters(cm.explanation!, ISSUER, DECISION), false);
});

test("v6 voter: a tampered published entry breaks the signed digest", () => {
  // The entries and their digest were rewritten together and the old TCT kept: the records still
  // re-check, so it is the commitment digest under the signature that refuses it.
  const row = negative("tampered_published_entry");
  const cm = commitmentOf(row);
  assert.equal(verifyCommitmentVoters(cm.explanation!, ISSUER, DECISION), true);
  assert.equal(verifyTct(ISSUER, row.signed_artifact, cm, NOW_S), false);
});
