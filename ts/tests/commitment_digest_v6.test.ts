// `seam-commitment-digest:v6` readers (Flows W2, A18): the digest, the `0x05`/`0x06` trailer decode under
// each scheme, statement selection from the raw `ext`, and the TCT verifier choosing ONE version.
//
// Driven row by row by `conformance/commitment_digest_v6_vector.json` (the runtime's independent stdlib
// generator) and `conformance/commitment_digest_v6_signed_vector.json` (real TCTs from the Rust test), both
// vendored byte for byte. Every section and every row is asserted. Refusal rows assert the REFUSAL only:
// rule names are advisory (v6 spec §Refusal rules), so a test must not fail because this port named a
// different applicable rule. Normative: seam-runtime `docs/specs/seam-commitment-digest.v6.md`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  type Commitment,
  COMMITMENT_DIGEST_DOMAIN_V6,
  CommitmentRefusedError,
  commitmentDigestUnder,
  decodeCommitmentTrailers,
  explanationDigest,
  seamCommitmentDigest,
  seamCommitmentDigestV6,
  selectCommitmentVersion,
  selectCommitmentVersionFromStatement,
  verifyTct,
} from "../src/index.js";

const conf = (name: string) => JSON.parse(readFileSync(new URL(`../../conformance/${name}`, import.meta.url), "utf8"));
const V = conf("commitment_digest_v6_vector.json");
const S = conf("commitment_digest_v6_signed_vector.json");
const G = conf("gate_block_vector.json");
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const NOW_S = 0; // every vector `exp` is far in the future (see verifyTct's `exp` comment)

type Row = Record<string, any>;
const caseNamed = (name: string): Row => {
  const c = V.cases.find((x: Row) => x.name === name);
  assert.ok(c, `case ${name} missing`);
  return c;
};

/** The case's fields 0-9 and 11 as a {@link Commitment} (field 8 as the published digest). */
function baseCommitment(c: Row): Commitment {
  return {
    ...c.commitment,
    explanation_digest: Uint8Array.from(c.commitment.explanation_digest),
    selection_digest: c.selection_digest,
    governing_doc_sha256: c.governing_doc_sha256,
  };
}

/** Assert `fn` refuses. Any {@link CommitmentRefusedError} passes, whatever rule it names. */
function assertRefused(fn: () => unknown, what: string) {
  assert.throws(fn, (e: unknown) => e instanceof CommitmentRefusedError, `${what}: expected a refusal`);
}

test("v6 vector: the domains are the ones this SDK frames", () => {
  assert.equal(V.commitment_digest_domain, COMMITMENT_DIGEST_DOMAIN_V6);
  assert.equal(S.commitment_digest_domain, COMMITMENT_DIGEST_DOMAIN_V6);
  assert.equal(V.gate_digest_domain, "seam-gate-digest:v1");
  assert.equal(V.explanation_digest_domain, "seam-explanation-digest:v2");
});

test("v6 cases: every case reproduces its fields and digest (digest-only and from trailers)", () => {
  assert.equal(V.cases.length, 15);
  let digestOnly = 0;
  let fromTrailers = 0;
  for (const c of V.cases as Row[]) {
    const base = baseCommitment(c);
    if (c.digest_only) {
      digestOnly++;
      // A digest-only case has no trailer bytes: a port that derives from `trailers` meets null here.
      assert.equal(c.trailers, null, c.name);
      const fields = { gate_digest: c.gate_digest, env: c.env };
      assert.equal(seamCommitmentDigestV6(base, fields), c.commitment_digest, `${c.name}: v6`);
      assert.equal(commitmentDigestUnder("v6", base, fields), c.commitment_digest, `${c.name}: under v6`);
      // The re-cut cases are v5's inputs verbatim: v5 field 10 is the same opaque label.
      assert.equal(
        seamCommitmentDigest({ ...base, certificate_digest: c.gate_digest }),
        c.v5_commitment_digest,
        `${c.name}: v5`,
      );
    } else {
      fromTrailers++;
      assert.equal(typeof c.trailers, "string", c.name);
      const t = decodeCommitmentTrailers(c.trailers, "v6");
      assert.equal(hex(t.field_10), c.field_10, `${c.name}: field 10`);
      assert.equal(hex(t.field_11), c.field_11, `${c.name}: field 11`);
      assert.equal(hex(t.field_12!), c.field_12, `${c.name}: field 12`);
      assert.equal(t.env, c.env, `${c.name}: env`);
      assert.equal(t.gate_digest === null ? null : hex(t.gate_digest), c.gate_digest, `${c.name}: gate digest`);
      if (c.gate_block_case !== null) {
        const g = G.cases.find((x: Row) => x.name === c.gate_block_case);
        assert.equal(g.gate_digest, c.gate_digest, `${c.name}: names its Gate case`);
        assert.equal(t.gate_block!.attempt_id, g.block.attempt_id, c.name);
      }
      // Derived from the trailers, with and without the doc digest also given beside them.
      const withTrailers: Commitment = { ...base, trailers: c.trailers };
      assert.equal(commitmentDigestUnder("v6", withTrailers), c.commitment_digest, `${c.name}: trailers + doc`);
      assert.equal(
        commitmentDigestUnder("v6", { ...withTrailers, governing_doc_sha256: null }),
        c.commitment_digest,
        `${c.name}: trailers only`,
      );
      // And through the digest-only path with the values the trailers carry.
      assert.equal(
        seamCommitmentDigestV6(base, { gate_digest: c.gate_digest, env: c.env }),
        c.commitment_digest,
        `${c.name}: digest-only`,
      );
    }
    for (const f of ["field_10", "field_11", "field_12"]) assert.match(c[f], /^(00|01[0-9a-f]+)$/, `${c.name}: ${f}`);
  }
  assert.equal(digestOnly, 7);
  assert.equal(fromTrailers, 8);
});

test("v6: a governing doc beside the trailers that disagrees with them refuses", () => {
  const c = caseNamed("doc_env_live");
  const base = { ...baseCommitment(c), trailers: c.trailers };
  assertRefused(() => commitmentDigestUnder("v6", { ...base, governing_doc_sha256: "00".repeat(32) }), "doc mismatch");
  assertRefused(() => commitmentDigestUnder("v6", { ...base, certificate_digest: "00".repeat(32) }), "certificate under v6");
  assert.throws(() => seamCommitmentDigestV6(base), TypeError, "digest-only refuses a commitment carrying trailers");
});

test("v6 digest_input_refusals: every row refuses before hashing", () => {
  assert.equal(V.digest_input_refusals.length, 10);
  for (const r of V.digest_input_refusals as Row[]) {
    assert.equal(r.scheme, "v6", r.name);
    const b = caseNamed(r.base_case);
    const ov = r.override ?? {};
    const cm: Commitment = {
      ...baseCommitment(b),
      ...("selection_digest" in ov ? { selection_digest: ov.selection_digest } : {}),
      ...("governing_doc_sha256" in ov ? { governing_doc_sha256: ov.governing_doc_sha256 } : {}),
    };
    const fields = { gate_digest: "gate_digest" in ov ? ov.gate_digest : b.gate_digest, env: "env" in r ? r.env : b.env };
    assertRefused(() => seamCommitmentDigestV6(cm, fields), r.name);
    assertRefused(() => commitmentDigestUnder("v6", cm, fields), `${r.name}: under v6`);
  }
});

test("v6 governing_trailer_refusals: every row refuses under v6 (env_frame_length_max_be64 as truncated)", () => {
  assert.equal(V.governing_trailer_refusals.length, 17);
  const base = baseCommitment(caseNamed("doc_present"));
  for (const r of V.governing_trailer_refusals as Row[]) {
    assert.equal(r.scheme, "v6", r.name);
    assertRefused(() => decodeCommitmentTrailers(r.trailers, "v6"), r.name);
    assertRefused(() => commitmentDigestUnder("v6", { ...base, trailers: r.trailers }), `${r.name}: digest`);
  }
  // The be64 frame length of 2^64-1 is read as a bigint: it runs past the body, never wraps to a small one.
  const max = V.governing_trailer_refusals.find((r: Row) => r.name === "env_frame_length_max_be64");
  assert.ok(max.trailers.includes("01ffffffffffffffff"));
});

test("v6 v5_refusals: every row refuses under v5", () => {
  assert.equal(V.v5_refusals.length, 6);
  for (const r of V.v5_refusals as Row[]) {
    assert.equal(r.scheme, "v5", r.name);
    if (r.trailers !== undefined) {
      assertRefused(() => decodeCommitmentTrailers(r.trailers, "v5"), r.name);
      const base = baseCommitment(caseNamed("doc_present"));
      assertRefused(() => commitmentDigestUnder("v5", { ...base, trailers: r.trailers }), `${r.name}: digest`);
    } else {
      const base = baseCommitment(caseNamed(r.base_case));
      assertRefused(() => commitmentDigestUnder("v5", base, { env: r.env }), r.name);
    }
  }
});

test("v6 scheme_free: both body versions decode and report their version; refusals refuse", () => {
  assert.equal(V.scheme_free.length, 7);
  for (const r of V.scheme_free as Row[]) {
    assert.equal(r.scheme, null, r.name);
    if (r.expect === "refused") {
      assertRefused(() => decodeCommitmentTrailers(r.trailers, null), r.name);
      continue;
    }
    const t = decodeCommitmentTrailers(r.trailers, null);
    assert.equal(hex(t.field_10), r.expect.field_10, `${r.name}: field 10`);
    assert.equal(hex(t.field_11), r.expect.field_11, `${r.name}: field 11`);
    if ("field_12" in r.expect) assert.equal(hex(t.field_12!), r.expect.field_12, `${r.name}: field 12`);
    else assert.equal(t.field_12, undefined, `${r.name}: no field 12`);
    assert.equal(t.governing_body_version, r.expect.governing_body_version, `${r.name}: body version`);
  }
});

test("v6 statement_selection: every row selects its version or refuses", () => {
  assert.equal(V.statement_selection.length, 29);
  for (const r of V.statement_selection as Row[]) {
    const select = "ext" in r ? () => selectCommitmentVersion(r.ext) : () => selectCommitmentVersionFromStatement(r.statement);
    if (r.expect === "refused") assertRefused(select, r.name);
    else assert.equal(select(), r.expect, r.name);
  }
});

test("v6 statement selection: JSON.parse keeps the last duplicate, so the raw scan is what refuses", () => {
  const dup = caseNamed("doc_env_live");
  const stmt = `{"type":"seam:commitment","commitment_digest":"${dup.commitment_digest}","commitment_digest_domain":"x","commitment_digest_domain":"${COMMITMENT_DIGEST_DOMAIN_V6}"}`;
  assert.equal(Object.keys(JSON.parse(stmt)).length, 3);
  assertRefused(() => selectCommitmentVersionFromStatement(stmt), "last-wins duplicate");
  assertRefused(() => selectCommitmentVersion(`{"com.zer07labs.seam":${stmt}}`), "last-wins duplicate in ext");
  // Deep in another namespace, and after unescaping.
  assertRefused(
    () => selectCommitmentVersion(`{"o":{"a":[{"k":1,"\\u006b":2}]},"com.zer07labs.seam":{"type":"seam:commitment","commitment_digest":"${dup.commitment_digest}"}}`),
    "deep escaped duplicate",
  );
});

// ── the signed vector ──

/** The signed case's commitment. Its explanation's `vote` / `objection` entries carry no sealed voter
 * record (the Rust generator seals none), so `verifyTct`'s voter re-check
 * (#1687) would refuse them for a reason unrelated to v6. The entries are therefore checked against the
 * published field-8 digest here, and the TCT is verified over that published digest (who and what). */
function signedCommitment(c: Row): Commitment {
  const cm = c.commitment as Commitment;
  assert.equal(hex(explanationDigest(cm.explanation!)), hex(Uint8Array.from(c.commitment.explanation_digest)), c.name);
  return {
    ...cm,
    explanation: undefined,
    explanation_digest: Uint8Array.from(c.commitment.explanation_digest),
    governing_doc_sha256: c.commitment.governing_doc_sha256 === null ? null : Uint8Array.from(c.commitment.governing_doc_sha256),
    trailers: c.trailers,
  };
}

test("v6 signed: every case verifies, selected v6 from its raw ext and recomputed from its trailers", () => {
  assert.equal(S.cases.length, 3);
  for (const c of S.cases as Row[]) {
    assert.equal(c.expect, "v6", c.name);
    const cm = signedCommitment(c);
    assert.equal(selectCommitmentVersion(c.ext), "v6", c.name);
    const t = decodeCommitmentTrailers(c.trailers, "v6");
    assert.equal(hex(t.field_10), c.field_10, `${c.name}: field 10`);
    assert.equal(hex(t.field_11), c.field_11, `${c.name}: field 11`);
    assert.equal(hex(t.field_12!), c.field_12, `${c.name}: field 12`);
    assert.equal(commitmentDigestUnder("v6", cm), c.commitment_digest, `${c.name}: digest`);
    // The JWS payload's ext is the vector's ext.
    const payload = JSON.parse(Buffer.from(c.signed_artifact.split(".")[1], "base64url").toString());
    assert.equal(selectCommitmentVersion(JSON.stringify(payload.ext)), "v6", c.name);
    assert.equal(verifyTct(S.issuer_aid, c.signed_artifact, cm, NOW_S), true, `${c.name}: verifyTct`);
    // Under v5 the same commitment is a different digest (or a refusal): v6 never falls back.
    let v5: string | undefined;
    try {
      v5 = commitmentDigestUnder("v5", cm);
    } catch (e) {
      assert.ok(e instanceof CommitmentRefusedError, c.name);
    }
    assert.notEqual(v5, c.commitment_digest, c.name);
    // A tampered trailer fails closed.
    const flip = (h: string) => h.slice(0, -2) + (parseInt(h.slice(-2), 16) ^ 0x01).toString(16).padStart(2, "0");
    const bad = { ...cm, trailers: c.trailers === "" ? "00" : flip(c.trailers) };
    assert.equal(verifyTct(S.issuer_aid, c.signed_artifact, bad, NOW_S), false, `${c.name}: tampered`);
    // The cross-port rule: under v6 absent trailers are a record with neither trailer, so the record's doc
    // beside them is refused, never framed; an ungoverned case still verifies.
    const absent = { ...cm, trailers: undefined };
    assert.equal(verifyTct(S.issuer_aid, c.signed_artifact, absent, NOW_S), c.trailers === "", `${c.name}: absent`);
  }
});

test("v6 signed negatives: every row is refused by verifyTct; selection refuses where the rule is a statement rule", () => {
  assert.equal(S.negatives.length, 5);
  for (const n of S.negatives as Row[]) {
    assert.equal(n.expect, "refused", n.name);
    const over = S.cases.find((c: Row) => c.name === n.over);
    assert.ok(over, `${n.name}: over ${n.over}`);
    const cm = signedCommitment(over);
    assert.equal(verifyTct(S.issuer_aid, n.signed_artifact, cm, NOW_S), false, n.name);
    const payload = Buffer.from(n.signed_artifact.split(".")[1], "base64url").toString();
    assert.ok(payload.includes('"ext"'), n.name);
    let selected: string | undefined;
    try {
      selected = selectCommitmentVersion(n.ext);
    } catch (e) {
      assert.ok(e instanceof CommitmentRefusedError, n.name);
    }
    if (selected !== undefined) {
      // It selected v5 (no domain member): the v5 recompute refuses or differs, and nothing retries v6.
      assert.equal(selected, "v5", n.name);
      const stmtDigest = JSON.parse(n.ext)["com.zer07labs.seam"].commitment_digest;
      let v5: string | undefined;
      try {
        v5 = commitmentDigestUnder("v5", cm);
      } catch (e) {
        assert.ok(e instanceof CommitmentRefusedError, n.name);
      }
      assert.notEqual(v5, stmtDigest, n.name);
    }
  }
});

test("v6 verifyTct: a v5 statement over a commitment without trailers still verifies exactly as v5", () => {
  const v5 = conf("commitment_digest_v5_signed_vector.json");
  for (const c of v5.cases.filter((x: Row) => x.commitment.signed_artifact.length > 0) as Row[]) {
    const r = c.commitment;
    const cm: Commitment = {
      ...(r as Commitment),
      explanation_digest: Uint8Array.from(r.explanation_digest),
      governing_doc_sha256: r.governing_doc_sha256 === null ? null : Uint8Array.from(r.governing_doc_sha256),
    };
    const jws = Buffer.from(r.signed_artifact).toString("utf8");
    assert.equal(verifyTct(v5.issuer_aid, jws, cm, NOW_S), true, c.name);
    // A v5 trailer run (0x06 body v1) carrying the same doc verifies too; a body v2 refuses under v5.
    if (r.governing_doc_sha256 !== null) {
      const doc = Buffer.from(r.governing_doc_sha256).toString("hex");
      assert.equal(verifyTct(v5.issuer_aid, jws, { ...cm, trailers: `062100000001${doc}` }, NOW_S), true, `${c.name}: v1`);
      assert.equal(verifyTct(v5.issuer_aid, jws, { ...cm, trailers: `06220000000${2}${doc}00` }, NOW_S), false, `${c.name}: v2`);
    }
  }
});
