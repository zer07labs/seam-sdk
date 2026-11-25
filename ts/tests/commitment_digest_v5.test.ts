// `seam-commitment-digest:v5` (#1711) + `seam-explanation-digest:v2`, and the RFC-AITP-0005 self-attestation TCT.
//
// `conformance/commitment_digest_v5_signed_vector.json` is seam-runtime's trust-aitp reference fixture,
// vendored: real TCTs over v5 digests, one governed and one ungoverned populated case. Per the normative
// spec (`seam-runtime/docs/specs/seam-commitment-digest.v5.md`, v4 plus field 11 `governing_doc_sha256`)
// an implementation is conforming iff it reproduces EVERY digest in that file and verifies its
// `signed_artifact` against its `issuer_aid`. `conformance/commitment_digest_v5_vector.json` is the
// independent stdlib-only generator's field-9/10/11 slot cases (byte fields hex); its
// `governing_trailer_refusals` pin the `0x06` trailer decoder. The SDK has one since Flows W2
// (`decodeCommitmentTrailers`), exercised against the v6 file's rows, v5 scheme included, in
// `commitment_digest_v6.test.ts`, so they are not re-run here. The `commitment` objects are the REST projection:
// snake_case, byte fields as JSON number arrays, absent `supersedes` / `confidence` / `rationale_ref`
// as `null`. v4 adds the sealed voter verification record on every vote / ballot / objection (`VV`, byte
// fields as number arrays) and the always-framed slots 9 (selection) and 10 (Gate certificate), given
// per case as `selection_digest` / `certificate_digest` hex or `null`. The TCT shape (`grants: ["aitp.attestation"]`, the digest under
// `ext["com.zer07labs.seam"]`) is taken from the signed vectors, which are the source of truth where
// the pinned spec's prose still describes the retired grants form. Mirrors
// `python/tests/test_commitment_digest_v5.py`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { create } from "@bufbuild/protobuf";
import {
  type Commitment,
  type ExplanationEntryInput,
  derivedUuid,
  explanationDigest,
  seamCommitmentDigest,
  verifyTct,
} from "../src/crypto.js";
import { commitmentView } from "../src/client.js";
import { CommitmentSchema, ExplanationKind, VoterVerification } from "../gen/seam/api/v1/seam_pb.js";
import { commitmentFromVector } from "./vector_commitment.js";
import { seededSealSeed, signWith } from "./seal_key_mint.js";

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
  governing_doc_sha256: number[] | null;
}

const conf = (name: string) =>
  JSON.parse(readFileSync(new URL(`../../conformance/${name}`, import.meta.url), "utf8"));

const vector = conf("commitment_digest_v5_signed_vector.json") as {
  issuer_aid: string;
  commitment_digest_domain: string;
  explanation_digest_domain: string;
  cases: {
    name: string;
    commitment: RestCommitment;
    selection_digest?: string | null;
    certificate_digest?: string | null;
    explanation_digest: string;
    commitment_digest: string;
  }[];
};
const slotVector = conf("commitment_digest_v5_vector.json") as {
  commitment_digest_domain: string;
  cases: {
    name: string;
    commitment: Record<string, any>;
    selection_digest: string | null;
    certificate_digest: string | null;
    governing_doc_sha256: string | null;
    governing_trailer: string | null;
    explanation_digest: string;
    commitment_digest: string;
  }[];
};
const vectors = conf("vectors.json");
const TCT = vectors.tct;
TCT.inputs.commitment = commitmentFromVector(TCT.inputs.commitment);
const EMPTY = "cabe83af912ea38ef4525f5a7d8580b4c4e217417edc0c93f936d2c18c4fd8f5";

// The shared vectors pin `now = 0` (see verifyTct's `exp` comment); every `exp` is far in the future.
const NOW_S = 0;
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

function toCommitment(r: RestCommitment, slots?: { selection_digest?: string | null; certificate_digest?: string | null }): Commitment {
  return {
    selection_digest: slots?.selection_digest ?? null,
    certificate_digest: slots?.certificate_digest ?? null,
    id: r.id,
    action: r.action,
    authority: r.authority,
    auth_method: r.auth_method,
    trust_basis: r.trust_basis,
    supersedes: r.supersedes,
    committer: r.committer,
    explanation: r.explanation,
    explanation_digest: new Uint8Array(r.explanation_digest),
    governing_doc_sha256: r.governing_doc_sha256 === null ? null : new Uint8Array(r.governing_doc_sha256),
  };
}

function caseNamed(name: string) {
  const c = vector.cases.find((x) => x.name === name);
  assert.ok(c, `vector case ${name} missing`);
  return c;
}

const signedCases = () => vector.cases.filter((c) => c.commitment.signed_artifact.length > 0);
/** The governed populated case — the one whose TCT binds a field 11. */
const signedCase = () => {
  assert.equal(signedCases().length, 2, "the vector should carry a governed and an ungoverned signed case");
  return caseNamed("populated_signed");
};

test("v5 vector: the domains are the ones this SDK frames", () => {
  assert.equal(vector.commitment_digest_domain, "seam-commitment-digest:v5");
  assert.equal(slotVector.commitment_digest_domain, "seam-commitment-digest:v5");
  assert.equal(vector.explanation_digest_domain, "seam-explanation-digest:v2");
});

test("v5 vector: every case reproduces its explanation and commitment digests", () => {
  assert.ok(vector.cases.length >= 6, "vector has fewer cases than the spec describes");
  for (const c of vector.cases) {
    assert.equal(hex(explanationDigest(c.commitment.explanation)), c.explanation_digest, `${c.name}: explanation`);
    assert.equal(hex(new Uint8Array(c.commitment.explanation_digest)), c.explanation_digest, `${c.name}: published`);
    const cm = toCommitment(c.commitment, c);
    assert.equal(seamCommitmentDigest(cm), c.commitment_digest, `${c.name}: entries + published`);
    // Published digest only (verifies who/what, not why), and entries only: the same field 8.
    assert.equal(seamCommitmentDigest({ ...cm, explanation: undefined }), c.commitment_digest, `${c.name}: published only`);
    assert.equal(seamCommitmentDigest({ ...cm, explanation_digest: undefined }), c.commitment_digest, `${c.name}: entries only`);
  }
});

test("v5 spec: empty explanation and the all-empty worked example", () => {
  assert.equal(hex(explanationDigest([])), EMPTY);
  // Six empty fields, an absent `supersedes`, the empty explanation.
  assert.equal(
    seamCommitmentDigest({ id: "", action: "", authority: "", auth_method: "", trust_basis: "" }),
    caseNamed("all_empty").commitment_digest,
  );
});

test("v5: absent and present-empty supersedes are different digests", () => {
  // The presence byte (since v3). v2 framed absent as the empty string.
  const absent = caseNamed("all_empty");
  const empty = caseNamed("empty_supersedes");
  assert.equal(absent.commitment.supersedes, null);
  assert.equal(empty.commitment.supersedes, "");
  assert.notEqual(absent.commitment_digest, empty.commitment_digest);
  // A key missing entirely, and `undefined`, are the same as null: absent.
  const { supersedes: _drop, ...missing } = toCommitment(absent.commitment);
  assert.equal(seamCommitmentDigest(missing), absent.commitment_digest);
  assert.equal(
    seamCommitmentDigest({ ...toCommitment(absent.commitment), supersedes: undefined }),
    absent.commitment_digest,
  );
});

test("v5: fields 9 and 10 — each slot is bound, and absent is not present", () => {
  const empty = toCommitment(caseNamed("all_empty").commitment);
  const sel = caseNamed("selection_present");
  const cert = caseNamed("certificate_present");
  const both = caseNamed("both_present");
  assert.equal(seamCommitmentDigest({ ...empty, selection_digest: sel.selection_digest }), sel.commitment_digest);
  assert.equal(seamCommitmentDigest({ ...empty, certificate_digest: cert.certificate_digest }), cert.commitment_digest);
  // Bytes, a number array and hex are the same input.
  const selBytes = new Uint8Array(Buffer.from(sel.selection_digest!, "hex"));
  assert.equal(seamCommitmentDigest({ ...empty, selection_digest: selBytes }), sel.commitment_digest);
  assert.equal(seamCommitmentDigest({ ...empty, selection_digest: [...selBytes] }), sel.commitment_digest);
  // The two slots are distinct positions: swapping them moves the digest.
  assert.notEqual(
    seamCommitmentDigest({ ...empty, selection_digest: cert.certificate_digest, certificate_digest: sel.selection_digest }),
    both.commitment_digest,
  );
  const digests = new Set([caseNamed("all_empty"), sel, cert, both].map((c) => c.commitment_digest));
  assert.equal(digests.size, 4);
});

test("v5: a slot digest that is not 32 bytes is refused, and verifyTct fails closed on it", () => {
  const sc = signedCase();
  const jws = Buffer.from(sc.commitment.signed_artifact).toString("utf8");
  const cm = toCommitment(sc.commitment);
  for (const bad of [new Uint8Array(0), new Uint8Array(31), new Uint8Array(33), "ab", "zz".repeat(32)]) {
    assert.throws(() => seamCommitmentDigest({ ...cm, selection_digest: bad }), Error);
    assert.throws(() => seamCommitmentDigest({ ...cm, certificate_digest: bad }), Error);
    assert.throws(() => seamCommitmentDigest({ ...cm, governing_doc_sha256: bad }), Error);
    assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, governing_doc_sha256: bad }, NOW_S), false);
    assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, selection_digest: bad }, NOW_S), false);
  }
});

test("v5: the voter verification record is bound, and a malformed one is refused", () => {
  const sc = signedCase();
  const jws = Buffer.from(sc.commitment.signed_artifact).toString("utf8");
  const cm = toCommitment(sc.commitment);
  const withRecord = cm.explanation!.findIndex((e) => e.voter_verification);
  assert.ok(withRecord >= 0, "the signed case should carry a voter record");
  const vv = cm.explanation![withRecord].voter_verification!;
  const swap = (v: unknown) =>
    cm.explanation!.map((e, i) => (i === withRecord ? { ...e, voter_verification: v as typeof vv } : e));
  const verifies = (v: unknown) =>
    verifyTct(vector.issuer_aid, jws, { ...cm, explanation: swap(v), explanation_digest: undefined }, NOW_S);
  assert.equal(verifies(vv), true, "control");
  assert.equal(verifies(null), false, "record dropped");
  assert.equal(verifies({ ...vv, accepted_at_ms: BigInt(vv.accepted_at_ms) + 1n }), false, "accepted_at_ms bound");
  assert.equal(verifies({ ...vv, audience: "seam-partner" }), false, "audience bound");
  for (const [name, bad] of [
    ["unknown method", { ...vv, method: "POP" }],
    ["unspecified method", { ...vv, method: "" }],
    ["31-byte content digest", { ...vv, content_digest: new Array(31).fill(0) }],
    ["33-byte content digest", { ...vv, content_digest: new Array(33).fill(0) }],
    ["negative time", { ...vv, issued_at_ms: -1 }],
    ["u64 overflow", { ...vv, expires_at_ms: 1n << 64n }],
    ["not bytes", { ...vv, signature: [256] }],
  ] as [string, unknown][]) {
    assert.throws(() => explanationDigest(swap(bad)), Error, `${name} must be refused`);
    assert.equal(verifies(bad), false, `${name} must verify false, never throw`);
  }
});

test("v5 vector: populated_signed verifies against issuer_aid; tampering does not", () => {
  const c = caseNamed("populated_signed");
  const jws = Buffer.from(c.commitment.signed_artifact).toString("utf8");
  const cm = toCommitment(c.commitment);
  assert.equal(verifyTct(vector.issuer_aid, jws, cm, NOW_S), true);
  assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, explanation: undefined }, NOW_S), true, "published only");
  assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, explanation_digest: undefined }, NOW_S), true, "entries only");
  assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, committer: "" }, NOW_S), false, "committer is bound");
  assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, supersedes: null }, NOW_S), false, "supersedes is bound");
  // No normalization: NFC-composing the decomposed `é` in `action` must break verification.
  assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, action: cm.action.normalize("NFC") }, NOW_S), false);
});

test("v5 generator: every field-9/10/11 slot case reproduces its digest", () => {
  for (const c of slotVector.cases) {
    const cm = {
      ...c.commitment,
      explanation_digest: c.explanation_digest,
      selection_digest: c.selection_digest,
      certificate_digest: c.certificate_digest,
      governing_doc_sha256: c.governing_doc_sha256,
    } as Commitment;
    assert.equal(seamCommitmentDigest(cm), c.commitment_digest, c.name);
  }
  const doc = slotVector.cases.find((c) => c.name === "doc_present")!;
  // The trailer the runtime seals it in (not decoded here): 0x06 ‖ u32le(33) ‖ 0x01 ‖ doc.
  assert.equal(doc.governing_trailer, "06" + "21000000" + "01" + doc.governing_doc_sha256);
});

test("v5: field 11 is TCT-bound — both signed cases verify, and a governed record read as ungoverned does not", () => {
  for (const c of signedCases()) {
    const jws = Buffer.from(c.commitment.signed_artifact).toString("utf8");
    assert.equal(verifyTct(vector.issuer_aid, jws, toCommitment(c.commitment), NOW_S), true, c.name);
  }
  const gov = signedCase();
  assert.notEqual(gov.commitment.governing_doc_sha256, null);
  const jws = Buffer.from(gov.commitment.signed_artifact).toString("utf8");
  const cm = toCommitment(gov.commitment);
  assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, governing_doc_sha256: null }, NOW_S), false, "dropped");
  assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, governing_doc_sha256: undefined }, NOW_S), false, "undefined");
  const other = new Uint8Array(cm.governing_doc_sha256 as Uint8Array);
  other[31] ^= 1;
  assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, governing_doc_sha256: other }, NOW_S), false, "another document");
});

test("v5: the conformance tct block reproduces", () => {
  const c = TCT.inputs.commitment as Commitment;
  assert.equal(hex(explanationDigest(c.explanation!)), TCT.explanation_digest_hex);
  assert.equal(seamCommitmentDigest(c), TCT.commitment_digest_hex);
});

test("v5: entries disagreeing with the published digest → verifyTct false (and the digest throws)", () => {
  const c = caseNamed("populated_signed");
  const jws = Buffer.from(c.commitment.signed_artifact).toString("utf8");
  const cm = toCommitment(c.commitment);
  const tampered = cm.explanation!.map((e, i) => (i === 3 ? { ...e, value: "REJECT" } : e));
  assert.throws(() => seamCommitmentDigest({ ...cm, explanation: tampered }), /does not match/);
  assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, explanation: tampered }, NOW_S), false);
  // Withheld entries ([] is "zero entries", not "not supplied") also disagree with the published digest.
  assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, explanation: [] }, NOW_S), false);
  // A wrong published digest alone (no entries) simply misses the statement.
  const wrong = new Uint8Array(cm.explanation_digest as Uint8Array);
  wrong[0] ^= 1;
  assert.equal(verifyTct(vector.issuer_aid, jws, { ...cm, explanation: undefined, explanation_digest: wrong }, NOW_S), false);
  // And on the conformance tct block: entries against an all-zero published digest.
  assert.equal(
    verifyTct(TCT.issuer_aid, TCT.signed_artifact_jws, { ...TCT.inputs.commitment, explanation_digest: new Uint8Array(32) }, NOW_S),
    false,
  );
});

test("v5: the published digest alone verifies who and what", () => {
  const { explanation: _drop, ...c } = TCT.inputs.commitment;
  assert.equal(
    verifyTct(TCT.issuer_aid, TCT.signed_artifact_jws, { ...c, explanation_digest: TCT.explanation_digest_hex }, NOW_S),
    true,
  );
});

test("v5: absent confidence and a stated 0.0 are different digests", () => {
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

test("v5: non-canonical confidence and unknown kind are refused, and verifyTct fails closed on them", () => {
  const c = caseNamed("populated_signed");
  const jws = Buffer.from(c.commitment.signed_artifact).toString("utf8");
  const cm = toCommitment(c.commitment);
  const base = cm.explanation![1];
  const bad: [string, ExplanationEntryInput][] = [
    ["-0.0", { ...base, confidence: -0 }],
    ["NaN", { ...base, confidence: NaN }],
    ["+inf", { ...base, confidence: Infinity }],
    ["-inf", { ...base, confidence: -Infinity }],
    ["1.5", { ...base, confidence: 1.5 }],
    ["-0.1", { ...base, confidence: -0.1 }],
    ["string", { ...base, confidence: "0.5" as unknown as number }],
    ["boolean", { ...base, confidence: true as unknown as number }],
    ["unknown kind", { ...base, kind: "comment" }],
    ["empty kind", { ...base, kind: "" }],
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

// -- the served proto, through commitmentView ----------------------------------------------------

const KINDS: Record<string, ExplanationKind> = {
  vote: ExplanationKind.VOTE,
  evaluation: ExplanationKind.EVALUATION,
  objection: ExplanationKind.OBJECTION,
  ballot: ExplanationKind.BALLOT,
};

const bytesOf = (b: Uint8Array | readonly number[] | string) =>
  typeof b === "string" ? new Uint8Array(Buffer.from(b, "hex")) : Uint8Array.from(b);

function protoFromVector(c: Record<string, any>) {
  return create(CommitmentSchema, {
    id: c.id,
    action: c.action,
    authority: c.authority,
    authMethod: c.auth_method,
    trustBasis: c.trust_basis,
    committer: c.committer,
    ...(c.supersedes === null || c.supersedes === undefined ? {} : { supersedes: c.supersedes }),
    ...(c.governing_doc_sha256 === null || c.governing_doc_sha256 === undefined
      ? {}
      : { governingDocSha256: new Uint8Array(c.governing_doc_sha256) }),
    explanation: (c.explanation as ExplanationEntryInput[]).map((e) => ({
      kind: KINDS[e.kind],
      participant: e.participant,
      proposalId: e.proposal_id,
      value: e.value,
      reason: e.reason,
      ...(e.confidence === null || e.confidence === undefined ? {} : { confidence: e.confidence }),
      ...(e.rationale_ref === null || e.rationale_ref === undefined ? {} : { rationaleRef: e.rationale_ref }),
      ...(e.voter_verification === null || e.voter_verification === undefined
        ? {}
        : {
            voterVerification: {
              method: e.voter_verification.method === "pop" ? VoterVerification.POP : VoterVerification.CP_SIGNED,
              principal: e.voter_verification.principal,
              contentDigest: bytesOf(e.voter_verification.content_digest),
              issuedAtMs: BigInt(e.voter_verification.issued_at_ms),
              expiresAtMs: BigInt(e.voter_verification.expires_at_ms),
              signature: bytesOf(e.voter_verification.signature),
              signerCertificate: bytesOf(e.voter_verification.signer_certificate),
              tenant: e.voter_verification.tenant,
              namespace: e.voter_verification.namespace,
              sessionId: e.voter_verification.session_id,
              openedAtMillis: BigInt(e.voter_verification.opened_at_millis),
              issuer: e.voter_verification.issuer,
              audience: e.voter_verification.audience,
              acceptedAtMs: BigInt(e.voter_verification.accepted_at_ms),
            },
          }),
    })),
  });
}

test("commitmentView of the served proto verifies (explicit presence survives)", () => {
  // verifyDecision's path: proto Commitment -> commitmentView -> verifyTct. An absent confidence is
  // not 0.0, and an absent supersedes is not "", or the digest moves.
  const m = protoFromVector(TCT.inputs.commitment);
  m.explanationDigest = Buffer.from(TCT.explanation_digest_hex, "hex");
  const view = commitmentView(m);
  assert.equal(view.explanation![0].confidence, null);
  assert.equal(view.explanation![1].confidence, 0);
  assert.equal(view.supersedes, undefined);
  assert.equal(verifyTct(TCT.issuer_aid, TCT.signed_artifact_jws, view, NOW_S), true);

  m.explanation[0].rationaleRef = undefined;
  assert.equal(verifyTct(TCT.issuer_aid, TCT.signed_artifact_jws, commitmentView(m), NOW_S), false);
});

test("commitmentView maps the served voter record, and an UNSPECIFIED method fails closed", () => {
  const sc = signedCase();
  const jws = Buffer.from(sc.commitment.signed_artifact).toString("utf8");
  const m = protoFromVector(sc.commitment);
  m.explanationDigest = new Uint8Array(sc.commitment.explanation_digest);
  const view = commitmentView(m);
  assert.ok(view.explanation!.some((e) => e.voter_verification?.method === "pop"));
  assert.equal(verifyTct(vector.issuer_aid, jws, view, NOW_S), true);
  const i = m.explanation.findIndex((e) => e.voterVerification);
  m.explanation[i].voterVerification!.method = VoterVerification.UNSPECIFIED;
  assert.equal(verifyTct(vector.issuer_aid, jws, commitmentView(m), NOW_S), false);
  m.explanation[i].voterVerification!.method = VoterVerification.POP;
  m.explanation[i].voterVerification!.contentDigest = new Uint8Array(31);
  assert.equal(verifyTct(vector.issuer_aid, jws, commitmentView(m), NOW_S), false);
});

test("commitmentView carries field 11 with explicit presence", () => {
  for (const c of signedCases()) {
    const jws = Buffer.from(c.commitment.signed_artifact).toString("utf8");
    const m = protoFromVector(c.commitment);
    m.explanationDigest = new Uint8Array(c.commitment.explanation_digest);
    const governed = c.commitment.governing_doc_sha256 !== null;
    assert.equal(m.governingDocSha256 !== undefined, governed, c.name);
    assert.equal(verifyTct(vector.issuer_aid, jws, commitmentView(m), NOW_S), true, c.name);
    if (governed) {
      m.governingDocSha256 = undefined;
      assert.equal(verifyTct(vector.issuer_aid, jws, commitmentView(m), NOW_S), false, "cleared");
      m.governingDocSha256 = new Uint8Array(0); // present-empty is NOT absent: refused, never hashed
      assert.deepEqual(commitmentView(m).governing_doc_sha256, new Uint8Array(0));
      assert.equal(verifyTct(vector.issuer_aid, jws, commitmentView(m), NOW_S), false, "present-empty");
    } else {
      assert.equal(commitmentView(m).governing_doc_sha256, null);
    }
  }
});

test("an UNSPECIFIED kind from the wire fails closed", () => {
  const m = protoFromVector(TCT.inputs.commitment);
  m.explanation[0].kind = ExplanationKind.UNSPECIFIED;
  assert.equal(verifyTct(TCT.issuer_aid, TCT.signed_artifact_jws, commitmentView(m), NOW_S), false);
});

test("commitmentView keeps supersedes presence", () => {
  const m = create(CommitmentSchema, { id: "i", action: "a", authority: "x", authMethod: "m", trustBasis: "t" });
  const absent = commitmentView(m).supersedes;
  assert.ok(absent === undefined || absent === null, `absent supersedes read as ${JSON.stringify(absent)}`);
  m.supersedes = "";
  assert.equal(commitmentView(m).supersedes, "");
  assert.notEqual(seamCommitmentDigest(commitmentView(m)), seamCommitmentDigest({ ...commitmentView(m), supersedes: undefined }));
});

// -- The self-attestation TCT shape (RFC-AITP-0005 / owner plan B5) -------------------------------
//
// Re-signed with the vector's own issuer key (seed `[7u8; 32]`) so the signature is valid and only
// the claim under test changes; otherwise every case below would fail on the signature and prove
// nothing about the claim checks.

// S-4 (seam-runtime #2031): the token is signed by the seeded SEAL key the issuer certifies, so a
// re-sign uses that key and keeps the vector's certificate member.
const SEED = new Uint8Array(32).fill(7);

function sign(header: string, payload: string): string {
  return signWith(seededSealSeed(SEED), header, payload);
}

function vectorClaims(): { c: Commitment; h: Record<string, any>; p: Record<string, any> } {
  const sc = signedCase();
  const [h, p] = Buffer.from(sc.commitment.signed_artifact).toString("utf8").split(".");
  return {
    c: toCommitment(sc.commitment),
    h: JSON.parse(Buffer.from(h, "base64url").toString()),
    p: JSON.parse(Buffer.from(p, "base64url").toString()),
  };
}

const verifyResigned = (c: Commitment, h: object, p: object) =>
  verifyTct(vector.issuer_aid, sign(JSON.stringify(h), JSON.stringify(p)), c, NOW_S);

test("the re-signed vector still verifies", () => {
  // The control: if re-signing alone broke verification, every refusal below would be vacuous.
  const { c, h, p } = vectorClaims();
  assert.deepEqual(p.grants, ["aitp.attestation"]);
  assert.deepEqual(Object.keys(p.ext), ["com.zer07labs.seam", "com.zer07labs.seam.seal-key-cert"]);
  assert.equal(verifyResigned(c, h, p), true);
});

test("the TCT jti is the derived uuid (P9)", () => {
  // Derived, not random: `derivedUuid("seam-tct-jti-v1", ...)`. A test assertion only -- verifyTct
  // does not check `jti`, matching the Python verifier.
  const blk = vectors.derived_uuid.tct_jti;
  const p = JSON.parse(Buffer.from(TCT.signed_artifact_jws.split(".")[1], "base64url").toString());
  assert.equal(p.jti, blk.uuid);
  assert.equal(derivedUuid(blk.tag, Buffer.from(blk.input_hex, "hex")), p.jti);
});

const stmt = (p: Record<string, any>) => p.ext["com.zer07labs.seam"];

const SHAPES: Record<string, (p: Record<string, any>) => void> = {
  "statement in grants (the retired v2 shape)": (p) => {
    p.grants = ["seam:commitment", "seam-commitment-digest:" + stmt(p).commitment_digest];
  },
  "extra grant": (p) => {
    p.grants = ["aitp.attestation", "x"];
  },
  "no grants": (p) => {
    delete p.grants;
  },
  "grants not an array": (p) => {
    p.grants = "aitp.attestation";
  },
  "no ext": (p) => {
    delete p.ext;
  },
  "extra ext key": (p) => {
    p.ext["org.example"] = {};
  },
  "wrong statement type": (p) => {
    stmt(p).type = "seam:other";
  },
  "extra statement field": (p) => {
    stmt(p).x = 1;
  },
  "missing statement type": (p) => {
    delete stmt(p).type;
  },
  "uppercase digest": (p) => {
    stmt(p).commitment_digest = stmt(p).commitment_digest.toUpperCase();
  },
  "aud is not iss": (p) => {
    p.aud = "aid:pubkey:" + "A".repeat(43);
  },
  "sub is not iss": (p) => {
    p.sub = "aid:pubkey:" + "A".repeat(43);
  },
};

test("a wrong attestation shape fails closed", () => {
  for (const [name, mutate] of Object.entries(SHAPES)) {
    const { c, h, p } = vectorClaims();
    mutate(p);
    assert.equal(verifyResigned(c, h, p), false, `${name} must fail closed`);
  }
});

test("a duplicate JSON key fails closed, in the payload and in the header", () => {
  // A duplicate key lets two parsers read two different statements from one signed payload.
  // `JSON.parse` silently keeps the LAST one, so this would otherwise verify.
  const { c, h, p } = vectorClaims();
  const body = JSON.stringify(p);
  const forged = body.slice(0, -1) + ',"grants":["aitp.attestation"]}';
  assert.equal(verifyTct(vector.issuer_aid, sign(JSON.stringify(h), forged), c, NOW_S), false);
  const dupHeader = JSON.stringify(h).slice(0, -1) + ',"typ":"aitp-tct+jwt"}';
  assert.equal(verifyTct(vector.issuer_aid, sign(dupHeader, body), c, NOW_S), false);
  // A duplicate nested inside the statement, with the LAST value the correct one.
  const s = stmt(p);
  const nested = body.replace(
    `"commitment_digest":"${s.commitment_digest}"`,
    `"commitment_digest":"${"0".repeat(64)}","commitment_digest":"${s.commitment_digest}"`,
  );
  assert.notEqual(nested, body);
  assert.equal(verifyTct(vector.issuer_aid, sign(JSON.stringify(h), nested), c, NOW_S), false);
  // The same key at different depths is not a duplicate.
  assert.equal(verifyTct(vector.issuer_aid, sign(JSON.stringify(h), body), c, NOW_S), true);
});
