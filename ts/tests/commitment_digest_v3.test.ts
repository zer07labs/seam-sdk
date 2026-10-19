// `seam-commitment-digest:v3` + `seam-explanation-digest:v1`, and the RFC-AITP-0005 self-attestation TCT.
//
// `conformance/commitment_digest_v3_vector.json` is seam-runtime's trust-aitp reference fixture,
// vendored. Per the normative spec (`seam-runtime/docs/specs/seam-commitment-digest.v3.md`) an
// implementation is conforming iff it reproduces EVERY digest in that file and verifies its
// `signed_artifact` against its `issuer_aid`. The `commitment` objects are the REST projection:
// snake_case, byte fields as JSON number arrays, absent `supersedes` / `confidence` / `rationale_ref`
// as `null`. The TCT shape (`grants: ["aitp.attestation"]`, the digest under
// `ext["com.zer07labs.seam"]`) is taken from the signed vectors, which are the source of truth where
// the pinned spec's prose still describes the retired grants form. Mirrors
// `python/tests/test_commitment_digest_v3.py`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { create } from "@bufbuild/protobuf";
import { ed25519 } from "@noble/curves/ed25519";
import {
  type Commitment,
  type ExplanationEntryInput,
  derivedUuid,
  explanationDigest,
  seamCommitmentDigest,
  verifyTct,
} from "../src/crypto.js";
import { commitmentView } from "../src/client.js";
import { CommitmentSchema, ExplanationKind } from "../gen/seam/api/v1/seam_pb.js";

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

const conf = (name: string) =>
  JSON.parse(readFileSync(new URL(`../../conformance/${name}`, import.meta.url), "utf8"));

const vector = conf("commitment_digest_v3_vector.json") as {
  issuer_aid: string;
  cases: { name: string; commitment: RestCommitment; explanation_digest: string; commitment_digest: string }[];
};
const vectors = conf("vectors.json");
const TCT = vectors.tct;
const EMPTY = "eb7853dc086ef5385db8408cf35c9c984e845ccc03d269102f942eed7806ce40";

// The shared vectors pin `now = 0` (see verifyTct's `exp` comment); every `exp` is far in the future.
const NOW_S = 0;
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

const signedCase = () => {
  const signed = vector.cases.filter((c) => c.commitment.signed_artifact.length > 0);
  assert.equal(signed.length, 1, "the vector should carry exactly one signed case");
  return signed[0];
};

test("v3 vector: every case reproduces its explanation and commitment digests", () => {
  assert.ok(vector.cases.length >= 3, "vector has fewer cases than the spec describes");
  for (const c of vector.cases) {
    assert.equal(hex(explanationDigest(c.commitment.explanation)), c.explanation_digest, `${c.name}: explanation`);
    assert.equal(hex(new Uint8Array(c.commitment.explanation_digest)), c.explanation_digest, `${c.name}: published`);
    const cm = toCommitment(c.commitment);
    assert.equal(seamCommitmentDigest(cm), c.commitment_digest, `${c.name}: entries + published`);
    // Published digest only (verifies who/what, not why), and entries only: the same field 9.
    assert.equal(seamCommitmentDigest({ ...cm, explanation: undefined }), c.commitment_digest, `${c.name}: published only`);
    assert.equal(seamCommitmentDigest({ ...cm, explanation_digest: undefined }), c.commitment_digest, `${c.name}: entries only`);
  }
});

test("v3 spec: empty explanation and the all-empty worked example", () => {
  assert.equal(hex(explanationDigest([])), EMPTY);
  // Six empty fields, an absent `supersedes`, the empty explanation.
  assert.equal(
    seamCommitmentDigest({ id: "", action: "", authority: "", auth_method: "", trust_basis: "" }),
    caseNamed("all_empty").commitment_digest,
  );
});

test("v3: absent and present-empty supersedes are different digests", () => {
  // The one change v3 makes: a presence byte. v2 framed absent as the empty string.
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

test("v3 vector: populated_signed verifies against issuer_aid; tampering does not", () => {
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

test("v3: the conformance tct block reproduces", () => {
  const c = TCT.inputs.commitment as Commitment;
  assert.equal(hex(explanationDigest(c.explanation!)), TCT.explanation_digest_hex);
  assert.equal(seamCommitmentDigest(c), TCT.commitment_digest_hex);
});

test("v3: entries disagreeing with the published digest → verifyTct false (and the digest throws)", () => {
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

test("v3: the published digest alone verifies who and what", () => {
  const { explanation: _drop, ...c } = TCT.inputs.commitment;
  assert.equal(
    verifyTct(TCT.issuer_aid, TCT.signed_artifact_jws, { ...c, explanation_digest: TCT.explanation_digest_hex }, NOW_S),
    true,
  );
});

test("v3: absent confidence and a stated 0.0 are different digests", () => {
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

test("v3: non-canonical confidence and unknown kind are refused, and verifyTct fails closed on them", () => {
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

function protoFromVector(c: Record<string, any>) {
  return create(CommitmentSchema, {
    id: c.id,
    action: c.action,
    authority: c.authority,
    authMethod: c.auth_method,
    trustBasis: c.trust_basis,
    committer: c.committer,
    explanation: (c.explanation as ExplanationEntryInput[]).map((e) => ({
      kind: KINDS[e.kind],
      participant: e.participant,
      proposalId: e.proposal_id,
      value: e.value,
      reason: e.reason,
      ...(e.confidence === null || e.confidence === undefined ? {} : { confidence: e.confidence }),
      ...(e.rationale_ref === null || e.rationale_ref === undefined ? {} : { rationaleRef: e.rationale_ref }),
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

const SEED = new Uint8Array(32).fill(7);
const b64 = (b: Uint8Array | string) => Buffer.from(b).toString("base64url");

function sign(header: string, payload: string): string {
  const signingInput = `${b64(header)}.${b64(payload)}`;
  return `${signingInput}.${b64(ed25519.sign(new TextEncoder().encode(signingInput), SEED))}`;
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
  assert.deepEqual(Object.keys(p.ext), ["com.zer07labs.seam"]);
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
