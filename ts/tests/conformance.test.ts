import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import * as crypto from "../src/crypto.js";
import * as root from "../src/index.js";
import {
  buildPresentation,
  derivedUuid,
  explanationDigest,
  participantsDigestV4,
  popMessageId,
  RecordDigestStripError,
  recordDigestV4,
  seamCommitmentDigest,
  UnsupportedRecordDigestVersion,
  verifyTct,
  verifyChainHeadAttestation,
} from "../src/crypto.js";
import type { Commitment } from "../src/crypto.js";

const vectors = JSON.parse(
  readFileSync(new URL("../../conformance/vectors.json", import.meta.url), "utf8"),
);

test("pinned-key presentation is byte-exact", () => {
  const { inputs, presentation } = vectors.admission;
  const got = buildPresentation(
    Buffer.from(inputs.agent_seed_hex, "hex"),
    inputs.receiver_aid,
    inputs.pop_nonce,
    inputs.now_ms,
  );
  assert.deepEqual(got, presentation);
  // P8: the presentation carries exactly these five fields, no more.
  assert.deepEqual(
    Object.keys(got).sort(),
    ["descriptor", "message_id", "pop_nonce", "sender_aid", "timestamp"],
  );
});

test("derived_uuid: all three runtime-emitted vectors reproduce (P9)", () => {
  // P9's one primitive, pinned by the KAT, the PoP `message_id`, and the TCT `jti`.
  const blk = vectors.derived_uuid;
  const names = Object.keys(blk).filter((k) => k !== "rule");
  assert.deepEqual(names, ["kat_derived_uuid_001", "pop_message_id", "tct_jti"]);
  for (const name of names) {
    const v = blk[name];
    assert.equal(derivedUuid(v.tag, Buffer.from(v.input_hex, "hex")), v.uuid, name);
  }
  assert.equal(blk.kat_derived_uuid_001.uuid, "27b131ae-bcc6-4466-ab32-1d0f896453b1");
});

test("the PoP message_id is derived from the nonce text", () => {
  // A function of the nonce, so a replayed presentation carries the same id, and the presentation
  // vector's own `message_id` is reproduced (it is not random).
  const v = vectors.derived_uuid.pop_message_id;
  const nonce = Buffer.from(v.input_hex, "hex").toString("ascii");
  assert.equal(popMessageId(nonce), v.uuid);
  const adm = vectors.admission;
  assert.equal(adm.presentation.message_id, popMessageId(adm.inputs.pop_nonce));
});

test("TCT verify: valid → true, tampered → false", () => {
  const t = vectors.tct;
  assert.equal(verifyTct(t.issuer_aid, t.signed_artifact_jws, t.inputs.commitment, 1700000001), true);
  assert.equal(
    verifyTct(t.issuer_aid, t.signed_artifact_jws, { ...t.inputs.commitment, action: "ALLOW" }, 1700000001),
    false,
  );
});

test("TCT verify fails closed on malformed/expired/forged", () => {
  const t = vectors.tct;
  const c = t.inputs.commitment;
  const jws = t.signed_artifact_jws as string;
  const iss = t.issuer_aid as string;
  const [h, p, s] = jws.split(".");
  const cases: [string, string, string, number][] = [
    ["expired", iss, jws, 9_999_999_999],
    ["not-3-parts", iss, "not.a", 1_700_000_001],
    ["wrong-issuer-key", "aid:pubkey:ed25519:" + "A".repeat(43), jws, 1_700_000_001],
    ["unsupported-aid", "did:web:example.com", jws, 1_700_000_001],
    ["tampered-signature", iss, `${h}.${p}.${s.slice(0, -4)}AAAA`, 1_700_000_001],
  ];
  for (const [name, issuer, token, now] of cases) {
    assert.equal(verifyTct(issuer, token, c, now), false, `${name} must fail closed`);
  }
});

test("chain-head attestation signature verifies, tamper does not (A14)", () => {
  const v = vectors.chain_head_attestation;
  const i = v.inputs;
  const att = {
    attestedLen: i.attested_len,
    attestedHead: Buffer.from(i.attested_head_hex, "hex"),
    attestedAt: i.attested_at,
    digestSchema: i.digest_schema,
    signature: Buffer.from(v.signature_hex, "hex"),
    tenant: "",
  };
  assert.equal(verifyChainHeadAttestation(v.issuer_aid, att), true);
  assert.equal(
    verifyChainHeadAttestation(v.issuer_aid, { ...att, attestedLen: i.attested_len + 1 }),
    false,
  );
});

// -- Commitment-digest framing coverage (W5.4 / G4) ----------------------------------------------
//
// `seam-commitment-digest:v3` is implemented byte-for-byte in ALL FIVE SDK languages -- the widest
// fan-out of any framing in this repo. Its digests are pinned directly below (the `tct` block's
// `explanation_digest_hex` / `commitment_digest_hex`, and `commitment_digest_v3.test.ts` over the
// runtime's own reference vector); seam-runtime's `sdk-digest-parity` job byte-diffs the whole of
// conformance/vectors.json against its own emitter, so those values originate there.
//
// What IS available is stronger than it looks. `verifyTct` recomputes the digest and compares it to
// the `commitment_digest` claim inside the runtime-signed JWS, so the vector already carries a
// runtime-produced expected value. The gap was never coverage of the digest -- it was coverage of
// the FIELD TUPLE: the pre-existing test tampered `action` only, so one of the framing inputs was
// proven bound.
//
// The difference is demonstrable, not theoretical: an implementation that silently drops
// `supersedes` from the preimage PASSES the pre-existing KAT test (the vector's commitment has no
// `supersedes`, so the bytes are identical) and FAILS the first test below.

const NOW_S = 1_700_000_001;

test("commitment digest binds every field", () => {
  // A field dropped from the preimage -- or reordered -- lets one artifact verify under another's
  // signature, which is the whole point of the digest: it attests WHO committed and HOW they authed,
  // not just the decision.
  const t = vectors.tct;
  const base = t.inputs.commitment as Commitment;
  const jws = t.signed_artifact_jws as string;
  const iss = t.issuer_aid as string;

  assert.equal(
    verifyTct(iss, jws, base, NOW_S),
    true,
    "the unmodified vector commitment must verify -- nothing below means anything otherwise",
  );

  const mutations: [string, Partial<Commitment>][] = [
    ["id", { id: base.id + "-x" }],
    ["action", { action: "ALLOW" }],
    ["authority", { authority: base.authority + "-x" }],
    // The vector's commitment omits `supersedes`, so absent is the branch already exercised. This
    // pins the PRESENT branch, which nothing covered: absent and present must differ, or a
    // supersession could be stripped from a sealed record undetected.
    ["supersedes (absent -> present)", { supersedes: "k-previous" }],
    // v3's presence byte: present-but-empty is not absent.
    ["supersedes (absent -> present empty)", { supersedes: "" }],
    ["auth_method", { auth_method: base.auth_method + "-x" }],
    ["trust_basis", { trust_basis: base.trust_basis + "-x" }],
    ["committer", { committer: base.committer + "-x" }],
    ["committer (present -> absent)", { committer: undefined }],
    ["explanation (entry reason)", {
      explanation: base.explanation!.map((e, i) => (i === 2 ? { ...e, reason: e.reason + "-x" } : e)),
    }],
    ["explanation (entry dropped)", { explanation: base.explanation!.slice(1) }],
    ["explanation (order)", { explanation: [...base.explanation!].reverse() }],
    // Absent is not zero: the first entry declined to state a confidence.
    ["explanation (absent confidence -> 0.0)", {
      explanation: base.explanation!.map((e, i) => (i === 0 ? { ...e, confidence: 0 } : e)),
    }],
    ["explanation (stated 0.0 -> absent)", {
      explanation: base.explanation!.map((e, i) => (i === 1 ? { ...e, confidence: null } : e)),
    }],
    ["explanation (rationale_ref dropped)", {
      explanation: base.explanation!.map((e, i) => (i === 0 ? { ...e, rationale_ref: null } : e)),
    }],
  ];
  for (const [field, change] of mutations) {
    assert.equal(
      verifyTct(iss, jws, { ...base, ...change }, NOW_S),
      false,
      `changing ${field} did not change the commitment digest -- that field is not bound`,
    );
  }
});

test("tct block: explanation and commitment digests match the runtime (seam-commitment-digest:v3)", () => {
  const t = vectors.tct;
  const c = t.inputs.commitment as Commitment;
  assert.equal(Buffer.from(explanationDigest(c.explanation!)).toString("hex"), t.explanation_digest_hex);
  assert.equal(seamCommitmentDigest(c), t.commitment_digest_hex);
  // The same digest via the published-only path (no entries) and via entries + agreeing published digest.
  const published = Buffer.from(t.explanation_digest_hex, "hex");
  assert.equal(seamCommitmentDigest({ ...c, explanation: undefined, explanation_digest: published }), t.commitment_digest_hex);
  assert.equal(seamCommitmentDigest({ ...c, explanation_digest: t.explanation_digest_hex }), t.commitment_digest_hex);
});

test("commitment digest is injective across field boundaries", () => {
  // The length prefixes are load-bearing, and this is what notices if someone "simplifies" them
  // away. Both seam-store and seam-trust-aitp record the reason in their own source: without an
  // 8-byte big-endian length before each field, ("a\0b","c") and ("a","b\0c") produce identical
  // preimages, letting one Commitment verify under another's TCT. The fields are arbitrary text
  // that may itself contain NUL (UTF-8 permits U+0000, and it survives the JSON/prost decision
  // path), so this is reachable rather than theoretical.
  const t = vectors.tct;
  const base = t.inputs.commitment as Commitment;

  // Fold the id/action boundary into `id` with a NUL. Under a NUL-joined framing this collides with
  // the real commitment; under length-prefixing it cannot.
  const shifted = { ...base, id: `${base.id}\u0000${base.action}`, action: "" };

  assert.equal(
    verifyTct(t.issuer_aid as string, t.signed_artifact_jws as string, shifted, NOW_S),
    false,
    "a boundary-shifted commitment verified -- the framing is separator-joined, not length-prefixed, " +
      "and one artifact can now verify under another's signature",
  );
});

// -- record_digest_v4 (P7) -----------------------------------------------------------------------
//
// The v4 cases come from TWO runtime files, both vendored byte-identical:
//
//   * `conformance/vectors.json` carries `record_digest_v4` and `record_digest_v4_absent_policy`.
//     seam-runtime's `sdk-digest-parity` gate diffs that whole file against its own emitter.
//   * `conformance/vectors_extended.json` carries three more v4 cases (every optional present, every
//     optional absent, and `mode: ""` as distinct from `mode: null`), deliberately kept out of the
//     byte-diffed file upstream.
//
// v1 to v3 are deleted, not dual-verified: a v3 record is "cannot verify", never a guess.

type V4Case = { name: string; inputs: Record<string, any>; digest_hex: string };

const extended = JSON.parse(
  readFileSync(new URL("../../conformance/vectors_extended.json", import.meta.url), "utf8"),
);

const RUNTIME_V4_BLOCKS = ["record_digest_v4", "record_digest_v4_absent_policy"];
const EXTENDED_V4_CASES = ["all_optionals_present", "optionals_none", "mode_empty_string"];

function loadV4Cases(src: any = vectors, ext: any = extended): V4Case[] {
  const cases: V4Case[] = [];
  for (const block of RUNTIME_V4_BLOCKS) {
    // A renamed or dropped runtime block is a BROKEN CROSS-REPO CONTRACT, not a thinner set.
    if (!src[block]) throw new Error(`conformance/vectors.json has no '${block}' block`);
    cases.push({ name: block, ...src[block] });
  }
  for (const name of EXTENDED_V4_CASES) {
    if (!ext[name]) throw new Error(`conformance/vectors_extended.json has no '${name}' case`);
    cases.push({ name, ...ext[name] });
  }
  return cases;
}

const v4Cases: V4Case[] = loadV4Cases();

const hex = (s: string | null): Uint8Array | null => (s === null ? null : Buffer.from(s, "hex"));

function v4Args(i: Record<string, any>) {
  return {
    decisionId: i.decision_id as string,
    tenant: i.tenant as string,
    namespace: i.namespace as string,
    ciphertextDigest: Buffer.from(i.ciphertext_digest_hex, "hex") as Uint8Array,
    sealedAt: i.sealed_at as number,
    outcome: i.outcome as string,
    mode: i.mode as string | null,
    policyVersion: i.policy_version as string | null,
    supersedes: i.supersedes as string | null,
    contextDigest: hex(i.context_digest_hex)!,
    participationDigest: hex(i.participation_digest_hex)!,
    policyRulesDigest: hex(i.policy_rules_digest_hex ?? null),
    classification: i.classification as string,
    participantsDigest: hex(i.participants_digest_hex)!,
    trustBasisCommitment: i.trust_basis_commitment as string,
    authMethod: i.auth_method as string,
    schemaVersion: i.schema_version as number,
  };
}

const v4Hex = (i: Record<string, any>) => Buffer.from(recordDigestV4(v4Args(i))).toString("hex");

test("the v4 case loader refuses a missing block", () => {
  for (const block of RUNTIME_V4_BLOCKS) {
    const doctored = { ...vectors };
    delete doctored[block];
    assert.throws(() => loadV4Cases(doctored), new RegExp(block));
  }
  for (const name of EXTENDED_V4_CASES) {
    const doctored = { ...extended };
    delete doctored[name];
    assert.throws(() => loadV4Cases(vectors, doctored), new RegExp(name));
  }
});

test("record digest v4 matches the reference in every case", () => {
  assert.equal(v4Cases.length, 5);
  for (const c of v4Cases) {
    assert.equal(c.inputs.domain, "seam.audit.record-digest.v4", c.name);
    assert.equal(v4Hex(c.inputs), c.digest_hex, `case ${c.name} did not reproduce`);
  }
});

test("participants digest v4 matches every case", () => {
  for (const c of v4Cases) {
    const got = Buffer.from(participantsDigestV4(c.inputs.participants)).toString("hex");
    assert.equal(got, c.inputs.participants_digest_hex, c.name);
  }
});

test("the ciphertext digest is sha256 of the ciphertext", () => {
  for (const c of v4Cases) {
    const got = createHash("sha256").update(Buffer.from(c.inputs.ciphertext_hex, "hex")).digest("hex");
    assert.equal(got, c.inputs.ciphertext_digest_hex, c.name);
  }
});

test("the v4 comparison is not vacuous: every slot is bound", () => {
  const base = vectors.record_digest_v4;
  const i = base.inputs;
  const changes: Record<string, unknown> = {
    decision_id: i.decision_id + "x",
    tenant: i.tenant + "x",
    namespace: i.namespace + "x",
    ciphertext_digest_hex: "00".repeat(32),
    sealed_at: i.sealed_at + 1,
    outcome: "Expired",
    mode: null,
    policy_version: "p",
    supersedes: "s",
    context_digest_hex: "00".repeat(32),
    participation_digest_hex: "00".repeat(32),
    policy_rules_digest_hex: null,
    classification: "Public",
    participants_digest_hex: "00".repeat(32),
    trust_basis_commitment: i.trust_basis_commitment + "x",
    auth_method: i.auth_method + "x",
  };
  for (const [k, v] of Object.entries(changes)) {
    assert.notEqual(v4Hex({ ...i, [k]: v }), base.digest_hex, `${k} is not bound`);
  }
});

test("absent and empty mode are different vectors", () => {
  const by = Object.fromEntries(v4Cases.map((c) => [c.name, c]));
  assert.equal(by.optionals_none.inputs.mode, null);
  assert.equal(by.mode_empty_string.inputs.mode, "");
  assert.notEqual(by.optionals_none.digest_hex, by.mode_empty_string.digest_hex);
});

test("a stripped mandatory slot is refused as a strip", () => {
  // Tags 11, 12, 14, 15, 16 and 17 are mandatory. Absent (or `len == 0`, which is how the wire says
  // absent) is a STRIP, reported distinctly, never a quiet digest over an empty slot.
  const slots: [keyof ReturnType<typeof v4Args>, number][] = [
    ["contextDigest", 11],
    ["participationDigest", 12],
    ["classification", 14],
    ["participantsDigest", 15],
    ["trustBasisCommitment", 16],
    ["authMethod", 17],
  ];
  const a = v4Args(vectors.record_digest_v4.inputs);
  for (const [slot, tag] of slots) {
    const empty = typeof a[slot] === "string" ? "" : new Uint8Array(0);
    for (const stripped of [null, empty]) {
      assert.throws(
        () => recordDigestV4({ ...a, [slot]: stripped } as any),
        (e: unknown) => e instanceof RecordDigestStripError && e.wireTag === tag,
        `${slot} = ${stripped === null ? "null" : "empty"} was not a tag-${tag} strip`,
      );
    }
  }
});

test("tag 13 (policy_rules_digest) is optional, not a strip", () => {
  const a = v4Args(vectors.record_digest_v4_absent_policy.inputs);
  assert.equal(a.policyRulesDigest, null);
  assert.equal(
    Buffer.from(recordDigestV4(a)).toString("hex"),
    vectors.record_digest_v4_absent_policy.digest_hex,
  );
});

test("any other schema_version cannot verify, and is checked first", () => {
  // v4 is the only formula. A v3 record is refused as unsupported, never recomputed under v4 (which
  // would read as tamper) and never under a retained v3 (which no longer exists).
  const a = v4Args(vectors.record_digest_v4.inputs);
  for (const version of [1, 2, 3, 5, 0]) {
    assert.throws(
      () => recordDigestV4({ ...a, schemaVersion: version }),
      (e: unknown) => e instanceof UnsupportedRecordDigestVersion && e.schemaVersion === version,
      `schema_version ${version}`,
    );
    // Checked before the strip checks: a v3 record with a stripped slot is still "unsupported".
    assert.throws(
      () => recordDigestV4({ ...a, schemaVersion: version, authMethod: "" }),
      UnsupportedRecordDigestVersion,
    );
  }
});

test("text is hashed as given, never normalised", () => {
  const i = vectors.record_digest_v4.inputs;
  const nfc = "approuv\u00e9".normalize("NFC");
  const nfd = nfc.normalize("NFD");
  assert.notEqual(nfc, nfd);
  assert.notEqual(v4Hex({ ...i, outcome: nfc }), v4Hex({ ...i, outcome: nfd }));
});

test("the retired formulas are gone", () => {
  for (const name of ["recordDigestV2", "recordDigestV3"]) {
    assert.equal(name in crypto, false, `crypto still exports ${name}`);
    assert.equal(name in root, false, `the package root still exports ${name}`);
  }
});
