import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  buildPresentation,
  verifyTct,
  recordDigestV2,
  recordDigestV3,
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

test("record digest v2 matches the reference (A14 design-a)", () => {
  const v = vectors.record_digest_v2;
  const i = v.inputs;
  const got = recordDigestV2({
    decisionId: i.decision_id,
    tenant: i.tenant,
    namespace: i.namespace,
    ciphertextDigest: Buffer.from(i.ciphertext_digest_hex, "hex"),
    sealedAt: i.sealed_at,
    outcome: i.outcome,
    mode: i.mode,
    policyVersion: i.policy_version,
    supersedes: i.supersedes,
    schemaVersion: i.schema_version,
  });
  assert.equal(Buffer.from(got).toString("hex"), v.digest_hex);
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
  };
  assert.equal(verifyChainHeadAttestation(v.issuer_aid, att), true);
  assert.equal(
    verifyChainHeadAttestation(v.issuer_aid, { ...att, attestedLen: i.attested_len + 1 }),
    false,
  );
});

// -- Commitment-digest framing coverage (W5.4 / G4) ----------------------------------------------
//
// `seam-commitment-digest:v1` is implemented byte-for-byte in ALL FIVE SDK languages -- the widest
// fan-out of any framing in this repo -- and has no vector section of its own. It cannot get one
// here either: seam-runtime's `sdk-digest-parity` job byte-diffs the whole of
// conformance/vectors.json against its own emitter, so a block added on this side turns the
// runtime's CI red. A vector for it must originate there.
//
// What IS available is stronger than it looks. `verifyTct` recomputes the digest and compares it to
// the `seam-commitment-digest:` grant inside the runtime-signed JWS, so the vector already carries a
// runtime-produced expected value. The gap was never coverage of the digest -- it was coverage of
// the FIELD TUPLE: the pre-existing test tampered `action` only, so one of seven framing inputs was
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
    ["auth_method", { auth_method: base.auth_method + "-x" }],
    ["trust_basis", { trust_basis: base.trust_basis + "-x" }],
  ];
  for (const [field, change] of mutations) {
    assert.equal(
      verifyTct(iss, jws, { ...base, ...change }, NOW_S),
      false,
      `changing ${field} did not change the commitment digest -- that field is not bound`,
    );
  }
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

// -- record_digest_v3 (B3) -----------------------------------------------------------------------
//
// The v3 block is a `cases` array, not v2's single `{inputs, digest_hex}` object: v3 has an optional
// slot (tag 13) and a mandatory-vs-absent distinction that one fixture cannot express. Every case is
// machine-emitted by `scripts/emit_record_digest_v3_vectors.py` -- no digest here was typed by hand --
// and seam-runtime's `sdk-digest-parity` job byte-diffs this whole file against its own emitter, so
// these bytes are a cross-repo contract, not a local fixture.

type V3Case = { name: string; inputs: Record<string, any>; digest_hex: string };

const v3Cases: V3Case[] = vectors.record_digest_v3.cases;

const hex = (s: string | null): Uint8Array | null => (s === null ? null : Buffer.from(s, "hex"));

function v3Args(i: Record<string, any>) {
  return {
    decisionId: i.decision_id as string,
    tenant: i.tenant as string,
    namespace: i.namespace as string,
    ciphertextDigest: Buffer.from(i.ciphertext_digest_hex, "hex"),
    sealedAt: i.sealed_at as number,
    outcome: i.outcome as string,
    mode: i.mode as string | null,
    policyVersion: i.policy_version as string | null,
    supersedes: i.supersedes as string | null,
    contextDigest: Buffer.from(i.context_digest_hex, "hex"),
    participationDigest: Buffer.from(i.participation_digest_hex, "hex"),
    policyRulesDigest: hex(i.policy_rules_digest_hex ?? null),
    schemaVersion: i.schema_version as number,
  };
}

test("record digest v3 reproduces every conformance case", () => {
  assert.ok(v3Cases.length > 0, "the v3 block is empty -- nothing below proves anything");
  for (const c of v3Cases) {
    const got = Buffer.from(recordDigestV3(v3Args(c.inputs))).toString("hex");
    assert.equal(got, c.digest_hex, `case ${c.name} did not reproduce`);
  }
});

test("the v3 conformance loop is falsifiable", () => {
  // Guard the guard: if `recordDigestV3` were wired to ignore its inputs (or the loop above were
  // comparing something to itself), every case would still "pass". Perturbing one byte of one input
  // must break every case -- that is what makes the loop above evidence rather than decoration.
  for (const c of v3Cases) {
    const a = v3Args(c.inputs);
    const perturbed = Buffer.from(a.ciphertextDigest);
    perturbed[0] ^= 0xff;
    const got = Buffer.from(recordDigestV3({ ...a, ciphertextDigest: perturbed })).toString("hex");
    assert.notEqual(got, c.digest_hex, `case ${c.name} survived a perturbed ciphertext_digest`);
  }
});

test("the v3 case set covers the distinctions it exists to cover", () => {
  // A case silently dropped from the emitted block would shrink coverage invisibly. These names are
  // the contract: each one pins a branch of the formula that no other case reaches.
  const names = new Set(v3Cases.map((c) => c.name));
  for (const required of [
    "all_optionals_present",
    "policy_rules_absent",
    "optionals_none",
    "mode_empty_string",
    "non_ascii_nfd",
  ]) {
    assert.ok(names.has(required), `the v3 vector case '${required}' is missing`);
  }
});

test("v3 keeps absent and present-but-empty apart", () => {
  // `opt(null)` is one byte; `opt("")` is five. Collapsing them is the classic implementation slip,
  // and these two cases differ in exactly that one field -- asserted here, not assumed.
  const none = v3Cases.find((c) => c.name === "optionals_none")!;
  const empty = v3Cases.find((c) => c.name === "mode_empty_string")!;
  for (const k of Object.keys(none.inputs)) {
    if (k === "mode") continue;
    assert.deepEqual(empty.inputs[k], none.inputs[k], `the two cases also differ in ${k}`);
  }
  assert.equal(none.inputs.mode, null);
  assert.equal(empty.inputs.mode, "");
  assert.notEqual(none.digest_hex, empty.digest_hex, "absent mode and empty mode hash the same");
});

test("no v3 case can absorb a context/participation swap", () => {
  // Slots 10 and 11 are adjacent and identically framed, so a wire-mapping that swaps tags 11 and 12
  // is undetectable if a fixture happens to set them equal. Every case must keep them distinct.
  for (const c of v3Cases) {
    assert.notEqual(
      c.inputs.context_digest_hex,
      c.inputs.participation_digest_hex,
      `case ${c.name} sets context_digest == participation_digest, so a slot swap would cancel`,
    );
  }
});

test("a v3 case exercises non-ASCII, still decomposed", () => {
  // The spec forbids normalization of any kind and names it as the step three of four
  // implementations get wrong. An all-ASCII fixture set is blind to that: NFC and NFD agree on
  // ASCII, and so do UTF-8 and Latin-1. This asserts the vector still carries the decomposed form --
  // if someone's editor "cleans up" the JSON to NFC, the digest silently stops covering the rule.
  const nfd = v3Cases.find((c) => c.name === "non_ascii_nfd")!;
  const text = nfd.inputs.mode as string;
  assert.ok(/[^\x00-\x7f]/.test(text), "the non-ASCII case is pure ASCII");
  assert.notEqual(
    text,
    text.normalize("NFC"),
    "the non-ASCII case is no longer decomposed -- it can no longer catch an NFC normalization",
  );
  // And the rule itself: normalizing the input must change the digest.
  const a = v3Args(nfd.inputs);
  const normalized = Buffer.from(
    recordDigestV3({ ...a, mode: text.normalize("NFC"), decisionId: a.decisionId.normalize("NFC") }),
  ).toString("hex");
  assert.notEqual(normalized, nfd.digest_hex, "NFC-normalizing the inputs did not change the digest");
});
