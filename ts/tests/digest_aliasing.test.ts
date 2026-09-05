// Two distinct inputs must never reach one digest. That is the only property a digest has, and this
// module broke it in three places at once — each demonstrated byte-for-byte before the fix landed:
//
//   * `recordDigestV2({ sealedAt: 2n ** 64n + 5n })` produced the SAME 32 bytes as `sealedAt: 5n`.
//     `DataView.setBigUint64` applies ToBigUint64, so the wrap is silent. Measured, both:
//     b566fdea56b8487bc5ebc26d1d6585339e9ab2a3a499247bd7230e4f20f05d7f
//   * the same for `schemaVersion` through `setUint32`, one u32 slot over.
//   * `jcsCanonicalize({ "\ud800": 1 })` canonicalized happily while Python raised
//     `UnicodeEncodeError` on the identical input — the guard existed for string VALUES and had
//     never been applied to object KEYS, so TS could digest an object no other implementation can
//     represent.
//
// `recordDigestV3` already refused all of this via `uintSlot` (then named `v3Uint`), and its
// docstring already explained why — "an alias, not an error". The argument is about `DataView` and
// IEEE doubles, neither of which knows which framing it is serving, so it always applied to v2 and
// to the attestation framing too. This phase routes them through the same function rather than
// writing a second copy of the rule.
//
// The assertions below deliberately pin the ALIAS, not just the throw: a test that only checks
// "out-of-range throws" would still pass against an implementation that had quietly started
// wrapping in-range values somewhere else. The frozen digests are what make "no in-range value
// moved by a single byte" a checkable claim rather than an assurance.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { runInNewContext } from "node:vm";

import { jcsCanonicalize, recordDigestV2, verifyChainHeadAttestation } from "../src/crypto.js";

// The runtime's committed KAT — the same source conformance.test.ts reads, so a runtime regen
// updates one file and reddens both rather than leaving a hand-copied literal here silently stale.
const vectors = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "..", "..", "conformance", "vectors.json"),
    "utf8",
  ),
) as {
  chain_head_attestation: {
    issuer_aid: string;
    signature_hex: string;
    inputs: {
      attested_len: number;
      attested_head_hex: string;
      attested_at: number;
      digest_schema: number;
    };
  };
};

const hex = (u: Uint8Array) => Buffer.from(u).toString("hex");

const BASE = {
  decisionId: "d",
  tenant: "t",
  namespace: "n",
  ciphertextDigest: new Uint8Array(32),
  outcome: "OK",
  mode: null,
  policyVersion: null,
  supersedes: null,
};

// Measured against the pre-fix implementation. If either moves, this phase changed a digest — which
// it must not: it narrows what is ACCEPTED, and touches no emitted byte of anything still accepted.
const FROZEN_SEALED_AT_5 = "b566fdea56b8487bc5ebc26d1d6585339e9ab2a3a499247bd7230e4f20f05d7f";

test("recordDigestV2: the u64 wrap that aliased 2^64+5 onto 5 is refused", () => {
  assert.equal(
    hex(recordDigestV2({ ...BASE, sealedAt: 5n })),
    FROZEN_SEALED_AT_5,
    "an in-range value moved — this phase must not change any digest it still accepts",
  );
  assert.throws(
    () => recordDigestV2({ ...BASE, sealedAt: (1n << 64n) + 5n }),
    RangeError,
    "2^64+5 still reaches a digest; before this phase it reached the SAME digest as 5",
  );
  // The boundary itself, from both sides.
  assert.throws(() => recordDigestV2({ ...BASE, sealedAt: 1n << 64n }), RangeError);
  assert.equal(typeof hex(recordDigestV2({ ...BASE, sealedAt: (1n << 64n) - 1n })), "string");
  assert.throws(() => recordDigestV2({ ...BASE, sealedAt: -1n }), RangeError);
});

test("recordDigestV2: number and bigint spellings of the same integer agree", () => {
  assert.equal(
    hex(recordDigestV2({ ...BASE, sealedAt: 5 })),
    hex(recordDigestV2({ ...BASE, sealedAt: 5n })),
    "5 and 5n must be the same value, not two",
  );
  // -0 is a real JS value and String(-0) is "0"; it must not become a second spelling of zero.
  assert.equal(
    hex(recordDigestV2({ ...BASE, sealedAt: -0 })),
    hex(recordDigestV2({ ...BASE, sealedAt: 0 })),
  );
});

test("recordDigestV2: the u32 wrap one slot over, on schemaVersion", () => {
  assert.throws(() => recordDigestV2({ ...BASE, sealedAt: 1n, schemaVersion: 2 + 2 ** 32 }), RangeError);
  assert.equal(
    hex(recordDigestV2({ ...BASE, sealedAt: 1n })),
    hex(recordDigestV2({ ...BASE, sealedAt: 1n, schemaVersion: 2 })),
    "the default schemaVersion is still 2 and still framed identically",
  );
});

test("recordDigestV2: a number above 2^53 is refused, matching v3", () => {
  // A deliberate NARROWING, not a byte change. Above 2^53 the value hashed is the nearest double
  // rather than the integer the caller meant, so Python (exact ints) would disagree — the same
  // cross-language argument that motivates the whole phase. bigint is how you say it.
  assert.throws(() => recordDigestV2({ ...BASE, sealedAt: 2 ** 60 }), RangeError);
  assert.equal(typeof hex(recordDigestV2({ ...BASE, sealedAt: 2n ** 60n })), "string");
});

test("recordDigestV2: proto3 JSON's stringified int64 is refused, not coerced", () => {
  // `BigInt("5")` is `5n`, so a coerced string would ALIAS a legitimate caller's digest. proto3 JSON
  // renders int64 as a string, so anyone feeding this from JSON.parse of a protobuf payload lands
  // here on their first record.
  assert.throws(() => recordDigestV2({ ...BASE, sealedAt: "5" as unknown as bigint }), TypeError);
});

test("jcsCanonicalize: a lone surrogate is refused in a KEY, as it already was in a value", () => {
  // Before this phase the first of these canonicalized to {"\ud800":1} and the second threw. Python
  // raises UnicodeEncodeError on both. The module's stated invariant — that the implementations
  // agree on which inputs have a digest AT ALL — was true only of the value position.
  assert.throws(() => jcsCanonicalize({ "\ud800": 1 }), /lone surrogate in object key/);
  assert.throws(() => jcsCanonicalize({ k: "\ud800" }), /lone surrogate in string/);
  assert.throws(() => jcsCanonicalize({ "\udc00": 1 }), /lone surrogate in object key/, "trailing half alone");
});

test("jcsCanonicalize: a correct surrogate PAIR in a key still canonicalizes unchanged", () => {
  // The guard must reject unpaired halves only. U+1F600 is stored as a valid pair in UTF-16 and is
  // perfectly encodable, so refusing it would break real callers to fix a bug they do not have.
  assert.equal(hex(jcsCanonicalize({ "\u{1F600}": 1 })), "7b22f09f9880223a317d");
  assert.equal(hex(jcsCanonicalize({ b: 1, a: 2 })), "7b2261223a322c2262223a317d", "ordinary keys untouched");
});

test("verifyChainHeadAttestation: an out-of-range length is not accepted as its wrapped self", () => {
  // The attestation framing shares u64le/u32le with the record digest, so it shared the alias: a
  // signature over attestedLen 1000 verified against a CLAIM of 2^64 + 1000. Measured against the
  // pre-fix build, this returned `true`.
  //
  // Signed by the RUNTIME, not by this test. The first cut of this test used a zero signature and a
  // placeholder AID, which `aidToPubkey` rejects — so `verifyChainHeadAttestation`'s own catch
  // returned false before the digest was ever computed, and the assertion held no matter what
  // `attestedLen` contained. Reverting the fix left the whole suite green. A test whose result is
  // decided by something other than the property it names is the exact failure this repo keeps a
  // vocabulary for, and it is worth having made it once in a file about aliasing.
  const v = vectors.chain_head_attestation;
  const i = v.inputs;
  const att = {
    attestedLen: BigInt(i.attested_len),
    attestedHead: Buffer.from(i.attested_head_hex, "hex"),
    attestedAt: BigInt(i.attested_at),
    digestSchema: i.digest_schema,
    signature: Buffer.from(v.signature_hex, "hex"),
  };

  // The control: without this, every assertion below passes against a broken verifier.
  assert.equal(
    verifyChainHeadAttestation(v.issuer_aid, att),
    true,
    "the runtime's own KAT must verify — if this is false the rest of the test proves nothing",
  );

  // The alias, from both u64 slots. `false` (refused inside the verifier) and a thrown RangeError
  // are both acceptable; `true` is not, and `true` is what the pre-fix build returned.
  for (const [slot, tampered] of [
    ["attestedLen", { ...att, attestedLen: (1n << 64n) + BigInt(i.attested_len) }],
    ["attestedAt", { ...att, attestedAt: (1n << 64n) + BigInt(i.attested_at) }],
  ] as const) {
    let got: boolean | string;
    try {
      got = verifyChainHeadAttestation(v.issuer_aid, tampered);
    } catch {
      got = "threw";
    }
    assert.notEqual(got, true, `${slot} + 2^64 verified as though it were the value the runtime signed`);
  }

  // And the u32 slot one field over.
  let schema: boolean | string;
  try {
    schema = verifyChainHeadAttestation(v.issuer_aid, {
      ...att,
      digestSchema: (1 << 30) * 4 + i.digest_schema,
    });
  } catch {
    schema = "threw";
  }
  assert.notEqual(schema, true, "digestSchema + 2^32 verified as though it were the signed value");
});

test("jcsCanonicalize: an exotic object is refused, not silently emitted as {}", () => {
  // The third place the aliasing rule lived. `typeof v === "object"` is true of `Date`, `Map`,
  // `Set`, `RegExp`, typed arrays, boxed primitives and every class instance, and JCS walked them
  // all with `Object.keys` — emitting whatever their own enumerable properties happened to be,
  // which is not what any of them mean. Measured, before this change:
  //
  //     jcsCanonicalize(new Date(0))             -> {}
  //     jcsCanonicalize(new Map([["a", 1]]))     -> {}
  //     jcsCanonicalize(new Set([1, 2]))         -> {}
  //     jcsCanonicalize(new Number(5))           -> {}
  //     jcsCanonicalize(new Uint8Array([1, 2]))  -> {"0":1,"1":2}
  //     jcsCanonicalize(new String("x"))         -> {"0":"x"}
  //     jcsCanonicalize(new (class { x = 1 })()) -> {"x":1}
  //
  // The last three did NOT collapse to `{}` — they serialized indices or fields — so "these carry
  // no state in own enumerable properties" is a generalization these very measurements refute, and
  // a class instance is a real narrowing rather than a meaningless digest removed. Refused anyway:
  // Python raises `TypeError: … is not JSON-serializable` on every corresponding input, and
  // agreement about which inputs have a digest at all is the property being bought.
  for (const [label, value] of [
    ["Date", new Date(0)],
    ["Map", new Map([["a", 1]])],
    ["Set", new Set([1, 2])],
    ["RegExp", /x/],
    ["Uint8Array", new Uint8Array([1, 2])],
    ["boxed Number", new Number(5)],
    ["boxed String", new String("x")],
    ["class instance", new (class Thing { x = 1 })()],
  ] as const) {
    assert.throws(() => jcsCanonicalize(value), TypeError, `${label} still canonicalizes`);
    assert.throws(() => jcsCanonicalize({ field: value }), TypeError, `${label} nested still canonicalizes`);
  }
});

test("jcsCanonicalize: the alias that made this urgent — two different Dates, one digest", () => {
  // Not "an exotic type is refused" but the consequence: `{ deadline: <date> }` had the SAME
  // tool_input_digest for every possible date, and `callSig` signed it. This is the assertion that
  // would have caught the bug; the one above only describes it.
  const a = { deadline: new Date("2026-01-01T00:00:00Z") };
  const b = { deadline: new Date("2030-01-01T00:00:00Z") };
  assert.throws(() => jcsCanonicalize(a), TypeError);
  assert.throws(() => jcsCanonicalize(b), TypeError);

  // And the shape a caller must move to still digests, distinctly.
  const iso = (o: { deadline: Date }) => ({ deadline: o.deadline.toISOString() });
  assert.notEqual(hex(jcsCanonicalize(iso(a))), hex(jcsCanonicalize(iso(b))));
});

test("jcsCanonicalize: plain data — including cross-realm and null-prototype — still canonicalizes", () => {
  // The guard must refuse exotic objects only. Refusing an ordinary data bag to fix a bug callers
  // do not have would be the worse defect, so the accepting side is pinned as hard as the refusing.
  assert.equal(hex(jcsCanonicalize({ b: 1, a: 2 })), "7b2261223a322c2262223a317d");
  assert.equal(hex(jcsCanonicalize(Object.assign(Object.create(null), { a: 1 }))), hex(jcsCanonicalize({ a: 1 })));
  assert.equal(hex(jcsCanonicalize([1, { a: null }, "x"])), hex(jcsCanonicalize([1, { a: null }, "x"])));

  // A `vm` realm has its own `Object.prototype`, so an identity check against ours would refuse a
  // perfectly ordinary object. The guard tests the prototype chain's DEPTH instead, which is why
  // this passes — and this test is why that choice cannot be quietly simplified away.
  const foreign = runInNewContext("({ a: 1, b: [2, 3] })") as Record<string, unknown>;
  assert.notEqual(Object.getPrototypeOf(foreign), Object.prototype, "vm realm should differ; test is stale if not");
  assert.equal(hex(jcsCanonicalize(foreign)), hex(jcsCanonicalize({ a: 1, b: [2, 3] })));
});

// ── The verifier's blanket catch: `false` was the wrong answer to a caller bug ────────────────────
// `verifyChainHeadAttestation` wrapped everything in `try { ... } catch { return false }`, which
// delivered its documented "false on any tamper" contract by answering `false` to questions it was
// never asked. Measured against the runtime's own KAT, before this change — every one of these
// returned `false`, while Python raised `TypeError` on the identical input:
//
//     attestedLen: "1000"     attestedLen: true     attestedLen: null
//     digestSchema: "2"       attestedHead: "abab"  issuerAid: 5
//
// `false` does not say "you called this wrong". It says "this attestation did not verify" — and an
// operator handed that goes looking for a compromised audit chain.
//
// `signature` is NOT in that list, and the first draft of this comment wrongly put it there. Measured
// against `git show HEAD~:ts/src/crypto.ts`, `signature: "<64 bytes of hex>"` returned **true** — it
// verified, correctly — because `@noble/curves` types the parameter as `Hex = Uint8Array | string`.
// Refusing it now is a NARROWING of working behaviour, taken because Python has never accepted it
// and the point of this phase is that the two agree on what is accepted. Worth stating precisely:
// a claim that a fix removes only broken behaviour is exactly the kind that goes unchecked.
//
// Raising cannot convert an attack into a crash, which is what makes this safe. Attacker-controlled
// bytes decode through protobuf into correctly-TYPED values with hostile contents; a wrong type can
// only come from the code doing the calling.

const ATT = {
  attestedLen: BigInt(vectors.chain_head_attestation.inputs.attested_len),
  attestedHead: Buffer.from(vectors.chain_head_attestation.inputs.attested_head_hex, "hex"),
  attestedAt: BigInt(vectors.chain_head_attestation.inputs.attested_at),
  digestSchema: vectors.chain_head_attestation.inputs.digest_schema,
  signature: Buffer.from(vectors.chain_head_attestation.signature_hex, "hex"),
};
const AID = vectors.chain_head_attestation.issuer_aid;

test("verifyChainHeadAttestation: a wrong-typed argument throws instead of reporting `false`", () => {
  // The control first. Without it every assertion below passes against a verifier that throws
  // unconditionally, which would be a worse bug than the one being fixed.
  assert.equal(verifyChainHeadAttestation(AID, ATT), true, "the runtime's KAT must still verify");

  for (const [label, over] of [
    ["attestedLen string", { attestedLen: "1000" }],
    ["attestedLen boolean", { attestedLen: true }],
    ["attestedLen null", { attestedLen: null }],
    ["attestedAt string", { attestedAt: "1700000000000" }],
    ["digestSchema string", { digestSchema: "2" }],
    ["attestedHead string", { attestedHead: "abab" }],
    ["attestedHead number", { attestedHead: 5 }],
    ["attestedHead plain array", { attestedHead: [1, 2, 3] }],
  ] as const) {
    assert.throws(
      () => verifyChainHeadAttestation(AID, { ...ATT, ...over } as never),
      TypeError,
      `${label} still comes back as "the attestation did not verify"`,
    );
  }
  assert.throws(() => verifyChainHeadAttestation(5 as never, ATT), TypeError, "non-string issuerAid");
  assert.throws(() => verifyChainHeadAttestation(AID, null as never), TypeError, "null attestation");

  // The narrowing, asserted as a narrowing. This input VERIFIED before — `@noble/curves` accepts a
  // hex string — so the test says so rather than filing it with the caller bugs above.
  assert.throws(
    () => verifyChainHeadAttestation(AID, { ...ATT, signature: vectors.chain_head_attestation.signature_hex } as never),
    TypeError,
    "a hex-string signature used to verify; it must now be refused, not silently accepted",
  );

  // A fractional length could not have arrived over the wire either — protobuf decodes uint64 to a
  // whole number — so it is a caller bug too, and throws. (`RangeError` rather than `TypeError`:
  // JavaScript has one number type, so "not a whole number" is a fact about the value. Python, which
  // distinguishes `float` from `int`, raises `TypeError` on its own equivalent. Both REFUSE, which is
  // the property that matters; identical exception classes across two languages is not one.)
  assert.throws(() => verifyChainHeadAttestation(AID, { ...ATT, attestedLen: 1.5 }), RangeError);
});

test("verifyChainHeadAttestation: genuinely untrusted input still answers `false`, never throws", () => {
  // The other half, and the half that makes the change safe to ship. Everything an attacker or a
  // corrupt record can actually produce must still return `false`, because a caller writing
  // `if (!verify(...)) reject()` has to keep working. Only caller bugs were promoted to throws.
  for (const [label, run] of [
    ["out-of-range attestedLen", () => verifyChainHeadAttestation(AID, { ...ATT, attestedLen: (1n << 64n) + 5n })],
    ["out-of-range attestedAt", () => verifyChainHeadAttestation(AID, { ...ATT, attestedAt: 1n << 64n })],
    ["out-of-range digestSchema", () => verifyChainHeadAttestation(AID, { ...ATT, digestSchema: 2 ** 32 })],
    ["tampered attestedLen", () => verifyChainHeadAttestation(AID, { ...ATT, attestedLen: 1001n })],
    ["tampered head", () => verifyChainHeadAttestation(AID, { ...ATT, attestedHead: new Uint8Array(32) })],
    ["wrong-length signature", () => verifyChainHeadAttestation(AID, { ...ATT, signature: new Uint8Array(10) })],
    ["forged signature", () => verifyChainHeadAttestation(AID, { ...ATT, signature: new Uint8Array(64) })],
    ["malformed issuer AID", () => verifyChainHeadAttestation("nope", ATT)],
    ["wrong issuer AID", () => verifyChainHeadAttestation(vectors.chain_head_attestation.issuer_aid.slice(0, -1) + "x", ATT)],
    // 2^60 is a whole number, and exactly representable — it is simply past where its NEIGHBOURS
    // are. Python holds it as an exact integer, digests it, and answers `false`. TypeScript must
    // reach the same `false`, which is why the safe-integer check stays INSIDE the catch: hoisting
    // it out with the type checks would close one divergence by opening another.
    ["2^60 as a number", () => verifyChainHeadAttestation(AID, { ...ATT, attestedLen: 2 ** 60 })],
  ] as const) {
    assert.equal(run(), false, `${label} must be refused, not thrown`);
  }
});
