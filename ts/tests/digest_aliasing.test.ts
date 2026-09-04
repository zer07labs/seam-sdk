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
