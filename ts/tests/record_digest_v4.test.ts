// `recordDigestV4` — the formula, its refusals, and the mistakes a second implementation makes.
//
// The SDK implementations of `seam.audit.record-digest.v4` are clean-room transcriptions from
// `seam-event.v1.md`; that independence is the product claim, and it is only worth anything if each
// one is tested against the spec's *distinctions* rather than against a digest it produced itself.
// So the reproduction tests live in `conformance.test.ts` (machine-emitted vectors), and this file
// carries what a vector cannot: that every input is bound, that the slot order is the spec's and not
// an append, that a strip is refused distinctly from a mismatch, and that nothing normalizes.
//
// The centrepiece is `refDigestV4` below — an INDEPENDENT second transcription of the preimage,
// built from Node's `Buffer`/`node:crypto` rather than the implementation's `DataView`/noble
// helpers. Two transcriptions that agree on 5 vectors and a mutation table are unlikely to be wrong
// in the same direction; one transcription compared against itself is not evidence at all.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  recordDigestV4,
  RecordDigestStripError,
  UnsupportedRecordDigestVersion,
} from "../src/crypto.js";

// The extended set, not only `conformance/vectors.json`: the baseline this file mutates needs every
// optional slot POPULATED, so that dropping one is a visible change. `vectors.json`'s two blocks
// leave `policy_version` and `supersedes` null, which would make several mutations below no-ops.
const extended = JSON.parse(
  readFileSync(new URL("../../conformance/vectors_extended.json", import.meta.url), "utf8"),
);

// The runtime's own two blocks, in the same `{name, inputs, digest_hex}` shape, so the independent
// transcription below runs over the cross-repo vectors as well as the extended set. If either block
// is missing, `vectors.json` and seam-runtime's emitter have stopped agreeing -- throw rather than
// quietly transcription-check the extended cases alone and call that agreement.
const vectors = JSON.parse(
  readFileSync(new URL("../../conformance/vectors.json", import.meta.url), "utf8"),
);

const ALL_V4_CASES: { name: string; inputs: any; digest_hex: string }[] = [
  ...["record_digest_v4", "record_digest_v4_absent_policy"].map((block) => {
    const b = vectors[block];
    if (!b) throw new Error(`conformance/vectors.json has no '${block}' block`);
    return { name: block, inputs: b.inputs, digest_hex: b.digest_hex };
  }),
  ...["all_optionals_present", "optionals_none", "mode_empty_string"].map((name) => {
    const c = extended[name];
    if (!c) throw new Error(`conformance/vectors_extended.json has no '${name}' case`);
    return { name, inputs: c.inputs, digest_hex: c.digest_hex };
  }),
];

type Args = Parameters<typeof recordDigestV4>[0];

const BASE_INPUTS = extended.all_optionals_present.inputs;

function argsOf(i: any): Args {
  return {
    decisionId: i.decision_id,
    tenant: i.tenant,
    namespace: i.namespace,
    ciphertextDigest: Buffer.from(i.ciphertext_digest_hex, "hex"),
    sealedAt: i.sealed_at,
    outcome: i.outcome,
    mode: i.mode,
    policyVersion: i.policy_version,
    supersedes: i.supersedes,
    contextDigest: Buffer.from(i.context_digest_hex, "hex"),
    participationDigest: Buffer.from(i.participation_digest_hex, "hex"),
    policyRulesDigest:
      i.policy_rules_digest_hex === null ? null : Buffer.from(i.policy_rules_digest_hex, "hex"),
    classification: i.classification,
    participantsDigest: Buffer.from(i.participants_digest_hex, "hex"),
    trustBasisCommitment: i.trust_basis_commitment,
    authMethod: i.auth_method,
    schemaVersion: i.schema_version,
  };
}

const baseArgs = (): Args => argsOf(BASE_INPUTS);

const hexOf = (b: Uint8Array) => Buffer.from(b).toString("hex");

// ── an independent transcription ─────────────────────────────────────────────────────────────────

const fr = (b: Uint8Array): Buffer => {
  const len = Buffer.alloc(4);
  len.writeUInt32LE(b.length, 0);
  return Buffer.concat([len, Buffer.from(b)]);
};
const opBytes = (b: Uint8Array | null): Buffer =>
  b === null ? Buffer.from([0]) : Buffer.concat([Buffer.from([1]), fr(b)]);
const opStr = (s: string | null): Buffer =>
  s === null ? Buffer.from([0]) : opBytes(Buffer.from(s, "utf8"));

/** The v4 preimage, transcribed a second time from the spec block with different primitives.
 * `order: "appended"` is the decoy: the same slots with the seven post-v2 ones appended AFTER
 * `schema_version` instead of inserted before it — the shape a "v4 = v2 plus new fields"
 * implementation naturally produces, and which the spec explicitly forbids. */
function refDigestV4(a: Args, order: "spec" | "appended" = "spec"): string {
  const sealed = Buffer.alloc(8);
  sealed.writeBigUInt64LE(BigInt(a.sealedAt), 0);
  const schema = Buffer.alloc(4);
  schema.writeUInt32LE(Number(a.schemaVersion ?? 4), 0);
  const utf8 = (s: string) => Buffer.from(s, "utf8");

  const shared = [
    fr(utf8("seam.audit.record-digest.v4")),
    fr(utf8(a.decisionId)),
    fr(utf8(a.tenant)),
    fr(utf8(a.namespace)),
    fr(a.ciphertextDigest),
    fr(sealed),
    fr(utf8(a.outcome)),
    opStr(a.mode),
    opStr(a.policyVersion),
    opStr(a.supersedes),
  ];
  const added = [
    fr(a.contextDigest),
    fr(a.participationDigest),
    opBytes(a.policyRulesDigest),
    fr(utf8(a.classification)),
    fr(a.participantsDigest),
    fr(utf8(a.trustBasisCommitment)),
    fr(utf8(a.authMethod)),
  ];
  const parts = order === "spec" ? [...shared, ...added, fr(schema)] : [...shared, fr(schema), ...added];
  return createHash("sha256").update(Buffer.concat(parts)).digest("hex");
}

test("the implementation agrees with an independent transcription on every vector case", () => {
  assert.equal(ALL_V4_CASES.length, 5);
  for (const c of ALL_V4_CASES) {
    const a = argsOf(c.inputs);
    assert.equal(hexOf(recordDigestV4(a)), refDigestV4(a), `case ${c.name}`);
    assert.equal(refDigestV4(a), c.digest_hex, `case ${c.name}: the reference disagrees with the vector`);
  }
});

test("the post-v2 slots are inserted before schema_version, not appended after it", () => {
  // The spec is explicit: "a verifier selects the whole formula by `schema_version`, so position is
  // fixed by this spec rather than by append order." Both orders hash the same 17 slots, so only a
  // direct comparison catches the wrong one — a vector alone would just say "mismatch" with no clue.
  const a = baseArgs();
  assert.equal(hexOf(recordDigestV4(a)), refDigestV4(a, "spec"));
  assert.notEqual(
    hexOf(recordDigestV4(a)),
    refDigestV4(a, "appended"),
    "the implementation appends the post-v2 slots after schema_version",
  );
});

// ── every field is bound ─────────────────────────────────────────────────────────────────────────

test("every input is bound into the digest", () => {
  const base = baseArgs();
  const expected = hexOf(recordDigestV4(base));

  const flip = (b: Uint8Array): Uint8Array => {
    const c = Buffer.from(b);
    c[0] ^= 0xff;
    return c;
  };

  const mutations: [keyof Args, Partial<Args>][] = [
    ["decisionId", { decisionId: base.decisionId + "-x" }],
    ["tenant", { tenant: base.tenant + "-x" }],
    ["namespace", { namespace: base.namespace + "-x" }],
    ["ciphertextDigest", { ciphertextDigest: flip(base.ciphertextDigest) }],
    ["sealedAt", { sealedAt: (base.sealedAt as number) + 1 }],
    ["outcome", { outcome: base.outcome + "-x" }],
    ["mode", { mode: base.mode + "-x" }],
    ["policyVersion", { policyVersion: base.policyVersion + "-x" }],
    ["supersedes", { supersedes: base.supersedes + "-x" }],
    ["contextDigest", { contextDigest: flip(base.contextDigest) }],
    ["participationDigest", { participationDigest: flip(base.participationDigest) }],
    ["policyRulesDigest", { policyRulesDigest: flip(base.policyRulesDigest!) }],
    ["classification", { classification: base.classification + "-x" }],
    ["participantsDigest", { participantsDigest: flip(base.participantsDigest) }],
    ["trustBasisCommitment", { trustBasisCommitment: base.trustBasisCommitment + "-x" }],
    ["authMethod", { authMethod: base.authMethod + "-x" }],
  ];

  // Completeness guard: a field added to the signature and forgotten here would leave an unbound
  // slot with a green suite. The table must name every key the function accepts -- except
  // `schemaVersion`, which is not a digest input to vary but the formula selector: any value but 4
  // is refused outright (asserted below and in "a v1-v3 record is refused").
  const covered = new Set<keyof Args>(mutations.map(([k]) => k));
  covered.add("schemaVersion");
  for (const k of Object.keys(base) as (keyof Args)[]) {
    assert.ok(covered.has(k), `the mutation table does not cover '${String(k)}'`);
  }
  assert.equal(covered.size, Object.keys(base).length, "the mutation table names a field that no longer exists");
  assert.throws(() => recordDigestV4({ ...base, schemaVersion: 7 }), UnsupportedRecordDigestVersion);

  for (const [field, change] of mutations) {
    assert.notEqual(
      hexOf(recordDigestV4({ ...base, ...change })),
      expected,
      `changing ${String(field)} did not change the digest -- that slot is not bound`,
    );
  }
});

test("swapping context_digest and participation_digest changes the digest", () => {
  // Slots 10 and 11 are adjacent, identically framed and identically sized, so a wire-mapping that
  // reads tag 12 into slot 10 produces a perfectly well-formed preimage. Only the values differing
  // makes the swap detectable — which is why the vectors keep them distinct.
  const base = baseArgs();
  const swapped = hexOf(
    recordDigestV4({
      ...base,
      contextDigest: base.participationDigest,
      participationDigest: base.contextDigest,
    }),
  );
  assert.notEqual(swapped, hexOf(recordDigestV4(base)));
});

test("policy_rules_digest: absent, present-and-zero, and present-and-set are three digests", () => {
  // `opt` is one byte when absent and 37 when present. An implementation that framed slot 12 (or
  // defaulted absent to 32 zero bytes) would collapse the first two.
  const base = baseArgs();
  const absent = hexOf(recordDigestV4({ ...base, policyRulesDigest: null }));
  const zeros = hexOf(recordDigestV4({ ...base, policyRulesDigest: new Uint8Array(32) }));
  const set = hexOf(recordDigestV4(base));
  assert.equal(new Set([absent, zeros, set]).size, 3, "absent, zeroed and set do not all differ");
});

test("undefined is absent for the string optionals, exactly as null is", () => {
  // Decoded protobuf and hand-built JS objects disagree about which one means "not set"; both reach
  // this function, and treating `undefined` as the string "undefined" would be silent corruption.
  const base = baseArgs();
  const nulls = hexOf(recordDigestV4({ ...base, mode: null, policyVersion: null, supersedes: null }));
  const undef = hexOf(
    recordDigestV4({
      ...base,
      mode: undefined as unknown as null,
      policyVersion: undefined as unknown as null,
      supersedes: undefined as unknown as null,
    }),
  );
  assert.equal(undef, nulls);
});

test("schemaVersion defaults to 4, and sealedAt accepts number or bigint", () => {
  const base = baseArgs();
  const { schemaVersion: _drop, ...withoutVersion } = base;
  assert.equal(hexOf(recordDigestV4(withoutVersion as Args)), hexOf(recordDigestV4(base)));
  assert.equal(hexOf(recordDigestV4({ ...base, schemaVersion: 4n })), hexOf(recordDigestV4(base)));
  assert.equal(
    hexOf(recordDigestV4({ ...base, sealedAt: BigInt(base.sealedAt as number) })),
    hexOf(recordDigestV4(base)),
  );
});

test("a v1-v3 record is refused as unsupported, before any strip check", () => {
  // v4 is the only formula (P7). A record of another version has no v4 digest at all, so it is
  // "cannot verify" -- never recomputed under v4 (which would read as tamper), and never a strip
  // even when it lacks the v4-only slots, because the version gate comes first.
  const base = baseArgs();
  for (const version of [0, 1, 2, 3, 5, 3n]) {
    assert.throws(
      () => recordDigestV4({ ...base, schemaVersion: version }),
      (e: unknown) => e instanceof UnsupportedRecordDigestVersion && e.schemaVersion === version,
      `schema_version ${String(version)} was not refused as unsupported`,
    );
    assert.throws(
      () =>
        recordDigestV4({
          ...base,
          schemaVersion: version,
          classification: "",
          participantsDigest: undefined as unknown as Uint8Array,
        }),
      UnsupportedRecordDigestVersion,
      `schema_version ${String(version)} with stripped v4 slots reported a strip, not unsupported`,
    );
  }
});

// ── strings hash raw, with no normalization ──────────────────────────────────────────────────────

test("no Unicode normalization is applied to any string slot", () => {
  // "Strings hash as their raw UTF-8 bytes, with no normalization of any kind." Normalization is the
  // step the spec singles out as the one three of four implementations get wrong — so it is tested
  // per string slot, not once.
  const base = baseArgs();
  const nfd = "café"; // e + COMBINING ACUTE ACCENT
  const nfc = "café"; // precomposed
  assert.notEqual(nfd, nfc);
  assert.equal(nfd.normalize("NFC"), nfc);

  for (const slot of [
    "decisionId",
    "tenant",
    "namespace",
    "outcome",
    "mode",
    "policyVersion",
    "supersedes",
    "classification",
    "trustBasisCommitment",
    "authMethod",
  ] as const) {
    assert.notEqual(
      hexOf(recordDigestV4({ ...base, [slot]: nfd })),
      hexOf(recordDigestV4({ ...base, [slot]: nfc })),
      `${slot} appears to be normalized before hashing`,
    );
  }
});

test("strings are encoded as UTF-8, not UTF-16 or Latin-1", () => {
  // `TextEncoder` is UTF-8; `Buffer.from(s)` defaults to UTF-8 too, but `Buffer.from(s, "latin1")`
  // and `"utf16le"` are one argument away and produce a well-formed, wrong digest. A multi-byte
  // codepoint is what separates them; the ASCII fixtures cannot.
  const base = baseArgs();
  const text = "café-日本";
  const got = hexOf(recordDigestV4({ ...base, mode: text }));
  for (const codec of ["latin1", "utf16le"] as const) {
    const wrong = hexOf(
      recordDigestV4({ ...base, mode: Buffer.from(text, codec).toString("latin1") }),
    );
    assert.notEqual(got, wrong, `the ${codec} encoding of the same string produced the same digest`);
  }
});

// ── strip refusals, distinct from mismatches ─────────────────────────────────────────────────────

// The reporting layer's mismatch wording — seam-verify's "does NOT match its own digest" and its
// twins. Deliberately NOT the bare word "mismatch": these messages say "This is a STRIP, not a
// digest mismatch", which uses the word to negate it. Matching the whole vocabulary would forbid
// exactly the sentence that makes the distinction clearest to an operator. The Python twin pins the
// same string (`test_record_digest_v4.py`).
const MISMATCH_WORDING = /does not match/i;

test("a stripped mandatory field is refused, not defaulted and not fallen back", () => {
  const base = baseArgs();
  // Tags 11, 12, 14, 15, 16 and 17 are mandatory. Absent spelled `undefined`, `null`, or empty
  // (`length === 0` is how the wire says absent) is one strip, never a digest over an empty slot.
  const slots: [string, number, keyof Args, string | Uint8Array][] = [
    ["context_digest", 11, "contextDigest", new Uint8Array(0)],
    ["participation_digest", 12, "participationDigest", new Uint8Array(0)],
    ["classification", 14, "classification", ""],
    ["participants_digest", 15, "participantsDigest", new Uint8Array(0)],
    ["trust_basis_commitment", 16, "trustBasisCommitment", ""],
    ["auth_method", 17, "authMethod", ""],
  ];
  const stripped: [string, number, Partial<Args>][] = slots.flatMap(([field, tag, key, empty]) =>
    [undefined, null, empty].map(
      (v) => [field, tag, { [key]: v } as Partial<Args>] as [string, number, Partial<Args>],
    ),
  );
  for (const [field, tag, change] of stripped) {
    assert.throws(
      () => recordDigestV4({ ...base, ...change }),
      (e: unknown) => {
        assert.ok(e instanceof RecordDigestStripError, `${field} did not raise the strip error type`);
        assert.equal(e.field, field);
        assert.equal(e.wireTag, tag);
        assert.match(e.message, new RegExp(field));
        assert.match(e.message, new RegExp(`tag ${tag}\\b`));
        assert.match(e.message, /STRIP/, "the message does not name the refusal as a strip");
        assert.doesNotMatch(
          e.message,
          MISMATCH_WORDING,
          "a strip is being described in the vocabulary of a mismatch -- the spec requires the two " +
            "be distinguishable by an operator reading the message",
        );
        return true;
      },
      `${field} absent must refuse`,
    );
  }
});

test("a wrong-length sub-digest is refused rather than hashed", () => {
  // Hashing a 31-byte context_digest would produce a perfectly well-formed digest that differs from
  // the wire one — surfacing a MALFORMED field as though the record had been REWRITTEN. That is the
  // exact confusion the spec's strip semantics exist to prevent, so length is checked, not assumed.
  const base = baseArgs();
  const cases: [string, number, Partial<Args>][] = [
    ["context_digest", 11, { contextDigest: new Uint8Array(31) }],
    ["participation_digest", 12, { participationDigest: new Uint8Array(33) }],
    ["policy_rules_digest", 13, { policyRulesDigest: new Uint8Array(16) }],
    ["policy_rules_digest", 13, { policyRulesDigest: new Uint8Array(0) }],
    ["participants_digest", 15, { participantsDigest: new Uint8Array(31) }],
  ];
  for (const [field, tag, change] of cases) {
    assert.throws(
      () => recordDigestV4({ ...base, ...change }),
      (e: unknown) => {
        assert.ok(e instanceof RecordDigestStripError);
        assert.equal(e.field, field);
        assert.equal(e.wireTag, tag);
        assert.match(e.message, /malformed/i);
        assert.doesNotMatch(e.message, MISMATCH_WORDING);
        return true;
      },
      `${field} wrong length must refuse`,
    );
  }
});

test("an absent policy_rules_digest is legitimate and must NOT refuse", () => {
  // The mirror of the tests above, and the reason they cannot simply refuse anything unset: tag 13
  // absent means no policy was bound, which is today's common case. A verifier that refused it would
  // reject almost every real record.
  const base = baseArgs();
  assert.doesNotThrow(() => recordDigestV4({ ...base, policyRulesDigest: null }));
  assert.doesNotThrow(() =>
    recordDigestV4({ ...base, policyRulesDigest: undefined as unknown as null }),
  );
  assert.equal(
    hexOf(recordDigestV4({ ...base, policyRulesDigest: undefined as unknown as null })),
    hexOf(recordDigestV4({ ...base, policyRulesDigest: null })),
  );
});

test("a refusal is structurally distinct from a mismatch", () => {
  // The distinctness requirement, as a property rather than a string check: a mismatch is a value
  // this function RETURNS (for the caller to compare), a strip is a value it never returns at all.
  // No caller can conflate them by accident, whatever it does with the message text.
  const base = baseArgs();
  const rewritten = recordDigestV4({ ...base, outcome: "Denied" });
  assert.equal(rewritten.length, 32, "a rewritten record still yields a digest, to be compared");
  assert.throws(
    () => recordDigestV4({ ...base, contextDigest: undefined as unknown as Uint8Array }),
    RecordDigestStripError,
  );
});

// ── inputs that would otherwise produce a silently-wrong digest ─────────────────────────────────

test("a non-bytes sub-digest of the right length is refused, not coerced -- all four tags", () => {
  // The one input that defeats a length-only guard: `Uint8Array.prototype.set` coerces each element
  // via ToNumber, so a 32-CHARACTER STRING becomes 32 NaN becomes 32 zero bytes. The result is not a
  // mismatch -- it is an ALIAS onto the digest a legitimate all-zeros sub-digest produces, and an
  // alias is strictly worse: a mismatch gets caught downstream, an alias never does.
  //
  // Tag 13 is in this table because leaving it out is exactly the mistake that shipped once: the
  // first fix guarded tags 11 and 12, the test parametrized 11 and 12, and `policyRulesDigest` kept
  // the hole with a green suite three lines away from the guard.
  const base = baseArgs();
  const decoys: [string, unknown][] = [
    ["32-char string", "x".repeat(32)],
    ["plain object with a length", { length: 32 }],
    ["Array of 32 numbers", new Array(32).fill(7)],
    ["ArrayBuffer", new ArrayBuffer(32)],
    ["DataView", new DataView(new ArrayBuffer(32))],
    // Exactly 32 BYTES, so the length check cannot catch it -- only the element-size check can. It
    // is refused because a Uint16Array's backing bytes are in HOST order, so accepting it would make
    // the digest depend on the endianness of the machine that computed it. Every length prefix in
    // this module is explicitly little-endian to prevent precisely that.
    ["Uint16Array of 32 bytes", new Uint16Array(16)],
  ];
  const slots: [string, number, keyof Args][] = [
    ["context_digest", 11, "contextDigest"],
    ["participation_digest", 12, "participationDigest"],
    ["policy_rules_digest", 13, "policyRulesDigest"],
    ["participants_digest", 15, "participantsDigest"],
  ];
  for (const [field, tag, key] of slots) {
    for (const [label, decoy] of decoys) {
      assert.throws(
        () => recordDigestV4({ ...base, [key]: decoy } as Args),
        (e: unknown) => {
          assert.ok(
            e instanceof RecordDigestStripError,
            `${field} accepted a ${label} without a typed refusal`,
          );
          assert.equal(e.field, field);
          assert.equal(e.wireTag, tag);
          assert.match(e.message, /malformed/i);
          return true;
        },
        `${field} accepted a ${label}`,
      );
    }
  }

  // The alias, demonstrated rather than described: this is the digest every decoy above would have
  // produced, and it is a digest a legitimate caller can also produce. Nothing downstream could tell
  // the two apart, which is why the refusal has to happen here.
  const legitZeros = hexOf(recordDigestV4({ ...base, contextDigest: new Uint8Array(32) }));
  assert.equal(legitZeros.length, 64);
  assert.notEqual(legitZeros, hexOf(recordDigestV4(base)));
});

test("genuine byte views are accepted, whatever their exact class", () => {
  // The guard must not overshoot. `Buffer` (a Uint8Array subclass) is what every caller in this repo
  // actually passes; a cross-realm `Uint8Array` -- from `node:vm` or a worker -- is genuine bytes but
  // fails `instanceof`, so the check is written over `ArrayBuffer.isView` + a one-byte element size.
  const base = baseArgs();
  const expected = hexOf(recordDigestV4(base));
  const raw = Buffer.from(BASE_INPUTS.context_digest_hex, "hex");

  const equivalents: [string, Uint8Array][] = [
    ["Buffer", raw],
    ["plain Uint8Array", new Uint8Array(raw)],
    ["Uint8ClampedArray", new Uint8ClampedArray(raw) as unknown as Uint8Array],
    ["a subarray view", new Uint8Array([...raw, 0xff]).subarray(0, 32)],
    // A signed view over the SAME bytes. Reinterpreting it is not coercion -- byte 0xff reads as
    // -1 through an Int8Array and as 255 through a Uint8Array, but it is one byte either way, and
    // it is the byte the caller holds. Refusing it would be the guard overshooting.
    ["Int8Array", new Int8Array(raw.buffer, raw.byteOffset, raw.byteLength) as unknown as Uint8Array],
  ];
  for (const [label, bytes] of equivalents) {
    assert.equal(
      hexOf(recordDigestV4({ ...base, contextDigest: bytes })),
      expected,
      `${label} was not treated as the same 32 bytes`,
    );
  }
});

test("an out-of-range or inexact integer is refused, not silently wrapped", () => {
  // `setBigUint64`/`setUint32` apply ToBigUint64/ToUint32, so 2^64+5 writes the same eight bytes as
  // 5. That is an alias again, not a mismatch. And a `number` above 2^53 is already inexact, so the
  // value hashed would be the nearest double rather than the integer the caller meant -- Python, with
  // exact ints, would disagree, which is a cross-language divergence in a signed digest.
  const base = baseArgs();
  const bad: [string, Partial<Args>][] = [
    ["sealedAt negative", { sealedAt: -1 }],
    ["sealedAt >= 2^64", { sealedAt: (1n << 64n) + 5n }],
    ["sealedAt fractional", { sealedAt: 1.5 }],
    ["sealedAt above 2^53 as a number", { sealedAt: 2 ** 60 }],
  ];
  for (const [label, change] of bad) {
    assert.throws(() => recordDigestV4({ ...base, ...change }), RangeError, `${label} was accepted`);
  }
  // `schemaVersion` is gated by value before any range check: anything but exactly 4 has no v4
  // digest, so an out-of-range spelling is unsupported rather than wrapped.
  for (const v of [-1, 2 ** 32 + 4, 4.5, (1n << 32n) + 4n]) {
    assert.throws(
      () => recordDigestV4({ ...base, schemaVersion: v }),
      UnsupportedRecordDigestVersion,
      `schemaVersion ${String(v)} was accepted`,
    );
  }

  // The number and bigint spellings of the same value must agree -- the range check must not have
  // changed how a legitimate value is encoded.
  assert.equal(
    hexOf(recordDigestV4({ ...base, sealedAt: 5 })),
    hexOf(recordDigestV4({ ...base, sealedAt: 5n })),
  );
});

test("a non-string in a string slot is refused, not stringified", () => {
  // `TextEncoder` encodes whatever ToString gives it: `undefined` becomes "undefined", `null` becomes
  // "null", `5` becomes "5". Each is a well-formed digest over text nobody supplied. Python raises
  // (`AttributeError`) on all three, so refusing here is parity.
  const base = baseArgs();
  for (const slot of ["decisionId", "tenant", "namespace", "outcome"] as const) {
    for (const bad of [undefined, null, 5, {}]) {
      assert.throws(
        () => recordDigestV4({ ...base, [slot]: bad } as unknown as Args),
        TypeError,
        `${slot} accepted ${String(bad)}`,
      );
    }
  }
  // The optional slots take null/undefined as ABSENT -- that is data, not a type error -- but still
  // refuse a non-string.
  for (const slot of ["mode", "policyVersion", "supersedes"] as const) {
    assert.doesNotThrow(() => recordDigestV4({ ...base, [slot]: null }));
    assert.throws(
      () => recordDigestV4({ ...base, [slot]: 5 } as unknown as Args),
      TypeError,
      `${slot} accepted a number`,
    );
  }
  // The mandatory v4 text slots refuse a non-string the same way (absent/empty is a strip, tested
  // above).
  for (const slot of ["classification", "trustBasisCommitment", "authMethod"] as const) {
    for (const bad of [5, {}, true]) {
      assert.throws(
        () => recordDigestV4({ ...base, [slot]: bad } as unknown as Args),
        TypeError,
        `${slot} accepted ${String(bad)}`,
      );
    }
  }
  // And the ciphertext digest, which is bytes rather than text but coerces the same way.
  assert.throws(
    () => recordDigestV4({ ...base, ciphertextDigest: "x".repeat(32) as unknown as Uint8Array }),
    TypeError,
  );
});

test("a lone surrogate in any string slot is refused, not encoded as U+FFFD", () => {
  // `TextEncoder` is lossy on invalid UTF-16: it substitutes U+FFFD rather than failing. A digest
  // taken over that substitution is one Python (UnicodeEncodeError) and Rust (`String` is always
  // well-formed) can never reproduce -- a cross-language divergence in a value whose entire purpose
  // is to be byte-identical everywhere. The JCS path in this same module already refuses it; the
  // record-digest path now does too.
  const base = baseArgs();
  const lone = "ctx-\ud800-tail"; // high surrogate with no low surrogate following
  assert.equal(new TextEncoder().encode(lone).length, new TextEncoder().encode("ctx-�-tail").length);

  for (const slot of [
    "decisionId",
    "tenant",
    "namespace",
    "outcome",
    "mode",
    "policyVersion",
    "supersedes",
    "classification",
    "trustBasisCommitment",
    "authMethod",
  ] as const) {
    assert.throws(
      () => recordDigestV4({ ...base, [slot]: lone }),
      /lone surrogate/,
      `${slot} accepted a lone surrogate`,
    );
  }

  // A well-formed astral pair (which IS valid Unicode) must still be accepted -- the guard must
  // reject unpaired surrogates, not every string that happens to contain surrogate code units.
  assert.doesNotThrow(() => recordDigestV4({ ...base, mode: "ok-\u{1f512}-ok" }));
});

// ── the class of defect, closed structurally ─────────────────────────────────────────────────────
//
// Three verification rounds each found ONE more coercion path -- tag 13 after tags 11 and 12, then
// `BigInt("5")` after the range checks. Each fix was correct and each left the same class open,
// because "did I guard every slot against every wrong-typed value" is not a question hand-written
// per-slot tests can answer. This does answer it: every parameter is declared with the KIND of value
// it accepts, and every kind is driven with a corpus of values of the other kinds. A slot added to
// the signature without a matching entry fails the completeness guard; a slot that accepts something
// outside its kind fails here rather than in a fourth review round.
//
// The property is refusal, not correctness-of-digest: for anything outside a slot's declared kind
// there IS no correct digest, so returning one at all is the defect. (The other direction -- that
// legitimate values are still accepted, and that equivalent spellings agree -- is what the
// vector loop and "genuine byte views are accepted" cover.)

type Kind = "bytes" | "text" | "uint";

const SLOT_KINDS: Record<keyof Args, Kind> = {
  decisionId: "text",
  tenant: "text",
  namespace: "text",
  outcome: "text",
  mode: "text",
  policyVersion: "text",
  supersedes: "text",
  ciphertextDigest: "bytes",
  contextDigest: "bytes",
  participationDigest: "bytes",
  policyRulesDigest: "bytes",
  participantsDigest: "bytes",
  classification: "text",
  trustBasisCommitment: "text",
  authMethod: "text",
  sealedAt: "uint",
  schemaVersion: "uint",
};

/** Values that are NOT of the given kind, and that JavaScript would silently convert into something
 * of it. Every one of these has a coercion in the language that makes it look plausible. */
const WRONG_KIND: Record<Kind, [string, unknown][]> = {
  bytes: [
    ["a 32-char string", "x".repeat(32)],
    ["an object with .length", { length: 32 }],
    ["an Array of 32 numbers", new Array(32).fill(7)],
    ["a bare ArrayBuffer", new ArrayBuffer(32)],
    ["a DataView", new DataView(new ArrayBuffer(32))],
    ["a 32-byte Uint16Array", new Uint16Array(16)],
    ["a number", 32],
    ["a boolean", true],
  ],
  text: [
    ["a number", 5],
    ["a bigint", 5n],
    ["a boolean", true],
    ["an Array", ["a"]],
    ["an object with toString", { toString: () => "a" }],
    ["bytes", new Uint8Array(4)],
  ],
  uint: [
    ["a numeric string", "5"],
    // proto3 JSON renders int64 as a string, so this exact value reaches the function from any caller
    // feeding it `JSON.parse` output. `BigInt` would turn it into the legitimate digest, silently.
    ["a proto3-JSON int64 string", "1700000000000"],
    ["an empty string (BigInt('') is 0n)", ""],
    ["a boolean", true],
    ["an Array (BigInt([5]) is 5n)", [5]],
    ["an object with valueOf", { valueOf: () => 5 }],
    ["a Uint8Array", new Uint8Array(1)],
  ],
};

test("no slot accepts a value outside its declared kind", () => {
  const base = baseArgs();
  const baseline = hexOf(recordDigestV4(base));

  // Completeness: a parameter added to the signature and not classified here would be silently
  // exempt from every check below -- which is precisely how tag 13 was missed the first time.
  for (const key of Object.keys(base) as (keyof Args)[]) {
    assert.ok(SLOT_KINDS[key] !== undefined, `slot '${String(key)}' has no declared kind`);
  }
  for (const key of Object.keys(SLOT_KINDS) as (keyof Args)[]) {
    assert.ok(key in base, `SLOT_KINDS names '${String(key)}', which is no longer a parameter`);
  }

  for (const [slot, kind] of Object.entries(SLOT_KINDS) as [keyof Args, Kind][]) {
    for (const [label, value] of WRONG_KIND[kind]) {
      let digested: string | null = null;
      try {
        digested = hexOf(recordDigestV4({ ...base, [slot]: value } as Args));
      } catch {
        continue; // refused -- which is the only acceptable outcome
      }
      assert.fail(
        `${String(slot)} (declared ${kind}) accepted ${label} and returned ${digested}` +
          (digested === baseline
            ? " -- which is BYTE-IDENTICAL to the legitimate digest, so nothing downstream could" +
              " ever detect it"
            : " -- a digest over a value the caller never supplied"),
      );
    }
  }
});

test("a byte view cannot lie about its own length", () => {
  // The subtlest hole this phase found, and the one no type check could catch: a GENUINE
  // `Uint8Array` whose `length` has been shadowed. Two readers then disagree -- `frameLE` writes a
  // prefix from the shadowed property, `concat`'s `set` copies the internal `[[ArrayLength]]` -- and
  // the result is a well-formed digest under a length prefix that lies about its own content. The
  // framing rules in the spec exist precisely to make a preimage self-delimiting; a lying prefix
  // dissolves that guarantee from inside a right-typed object.
  //
  // It aliased: the spoof below produced a digest byte-identical to a legitimate all-zeros
  // sub-digest, so nothing downstream could ever have told the two apart.
  const base = baseArgs();

  const shadowed = new Uint8Array(0);
  Object.defineProperty(shadowed, "length", { value: 32 });
  class LyingLength extends Uint8Array {
    override get length() {
      return 32;
    }
  }
  const spoofs: [string, Uint8Array][] = [
    ["an own `length` property", shadowed],
    ["a subclass with a `length` getter", new LyingLength(0)],
  ];

  // The four 32-byte slots: a spoof claiming 32 while holding 0 must be refused by the length check,
  // now that the length check sees the truth.
  for (const slot of ["contextDigest", "participationDigest", "policyRulesDigest", "participantsDigest"] as const) {
    for (const [label, spoof] of spoofs) {
      assert.throws(
        () => recordDigestV4({ ...base, [slot]: spoof }),
        `${slot} accepted ${label} -- the length prefix and the copied bytes now disagree`,
      );
    }
  }

  // Tag 10 carries no length requirement, so there is nothing for a length check to refuse -- and
  // nothing to refuse it FOR: the spoof holds zero bytes, and zero bytes is what gets hashed. The
  // property that matters here is not rejection but honesty, so it is asserted as such.
  assert.equal(
    hexOf(recordDigestV4({ ...base, ciphertextDigest: spoofs[0][1] })),
    hexOf(recordDigestV4({ ...base, ciphertextDigest: new Uint8Array(0) })),
    "a ciphertextDigest claiming 32 bytes while holding 0 did not hash as the 0 bytes it holds",
  );

  // The mirror image, and the reason the fix READS THROUGH the lie rather than merely rejecting
  // anything suspicious: a real 32-byte array whose `length` claims 4 is still 32 bytes of genuine
  // digest. The internal slots are the truth, the shadowed property is noise, and the digest must
  // come out identical to the same bytes with no lie attached. A guard that only distrusted
  // mismatched metadata would refuse this legitimate value instead.
  const trueBytes = Buffer.from(BASE_INPUTS.context_digest_hex, "hex");
  const understating = Object.defineProperty(new Uint8Array(trueBytes), "length", { value: 4 });
  assert.equal(
    hexOf(recordDigestV4({ ...base, contextDigest: understating })),
    hexOf(recordDigestV4(base)),
    "a shadowed `length` changed the digest -- the bytes are being read through the property",
  );

  // And the guard must read through internal slots, not merely distrust `length`: a legitimate view
  // whose byteOffset/byteLength are perfectly ordinary must still work.
  const backing = new Uint8Array([...new Uint8Array(8), ...Buffer.from(BASE_INPUTS.context_digest_hex, "hex")]);
  assert.equal(
    hexOf(recordDigestV4({ ...base, contextDigest: backing.subarray(8) })),
    hexOf(recordDigestV4(base)),
    "an offset subarray of the right bytes was not treated as those bytes",
  );
});
