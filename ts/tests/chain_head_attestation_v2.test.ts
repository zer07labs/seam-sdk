// seam-runtime #835: the v2 chain-head attestation framing (tenant inside the signature), and the step-4
// strict dispatch -- an empty tenant verifies under v1 only, a non-empty one under v2 only.
//
// Pinned against conformance/chain_head_attestation_v2_vector.json, vendored verbatim from the runtime's
// crates/seam-client/tests/conformance_vectors_extended.json (`chain_head_attestation_v2`). The shared v1
// block in conformance/vectors.json is untouched -- it is a byte-identity contract.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import {
  CHAIN_HEAD_ATTESTATION_DOMAIN_V1,
  CHAIN_HEAD_ATTESTATION_DOMAIN_V2,
  verifyChainHeadAttestation,
} from "../src/crypto.js";

const read = (name: string) =>
  JSON.parse(readFileSync(new URL(`../../conformance/${name}`, import.meta.url), "utf8"));
const V2 = read("chain_head_attestation_v2_vector.json");
const V1 = read("vectors.json").chain_head_attestation;

const att = (v: typeof V2) => ({
  attestedLen: v.inputs.attested_len,
  attestedHead: Buffer.from(v.inputs.attested_head_hex, "hex"),
  attestedAt: v.inputs.attested_at,
  digestSchema: v.inputs.digest_schema,
  signature: Buffer.from(v.signature_hex, "hex"),
});

test("the vector is the framing this module implements", () => {
  assert.equal(V2.inputs.domain, CHAIN_HEAD_ATTESTATION_DOMAIN_V2);
  assert.deepEqual(V2.frame_order, [
    "domain",
    "attested_len",
    "attested_head",
    "attested_at",
    "digest_schema",
    "issuer_aid",
    "tenant",
  ]);
});

test("the runtime's v2 signature verifies over its own tenant", () => {
  assert.equal(verifyChainHeadAttestation(V2.issuer_aid, { ...att(V2), tenant: V2.inputs.tenant }), true);
});

test("v2 binds the tenant: relabelled or emptied fails", () => {
  for (const tenant of ["acmf", ""]) {
    assert.equal(verifyChainHeadAttestation(V2.issuer_aid, { ...att(V2), tenant }), false, String(tenant));
  }
});

test("any other tamper still fails under v2", () => {
  const a = { ...att(V2), tenant: "acme" };
  assert.equal(verifyChainHeadAttestation(V2.issuer_aid, { ...a, attestedLen: a.attestedLen + 1 }), false);
  assert.equal(verifyChainHeadAttestation(V2.issuer_aid, { ...a, digestSchema: a.digestSchema + 1 }), false);
});

test("the v1 vector verifies with its empty tenant", () => {
  assert.equal(verifyChainHeadAttestation(V1.issuer_aid, { ...att(V1), tenant: "" }), true);
});

// `tenant` is required (#835 step 4): a defaulted "" let a caller who left it off check the v1 framing
// alone, so a v1 attestation relabelled to a tenant verified. Refused in the type AND at runtime, since a
// JavaScript caller never sees the type -- for the v1 vector too, whose right answer is an explicit "".
test("omitting tenant is a type error, and a TypeError at runtime", () => {
  for (const v of [V2, V1]) {
    // @ts-expect-error -- `tenant` is required; this is the call the type must refuse.
    assert.throws(() => verifyChainHeadAttestation(v.issuer_aid, att(v)), /tenant must be a string, not undefined/);
    assert.throws(
      () => verifyChainHeadAttestation(v.issuer_aid, { ...att(v), tenant: undefined } as never),
      TypeError,
    );
  }
});

// #835 step 4, mirroring the runtime's `conformance_drift` test: a v1 signature carries the tenant outside
// the signature, so a non-empty tenant on it could have been relabelled -- refused, with no fallback.
test("the v1 vector relabelled to a tenant is refused", () => {
  assert.equal(verifyChainHeadAttestation(V1.issuer_aid, { ...att(V1), tenant: "acme" }), false);
});

// Transcribed from the spec independently of src/crypto.ts, so this also cross-checks its framing.
const frame = (b: Uint8Array): Uint8Array => {
  const out = new Uint8Array(4 + b.length);
  new DataView(out.buffer).setUint32(0, b.length, true);
  out.set(b, 4);
  return out;
};
const le = (n: number, bytes: 4 | 8): Uint8Array => {
  const out = new Uint8Array(bytes);
  const dv = new DataView(out.buffer);
  if (bytes === 8) dv.setBigUint64(0, BigInt(n), true);
  else dv.setUint32(0, n, true);
  return out;
};
const digest = (v: typeof V2, tenant?: string): Uint8Array => {
  const enc = new TextEncoder();
  const parts = [
    frame(enc.encode(tenant === undefined ? CHAIN_HEAD_ATTESTATION_DOMAIN_V1 : CHAIN_HEAD_ATTESTATION_DOMAIN_V2)),
    frame(le(v.inputs.attested_len, 8)),
    frame(Buffer.from(v.inputs.attested_head_hex, "hex")),
    frame(le(v.inputs.attested_at, 8)),
    frame(le(v.inputs.digest_schema, 4)),
    frame(enc.encode(v.issuer_aid)),
    ...(tenant === undefined ? [] : [frame(enc.encode(tenant))]),
  ];
  return sha256(Buffer.concat(parts));
};

// Never minted by the runtime; hand-rolled with the vector's own seed. An empty tenant selects v1 only, so
// a genuine v2 signature over "" is refused -- and the v1 signature over the same inputs verifies, which
// proves the refusal is the framing, not the key.
test("a v2 signature over the empty tenant is refused", () => {
  const seed = Buffer.from(V2.inputs.issuer_seed_hex, "hex");
  const v2OverEmpty = ed25519.sign(digest(V2, ""), seed);
  const v1 = ed25519.sign(digest(V2), seed);
  assert.equal(
    verifyChainHeadAttestation(V2.issuer_aid, { ...att(V2), signature: v2OverEmpty, tenant: "" }),
    false,
  );
  assert.equal(verifyChainHeadAttestation(V2.issuer_aid, { ...att(V2), signature: v1, tenant: "" }), true);
  // Sanity: the hand-rolled v2 digest is the runtime's, so the refusal above is not a framing typo.
  assert.equal(
    verifyChainHeadAttestation(V2.issuer_aid, {
      ...att(V2),
      signature: ed25519.sign(digest(V2, "acme"), seed),
      tenant: "acme",
    }),
    true,
  );
});

test("a non-string tenant is a caller bug, not a failed verification", () => {
  assert.throws(
    () => verifyChainHeadAttestation(V2.issuer_aid, { ...att(V2), tenant: 7 as unknown as string }),
    /tenant must be a string/,
  );
});

// The safe call shape (#835 step 4): pass the generated ChainHeadAttestation message itself, so `tenant`
// comes from the artifact and can be neither left off nor copied across wrongly.
test("the generated ChainHeadAttestation message carries its tenant into the framing", async () => {
  const { create } = await import("@bufbuild/protobuf");
  const { ChainHeadAttestationSchema } = await import("../gen/seam/event/v1/seam_event_pb.js");
  const msg = (v: typeof V2, tenant: string) =>
    create(ChainHeadAttestationSchema, {
      attestedLen: BigInt(v.inputs.attested_len),
      attestedHead: Buffer.from(v.inputs.attested_head_hex, "hex"),
      attestedAt: BigInt(v.inputs.attested_at),
      issuerAid: v.issuer_aid,
      digestSchema: v.inputs.digest_schema,
      signature: Buffer.from(v.signature_hex, "hex"),
      tenant,
    });
  assert.equal(verifyChainHeadAttestation(V2.issuer_aid, msg(V2, V2.inputs.tenant)), true);
  assert.equal(verifyChainHeadAttestation(V1.issuer_aid, msg(V1, "")), true);
  assert.equal(verifyChainHeadAttestation(V1.issuer_aid, msg(V1, "acme")), false, "relabelled v1 message");
});
