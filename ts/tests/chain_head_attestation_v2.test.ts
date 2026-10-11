// seam-runtime #835 step 1: the v2 chain-head attestation framing (tenant inside the signature).
//
// Pinned against conformance/chain_head_attestation_v2_vector.json, vendored verbatim from the runtime's
// crates/seam-client/tests/conformance_vectors_extended.json (`chain_head_attestation_v2`). The shared v1
// block in conformance/vectors.json is untouched -- it is a byte-identity contract.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { CHAIN_HEAD_ATTESTATION_DOMAIN_V2, verifyChainHeadAttestation } from "../src/crypto.js";

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

test("v2 binds the tenant: relabelled or emptied fails, and so does omitting it", () => {
  for (const tenant of ["acmf", "", undefined]) {
    assert.equal(verifyChainHeadAttestation(V2.issuer_aid, { ...att(V2), tenant }), false, String(tenant));
  }
});

test("any other tamper still fails under v2", () => {
  const a = { ...att(V2), tenant: "acme" };
  assert.equal(verifyChainHeadAttestation(V2.issuer_aid, { ...a, attestedLen: a.attestedLen + 1 }), false);
  assert.equal(verifyChainHeadAttestation(V2.issuer_aid, { ...a, digestSchema: a.digestSchema + 1 }), false);
});

test("a v1 attestation with a tenant still verifies until #835 step 4", () => {
  assert.equal(verifyChainHeadAttestation(V1.issuer_aid, { ...att(V1), tenant: "acme" }), true);
  assert.equal(verifyChainHeadAttestation(V1.issuer_aid, att(V1)), true);
});

test("a non-string tenant is a caller bug, not a failed verification", () => {
  assert.throws(
    () => verifyChainHeadAttestation(V2.issuer_aid, { ...att(V2), tenant: 7 as unknown as string }),
    /tenant must be a string/,
  );
});
