// The Gate block v1 (`0x05` trailer) and `seam-gate-digest:v1` (Flows W2, A18) — the strict reader.
//
// Driven row by row by `conformance/gate_block_vector.json` (the runtime's independent stdlib generator,
// vendored byte for byte). Every reader-side section and row is asserted. Refusal rows assert the REFUSAL
// only: rule names are advisory (gate spec §Refusal rules). Every `be64` field decodes to a `bigint` and is
// compared as one (`unavailable_max_be64` decodes, `frame_length_max_be64` refuses as truncated).
// Normative: seam-runtime `docs/specs/seam-gate-block.v1.md`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  CommitmentRefusedError,
  GATE_DIGEST_DOMAIN,
  type GateBlock,
  decodeCommitmentTrailers,
  decodeGateBody,
  gateDigest,
} from "../src/index.js";

const G = JSON.parse(readFileSync(new URL("../../conformance/gate_block_vector.json", import.meta.url), "utf8"));
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
type Row = Record<string, any>;
const DOC = "3488696887c9b0454b0947e69ec0b51c62c9d63f3f840ea98f3fd3b8e1004a05"; // SHA-256("seam-governing-doc:test-vector")

function assertRefused(fn: () => unknown, what: string) {
  assert.throws(fn, (e: unknown) => e instanceof CommitmentRefusedError, `${what}: expected a refusal`);
}

/** The block in the vector's JSON shape: every `be64` as a decimal string, `signature` as hex. */
function asVectorBlock(b: GateBlock): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(b)) {
    if (typeof v === "bigint") out[k] = v.toString();
    else if (v instanceof Uint8Array) out[k] = hex(v);
    else out[k] = v;
  }
  return out;
}

/** A `0x06` body v2 trailer with `env` present, so a lone Gate trailer can pass `gate_env_binding`. */
function governingV2(env: string): string {
  const e = Buffer.from(env, "ascii");
  const body = Buffer.concat([Buffer.from([2]), Buffer.from(DOC, "hex"), Buffer.from([1]), Buffer.alloc(8), e]);
  body.writeBigUInt64BE(BigInt(e.length), 34);
  const len = Buffer.alloc(4);
  len.writeUInt32LE(body.length);
  return "06" + len.toString("hex") + body.toString("hex");
}

test("gate vector: the domain and its 27-byte preimage prefix", () => {
  assert.equal(G.gate_digest_domain, GATE_DIGEST_DOMAIN);
  assert.equal(G.labels.governing_doc_sha256, 'SHA-256("seam-governing-doc:test-vector")');
});

test("gate cases: every case decodes to its block and reproduces its digest, trailer and field 10", () => {
  assert.equal(G.cases.length, 8);
  for (const c of G.cases as Row[]) {
    const block = decodeGateBody(c.gate_body);
    assert.deepEqual(asVectorBlock(block), c.block, `${c.name}: block`);
    const body = Buffer.from(c.gate_body, "hex");
    const digest = gateDigest(c.gate_body);
    assert.equal(hex(digest), c.gate_digest, `${c.name}: gate digest`);
    assert.equal(hex(gateDigest(new Uint8Array(body))), c.gate_digest, `${c.name}: bytes in`);
    // The preimage: F("seam-gate-digest:v1") then the body whole, its version byte included.
    assert.equal(c.gate_digest_preimage_prefix, "0000000000000013" + Buffer.from(GATE_DIGEST_DOMAIN).toString("hex"));
    const len = Buffer.alloc(4);
    len.writeUInt32LE(body.length);
    assert.equal(c.trailer, "05" + len.toString("hex") + c.gate_body, `${c.name}: trailer`);
    assert.equal(c.field_10, "010000000000000020" + c.gate_digest, `${c.name}: field 10`);
    // And through the trailer sequence, beside a matching `0x06` v2 env (gate_env_binding).
    const t = decodeCommitmentTrailers(c.trailer + governingV2(block.env), "v6");
    assert.equal(hex(t.field_10), c.field_10, `${c.name}: field 10 via the sequence`);
    assert.deepEqual(asVectorBlock(t.gate_block!), c.block, `${c.name}: block via the sequence`);
  }
});

test("gate: be64 fields are bigints — 2^64-1 decodes exactly", () => {
  const max = (G.cases as Row[]).find((c) => c.name === "unavailable_max_be64")!;
  const b = decodeGateBody(max.gate_body);
  assert.equal(b.status, "unavailable");
  const top = 2n ** 64n - 1n;
  assert.equal(b.timeout_ms, top);
  assert.equal(b.requested_at_ms, top);
  assert.equal(b.status === "unavailable" && b.given_up_at_ms, top);
  assert.equal(typeof b.timeout_ms, "bigint");
});

test("gate presence_states: absent, answered and unavailable frame field 10", () => {
  assert.equal(G.presence_states.length, 3);
  for (const p of G.presence_states as Row[]) {
    if (p.trailer === null) {
      assert.equal(hex(decodeCommitmentTrailers("", "v6").field_10), p.field_10, p.name);
      assert.equal(hex(decodeCommitmentTrailers(governingV2("live"), "v6").field_10), p.field_10, p.name);
      continue;
    }
    const c = (G.cases as Row[]).find((x) => x.name === p.case)!;
    assert.equal(p.trailer, c.trailer, p.name);
    const t = decodeCommitmentTrailers(p.trailer + governingV2(c.block.env), "v6");
    assert.equal(hex(t.field_10), p.field_10, p.name);
    assert.equal(t.gate_block!.status, p.name, p.name);
  }
});

test("gate body_refusals: every row refuses", () => {
  assert.equal(G.body_refusals.length, 36);
  for (const r of G.body_refusals as Row[]) {
    assert.equal(r.expect, "refused", r.name);
    assertRefused(() => decodeGateBody(r.gate_body), r.name);
  }
});

test("gate sequences: each run under v6 decodes to its fields 10-12 or refuses", () => {
  assert.equal(G.sequences.length, 13);
  for (const r of G.sequences as Row[]) {
    assert.equal(r.scheme, "v6", r.name);
    if (r.expect === "refused") {
      assertRefused(() => decodeCommitmentTrailers(r.trailers, "v6"), r.name);
      continue;
    }
    const t = decodeCommitmentTrailers(r.trailers, "v6");
    assert.equal(hex(t.field_10), r.expect.field_10, `${r.name}: field 10`);
    assert.equal(hex(t.field_11), r.expect.field_11, `${r.name}: field 11`);
    assert.equal(hex(t.field_12!), r.expect.field_12, `${r.name}: field 12`);
  }
});

// `outage_classification` (32 rows) and `writer_refusals` (2 rows) bind the WRITER: which observed
// decision-api outcome is sealed as `unavailable` (and with which reason) versus refused with a typed error,
// and that a 4xx is never written as reason 3. The SDK is a reader — it never calls Gate and never seals —
// so these sections are deliberately not ported (Flows W2 plan, cross-port contract item 3).
test("gate outage_classification and writer_refusals: writer-side, not ported (the SDK is a reader)", { skip: "writer-side: the SDK is a reader" }, () => {
  assert.ok(G.outage_classification.length > 0 && G.writer_refusals.length > 0);
});
