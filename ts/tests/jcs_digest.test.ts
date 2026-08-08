// JCS + toolInputDigest must reproduce the runtime's cross-language vector byte-for-byte — and
// therefore match the Python SDK character-for-character. The vector is COPIED from the runtime
// (`crates/seam-api/tests/fixtures/`), never re-derived; a mismatch is a contract break.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { ed25519 } from "@noble/curves/ed25519";

import { callSig, callSigPayload, jcsCanonicalize, toolInputDigest } from "../src/crypto.js";

const VECTOR = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "..", "..", "conformance", "authorize_jcs_digest_vector.json"),
    "utf8",
  ),
) as { cases: { name: string; input: unknown; canonical: string; digest: string }[] };

const dec = new TextDecoder();

test("every runtime vector case is byte-exact", () => {
  for (const c of VECTOR.cases) {
    const canonical = jcsCanonicalize(c.input);
    assert.equal(dec.decode(canonical), c.canonical, c.name);
    assert.equal(toolInputDigest(canonical), c.digest, c.name);
  }
});

test("ES6 number rendering edges (ECMA-262 Number::toString)", () => {
  const cases: [number, string][] = [
    [1e-7, "1e-7"],
    [0.000001, "0.000001"],
    [1.5e22, "1.5e+22"],
    [100.0, "100"],
    [-0, "0"],
  ];
  for (const [v, want] of cases) assert.equal(dec.decode(jcsCanonicalize(v)), want);
});

test("unrepresentable inputs are rejected", () => {
  assert.throws(() => jcsCanonicalize(NaN));
  assert.throws(() => jcsCanonicalize(Infinity));
  assert.throws(() => jcsCanonicalize(2n ** 53n + 1n));
  assert.throws(() => jcsCanonicalize(() => {}));
});

// Shape only. The FRAMING is pinned by call_sig_payload.test.ts against the runtime's own bytes.
// In its previous form this test verified the signature against the payload it had just built
// itself (`ticket || digest`), so it stayed green straight through the v1→v2 framing change while
// every live ENFORCE call was being rejected. A test that reconstructs the subject's own input can
// only prove self-consistency — never conformance.
test("callSig is Ed25519 over the v2 payload", () => {
  const seed = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));
  const ticket = new TextEncoder().encode("opaque-ticket-bytes");
  const digest = toolInputDigest(jcsCanonicalize({ a: 1 }));
  const sig = callSig(seed, ticket, digest, "t", "a");
  assert.equal(sig.length, 64);
  assert.ok(ed25519.verify(sig, callSigPayload(ticket, digest, "t", "a"), ed25519.getPublicKey(seed)));
  assert.ok(
    !ed25519.verify(sig, callSigPayload(ticket, digest, "t", "DIFFERENT"), ed25519.getPublicKey(seed)),
  );
});

test("lone surrogates are rejected (parity with Python/Rust)", () => {
  assert.throws(() => jcsCanonicalize({ s: "\ud800" }));
  assert.throws(() => jcsCanonicalize("\udfff"));
  // A well-formed surrogate PAIR is fine (it's just a supplementary-plane char).
  assert.equal(new TextDecoder().decode(jcsCanonicalize("😀")), '"😀"');
});
