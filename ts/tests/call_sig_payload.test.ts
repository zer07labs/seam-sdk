// The cross-language conformance test for the `callSig` signed payload (v2).
//
// This file exists because of a specific failure. seam-runtime #286 moved the payload from v1
// (`ticket || digest`) to v2 (domain-separated, length-prefixed, additionally covering toolName and
// agentId). Every published SDK kept signing v1, and NOTHING in this repo noticed: the SDK's own
// tests sign and verify with the SDK's own function, so they stay green whatever the framing is.
// The break surfaced only as a live runtime rejecting every ENFORCE call.
//
// A self-consistent signature is not a conformant one. These bytes come from executing the
// runtime's Rust `call_sig_payload`. There is deliberately NO bless mode: a mismatch is a CONTRACT
// BREAK, not a prompt to regenerate the vector.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { ed25519 } from "@noble/curves/ed25519";

import { CALL_SIG_CONTEXT, callSig, callSigPayload } from "../src/crypto.js";

type Case = {
  name: string;
  ticket_hex: string;
  tool_input_digest: string;
  tool_name: string;
  agent_id: string;
  payload_hex: string;
};

const VECTOR = JSON.parse(
  readFileSync(
    join(
      dirname(fileURLToPath(import.meta.url)),
      "..",
      "..",
      "conformance",
      "call_sig_payload_vector.json",
    ),
    "utf8",
  ),
) as { context: string; cases: Case[] };

function fromHex(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

// A vector that lost its cases would parametrise over nothing and report green — the same class of
// non-event that let the v1/v2 skew ship in the first place.
test("the vector is present and populated", () => {
  assert.ok(VECTOR.cases.length >= 6, "the vector lost cases; it pins a wire contract");
});

test("the context tag matches the vector", () => {
  assert.equal(CALL_SIG_CONTEXT, VECTOR.context);
});

test("every payload is byte-exact against the runtime", () => {
  for (const c of VECTOR.cases) {
    const got = callSigPayload(
      fromHex(c.ticket_hex),
      c.tool_input_digest,
      c.tool_name,
      c.agent_id,
    );
    assert.equal(
      toHex(got),
      c.payload_hex,
      `callSig payload diverged from the runtime for case ${c.name}. This is a wire CONTRACT ` +
        `BREAK — every ENFORCE call will be rejected. Do not regenerate the vector to fix it.`,
    );
  }
});

// Without length prefixes these frame identically, which would let a captured signature be
// re-pointed at a different tool — the exact gap v2 closes.
test("length prefixes disambiguate adjacent fields", () => {
  const enc = new TextEncoder();
  const a = callSigPayload(enc.encode("t"), "d", "read", "x");
  const b = callSigPayload(enc.encode("t"), "d", "read_x", "");
  assert.notEqual(toHex(a), toHex(b));
});

// The TS-specific trap: `"träns".length` is 5, its UTF-8 encoding is 6 bytes. Prefixing the string
// length rather than the encoded length diverges from Python and Rust on any non-ASCII input.
test("lengths are byte counts, not UTF-16 code-unit counts", () => {
  const empty = new Uint8Array(0);
  const ascii = callSigPayload(empty, "", "abcde", "");
  const utf8 = callSigPayload(empty, "", "träns", "");
  assert.equal(utf8.length, ascii.length + 1);
});

test("every field is bound into the payload", () => {
  const enc = new TextEncoder();
  const base = toHex(callSigPayload(enc.encode("t"), "d", "n", "a"));
  assert.notEqual(toHex(callSigPayload(enc.encode("T"), "d", "n", "a")), base);
  assert.notEqual(toHex(callSigPayload(enc.encode("t"), "D", "n", "a")), base);
  assert.notEqual(toHex(callSigPayload(enc.encode("t"), "d", "N", "a")), base);
  assert.notEqual(toHex(callSigPayload(enc.encode("t"), "d", "n", "A")), base);
});

// The regression, pinned: if a v1 signature ever verifies against the v2 payload again, the domain
// separation has been lost and a stale client would be silently accepted.
test("v1 framing no longer verifies", () => {
  const seed = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));
  const enc = new TextEncoder();
  const ticket = enc.encode("ticket");
  const digest = "sha256:aa";
  const v1 = ed25519.sign(new Uint8Array([...ticket, ...enc.encode(digest)]), seed);
  assert.ok(
    !ed25519.verify(v1, callSigPayload(ticket, digest, "tool", "a7"), ed25519.getPublicKey(seed)),
  );
});

test("a signature verifies over the payload", () => {
  const seed = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));
  const ticket = new TextEncoder().encode("ticket");
  const sig = callSig(seed, ticket, "sha256:aa", "tool", "a7");
  assert.ok(
    ed25519.verify(sig, callSigPayload(ticket, "sha256:aa", "tool", "a7"), ed25519.getPublicKey(seed)),
  );
});
