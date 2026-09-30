// The cross-language conformance test for the per-request credential's signed payload (#508).
//
// Mirrors call_sig_payload.test.ts's structure and the lesson behind it: a self-consistent
// signature is not a conformant one. These bytes come from executing the runtime's Rust
// `request_sig_payload`. There is deliberately NO bless mode: a mismatch is a CONTRACT BREAK, not a
// prompt to regenerate the vector.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { ed25519 } from "@noble/curves/ed25519";

import {
  CALL_SIG_CONTEXT,
  REQUEST_SIG_CONTEXT,
  callSigPayload,
  requestSig,
  requestSigPayload,
} from "../src/crypto.js";

type Case = {
  name: string;
  ticket_hex: string;
  rpc_full_name: string;
  resource_id: string;
  body_digest: string;
  body_input_hex?: string;
  payload_hex: string;
};

const VECTOR = JSON.parse(
  readFileSync(
    join(
      dirname(fileURLToPath(import.meta.url)),
      "..",
      "..",
      "conformance",
      "request_sig_payload_vector.json",
    ),
    "utf8",
  ),
) as { domain: string; cases: Case[] };

function fromHex(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

// A vector that lost its cases would parametrise over nothing and report green.
test("the vector is present and populated", () => {
  assert.ok(VECTOR.cases.length >= 6, "the vector lost cases; it pins a wire contract");
});

test("the domain tag matches the vector, and differs from the Authorize call_sig tag", () => {
  assert.equal(REQUEST_SIG_CONTEXT, VECTOR.domain);
  assert.notEqual(REQUEST_SIG_CONTEXT, CALL_SIG_CONTEXT);
});

test("every payload is byte-exact against the runtime", () => {
  for (const c of VECTOR.cases) {
    const got = requestSigPayload(
      fromHex(c.ticket_hex),
      c.rpc_full_name,
      c.resource_id,
      c.body_digest,
    );
    assert.equal(
      toHex(got),
      c.payload_hex,
      `request_sig payload diverged from the runtime for case ${c.name}. This is a wire ` +
        `CONTRACT BREAK. Do not regenerate the vector to fix it.`,
    );
  }
});

test("the bodied-verb digest computation matches the pinned bytes", () => {
  for (const c of VECTOR.cases) {
    if (!c.body_input_hex) continue;
    const digest = "sha256:" + createHash("sha256").update(fromHex(c.body_input_hex)).digest("hex");
    assert.equal(digest, c.body_digest, `case ${c.name}`);
  }
});

// THE re-pointing guard: omitting rpcFullName from the payload would make a structural read and
// the decrypted proof beside it sign identically.
test("same ticket and resource, different verb, produce different payloads", () => {
  const ticket = new Uint8Array([1]);
  const a = requestSigPayload(ticket, "/seam.api.v1.SeamCoordination/GetDecision", "dec:1", "");
  const b = requestSigPayload(
    ticket,
    "/seam.api.v1.SeamCoordination/GetCommitmentProof",
    "dec:1",
    "",
  );
  assert.notEqual(toHex(a), toHex(b));
});

test("length prefixes disambiguate adjacent fields", () => {
  const empty = new Uint8Array(0);
  const a = requestSigPayload(empty, "/seam.api.v1.SeamCoordination/Replay", "x", "");
  const b = requestSigPayload(empty, "/seam.api.v1.SeamCoordination/Replayx", "", "");
  assert.notEqual(toHex(a), toHex(b));
});

// The TS-specific trap: UTF-16 code-unit length diverges from the UTF-8 byte length on any
// non-ASCII input.
test("lengths are byte counts, not UTF-16 code-unit counts", () => {
  const empty = new Uint8Array(0);
  const ascii = requestSigPayload(empty, "/x/Y", "s-abc", "");
  const utf8 = requestSigPayload(empty, "/x/Y", "s-é中🔐", "");
  assert.ok(utf8.length > ascii.length);
});

test("every field is bound into the payload", () => {
  const ticket = new Uint8Array([1]);
  const base = toHex(
    requestSigPayload(ticket, "/seam.api.v1.SeamCoordination/GetDecision", "dec:1", "sha256:aa"),
  );
  assert.notEqual(
    toHex(requestSigPayload(new Uint8Array([2]), "/seam.api.v1.SeamCoordination/GetDecision", "dec:1", "sha256:aa")),
    base,
  );
  assert.notEqual(
    toHex(requestSigPayload(ticket, "/seam.api.v1.SeamCoordination/ReplayDecision", "dec:1", "sha256:aa")),
    base,
  );
  assert.notEqual(
    toHex(requestSigPayload(ticket, "/seam.api.v1.SeamCoordination/GetDecision", "dec:2", "sha256:aa")),
    base,
  );
  assert.notEqual(
    toHex(requestSigPayload(ticket, "/seam.api.v1.SeamCoordination/GetDecision", "dec:1", "sha256:bb")),
    base,
  );
});

test("a signature verifies over the payload", () => {
  const seed = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));
  const ticket = new TextEncoder().encode("ticket");
  const sig = requestSig(seed, ticket, "/seam.api.v1.SeamCoordination/GetDecision", "dec:1", "");
  assert.ok(
    ed25519.verify(
      sig,
      requestSigPayload(ticket, "/seam.api.v1.SeamCoordination/GetDecision", "dec:1", ""),
      ed25519.getPublicKey(seed),
    ),
  );
});

// The two credentials use different domain tags, so a captured one must never verify as the other
// even when every other input happens to collide.
test("a call_sig payload signature does not verify against a request_sig payload", () => {
  const seed = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));
  const enc = new TextEncoder();
  const sig = ed25519.sign(callSigPayload(enc.encode("t"), "d", "n", "a"), seed);
  assert.ok(
    !ed25519.verify(
      sig,
      requestSigPayload(enc.encode("t"), "d", "n", "a"),
      ed25519.getPublicKey(seed),
    ),
  );
});
