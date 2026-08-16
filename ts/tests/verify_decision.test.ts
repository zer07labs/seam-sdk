// `verifyDecision` must surface an issuer-AID mismatch as a DISTINCT signal, not a bland `false`.
//
// A malicious server that swaps the issuer key (a key-substitution attempt) must be distinguishable from
// an ordinary cryptographically-invalid decision — otherwise the security signal is silently downgraded.
// These tests run server-free: `getCommitmentProof` is stubbed, so only the local verification contract is
// exercised. Mirrors the Rust reference's distinct `ClientError::Crypto("issuer AID mismatch…")`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { IssuerMismatchError, SeamClient } from "../src/client.js";

const vectors = JSON.parse(
  readFileSync(new URL("../../conformance/vectors.json", import.meta.url), "utf8"),
);

/** A client whose `getCommitmentProof` returns a stub proof carrying `issuerAid` — no I/O ever happens.
 * `action` overrides the committed action; a wrong value makes the commitment digest miss the TCT's grant
 * (an ordinary invalid/tampered decision, signature still well-formed). `signedArtifact` overrides the raw
 * artifact bytes, for exercising the UTF-8 decode path directly. */
function clientWithProof(issuerAid: string, action?: string, signedArtifact?: Uint8Array): SeamClient {
  const t = vectors.tct;
  const c = t.inputs.commitment;
  const proof = {
    issuerAid,
    commitment: {
      id: c.id,
      action: action ?? c.action,
      authority: c.authority,
      authMethod: c.auth_method,
      trustBasis: c.trust_basis,
      supersedes: c.supersedes ?? "",
      signedArtifact: signedArtifact ?? new TextEncoder().encode(t.signed_artifact_jws),
    },
  };
  const client = SeamClient.connect("http://127.0.0.1:1"); // lazy transport; never dialed
  (client as unknown as { getCommitmentProof: () => Promise<typeof proof> }).getCommitmentProof =
    async () => proof;
  return client;
}

test("verifyDecision: swapped issuer key rejects with a DISTINCT IssuerMismatchError, not a bland false", async () => {
  const serverIssuer = vectors.tct.issuer_aid as string;
  const pinned = "aid:pubkey:ed25519:" + "A".repeat(43); // pinned out of band
  const client = clientWithProof(serverIssuer);

  await assert.rejects(client.verifyDecision("dec-1", pinned), (err: unknown) => {
    assert.ok(err instanceof IssuerMismatchError, "must be the distinct typed error");
    assert.equal(err.proofIssuer, serverIssuer);
    assert.equal(err.expectedIssuer, pinned);
    return true;
  });
});

test("verifyDecision: matching issuer but invalid TCT resolves to false (no throw)", async () => {
  const issuer = vectors.tct.issuer_aid as string;
  // Issuer matches the pin, so we pass the mismatch gate; the tampered action ⇒ digest miss ⇒ invalid.
  const client = clientWithProof(issuer, "TAMPERED");
  assert.equal(await client.verifyDecision("dec-1", issuer), false);
});

test("verifyDecision: non-UTF-8 signedArtifact throws rather than decoding lossily to a bland false", async () => {
  // Mirrors the Python SDK, where `c.signed_artifact.decode()` raises `UnicodeDecodeError` uncaught.
  // A corrupted artifact must be distinguishable from an ordinary invalid decision, not silently folded
  // into `false` by a lossy decode (which would replace the bad bytes with U+FFFD and just fail the TCT
  // signature check for an unrelated reason).
  const issuer = vectors.tct.issuer_aid as string;
  const invalidUtf8 = new Uint8Array([0xff, 0xfe, 0xfd]);
  const client = clientWithProof(issuer, undefined, invalidUtf8);
  await assert.rejects(client.verifyDecision("dec-1", issuer), TypeError);
});
