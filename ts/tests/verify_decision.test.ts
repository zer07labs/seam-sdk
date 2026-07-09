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
 * (an ordinary invalid/tampered decision, signature still well-formed). */
function clientWithProof(issuerAid: string, action?: string): SeamClient {
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
      signedArtifact: new TextEncoder().encode(t.signed_artifact_jws),
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
