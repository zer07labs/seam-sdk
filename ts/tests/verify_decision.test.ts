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
import { ExplanationKind, VoterVerification } from "../gen/seam/api/v1/seam_pb.js";

const vectors = JSON.parse(
  readFileSync(new URL("../../conformance/vectors.json", import.meta.url), "utf8"),
);

type ProtoEntry = {
  kind: ExplanationKind;
  participant: string;
  proposalId: string;
  value: string;
  reason: string;
  confidence?: number;
  rationaleRef?: string;
  voterVerification?: Record<string, unknown>;
};

const fromHex = (h: string) => new Uint8Array(Buffer.from(h, "hex"));

/** The vector's `*_hex` voter verification record (#1687) as the proto `VoterVerificationRecord`. */
function protoVoterRecord(v: Record<string, any>): Record<string, unknown> {
  return {
    method: v.method === "pop" ? VoterVerification.POP : VoterVerification.CP_SIGNED,
    principal: v.principal,
    contentDigest: fromHex(v.content_digest_hex),
    issuedAtMs: BigInt(v.issued_at_ms),
    expiresAtMs: BigInt(v.expires_at_ms),
    signature: fromHex(v.signature_hex),
    signerCertificate: fromHex(v.signer_certificate_hex),
    tenant: v.tenant,
    namespace: v.namespace,
    sessionId: v.session_id,
    openedAtMillis: BigInt(v.opened_at_millis),
    issuer: v.issuer,
    audience: v.audience,
    acceptedAtMs: BigInt(v.accepted_at_ms),
  };
}

const KIND: Record<string, ExplanationKind> = {
  vote: ExplanationKind.VOTE,
  evaluation: ExplanationKind.EVALUATION,
  objection: ExplanationKind.OBJECTION,
  ballot: ExplanationKind.BALLOT,
};

/** The vector's explanation as the proto (camelCase, enum kind, absent = `undefined`) would carry it. */
function protoExplanation(): ProtoEntry[] {
  return (vectors.tct.inputs.commitment.explanation as Record<string, unknown>[]).map((e) => ({
    kind: KIND[e.kind as string],
    participant: e.participant as string,
    proposalId: e.proposal_id as string,
    value: e.value as string,
    reason: e.reason as string,
    ...(e.confidence !== null ? { confidence: e.confidence as number } : {}),
    ...(e.rationale_ref !== null ? { rationaleRef: e.rationale_ref as string } : {}),
    ...(e.voter_verification !== null && e.voter_verification !== undefined
      ? { voterVerification: protoVoterRecord(e.voter_verification as Record<string, any>) }
      : {}),
  }));
}

/** A client whose `getCommitmentProof` returns a stub proof carrying `issuerAid` — no I/O ever happens.
 * `action` overrides the committed action; a wrong value makes the commitment digest miss the TCT's grant
 * (an ordinary invalid/tampered decision, signature still well-formed). `signedArtifact` overrides the raw
 * artifact bytes, for exercising the UTF-8 decode path directly. `extra` overrides any other proto field
 * (committer / explanation / explanationDigest). */
function clientWithProof(
  issuerAid: string,
  action?: string,
  signedArtifact?: Uint8Array,
  extra: Record<string, unknown> = {},
): SeamClient {
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
      // v4 frames absent and present-empty differently (a presence byte): an unset `supersedes` must
      // stay unset, as the proto's explicit presence carries it, not become "".
      ...(c.supersedes !== null && c.supersedes !== undefined ? { supersedes: c.supersedes } : {}),
      signedArtifact: signedArtifact ?? new TextEncoder().encode(t.signed_artifact_jws),
      committer: c.committer,
      explanationDigest: new Uint8Array(Buffer.from(t.explanation_digest_hex, "hex")),
      explanation: protoExplanation(),
      ...extra,
    },
  };
  const client = SeamClient.connect("http://127.0.0.1:1"); // lazy transport; never dialed
  (client as unknown as { getCommitmentProof: () => Promise<typeof proof> }).getCommitmentProof =
    async () => proof;
  return client;
}

// #1687: verifyDecision checks the sealed voter records come from the decision's own session, so the id
// names the vector's (`dec:{tenant}:{session}` of its voter record).
const DECISION_ID = "dec:acme:s-conformance-0000000";

test("verifyDecision: a decision id naming another session, or no session, resolves to false", async () => {
  const issuer = vectors.tct.issuer_aid as string;
  for (const id of ["dec:acme:s-other-0000000000000", "dec:other:s-conformance-0000000", "dec-1"])
    assert.equal(await clientWithProof(issuer).verifyDecision(id, issuer), false, id);
});

test("verifyDecision: a served v4 commitment (committer + explanation + digest) verifies", async () => {
  const issuer = vectors.tct.issuer_aid as string;
  assert.equal(await clientWithProof(issuer).verifyDecision(DECISION_ID, issuer), true);
  // Unset published digest (empty bytes) = "not published": the entries alone still bind field 8.
  assert.equal(
    await clientWithProof(issuer, undefined, undefined, { explanationDigest: new Uint8Array() }).verifyDecision(
      DECISION_ID,
      issuer,
    ),
    true,
  );
});

test("verifyDecision: explanation entries that disagree with the published digest resolve to false", async () => {
  const issuer = vectors.tct.issuer_aid as string;
  const tampered = protoExplanation();
  tampered[2] = { ...tampered[2], reason: "no reason" };
  for (const [name, extra] of [
    ["tampered entry", { explanation: tampered }],
    // The proto cannot say "entries not served": an empty list is taken as zero entries.
    ["entries withheld", { explanation: [] }],
    ["unspecified kind", { explanation: [{ ...protoExplanation()[0], kind: ExplanationKind.UNSPECIFIED }] }],
    // #1687: an UNSPECIFIED method is never sealed, and a content digest is exactly 32 bytes.
    ["unspecified voter method", {
      explanation: protoExplanation().map((e, i) =>
        i === 2 ? { ...e, voterVerification: { ...e.voterVerification, method: VoterVerification.UNSPECIFIED } } : e),
    }],
    ["31-byte voter content digest", {
      explanation: protoExplanation().map((e, i) =>
        i === 2 ? { ...e, voterVerification: { ...e.voterVerification, contentDigest: new Uint8Array(31) } } : e),
    }],
    ["voter record withheld", {
      explanation: protoExplanation().map((e, i) => (i === 2 ? { ...e, voterVerification: undefined } : e)),
    }],
    ["committer changed", { committer: "aid:pubkey:ed25519:" + "B".repeat(43) }],
  ] as [string, Record<string, unknown>][]) {
    assert.equal(
      await clientWithProof(issuer, undefined, undefined, extra).verifyDecision(DECISION_ID, issuer),
      false,
      name,
    );
  }
});

test("verifyDecision: swapped issuer key rejects with a DISTINCT IssuerMismatchError, not a bland false", async () => {
  const serverIssuer = vectors.tct.issuer_aid as string;
  const pinned = "aid:pubkey:ed25519:" + "A".repeat(43); // pinned out of band
  const client = clientWithProof(serverIssuer);

  await assert.rejects(client.verifyDecision(DECISION_ID, pinned), (err: unknown) => {
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
  assert.equal(await client.verifyDecision(DECISION_ID, issuer), false);
});

test("verifyDecision: non-UTF-8 signedArtifact throws rather than decoding lossily to a bland false", async () => {
  // Mirrors the Python SDK, where `c.signed_artifact.decode()` raises `UnicodeDecodeError` uncaught.
  // A corrupted artifact must be distinguishable from an ordinary invalid decision, not silently folded
  // into `false` by a lossy decode (which would replace the bad bytes with U+FFFD and just fail the TCT
  // signature check for an unrelated reason).
  const issuer = vectors.tct.issuer_aid as string;
  const invalidUtf8 = new Uint8Array([0xff, 0xfe, 0xfd]);
  const client = clientWithProof(issuer, undefined, invalidUtf8);
  await assert.rejects(client.verifyDecision(DECISION_ID, issuer), TypeError);
});

test("verifyDecision: opts.sealedAtMs binds the TCT's iat to the chained seal second (S-4 evidence grade)", async () => {
  const issuer = vectors.tct.issuer_aid as string;
  const jws = vectors.tct.signed_artifact_jws as string;
  const iat = BigInt(JSON.parse(Buffer.from(jws.split(".")[1], "base64url").toString()).iat);
  const at = async (sealedAtMs: bigint | number) =>
    clientWithProof(issuer).verifyDecision(DECISION_ID, issuer, { sealedAtMs });
  assert.equal(await at(iat * 1000n), true, "exact second boundary");
  assert.equal(await at(iat * 1000n + 999n), true, "floor, not round");
  assert.equal(await at(Number(iat * 1000n)), true, "a safe-integer number is accepted");
  assert.equal(await at(iat * 1000n + 1000n), false, "iat 1 s before the seal second (backdated)");
  assert.equal(await at(iat * 1000n - 1n), false, "iat 1 s after the seal second");
  assert.equal(await at(-1n), false, "negative");
  assert.equal(await at(1.5), false, "not an integer");
});
