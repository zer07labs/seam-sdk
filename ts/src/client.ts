// Ergonomic Seam client over the generated gRPC stubs (protobuf-es v2 + @connectrpc/connect) + the stock
// crypto shim. `runDecision` owns the full binding path (pinned-key PoP admission → decide → seal);
// `verifyDecision` verifies a sealed decision's rooted TCT locally — zero server trust beyond the fetch.

import { createClient, type Client } from "@connectrpc/connect";
import { createGrpcTransport } from "@connectrpc/connect-node";
import { ed25519 } from "@noble/curves/ed25519";

import {
  SeamAdmission,
  SeamCoordination,
  SeamTrust,
} from "../gen/seam/api/v1/seam_pb.js";
import { aidFromPubkey, buildPresentation, verifyTct } from "./crypto.js";

/**
 * The fetched proof's issuer AID does not match the issuer the caller pinned out of band.
 *
 * Thrown by {@link SeamClient.verifyDecision}. This is a **distinct security signal** — a malicious server
 * attempting to substitute its own issuer key — and must never be conflated with an ordinary
 * cryptographically-invalid decision (which resolves to `false`). Mirrors the Rust reference
 * (`ClientError::Crypto("issuer AID mismatch…")`).
 */
export class IssuerMismatchError extends Error {
  readonly name = "IssuerMismatchError";
  constructor(
    readonly proofIssuer: string,
    readonly expectedIssuer: string,
  ) {
    super(`issuer AID mismatch: proof carried ${JSON.stringify(proofIssuer)}, expected ${JSON.stringify(expectedIssuer)}`);
  }
}

export class Agent {
  constructor(public readonly seed: Uint8Array) {
    if (seed.length !== 32) throw new Error("agent seed must be 32 bytes");
  }
  get aid(): string {
    return aidFromPubkey(ed25519.getPublicKey(this.seed));
  }
}

export class SeamClient {
  private readonly admission: Client<typeof SeamAdmission>;
  private readonly coord: Client<typeof SeamCoordination>;
  private readonly trust: Client<typeof SeamTrust>;

  constructor(transport: ReturnType<typeof createGrpcTransport>) {
    this.admission = createClient(SeamAdmission, transport);
    this.coord = createClient(SeamCoordination, transport);
    this.trust = createClient(SeamTrust, transport);
  }

  /** Connect to a Seam gRPC endpoint (e.g. `http://127.0.0.1:8090`). */
  static connect(baseUrl: string): SeamClient {
    return new SeamClient(createGrpcTransport({ baseUrl }));
  }

  private async presentation(agent: Agent) {
    const ch = await this.admission.issueChallenge({});
    const body = buildPresentation(agent.seed, ch.receiverAid, ch.nonce, Date.now());
    return { presentationJson: new TextEncoder().encode(JSON.stringify(body)) };
  }

  /** Admit (the PoP handshake) → run a coordinated decision → seal, in one call. */
  async runDecision(
    agent: Agent,
    sessionId: string,
    participants: string[],
    votes: [string, string][],
  ) {
    return this.coord.runDecision({
      sessionId,
      participants,
      votes: votes.map(([a, value]) => ({ agent: a, value })),
      presentation: await this.presentation(agent),
    });
  }

  getDecision(decisionId: string) {
    return this.coord.getDecision({ decisionId });
  }
  replayDecision(decisionId: string) {
    return this.coord.replayDecision({ decisionId });
  }
  issuerAid() {
    return this.trust.issuerAid({}).then((r) => r.issuerAid);
  }
  getCommitmentProof(decisionId: string) {
    return this.coord.getCommitmentProof({ decisionId });
  }

  /**
   * Fetch a sealed decision's proof and verify its rooted TCT locally — zero server trust.
   * `expectedIssuer` is the issuer AID the caller pinned out of band (or TOFU-cached via `issuerAid()`);
   * the server-supplied `proof.issuerAid` must match, so a malicious server can't substitute its own key.
   *
   * Resolves `true` iff the rooted TCT is cryptographically valid for the pinned issuer, `false` for an
   * ordinary invalid decision. Rejects with {@link IssuerMismatchError} when the proof's issuer AID does
   * not match `expectedIssuer` — a distinct security signal (an attempted key substitution), never
   * downgraded to a bland `false`. Mirrors the Rust reference's distinct `ClientError::Crypto`.
   */
  async verifyDecision(decisionId: string, expectedIssuer: string): Promise<boolean> {
    const proof = await this.getCommitmentProof(decisionId);
    if (proof.issuerAid !== expectedIssuer)
      throw new IssuerMismatchError(proof.issuerAid, expectedIssuer);
    const c = proof.commitment;
    if (!c) return false;
    return verifyTct(expectedIssuer, new TextDecoder().decode(c.signedArtifact), {
      id: c.id,
      action: c.action,
      authority: c.authority,
      auth_method: c.authMethod,
      trust_basis: c.trustBasis,
      supersedes: c.supersedes || "",
    });
  }
}
