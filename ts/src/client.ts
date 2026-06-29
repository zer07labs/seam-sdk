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
   */
  async verifyDecision(decisionId: string, expectedIssuer: string): Promise<boolean> {
    const proof = await this.getCommitmentProof(decisionId);
    if (proof.issuerAid !== expectedIssuer) return false;
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
