// Ergonomic Seam client over the generated gRPC stubs (protobuf-es v2 + @connectrpc/connect) + the stock
// crypto shim. `runDecision` owns the full binding path (pinned-key PoP admission → decide → seal);
// `verifyDecision` verifies a sealed decision's rooted TCT locally — zero server trust beyond the fetch.

import { createClient, type Client } from "@connectrpc/connect";
import { createGrpcTransport } from "@connectrpc/connect-node";
import { ed25519 } from "@noble/curves/ed25519";

import {
  SeamAdmission,
  SeamContext,
  SeamCoordination,
  SeamTrust,
  type Anchor,
  type Commitment,
  type ContextBinding,
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

/**
 * Multi-dimension session budget (enterprise 6.2). Every field is optional; an unset dimension is
 * unlimited. `messages`, when set, overrides the legacy `budget` count. `softPct` is the soft-warning
 * threshold as a percent of any limit (server default 80). `uint64` dimensions are `bigint`.
 */
export interface BudgetLimits {
  messages?: bigint;
  tokens?: bigint;
  costMicros?: bigint;
  wallMs?: bigint;
  softPct?: number;
}

/**
 * Caller-reported per-step resource spend (enterprise 6.2), debited to the session ledger. The protocol
 * cannot know what an agent runtime spent; the orchestrator reports it. Absent = zero.
 */
export interface StepUsage {
  tokens?: bigint;
  costMicros?: bigint;
}

export class SeamClient {
  private readonly admission: Client<typeof SeamAdmission>;
  private readonly coord: Client<typeof SeamCoordination>;
  private readonly trust: Client<typeof SeamTrust>;
  private readonly context: Client<typeof SeamContext>;

  constructor(transport: ReturnType<typeof createGrpcTransport>) {
    this.admission = createClient(SeamAdmission, transport);
    this.coord = createClient(SeamCoordination, transport);
    this.trust = createClient(SeamTrust, transport);
    this.context = createClient(SeamContext, transport);
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

  /**
   * Admit (the PoP handshake) → run a coordinated decision → seal, in one call.
   *
   * `features` are optional pre-decision request features (e.g. `{ amount_band: "high" }`) that the advisory
   * learning classifier keys `context_class` on. They **never** affect the sealed record — the decision seals
   * identically with or without them. Omitted ⇒ no features (non-breaking). Mirrors the Rust reference's
   * `run_decision_with_features`.
   */
  async runDecision(
    agent: Agent,
    sessionId: string,
    participants: string[],
    votes: [string, string][],
    features?: Record<string, string>,
  ) {
    return this.coord.runDecision({
      sessionId,
      participants,
      votes: votes.map(([a, value]) => ({ agent: a, value })),
      presentation: await this.presentation(agent),
      features: features ?? {},
    });
  }

  // ── Incremental session lifecycle (enterprise 6.2 budget surface) ─────────────────────────────
  // open → propose/vote → commit, with resume/cancel/expire/status. Budgets are first-class:
  // multi-dimension `limits` at open, per-step `usage`, and the dimension-raising resume. A step
  // whose `state === "Suspended"` is a hard budget breach (a resolved step, not a thrown error — the
  // R9 approver then resumes with a raise). A scope-floor denial throws a `PERMISSION_DENIED`.

  /** Admit (the PoP handshake) → open an incremental session. `budget` is the legacy message count
   * (0 ⇒ the server default 32); `limits` adds the other 6.2 dimensions. */
  async openSession(
    agent: Agent,
    opts: {
      sessionId: string;
      participants: string[];
      budget?: number;
      limits?: BudgetLimits;
      mode?: string;
    },
  ) {
    return this.coord.openSession({
      sessionId: opts.sessionId,
      participants: opts.participants,
      budget: opts.budget ?? 32,
      mode: opts.mode ?? "",
      presentation: await this.presentation(agent),
      limits: opts.limits,
    });
  }

  submitProposal(
    sessionId: string,
    proposer: string,
    proposalId: string,
    option: string,
    usage?: StepUsage,
  ) {
    return this.coord.submitProposal({ sessionId, proposer, proposalId, option, usage });
  }

  submitVote(
    sessionId: string,
    voter: string,
    proposalId: string,
    value: string,
    usage?: StepUsage,
  ) {
    return this.coord.submitVote({ sessionId, voter, proposalId, value, usage });
  }

  submitCommit(sessionId: string, commitmentId: string, action: string, usage?: StepUsage) {
    return this.coord.submitCommit({ sessionId, commitmentId, action, usage });
  }

  /** Resume a Suspended session (the R9 approver action). `raise` raises any budget dimension;
   * absent, `budget` raises the message count. */
  resumeSession(sessionId: string, opts?: { budget?: number; raise?: BudgetLimits }) {
    return this.coord.resumeSession({
      sessionId,
      budget: opts?.budget ?? 32,
      raise: opts?.raise,
    });
  }

  cancelSession(sessionId: string) {
    return this.coord.cancelSession({ sessionId });
  }
  expireSession(sessionId: string) {
    return this.coord.expireSession({ sessionId });
  }
  sessionStatus(sessionId: string) {
    return this.coord.sessionStatus({ sessionId });
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

  /** Report a delayed correctness outcome for a sealed decision (advisory, Plan R). The sealed record is
   * never mutated; this only emits a LEARNING_OUTCOME. Resolves whether it was recorded. */
  async reportOutcome(decisionId: string, correct: boolean, verifiedBy?: string): Promise<boolean> {
    return (await this.coord.reportOutcome({ decisionId, correct, verifiedBy })).recorded;
  }

  // ── Context binding (data plane) ──────────────────────────────────────────────────────────────

  /** Register context content at a `fidelity` (`Digest` | `Reference` | `Value`); resolves its content
   * ref (a `sha256:` ref or an `acdp://` remote id). */
  async registerContext(
    content: Uint8Array,
    fidelity: string,
    derivedFrom: string[] = [],
  ): Promise<string> {
    return (await this.context.registerContext({ content, fidelity, derivedFrom })).contentRef;
  }

  /** Resolve context refs to their bindings (fidelity, classification, lineage, version). */
  async resolveContext(refs: string[]): Promise<ContextBinding[]> {
    return (await this.context.resolveContext({ refs })).bindings;
  }

  // ── Trust / verification (data plane) ─────────────────────────────────────────────────────────

  /** Server-side verification of a rooted commitment. For zero-server-trust verification prefer
   * {@link verifyDecision}, which verifies locally against a pinned issuer. */
  async verifyCommitment(commitment: Commitment, signedArtifact: Uint8Array): Promise<boolean> {
    return (await this.trust.verifyCommitment({ commitment, signedArtifact })).valid;
  }

  /** Verify a counterparty's published audit-chain anchor (network mode). */
  async verifyPartyAnchor(partyId: string, anchor: Anchor): Promise<boolean> {
    return (await this.trust.verifyPartyAnchor({ partyId, anchor })).valid;
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
