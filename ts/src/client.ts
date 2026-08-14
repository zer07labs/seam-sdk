// Ergonomic Seam client over the generated gRPC stubs (protobuf-es v2 + @connectrpc/connect) + the stock
// crypto shim. `runDecision` owns the full binding path (pinned-key PoP admission → decide → seal);
// `verifyDecision` verifies a sealed decision's rooted TCT locally — zero server trust beyond the fetch.

import { createClient, type Client } from "@connectrpc/connect";
import { createGrpcTransport, Http2SessionManager } from "@connectrpc/connect-node";
import { ed25519 } from "@noble/curves/ed25519";

import {
  AuthorizeVerdict,
  SeamAdmission,
  SeamAuthorization,
  SeamContext,
  SeamCoordination,
  SeamTrust,
  type Anchor,
  type Commitment,
  type ContextBinding,
} from "../gen/seam/api/v1/seam_pb.js";
// ChainHeadAttestation moved to the canonical seam.event.v1 package.
import { type ChainHeadAttestation } from "../gen/seam/event/v1/seam_event_pb.js";
import {
  aidFromPubkey,
  buildPresentation,
  callSig,
  jcsCanonicalize,
  toolInputDigest,
  verifyTct,
} from "./crypto.js";
import {
  errorMappingInterceptor,
  ProtocolViolationError,
  UnauthenticatedError,
} from "./errors.js";

// `timeoutMs` is PER-RPC, not an overall budget for the call. Decided, not accidental — and it has a
// consequence callers must size around, so it is stated here rather than discovered.
//
// Every unary method takes `{ timeoutMs }` and propagates it as the deadline on each wire call it
// makes. Most methods make exactly one, so per-RPC and overall coincide. Three do not:
//
//   * `authorize` may make up to SIX: an admit (challenge + Admit = 2) when the ticket is cold or
//     stale, the Authorize itself (1), and — on `UNAUTHENTICATED` — a refresh (another 2) plus one
//     retried Authorize (1). So the worst case is 6x the value passed, not the 1x it reads as.
//   * `runDecision` and `openSession` each begin with the challenge→Admit handshake (3x).
//
// A caller that needs a hard overall bound must impose its own outer clock (the adapters' `Gate`
// does exactly that). The SDK never retries beyond the single ticket refresh — adapters own retry
// semantics. A deadline breach surfaces as a typed `DeadlineExceededError`, distinct from a DENY
// verdict. Mirrors the Python SDK's `DEFAULT_TIMEOUT_S = 2.0`.
export const DEFAULT_TIMEOUT_MS = 2_000;

/** Per-call options accepted by every unary method. `timeoutMs` overrides the plane's default
 * deadline (`DEFAULT_TIMEOUT_MS` on the data plane, `DEFAULT_ADMIN_TIMEOUT_MS` on the management
 * plane); it is a PER-RPC deadline — see the note on {@link DEFAULT_TIMEOUT_MS}. */
export interface UnaryCallOptions {
  timeoutMs?: number;
}

const call = (opts?: UnaryCallOptions) => ({
  timeoutMs: opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS,
});

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

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
 * `Authorize` returned a verdict this SDK version does not recognize (including the proto zero value
 * `AUTHORIZE_VERDICT_UNSPECIFIED`, which a correct server never emits). Growth policy (normative, from
 * the proto): an unrecognized verdict MUST route to the adapter's FailPolicy — never to an implicit
 * allow. Throwing a typed error is how this SDK enforces that.
 */
export class UnknownVerdictError extends Error {
  readonly name = "UnknownVerdictError";
  constructor(
    readonly rawValue: number,
    readonly authorizeId: string,
  ) {
    super(
      `unrecognized AuthorizeVerdict value ${rawValue} (authorize_id=${authorizeId || "<none>"}); treat as failure, never allow`,
    );
  }
}

/** One advisory verdict. `transformedInput` is the guard-redacted canonical JSON, set iff
 * `verdict === "TRANSFORM"`. `authorizeId` correlates the advisory event — NOT a decisionId. */
export interface AuthorizeResult {
  verdict: "ALLOW" | "DENY" | "TRANSFORM" | "ESCALATE";
  reason: string;
  transformedInput?: Uint8Array;
  authorizeId: string;
  policyVersion: string;
  allowed: boolean;
}

const VERDICT_NAMES: Partial<Record<AuthorizeVerdict, AuthorizeResult["verdict"]>> = {
  [AuthorizeVerdict.ALLOW]: "ALLOW",
  [AuthorizeVerdict.DENY]: "DENY",
  [AuthorizeVerdict.TRANSFORM]: "TRANSFORM",
  [AuthorizeVerdict.ESCALATE]: "ESCALATE",
};

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
  private readonly authz: Client<typeof SeamAuthorization>;
  // Admission-ticket lifecycle (advisory Authorize path), keyed by agent AID: admit-once, refreshed
  // at 80% TTL, retried exactly once on UNAUTHENTICATED. `admitting` serializes concurrent admits so
  // parallel authorize() calls share one handshake instead of racing N of them.
  private readonly tickets = new Map<string, { ticket: Uint8Array; refreshAtMs: number }>();
  private readonly admitting = new Map<string, Promise<Uint8Array>>();

  // The HTTP/2 session this client owns (set by `connect`), so `close()` can tear it down. A client
  // constructed over an externally-supplied transport owns no session and `close()` is a no-op.
  private readonly session?: Http2SessionManager;

  constructor(
    transport: ReturnType<typeof createGrpcTransport>,
    session?: Http2SessionManager,
  ) {
    this.admission = createClient(SeamAdmission, transport);
    this.coord = createClient(SeamCoordination, transport);
    this.trust = createClient(SeamTrust, transport);
    this.context = createClient(SeamContext, transport);
    this.authz = createClient(SeamAuthorization, transport);
    this.session = session;
  }

  /** Connect to a Seam gRPC endpoint (e.g. `http://127.0.0.1:8090`, or `https://…` for TLS). */
  static connect(baseUrl: string): SeamClient {
    // An explicit session manager (rather than the transport's internal one) is the only public
    // path connect-node offers to tear the HTTP/2 session down — it is what makes close() real.
    const session = new Http2SessionManager(baseUrl);
    return new SeamClient(
      createGrpcTransport({
        baseUrl,
        interceptors: [errorMappingInterceptor()],
        sessionManager: session,
      }),
      session,
    );
  }

  /**
   * Close the underlying HTTP/2 session (connection + any open streams), releasing its socket and
   * keepalive timers. A long-lived worker that rebuilds its client on reconnect would otherwise
   * leak one connection per rebuild. Mirrors the Python SDK's `close()`.
   *
   * Idempotent — a repeated close is a no-op. Limitation: a client constructed directly over an
   * externally-created transport (rather than via {@link SeamClient.connect}) has no handle on that
   * transport's internal session (connect-node exposes none), so `close()` is a documented no-op
   * there; the transport's own idle timeout eventually reaps the connection.
   */
  close(): void {
    this.session?.abort();
  }

  private async presentation(agent: Agent, opts?: UnaryCallOptions) {
    const ch = await this.admission.issueChallenge({}, call(opts));
    const body = buildPresentation(agent.seed, ch.receiverAid, ch.nonce, Date.now());
    return { presentationJson: new TextEncoder().encode(JSON.stringify(body)) };
  }

  // ── Advisory authorization (1-RTT, unsealed) ──────────────────────────────────────────────────

  /** Run the challenge→`Admit` handshake now and cache the admission ticket. {@link authorize} calls
   * this lazily; an explicit `admit` only front-loads the 2-RTT handshake (e.g. at worker startup). */
  async admit(agent: Agent, opts?: UnaryCallOptions): Promise<Uint8Array> {
    // Coalesce concurrent admits per agent: everyone awaits the one in-flight handshake.
    const aid = agent.aid;
    const inFlight = this.admitting.get(aid);
    if (inFlight) return inFlight;
    const p = (async () => {
      const t = await this.admission.admit(await this.presentation(agent, opts), call(opts));
      const nowMs = Date.now();
      const ttlMs = Number(t.expiresAtMs) - nowMs;
      if (ttlMs > 0 && t.ticket.length > 0) {
        this.tickets.set(aid, { ticket: t.ticket, refreshAtMs: nowMs + ttlMs * 0.8 });
      } else {
        this.tickets.delete(aid); // never cache an expired/empty ticket
      }
      return t.ticket;
    })();
    this.admitting.set(aid, p);
    try {
      return await p;
    } finally {
      this.admitting.delete(aid);
    }
  }

  /**
   * Ask one advisory `(toolName, toolInput) -> verdict` question — 1 RTT steady-state, seals nothing.
   *
   * `toolInput` is the tool call's input as a plain JSON-able value; it is JCS-canonicalized and
   * digested here, and the per-call `callSig` binds the ticket to that exact digest.
   * `digestOnly: true` sends the digest without the raw input (audit-grade; no guard scan or
   * TRANSFORM). Ticket lifecycle: lazy admit, cached, refreshed at 80% TTL, retried exactly once on
   * `UNAUTHENTICATED`. An unknown verdict throws {@link UnknownVerdictError} — never an implicit
   * allow. An old runtime without the Authorize service throws `UnimplementedError`; adapters
   * typically degrade to their Observe tier on it.
   */
  async authorize(
    agent: Agent,
    toolName: string,
    toolInput?: unknown,
    opts?: {
      digestOnly?: boolean;
      features?: Record<string, string>;
      sessionId?: string;
      subject?: string;
      agentId?: string;
      clientRequestId?: string;
      timeoutMs?: number;
    },
  ): Promise<AuthorizeResult> {
    const canonical = jcsCanonicalize(toolInput ?? {});
    const digest = toolInputDigest(canonical);
    const request = (ticket: Uint8Array) => ({
      ticket,
      toolName,
      toolInputDigest: digest,
      toolInput: opts?.digestOnly ? new Uint8Array(0) : canonical,
      // The signed toolName/agentId must be the WIRE values assembled here — the runtime verifies
      // them verbatim against the request, so any divergence is a rejected call.
      callSig: callSig(agent.seed, ticket, digest, toolName, opts?.agentId ?? ""),
      features: opts?.features ?? {},
      sessionId: opts?.sessionId ?? "",
      subject: opts?.subject ?? "",
      agentId: opts?.agentId ?? "",
      clientRequestId: opts?.clientRequestId ?? "",
    });

    const cached = this.tickets.get(agent.aid);
    let ticket =
      cached && Date.now() < cached.refreshAtMs ? cached.ticket : await this.admit(agent, opts);
    let resp;
    try {
      resp = await this.authz.authorize(request(ticket), call(opts));
    } catch (e) {
      if (!(e instanceof UnauthenticatedError)) throw e;
      // Expired/rejected ticket: refresh once, retry once. A second failure propagates typed.
      ticket = await this.refreshTicket(agent, ticket, opts);
      resp = await this.authz.authorize(request(ticket), call(opts));
    }
    const verdict = VERDICT_NAMES[resp.verdict];
    if (!verdict) throw new UnknownVerdictError(resp.verdict, resp.authorizeId);
    if (verdict === "TRANSFORM" && resp.transformedInput.length === 0)
      // A TRANSFORM that carries no rewrite is a protocol violation; surfacing it as a result would
      // hand a truthiness-gating caller the ORIGINAL (unredacted) input to execute.
      throw new ProtocolViolationError(
        `TRANSFORM verdict without transformed_input (authorize_id=${resp.authorizeId || "<none>"}); treat as failure, never execute the original input`,
        resp.authorizeId,
      );
    return {
      verdict,
      reason: resp.reason,
      transformedInput: verdict === "TRANSFORM" ? resp.transformedInput : undefined,
      authorizeId: resp.authorizeId,
      policyVersion: resp.policyVersion,
      allowed: verdict === "ALLOW",
    };
  }

  /**
   * Re-admit after an `UNAUTHENTICATED`, coalescing concurrent refreshes to ONE.
   *
   * The re-check is the whole point (mirrors Python's `_refresh_ticket`). Unconditionally
   * invalidating and re-admitting meant N concurrent callers produced N re-admits: each one threw
   * away the ticket the previous caller had just minted, so every caller admitted for itself. Cold
   * start already coalesced correctly (they all find an empty cache and `admit`'s in-flight map
   * serializes them) — which is what made this easy to miss.
   *
   * It matters under mass revocation, which is precisely when the admission endpoint is already the
   * most loaded thing in the system: every in-flight call fails at once and, before this, every one
   * of them stampeded it.
   *
   * So: if the cache now holds a fresh ticket that is NOT the one we failed on, some other caller
   * already refreshed and we adopt theirs. Only the caller still holding the dead ticket (or
   * finding none) pays for the round trip — and even then `admit`'s coalescing bounds the fan-out
   * to one in-flight handshake. When the adopted ticket is ALSO dead (a revocation that killed
   * every outstanding ticket), the adopter's single retry fails typed — there is no second refresh,
   * because the retry in {@link authorize} is deliberately one-shot. That trade is the right one:
   * the alternative re-opens the stampede on exactly the failure that causes it.
   */
  private async refreshTicket(
    agent: Agent,
    failed: Uint8Array,
    opts?: UnaryCallOptions,
  ): Promise<Uint8Array> {
    const cached = this.tickets.get(agent.aid);
    if (cached && Date.now() < cached.refreshAtMs && !bytesEqual(cached.ticket, failed)) {
      return cached.ticket; // a concurrent caller already refreshed — adopt, never stampede
    }
    this.tickets.delete(agent.aid);
    return this.admit(agent, opts); // coalesces with any in-flight handshake
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
    onBehalfOf?: string[],
    opts?: UnaryCallOptions,
  ) {
    return this.coord.runDecision(
      {
        sessionId,
        participants,
        votes: votes.map(([a, value]) => ({ agent: a, value })),
        presentation: await this.presentation(agent, opts),
        features: features ?? {},
        // Phase 0b: end-user data subjects. The engine never reads them; the kernel folds each into
        // the sealed record's participation as an inert `subject:<i>` declaration (GDPR-erasure join).
        onBehalfOf: onBehalfOf ?? [],
      },
      call(opts),
    );
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
      onBehalfOf?: string[];
      timeoutMs?: number;
    },
  ) {
    return this.coord.openSession(
      {
        sessionId: opts.sessionId,
        participants: opts.participants,
        // 0 ⇒ the server default (32) — the proto owns the default, the client never re-states it.
        budget: opts.budget ?? 0,
        mode: opts.mode ?? "",
        presentation: await this.presentation(agent, opts),
        limits: opts.limits,
        onBehalfOf: opts.onBehalfOf ?? [],
      },
      call(opts),
    );
  }

  submitProposal(
    sessionId: string,
    proposer: string,
    proposalId: string,
    option: string,
    usage?: StepUsage,
    opts?: UnaryCallOptions,
  ) {
    return this.coord.submitProposal(
      { sessionId, proposer, proposalId, option, usage },
      call(opts),
    );
  }

  submitVote(
    sessionId: string,
    voter: string,
    proposalId: string,
    value: string,
    usage?: StepUsage,
    opts?: UnaryCallOptions,
  ) {
    return this.coord.submitVote({ sessionId, voter, proposalId, value, usage }, call(opts));
  }

  submitCommit(
    sessionId: string,
    commitmentId: string,
    action: string,
    usage?: StepUsage,
    opts?: UnaryCallOptions,
  ) {
    return this.coord.submitCommit({ sessionId, commitmentId, action, usage }, call(opts));
  }

  /** @deprecated Resume moved to the **management** plane (rt-D): this data-plane RPC now returns
   * `PERMISSION_DENIED` ("call SeamAdmin.ResumeSession"). Use {@link SeamAdminClient.resumeSession} (the R9
   * approver action) with an operator token instead. Retained only so an old caller gets a clear error. */
  resumeSession(
    sessionId: string,
    opts?: { budget?: number; raise?: BudgetLimits; timeoutMs?: number },
  ) {
    return this.coord.resumeSession(
      {
        sessionId,
        budget: opts?.budget ?? 0,
        raise: opts?.raise,
      },
      call(opts),
    );
  }

  cancelSession(sessionId: string, opts?: UnaryCallOptions) {
    return this.coord.cancelSession({ sessionId }, call(opts));
  }
  expireSession(sessionId: string, opts?: UnaryCallOptions) {
    return this.coord.expireSession({ sessionId }, call(opts));
  }
  sessionStatus(sessionId: string, opts?: UnaryCallOptions) {
    return this.coord.sessionStatus({ sessionId }, call(opts));
  }

  getDecision(decisionId: string, opts?: UnaryCallOptions) {
    return this.coord.getDecision({ decisionId }, call(opts));
  }
  replayDecision(decisionId: string, opts?: UnaryCallOptions) {
    return this.coord.replayDecision({ decisionId }, call(opts));
  }
  issuerAid(opts?: UnaryCallOptions) {
    return this.trust.issuerAid({}, call(opts)).then((r) => r.issuerAid);
  }
  getCommitmentProof(decisionId: string, opts?: UnaryCallOptions) {
    return this.coord.getCommitmentProof({ decisionId }, call(opts));
  }

  /** Report a delayed correctness outcome for a sealed decision (advisory, Plan R). The sealed record is
   * never mutated; this only emits a LEARNING_OUTCOME. Resolves whether it was recorded. */
  async reportOutcome(
    decisionId: string,
    correct: boolean,
    verifiedBy?: string,
    opts?: UnaryCallOptions,
  ): Promise<boolean> {
    return (await this.coord.reportOutcome({ decisionId, correct, verifiedBy }, call(opts)))
      .recorded;
  }

  // ── Context binding (data plane) ──────────────────────────────────────────────────────────────

  /** Register context content at a `fidelity` (`Digest` | `Reference` | `Value`); resolves its content
   * ref (a `sha256:` ref or an `acdp://` remote id). */
  async registerContext(
    content: Uint8Array,
    fidelity: string,
    derivedFrom: string[] = [],
    opts?: UnaryCallOptions,
  ): Promise<string> {
    return (await this.context.registerContext({ content, fidelity, derivedFrom }, call(opts)))
      .contentRef;
  }

  /** Resolve context refs to their bindings (fidelity, classification, lineage, version). */
  async resolveContext(refs: string[], opts?: UnaryCallOptions): Promise<ContextBinding[]> {
    return (await this.context.resolveContext({ refs }, call(opts))).bindings;
  }

  // ── Trust / verification (data plane) ─────────────────────────────────────────────────────────

  /** Server-side verification of a rooted commitment. For zero-server-trust verification prefer
   * {@link verifyDecision}, which verifies locally against a pinned issuer. */
  async verifyCommitment(
    commitment: Commitment,
    signedArtifact: Uint8Array,
    opts?: UnaryCallOptions,
  ): Promise<boolean> {
    return (await this.trust.verifyCommitment({ commitment, signedArtifact }, call(opts))).valid;
  }

  /** Verify a counterparty's published audit-chain anchor (network mode). */
  async verifyPartyAnchor(
    partyId: string,
    anchor: Anchor,
    opts?: UnaryCallOptions,
  ): Promise<boolean> {
    return (await this.trust.verifyPartyAnchor({ partyId, anchor }, call(opts))).valid;
  }

  /** Verify a counterparty's signed chain-head attestation against the registry-pinned key (A14 network
   * mode). Resolves `true` iff the attestation's Ed25519 signature checks out against the pubkey
   * registered for `partyId`; `false` for an unknown party or any tamper (a boolean verdict, never a
   * rejection) — mirroring {@link verifyPartyAnchor}. */
  async verifyPartyAttestation(
    partyId: string,
    attestation: ChainHeadAttestation,
    opts?: UnaryCallOptions,
  ): Promise<boolean> {
    return (await this.trust.verifyPartyAttestation({ partyId, attestation }, call(opts)))
      .valid;
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
  async verifyDecision(
    decisionId: string,
    expectedIssuer: string,
    opts?: UnaryCallOptions,
  ): Promise<boolean> {
    const proof = await this.getCommitmentProof(decisionId, opts);
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
