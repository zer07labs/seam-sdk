// Ergonomic Seam client over the generated gRPC stubs (protobuf-es v2 + @connectrpc/connect) + the stock
// crypto shim. `runDecision` owns the full binding path (pinned-key PoP admission → decide → seal);
// `verifyDecision` verifies a sealed decision's rooted TCT locally — zero server trust beyond the fetch.

import { createClient, type Client } from "@connectrpc/connect";
import { createGrpcTransport, Http2SessionManager } from "@connectrpc/connect-node";
import { ed25519 } from "@noble/curves/ed25519";

import {
  AuthorizeVerdict,
  BallotChoice,
  CollectiveVerdict,
  SeamAdmission,
  SeamAuthorization,
  SeamContext,
  SeamCoordination,
  SeamTrust,
  type Anchor,
  type Commitment,
  type ContextBinding,
  type DecisionResponse,
  type SessionStep,
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

/** Range-check a `uint32` at the client boundary.
 *
 * protobuf-es coerces silently here in a way Python's does not: a negative or fractional `number`
 * assigned to a `uint32` field marshals to *some* value rather than throwing, so an off-by-one in
 * `requiredApprovals` would reach the server as a different quorum than the caller asked for. Fail
 * here instead, naming the SDK argument. */
function u32(value: number, field: string): number {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new RangeError(
      `${field} must be an integer in a uint32 (0..4294967295), got ${value}`,
    );
  }
  return value;
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

/**
 * A `collectiveOutcome` — on a `DecisionResponse` **or** a `SessionStep` — carried a
 * `CollectiveVerdict` this SDK version does not recognize, including the proto zero value
 * `COLLECTIVE_VERDICT_UNSPECIFIED`, which a correct server never emits.
 *
 * `decisionId` may be `""`: it is required on `DecisionResponse` but `optional` on `SessionStep`,
 * and an absent one renders as `<none>` rather than blocking the throw.
 *
 * Growth policy (normative, copied verbatim into the proto from `AuthorizeVerdict`'s): any value a
 * client does not recognize, INCLUDING `COLLECTIVE_VERDICT_UNSPECIFIED`, MUST route to the adapter's
 * FailPolicy, never to allow. Throwing is how this SDK enforces that — the same discipline
 * {@link UnknownVerdictError} applies on the Authorize path, and for the same reason: a returned
 * value has a truthiness that can go the wrong way, and a thrown one does not.
 */
export class UnknownCollectiveVerdictError extends Error {
  readonly name = "UnknownCollectiveVerdictError";
  constructor(
    readonly rawValue: number,
    readonly decisionId: string,
  ) {
    super(
      `unrecognized CollectiveVerdict value ${rawValue} (decision_id=${decisionId || "<none>"}); treat as failure, never allow`,
    );
  }
}

/** The closed verdict set this SDK version understands. Anything outside it — including the zero
 * value — is a failure per the growth policy above. */
// NOTE the bare names. The proto deliberately PREFIXES these values (`COLLECTIVE_VERDICT_APPROVED`)
// because proto3 scopes enum values at the FILE level, so bare `APPROVED`/`DECLINED` would collide
// with `AuthorizeVerdict`'s vocabulary. protobuf-es strips that prefix back off per-enum, so in
// TypeScript they are `CollectiveVerdict.APPROVED` — the collision the prefix guards against cannot
// occur here, since each enum is its own object.
const COLLECTIVE_VERDICT_NAMES: Record<number, CollectiveOutcome["verdict"]> = {
  [CollectiveVerdict.APPROVED]: "APPROVED",
  [CollectiveVerdict.DECLINED]: "DECLINED",
  [CollectiveVerdict.SPLIT]: "SPLIT",
  [CollectiveVerdict.ESCALATED]: "ESCALATED",
  [CollectiveVerdict.NO_VOTES]: "NO_VOTES",
};

/** The runtime's own judgment of what a panel decided, as it derived it from the actual tally.
 *
 * `verdict` is the judgment and the only field to branch on. The counters are OBSERVABILITY — they
 * are here so a caller can *show* the tally, not so it can recompute the verdict from them. The
 * proto is explicit that a client-side tally is self-grading and unverifiable, which is the whole
 * reason `verdict` exists as a field. */
export interface CollectiveOutcome {
  verdict: "APPROVED" | "DECLINED" | "SPLIT" | "ESCALATED" | "NO_VOTES";
  approveCount: number;
  /** REJECT and BLOCK both, matching the runtime's own fold. */
  rejectCount: number;
  /** Includes ESCALATE / REVIEW. */
  abstainCount: number;
  /** Not redundant with the vote counts — MACP's `unanimous` algorithm uses DECLARED participants
   * as its denominator, so a panel of 3 with 2 APPROVE votes is denied for not all having voted. */
  declaredParticipantCount: number;
  statedValueContradictedTally: boolean;
}

/** Decode `resp.collectiveOutcome`, fail-closed. Accepts a `DecisionResponse` **or** a `SessionStep`.
 *
 * Returns `undefined` **iff the field is absent** — the runtime did not carry one on this response
 * (an older runtime, or a read verb that per the proto never does). That is not "the panel decided
 * nothing"; it is "this response does not answer the question", and the caller must decide what
 * that means for its own fail policy rather than being handed a value.
 *
 * **On a `SessionStep`, absent is the common case and does not mean "not supported".** The field is
 * present ONLY on the step that applied the commit envelope and sealed the session; it is absent on
 * every open/propose/vote/ballot step, and also on the sealed-idempotent replay and the
 * pending-commitment seal retry (`seam.api.v1`, `SessionStep.collective_outcome` field 4 — cited by
 * field, not by line: the proto lives in another repository that nothing here tracks or gates).
 * Read `undefined` from a non-terminal step as "not yet decided", never as a missing feature.
 *
 * One decoder, two message types, on purpose: the hazard being guarded is a property of the FIELD —
 * `optional` presence over an open enum whose zero value is UNSPECIFIED — not of the message that
 * carries it. A second implementation per message type is a second place for the fail-open inversion
 * to reappear.
 *
 * Throws {@link UnknownCollectiveVerdictError} for `COLLECTIVE_VERDICT_UNSPECIFIED` or any value
 * this SDK version does not know — never an implicit allow.
 *
 * Why this helper exists at all: `collectiveOutcome` is `optional`, and proto3 makes `0` the silent
 * default, so reading `resp.collectiveOutcome?.verdict` on an absent field is indistinguishable
 * from UNSPECIFIED — and the natural negative test (`verdict !== DECLINED`) allows on every
 * unrecognized value, which is the exact inversion the growth policy forbids. */
export function collectiveOutcomeOf(
  resp: DecisionResponse | SessionStep,
): CollectiveOutcome | undefined {
  const outcome = resp.collectiveOutcome;
  if (outcome === undefined) return undefined;

  const verdict = COLLECTIVE_VERDICT_NAMES[outcome.verdict];
  // `decisionId` is required on DecisionResponse but `optional` on SessionStep, so the union
  // narrows it to `string | undefined`. Coalesce rather than widen the error's field: the message
  // already renders an empty id as `<none>` (see the constructor above).
  if (!verdict)
    throw new UnknownCollectiveVerdictError(outcome.verdict, resp.decisionId ?? "");

  return {
    verdict,
    approveCount: outcome.approveCount,
    rejectCount: outcome.rejectCount,
    abstainCount: outcome.abstainCount,
    declaredParticipantCount: outcome.declaredParticipantCount,
    statedValueContradictedTally: outcome.statedValueContradictedTally,
  };
}

/** The runtime's statement about whether a policy gated this decision.
 *
 * Both fields are `readonly`, for the reason the Python twin is a frozen dataclass: this is the
 * runtime's claim, and a caller should not edit it and pass it on as though it came from the wire.
 * That buys strictly less here than it does there, and saying so is the point of writing it down —
 * `readonly` is erased at compile time, so `(pe as { enforced: boolean }).enforced = true` succeeds
 * at runtime where Python raises `FrozenInstanceError`. It stops the accident, not the determined.
 *
 * Deliberately two fields and no convenience booleans. `enforced` is already the boolean, and the
 * unsafe-to-guess case is already expressed by {@link policyEnforcementOf} returning `undefined`
 * rather than an instance. An `allowed`-style twin would be a second falsiness that can go the wrong
 * way — the same argument {@link CollectiveOutcome} makes for having no `declined` counterpart.
 *
 * Declared on both sides: this name and the generated `pb.PolicyEnforcement` are different types,
 * and at the package root this one is what you get. The wire message stays reachable as
 * `pb.PolicyEnforcement`; see the dual-declaration note at the top of `index.ts` for why, and for
 * the hazard that runs opposite to intuition. */
export interface PolicyEnforcement {
  /** true iff a real policy definition gated this commitment. */
  readonly enforced: boolean;
  /** `undefined` **iff the id is absent**, never `""`. `policy_id` has explicit presence of its own,
   * so an explicitly-encoded empty string is a different answer from an unset one; collapsing them
   * would reintroduce this helper's own bug one level down, inside the fix for it. It is always a
   * present property, so `"policyId" in pe` is never how to tell — the value is, one way only. */
  readonly policyId: string | undefined;
}

/** Decode `resp.policyEnforcement`. Accepts a `DecisionResponse` **or** a `SessionStep`.
 *
 * Returns `undefined` **iff the field is absent**, and an object otherwise — including when that
 * object carries `enforced: false`. Three states, and the middle one is the one that gets lost:
 *
 * | state                      | `resp.policyEnforcement` | `…?.enforced` | this helper |
 * | -------------------------- | ------------------------ | ------------- | ----------- |
 * | absent                     | `undefined`              | `undefined`   | `undefined` |
 * | present, `enforced: false` | an object                | `false`       | an object   |
 * | present, `enforced: true`  | an object                | `true`        | an object   |
 *
 * **The hazard is not the same shape as the Python twin's, and which one it is matters.** In
 * `seam_sdk._policy` the first two rows are *value-identical*: `resp.policy_enforcement` compares
 * equal across them, and only `HasField` separates them. protobuf-es models presence natively, so in
 * TypeScript those rows are already distinguishable by value. What collapses them is the read a
 * caller actually writes — `undefined` and `false` are different values with the *same falsiness*:
 *
 *     if (!resp.policyEnforcement?.enforced) { … }   // WRONG: true for BOTH of the first two rows
 *
 * which reads "the runtime never told me" as "the runtime told me none was enforced" — the fail-open
 * direction, reached by the idiomatic spelling rather than by a mistake. What this helper returns is
 * the one shape whose falsiness cannot answer the unanswered question: absent is `undefined`, and
 * every other state is a truthy object whose `.enforced` the caller must then actually read.
 *
 * **On a `SessionStep`, absent is the common case** — not an error, and not a missing feature. The
 * field is populated on exactly three steps: the **commit-terminal** step; the **sealed-idempotent
 * replay** (a resubmit against an already-sealed session, re-reporting a seal this call did not
 * perform); and the **pending-commitment seal retry**. It is absent on every non-terminal step —
 * open, propose, vote, ballot — on **both suspended shapes** (awaiting an approver, and the budget
 * breach), and on the **expiry seal**.
 *
 * Two things in that list contradict the proto's own comment for this field (`seam.api.v1`,
 * `SessionStep.policy_enforcement` field 3 — cited by field, not by line: the proto lives in another
 * repository that nothing here tracks or gates). It is **not** "only on a step that resolves the
 * session via commit": the sealed-idempotent replay resolves nothing and carries the field anyway.
 * And **presence is not tied to `decisionId`**, whose terminal-only presence the proto comment
 * offers as the analogy — the expiry seal is the counterexample, carrying a `decisionId` with no
 * `policyEnforcement`, so a reader who follows the analogy infers the opposite of the truth.
 *
 * The three sites are enumerated rather than generalised, deliberately: every short general rule
 * anyone has written for this field has been wrong, including both of the proto comment's. The
 * enumeration and the matrix behind it are measured in **zer07labs/seam-runtime#526**, which is the
 * citation this carries — `PROGRESS.md`'s clean-room constraint forbids reading that repository's
 * Rust sources, and the issue publishes the matrix in its own body. It describes the runtime as
 * measured at the time of writing, is not enforced by anything here, and is not a contract the SDK
 * can check: read it as orientation for interpreting an `undefined`, never as a guarantee to branch
 * on. This block and the Python module docstring are deliberately the same content in two places, so
 * neither language is the authoritative copy of it.
 *
 * One decoder, two message types, on purpose: the hazard is a property of the **field** — explicit
 * presence over a message whose absent form is falsy — not of the message carrying it. Field numbers
 * differ (7 on `DecisionResponse`, 3 on `SessionStep`) and both have explicit presence, so the one
 * `undefined` check covers both; a second implementation per carrier would be a second place for the
 * same inversion to reappear.
 *
 * Never throws. Unlike {@link collectiveOutcomeOf} there is no enum here and no growth policy, so
 * there is no unrecognized value to fail closed on — the only distinction to preserve is
 * present-versus-absent. The Python twin has to qualify this (its `HasField` raises on a message
 * type lacking the field); here the union is enforced by the compiler and a non-carrier is a
 * compile error rather than a runtime one. */
export function policyEnforcementOf(
  resp: DecisionResponse | SessionStep,
): PolicyEnforcement | undefined {
  const enforcement = resp.policyEnforcement;
  if (enforcement === undefined) return undefined;

  // A fresh object, not `enforcement` itself: the generated message carries a `$typeName` brand, and
  // handing it back would put the stub tree in this function's public contract. `policyId` passes
  // straight through because protobuf-es already models its explicit presence as `string |
  // undefined` — this is the line where the Python twin needs a `HasField` and this one does not.
  return {
    enforced: enforcement.enforced,
    policyId: enforcement.policyId,
  };
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

/** Return the canonical bytes for exactly one of `toolInput` / `canonical`.
 *
 * Passing both is an error rather than a precedence rule. Silently preferring one would be the same
 * shape of failure this parameter exists to remove: a disagreement resolved quietly, in a signed
 * digest, where nobody looks (seam-sdk#60).
 */
function resolveCanonical(toolInput: unknown, canonical: Uint8Array | undefined): Uint8Array {
  if (canonical === undefined) return jcsCanonicalize(toolInput ?? {});
  if (toolInput !== undefined)
    throw new Error(
      "toolInput and canonical are mutually exclusive — pass the value OR the bytes you already derived " +
        "from it, never both. Accepting both would mean choosing one silently, which is the failure this " +
        "option exists to remove (seam-sdk#60).",
    );
  if (!(canonical instanceof Uint8Array))
    throw new Error(`canonical must be a Uint8Array, got ${typeof canonical}`);
  if (canonical.length === 0)
    throw new Error(
      "canonical is empty; JCS never produces zero bytes (a no-argument call is `{}`). An empty value " +
        "would digest to something no re-derivation can reproduce.",
    );
  return canonical;
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
      /** Already-canonical JCS bytes you derived yourself, via {@link jcsCanonicalize}. Mutually
       * exclusive with `toolInput`, and the point of it: pass this and the value is derived exactly
       * ONCE, by you. Otherwise a caller that needs the digest before the call canonicalizes the
       * object, this SDK canonicalizes it again, and the two derivations can disagree across the gap
       * between them (seam-sdk#60). The bytes are NOT re-canonicalized to validate them — doing so
       * would reinstate the second derivation — so canonicality is your assertion. */
      canonical?: Uint8Array;
      digestOnly?: boolean;
      features?: Record<string, string>;
      sessionId?: string;
      subject?: string;
      /** Supersedes the deprecated singular `subject`: the server takes the union of both, drops
       * empty entries, dedupes first-wins, and caps the effective set at 16. **Today the server
       * refuses an effective subject set larger than one** — supplying more than one is the
       * server's `INVALID_ARGUMENT` until Phase B ships `AuthorizeEvaluated.subject_digests`; this
       * field exists now so callers can migrate off `subject` one at a time. It is not part of the
       * signed payload (`callSig` does not cover `subject` or `subjects`). */
      subjects?: string[];
      agentId?: string;
      clientRequestId?: string;
      timeoutMs?: number;
    },
  ): Promise<AuthorizeResult> {
    const canonical = resolveCanonical(toolInput, opts?.canonical);
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
      subjects: opts?.subjects ?? [],
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

  /**
   * Submit a MACP evaluation for a proposal.
   *
   * `recommendation` is MACP's closed vocabulary: `APPROVE | REVIEW | BLOCK | REJECT`.
   *
   * `confidence` is EXPLICIT PRESENCE on the wire: omitting it means *declined to claim* and is
   * **not** `0`  — the runtime never fabricates a value into the caller's intent. When present it
   * must be in `[0.0, 1.0]`; out-of-range is the server's `INVALID_ARGUMENT` (MACP refuses it —
   * `macp-modes-0.5.0 src/mode/decision.rs:166-171`), deliberately not mirrored client-side.
   *
   * `rationaleRef` is a `sha256:<hex>` context ref. It is accepted and recorded on the request
   * path only — it is **NOT YET SEALED**.
   */
  submitEvaluation(
    sessionId: string,
    evaluator: string,
    proposalId: string,
    recommendation: string,
    opts?: {
      confidence?: number;
      reason?: string;
      rationaleRef?: string;
      usage?: StepUsage;
      timeoutMs?: number;
    },
  ) {
    return this.coord.submitEvaluation(
      {
        sessionId,
        evaluator,
        proposalId,
        recommendation,
        reason: opts?.reason ?? "",
        // Omitting the key is absence on the wire — never `?? 0`, which would collapse "declined
        // to claim" into a real confidence value the caller never gave.
        ...(opts?.confidence !== undefined ? { confidence: opts.confidence } : {}),
        ...(opts?.rationaleRef !== undefined ? { rationaleRef: opts.rationaleRef } : {}),
        usage: opts?.usage,
      },
      call(opts),
    );
  }

  /**
   * Submit a MACP objection against a proposal.
   *
   * `severity` is one of `low | medium | high | critical`; empty defaults to `medium` (the MACP
   * default, applied server-side).
   */
  submitObjection(
    sessionId: string,
    objector: string,
    proposalId: string,
    reason: string,
    opts?: {
      severity?: string;
      usage?: StepUsage;
      timeoutMs?: number;
    },
  ) {
    return this.coord.submitObjection(
      { sessionId, objector, proposalId, reason, severity: opts?.severity ?? "", usage: opts?.usage },
      call(opts),
    );
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

  // ── Quorum-mode-only steps (`macp.mode.quorum.v1`) ────────────────────────────────────────────
  // request -> ballot x N -> submitCommit (reused unchanged). Both are rejected with a typed
  // mode-mismatch error against a session opened in any other mode. That check is the server's to
  // make and is deliberately NOT mirrored here: a client-side copy of a server-side rule is a
  // second grammar to keep in sync, and the first thing to drift.

  /** Open an N-of-M approval round. Only the session initiator may submit one (enforced by the
   * mode engine, not the contract). `requiredApprovals` is the N: how many APPROVE ballots close
   * the round. Range-checked as a `uint32` here so an out-of-range value names this argument
   * rather than surfacing from the generated setter. */
  submitApprovalRequest(
    sessionId: string,
    requester: string,
    requestId: string,
    action: string,
    requiredApprovals: number,
    usage?: StepUsage,
    opts?: UnaryCallOptions,
  ) {
    return this.coord.submitApprovalRequest(
      {
        sessionId,
        requester,
        requestId,
        action,
        requiredApprovals: u32(requiredApprovals, "requiredApprovals"),
        usage,
      },
      call(opts),
    );
  }

  /** Cast one ballot against an open approval request. One RPC covers approve/reject/abstain: the
   * three upstream MACP payloads are structurally identical, and `choice` is what selects the wire
   * envelope. `BALLOT_CHOICE_UNSPECIFIED` is not a vote — passing it is the server's
   * INVALID_ARGUMENT to raise. */
  submitBallot(
    sessionId: string,
    voter: string,
    requestId: string,
    choice: BallotChoice,
    reason = "",
    usage?: StepUsage,
    opts?: UnaryCallOptions,
  ) {
    return this.coord.submitBallot(
      { sessionId, voter, requestId, choice, reason, usage },
      call(opts),
    );
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

  /**
   * Resolve context refs to their bindings.
   *
   * Returns the generated `ContextBinding` unchanged — nothing is projected or renamed, so every
   * field the contract carries arrives, including the ACDP receipt slots (`contentHash`,
   * `receiptHash`, `keyStatus`, `resolvedStatus`) and `retraction`, which this SDK passes through
   * without interpreting. `keyStatus` (closed, PascalCase) and `resolvedStatus` (open, lowercase)
   * are byte-identical to what enters the `context_digest` preimage — do not case-fold, normalise
   * or map them.
   */
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
   *
   * `signedArtifact` must decode as UTF-8; a non-UTF-8 artifact throws `TypeError` rather than
   * decoding lossily. Mirrors the Python SDK, where the equivalent `.decode()` raises
   * `UnicodeDecodeError` — both SDKs fail loud on a corrupted artifact instead of silently
   * returning `false`, which would be indistinguishable from an ordinary invalid decision.
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
    return verifyTct(expectedIssuer, new TextDecoder("utf-8", { fatal: true }).decode(c.signedArtifact), {
      id: c.id,
      action: c.action,
      authority: c.authority,
      auth_method: c.authMethod,
      trust_basis: c.trustBasis,
      supersedes: c.supersedes || "",
    });
  }
}
