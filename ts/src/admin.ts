// Seam management-plane client (`SeamAdmin`) — GDPR erasure + governance.
//
// The admin surface lives on a **separate management listener** (`SEAM_GRPC_MGMT_LISTEN`), never the data
// plane, and is gated by an **operator token** — a compact-JWS credential the control plane mints against
// the runtime's installed `operator_keys` trust root, enforcing a per-verb scope (the deprecated shared
// `SEAM_MGMT_TOKEN` bearer was removed in seam-runtime #175). This client is token-agnostic: when a token is
// supplied, it attaches `authorization: Bearer <token>` on every call via a Connect interceptor. With
// the runtime in `SEAM_DEV_INSECURE` mode and no `operator_keys` root installed, the plane is dev-open and the
// token may be omitted.
//
// Erasure is a preview → confirm → erase flow (runtime audit P0.1): `previewErasure` is non-destructive;
// `eraseSubject` requires a non-empty `tenant` scope and a `confirmCount` equal to the preview's
// `wouldErase` count. `eraseSubjectConfirmed` is the common, safe path that does both.

import {
  Code,
  createClient,
  type Client,
  type Interceptor,
} from "@connectrpc/connect";
import { createGrpcTransport, Http2SessionManager } from "@connectrpc/connect-node";

import {
  SeamAdmin,
  SeamEvents,
  type ErasurePreview,
  type GrantView,
  type ListLegalHoldsResponse,
  type TenantView,
  type AuditEntry,
  type Anchor, type RedriveOutcome,
} from "../gen/seam/api/v1/seam_pb.js";
// The event messages now live in the canonical seam.event.v1 package (imported by seam.api.v1).
import {
  type ErasureCertificate,
  type SeamEvent,
} from "../gen/seam/event/v1/seam_event_pb.js";
import { errorMappingInterceptor, InvalidArgumentError, toSeamError } from "./errors.js";
import {
  DEFAULT_OPERATOR_AUD,
  DpopError,
  DpopKeyError,
  OperatorDpopKey,
  mgmtDpopGrpcHtu,
  peekTokenClaims,
  tokenCnfJkt,
} from "./dpop.js";
import { dpopAuth } from "./dpop_interceptor.js";
import {
  recordDigestV4,
  UnsupportedRecordDigestVersion,
  validateEnrollPopNonce,
  type EnrollProof,
} from "./crypto.js";
import type { BudgetLimits, UnaryCallOptions } from "./client.js";

// Management-plane calls get their own, larger default deadline — but they DO get one.
//
// 30s rather than the data plane's 2s because these are operator-cadence, not hot-path: erasure
// and retention enforcement do real work over potentially many records. An unbounded destructive
// RPC (an `eraseSubject` against a wedged management plane) hangs the operator's process with no
// way to know whether the erasure landed — and the instinct at that point is Ctrl-C and re-run,
// against a server that may still be working. Pass `{ timeoutMs }` to widen it for a large tenant;
// the point is that the number exists and the caller owns it. Mirrors the Python SDK's
// `DEFAULT_ADMIN_TIMEOUT_S = 30`. `streamEvents` is the one deliberate exception — see its doc.
export const DEFAULT_ADMIN_TIMEOUT_MS = 30_000;

const call = (opts?: UnaryCallOptions) => ({
  timeoutMs: opts?.timeoutMs ?? DEFAULT_ADMIN_TIMEOUT_MS,
});

// The placer-named tenant on a legal-hold place/release (runtime #1037): the `x-seam-tenant` header
// when `tenant` is given, else no `headers` option at all — so an omitted tenant leaves the call
// identical to the pre-#1037 one. Presence, not truthiness: `""` is sent, and the runtime refuses it
// as present-but-empty.
const legalHoldCall = (opts?: { tenant?: string } & UnaryCallOptions) =>
  opts?.tenant === undefined
    ? call(opts)
    : { ...call(opts), headers: { "x-seam-tenant": opts.tenant } };

// Refuse an empty delivery-stream binding before it is sent (k8s P7). The runtime refuses it too, but a
// runtime older than the field ignores it, and there an empty binding would consume.
function requireStreamId(verb: string, streamId: string): void {
  if (!streamId) {
    throw new InvalidArgumentError(
      `${verb}: streamId is required — pass this relay's configured SEAM_STREAM_ID (it is never discovered from the server it exists to check)`,
      Code.InvalidArgument,
    );
  }
}

/** The `seam-event.v1` kinds the SDK knows about. A consumer MAY branch on these, but MUST still tolerate
 * an unknown kind — the wire is a tolerant reader (new kinds are additive): pass anything not in this set
 * through opaque, never erroring on it. */
export const KNOWN_KINDS: ReadonlySet<string> = new Set([
  "DECISION_SEALED",
  "LEARNING_DECISION",
  "LEARNING_OUTCOME",
  "AUDIT_ENTRY",
  "BUDGET_BREACH",
  "ERASURE_CERTIFICATE",
  "SESSION_LIFECYCLE",
  "CHAIN_HEAD_ATTESTATION",
  "AUTHORIZE_EVALUATED",
  "POLICY_DENIED",
]);

/** Recompute a streamed `DECISION_SEALED`'s record digest from its payload and compare it to the wire
 * `digest` (tag 19) — live authenticity for a single record, the in-client counterpart of
 * `seam-verify chain --issuer`'s design-a. Recomputes **v4 only** (`seam.audit.record-digest.v4`).
 * Returns `true` iff they match; `false` for a rewritten payload or a record stripped of its
 * `ciphertextDigest` (tag 10).
 *
 * Throws `UnsupportedRecordDigestVersion` — meaning **cannot-verify** — for any `schemaVersion` other
 * than 4. v1-v3 were retired by the runtime's protocol pass (P7); recomputing a record of another
 * version under the v4 tag would report a spurious `false` on a genuine record, and defaulting to an
 * older formula is what the spec forbids. Throws a plain `Error` for a non-`DECISION_SEALED` event, an
 * event with no payload, or one with no wire digest.
 *
 * Throws `RecordDigestStripError` — deliberately **not** a `false` — when the record is missing a
 * mandatory field: `contextDigest` (11), `participationDigest` (12), `classification` (14),
 * `participantsDigest` (15), `trustBasisCommitment` (16) or `authMethod` (17). The spec requires a strip
 * to be reported distinctly from a digest mismatch; that distinction is enforced in `recordDigestV4`,
 * and this helper's job is to hand it the wire values unaltered rather than re-implement the check
 * beside it.
 *
 * **Presence on tags 10-17 is length, not a presence bit.** All eight are singular proto3 fields, so
 * the generated type is a plain `Uint8Array` / `string` that is *empty* — never `undefined` — when the
 * field is absent. `seam-event.v1.md` §"Presence on the wire" pins the consumer rule as a total
 * mapping: `length === 0` means absent however the bytes arose, including an explicitly-encoded
 * zero-length field from a non-conforming producer, which proto3 obliges a decoder to accept.
 * `mode`/`policyVersion`/`supersedes` (tags 4/5/7) are the opposite case — they ARE `optional`, because
 * the empty string is a real value there, so those keep `?? null` and absent stays distinct from `""`.
 *
 * **`?? null` is the wrong idiom for tag 13 and would corrupt a verdict silently.** An absent
 * `policyRulesDigest` arrives as an empty `Uint8Array`, not `undefined`, so `??` never fires: the empty
 * value would frame as `opt(Some(empty))` (five bytes) where the sealer wrote `opt(None)` (one byte),
 * reporting a mismatch on a genuine record. It must be tested for length. The mandatory tags need no
 * such mapping — passing the empty value through is precisely what raises the strip error. */
export function verifyStreamedRecordDigest(event: SeamEvent): boolean {
  if (event.kind !== "DECISION_SEALED") {
    throw new Error(`not a DECISION_SEALED event: ${event.kind}`);
  }
  const p = event.payload;
  if (!p) throw new Error("DECISION_SEALED event has no payload");
  if (p.schemaVersion !== 4) throw new UnsupportedRecordDigestVersion(p.schemaVersion);
  if (!event.digest)
    throw new Error("event carries no wire digest to compare against");
  if (p.ciphertextDigest.length === 0) {
    // A tag-10 strip. Spec §Ordering & integrity Verification (c) makes this a REFUSE — a failing
    // verdict, which for a helper answering "does this verify?" is exactly `false`. Unlike tags
    // 11-17, the spec attaches no distinct-reporting requirement to tag 10, so this stays the boolean
    // it has always been rather than becoming a throw.
    //
    // This check precedes the strip checks, so a record stripped of tag 10 AND a mandatory tag reports
    // `false` rather than the strip throw — an adversary who strips both gets the quieter diagnostic.
    // That is deliberate and not a hole: the record still FAILS either way.
    return false;
  }
  const recomputed = recordDigestV4({
    decisionId: p.decisionId,
    tenant: p.tenant,
    namespace: p.namespace,
    ciphertextDigest: p.ciphertextDigest,
    sealedAt: p.sealedAt,
    outcome: p.outcome,
    mode: p.mode ?? null,
    policyVersion: p.policyVersion ?? null,
    supersedes: p.supersedes ?? null,
    contextDigest: p.contextDigest,
    participationDigest: p.participationDigest,
    // length === 0 => absent => opt(None). NOT `?? null` — see the note above.
    policyRulesDigest: p.policyRulesDigest.length === 0 ? null : p.policyRulesDigest,
    classification: p.classification,
    participantsDigest: p.participantsDigest,
    trustBasisCommitment: p.trustBasisCommitment,
    authMethod: p.authMethod,
    schemaVersion: p.schemaVersion,
  });
  const wire = event.digest;
  if (recomputed.length !== wire.length) return false;
  return recomputed.every((b, i) => b === wire[i]);
}

/** A Connect interceptor that attaches `authorization: Bearer <token>` to every request. */
function bearerAuth(token: string): Interceptor {
  return (next) => async (req) => {
    req.header.set("authorization", `Bearer ${token}`);
    return next(req);
  };
}

/** Options for {@link SeamAdminClient.connect}. */
export interface AdminConnectOptions {
  /** A control-plane-minted operator token. */
  token?: string;
  /** The key a DPoP-bound token was minted for — the JWK the console revealed with it, loaded with
   * {@link OperatorDpopKey.fromJwk}. Required for a bound token, refused for an unbound one. */
  dpopKey?: OperatorDpopKey;
  /** The runtime's `SEAM_RUNTIME_AUD`. Defaults to the token's own `aud` claim, else `"seam-runtime"`. */
  aud?: string;
  /** Integer seconds; overrides the local clock for each proof's `iat`. Tests only. */
  clock?: () => number;
}

function resolveOperatorAud(explicit: string | undefined, claims: Record<string, unknown>): string {
  let aud: string;
  if (explicit !== undefined) aud = explicit;
  else if (!Object.prototype.hasOwnProperty.call(claims, "aud")) aud = DEFAULT_OPERATOR_AUD;
  else if (typeof claims.aud === "string") aud = claims.aud;
  else {
    throw new DpopKeyError(
      "the operator token's aud is not a single string; pass aud with the runtime's SEAM_RUNTIME_AUD (default 'seam-runtime')",
    );
  }
  mgmtDpopGrpcHtu("/", aud); // refuses an aud that cannot form an htu, before any call
  return aud;
}

/** The auth interceptor `connect` installs, or `undefined`. Every pairing the runtime is GUARANTEED to
 * refuse throws here instead, by name, before a transport exists. */
function managementAuth(opts: AdminConnectOptions): Interceptor | undefined {
  // `null` reads as absent, like Python's `None`, for callers outside the type system.
  const token = opts.token ?? undefined;
  const dpopKey = opts.dpopKey ?? undefined;
  const aud = opts.aud ?? undefined;
  const clock = opts.clock ?? undefined;
  if (dpopKey === undefined) {
    if (aud !== undefined || clock !== undefined) throw new DpopError("aud and clock apply only with dpopKey");
    if (!token) return undefined;
    let bound = false;
    try {
      bound = Object.prototype.hasOwnProperty.call(peekTokenClaims(token), "cnf");
    } catch (e) {
      if (!(e instanceof DpopError)) throw e; // an opaque Bearer token (dev, tests): the runtime judges it
    }
    if (bound) {
      throw new DpopKeyError(
        "this operator token is DPoP-bound (it carries cnf); pass the key revealed with it as dpopKey — sent as Bearer it is refused with scheme_mismatch",
      );
    }
    return bearerAuth(token);
  }
  if (!(dpopKey instanceof OperatorDpopKey)) {
    throw new DpopError("dpopKey must be an OperatorDpopKey (OperatorDpopKey.fromJwk(...))");
  }
  if (!token) throw new DpopKeyError("dpopKey needs token, the operator token it is bound to");
  if (clock !== undefined) {
    // Probe once, so a fractional clock (`() => Date.now() / 1000`) fails here rather than on every call.
    const sample = typeof clock === "function" ? clock() : undefined;
    if (!Number.isSafeInteger(sample) || (sample as number) < 0) {
      throw new DpopError("clock must be a function returning integer seconds");
    }
  }
  const claims = peekTokenClaims(token);
  const jkt = tokenCnfJkt(claims);
  if (jkt === undefined) {
    throw new DpopKeyError("this operator token is not DPoP-bound (no cnf.jkt); omit dpopKey and send it as Bearer");
  }
  if (jkt !== dpopKey.jkt) {
    throw new DpopKeyError(
      `the token is bound to key ${jkt}, but dpopKey is ${dpopKey.jkt}; load the JWK revealed with this token`,
    );
  }
  return dpopAuth(token, dpopKey, resolveOperatorAud(aud, claims), clock);
}

export class SeamAdminClient {
  private readonly admin: Client<typeof SeamAdmin>;
  private readonly events: Client<typeof SeamEvents>;
  // The HTTP/2 session this client owns (set by `connect`), so `close()` can tear it down.
  private readonly session?: Http2SessionManager;

  constructor(
    transport: ReturnType<typeof createGrpcTransport>,
    session?: Http2SessionManager,
  ) {
    this.admin = createClient(SeamAdmin, transport);
    this.events = createClient(SeamEvents, transport);
    this.session = session;
  }

  /**
   * Connect to a Seam **management** endpoint (`SEAM_GRPC_MGMT_LISTEN`, distinct from the data plane;
   * use `https://…` for TLS). `token` is a control-plane-minted **operator token**; when set, every call
   * carries `authorization: Bearer <token>`. Omit it only against a dev-open server (`SEAM_DEV_INSECURE`
   * with no `operator_keys` root installed).
   *
   * **DPoP-bound tokens** (runtime 0.54.0+). A token minted with a key binding — the management console
   * reveals it once together with a private JWK — must be paired with that key:
   *
   * ```ts
   * const dpopKey = OperatorDpopKey.fromJwk(revealedJwkJson);
   * const admin = SeamAdminClient.connect(baseUrl, { token, dpopKey });
   * ```
   *
   * Every call then carries `authorization: DPoP <token>` and a fresh `dpop` proof signed over that
   * call's request. The proof's `iat` must be within 60 s of the runtime's clock. Throws
   * {@link DpopKeyError} — before any connection — for a pairing the runtime is guaranteed to refuse:
   * `dpopKey` without `token`, a token with no `cnf.jkt`, a key that is not the one the token is bound
   * to, a bound token without `dpopKey`, or a token whose `aud` is a list (pass `aud`).
   */
  static connect(baseUrl: string, opts: AdminConnectOptions = {}): SeamAdminClient {
    const interceptors: Interceptor[] = [errorMappingInterceptor()];
    const auth = managementAuth(opts);
    if (auth !== undefined) interceptors.push(auth);
    const session = new Http2SessionManager(baseUrl);
    return new SeamAdminClient(
      createGrpcTransport({ baseUrl, interceptors, sessionManager: session }),
      session,
    );
  }

  /**
   * Close the underlying HTTP/2 session (connection + any open streams, including a live
   * `streamEvents` tail), releasing its socket and keepalive timers. Mirrors the Python SDK's
   * `close()`. Idempotent — a repeated close is a no-op. Limitation: a client constructed directly
   * over an externally-created transport has no handle on that transport's internal session
   * (connect-node exposes none), so `close()` is a documented no-op there.
   */
  close(): void {
    this.session?.abort();
  }

  // ── GDPR erasure (preview → confirm → erase) ──────────────────────────────────────────────────

  /** Non-destructive: what WOULD be shredded (`wouldErase`), held by legal hold (`held`), or already
   * shredded (`alreadyErased`) for `subject` in `tenant`. */
  previewErasure(
    tenant: string,
    subject: string,
    opts?: UnaryCallOptions,
  ): Promise<ErasurePreview> {
    return this.admin.previewErasure({ tenant, subject }, call(opts));
  }

  /** Crypto-shred every record bound to `subject` in `tenant`; returns the signed certificate. `tenant`
   * is REQUIRED (empty ⇒ rejected); `confirmCount` MUST equal the preview's `wouldErase.length`.
   * The run time is always the server's clock: runtime 0.67.0 removed `nowMillis` from
   * `ErasureRequest` (seam-sdk#315), and `opts` moved up into its positional slot. */
  eraseSubject(
    tenant: string,
    subject: string,
    confirmCount: bigint,
    opts?: UnaryCallOptions,
  ): Promise<ErasureCertificate> {
    return this.admin.eraseSubject(
      { tenant, subject, confirmCount },
      call(opts),
    );
  }

  /** The common, safe path: preview, then erase with the preview's `wouldErase` count.
   * `timeoutMs` applies to EACH of the two calls, not to the pair — the worst case is 2x it. */
  async eraseSubjectConfirmed(
    tenant: string,
    subject: string,
    opts?: UnaryCallOptions,
  ): Promise<ErasureCertificate> {
    const preview = await this.previewErasure(tenant, subject, opts);
    return this.eraseSubject(
      tenant,
      subject,
      BigInt(preview.wouldErase.length),
      opts,
    );
  }

  // ── Governance / tenancy ──────────────────────────────────────────────────────────────────────

  /** Bind an agent identity to a tenant/namespace.
   *
   * `pop` is the subject AID's proof-of-possession for exactly this `tenant`/`namespace` (seam-runtime
   * #1157), produced by the AGENT — `agent.enrolmentProof(tenant, namespace)` — not by the operator
   * making this call. It is **required when the operator token is tenant-scoped**; a fleet token may
   * pass `undefined`, and then no `pop` is sent. A malformed one (a nonce outside 1..=128 chars of
   * `[A-Za-z0-9_-]`, a signature that is not 64 bytes) throws `InvalidArgumentError` before any RPC. */
  async enrollTenant(
    subjectAid: string,
    tenant: string,
    namespace: string,
    pop?: EnrollProof,
    opts?: UnaryCallOptions,
  ): Promise<TenantView> {
    return this.admin.enrollTenant(
      { subjectAid, tenant, namespace, pop: checkedEnrollPop(pop) },
      call(opts),
    );
  }

  async listTenants(opts?: UnaryCallOptions): Promise<TenantView[]> {
    return (await this.admin.listTenants({}, call(opts))).tenants;
  }

  /** Revoke (soft-delete) a subject AID's enrollment — the inverse of `enrollTenant`. The durable
   * row is tombstoned (never deleted), the in-memory binding is evicted with no restart, and a
   * `tenant_revoked` entry is chained. Idempotent: revoking an already-revoked AID succeeds. An AID
   * with no enrollment row AND no live `enroll:` chain entry gets a `NotFoundError`; a tenant-scoped
   * operator gets the same success as an idempotent re-revoke instead, so it cannot use this to
   * probe another tenant's AIDs (seam-runtime #951). A chain-only enrollment (a chain entry with no
   * row) is revoked by chaining a `tenant_revoked` entry same as any other. Requires the
   * `tenant:revoke` operator scope. */
  async revokeTenant(subjectAid: string, opts?: UnaryCallOptions): Promise<void> {
    await this.admin.revokeTenant({ subjectAid }, call(opts));
  }

  /** Register a counterparty's raw 32-byte ed25519 public key (network mode). Requires the
   * `grant:create` operator scope; a fleet-wide (no-tenant-claim) operator is refused (seam-runtime
   * #903 Phase 1). The party is bound to the *calling operator's own* `tenant` claim — never a request
   * field — so that same tenant is what to pass to `SeamClient.verifyPartyAnchor`'s `tenant` option to
   * verify this party later. */
  async registerParty(
    partyId: string,
    pubkey: Uint8Array,
    opts?: UnaryCallOptions,
  ): Promise<void> {
    await this.admin.registerParty({ partyId, pubkey }, call(opts));
  }

  /** Revoke a previously-registered party's verifying key (PartyRegistry-durability Phase 4) — parity
   * with the HTTP `DELETE /v1/parties/{party_id}`. Chained (`party_removed`) and durable. Requires the
   * `grant:revoke` operator scope. */
  async removeParty(partyId: string, opts?: UnaryCallOptions): Promise<void> {
    await this.admin.removeParty({ partyId }, call(opts));
  }

  // ── Cross-namespace read grants (build-ent-deploy-infra §D2) ──────────────────────────────────
  // Parity with the HTTP `POST/GET/DELETE /v1/grants`. Place/revoke are chained to the audit trail;
  // cross-tenant reads are never grantable.

  /** Grant subjects enrolled in `fromNs` read access to `toNs` records of the SAME `tenant` until
   * `expiresAt` (unix millis, must be in the future). Requires the `grant:create` operator scope. */
  async placeGrant(
    tenant: string,
    fromNs: string,
    toNs: string,
    grantor: string,
    expiresAt: bigint,
    opts?: UnaryCallOptions,
  ): Promise<void> {
    await this.admin.placeGrant({ tenant, fromNs, toNs, grantor, expiresAt }, call(opts));
  }

  /** Revoke a cross-namespace grant (idempotent). Requires the `grant:revoke` operator scope. */
  async revokeGrant(
    tenant: string,
    fromNs: string,
    toNs: string,
    revoker: string,
    opts?: UnaryCallOptions,
  ): Promise<void> {
    await this.admin.revokeGrant({ tenant, fromNs, toNs, revoker }, call(opts));
  }

  /** Every stored cross-namespace grant. Requires the `grant:revoke` operator scope. */
  async listGrants(opts?: UnaryCallOptions): Promise<GrantView[]> {
    return (await this.admin.listGrants({}, call(opts))).grants;
  }

  /** Resume a Suspended session — the R9 approver action, on the **management** plane (rt-D: this moved
   * off the data plane, where `SeamCoordination.ResumeSession` is now a tombstone). Requires the
   * `session:resume` operator scope. `approver` is a **required**, non-empty attribution for the approval.
   * `raise` raises any budget dimension; absent, `budget` raises the message count. `tenant`/`namespace`
   * scope the lookup — leave empty to resolve the session by id alone. */
  async resumeSession(
    sessionId: string,
    approver: string,
    opts?: {
      tenant?: string;
      namespace?: string;
      budget?: number;
      raise?: BudgetLimits;
      timeoutMs?: number;
    },
  ) {
    return this.admin.resumeSession(
      {
        sessionId,
        approver,
        tenant: opts?.tenant ?? "",
        namespace: opts?.namespace ?? "",
        // 0 ⇒ the server default — the proto owns the default, the client never re-states it.
        budget: opts?.budget ?? 0,
        raise: opts?.raise,
      },
      call(opts),
    );
  }

  // ── Retention & legal hold ────────────────────────────────────────────────────────────────────

  /** One page of legal holds, ordered by `decisionId`. To page, pass the previous response's
   * `nextCursor` as `cursor`; `nextCursor` is present only when the page was full.
   *
   * An omitted `tenant` applies no filter. `tenant: ""` is a different request: it filters the reserved
   * legacy tenant `""` and is NOT fleet-wide. A Scoped operator may only name its own tenant. `limit`
   * is clamped server-side to 1..=1000; omitted takes the server default (100).
   *
   * **Not every row is a live hold** (runtime #1186). A row with `releasedAt` set is a hold released
   * inside the deployment's release grace and not placed again. Retention still treats the record as
   * held until `purgeEligibleAt`, and re-placing the hold before then undoes the release. Check
   * `row.releasedAt !== undefined` before treating a row as live. The response's `releaseGraceMillis`
   * is that grace; `0n` means no released rows are listed. */
  async listLegalHolds(
    opts?: { tenant?: string; cursor?: string; limit?: number } & UnaryCallOptions,
  ): Promise<ListLegalHoldsResponse> {
    // Pass each filter only when set: presence is meaningful (`tenant: ""` is not "no filter").
    return this.admin.listLegalHolds(
      { tenant: opts?.tenant, cursor: opts?.cursor, limit: opts?.limit },
      call(opts),
    );
  }

  /** Pin a decision against erasure and retention until the hold is released.
   *
   * `tenant` names the tenant the hold is placed for (runtime #1037), sent as the `x-seam-tenant`
   * header — no proto field. Name it on a **preemptive** hold (a decision id not yet sealed) so the
   * hold's audit entry is tenant-bound. An unenrolled or mismatched tenant is refused
   * (`PermissionDenied`); `tenant: ""` is present-but-empty and refused (`InvalidArgument`). Omitted
   * sends no header — the request is exactly the pre-#1037 one. */
  async placeLegalHold(
    decisionId: string,
    opts?: { tenant?: string } & UnaryCallOptions,
  ): Promise<void> {
    await this.admin.placeLegalHold({ decisionId }, legalHoldCall(opts));
  }
  /** Release a legal hold, making the decision eligible for erasure/retention again. `tenant` is sent
   * as the `x-seam-tenant` header exactly as on `placeLegalHold`; omitted sends none. */
  async releaseLegalHold(
    decisionId: string,
    opts?: { tenant?: string } & UnaryCallOptions,
  ): Promise<void> {
    await this.admin.releaseLegalHold({ decisionId }, legalHoldCall(opts));
  }

  /** Crypto-shred decisions past their tiered retention windows; returns the purged decision ids.
   * The windows are measured from the server's clock: runtime 0.67.0 removed `nowMillis` from
   * `RetentionRequest` (seam-sdk#315), and `opts` moved up into its positional slot. */
  async enforceRetention(
    fullDays: bigint,
    sealedDigestDays: bigint,
    commitmentOnlyDays: bigint,
    opts?: UnaryCallOptions,
  ): Promise<string[]> {
    return (
      await this.admin.enforceRetention(
        {
          fullDays,
          sealedDigestDays,
          commitmentOnlyDays,
        },
        call(opts),
      )
    ).purged;
  }

  async auditTrail(opts?: UnaryCallOptions): Promise<AuditEntry[]> {
    return (await this.admin.auditTrail({}, call(opts))).entries;
  }

  // ── Governance event stream (seam-event.v1 outbox) ────────────────────────────────────────────

  /**
   * Server-stream the `seam-event.v1` governance outbox. Two modes:
   *   - **drain** (`follow: false`, default): yield the current unpublished backlog, then end. `ack: true`
   *     marks exactly the yielded rows published (at-least-once relay watermark); `fromSeq` is advisory.
   *   - **live tail** (`follow: true`): yield the backlog from `fromSeq`, then keep yielding new events as
   *     they arrive — cursor-based, never acks. Resume from the last `seq + 1n` and dedup by `eventId`.
   *     The stream ends cleanly when the server drains on shutdown.
   *
   * `streamId` is REQUIRED: the delivery stream this relay is bound to, its configured `SEAM_STREAM_ID`
   * (k8s P7). The runtime refuses a stream that is not its own, empty included, with
   * `FAILED_PRECONDITION` (`stream_id_mismatch`) before reading any event, so a relay pointed at the
   * wrong cell fails instead of consuming. It is never discovered from the server it exists to check;
   * an empty value throws a client-side {@link InvalidArgumentError} without a round trip.
   *
   * `ack` is drain-only (the proto contract): combining `ack: true` with `follow: true` throws a
   * client-side {@link InvalidArgumentError} eagerly — a live tail never acks, and silently dropping
   * either flag would corrupt the relay watermark.
   *
   * `signal` cancels the stream (e.g. to terminate a follow-tail): pass an `AbortController`'s signal
   * and `abort()` it; the iteration then rejects with a `Canceled`-coded error.
   *
   * `timeoutMs` defaults to `undefined` — **no deadline** — the one deliberate exception to this
   * client's every-call-is-bounded rule. A deadline bounds the whole STREAM, not the gap between
   * events, so any finite default would kill a healthy live tail the moment it outlived the number.
   * Set it only for a bounded drain (`follow: false`), where "this should have finished by now" is a
   * meaningful statement.
   */
  streamEvents(opts: {
    streamId: string;
    fromSeq?: bigint;
    follow?: boolean;
    ack?: boolean;
    signal?: AbortSignal;
    timeoutMs?: number;
  }): AsyncIterable<SeamEvent> {
    requireStreamId("streamEvents", opts.streamId);
    if (opts.ack && opts.follow) {
      throw new InvalidArgumentError(
        "streamEvents: ack is drain-only — a live tail (follow: true) never acks; drop one of the two flags",
        Code.InvalidArgument,
      );
    }
    const events = this.events;
    return (async function* () {
      try {
        for await (const ev of events.streamEvents(
          {
            streamId: opts.streamId,
            fromSeq: opts.fromSeq ?? 0n,
            follow: opts.follow ?? false,
            ack: opts.ack ?? false,
          },
          { signal: opts.signal, timeoutMs: opts.timeoutMs },
        )) {
          yield ev;
        }
      } catch (e) {
        throw toSeamError(e);
      }
    })();
  }

  /**
   * Report the relay's durably-consumed outbox cursor so the runtime can bound its outbox (R1).
   *
   * `consumedCursor` is the first outbox offset the relay has NOT yet durably delivered downstream (its
   * contiguous-delivery resume offset). The runtime advances a monotone GC watermark from it and prunes
   * only rows *below* it, so it can never delete a row the relay still needs. A lower re-report is a
   * durable no-op (the watermark is monotone); a value past the outbox head is clamped by the runtime.
   * Requires the destructive `events:consume` operator scope.
   *
   * `streamId` is REQUIRED: the stream `consumedCursor` is an offset of (k8s P7). Only that stream's
   * watermark advances; a stream that is not the runtime's own, empty included, is
   * `FAILED_PRECONDITION` (`stream_id_mismatch`) and advances nothing. Empty throws here.
   */
  async reportEventsConsumed(
    consumedCursor: bigint,
    opts: UnaryCallOptions & { streamId: string },
  ): Promise<void> {
    requireStreamId("reportEventsConsumed", opts.streamId);
    try {
      await this.events.reportEventsConsumed(
        { consumedCursor, streamId: opts.streamId },
        call(opts),
      );
    } catch (e) {
      throw toSeamError(e);
    }
  }

  /**
   * Re-drive existing outbox events by reference (seam-runtime #1176, DLQ retry option C).
   *
   * Names events by their coordinates — `tenant` plus the global outbox `fromSeq` (a DLQ letter's
   * `tenant`/`seq` headers), optionally a bounded inclusive range up to `toSeq` (at most 1000 seqs), or a
   * single seq cross-checked by `eventId`. The runtime re-reads ITS OWN stored row for each and appends one
   * advisory `EVENT_REDRIVEN` wrapper carrying it verbatim; a DLQ letter's own bytes never reach the
   * stream. Resolves to one outcome per requested seq, in seq order, whose `status` is `redriven` |
   * `not_found` | `pruned` | `not_redrivable` | `event_id_mismatch`. Requires the `events:redrive`
   * operator scope (not `events:consume`).
   */
  async redriveEvents(
    tenant: string,
    fromSeq: bigint,
    opts?: UnaryCallOptions & { toSeq?: bigint; eventId?: string },
  ): Promise<RedriveOutcome[]> {
    if (!tenant) {
      throw new InvalidArgumentError(
        "redriveEvents: tenant is required — the tenant whose events to re-drive",
        Code.InvalidArgument,
      );
    }
    try {
      const res = await this.events.redriveEvents(
        { tenant, fromSeq, toSeq: opts?.toSeq, eventId: opts?.eventId },
        call(opts),
      );
      return res.outcomes;
    } catch (e) {
      throw toSeamError(e);
    }
  }
}

export type { Anchor, GrantView, RedriveOutcome };

// ── Enrolment proof-of-possession (#205) ─────────────────────────────────────────────────────────
// Kept at the end of the file so it shifts no line cited by COMPATIBILITY.md / DECISIONS.md above it.

/** Validate an enrolment proof client-side, refusing early in the SDK's `InvalidArgumentError` style
 * rather than sending what the runtime would refuse. `undefined` stays `undefined` — the field is left
 * unset, which is a fleet token's enrolment. */
function checkedEnrollPop(pop: EnrollProof | undefined): EnrollProof | undefined {
  if (pop === undefined) return undefined;
  const refuse = (why: string): never => {
    throw new InvalidArgumentError(`enrollTenant: ${why}`, Code.InvalidArgument);
  };
  try {
    validateEnrollPopNonce(pop.nonce);
  } catch (e) {
    refuse((e as Error).message);
  }
  if (typeof pop.issuedAtMs !== "bigint" || pop.issuedAtMs < 0n || pop.issuedAtMs >= 1n << 64n) {
    refuse(`pop.issuedAtMs must be a bigint in [0, 2^64), got ${String(pop.issuedAtMs)}`);
  }
  if (!(pop.signature instanceof Uint8Array) || pop.signature.length !== 64) {
    refuse(
      "pop.signature must be the raw 64-byte Ed25519 signature (not the REST base64url string), got " +
        (pop.signature instanceof Uint8Array ? `${pop.signature.length} bytes` : typeof pop.signature),
    );
  }
  return { issuedAtMs: pop.issuedAtMs, nonce: pop.nonce, signature: pop.signature };
}
