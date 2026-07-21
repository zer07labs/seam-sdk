// Seam management-plane client (`SeamAdmin`) — GDPR erasure + governance.
//
// The admin surface lives on a **separate management listener** (`SEAM_GRPC_MGMT_LISTEN`), never the data
// plane, and is gated by a bearer token (`SEAM_MGMT_TOKEN`). This client targets that endpoint and, when a
// token is supplied, attaches `authorization: Bearer <token>` on every call via a Connect interceptor. With
// the runtime in `SEAM_DEV_INSECURE` mode and no token configured, the plane is unauthenticated and the
// token may be omitted.
//
// Erasure is a preview → confirm → erase flow (runtime audit P0.1): `previewErasure` is non-destructive;
// `eraseSubject` requires a non-empty `tenant` scope and a `confirmCount` equal to the preview's
// `wouldErase` count. `eraseSubjectConfirmed` is the common, safe path that does both.

import { createClient, type Client, type Interceptor } from "@connectrpc/connect";
import { createGrpcTransport } from "@connectrpc/connect-node";

import {
  SeamAdmin,
  SeamEvents,
  type ErasurePreview,
  type ErasureCertificate,
  type TenantView,
  type AuditEntry,
  type Anchor,
  type SeamEvent,
} from "../gen/seam/api/v1/seam_pb.js";
import { errorMappingInterceptor, toSeamError } from "./errors.js";
import { recordDigestV2 } from "./crypto.js";

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
]);

/** Recompute a streamed v2 `DECISION_SEALED`'s record digest from its payload (+ `ciphertextDigest`, tag
 * 10) and compare it to the wire `digest` (tag 19) — live authenticity for a single record, the in-client
 * counterpart of `seam-verify chain --issuer`'s design-a. Returns `true` iff they match; `false` for a
 * rewritten payload or a v2 record stripped of its `ciphertextDigest`. Throws for anything not
 * stream-recomputable (a non-`DECISION_SEALED` event, a v1 record, or an event with no wire digest).
 * `mode`/`policyVersion`/`supersedes` map `undefined` → `null` so absent and `""` stay distinct. */
export function verifyStreamedRecordDigest(event: SeamEvent): boolean {
  if (event.kind !== "DECISION_SEALED") {
    throw new Error(`not a DECISION_SEALED event: ${event.kind}`);
  }
  const p = event.payload;
  if (!p) throw new Error("DECISION_SEALED event has no payload");
  if (p.schemaVersion < 2) {
    throw new Error(`v${p.schemaVersion} record is not stream-recomputable (only v2+)`);
  }
  if (!event.digest) throw new Error("event carries no wire digest to compare against");
  if (p.ciphertextDigest.length === 0) return false; // a v2 record with no ciphertext_digest is a strip
  const recomputed = recordDigestV2({
    decisionId: p.decisionId,
    tenant: p.tenant,
    namespace: p.namespace,
    ciphertextDigest: p.ciphertextDigest,
    sealedAt: p.sealedAt,
    outcome: p.outcome,
    mode: p.mode ?? null,
    policyVersion: p.policyVersion ?? null,
    supersedes: p.supersedes ?? null,
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

export class SeamAdminClient {
  private readonly admin: Client<typeof SeamAdmin>;
  private readonly events: Client<typeof SeamEvents>;

  constructor(transport: ReturnType<typeof createGrpcTransport>) {
    this.admin = createClient(SeamAdmin, transport);
    this.events = createClient(SeamEvents, transport);
  }

  /**
   * Connect to a Seam **management** endpoint (`SEAM_GRPC_MGMT_LISTEN`, distinct from the data plane;
   * use `https://…` for TLS). When `token` is set, every call carries `authorization: Bearer <token>`;
   * omit it only against a dev server running unauthenticated (`SEAM_DEV_INSECURE` with no
   * `SEAM_MGMT_TOKEN`).
   */
  static connect(baseUrl: string, opts?: { token?: string }): SeamAdminClient {
    const interceptors: Interceptor[] = [errorMappingInterceptor()];
    if (opts?.token) interceptors.push(bearerAuth(opts.token));
    return new SeamAdminClient(createGrpcTransport({ baseUrl, interceptors }));
  }

  // ── GDPR erasure (preview → confirm → erase) ──────────────────────────────────────────────────

  /** Non-destructive: what WOULD be shredded (`wouldErase`), held by legal hold (`held`), or already
   * shredded (`alreadyErased`) for `subject` in `tenant`. */
  previewErasure(tenant: string, subject: string): Promise<ErasurePreview> {
    return this.admin.previewErasure({ tenant, subject });
  }

  /** Crypto-shred every record bound to `subject` in `tenant`; returns the signed certificate. `tenant`
   * is REQUIRED (empty ⇒ rejected); `confirmCount` MUST equal the preview's `wouldErase.length`. */
  eraseSubject(
    tenant: string,
    subject: string,
    confirmCount: bigint,
  ): Promise<ErasureCertificate> {
    return this.admin.eraseSubject({ tenant, subject, confirmCount });
  }

  /** The common, safe path: preview, then erase with the preview's `wouldErase` count. */
  async eraseSubjectConfirmed(
    tenant: string,
    subject: string,
  ): Promise<ErasureCertificate> {
    const preview = await this.previewErasure(tenant, subject);
    return this.eraseSubject(tenant, subject, BigInt(preview.wouldErase.length));
  }

  // ── Governance / tenancy ──────────────────────────────────────────────────────────────────────

  enrollTenant(subjectAid: string, tenant: string, namespace: string): Promise<TenantView> {
    return this.admin.enrollTenant({ subjectAid, tenant, namespace });
  }

  async listTenants(): Promise<TenantView[]> {
    return (await this.admin.listTenants({})).tenants;
  }

  /** Register a counterparty's raw 32-byte ed25519 public key (network mode). */
  async registerParty(partyId: string, pubkey: Uint8Array): Promise<void> {
    await this.admin.registerParty({ partyId, pubkey });
  }

  // ── Retention & legal hold ────────────────────────────────────────────────────────────────────

  async placeLegalHold(decisionId: string): Promise<void> {
    await this.admin.placeLegalHold({ decisionId });
  }
  async releaseLegalHold(decisionId: string): Promise<void> {
    await this.admin.releaseLegalHold({ decisionId });
  }

  /** Crypto-shred decisions past their tiered retention windows; returns the purged decision ids. */
  async enforceRetention(
    fullDays: bigint,
    sealedDigestDays: bigint,
    commitmentOnlyDays: bigint,
    nowMillis?: bigint,
  ): Promise<string[]> {
    return (
      await this.admin.enforceRetention({
        fullDays,
        sealedDigestDays,
        commitmentOnlyDays,
        nowMillis,
      })
    ).purged;
  }

  async auditTrail(): Promise<AuditEntry[]> {
    return (await this.admin.auditTrail({})).entries;
  }

  // ── Governance event stream (seam-event.v1 outbox) ────────────────────────────────────────────

  /**
   * Server-stream the `seam-event.v1` governance outbox. Two modes:
   *   - **drain** (`follow: false`, default): yield the current unpublished backlog, then end. `ack: true`
   *     marks exactly the yielded rows published (at-least-once relay watermark); `fromSeq` is advisory.
   *   - **live tail** (`follow: true`): yield the backlog from `fromSeq`, then keep yielding new events as
   *     they arrive — cursor-based, never acks. Resume from the last `seq + 1n` and dedup by `eventId`.
   *     The stream ends cleanly when the server drains on shutdown.
   */
  async *streamEvents(opts?: {
    fromSeq?: bigint;
    follow?: boolean;
    ack?: boolean;
  }): AsyncIterable<SeamEvent> {
    try {
      for await (const ev of this.events.streamEvents({
        fromSeq: opts?.fromSeq ?? 0n,
        follow: opts?.follow ?? false,
        ack: opts?.ack ?? false,
      })) {
        yield ev;
      }
    } catch (e) {
      throw toSeamError(e);
    }
  }
}

export type { Anchor };
