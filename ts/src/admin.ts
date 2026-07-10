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
