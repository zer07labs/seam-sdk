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
  type ErasurePreview,
  type ErasureCertificate,
  type TenantView,
  type AuditEntry,
  type Anchor,
} from "../gen/seam/api/v1/seam_pb.js";

/** A Connect interceptor that attaches `authorization: Bearer <token>` to every request. */
function bearerAuth(token: string): Interceptor {
  return (next) => async (req) => {
    req.header.set("authorization", `Bearer ${token}`);
    return next(req);
  };
}

export class SeamAdminClient {
  private readonly admin: Client<typeof SeamAdmin>;

  constructor(transport: ReturnType<typeof createGrpcTransport>) {
    this.admin = createClient(SeamAdmin, transport);
  }

  /**
   * Connect to a Seam **management** endpoint (`SEAM_GRPC_MGMT_LISTEN`, distinct from the data plane).
   * When `token` is set, every call carries `authorization: Bearer <token>`; omit it only against a dev
   * server running unauthenticated (`SEAM_DEV_INSECURE` with no `SEAM_MGMT_TOKEN`).
   */
  static connect(baseUrl: string, opts?: { token?: string }): SeamAdminClient {
    const interceptors = opts?.token ? [bearerAuth(opts.token)] : [];
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
}

export type { Anchor };
