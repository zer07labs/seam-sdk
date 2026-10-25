// The `x-seam-tenant` routing hint on every data-plane call (seam-runtime k8s P15, D123) — Python's
// `seam_sdk.tenant`.
//
// `seam-cell-router` routes each `seam.api.v1` call to the cell where the caller's tenant lives.
// IssueChallenge, Admit and RunDecision carry no tenant before authentication, so the router reads it
// from this header, on every call. It is a routing hint, never authority: the cell still derives the
// tenant from identity and refuses a misrouted call `FAILED_PRECONDITION` reason `WRONG_CELL`
// (`WRONG_CELL_REASON`). `SeamClient.connect(url, { tenant })` installs the interceptor; a caller that
// builds its own transport adds `tenantHeaderInterceptor(tenant)` to its `interceptors`.

import type { Interceptor } from "@connectrpc/connect";

/** The request header `seam-cell-router` routes on (D123). Shared with legal-hold's placer-named
 * tenant on the management plane (runtime #1037), which is a different, per-call use of the name. */
export const TENANT_HEADER = "x-seam-tenant";

/** Attach `x-seam-tenant: <tenant>` to every call, unary and streaming. A call that already names the
 * header keeps its own value: the interceptor fills a gap, it never rewrites what a caller sent. An
 * empty tenant is refused here rather than sent — the router refuses a missing or malformed value
 * uniformly, and an empty header reads there as a caller that meant to route and named nothing. */
export function tenantHeaderInterceptor(tenant: string): Interceptor {
  if (typeof tenant !== "string" || tenant === "")
    throw new TypeError(
      "tenant must be this caller's enrolled tenant id (a non-empty string); omit it entirely to send no " +
        "x-seam-tenant header",
    );
  return (next) => (req) => {
    if (!req.header.has(TENANT_HEADER)) req.header.set(TENANT_HEADER, tenant);
    return next(req);
  };
}
