// Public entry point for @zer07labs/seam-sdk.
//
// `SeamClient` — the data-plane client (admission → decide/seal, sessions & budgets, context, trust,
// local zero-server-trust verification). `SeamAdminClient` — the management-plane client (GDPR erasure +
// governance), which targets a separate endpoint with an optional bearer token.

export * from "./client.js";
export * from "./admin.js";
export * from "./crypto.js";
