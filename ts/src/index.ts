// Public entry point for @zer07labs/seam-sdk.
//
// `SeamClient` — the data-plane client (admission → decide/seal, sessions & budgets, context, trust,
// local zero-server-trust verification). `SeamAdminClient` — the management-plane client (GDPR erasure +
// governance), which targets a separate endpoint with an optional bearer token.

export * from "./client.js";
export * from "./admin.js";
export * from "./crypto.js";
export * from "./errors.js";

// ── Generated protobuf surface ────────────────────────────────────────────────────────────────────
// Every generated message type that appears in a public method signature is reachable from this root
// entry (the package's exports map exposes only "."), so consumers can NAME what the clients accept
// and return — and construct the ones they must pass in, via protobuf-es `create(Schema)`, e.g.
// `create(AnchorSchema, { … })` for `verifyPartyAnchor`.
//
// FIVE generated names are declared on BOTH sides — by a hand-written export here and by the
// generated surface — and at this root the hand-written declaration is the one you get. The
// generated type stays reachable as `pb.X`. Listed one entry per NAME, so the count can be checked
// against the list without decoding a grouping; `python/tests/test_shadowed_names_comment.py`
// computes the set from the code and reddens if this list or its count drifts from it.
//
//   `pb.Commitment`         — the message behind `verifyCommitment`; the root-level `Commitment` is
//                             crypto.ts's snake_case commitment for local `verifyTct`.
//   `pb.BudgetLimits`       — the wire messages behind the root-level DTO interfaces of the same
//   `pb.StepUsage`            names. The clients accept the DTOs, so the wire types are rarely
//                             needed.
//   `pb.CollectiveOutcome`  — the wire message behind the DTO that `collectiveOutcomeOf` returns.
//   `pb.PolicyEnforcement`  — the wire message behind the DTO that `policyEnforcementOf` returns.
//
// **Why they are `pb.`-only is worth stating precisely, because the obvious explanation is wrong.**
// It is not that a star export beat another star export: this file never star-exports the generated
// module. `export * as pb` exports exactly one name — `pb` — and contributes none of the module's
// inner names at the root. Every generated name that DOES reach the root gets there through an
// explicit list below — a deliberately small subset, 40 of the 167 the two modules declare, with the
// rest `pb.`/`ev.`-only and always so. These five are simply not on those lists, which is a
// different thing from being displaced. Ordering has nothing to do with it, and had
// there been two competing star exports, ESM would have EXCLUDED the ambiguous name rather than
// resolving it to the first. **The causality runs the other way from the intuition:** adding one of
// these five to the explicit `export type { … }` list would not "un-hide" it — it would make the
// GENERATED type win the root name and silently displace the hand-written one.
//
// The last two differ from the first three in a way worth knowing before reaching for `pb.`: the
// root-level `CollectiveOutcome` and `PolicyEnforcement` are DECODED forms, not parallel spellings
// of the wire type. `CollectiveOutcome.verdict` is a narrowed string union where the wire type has
// an open enum, and `PolicyEnforcement` is only ever reached through a decoder that returns
// `undefined` for an absent field. Take the `pb.` type to build or inspect a raw message; take the
// root-level one to read what a client handed you.

// seam.api.v1 — types in public signatures.
export type {
  Anchor,
  AuditEntry,
  CommitmentProof,
  ContextBinding,
  DecisionRecordView,
  DecisionResponse,
  ErasurePreview,
  GrantView,
  ReplayView,
  SessionStatusResponse,
  SessionStep,
  TenantView,
  TerminalResponse,
} from "../gen/seam/api/v1/seam_pb.js";
// seam.api.v1 — request-side enums a caller must NAME to build a request.
export { BallotChoice } from "../gen/seam/api/v1/seam_pb.js";
// seam.api.v1 — schemas (constructing / decoding those messages).
export {
  AnchorSchema,
  AuditEntrySchema,
  BudgetLimitsSchema,
  CommitmentProofSchema,
  CommitmentSchema,
  ContextBindingSchema,
  DecisionRecordViewSchema,
  DecisionResponseSchema,
  ErasurePreviewSchema,
  GrantViewSchema,
  ReplayViewSchema,
  SessionStatusResponseSchema,
  SessionStepSchema,
  StepUsageSchema,
  TenantViewSchema,
  TerminalResponseSchema,
} from "../gen/seam/api/v1/seam_pb.js";

// seam.event.v1 — types + schemas in public signatures (`streamEvents`, `eraseSubject`,
// `verifyPartyAttestation`, `verifyStreamedRecordDigest`).
export type {
  ChainHeadAttestation,
  DecisionSealed,
  ErasureCertificate,
  SeamEvent,
  SessionLifecycle,
} from "../gen/seam/event/v1/seam_event_pb.js";
export {
  ChainHeadAttestationSchema,
  DecisionSealedSchema,
  ErasureCertificateSchema,
  SeamEventSchema,
  SessionLifecycleSchema,
} from "../gen/seam/event/v1/seam_event_pb.js";

// The complete generated modules, namespaced — the escape hatch for anything not re-exported above
// (service descriptors, request/response messages, enums). Mirrors the Python SDK's `pb` / `ev`
// module re-exports.
export * as pb from "../gen/seam/api/v1/seam_pb.js";
export * as ev from "../gen/seam/event/v1/seam_event_pb.js";
