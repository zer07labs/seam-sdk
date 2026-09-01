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
// FIVE generated names are shadowed by hand-written exports of the same name and stay reachable
// through the `pb` namespace instead. Counted one per NAME, not one per group: the previous wording
// said "Two" while listing three, counting `pb.BudgetLimits` / `pb.StepUsage` as a single entry, and
// a count that has to be decoded before it can be checked is a count that cannot go stale loudly.
//
//   `pb.Commitment`         — the message behind `verifyCommitment`; the root-level `Commitment` is
//                             crypto.ts's snake_case commitment for local `verifyTct`.
//   `pb.BudgetLimits`       — the wire messages behind the root-level DTO interfaces of the same
//   `pb.StepUsage`            names. The clients accept the DTOs, so the wire types are rarely
//                             needed.
//   `pb.CollectiveOutcome`  — the wire message behind the DTO that `collectiveOutcomeOf` returns.
//   `pb.PolicyEnforcement`  — the wire message behind the DTO that `policyEnforcementOf` returns.
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
