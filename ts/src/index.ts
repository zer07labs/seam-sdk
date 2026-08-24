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
// Two generated names are shadowed by longstanding hand-written exports and stay reachable through
// the `pb` namespace instead: `pb.Commitment` (the message behind `verifyCommitment`; the root-level
// `Commitment` is crypto.ts's snake_case commitment for local `verifyTct`) and `pb.BudgetLimits` /
// `pb.StepUsage` (the wire messages behind the root-level DTO interfaces of the same names — the
// clients accept the DTOs, so the wire types are rarely needed).

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
