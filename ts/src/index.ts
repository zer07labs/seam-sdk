// Public entry point for @zer07labs/seam-sdk.
//
// `SeamClient` — the data-plane client (admission → decide/seal, sessions & budgets, context, trust,
// local zero-server-trust verification). `SeamAdminClient` — the management-plane client (GDPR erasure +
// governance), which targets a separate endpoint with an optional bearer token.

export * from "./client.js";
export * from "./admin.js";
export * from "./crypto.js";
export * from "./errors.js";
// Cell routing (seam-runtime k8s P15, D123): the `x-seam-tenant` hint (Python's `seam_sdk.tenant`).
export * from "./tenant.js";
// Opt-in `SESSION_UNAVAILABLE` retry (Python's `seam_sdk.with_session_retry`).
export * from "./retry.js";
// Session / decision ids — the runtime's P4 / P5 rules (Python's `seam_sdk.ids`).
export * from "./ids.js";
// Identity custody (seam-sdk#201, #274): the schema-v1 bootstrap file — the same six names Python's
// `seam_sdk` root exports. Listed, not star-exported, so the layout helper `identityFileBody`, the
// test-only `seedCodec` and the module constants stay internal to `identity.ts` and its tests.
export {
  IdentityFacts,
  IdentityFileError,
  LoadedIdentity,
  createIdentityFile,
  loadIdentityFacts,
  loadIdentityFile,
} from "./identity.js";
// Management-plane DPoP (seam-sdk#290): the operator's Ed25519 proof signer — Python's `seam_sdk.dpop`.
// Listed, not star-exported, so the token-peek helpers stay internal to `dpop.ts` and `admin.ts`.
export {
  DEFAULT_OPERATOR_AUD,
  DpopError,
  DpopKeyError,
  MGMT_DPOP_MAX_BODY_BYTES,
  MGMT_DPOP_MAX_IAT,
  MGMT_DPOP_MAX_JTI_BYTES,
  MGMT_DPOP_MAX_PROOF_BYTES,
  OperatorDpopKey,
  mgmtDpopGrpcHtu,
  mgmtDpopHttpHeaders,
  mgmtDpopHttpHtu,
  mgmtDpopProof,
  newMgmtDpopJti,
} from "./dpop.js";
export type { MgmtDpopProofInput } from "./dpop.js";

// ── Generated protobuf surface ────────────────────────────────────────────────────────────────────
// Every generated message type that appears in a public method signature is reachable from this root
// entry (the package's exports map exposes only "."), so consumers can NAME what the clients accept
// and return — and construct the ones they must pass in, via protobuf-es `create(Schema)`, e.g.
// `create(AnchorSchema, { … })` for `verifyPartyAnchor`.
//
// SIX generated names are declared on BOTH sides — by a hand-written export here and by the
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
//   `pb.SealAttestation`    — the wire message behind the DTO that `sealAttestationOf` returns.
//
// **Why they are `pb.`-only is worth stating precisely, because the obvious explanation is wrong.**
// It is not that a star export beat another star export: this file never star-exports the generated
// module. `export * as pb` exports exactly one name — `pb` — and contributes none of the module's
// inner names at the root. Every generated name that DOES reach the root gets there through an
// explicit list below — a deliberately small subset of what the two modules declare, with the
// rest `pb.`/`ev.`-only and always so. These six are simply not on those lists, which is a
// different thing from being displaced. Ordering has nothing to do with it, and had
// there been two competing star exports, ESM would have EXCLUDED the ambiguous name rather than
// resolving it to the first. **The causality runs the other way from the intuition:** adding one of
// these six to the explicit `export type { … }` list would not "un-hide" it — it would make the
// GENERATED type win the root name and silently displace the hand-written one.
//
// The last three differ from the first three in a way worth knowing before reaching for `pb.`: the
// root-level `CollectiveOutcome`, `PolicyEnforcement` and `SealAttestation` are DECODED forms, not
// parallel spellings of the wire type. `CollectiveOutcome.verdict` and `SealAttestation.availability`
// are narrowed string unions where the wire type has an open enum, and `PolicyEnforcement` is only
// ever reached through a decoder that returns `undefined` for an absent field. Take the `pb.` type to build or inspect a raw message; take the
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
  RedriveOutcome,
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
  RedriveOutcomeSchema,
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
  EventRedriven,
  SeamEvent,
  SessionLifecycle,
} from "../gen/seam/event/v1/seam_event_pb.js";
export {
  ChainHeadAttestationSchema,
  DecisionSealedSchema,
  ErasureCertificateSchema,
  EventRedrivenSchema,
  SeamEventSchema,
  SessionLifecycleSchema,
} from "../gen/seam/event/v1/seam_event_pb.js";

// The complete generated modules, namespaced — the escape hatch for anything not re-exported above
// (service descriptors, request/response messages, enums). Mirrors the Python SDK's `pb` / `ev`
// module re-exports.
export * as pb from "../gen/seam/api/v1/seam_pb.js";
export * as ev from "../gen/seam/event/v1/seam_event_pb.js";
