"""Seam SDK for Python — generated gRPC transport + a stock-crypto client shim.

``SeamClient`` owns the binding path (pinned-key PoP admission + decide/seal) and independent TCT
verification; ``Agent`` holds the agent seed. The crypto is pure stock Ed25519/SHA-256/JOSE — conformance
vectors generated from the Rust runtime pin the exact bytes (see ``conformance/vectors.json``).
"""

from . import aio
from ._authorize import AuthorizeResult, canonicalize_tool_input
from ._collective import CollectiveOutcome, collective_outcome_of
from ._policy import PolicyEnforcement, policy_enforcement_of
from .admin import (
    DEFAULT_ADMIN_TIMEOUT_S,
    KNOWN_KINDS,
    SeamAdminClient,
    verify_streamed_record_digest,
)

# Request-side enum on the quorum verbs. Re-exported so a caller can NAME a ballot choice
# (`BallotChoice.BALLOT_CHOICE_APPROVE`) without importing from the private `_gen` tree.
from seam_sdk._gen.seam.api.v1.seam_pb2 import BallotChoice

from .client import (
    DEFAULT_TIMEOUT_S,
    Agent,
    BudgetLimits,
    SeamClient,
    StepUsage,
)
from .crypto import (
    aid_from_pubkey,
    build_presentation,
    call_sig,
    call_sig_payload,
    call_sig_v3,
    call_sig_v3_payload,
    EnrollProof,
    enroll_pop,
    enroll_pop_payload,
    explanation_digest,
    jcs_canonicalize,
    record_digest_v4,
    participants_digest_v4,
    context_digest_v4,
    ContextProvenanceError,
    RECEIPT_KEY_STATUSES,
    derived_uuid,
    pop_message_id,
    RecordDigestStripError,
    UnsupportedRecordDigestVersion,
    tool_input_digest,
    verify_chain_head_attestation,
    verify_chain_head_attestation_message,
    verify_tct,
)
from .ids import (
    DecisionId,
    InvalidDecisionIdError,
    InvalidSessionIdError,
    decision_id_for_session,
    is_valid_session_id,
    parse_decision_id,
    validate_session_id,
)
from .identity import (
    IdentityFacts,
    IdentityFileError,
    LoadedIdentity,
    create_identity_file,
    load_identity_facts,
    load_identity_file,
)
from .errors import (
    AlreadyExistsError,
    CanonicalizationError,
    DeadlineExceededError,
    FailedPreconditionError,
    InternalError,
    InvalidArgumentError,
    IssuerMismatchError,
    NotFoundError,
    PermissionDeniedError,
    ProtocolViolationError,
    ResourceExhaustedError,
    SeamError,
    SeamRpcError,
    UnauthenticatedError,
    UnavailableError,
    UnimplementedError,
    UnknownCollectiveVerdictError,
    UnknownVerdictError,
    SESSION_UNAVAILABLE_REASON,
    WRONG_CELL_REASON,
    is_retryable,
    is_session_unavailable,
    is_wrong_cell,
    map_rpc_error,
)
from .tenant import TENANT_HEADER, AioTenantInterceptor, TenantInterceptor
from .retry import (
    DEFAULT_RETRY_BUDGET_S,
    with_session_retry,
    with_session_retry_async,
)

__all__ = [
    "Agent",
    "create_identity_file",
    "load_identity_file",
    "load_identity_facts",
    "LoadedIdentity",
    "IdentityFacts",
    "IdentityFileError",
    "SeamClient",
    "SeamAdminClient",
    "BudgetLimits",
    "StepUsage",
    "BallotChoice",
    "aio",
    "aid_from_pubkey",
    "build_presentation",
    "verify_tct",
    "explanation_digest",
    # Advisory authorization (Authorize verb)
    "AuthorizeResult",
    "canonicalize_tool_input",
    # Collective outcome (C5) — fail-closed decoding of collective_outcome, on either a
    # DecisionResponse or a SessionStep
    "CollectiveOutcome",
    "collective_outcome_of",
    # Policy enforcement — presence-aware, NOT fail-closed and NOT C5: there is no enum here, and
    # the only distinction being preserved is present-versus-absent. Filed separately on purpose;
    # listing it under the line above would say the same false thing about it that folding it into
    # `_collective.py` would have.
    "PolicyEnforcement",
    "policy_enforcement_of",
    "DEFAULT_TIMEOUT_S",
    "DEFAULT_ADMIN_TIMEOUT_S",
    "jcs_canonicalize",
    "tool_input_digest",
    "call_sig",
    "call_sig_payload",
    "call_sig_v3",
    "call_sig_v3_payload",
    # Enrolment proof-of-possession (#205) — EnrollTenantRequest.pop
    "EnrollProof",
    "enroll_pop",
    "enroll_pop_payload",
    # Streamed-event surface (A14)
    "KNOWN_KINDS",
    "verify_streamed_record_digest",
    "record_digest_v4",
    "participants_digest_v4",
    "context_digest_v4",
    "ContextProvenanceError",
    "RECEIPT_KEY_STATUSES",
    "derived_uuid",
    "pop_message_id",
    "RecordDigestStripError",
    "UnsupportedRecordDigestVersion",
    "DecisionId",
    "InvalidDecisionIdError",
    "InvalidSessionIdError",
    "decision_id_for_session",
    "is_valid_session_id",
    "parse_decision_id",
    "validate_session_id",
    "verify_chain_head_attestation",
    "verify_chain_head_attestation_message",
    # Error taxonomy
    "SeamError",
    "CanonicalizationError",
    "map_rpc_error",
    # SESSION_UNAVAILABLE (seam-runtime k8s P6) — classification plus the opt-in retry helper
    "SESSION_UNAVAILABLE_REASON",
    "is_retryable",
    "is_session_unavailable",
    "DEFAULT_RETRY_BUDGET_S",
    "with_session_retry",
    "with_session_retry_async",
    # Cell routing (seam-runtime k8s P15, D123) — the x-seam-tenant hint and WRONG_CELL
    "TENANT_HEADER",
    "TenantInterceptor",
    "AioTenantInterceptor",
    "WRONG_CELL_REASON",
    "is_wrong_cell",
    "IssuerMismatchError",
    "SeamRpcError",
    "InvalidArgumentError",
    "FailedPreconditionError",
    "PermissionDeniedError",
    "UnauthenticatedError",
    "NotFoundError",
    "ProtocolViolationError",
    "AlreadyExistsError",
    "ResourceExhaustedError",
    "UnavailableError",
    "DeadlineExceededError",
    "UnimplementedError",
    "InternalError",
    "UnknownVerdictError",
    "UnknownCollectiveVerdictError",
]
