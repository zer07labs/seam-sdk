"""Seam SDK for Python — generated gRPC transport + a stock-crypto client shim.

``SeamClient`` owns the binding path (pinned-key PoP admission + decide/seal) and independent TCT
verification; ``Agent`` holds the agent seed. The crypto is pure stock Ed25519/SHA-256/JOSE — conformance
vectors generated from the Rust runtime pin the exact bytes (see ``conformance/vectors.json``).
"""

from . import aio
from ._authorize import AuthorizeResult, canonicalize_tool_input
from ._collective import CollectiveOutcome, collective_outcome_of
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
    jcs_canonicalize,
    record_digest_v2,
    record_digest_v3,
    RecordDigestStripError,
    tool_input_digest,
    verify_chain_head_attestation,
    verify_tct,
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
    map_rpc_error,
)

__all__ = [
    "Agent",
    "SeamClient",
    "SeamAdminClient",
    "BudgetLimits",
    "StepUsage",
    "BallotChoice",
    "aio",
    "aid_from_pubkey",
    "build_presentation",
    "verify_tct",
    # Advisory authorization (Authorize verb)
    "AuthorizeResult",
    "canonicalize_tool_input",
    # Collective outcome (C5) — fail-closed decoding of collective_outcome, on either a
    # DecisionResponse or a SessionStep
    "CollectiveOutcome",
    "collective_outcome_of",
    "DEFAULT_TIMEOUT_S",
    "DEFAULT_ADMIN_TIMEOUT_S",
    "jcs_canonicalize",
    "tool_input_digest",
    "call_sig",
    "call_sig_payload",
    # Streamed-event surface (A14)
    "KNOWN_KINDS",
    "verify_streamed_record_digest",
    "record_digest_v2",
    "record_digest_v3",
    "RecordDigestStripError",
    "verify_chain_head_attestation",
    # Error taxonomy
    "SeamError",
    "CanonicalizationError",
    "map_rpc_error",
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
