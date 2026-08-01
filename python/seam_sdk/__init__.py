"""Seam SDK for Python — generated gRPC transport + a stock-crypto client shim.

``SeamClient`` owns the binding path (pinned-key PoP admission + decide/seal) and independent TCT
verification; ``Agent`` holds the agent seed. The crypto is pure stock Ed25519/SHA-256/JOSE — conformance
vectors generated from the Rust runtime pin the exact bytes (see ``conformance/vectors.json``).
"""

from . import aio
from ._authorize import AuthorizeResult
from .admin import KNOWN_KINDS, SeamAdminClient, verify_streamed_record_digest
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
    jcs_canonicalize,
    tool_input_digest,
    verify_tct,
)
from .errors import (
    AlreadyExistsError,
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
    UnknownVerdictError,
)

__all__ = [
    "Agent",
    "SeamClient",
    "SeamAdminClient",
    "BudgetLimits",
    "StepUsage",
    "aio",
    "aid_from_pubkey",
    "build_presentation",
    "verify_tct",
    # Advisory authorization (Authorize verb)
    "AuthorizeResult",
    "DEFAULT_TIMEOUT_S",
    "jcs_canonicalize",
    "tool_input_digest",
    "call_sig",
    # Streamed-event surface (A14)
    "KNOWN_KINDS",
    "verify_streamed_record_digest",
    # Error taxonomy
    "SeamError",
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
]
