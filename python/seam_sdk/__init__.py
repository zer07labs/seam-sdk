"""Seam SDK for Python — generated gRPC transport + a stock-crypto client shim.

``SeamClient`` owns the binding path (pinned-key PoP admission + decide/seal) and independent TCT
verification; ``Agent`` holds the agent seed. The crypto is pure stock Ed25519/SHA-256/JOSE — conformance
vectors generated from the Rust runtime pin the exact bytes (see ``conformance/vectors.json``).
"""

from .admin import SeamAdminClient
from .client import (
    Agent,
    BudgetLimits,
    SeamClient,
    StepUsage,
)
from .crypto import aid_from_pubkey, build_presentation, verify_tct
from .errors import (
    AlreadyExistsError,
    DeadlineExceededError,
    FailedPreconditionError,
    InternalError,
    InvalidArgumentError,
    IssuerMismatchError,
    NotFoundError,
    PermissionDeniedError,
    ResourceExhaustedError,
    SeamError,
    SeamRpcError,
    UnauthenticatedError,
    UnavailableError,
    UnimplementedError,
)

__all__ = [
    "Agent",
    "SeamClient",
    "SeamAdminClient",
    "BudgetLimits",
    "StepUsage",
    "aid_from_pubkey",
    "build_presentation",
    "verify_tct",
    # Error taxonomy
    "SeamError",
    "IssuerMismatchError",
    "SeamRpcError",
    "InvalidArgumentError",
    "FailedPreconditionError",
    "PermissionDeniedError",
    "UnauthenticatedError",
    "NotFoundError",
    "AlreadyExistsError",
    "ResourceExhaustedError",
    "UnavailableError",
    "DeadlineExceededError",
    "UnimplementedError",
    "InternalError",
]
