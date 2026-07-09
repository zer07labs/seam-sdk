"""Seam SDK for Python — generated gRPC transport + a stock-crypto client shim.

``SeamClient`` owns the binding path (pinned-key PoP admission + decide/seal) and independent TCT
verification; ``Agent`` holds the agent seed. The crypto is pure stock Ed25519/SHA-256/JOSE — conformance
vectors generated from the Rust runtime pin the exact bytes (see ``conformance/vectors.json``).
"""

from .client import Agent, IssuerMismatchError, SeamClient, SeamError
from .crypto import aid_from_pubkey, build_presentation, verify_tct

__all__ = [
    "Agent",
    "SeamClient",
    "SeamError",
    "IssuerMismatchError",
    "aid_from_pubkey",
    "build_presentation",
    "verify_tct",
]
