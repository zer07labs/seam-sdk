"""Seam SDK error taxonomy.

``SeamError`` is the base of everything the SDK raises. ``IssuerMismatchError`` is the one *client-side*
semantic error (a key-substitution signal from ``verify_decision``). Server-returned gRPC failures are
mapped to typed ``SeamRpcError`` subclasses keyed by status code — but each is **also** a
``grpc.RpcError`` with the usual ``.code()``/``.details()``, so existing ``except grpc.RpcError`` handlers
and ``.code()`` checks keep working unchanged. This is purely additive.
"""

from __future__ import annotations

import grpc


class SeamError(Exception):
    """Base class for all Seam SDK errors."""


class IssuerMismatchError(SeamError):
    """The fetched proof's issuer AID does not match the issuer the caller pinned out of band.

    Raised by :meth:`SeamClient.verify_decision`. This is a **distinct security signal** — a malicious
    server attempting to substitute its own issuer key — and must never be conflated with an ordinary
    cryptographically-invalid decision (which returns ``False``). Mirrors the Rust reference
    (``ClientError::Crypto("issuer AID mismatch…")``).
    """

    def __init__(self, proof_issuer: str, expected_issuer: str):
        self.proof_issuer = proof_issuer
        self.expected_issuer = expected_issuer
        super().__init__(
            f"issuer AID mismatch: proof carried {proof_issuer!r}, expected {expected_issuer!r}"
        )


class SeamRpcError(SeamError, grpc.RpcError):
    """A server-returned gRPC error, typed by status code.

    Subclasses :class:`SeamError` **and** ``grpc.RpcError`` — so it is catchable as either, and exposes the
    standard ``code()``/``details()`` accessors. Prefer catching a specific subclass
    (e.g. :class:`PermissionDeniedError`); the raw ``except grpc.RpcError`` still works too.
    """

    def __init__(self, code: grpc.StatusCode, details: str):
        self._code = code
        self._details = details
        super().__init__(f"{code.name}: {details}" if details else code.name)

    def code(self) -> grpc.StatusCode:
        return self._code

    def details(self) -> str:
        return self._details


class InvalidArgumentError(SeamRpcError):
    """`INVALID_ARGUMENT` — e.g. an empty erasure ``tenant`` or a wrong ``confirm_count``."""


class FailedPreconditionError(SeamRpcError):
    """`FAILED_PRECONDITION`."""


class PermissionDeniedError(SeamRpcError):
    """`PERMISSION_DENIED` — e.g. a session scope-floor denial (distinct from `INVALID_ARGUMENT`)."""


class UnauthenticatedError(SeamRpcError):
    """`UNAUTHENTICATED` — a missing or invalid management operator token."""


class NotFoundError(SeamRpcError):
    """`NOT_FOUND` — e.g. an unknown decision id."""


class AlreadyExistsError(SeamRpcError):
    """`ALREADY_EXISTS`."""


class ResourceExhaustedError(SeamRpcError):
    """`RESOURCE_EXHAUSTED` — e.g. an erasure exceeding the per-call cap."""


class UnavailableError(SeamRpcError):
    """`UNAVAILABLE` — transport/server not reachable."""


class DeadlineExceededError(SeamRpcError):
    """`DEADLINE_EXCEEDED`."""


class UnimplementedError(SeamRpcError):
    """`UNIMPLEMENTED` — e.g. a management RPC invoked on the data plane."""


class InternalError(SeamRpcError):
    """`INTERNAL` and any other/unknown status."""


_BY_CODE = {
    grpc.StatusCode.INVALID_ARGUMENT: InvalidArgumentError,
    grpc.StatusCode.FAILED_PRECONDITION: FailedPreconditionError,
    grpc.StatusCode.PERMISSION_DENIED: PermissionDeniedError,
    grpc.StatusCode.UNAUTHENTICATED: UnauthenticatedError,
    grpc.StatusCode.NOT_FOUND: NotFoundError,
    grpc.StatusCode.ALREADY_EXISTS: AlreadyExistsError,
    grpc.StatusCode.RESOURCE_EXHAUSTED: ResourceExhaustedError,
    grpc.StatusCode.UNAVAILABLE: UnavailableError,
    grpc.StatusCode.DEADLINE_EXCEEDED: DeadlineExceededError,
    grpc.StatusCode.UNIMPLEMENTED: UnimplementedError,
    grpc.StatusCode.INTERNAL: InternalError,
}


def map_rpc_error(exc: grpc.RpcError) -> SeamRpcError:
    """Map a raw ``grpc.RpcError`` to the typed :class:`SeamRpcError` subclass for its status code.
    Already-typed errors pass through unchanged (so mapping is idempotent)."""
    if isinstance(exc, SeamRpcError):
        return exc
    code = (
        exc.code() if callable(getattr(exc, "code", None)) else grpc.StatusCode.UNKNOWN
    )
    details = (exc.details() if callable(getattr(exc, "details", None)) else "") or ""
    return _BY_CODE.get(code, InternalError)(code, details)


class _MappedStub:
    """Wrap a blocking gRPC stub so unary calls raise the typed :class:`SeamRpcError` for their status
    code (still a ``grpc.RpcError``). Streaming responses pass through — the caller maps iteration
    errors (they surface while consuming the stream, not at call time)."""

    def __init__(self, stub):
        object.__setattr__(self, "_stub", stub)

    def __getattr__(self, name):
        attr = getattr(self._stub, name)
        if not callable(attr):
            return attr

        def call(*args, **kwargs):
            try:
                return attr(*args, **kwargs)
            except grpc.RpcError as e:
                raise map_rpc_error(e) from e

        return call
