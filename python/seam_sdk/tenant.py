"""The ``x-seam-tenant`` routing hint on every data-plane call (seam-runtime k8s P15, D123).

``seam-cell-router`` routes each ``seam.api.v1`` call to the cell where the caller's tenant lives.
``IssueChallenge``, ``Admit`` and ``RunDecision`` carry no tenant before authentication, so the router
reads it from this header — on **every** call, those included. It is a routing hint, never authority:
the cell still derives the tenant from identity and refuses a call that reached the wrong cell with
``FAILED_PRECONDITION`` reason ``WRONG_CELL`` (:data:`seam_sdk.errors.WRONG_CELL_REASON`).

A client connected straight to its cell (no router in front) needs none of this, and a client built
without ``tenant=`` sends exactly what it sent before. :meth:`SeamClient.connect(..., tenant=...)
<seam_sdk.client.SeamClient.connect>` installs the interceptor; a caller that builds its own channel
installs :class:`TenantInterceptor` (``grpc.intercept_channel``) or :class:`AioTenantInterceptor`
(``grpc.aio.*_channel(..., interceptors=[...])``) itself.
"""

from __future__ import annotations

import collections

import grpc

#: The request header ``seam-cell-router`` routes on (D123). Shared with legal-hold's placer-named
#: tenant on the management plane (runtime #1037), which is a different, per-call use of the name.
TENANT_HEADER = "x-seam-tenant"


class _CallDetails(
    collections.namedtuple(
        "_CallDetails",
        (
            "method",
            "timeout",
            "metadata",
            "credentials",
            "wait_for_ready",
            "compression",
        ),
    ),
    grpc.ClientCallDetails,
):
    """A sync call's details with the metadata replaced (grpc's own type is not constructible)."""


def _require_tenant(tenant: str) -> str:
    # Refused here rather than sent: the router refuses a missing or malformed value uniformly, and
    # an empty header would read there as a caller that meant to route and named nothing.
    if not isinstance(tenant, str) or not tenant:
        raise ValueError(
            "tenant must be this caller's enrolled tenant id (a non-empty string); "
            "omit it entirely to send no x-seam-tenant header"
        )
    return tenant


def _with_tenant(metadata, tenant: str) -> list:
    # A call that already names the header keeps its own value: the interceptor fills a gap, it
    # never rewrites what a caller sent on purpose.
    pairs = list(metadata or ())
    if not any(k == TENANT_HEADER for k, _ in pairs):
        pairs.append((TENANT_HEADER, tenant))
    return pairs


class TenantInterceptor(
    grpc.UnaryUnaryClientInterceptor,
    grpc.UnaryStreamClientInterceptor,
    grpc.StreamUnaryClientInterceptor,
    grpc.StreamStreamClientInterceptor,
):
    """Attach ``x-seam-tenant: <tenant>`` to every call on a sync channel, all four call shapes:
    ``grpc.intercept_channel(channel, TenantInterceptor("acme"))``."""

    def __init__(self, tenant: str):
        self.tenant = _require_tenant(tenant)

    def _details(self, details: grpc.ClientCallDetails):
        return _CallDetails(
            details.method,
            details.timeout,
            _with_tenant(details.metadata, self.tenant),
            details.credentials,
            details.wait_for_ready,
            details.compression,
        )

    def intercept_unary_unary(self, continuation, details, request):
        return continuation(self._details(details), request)

    def intercept_unary_stream(self, continuation, details, request):
        return continuation(self._details(details), request)

    def intercept_stream_unary(self, continuation, details, request_iterator):
        return continuation(self._details(details), request_iterator)

    def intercept_stream_stream(self, continuation, details, request_iterator):
        return continuation(self._details(details), request_iterator)


class AioTenantInterceptor(
    grpc.aio.UnaryUnaryClientInterceptor,
    grpc.aio.UnaryStreamClientInterceptor,
    grpc.aio.StreamUnaryClientInterceptor,
    grpc.aio.StreamStreamClientInterceptor,
):
    """:class:`TenantInterceptor` for ``grpc.aio``, passed at channel construction:
    ``grpc.aio.insecure_channel(target, interceptors=[AioTenantInterceptor("acme")])``."""

    def __init__(self, tenant: str):
        self.tenant = _require_tenant(tenant)

    def _details(self, details):
        return details._replace(
            metadata=grpc.aio.Metadata(*_with_tenant(details.metadata, self.tenant))
        )

    async def intercept_unary_unary(self, continuation, details, request):
        return await continuation(self._details(details), request)

    async def intercept_unary_stream(self, continuation, details, request):
        return await continuation(self._details(details), request)

    async def intercept_stream_unary(self, continuation, details, request_iterator):
        return await continuation(self._details(details), request_iterator)

    async def intercept_stream_stream(self, continuation, details, request_iterator):
        return await continuation(self._details(details), request_iterator)
