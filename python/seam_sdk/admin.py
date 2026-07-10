"""Seam management-plane client (``SeamAdmin``) — GDPR erasure + governance.

The admin surface lives on a **separate management listener** (``SEAM_GRPC_MGMT_LISTEN``), never the data
plane, and is gated by a bearer token (``SEAM_MGMT_TOKEN``). This client targets that endpoint and, when a
token is supplied, attaches ``authorization: Bearer <token>`` metadata on every call (via a channel
interceptor, so it works over the dev plaintext channel too). With the runtime in ``SEAM_DEV_INSECURE`` mode
and no token configured, the plane is unauthenticated and the token may be omitted.

Erasure is a **preview → confirm → erase** flow (runtime audit P0.1): ``preview_erasure`` is non-destructive;
``erase_subject`` requires a non-empty ``tenant`` scope and a ``confirm_count`` that must equal the preview's
``would_erase`` count. ``erase_subject_confirmed`` is the common, safe path that does both.
"""

from __future__ import annotations

import collections
from typing import Optional, Sequence

import grpc

# Importing the client module first ensures the generated `_gen` dir is on `sys.path` (client.py does the
# path insertion at import time), so `from seam.api.v1 import ...` resolves here too.
from . import client as _client  # noqa: F401
from seam.api.v1 import seam_pb2 as pb  # noqa: E402
from seam.api.v1 import seam_pb2_grpc as rpc  # noqa: E402

__all__ = ["SeamAdminClient"]


class _ClientCallDetails(
    collections.namedtuple(
        "_ClientCallDetails",
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
    """Mutable-metadata view of a call's details, so the interceptor can append the bearer header."""


class _BearerAuthInterceptor(
    grpc.UnaryUnaryClientInterceptor, grpc.UnaryStreamClientInterceptor
):
    """Attach ``authorization: Bearer <token>`` to every call. Works with an *insecure* channel (grpc's
    ``CallCredentials`` require TLS; a client interceptor does not), which the dev/loopback path needs."""

    def __init__(self, token: str):
        self._header = ("authorization", f"Bearer {token}")

    def _with_auth(self, details: grpc.ClientCallDetails) -> _ClientCallDetails:
        metadata = list(details.metadata or [])
        metadata.append(self._header)
        return _ClientCallDetails(
            details.method,
            details.timeout,
            metadata,
            details.credentials,
            details.wait_for_ready,
            details.compression,
        )

    def intercept_unary_unary(self, continuation, details, request):
        return continuation(self._with_auth(details), request)

    def intercept_unary_stream(self, continuation, details, request):
        return continuation(self._with_auth(details), request)


class SeamAdminClient:
    """High-level client over the ``SeamAdmin`` management-plane service."""

    def __init__(self, channel: grpc.Channel):
        self._ch = channel
        self._admin = rpc.SeamAdminStub(channel)

    @classmethod
    def connect(
        cls,
        target: str,
        *,
        token: Optional[str] = None,
        credentials: Optional[grpc.ChannelCredentials] = None,
    ) -> "SeamAdminClient":
        """Connect to a Seam **management** endpoint (``SEAM_GRPC_MGMT_LISTEN``, distinct from the data
        plane). When ``token`` is set, every call carries ``authorization: Bearer <token>``; omit it only
        against a dev server running unauthenticated (``SEAM_DEV_INSECURE`` with no ``SEAM_MGMT_TOKEN``).
        Plaintext by default; pass ``credentials=grpc.ssl_channel_credentials()`` for TLS (recommended
        whenever a real bearer token is in play, so it isn't sent over cleartext)."""
        channel = (
            grpc.secure_channel(target, credentials)
            if credentials is not None
            else grpc.insecure_channel(target)
        )
        if token:
            channel = grpc.intercept_channel(channel, _BearerAuthInterceptor(token))
        return cls(channel)

    # ── GDPR erasure (preview → confirm → erase) ─────────────────────────────────────────────────

    def preview_erasure(self, tenant: str, subject: str) -> pb.ErasurePreview:
        """Non-destructive: what WOULD be crypto-shredded (``would_erase``), what a legal hold pins
        (``held``), and what is already shredded (``already_erased``) for ``subject`` in ``tenant``."""
        return self._admin.PreviewErasure(
            pb.ErasureRequest(subject=subject, tenant=tenant)
        )

    def erase_subject(
        self, tenant: str, subject: str, confirm_count: int
    ) -> pb.ErasureCertificate:
        """Crypto-shred every record bound to ``subject`` in ``tenant`` and return the signed,
        chain-anchored certificate. ``tenant`` is REQUIRED (empty ⇒ server rejects); ``confirm_count``
        MUST equal the preview's ``len(would_erase)`` or the server rejects (``INVALID_ARGUMENT``)."""
        return self._admin.EraseSubject(
            pb.ErasureRequest(
                subject=subject, tenant=tenant, confirm_count=confirm_count
            )
        )

    def erase_subject_confirmed(
        self, tenant: str, subject: str
    ) -> pb.ErasureCertificate:
        """The common, safe path: preview, then erase with the preview's ``would_erase`` count."""
        preview = self.preview_erasure(tenant, subject)
        return self.erase_subject(tenant, subject, len(preview.would_erase))

    # ── Governance / tenancy ─────────────────────────────────────────────────────────────────────

    def enroll_tenant(
        self, subject_aid: str, tenant: str, namespace: str
    ) -> pb.TenantView:
        return self._admin.EnrollTenant(
            pb.EnrollTenantRequest(
                subject_aid=subject_aid, tenant=tenant, namespace=namespace
            )
        )

    def list_tenants(self) -> Sequence[pb.TenantView]:
        return list(self._admin.ListTenants(pb.Empty()).tenants)

    def register_party(self, party_id: str, pubkey: bytes) -> None:
        """Register a counterparty's raw 32-byte ed25519 public key (network mode)."""
        self._admin.RegisterParty(
            pb.RegisterPartyRequest(party_id=party_id, pubkey=pubkey)
        )

    # ── Retention & legal hold ───────────────────────────────────────────────────────────────────

    def place_legal_hold(self, decision_id: str) -> None:
        self._admin.PlaceLegalHold(pb.DecisionRef(decision_id=decision_id))

    def release_legal_hold(self, decision_id: str) -> None:
        self._admin.ReleaseLegalHold(pb.DecisionRef(decision_id=decision_id))

    def enforce_retention(
        self,
        full_days: int,
        sealed_digest_days: int,
        commitment_only_days: int,
        *,
        now_millis: Optional[int] = None,
    ) -> Sequence[str]:
        """Crypto-shred decisions past their tiered retention windows; returns the purged decision ids."""
        req = pb.RetentionRequest(
            full_days=full_days,
            sealed_digest_days=sealed_digest_days,
            commitment_only_days=commitment_only_days,
        )
        if now_millis is not None:
            req.now_millis = now_millis
        return list(self._admin.EnforceRetention(req).purged)

    def audit_trail(self) -> Sequence[pb.AuditEntry]:
        return list(self._admin.AuditTrail(pb.Empty()).entries)
