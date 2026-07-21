"""Seam management-plane client (``SeamAdmin``) — GDPR erasure + governance.

The admin surface lives on a **separate management listener** (``SEAM_GRPC_MGMT_LISTEN``), never the data
plane, and is gated by an **operator token** — a compact-JWS credential the control plane mints against the
runtime's installed ``operator_keys`` trust root, enforcing a per-verb scope (the deprecated shared
``SEAM_MGMT_TOKEN`` bearer was removed in seam-runtime #175). This client is token-agnostic: when a token is
supplied it attaches ``authorization: Bearer <token>`` metadata on every call (via a channel interceptor,
so it works over the dev plaintext channel too). With the runtime in ``SEAM_DEV_INSECURE`` mode and no
``operator_keys`` root installed, the plane is dev-open and the token may be omitted.

Erasure is a **preview → confirm → erase** flow (runtime audit P0.1): ``preview_erasure`` is non-destructive;
``erase_subject`` requires a non-empty ``tenant`` scope and a ``confirm_count`` that must equal the preview's
``would_erase`` count. ``erase_subject_confirmed`` is the common, safe path that does both.
"""

from __future__ import annotations

import collections
from typing import Iterator, Optional, Sequence

import grpc

# Importing the client module first ensures the generated `_gen` dir is on `sys.path` (client.py does the
# path insertion at import time), so `from seam.api.v1 import ...` resolves here too.
from . import client as _client  # noqa: F401
from seam.api.v1 import seam_pb2 as pb  # noqa: E402
from seam.api.v1 import seam_pb2_grpc as rpc  # noqa: E402

from .errors import _MappedStub, map_rpc_error  # noqa: E402
from .crypto import record_digest_v2  # noqa: E402

__all__ = [
    "SeamAdminClient",
    "KNOWN_KINDS",
    "verify_streamed_record_digest",
]

# The `seam-event.v1` kinds the SDK knows about. A consumer MAY use this to branch on typed payloads, but
# MUST still tolerate an unknown kind (the wire is a tolerant reader — new kinds are additive): iterate
# `stream_events` and pass anything not in this set through opaque, never erroring on it.
KNOWN_KINDS = frozenset(
    {
        "DECISION_SEALED",
        "LEARNING_DECISION",
        "LEARNING_OUTCOME",
        "AUDIT_ENTRY",
        "BUDGET_BREACH",
        "ERASURE_CERTIFICATE",
        "SESSION_LIFECYCLE",
        "CHAIN_HEAD_ATTESTATION",
    }
)


def verify_streamed_record_digest(event: pb.SeamEvent) -> bool:
    """Recompute a streamed v2 ``DECISION_SEALED``'s record digest from its payload (+ ``ciphertext_digest``,
    tag 10) and compare it to the wire ``digest`` (tag 19) — live authenticity for a single record, the
    in-client counterpart of ``seam-verify chain --issuer``'s design-a. Returns ``True`` iff they match;
    ``False`` for a rewritten payload or a v2 record stripped of its ``ciphertext_digest``.

    Raises :class:`ValueError` for anything not stream-recomputable: a non-``DECISION_SEALED`` event, a v1
    record (the historical digest is not recomputable from the wire), or an event with no wire digest. The
    presence of ``mode``/``policy_version``/``supersedes`` is read via ``HasField`` so ``None`` and ``""``
    stay distinct — the framing requires it."""
    if event.kind != "DECISION_SEALED":
        raise ValueError(f"not a DECISION_SEALED event: {event.kind}")
    p = event.payload
    if p.schema_version < 2:
        raise ValueError(
            f"v{p.schema_version} record is not stream-recomputable (only v2+)"
        )
    if not event.HasField("digest"):
        raise ValueError("event carries no wire digest to compare against")
    if not p.ciphertext_digest:
        return False  # a v2 record with no ciphertext_digest is a strip/downgrade — never a match
    recomputed = record_digest_v2(
        p.decision_id,
        p.tenant,
        p.namespace,
        bytes(p.ciphertext_digest),
        p.sealed_at,
        p.outcome,
        p.mode if p.HasField("mode") else None,
        p.policy_version if p.HasField("policy_version") else None,
        p.supersedes if p.HasField("supersedes") else None,
        p.schema_version,
    )
    return recomputed == bytes(event.digest)


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
        self._admin = _MappedStub(rpc.SeamAdminStub(channel))
        # Streaming stub for the governance outbox; iteration errors are mapped in stream_events.
        self._events = rpc.SeamEventsStub(channel)

    @classmethod
    def connect(
        cls,
        target: str,
        *,
        token: Optional[str] = None,
        credentials: Optional[grpc.ChannelCredentials] = None,
    ) -> "SeamAdminClient":
        """Connect to a Seam **management** endpoint (``SEAM_GRPC_MGMT_LISTEN``, distinct from the data
        plane). ``token`` is a control-plane-minted **operator token**; when set, every call carries
        ``authorization: Bearer <token>``. Omit it only against a dev-open server (``SEAM_DEV_INSECURE`` with
        no ``operator_keys`` root installed). Plaintext by default; pass
        ``credentials=grpc.ssl_channel_credentials()`` for TLS (recommended whenever a real operator token is
        in play, so it isn't sent over cleartext)."""
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

    # ── Session governance ───────────────────────────────────────────────────────────────────────

    def resume_session(
        self,
        session_id: str,
        approver: str,
        *,
        tenant: str = "",
        namespace: str = "",
        budget: int = 32,
        raise_: Optional["_client.BudgetLimits"] = None,
    ) -> pb.SessionStep:
        """Resume a Suspended session — the R9 approver action, on the **management** plane (rt-D: this
        moved off the data plane, where ``SeamCoordination.ResumeSession`` is now a tombstone). It requires
        the ``session:resume`` operator scope. ``approver`` is a **required**, non-empty attribution for the
        approval (an R9 approval must name who granted it). ``raise_`` raises any budget dimension; absent,
        ``budget`` raises the message count. ``tenant``/``namespace`` scope the lookup — leave empty to
        resolve the session by id alone."""
        req = pb.AdminResumeRequest(
            session_id=session_id,
            approver=approver,
            tenant=tenant,
            namespace=namespace,
            budget=budget,
        )
        if raise_ is not None:
            # `raise` is a Python keyword, so the generated field is reached via getattr.
            getattr(req, "raise").CopyFrom(raise_.to_pb())
        return self._admin.ResumeSession(req)

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

    # ── Governance event stream (seam-event.v1 outbox) ───────────────────────────────────────────

    def stream_events(
        self, *, from_seq: int = 0, follow: bool = False, ack: bool = False
    ) -> Iterator[pb.SeamEvent]:
        """Server-stream the ``seam-event.v1`` governance outbox. Two modes:

        * **drain** (``follow=False``, default): yield the current unpublished backlog, then stop.
          ``ack=True`` marks exactly the yielded rows published (the at-least-once relay watermark);
          ``from_seq`` is advisory in this mode.
        * **live tail** (``follow=True``): yield the backlog from ``from_seq``, then keep yielding new
          events as they arrive — cursor-based, never acks. Resume from the last ``seq + 1`` and dedup
          by ``event_id``. The stream ends cleanly when the server drains on shutdown.

        Yields :class:`pb.SeamEvent`. Iterate in a thread/task for ``follow=True`` (it blocks)."""
        req = pb.StreamEventsRequest(from_seq=from_seq, ack=ack, follow=follow)
        try:
            for event in self._events.StreamEvents(req):
                yield event
        except grpc.RpcError as e:
            raise map_rpc_error(e) from e
