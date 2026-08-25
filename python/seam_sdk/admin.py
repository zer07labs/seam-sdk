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
from typing import Callable, Iterator, Optional, Sequence

import grpc

from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc
from seam_sdk._gen.seam.event.v1 import seam_event_pb2 as ev

from . import client as _client  # noqa: TC001 — referenced by the `raise_` annotation below
from .errors import _MappedStub, map_rpc_error
from .crypto import record_digest_v2, record_digest_v3  # noqa: E402

# Management-plane calls get their own, larger default deadline — but they DO get one.
#
# Every method here used to have none at all, including `erase_subject`, which crypto-shreds a
# subject's records. An unbounded destructive RPC is not a conservative choice: a stalled call to a
# wedged management plane hangs the operator's process forever with no way to know whether the
# erasure landed, and an interactive operator's instinct is to Ctrl-C and re-run — against a server
# that may still be working. A generous, overridable deadline is strictly better than none.
#
# 30s rather than the data plane's 2s because these are operator-cadence, not hot-path: erasure and
# retention enforcement do real work over potentially many records. Pass `timeout=` to widen it for a
# large tenant; the point is that the number exists and the caller owns it.
DEFAULT_ADMIN_TIMEOUT_S = 30.0

__all__ = [
    "SeamAdminClient",
    "EventStream",
    "KNOWN_KINDS",
    "DEFAULT_ADMIN_TIMEOUT_S",
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
        "AUTHORIZE_EVALUATED",
    }
)


def verify_streamed_record_digest(event: ev.SeamEvent) -> bool:
    """Recompute a streamed ``DECISION_SEALED``'s record digest from its payload and compare it to the wire
    ``digest`` (tag 19) — live authenticity for a single record, the in-client counterpart of
    ``seam-verify chain --issuer``'s design-a. Handles ``schema_version`` 2 and 3. Returns ``True`` iff they
    match; ``False`` for a rewritten payload or a record stripped of its ``ciphertext_digest`` (tag 10).

    Raises :class:`ValueError` for anything not stream-recomputable: a non-``DECISION_SEALED`` event, a v1
    record (the historical digest is not recomputable from the wire), a schema version NEWER than v3 (a
    future framing this SDK does not know; recomputing it with a known domain tag would report a spurious
    ``False`` on a genuine record), or an event with no wire digest.

    Raises :class:`~seam_sdk.crypto.RecordDigestStripError` — a ``ValueError`` subclass, and deliberately
    **not** a ``False`` — when a v3 record is missing ``context_digest`` (tag 11) or ``participation_digest``
    (tag 12). The spec requires a strip to be reported distinctly from a digest mismatch; that distinction
    is enforced in :func:`~seam_sdk.crypto.record_digest_v3`, and this helper's job is to hand it the wire
    values unaltered rather than to re-implement the check beside it.

    **Presence on tags 10-13 is length, not ``HasField``.** All four digest fields are singular proto3
    ``bytes``, so no presence bit is generated and ``HasField`` raises on them. ``seam-event.v1.md``
    §"Presence on the wire" pins the consumer rule as a total mapping — ``len == 0`` means absent however
    the bytes arose, including an explicitly-encoded zero-length field from a non-conforming producer,
    which proto3 obliges a decoder to accept. ``mode``/``policy_version``/``supersedes`` (tags 4/5/7) are
    the opposite case: they *are* ``optional``, because the empty string is a real value there, so those
    keep ``HasField`` and ``None`` stays distinct from ``""``.

    The tag-13 mapping is the one that would silently corrupt a verdict if skipped: an absent
    ``policy_rules_digest`` is a legitimate state framing as ``opt(None)`` (one byte), while the decoded
    empty value passed through as-is would frame ``opt(Some(b""))`` (five bytes) and report a mismatch on a
    genuine record. Tags 11/12 need no mapping — passing the empty value through is precisely what raises
    the strip error."""
    if event.kind != "DECISION_SEALED":
        raise ValueError(f"not a DECISION_SEALED event: {event.kind}")
    p = event.payload
    if p.schema_version < 2:
        raise ValueError(
            f"v{p.schema_version} record is not stream-recomputable by this SDK (only v2 and v3)"
        )
    if p.schema_version > 3:
        raise ValueError(
            f"v{p.schema_version} record is not stream-recomputable by this SDK "
            f"(knows v2 and v3); upgrade the SDK"
        )
    if not event.HasField("digest"):
        raise ValueError("event carries no wire digest to compare against")
    if not p.ciphertext_digest:
        # A tag-10 strip. Spec §Ordering & integrity Verification (c) makes this a REFUSE for every
        # schema_version >= 2 — i.e. the record fails, which for a helper answering "does this verify?"
        # is exactly `False`. Unlike tags 11/12, the spec attaches no distinct-reporting requirement to
        # tag 10, so this stays the boolean it has always been rather than becoming an exception.
        #
        # This check precedes the v3 arm, so a v3 record stripped of tags 10 AND 11/12 reports `False`
        # rather than the strip raise — an adversary who strips both gets the quieter diagnostic. That
        # is deliberate and not a hole: the record still FAILS either way, and tag 10's rule is the
        # older and broader one (every v2+ record), so it is the right thing to answer first.
        return False
    mode = p.mode if p.HasField("mode") else None
    policy_version = p.policy_version if p.HasField("policy_version") else None
    supersedes = p.supersedes if p.HasField("supersedes") else None

    if p.schema_version == 3:
        policy_rules = bytes(p.policy_rules_digest)
        recomputed = record_digest_v3(
            p.decision_id,
            p.tenant,
            p.namespace,
            bytes(p.ciphertext_digest),
            p.sealed_at,
            p.outcome,
            mode,
            policy_version,
            supersedes,
            bytes(p.context_digest),
            bytes(p.participation_digest),
            policy_rules if policy_rules else None,  # len == 0 ⇒ absent ⇒ opt(None)
            p.schema_version,
        )
    else:
        recomputed = record_digest_v2(
            p.decision_id,
            p.tenant,
            p.namespace,
            bytes(p.ciphertext_digest),
            p.sealed_at,
            p.outcome,
            mode,
            policy_version,
            supersedes,
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


class EventStream:
    """One ``StreamEvents`` call: iterable like the generator it replaced, plus deliberate cancellation.

    **Lazy**, exactly as the generator was: nothing is sent — the RPC, and with it any ``ack`` — until
    the first iteration. Iteration errors surface typed (:class:`~seam_sdk.errors.SeamRpcError`), at
    iteration time, unchanged.

    :meth:`cancel` is the deliberate way OUT of a ``follow=True`` live tail, which otherwise ends only
    when the server drains on shutdown. After ``cancel()`` the iteration ends cleanly (``StopIteration``,
    not an error — the caller asked for it); called before the first iteration, the RPC is never sent
    at all."""

    def __init__(self, start: Callable[[], Iterator[ev.SeamEvent]]):
        self._start = start
        self._call = None
        self._cancelled = False

    def __iter__(self) -> "EventStream":
        return self

    def __next__(self) -> ev.SeamEvent:
        if self._call is None:
            if self._cancelled:
                raise StopIteration
            self._call = self._start()
        try:
            return next(self._call)
        except grpc.RpcError as e:
            code = e.code() if callable(getattr(e, "code", None)) else None
            if self._cancelled and code is grpc.StatusCode.CANCELLED:
                # Our own deliberate cancel coming back around — a clean end, never an error.
                raise StopIteration from None
            raise map_rpc_error(e) from e

    def cancel(self) -> bool:
        """Cancel the underlying RPC (ending a live tail deliberately). Idempotent. Returns whether
        the cancellation took — always ``True`` before the first iteration (the RPC is then simply
        never sent)."""
        self._cancelled = True
        if self._call is not None:
            return self._call.cancel()
        return True


class SeamAdminClient:
    """High-level client over the ``SeamAdmin`` management-plane service."""

    def __init__(self, channel: grpc.Channel):
        self._ch = channel
        self._admin = _MappedStub(rpc.SeamAdminStub(channel))
        # Streaming stub for the governance outbox; iteration errors are mapped in stream_events.
        self._events = rpc.SeamEventsStub(channel)

    def close(self) -> None:
        """Close the underlying channel. Idempotent — grpc tolerates a repeated close."""
        self._ch.close()

    def __enter__(self) -> "SeamAdminClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

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

    def preview_erasure(
        self, tenant: str, subject: str, *, timeout: float = DEFAULT_ADMIN_TIMEOUT_S
    ) -> pb.ErasurePreview:
        """Non-destructive: what WOULD be crypto-shredded (``would_erase``), what a legal hold pins
        (``held``), and what is already shredded (``already_erased``) for ``subject`` in ``tenant``."""
        return self._admin.PreviewErasure(
            pb.ErasureRequest(subject=subject, tenant=tenant), timeout=timeout
        )

    def erase_subject(
        self,
        tenant: str,
        subject: str,
        confirm_count: int,
        *,
        now_millis: Optional[int] = None,
        timeout: float = DEFAULT_ADMIN_TIMEOUT_S,
    ) -> ev.ErasureCertificate:
        """Crypto-shred every record bound to ``subject`` in ``tenant`` and return the signed,
        chain-anchored certificate. ``tenant`` is REQUIRED (empty ⇒ server rejects); ``confirm_count``
        MUST equal the preview's ``len(would_erase)`` or the server rejects (``INVALID_ARGUMENT``).
        ``now_millis`` overrides the injected run time (default: the server clock) — mirrors
        ``enforce_retention``'s identical field."""
        req = pb.ErasureRequest(
            subject=subject, tenant=tenant, confirm_count=confirm_count
        )
        if now_millis is not None:
            req.now_millis = now_millis
        return self._admin.EraseSubject(req, timeout=timeout)

    def erase_subject_confirmed(
        self,
        tenant: str,
        subject: str,
        *,
        now_millis: Optional[int] = None,
        timeout: float = DEFAULT_ADMIN_TIMEOUT_S,
    ) -> ev.ErasureCertificate:
        """The common, safe path: preview, then erase with the preview's ``would_erase`` count.

        ``timeout`` applies to EACH of the two calls, not to the pair — so the worst case is 2x it.
        Stated rather than left to be discovered: this is the same arithmetic the adapters'
        SessionBinder documents for its own two-call failure path."""
        preview = self.preview_erasure(tenant, subject, timeout=timeout)
        return self.erase_subject(
            tenant,
            subject,
            len(preview.would_erase),
            now_millis=now_millis,
            timeout=timeout,
        )

    # ── Governance / tenancy ─────────────────────────────────────────────────────────────────────

    def enroll_tenant(
        self,
        subject_aid: str,
        tenant: str,
        namespace: str,
        *,
        timeout: float = DEFAULT_ADMIN_TIMEOUT_S,
    ) -> pb.TenantView:
        """Bind an agent identity to a tenant/namespace."""
        return self._admin.EnrollTenant(
            pb.EnrollTenantRequest(
                subject_aid=subject_aid, tenant=tenant, namespace=namespace
            ),
            timeout=timeout,
        )

    def list_tenants(
        self, *, timeout: float = DEFAULT_ADMIN_TIMEOUT_S
    ) -> Sequence[pb.TenantView]:
        """Every enrolled tenant view."""
        return list(self._admin.ListTenants(pb.Empty(), timeout=timeout).tenants)

    def register_party(
        self, party_id: str, pubkey: bytes, *, timeout: float = DEFAULT_ADMIN_TIMEOUT_S
    ) -> None:
        """Register a counterparty's raw 32-byte ed25519 public key (network mode)."""
        self._admin.RegisterParty(
            pb.RegisterPartyRequest(party_id=party_id, pubkey=pubkey), timeout=timeout
        )

    def remove_party(
        self, party_id: str, *, timeout: float = DEFAULT_ADMIN_TIMEOUT_S
    ) -> None:
        """Revoke a previously-registered party's verifying key (chained + durable). Requires the
        ``grant:revoke`` operator scope."""
        self._admin.RemoveParty(
            pb.RemovePartyRequest(party_id=party_id), timeout=timeout
        )

    # ── Cross-namespace read grants (§D2) ────────────────────────────────────────────────────────

    def place_grant(
        self,
        tenant: str,
        from_ns: str,
        to_ns: str,
        grantor: str,
        expires_at: int,
        *,
        timeout: float = DEFAULT_ADMIN_TIMEOUT_S,
    ) -> None:
        """Grant subjects enrolled in ``from_ns`` read access to ``to_ns`` records of the SAME
        ``tenant`` until ``expires_at`` (unix millis, must be in the future) — cross-tenant reads are
        never grantable. Chained to the audit trail. Requires the ``grant:create`` operator scope."""
        self._admin.PlaceGrant(
            pb.PlaceGrantRequest(
                tenant=tenant,
                from_ns=from_ns,
                to_ns=to_ns,
                grantor=grantor,
                expires_at=expires_at,
            ),
            timeout=timeout,
        )

    def revoke_grant(
        self,
        tenant: str,
        from_ns: str,
        to_ns: str,
        revoker: str,
        *,
        timeout: float = DEFAULT_ADMIN_TIMEOUT_S,
    ) -> None:
        """Revoke a cross-namespace grant (idempotent). Chained to the audit trail. Requires the
        ``grant:revoke`` operator scope."""
        self._admin.RevokeGrant(
            pb.RevokeGrantRequest(
                tenant=tenant, from_ns=from_ns, to_ns=to_ns, revoker=revoker
            ),
            timeout=timeout,
        )

    def list_grants(
        self, *, timeout: float = DEFAULT_ADMIN_TIMEOUT_S
    ) -> Sequence[pb.GrantView]:
        """Every stored cross-namespace grant. Requires the ``grant:revoke`` operator scope."""
        return list(self._admin.ListGrants(pb.Empty(), timeout=timeout).grants)

    # ── Session governance ───────────────────────────────────────────────────────────────────────

    def resume_session(
        self,
        session_id: str,
        approver: str,
        *,
        tenant: str = "",
        namespace: str = "",
        budget: int = 0,
        raise_: Optional["_client.BudgetLimits"] = None,
        timeout: float = DEFAULT_ADMIN_TIMEOUT_S,
    ) -> pb.SessionStep:
        """Resume a Suspended session — the R9 approver action, on the **management** plane (rt-D: this
        moved off the data plane, where ``SeamCoordination.ResumeSession`` is now a tombstone). It requires
        the ``session:resume`` operator scope. ``approver`` is a **required**, non-empty attribution for the
        approval (an R9 approval must name who granted it). ``raise_`` raises any budget dimension; absent,
        ``budget`` raises the message count (0 means the server default, currently 32).
        ``tenant``/``namespace`` scope the lookup — leave empty to resolve the session by id alone."""
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
        return self._admin.ResumeSession(req, timeout=timeout)

    # ── Retention & legal hold ───────────────────────────────────────────────────────────────────

    def place_legal_hold(
        self, decision_id: str, *, timeout: float = DEFAULT_ADMIN_TIMEOUT_S
    ) -> None:
        """Pin a decision against erasure and retention until the hold is released."""
        self._admin.PlaceLegalHold(
            pb.DecisionRef(decision_id=decision_id), timeout=timeout
        )

    def release_legal_hold(
        self, decision_id: str, *, timeout: float = DEFAULT_ADMIN_TIMEOUT_S
    ) -> None:
        """Release a legal hold, making the decision eligible for erasure/retention again."""
        self._admin.ReleaseLegalHold(
            pb.DecisionRef(decision_id=decision_id), timeout=timeout
        )

    def enforce_retention(
        self,
        full_days: int,
        sealed_digest_days: int,
        commitment_only_days: int,
        *,
        now_millis: Optional[int] = None,
        timeout: float = DEFAULT_ADMIN_TIMEOUT_S,
    ) -> Sequence[str]:
        """Crypto-shred decisions past their tiered retention windows; returns the purged decision ids."""
        req = pb.RetentionRequest(
            full_days=full_days,
            sealed_digest_days=sealed_digest_days,
            commitment_only_days=commitment_only_days,
        )
        if now_millis is not None:
            req.now_millis = now_millis
        return list(self._admin.EnforceRetention(req, timeout=timeout).purged)

    def audit_trail(
        self, *, timeout: float = DEFAULT_ADMIN_TIMEOUT_S
    ) -> Sequence[pb.AuditEntry]:
        """The management plane's audit entries."""
        return list(self._admin.AuditTrail(pb.Empty(), timeout=timeout).entries)

    # ── Governance event stream (seam-event.v1 outbox) ───────────────────────────────────────────

    def stream_events(
        self,
        *,
        from_seq: int = 0,
        follow: bool = False,
        ack: bool = False,
        timeout: Optional[float] = None,
    ) -> "EventStream":
        """Server-stream the ``seam-event.v1`` governance outbox. Two modes:

        * **drain** (``follow=False``, default): yield the current unpublished backlog, then stop.
          ``ack=True`` marks exactly the yielded rows published (the at-least-once relay watermark);
          ``from_seq`` is advisory in this mode.
        * **live tail** (``follow=True``): yield the backlog from ``from_seq``, then keep yielding new
          events as they arrive — cursor-based, never acks. Resume from the last ``seq + 1`` and dedup
          by ``event_id``. The stream ends cleanly when the server drains on shutdown.

        ``ack`` is **drain-only** by contract; ``ack=True`` with ``follow=True`` raises
        :class:`ValueError` here rather than sending a request the proto declares meaningless.

        Returns an :class:`EventStream` of :class:`ev.SeamEvent` — iterable exactly like the generator
        it replaced, and **lazy** like it too: NOTHING is sent (the ack included) until the first
        iteration, so constructing the stream commits to nothing. The handle adds :meth:`EventStream.cancel`
        for deliberately ending a live tail. Iterate in a thread/task for ``follow=True`` (it blocks).

        ``timeout`` defaults to ``None`` — **no deadline** — and that is the one deliberate exception
        to this client's every-call-is-bounded rule. A gRPC deadline bounds the whole STREAM, not the
        gap between events, so any finite value silently kills a healthy live tail the moment it
        outlives the number. Set it only for a bounded drain (``follow=False``), where "this should
        have finished by now" is a meaningful statement."""
        if ack and follow:
            raise ValueError(
                "ack is drain-only: ack=True cannot be combined with follow=True "
                "(a live tail is cursor-based and never acks)"
            )
        req = pb.StreamEventsRequest(from_seq=from_seq, ack=ack, follow=follow)
        return EventStream(lambda: self._events.StreamEvents(req, timeout=timeout))

    def report_events_consumed(
        self, consumed_cursor: int, *, timeout: float = DEFAULT_ADMIN_TIMEOUT_S
    ) -> None:
        """Report the relay's durably-consumed outbox cursor so the runtime can bound its outbox (R1).

        ``consumed_cursor`` is the FIRST outbox offset the relay has NOT yet durably delivered downstream
        (its contiguous-delivery resume offset). The runtime advances a monotone GC watermark from it and
        prunes only rows *below* it, so it can never delete a row the relay still needs. A lower re-report
        is a durable no-op (the watermark is monotone); a value past the outbox head is clamped by the
        runtime. Requires the destructive ``events:consume`` operator scope."""
        try:
            self._events.ReportEventsConsumed(
                pb.ReportConsumedRequest(consumed_cursor=consumed_cursor),
                timeout=timeout,
            )
        except grpc.RpcError as e:
            raise map_rpc_error(e) from e
