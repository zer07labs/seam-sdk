"""Ergonomic Seam client over the generated gRPC stubs + the stock crypto shim.

`SeamClient.run_decision` owns the full binding path (admit via the pinned-key PoP, then decide+seal in
one call); `verify_decision` fetches a sealed decision's proof and verifies its rooted TCT locally — zero
server trust beyond the fetch.
"""

from __future__ import annotations

import json
import secrets
import threading
import warnings
from dataclasses import dataclass
from typing import Callable, Dict, Mapping, Optional, Sequence, TypeVar

import grpc
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._authorize import (
    AuthorizeResult,
    TicketCache,
    _resolve_canonical,
    build_authorize_request,
    credential_metadata,
    result_of,
)
from .crypto import (
    EnrollProof,
    aid_from_pubkey,
    build_presentation,
    enroll_pop,
    new_enroll_pop_nonce,
    verify_tct,
)
from .errors import (  # noqa: F401  (SeamError re-exported)
    FailedPreconditionError,
    IssuerMismatchError,
    SeamError,
    UnauthenticatedError,
    UnavailableError,
    _MappedStub,
    is_session_unavailable,
    is_tenant_moving,
)
from .tenant import TenantInterceptor

# The generated transport stubs are ROOTED subpackages (`scripts/root_gen.py` rewrites the
# raw buf output), so they import like any other module — no sys.path injection, no global
# `seam` namespace collision with installed packages. BEHAVIOR CHANGE for anyone who
# imported `seam.api.v1` directly off the old path hack: import `seam_sdk._gen.seam.api.v1`
# (the public `seam_sdk` API is unchanged).
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk._gen.seam.api.v1 import seam_pb2_grpc as rpc
from seam_sdk._gen.seam.event.v1 import seam_event_pb2 as ev  # noqa: F401  (re-exported)

_T = TypeVar("_T")

# The credentialed writes the runtime's seen-proof cache burns at admission (seam-runtime
# ``authorize.rs`` ``replay_guarded``: every credentialed write but ``ReportOutcome``). It burns
# BEFORE the session lease is taken and before the tenant-move check (seamd ``session.rs``
# ``refuse_moving``), so a ``SESSION_UNAVAILABLE`` or ``TENANT_MOVING`` refusal has already spent the
# signature: re-signing the same body under the same ticket yields the same bytes, refused
# ``request_replayed``. :meth:`SeamClient._forget_burned_ticket` drops that ticket so a retry
# re-admits and signs fresh bytes.
_REPLAY_GUARDED = frozenset(
    "/seam.api.v1.SeamCoordination/" + verb
    for verb in (
        "OpenSession",
        "SubmitProposal",
        "SubmitEvaluation",
        "SubmitObjection",
        "SubmitVote",
        "SubmitCommit",
        "SubmitApprovalRequest",
        "SubmitBallot",
        "CancelSession",
        "ExpireSession",
    )
)


# ``SeamError`` and ``IssuerMismatchError`` are defined in :mod:`seam_sdk.errors` and imported above; they
# stay importable from here (``from seam_sdk.client import SeamError``) for backward compatibility.


def _vote_messages(votes) -> list:
    """`run_decision`'s ballot: ``(agent, value)`` or ``(agent, value, reason)`` per vote, mixed.

    Shape only. An entry of any other length is a caller bug in THIS process, refused before the
    wire with the vote's index; the reason's content is the runtime's to judge, never checked here.
    """
    out = []
    for i, vote in enumerate(votes):
        # Any non-string sequence, as the old `for a, v in votes` unpacking accepted; a str/bytes of
        # length 2 or 3 would otherwise unpack into characters and send a nonsense vote.
        if (
            isinstance(vote, (str, bytes))
            or not isinstance(vote, Sequence)
            or len(vote) not in (2, 3)
        ):
            raise TypeError(
                f"votes[{i}] must be an (agent, value) pair or an (agent, value, reason) triple"
            )
        agent, value, *rest = vote
        out.append(pb.Vote(agent=agent, value=value, reason=rest[0] if rest else ""))
    return out


def _now_ms() -> int:
    import time

    return int(time.time() * 1000)


# ``timeout`` is PER-RPC, not an overall budget for the call. Decided, not accidental — and it has a
# consequence callers must size around, so it is stated here rather than discovered.
#
# Every public method takes ``timeout`` (seconds) and propagates it as the gRPC deadline on each
# wire call it makes. Most methods make exactly one, so per-RPC and overall coincide. These do not:
#
#   * ``authorize`` may make up to SIX: an admit (challenge + Admit = 2) when the ticket is cold or
#     stale, the Authorize itself (1), and — on ``UNAUTHENTICATED`` — a refresh (another 2) plus one
#     retried Authorize (1). So the worst case is 6x the value passed, not the 1x it reads as.
#   * The credentialed reads — ``session_status``, ``get_decision``, ``replay_decision``,
#     ``get_commitment_proof`` (so ``verify_decision``), ``get_escalation`` — and ``report_outcome``
#     have the same SIX-call bound when they carry a credential (``credential=`` or a bound agent):
#     they refresh a rejected ticket once and resend once, exactly as ``authorize`` does (#275).
#     So do the seven ``submit_*`` steps (D-SUBMIT-RETRY): the resend re-signs the same request.
#   * ``run_decision`` and ``open_session`` each begin with the challenge→Admit handshake.
#
# So a caller that needs a hard overall bound must impose its own outer clock; the adapters'
# ``Gate`` does exactly that with ``asyncio.wait_for`` around every call, and its ``timeout_s``
# is the number that actually bounds a gated tool call.
#
# Overall-budget semantics were considered and rejected for now: it would mean threading a
# deadline through the ticket lifecycle and deciding what a partially-spent budget means for the
# refresh, which is a contract change for every existing caller in exchange for a bound the one
# consumer that needs it already imposes. Recorded in ASSUMPTIONS.md.
#
# The SDK never retries beyond that single ticket refresh, and only ``authorize``, the credentialed
# reads, ``report_outcome`` and the seven ``submit_*`` steps take it (the same SIX-call bound) —
# ``open_session``, ``cancel_session`` and ``expire_session`` make exactly one call (#275,
# D-WRITES-EXCLUDED). Adapters own every other retry (opt-in: ``with_session_retry``). A deadline breach surfaces as
# ``DeadlineExceededError``, distinct from a DENY verdict, and is never retried.
DEFAULT_TIMEOUT_S = 2.0


# The one shared paragraph every ``submit_*`` docstring carries (sync and aio), appended by
# :func:`_submit_retry_doc` so the seven copies cannot drift. D-SUBMIT-RETRY, #275; the runtime
# behaviour it describes is in plans/archive/post-onboarding-sdk-asks.md (Context, facts 6-8).
_SUBMIT_RETRY_NOTE = """
        **Refresh-once (#275).** With a credential (``credential=`` or a bound agent), a rejected
        ticket is refreshed once and this SAME request is re-signed under the new ticket and resent
        once; a second ``UNAUTHENTICATED`` raises :class:`UnauthenticatedError`. Resending an
        identical body is safe: the runtime refuses a reused signature as ``UNAUTHENTICATED`` and
        dedupes a byte-identical step, with no second effect and no second budget debit. So an
        application resend after a lost response, refreshed here, also lands at most once.

        * ``usage`` is NOT part of a step's identity: a resend differing only in ``usage`` is
          deduped and its ``usage`` silently dropped (not debited). A changed ``reason``, proposal
          id or value is a new message.
        * ``SessionStep`` cannot say "deduped". A duplicate of a NON-resolving step returns
          ``decision_id``, ``collective_outcome`` and ``policy_enforcement`` all unset. A resend
          after a step that SEALED the session returns the sealed ``decision_id`` but NO
          ``collective_outcome`` (``policy_enforcement`` only if the session is attestable) — so
          after a retried write, the record's copy is ``seal_attestation_of(get_decision(...))`` (``NOT_RECORDED`` on 0.61.x).
        * A resend after the session was swept, or while an Expire/Cancel seal is pending,
          raises :class:`FailedPreconditionError` (``session_not_open``) instead of returning the
          sealed id.
        * A resend whose ``reason`` trips the runtime's boundary guard adds one more
          ``boundary.data_flagged`` audit row; the step itself is still applied once.
        """


def _submit_retry_doc(fn: _T) -> _T:
    """Append :data:`_SUBMIT_RETRY_NOTE` to a ``submit_*`` docstring (sync and aio)."""
    doc = fn.__doc__ or ""  # type: ignore[attr-defined]
    fn.__doc__ = doc.rstrip() + "\n" + _SUBMIT_RETRY_NOTE  # type: ignore[attr-defined]
    return fn


class Agent:
    """An agent identity — a 32-byte seed that derives the pinned AID and signs the admission PoP."""

    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise ValueError("agent seed must be 32 bytes")
        self.seed = seed
        self._aid: Optional[str] = None

    @classmethod
    def generate(cls) -> "Agent":
        """A new agent identity from 32 CSPRNG bytes (``secrets.token_bytes``). To persist it, use
        :func:`seam_sdk.identity.create_identity_file`, which generates and writes in one step."""
        return cls(secrets.token_bytes(32))

    @property
    def aid(self) -> str:
        # Derived once — the AID keys the per-agent ticket cache on the authorize hot path.
        if self._aid is None:
            pub = (
                Ed25519PrivateKey.from_private_bytes(self.seed)
                .public_key()
                .public_bytes_raw()
            )
            self._aid = aid_from_pubkey(pub)
        return self._aid

    def enrolment_proof(
        self,
        tenant: str,
        namespace: str,
        *,
        issued_at_ms: Optional[int] = None,
        nonce: Optional[str] = None,
    ) -> EnrollProof:
        """This agent's consent to being enrolled under ``tenant``/``namespace`` (seam-runtime #1157):
        the ``pop`` an operator passes to ``SeamAdminClient.enroll_tenant(..., pop=...)``. Required for
        enrolment by a tenant-scoped operator token.

        ``issued_at_ms`` defaults to now and ``nonce`` to 16 fresh random bytes as 22 base64url
        characters; both are overridable for tests. The runtime accepts the proof for 5 minutes (and
        up to 60 s ahead of its clock), so mint it just before the enrolment call."""
        return enroll_pop(
            self.seed,
            tenant,
            namespace,
            issued_at_ms=_now_ms() if issued_at_ms is None else issued_at_ms,
            nonce=new_enroll_pop_nonce() if nonce is None else nonce,
        )


@dataclass
class BudgetLimits:
    """Multi-dimension session budget (enterprise 6.2). Every field is optional; an unset
    dimension is unlimited. ``messages``, when set, overrides the legacy ``budget`` count.
    ``soft_pct`` is the soft-warning threshold as a percent of any limit (server default 80)."""

    messages: Optional[int] = None
    tokens: Optional[int] = None
    cost_micros: Optional[int] = None
    wall_ms: Optional[int] = None
    soft_pct: Optional[int] = None

    def to_pb(self) -> "pb.BudgetLimits":
        kwargs = {
            k: v
            for k, v in (
                ("messages", self.messages),
                ("tokens", self.tokens),
                ("cost_micros", self.cost_micros),
                ("wall_ms", self.wall_ms),
                ("soft_pct", self.soft_pct),
            )
            if v is not None
        }
        return pb.BudgetLimits(**kwargs)


@dataclass
class StepUsage:
    """Caller-reported per-step resource spend (enterprise 6.2), debited to the session ledger.
    The protocol cannot know what an agent runtime spent; the orchestrator reports it. Absent =
    zero."""

    tokens: int = 0
    cost_micros: int = 0

    def to_pb(self) -> "pb.StepUsage":
        return pb.StepUsage(tokens=self.tokens, cost_micros=self.cost_micros)


def _u32(value: int, field: str) -> int:
    """Range-check a ``uint32`` at the client boundary.

    protobuf-python raises on out-of-range assignment, but the error names the generated field and
    not the SDK argument the caller actually passed — and a ``bool`` would sail through silently as
    0/1, because ``bool`` is an ``int`` subclass. Fail here, naming the SDK argument.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an int, got {type(value).__name__}")
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"{field} must fit in a uint32 (0..4294967295), got {value}")
    return value


class SeamClient:
    """A high-level client over a gRPC channel to a Seam server."""

    # Class-level default so a client built without ``__init__`` (``object.__new__`` in tests and
    # downstream doubles) reads as unbound rather than raising AttributeError.
    _agent: Optional[Agent] = None

    def __init__(self, channel: grpc.Channel, *, agent: Optional[Agent] = None):
        # ``agent`` binds this client to one identity (seam-sdk#202): every subject-scoped verb then
        # attaches that agent's ``seam-request-call-v1`` credential unless the call passes its own
        # ``credential=``. Unbound (the default), the credential stays opt-in per call, as before.
        self._agent = agent
        self._ch = channel
        # Stubs are wrapped so server errors surface as typed ``SeamRpcError`` subclasses (still
        # ``grpc.RpcError``) instead of bare status codes.
        self._admission = _MappedStub(rpc.SeamAdmissionStub(channel))
        self._coord = _MappedStub(rpc.SeamCoordinationStub(channel))
        self._trust = _MappedStub(rpc.SeamTrustStub(channel))
        self._context = _MappedStub(rpc.SeamContextStub(channel))
        self._authz = _MappedStub(rpc.SeamAuthorizationStub(channel))
        # Admission-ticket lifecycle (advisory Authorize path): one cache AND one lock PER AGENT AID —
        # admit-once, refresh at 80% TTL, retry exactly once on UNAUTHENTICATED.
        #
        # Per-AID, not one global lock: a hung `Admit` for agent A held the single lock for its whole
        # timeout, so agent B could not even READ its own already-cached ticket. One slow identity
        # stalling every other identity's hot path is not a property a shared client should have.
        self._tickets: Dict[str, TicketCache] = {}
        self._ticket_locks: Dict[str, threading.Lock] = {}
        # Guards the two dicts above and NOTHING else. It is never held across an RPC — only across a
        # dict lookup — which is what keeps the per-AID split from collapsing back into a global lock.
        self._registry_lock = threading.Lock()

    @classmethod
    def connect(
        cls,
        target: str,
        *,
        credentials: Optional[grpc.ChannelCredentials] = None,
        agent: Optional[Agent] = None,
        tenant: Optional[str] = None,
    ) -> "SeamClient":
        """Connect to a Seam data-plane endpoint. Plaintext by default (the dev/loopback path); pass
        ``credentials=grpc.ssl_channel_credentials()`` (or a configured creds object) to use TLS.
        ``agent`` binds the client to that identity — see :meth:`__init__`. ``tenant`` (this caller's
        enrolled tenant id) is sent as ``x-seam-tenant`` on every call, ``IssueChallenge`` and
        ``Admit`` included, so a ``seam-cell-router`` in front can route it (k8s P15, D123) — see
        :mod:`seam_sdk.tenant`. Omitted, no header is sent: right for a direct-to-cell endpoint."""
        # Built before the channel, so a refused tenant leaves nothing open behind it.
        interceptor = TenantInterceptor(tenant) if tenant is not None else None
        channel = (
            grpc.secure_channel(target, credentials)
            if credentials is not None
            else grpc.insecure_channel(target)
        )
        if interceptor is not None:
            channel = grpc.intercept_channel(channel, interceptor)
        return cls(channel, agent=agent)

    def close(self) -> None:
        """Close the underlying channel.

        The aio client has had this since it shipped; the sync one leaked a channel — and with it a
        connection and the ticket-refresh state keyed to it — for every client a process constructed.
        A long-lived worker that rebuilds its client on reconnect leaked one per reconnect.

        Idempotent: grpc tolerates a repeated close, so ``with`` plus an explicit ``close()`` is safe.
        """
        self._ch.close()

    def __enter__(self) -> "SeamClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _presentation(
        self, agent: Agent, timeout: float = DEFAULT_TIMEOUT_S
    ) -> pb.PinnedPresentation:
        ch = self._admission.IssueChallenge(pb.IssueChallengeRequest(), timeout=timeout)
        body = build_presentation(agent.seed, ch.receiver_aid, ch.nonce, _now_ms())
        return pb.PinnedPresentation(presentation_json=json.dumps(body).encode())

    # ── Advisory authorization (1-RTT, unsealed) ────────────────────────────────────────────────

    def admit(self, agent: Agent, *, timeout: float = DEFAULT_TIMEOUT_S) -> bytes:
        """Run the challenge→``Admit`` handshake now and cache the resulting admission ticket.

        :meth:`authorize` calls this lazily — an explicit ``admit`` is only useful to front-load the
        2-RTT handshake (e.g. at worker startup). Returns the opaque ticket bytes."""
        cache, lock = self._cache_and_lock(agent.aid)
        with lock:
            return self._admit_locked(agent, cache, timeout)

    def _cache_and_lock(self, aid: str) -> "tuple[TicketCache, threading.Lock]":
        """The (cache, lock) pair for one agent identity, created on first use.

        Both dicts grow per distinct AID and are never evicted. That is deliberate for the shape
        this client is built for — an agent process holds one identity, occasionally a handful — and
        the entries are tiny. A gateway multiplexing thousands of identities through ONE client
        would grow them without bound; that deployment wants an LRU here, and should be treated as
        a change to make rather than a bug to discover. Noted rather than pre-solved: the eviction
        policy interacts with the refresh coalescing above (evicting a lock mid-refresh would split
        the very race it exists to serialize), so it is not a change to make speculatively.
        """
        with self._registry_lock:
            return (
                self._tickets.setdefault(aid, TicketCache()),
                self._ticket_locks.setdefault(aid, threading.Lock()),
            )

    def _admit_locked(self, agent: Agent, cache: TicketCache, timeout: float) -> bytes:
        ticket = self._admission.Admit(
            self._presentation(agent, timeout), timeout=timeout
        )
        cache.store(ticket.ticket, ticket.expires_at_ms, _now_ms())
        return ticket.ticket

    def authorize(
        self,
        agent: Agent,
        tool_name: str,
        tool_input=None,
        *,
        canonical: Optional[bytes] = None,
        digest_only: bool = False,
        features: Optional[Mapping[str, str]] = None,
        session_id: str = "",
        subject: str = "",
        subjects: Sequence[str] = (),
        agent_id: str = "",
        client_request_id: str = "",
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> AuthorizeResult:
        """Ask one advisory ``(tool_name, tool_input) -> verdict`` question — 1 RTT, seals nothing.

        ``tool_input`` is the tool call's input as a plain JSON-able object; it is JCS-canonicalized
        and digested here, and the per-call ``call_sig`` binds the ticket to that exact digest.
        ``digest_only=True`` sends the digest without the raw input (audit-grade; no guard scan or
        TRANSFORM). The ticket lifecycle is owned by the client: lazy admit, cached, refreshed at 80%
        TTL, retried exactly once on ``UNAUTHENTICATED``. An unknown verdict raises
        :class:`~seam_sdk.errors.UnknownVerdictError` — never an implicit allow. An old runtime
        without the Authorize service raises ``UnimplementedError``; adapters typically degrade to
        their Observe tier on it.

        ``canonical`` is the alternative to ``tool_input`` and the reason this parameter exists: pass
        the JCS bytes you already derived (via :func:`seam_sdk.canonicalize_tool_input`) and the value
        is derived exactly ONCE, by you. Otherwise a caller that needs the digest before the call —
        to record it on a handle row, say — canonicalizes the object, the SDK canonicalizes it again,
        and the two derivations can disagree across the gap between them (seam-sdk#60). The two
        parameters are mutually exclusive; passing both is an error rather than a precedence rule.

        ``subjects`` supersedes the deprecated singular ``subject``: the server takes the union of
        both, drops empty entries, dedupes first-wins, and caps the effective set at 16. **Today the
        server refuses an effective subject set larger than one** — supplying more than one is the
        server's ``INVALID_ARGUMENT`` until Phase B ships ``AuthorizeEvaluated.subject_digests``; this
        parameter exists now so callers can migrate off ``subject`` one at a time. Both are signed by
        ``call_sig`` v3, in the order passed.
        """
        # Canonicalized ONCE, before the ticket is acquired and outside the closure below. Both
        # halves of that are load-bearing. Inside the closure it was re-derived on the refresh-and-
        # retry path — `build` is called twice — so a tool_input mutated during the admit RTT was
        # signed and sent with a DIFFERENT digest on the retry than on the first attempt, and the
        # request was internally consistent, so the runtime accepted it (seam-sdk#60). Before the
        # ticket, so uncanonicalizable input fails without first spending an admit round trip.
        # `ts/src/client.ts` has always hoisted it; this is the Python twin catching up.
        canonical = _resolve_canonical(tool_input, canonical)
        ticket = self._ticket_for(agent, timeout)
        build = lambda t: build_authorize_request(  # noqa: E731 — rebuilt on refresh (new call_sig)
            ticket=t,
            agent_seed=agent.seed,
            tool_name=tool_name,
            canonical=canonical,
            digest_only=digest_only,
            features=features,
            session_id=session_id,
            subject=subject,
            subjects=list(subjects),
            agent_id=agent_id,
            client_request_id=client_request_id,
        )
        try:
            resp = self._authz.Authorize(build(ticket), timeout=timeout)
        except UnauthenticatedError:
            # Expired/rejected ticket: refresh once, retry once. A second failure propagates typed.
            ticket = self._refresh_ticket(agent, ticket, timeout)
            resp = self._authz.Authorize(build(ticket), timeout=timeout)
        return result_of(resp)

    def get_escalation(
        self,
        authorize_id: str,
        *,
        credential: Optional[Agent] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.EscalationView:
        """Read back one ESCALATE verdict by the ``authorize_id`` its ``AuthorizeResponse`` returned
        (#517). NOT_FOUND for an ALLOW/DENY/TRANSFORM id, or one outside this caller's scope.
        ``credential`` carries the caller's identity in band (#508) — see :meth:`get_decision`,
        including its refresh-once-on-``UNAUTHENTICATED`` rule (#275)."""
        return self._credentialed_call(
            credential,
            "/seam.api.v1.SeamAuthorization/GetEscalation",
            authorize_id,
            None,
            lambda md: self._authz.GetEscalation(
                pb.EscalationRef(authorize_id=authorize_id),
                timeout=timeout,
                metadata=md,
            ),
            timeout=timeout,
        )

    def _refresh_ticket(self, agent: Agent, failed: bytes, timeout: float) -> bytes:
        """Re-admit after an ``UNAUTHENTICATED``, coalescing concurrent refreshes to ONE.

        The re-check inside the lock is the whole point. Unconditionally invalidating and
        re-admitting meant N concurrent callers produced N re-admits: each one threw away the
        ticket the previous caller had just minted, so every caller admitted for itself. Cold start
        already coalesced correctly (they all find an empty cache and the first one fills it) —
        which is what made this easy to miss, because the obvious test passes.

        It matters under mass revocation, which is precisely when the admission endpoint is already
        the most loaded thing in the system: every in-flight call fails at once and, before this,
        every one of them stampeded it.

        So: if the cache now holds a ticket that is NOT the one we failed on, some other caller
        already refreshed and we use theirs. Only the caller still holding the dead ticket (or
        finding none) pays for the round trip.

        **What adopting costs, when the adopted ticket is also dead.** Under a revocation that kills
        every outstanding ticket rather than one, an adopter takes a ticket that the server will
        also reject. It retries once, fails, and the ``UnauthenticatedError`` propagates typed —
        there is no second refresh, because the retry in ``authorize`` is deliberately one-shot.
        Before this change that caller would have minted its own ticket and might have succeeded.
        That is a real trade and it is the right one: the alternative is re-opening the stampede on
        exactly the failure that causes it. The bound is what matters — N callers serialize behind
        the lock, each paying at most one admit attempt, with no fan-out and no retry loop.
        """
        cache, lock = self._cache_and_lock(agent.aid)
        with lock:
            current = cache.get(_now_ms())
            if current is not None and current != failed:
                return current
            cache.invalidate()
            return self._admit_locked(agent, cache, timeout)

    def _ticket_for(self, agent: Agent, timeout: float) -> bytes:
        cache, lock = self._cache_and_lock(agent.aid)
        with lock:
            ticket = cache.get(_now_ms())
            if ticket is None:
                ticket = self._admit_locked(agent, cache, timeout)
            return ticket

    def _signer(self, credential: Optional[Agent]) -> Optional[Agent]:
        """Who signs a subject-scoped call: an explicit ``credential`` wins; otherwise the client's
        bound agent (seam-sdk#202); with neither, ``None`` — no credential is sent, opt-in per call on
        an unbound client, as since #508. The one resolve step both credentialed paths share."""
        return credential if credential is not None else self._agent

    def _signed_once(
        self,
        credential: Optional[Agent],
        rpc_full_name: str,
        resource_id: str,
        body,
        send: Callable[[Optional[list]], _T],
        *,
        timeout: float,
    ) -> _T:
        """Send a subject-scoped call that does NOT retry (``open_session``, ``cancel_session``,
        ``expire_session``: D-WRITES-EXCLUDED / plans/archive/post-onboarding-sdk-asks.md). Resolves the
        signer as :meth:`_signer` does and sends ``send(None)`` without one. Reuses the same
        cached/admitted ticket :meth:`authorize` would for this agent; never mints a second one."""
        signer = self._signer(credential)
        if signer is None:
            return send(None)
        ticket = self._ticket_for(signer, timeout)
        try:
            return send(
                credential_metadata(
                    signer.seed, ticket, rpc_full_name, resource_id, body
                )
            )
        except (UnavailableError, FailedPreconditionError) as e:
            self._forget_burned_ticket(signer, ticket, rpc_full_name, e)
            raise

    def _forget_burned_ticket(
        self, signer: Agent, ticket: bytes, rpc_full_name: str, exc: BaseException
    ) -> None:
        """On ``SESSION_UNAVAILABLE`` or ``TENANT_MOVING`` for a :data:`_REPLAY_GUARDED` write, drop
        ``ticket`` (see there): the runtime burned this call's proof, so the next attempt must
        re-admit to sign new bytes. Every other error, and every read, leaves the cache alone."""
        if rpc_full_name in _REPLAY_GUARDED and (
            is_session_unavailable(exc) or is_tenant_moving(exc)
        ):
            self._invalidate_ticket(signer, ticket)

    def _credentialed_call(
        self,
        credential: Optional[Agent],
        rpc_full_name: str,
        resource_id: str,
        body,
        send: Callable[[Optional[list]], _T],
        *,
        timeout: float,
        retry: bool = True,
    ) -> _T:
        """Send one subject-scoped call, refreshing a rejected ticket ONCE and resending ONCE (#275).

        ``send(metadata)`` performs the RPC; it is called once, or twice when the first attempt is
        refused ``UNAUTHENTICATED``. The rule, in the one place it lives for this client:

        * **No signer, no retry** (D-NO-CRED-NO-RETRY). Without ``credential=`` and without a bound
          agent there is no ticket to refresh, so ``send(None)`` runs once and its error propagates.
        * **Refresh through** :meth:`_refresh_ticket`, the coalesced path :meth:`authorize` uses, so
          N concurrent rejections on one AID — reads and ``authorize`` mixed — cost ONE re-admit
          (adopt-if-different under the per-AID lock). The refresh is keyed to the SIGNER: an explicit
          ``credential=`` on a bound client refreshes the credential's ticket, never the bound one's.
        * **Re-sign over the same ``body`` object.** The ``x-seam-call-sig-bin`` frames the ticket
          bytes, so a resend under a new ticket must be re-signed; the body is the identical message,
          so both attempts carry byte-identical serialized requests.
        * **Exactly once.** A second ``UNAUTHENTICATED`` propagates typed. A failure of the refresh's
          own challenge/``Admit`` (``UNAVAILABLE``/``CHALLENGE_REFUSED`` included) propagates typed
          and is never looped. Any other status (``NOT_FOUND``, ``PERMISSION_DENIED``,
          ``DEADLINE_EXCEEDED``, …) propagates on the first attempt with no refresh.
        * **``retry=False`` is "invalidate, then raise"**: the rejected ticket is dropped from the cache
          if it is still the cached one (so the NEXT call re-admits instead of reusing it until 80% of
          its TTL), and the error propagates. No call site uses it today: it is the flip-back path
          for the ``submit_*`` steps (D-SUBMIT-RETRY) — set their ``retry=`` to ``False`` and they
          invalidate-then-raise, with no API change.

        A rejection the refresh cannot fix (an out-of-scope id, a missing subject — the runtime makes
        those indistinguishable from a dead ticket on purpose) therefore costs one re-admit and one
        resend before it raises: at most six wire calls, the same bound as :meth:`authorize`. No
        negative cache is kept, so a caller polling an out-of-scope id re-admits on every call.
        """
        signer = self._signer(credential)
        if signer is None:
            return send(None)
        ticket = self._ticket_for(signer, timeout)
        try:
            return send(
                credential_metadata(
                    signer.seed, ticket, rpc_full_name, resource_id, body
                )
            )
        except (UnavailableError, FailedPreconditionError) as e:
            self._forget_burned_ticket(signer, ticket, rpc_full_name, e)
            raise
        except UnauthenticatedError:
            if not retry:
                self._invalidate_ticket(signer, ticket)
                raise
            # Inside the handler on purpose: a failure of the refresh itself carries the rejection
            # that caused it as ``__context__``.
            ticket = self._refresh_ticket(signer, ticket, timeout)
        # Outside it: the resend's own failure is the error, not a chained "during handling of".
        try:
            return send(
                credential_metadata(
                    signer.seed, ticket, rpc_full_name, resource_id, body
                )
            )
        except (UnavailableError, FailedPreconditionError) as e:
            self._forget_burned_ticket(signer, ticket, rpc_full_name, e)
            raise

    def _invalidate_ticket(self, agent: Agent, failed: bytes) -> None:
        """Drop ``failed`` from the cache if it is still the cached ticket — compare-and-invalidate
        under the per-AID lock, so a ticket another caller has since refreshed in is never thrown
        away (the same rule as :meth:`_refresh_ticket`'s adopt-if-different)."""
        cache, lock = self._cache_and_lock(agent.aid)
        with lock:
            if cache.get(_now_ms()) == failed:
                cache.invalidate()

    def run_decision(
        self,
        agent: Agent,
        session_id: str,
        participants,
        votes,
        *,
        features: Optional[Mapping[str, str]] = None,
        on_behalf_of: Sequence[str] = (),
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.DecisionResponse:
        """Admit (the PoP handshake) → run a coordinated decision → seal, in one call.

        ``features`` are optional pre-decision request features (e.g. ``{"amount_band": "high"}``) that the
        advisory learning classifier keys ``context_class`` on. They **never** affect the sealed record —
        the decision seals identically with or without them. Absent ⇒ no features (non-breaking). Mirrors
        the Rust reference's ``run_decision_with_features``.

        ``on_behalf_of`` names the end-user data subjects this decision is made for (Phase 0b). The
        engine never reads them; the kernel folds each into the sealed record's participation as an
        inert ``subject:<i>`` declaration, which is what makes GDPR erasure find the record. The
        ``subject:`` prefix is reserved — supplying it here is the server's INVALID_ARGUMENT to raise.

        ``votes`` is a sequence of ``(agent, value)`` pairs or ``(agent, value, reason)`` triples,
        mixed freely. ``reason`` is the voter's stated reason, sealed in that vote's envelope
        (``Vote.reason``, seam-runtime #804/#851) exactly as :meth:`submit_vote`'s is. A pair, or an
        empty reason, sends no reason — byte-identical to a vote without one. The runtime bounds it
        (4096 bytes, redacted, classified) and REQUIRES it — non-empty after trimming whitespace — on
        every vote when the governing policy sets ``rules["x-com.zer07labs.seam"].capture_dissent``, refusing the whole
        decision otherwise; neither rule is mirrored here. A malformed entry (not a 2- or 3-element
        non-string sequence) raises ``TypeError`` before any RPC.
        """
        req = pb.RunDecisionRequest(
            session_id=session_id,
            participants=list(participants),
            votes=_vote_messages(votes),
            presentation=self._presentation(agent, timeout),
            on_behalf_of=list(on_behalf_of),
        )
        if features:
            req.features.update(features)
        return self._coord.RunDecision(req, timeout=timeout)

    # ── Incremental session lifecycle (enterprise 6.2 budget surface) ───────────────────────────
    # open → propose/vote → commit, with resume/cancel/expire/status. Budgets are first-class:
    # multi-dimension ``limits`` at open, per-step ``usage``, and the dimension-raising resume.
    # A step returns a ``SessionStep`` whose ``state == "Suspended"`` when a hard budget dimension
    # is breached (an ``Ok`` step, not an error — the R9 approver then resumes with a raise). A
    # scope-floor denial surfaces as a gRPC ``PERMISSION_DENIED`` error.

    def open_session(
        self,
        agent: Agent,
        session_id: str,
        participants: Sequence[str],
        *,
        budget: int = 0,
        limits: Optional[BudgetLimits] = None,
        mode: str = "",
        on_behalf_of: Sequence[str] = (),
        credential: Optional[Agent] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        """Admit (the PoP handshake) → open an incremental session. ``budget`` is the legacy
        message count (0 means the server default, currently 32 — the proto's semantics, so the
        server owns the number); ``limits`` adds the other 6.2 dimensions. ``on_behalf_of`` binds
        end-user data subjects to the session (see :meth:`run_decision`). ``credential`` is the
        per-request identity (#508), defaulting to the bound agent (#202) — see :meth:`get_decision`."""
        req = pb.OpenSessionRequest(
            session_id=session_id,
            participants=list(participants),
            budget=budget,
            mode=mode,
            presentation=self._presentation(agent, timeout),
            on_behalf_of=list(on_behalf_of),
        )
        if limits is not None:
            req.limits.CopyFrom(limits.to_pb())
        return self._signed_once(
            credential,
            "/seam.api.v1.SeamCoordination/OpenSession",
            "",
            req,
            lambda md: self._coord.OpenSession(req, timeout=timeout, metadata=md),
            timeout=timeout,
        )

    @_submit_retry_doc
    def submit_proposal(
        self,
        session_id: str,
        proposer: str,
        proposal_id: str,
        option: str,
        *,
        usage: Optional[StepUsage] = None,
        credential: Optional[Agent] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        req = pb.ProposalRequest(
            session_id=session_id,
            proposer=proposer,
            proposal_id=proposal_id,
            option=option,
        )
        if usage is not None:
            req.usage.CopyFrom(usage.to_pb())
        return self._credentialed_call(
            credential,
            "/seam.api.v1.SeamCoordination/SubmitProposal",
            "",
            req,
            lambda md: self._coord.SubmitProposal(req, timeout=timeout, metadata=md),
            timeout=timeout,
            retry=True,  # D-SUBMIT-RETRY (#275): see _SUBMIT_RETRY_NOTE
        )

    @_submit_retry_doc
    def submit_vote(
        self,
        session_id: str,
        voter: str,
        proposal_id: str,
        value: str,
        *,
        reason: str = "",
        usage: Optional[StepUsage] = None,
        credential: Optional[Agent] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        """Cast a vote on a proposal. ``reason`` is the voter's stated reason, sealed into the vote
        envelope (seam-runtime #804). Empty means no reason, byte-identical to a vote without one. The
        server bounds it (4096 bytes, injection-redacted, classified) and REQUIRES it when the governing
        policy sets ``rules["x-com.zer07labs.seam"].capture_dissent``; those checks are deliberately not mirrored here."""
        req = pb.VoteRequest(
            session_id=session_id,
            voter=voter,
            proposal_id=proposal_id,
            value=value,
            reason=reason,
        )
        if usage is not None:
            req.usage.CopyFrom(usage.to_pb())
        return self._credentialed_call(
            credential,
            "/seam.api.v1.SeamCoordination/SubmitVote",
            "",
            req,
            lambda md: self._coord.SubmitVote(req, timeout=timeout, metadata=md),
            timeout=timeout,
            retry=True,  # D-SUBMIT-RETRY (#275): see _SUBMIT_RETRY_NOTE
        )

    @_submit_retry_doc
    def submit_evaluation(
        self,
        session_id: str,
        evaluator: str,
        proposal_id: str,
        recommendation: str,
        *,
        confidence: Optional[float] = None,
        reason: str = "",
        rationale_ref: Optional[str] = None,
        usage: Optional[StepUsage] = None,
        credential: Optional[Agent] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        """Submit a MACP evaluation for a proposal.

        ``recommendation`` is MACP's closed vocabulary: ``APPROVE | REVIEW | BLOCK | REJECT``.

        ``confidence`` is EXPLICIT PRESENCE on the wire: absent means *declined to claim* and is
        **not** ``0.0`` — the runtime never fabricates a value into the caller's intent. When
        present it must be in ``[0.0, 1.0]``; out-of-range is the server's ``INVALID_ARGUMENT``
        (MACP refuses it — ``macp-modes-0.5.0 src/mode/decision.rs:166-171``), deliberately not
        mirrored client-side.

        ``rationale_ref`` is a ``sha256:<hex>`` context ref. Since runtime 0.44.0 it is **sealed**:
        every accepted evaluation's ``rationale_ref`` (and whether a ``confidence`` was stated at
        all) is bound into the Commitment's explanation under ``seam-explanation-digest:v1``, which
        ``seam-commitment-digest:v3`` covers. ``verify_decision`` recomputes it locally.
        """
        req = pb.EvaluationRequest(
            session_id=session_id,
            evaluator=evaluator,
            proposal_id=proposal_id,
            recommendation=recommendation,
            reason=reason,
        )
        if confidence is not None:
            req.confidence = confidence  # presence; NEVER default it to 0.0
        if rationale_ref is not None:
            req.rationale_ref = rationale_ref
        if usage is not None:
            req.usage.CopyFrom(usage.to_pb())
        return self._credentialed_call(
            credential,
            "/seam.api.v1.SeamCoordination/SubmitEvaluation",
            "",
            req,
            lambda md: self._coord.SubmitEvaluation(req, timeout=timeout, metadata=md),
            timeout=timeout,
            retry=True,  # D-SUBMIT-RETRY (#275): see _SUBMIT_RETRY_NOTE
        )

    @_submit_retry_doc
    def submit_objection(
        self,
        session_id: str,
        objector: str,
        proposal_id: str,
        reason: str,
        *,
        severity: str = "",
        usage: Optional[StepUsage] = None,
        credential: Optional[Agent] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        """Submit a MACP objection against a proposal.

        ``severity`` is one of ``low | medium | high | critical``; empty defaults to ``medium``
        (the MACP default, applied server-side).
        """
        req = pb.ObjectionRequest(
            session_id=session_id,
            objector=objector,
            proposal_id=proposal_id,
            reason=reason,
            severity=severity,
        )
        if usage is not None:
            req.usage.CopyFrom(usage.to_pb())
        return self._credentialed_call(
            credential,
            "/seam.api.v1.SeamCoordination/SubmitObjection",
            "",
            req,
            lambda md: self._coord.SubmitObjection(req, timeout=timeout, metadata=md),
            timeout=timeout,
            retry=True,  # D-SUBMIT-RETRY (#275): see _SUBMIT_RETRY_NOTE
        )

    @_submit_retry_doc
    def submit_commit(
        self,
        session_id: str,
        commitment_id: str,
        action: str,
        *,
        supersedes: Optional[str] = None,
        usage: Optional[StepUsage] = None,
        credential: Optional[Agent] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        """Submit a MACP commit, sealing ``commitment_id``'s decision.

        ``supersedes`` names the prior decision this one replaces, **by its decision id**
        (``dec:{tenant}:{session}`` — build it with :func:`seam_sdk.decision_id_for_session`). The
        runtime resolves it within this session's tenant, hashes the prior's sealed commitment, and
        seals ``{session}/sha256:<hex>`` into the record — so the served ``Commitment.supersedes`` is
        that stored form, not what was sent. A prior that is missing, in another tenant, not
        ``Resolved``, or carries no MACP commitment is refused with one uniform ``INVALID_ENVELOPE``
        (seam-runtime ``docs/specs/seam-commitment-digest.v3.md`` §supersedes). Omit it rather than
        passing ``""``: absence and an empty value are different digests under v3.
        """
        req = pb.CommitRequest(
            session_id=session_id,
            commitment_id=commitment_id,
            action=action,
        )
        if supersedes is not None:
            req.supersedes = supersedes
        if usage is not None:
            req.usage.CopyFrom(usage.to_pb())
        return self._credentialed_call(
            credential,
            "/seam.api.v1.SeamCoordination/SubmitCommit",
            "",
            req,
            lambda md: self._coord.SubmitCommit(req, timeout=timeout, metadata=md),
            timeout=timeout,
            retry=True,  # D-SUBMIT-RETRY (#275): see _SUBMIT_RETRY_NOTE
        )

    # ── Quorum-mode-only steps (`macp.mode.quorum.v1`) ─────────────────────────────────────────
    # request → ballot × N → submit_commit (reused unchanged). Both verbs are rejected with a typed
    # mode-mismatch error against a session opened in any other mode. That check is the server's to
    # make and is deliberately NOT mirrored here: a client-side copy of a server-side rule is a
    # second grammar to keep in sync, and the first thing to drift.

    @_submit_retry_doc
    def submit_approval_request(
        self,
        session_id: str,
        requester: str,
        request_id: str,
        action: str,
        required_approvals: int,
        *,
        usage: Optional[StepUsage] = None,
        credential: Optional[Agent] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        """Open an N-of-M approval round. Only the session initiator may submit one (enforced by
        the mode engine, not the contract).

        ``required_approvals`` is the N: how many APPROVE ballots close the round.
        """
        req = pb.ApprovalRequestRequest(
            session_id=session_id,
            requester=requester,
            request_id=request_id,
            action=action,
            required_approvals=_u32(required_approvals, "required_approvals"),
        )
        if usage is not None:
            req.usage.CopyFrom(usage.to_pb())
        return self._credentialed_call(
            credential,
            "/seam.api.v1.SeamCoordination/SubmitApprovalRequest",
            "",
            req,
            lambda md: self._coord.SubmitApprovalRequest(
                req, timeout=timeout, metadata=md
            ),
            timeout=timeout,
            retry=True,  # D-SUBMIT-RETRY (#275): see _SUBMIT_RETRY_NOTE
        )

    @_submit_retry_doc
    def submit_ballot(
        self,
        session_id: str,
        voter: str,
        request_id: str,
        choice: "pb.BallotChoice.ValueType",
        *,
        reason: str = "",
        usage: Optional[StepUsage] = None,
        credential: Optional[Agent] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        """Cast one ballot against an open approval request.

        ``choice`` is a :class:`BallotChoice` — ``BALLOT_CHOICE_APPROVE`` / ``_REJECT`` /
        ``_ABSTAIN``. One RPC covers all three: the three upstream MACP payloads are structurally
        identical, and the tag is what selects the wire envelope. ``BALLOT_CHOICE_UNSPECIFIED`` is
        not a vote — passing it is the server's INVALID_ARGUMENT to raise.
        """
        req = pb.BallotRequest(
            session_id=session_id,
            voter=voter,
            request_id=request_id,
            choice=choice,
            reason=reason,
        )
        if usage is not None:
            req.usage.CopyFrom(usage.to_pb())
        return self._credentialed_call(
            credential,
            "/seam.api.v1.SeamCoordination/SubmitBallot",
            "",
            req,
            lambda md: self._coord.SubmitBallot(req, timeout=timeout, metadata=md),
            timeout=timeout,
            retry=True,  # D-SUBMIT-RETRY (#275): see _SUBMIT_RETRY_NOTE
        )

    def resume_session(
        self,
        session_id: str,
        *,
        budget: int = 0,
        raise_: Optional[BudgetLimits] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStep:
        """**Deprecated / tombstone.** Resume moved to the **management** plane (rt-D): this data-plane RPC
        now returns ``PERMISSION_DENIED`` ("call SeamAdmin.ResumeSession"). Use
        :meth:`SeamAdminClient.resume_session` (the R9 approver action) with an operator token instead.
        Retained only so an old caller gets a clear, typed error rather than a missing attribute.
        ``budget`` follows the proto's semantics: 0 means the server default, currently 32."""
        warnings.warn(
            "SeamClient.resume_session is a tombstone: resume moved to the management plane "
            "(SeamAdmin.ResumeSession) — use SeamAdminClient.resume_session with an operator token",
            DeprecationWarning,
            stacklevel=2,
        )
        req = pb.ResumeRequest(session_id=session_id, budget=budget)
        if raise_ is not None:
            # `raise` is a Python keyword, so the generated field is reached via getattr.
            getattr(req, "raise").CopyFrom(raise_.to_pb())
        return self._coord.ResumeSession(req, timeout=timeout)

    def cancel_session(
        self,
        session_id: str,
        *,
        credential: Optional[Agent] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.TerminalResponse:
        req = pb.SessionRef(session_id=session_id)
        return self._signed_once(
            credential,
            "/seam.api.v1.SeamCoordination/CancelSession",
            "",
            req,
            lambda md: self._coord.CancelSession(req, timeout=timeout, metadata=md),
            timeout=timeout,
        )

    def expire_session(
        self,
        session_id: str,
        *,
        credential: Optional[Agent] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.TerminalResponse:
        req = pb.SessionRef(session_id=session_id)
        return self._signed_once(
            credential,
            "/seam.api.v1.SeamCoordination/ExpireSession",
            "",
            req,
            lambda md: self._coord.ExpireSession(req, timeout=timeout, metadata=md),
            timeout=timeout,
        )

    def session_status(
        self,
        session_id: str,
        *,
        credential: Optional[Agent] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.SessionStatusResponse:
        return self._credentialed_call(
            credential,
            "/seam.api.v1.SeamCoordination/SessionStatus",
            session_id,
            None,
            lambda md: self._coord.SessionStatus(
                pb.SessionRef(session_id=session_id), timeout=timeout, metadata=md
            ),
            timeout=timeout,
        )

    def get_decision(
        self,
        decision_id: str,
        *,
        credential: Optional[Agent] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.DecisionRecordView:
        """``credential``, when supplied, carries the caller's identity in band (#508) — the sound
        posture on a deployment that strips ``x-seam-subject`` at its edge. Reuses the same
        cached/admitted ticket :meth:`authorize` would for this agent. Omitted, it defaults to the
        agent the client is bound to (``SeamClient(channel, agent=...)``, seam-sdk#202); on an unbound
        client no credential is sent.

        With a credential, an ``UNAUTHENTICATED`` refreshes the signer's ticket once and resends once
        (#275) — the same rule for every credentialed read (``session_status``, ``replay_decision``,
        ``get_commitment_proof``, ``get_escalation``) and ``report_outcome``. A second rejection
        raises :class:`~seam_sdk.errors.UnauthenticatedError`. The runtime answers a scope refusal
        (an out-of-scope or absent id) with the same ``UNAUTHENTICATED`` as a dead ticket, so such a
        call also pays one re-admit before it raises; without a credential nothing is retried.

        Returns the raw view. Read its policy enforcement with
        :func:`~seam_sdk.policy_enforcement_of` and its seal attestation with
        :func:`~seam_sdk.seal_attestation_of` (runtime 0.61.0+) rather than the raw fields."""
        return self._credentialed_call(
            credential,
            "/seam.api.v1.SeamCoordination/GetDecision",
            decision_id,
            None,
            lambda md: self._coord.GetDecision(
                pb.DecisionRef(decision_id=decision_id), timeout=timeout, metadata=md
            ),
            timeout=timeout,
        )

    def replay_decision(
        self,
        decision_id: str,
        *,
        credential: Optional[Agent] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.ReplayView:
        return self._credentialed_call(
            credential,
            "/seam.api.v1.SeamCoordination/ReplayDecision",
            decision_id,
            None,
            lambda md: self._coord.ReplayDecision(
                pb.DecisionRef(decision_id=decision_id), timeout=timeout, metadata=md
            ),
            timeout=timeout,
        )

    def report_outcome(
        self,
        decision_id: str,
        correct: bool,
        verified_by: Optional[str] = None,
        *,
        idempotency_key: str,
        credential: Optional[Agent] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> bool:
        """Report a delayed correctness outcome for a sealed decision (advisory, Plan R). The sealed
        record is never mutated; this only emits a LEARNING_OUTCOME. ``verified_by`` records the source
        (downstream system / reviewer). Returns whether it was recorded. NOT_FOUND if the id is unknown.

        ``idempotency_key`` is **required** (seam-runtime #1154): 1–128 printable ASCII characters,
        checked here before any network call. It must be **stable per logical outcome**. A retry of the
        same report must reuse the key, which makes the retry a no-op that returns the original response.
        A correction, or a second reporter, needs a NEW key. Reusing a key with a different
        ``correct``/``verified_by`` is refused with ``INVALID_ARGUMENT``. Derive it from your own outcome
        identity (for example your review or ticket id), never from a fresh random value per attempt,
        which would turn every retry into a second report. It is stored durably and never erased, so keep
        personal data out of it.

        ``credential`` opts in to the in-band request credential (#508). The digest covers the whole
        request message; this is what makes the verb callable on a header-denied plane. With a
        credential (explicit or the bound agent), an ``UNAUTHENTICATED`` refreshes the ticket once and
        re-signs and resends the SAME request once (#275) — safe because the key above makes a resend
        of a report that already landed a no-op. A second rejection raises ``UnauthenticatedError``."""
        req = pb.ReportOutcomeRequest(
            decision_id=decision_id,
            correct=correct,
            idempotency_key=_check_idempotency_key(idempotency_key),
        )
        if verified_by is not None:
            req.verified_by = verified_by
        # Refresh-once (#275): ReportOutcome is idempotent on its signed ``idempotency_key`` and exempt
        # from the runtime's write replay guard, so the resend re-signs the SAME ``req`` — if the
        # first attempt had landed, the resend is a no-op returning the original response.
        return self._credentialed_call(
            credential,
            "/seam.api.v1.SeamCoordination/ReportOutcome",
            "",
            req,
            lambda md: self._coord.ReportOutcome(req, timeout=timeout, metadata=md),
            timeout=timeout,
        ).recorded

    # ── Context binding (data plane) ─────────────────────────────────────────────────────────────

    def register_context(
        self,
        content: bytes,
        fidelity: str,
        derived_from: Optional[Sequence[str]] = None,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> str:
        """Register context content at a given ``fidelity`` (``Digest`` | ``Reference`` | ``Value``);
        returns its content ref (a ``sha256:`` ref or an ``acdp://`` remote id)."""
        return self._context.RegisterContext(
            pb.RegisterContextRequest(
                content=content,
                fidelity=fidelity,
                derived_from=list(derived_from or []),
            ),
            timeout=timeout,
        ).content_ref

    def resolve_context(
        self, refs: Sequence[str], *, timeout: float = DEFAULT_TIMEOUT_S
    ) -> Sequence[pb.ContextBinding]:
        """Resolve context refs to their bindings.

        Returns the generated `ContextBinding` unchanged. Nothing is projected or renamed here, so
        every field the contract carries arrives — including the five ACDP receipt slots
        (`content_hash`, `receipt_hash`, `key_status`, `resolved_status`, `receipt_key_status`),
        `retraction`, and the P3 key-revocation pair (`revocation`, `revocation_trust_class`), all of
        which this SDK passes through without interpreting. `key_status` and `receipt_key_status`
        (closed, PascalCase) and `resolved_status` (open, lowercase) are byte-identical to what
        enters the `context_digest` preimage — do not case-fold, normalise or map them.
        `receipt_key_status` is present exactly when `receipt_hash` is: `Historical` means the receipt
        was verified under a rotated-out registry key — valid history, NOT a current registry
        attestation, and must not be presented as one. :func:`seam_sdk.context_digest_v4` recomputes
        the sealed digest from these bindings and refuses an unpaired or out-of-vocabulary slot.
        """
        return list(
            self._context.ResolveContext(
                pb.ResolveContextRequest(refs=list(refs)), timeout=timeout
            ).bindings
        )

    # ── Trust / verification (data plane) ────────────────────────────────────────────────────────

    def issuer_aid(self, *, timeout: float = DEFAULT_TIMEOUT_S) -> str:
        return self._trust.IssuerAid(pb.Empty(), timeout=timeout).issuer_aid

    def server_info(self, *, timeout: float = DEFAULT_TIMEOUT_S) -> str:
        """The runtime's version (seam.api.v1 ``SeamTrust/ServerInfo``, runtime 0.63.0+).

        A semver string such as ``"0.63.0"`` — the seamd crate version, which the runtime always sets —
        returned verbatim, not parsed or normalised. Like :meth:`issuer_aid` it needs no credential or ticket (only TLS/mTLS gates
        it), and the SDK never retries it. A runtime older than 0.63.0 raises
        :class:`~seam_sdk.errors.UnimplementedError`: fall back to an explicitly configured version
        or to control-plane discovery. The value is server-asserted and unsigned — an input for
        picking a compatible SDK or adapter, never a trust signal.
        """
        return self._trust.ServerInfo(pb.Empty(), timeout=timeout).runtime_version

    def verify_commitment(
        self,
        commitment: pb.Commitment,
        signed_artifact: bytes,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> bool:
        """Server-side verification of a rooted commitment (the ``SeamTrust`` path). For zero-server-trust
        verification prefer :meth:`verify_decision`, which verifies locally against a pinned issuer."""
        return self._trust.VerifyCommitment(
            pb.VerifyCommitmentRequest(
                commitment=commitment, signed_artifact=signed_artifact
            ),
            timeout=timeout,
        ).valid

    def verify_party_anchor(
        self,
        party_id: str,
        anchor: pb.Anchor,
        *,
        tenant: str = "",
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> bool:
        """Verify a counterparty's published audit-chain anchor (network mode). ``tenant`` scopes the
        lookup to the partition the party was registered under — leave empty for the untenanted
        partition, matching the pre-#903 behavior. Unlike :meth:`verify_party_attestation`, whose
        tenant lives *inside* the attestation message itself, ``Anchor`` is deliberately
        tenant-agnostic, so this tenant is a sibling of ``party_id``/``anchor`` on the request, not a
        field of the anchor."""
        return self._trust.VerifyPartyAnchor(
            pb.VerifyAnchorRequest(party_id=party_id, anchor=anchor, tenant=tenant),
            timeout=timeout,
        ).valid

    def verify_party_attestation(
        self,
        party_id: str,
        attestation: ev.ChainHeadAttestation,
        *,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> bool:
        """Verify a counterparty's signed chain-head attestation against the registry-pinned key (A14
        network mode). Returns ``True`` iff the attestation's Ed25519 signature checks out against the
        pubkey registered for ``party_id``; ``False`` for an unknown party or any tamper (a boolean
        verdict, never an exception) — mirroring :meth:`verify_party_anchor`, except that this
        attestation's own ``tenant`` field scopes the lookup, whereas ``verify_party_anchor`` takes
        ``tenant`` as a request-level argument since ``Anchor`` carries no tenant of its own. Since
        seam-runtime #835 step 4 that ``tenant`` is SIGNED: a non-empty one verifies under the v2 framing
        only, so a v1 attestation relabelled to a tenant comes back ``False``."""
        return self._trust.VerifyPartyAttestation(
            pb.VerifyAttestationRequest(party_id=party_id, attestation=attestation),
            timeout=timeout,
        ).valid

    def get_commitment_proof(
        self,
        decision_id: str,
        *,
        credential: Optional[Agent] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> pb.CommitmentProof:
        return self._credentialed_call(
            credential,
            "/seam.api.v1.SeamCoordination/GetCommitmentProof",
            decision_id,
            None,
            lambda md: self._coord.GetCommitmentProof(
                pb.DecisionRef(decision_id=decision_id), timeout=timeout, metadata=md
            ),
            timeout=timeout,
        )

    def verify_decision(
        self,
        decision_id: str,
        expected_issuer: str,
        *,
        credential: Optional[Agent] = None,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> bool:
        """Fetch a sealed decision's proof and verify its rooted TCT locally — zero server trust.

        `expected_issuer` is the issuer AID the caller **pinned out of band** (or TOFU-cached). The TCT is
        verified against it, and the server-supplied `proof.issuer_aid` must match — so a malicious server
        cannot substitute its own key. Get the issuer once via `issuer_aid()` and pin it; never trust the
        per-response issuer as the verification anchor.

        Returns ``True`` iff the rooted TCT is cryptographically valid for the pinned issuer, ``False`` for
        an ordinary invalid decision. Raises :class:`IssuerMismatchError` when the proof's issuer AID does
        not match `expected_issuer` — a distinct security signal (an attempted key substitution), never
        downgraded to a bland ``False``. Mirrors the Rust reference's distinct ``ClientError::Crypto``.

        ``credential`` is passed to the proof fetch (:meth:`get_commitment_proof`); omitted, it defaults
        to the client's bound agent, which a credential-only deployment needs for this subject-scoped read.
        """
        proof = self.get_commitment_proof(
            decision_id, credential=credential, timeout=timeout
        )
        if proof.issuer_aid != expected_issuer:
            raise IssuerMismatchError(proof.issuer_aid, expected_issuer)
        c = proof.commitment
        return verify_tct(
            expected_issuer, c.signed_artifact.decode(), commitment_view(c)
        )


# The lowercase words `seam-explanation-digest:v1` frames, by `ExplanationKind` value. An unknown or
# UNSPECIFIED kind maps to a word the digest refuses, so verification fails closed rather than guessing.
_EXPLANATION_KIND_WORDS = {
    pb.EXPLANATION_KIND_VOTE: "vote",
    pb.EXPLANATION_KIND_EVALUATION: "evaluation",
    pb.EXPLANATION_KIND_OBJECTION: "objection",
    pb.EXPLANATION_KIND_BALLOT: "ballot",
}


def commitment_view(c: "pb.Commitment") -> dict:
    """The dict :func:`~seam_sdk.crypto.verify_tct` takes, from a served ``Commitment``.

    Carries the committer and the sealed explanation (entries AND the published digest), so
    verification checks the entries against the digest before binding it (seam-commitment-digest:v3).
    Explicit presence is preserved: an absent ``confidence`` / ``rationale_ref`` stays ``None``."""
    return {
        "id": c.id,
        "action": c.action,
        "authority": c.authority,
        "auth_method": c.auth_method,
        "trust_basis": c.trust_basis,
        # v3 frames absent and present-empty differently (a presence byte), so explicit presence
        # must survive: `c.supersedes or ""` turned every unsuperseding commitment into a
        # present-empty one and its TCT would never verify.
        "supersedes": c.supersedes if c.HasField("supersedes") else None,
        "committer": c.committer,
        # proto3 bytes cannot say "absent": empty means not published, and the entries decide.
        "explanation_digest": bytes(c.explanation_digest) or None,
        "explanation": [
            {
                "kind": _EXPLANATION_KIND_WORDS.get(e.kind, f"<unknown kind {e.kind}>"),
                "participant": e.participant,
                "proposal_id": e.proposal_id,
                "value": e.value,
                "reason": e.reason,
                "confidence": e.confidence if e.HasField("confidence") else None,
                "rationale_ref": e.rationale_ref
                if e.HasField("rationale_ref")
                else None,
            }
            for e in c.explanation
        ],
    }


def _check_idempotency_key(key: str) -> str:
    """The runtime's ``ReportOutcome`` key rule (#1154), checked before any network call: 1–128
    printable ASCII characters (U+0020..U+007E). Shared by the sync and async clients."""
    if not isinstance(key, str):
        raise TypeError(f"idempotency_key must be a str, got {type(key).__name__}")
    if not 1 <= len(key) <= 128 or not all(" " <= ch <= "~" for ch in key):
        raise ValueError(
            "idempotency_key must be 1-128 printable ASCII characters (U+0020..U+007E); "
            "the runtime refuses anything else with INVALID_ARGUMENT"
        )
    return key
