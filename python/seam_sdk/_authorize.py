"""Transport-agnostic core of the advisory ``Authorize`` verb — shared by the sync and aio clients.

Everything here is pure computation (digesting, signing, cache arithmetic, verdict decoding); the
clients own only their transport and their lock discipline. Keeping one core is what stops the sync
and async ticket lifecycles from drifting apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional

from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb

from .crypto import call_sig, jcs_canonicalize, tool_input_digest
from .errors import ProtocolViolationError, UnknownVerdictError

# The closed verdict set this SDK version understands. GROWTH POLICY (proto, normative): any value NOT
# in this map — including AUTHORIZE_VERDICT_UNSPECIFIED — must surface as a typed failure the adapter's
# FailPolicy consumes, NEVER as an implicit allow.
_VERDICT_NAMES = {
    pb.ALLOW: "ALLOW",
    pb.DENY: "DENY",
    pb.TRANSFORM: "TRANSFORM",
    pb.ESCALATE: "ESCALATE",
}


@dataclass(frozen=True)
class AuthorizeResult:
    """One advisory verdict. ``transformed_input`` is the guard-redacted canonical JSON, set iff
    ``verdict == "TRANSFORM"``. ``authorize_id`` correlates the advisory event — it is NOT a
    decision_id; nothing was sealed."""

    verdict: str  # "ALLOW" | "DENY" | "TRANSFORM" | "ESCALATE" — the closed set, enforced below
    reason: str
    transformed_input: Optional[bytes]
    authorize_id: str
    policy_version: str

    @property
    def allowed(self) -> bool:
        return self.verdict == "ALLOW"


def result_of(resp: "pb.AuthorizeResponse") -> AuthorizeResult:
    """Decode a response into :class:`AuthorizeResult`, raising :class:`UnknownVerdictError` for
    UNSPECIFIED or any enum value this SDK doesn't know (fail-safe, never an implicit allow)."""
    name = _VERDICT_NAMES.get(resp.verdict)
    if name is None:
        raise UnknownVerdictError(int(resp.verdict), resp.authorize_id)
    if name == "TRANSFORM" and not resp.transformed_input:
        # A TRANSFORM that carries no rewrite is a protocol violation; surfacing it as a result
        # would hand a truthiness-gating caller the ORIGINAL (unredacted) input to execute.
        raise ProtocolViolationError(
            f"TRANSFORM verdict without transformed_input (authorize_id={resp.authorize_id or '<none>'}); "
            "treat as failure, never execute the original input",
            resp.authorize_id,
        )
    return AuthorizeResult(
        verdict=name,
        reason=resp.reason,
        transformed_input=resp.transformed_input if name == "TRANSFORM" else None,
        authorize_id=resp.authorize_id,
        policy_version=resp.policy_version,
    )


class TicketCache:
    """Client-owned admission-ticket lifecycle: cached after one ``Admit``, treated as stale at 80% of
    its TTL (so a refresh lands before expiry, not after a failed call). Time is injected in ms so
    tests never sleep. NOT lock-aware — the owning client serializes access with its own lock
    (``threading.Lock`` / ``asyncio.Lock``)."""

    def __init__(self) -> None:
        self._ticket: Optional[bytes] = None
        self._refresh_at_ms: int = 0

    def get(self, now_ms: int) -> Optional[bytes]:
        if self._ticket is not None and now_ms < self._refresh_at_ms:
            return self._ticket
        return None

    def store(self, ticket: bytes, expires_at_ms: int, now_ms: int) -> None:
        ttl_ms = expires_at_ms - now_ms
        if ttl_ms <= 0 or not ticket:
            # An already-expired or empty ticket is never cached — the next call re-admits.
            self.invalidate()
            return
        self._ticket = ticket
        self._refresh_at_ms = now_ms + (ttl_ms * 8) // 10

    def invalidate(self) -> None:
        self._ticket = None
        self._refresh_at_ms = 0


def build_authorize_request(
    *,
    ticket: bytes,
    agent_seed: bytes,
    tool_name: str,
    tool_input=None,
    digest_only: bool = False,
    features: Optional[Mapping[str, str]] = None,
    session_id: str = "",
    subject: str = "",
    agent_id: str = "",
    client_request_id: str = "",
) -> "pb.AuthorizeRequest":
    """Canonicalize → digest → sign → assemble one ``AuthorizeRequest`` (the 1-RTT ticket path).

    ``tool_input`` is the tool call's input as a plain JSON-able object; it is JCS-canonicalized here
    (the digest is computed over those exact bytes, so client and server can never disagree on what
    was hashed). ``digest_only=True`` omits the raw bytes — the audit-grade mode for sensitive tools;
    the guard scan and TRANSFORM are unavailable without the input.
    """
    canonical = jcs_canonicalize(tool_input if tool_input is not None else {})
    digest = tool_input_digest(canonical)
    req = pb.AuthorizeRequest(
        ticket=ticket,
        tool_name=tool_name,
        tool_input_digest=digest,
        call_sig=call_sig(agent_seed, ticket, digest),
        session_id=session_id,
        subject=subject,
        agent_id=agent_id,
        client_request_id=client_request_id,
    )
    if not digest_only:
        req.tool_input = canonical
    if features:
        req.features.update(features)
    return req
