"""Session and decision identifiers — the runtime's P4 / P5 rules, checked client-side.

The server is authoritative for both. These helpers exist so a caller can build and parse ids without
string-splitting by hand, and can catch a malformed id before spending an admission challenge on it
(seam-runtime ``docs/specs/session-open.md``: the presentation is verified before the id check, so a
refused id still spends the nonce).

* **Session id (P4).** Either a canonical lowercase UUID of version 4 or 7, or a token of at least 22
  characters from ``[A-Za-z0-9_-]``; at most 128 UTF-8 bytes either way. A 36-character hyphenated id
  that parses as a UUID is judged **only** as a UUID — it does not fall back to the token rule — so an
  uppercase UUID, or a v1 one, is refused even though its characters would pass as a token.
* **Decision id (P5).** ``dec:{tenant}:{session}``. Parsing strips ``dec:``, splits on the **first**
  ``:``, and validates both halves: the tenant against ``^[A-Za-z0-9_-]{1,128}$`` and the session by the
  P4 rule. Anything else is refused rather than guessed at — so an extra ``:`` lands in the session
  half, where the P4 charset refuses it.

Stdlib only.
"""

from __future__ import annotations

import re
from typing import NamedTuple

__all__ = [
    "DECISION_ID_PREFIX",
    "InvalidSessionIdError",
    "InvalidDecisionIdError",
    "DecisionId",
    "validate_session_id",
    "is_valid_session_id",
    "decision_id_for_session",
    "parse_decision_id",
]

#: The literal every decision id starts with.
DECISION_ID_PREFIX = "dec:"
#: The session-id byte cap (RFC-0004 §11.2 floor; Seam caps exactly there).
SESSION_ID_MAX_BYTES = 128
#: The token form's minimum length — 16 random bytes in unpadded base64url.
SESSION_ID_TOKEN_MIN_LEN = 22

_TOKEN = re.compile(r"[A-Za-z0-9_-]+")
_TENANT = re.compile(r"[A-Za-z0-9_-]{1,128}")
# "Parses as a UUID": 8-4-4-4-12 hex in either case. Judged only as a UUID once it matches.
_UUID_SHAPE = re.compile(
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
)
_CANONICAL_UUID_V4_V7 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}"
)


class InvalidSessionIdError(ValueError):
    """A session id the runtime would refuse with ``INVALID_SESSION_ID``. ``reason`` says which rule."""

    def __init__(self, reason: str) -> None:
        # The id itself is deliberately not echoed, matching the runtime's refusal.
        super().__init__(f"invalid session id: {reason}")
        #: Which rule refused it, in words.
        self.reason = reason


class InvalidDecisionIdError(ValueError):
    """A decision id that is not ``dec:{tenant}:{session}`` with both halves valid."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"invalid decision id: {reason}")
        #: Which rule refused it, in words.
        self.reason = reason


class DecisionId(NamedTuple):
    """A parsed decision id."""

    tenant: str
    session_id: str

    def __str__(self) -> str:
        return f"{DECISION_ID_PREFIX}{self.tenant}:{self.session_id}"


def _session_refusal(session_id: object) -> str | None:
    """Why ``session_id`` is refused, or ``None`` when it is accepted."""
    if not isinstance(session_id, str):
        return f"must be a str, not {type(session_id).__name__}"
    try:
        n = len(session_id.encode("utf-8"))
    except UnicodeEncodeError:
        return "is not valid UTF-8"
    if n > SESSION_ID_MAX_BYTES:
        return f"is over the {SESSION_ID_MAX_BYTES}-byte cap"
    if _UUID_SHAPE.fullmatch(session_id):
        if _CANONICAL_UUID_V4_V7.fullmatch(session_id):
            return None
        return "a UUID-form id must be a canonical lowercase UUID of version 4 or 7"
    if not _TOKEN.fullmatch(session_id):
        return "uses characters outside [A-Za-z0-9_-]"
    if len(session_id) < SESSION_ID_TOKEN_MIN_LEN:
        return f"a token id must be at least {SESSION_ID_TOKEN_MIN_LEN} characters"
    return None


def validate_session_id(session_id: str) -> str:
    """Return ``session_id`` unchanged if the runtime's P4 rule accepts it; else raise
    :class:`InvalidSessionIdError`. ``str(uuid.uuid4())`` always passes."""
    reason = _session_refusal(session_id)
    if reason is not None:
        raise InvalidSessionIdError(reason)
    return session_id


def is_valid_session_id(session_id: object) -> bool:
    """``True`` iff the runtime's P4 rule accepts ``session_id``."""
    return _session_refusal(session_id) is None


def _check_tenant(tenant: object) -> str:
    if not isinstance(tenant, str) or not _TENANT.fullmatch(tenant):
        raise InvalidDecisionIdError("tenant must match ^[A-Za-z0-9_-]{1,128}$")
    return tenant


def decision_id_for_session(tenant: str, session_id: str) -> str:
    """Build ``dec:{tenant}:{session_id}``, refusing a tenant or session the runtime would refuse."""
    _check_tenant(tenant)
    reason = _session_refusal(session_id)
    if reason is not None:
        raise InvalidDecisionIdError(f"session half: {reason}")
    return f"{DECISION_ID_PREFIX}{tenant}:{session_id}"


def parse_decision_id(decision_id: str) -> DecisionId:
    """Parse ``dec:{tenant}:{session}``. Strips ``dec:``, splits on the first ``:``, and validates both
    halves; refuses anything else with :class:`InvalidDecisionIdError` rather than guessing."""
    if not isinstance(decision_id, str) or not decision_id.startswith(
        DECISION_ID_PREFIX
    ):
        raise InvalidDecisionIdError("must start with 'dec:'")
    tenant, sep, session_id = decision_id[len(DECISION_ID_PREFIX) :].partition(":")
    if not sep:
        raise InvalidDecisionIdError("must be dec:{tenant}:{session}")
    _check_tenant(tenant)
    reason = _session_refusal(session_id)
    if reason is not None:
        raise InvalidDecisionIdError(f"session half: {reason}")
    return DecisionId(tenant, session_id)
