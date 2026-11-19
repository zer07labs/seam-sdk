"""RT4 (runtime 0.95.0, seam-runtime#1776): ``OpenSessionRequest.requester`` (``seam.api.v1`` field 10).

The human principal a session was opened for, as the control plane's pseudonymous principal id
(``p_`` + a hash of issuer and subject). It is **optional** and caller-asserted metadata: it enters no
digest, no event and no audit row, and the runtime stores it sealed as personal data.

``RequesterKind`` is request-only: no response message carries it, so no fail-closed reader of this SDK
(the collective-verdict and Authorize readers) can ever meet an unknown value of it. The only kind the
runtime accepts is ``REQUESTER_KIND_HUMAN``, so the clients take just the id and always send that kind;
another kind, if the runtime ever adds one, is an additive parameter.

The id rule mirrors the runtime's Ring-0 ``seam_types::valid_requester_id`` (spec
``docs/specs/session-open.md`` §Requester): ``p_`` followed by zero or more of ``[A-Za-z0-9._:-]``, 3 to
128 bytes in total. The runtime refuses anything else with ``INVALID_ARGUMENT`` before it spends the
presentation's nonce. Checking it here as well turns a caller bug into a local ``ValueError`` before
any RPC. Like the runtime's refusal, the error never echoes the id: a raw email or IdP subject passed
here by mistake is personal data and must not reach a log through an exception message.
"""

from __future__ import annotations

import re
from typing import Optional

from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb

#: The shortest accepted id (``p_`` plus one character).
REQUESTER_ID_MIN_BYTES = 3
#: The longest accepted id: a 128-byte id is accepted, a 129-byte id is refused.
REQUESTER_ID_MAX_BYTES = 128

_REQUESTER_ID = re.compile(r"p_[A-Za-z0-9._:-]*")


def valid_requester_id(requester_id: object) -> bool:
    """Whether ``requester_id`` is an id the runtime accepts. Never raises."""
    if not isinstance(requester_id, str) or not requester_id.isascii():
        return False
    n = len(requester_id)  # ASCII, so characters == bytes
    return (
        REQUESTER_ID_MIN_BYTES <= n <= REQUESTER_ID_MAX_BYTES
        and _REQUESTER_ID.fullmatch(requester_id) is not None
    )


def requester_pb(requester_id: Optional[str]) -> Optional[pb.Requester]:
    """The wire ``Requester`` for ``requester_id``; ``None`` (field absent) for ``None``.

    Raises ``ValueError`` for an id the runtime would refuse. The message names the rule, never the id.
    """
    if requester_id is None:
        return None
    if not valid_requester_id(requester_id):
        raise ValueError(
            "requester must be the control plane's pseudonymous principal id: 'p_' followed by "
            "[A-Za-z0-9._:-], 3 to 128 bytes in total (a raw email or IdP subject is refused); "
            "the value is not echoed"
        )
    return pb.Requester(kind=pb.REQUESTER_KIND_HUMAN, id=requester_id)
