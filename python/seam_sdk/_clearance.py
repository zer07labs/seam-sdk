"""The caller's decrypt clearance on the decision reads (#384).

seam-runtime applies a namespace's §2.3 decrypt-clearance floor on ``GetDecision`` (the seal
attestation and the experiment allocation on the view), ``ReplayDecision`` (runtime 0.101.0+) and
``GetCommitmentProof``. It takes the caller's clearance from ``x-seam-clearance`` metadata. If the
value is absent or unrecognised, the read is at ``Public``, the lowest clearance.

``clearance=`` on :meth:`~seam_sdk.SeamClient.get_decision`, ``replay_decision``,
``get_commitment_proof`` and ``verify_decision`` (and the ``aio`` twins) sends it. The default
``None`` sends no header, so the wire is byte-identical to an SDK without the option.

**The value set is closed and exact.** It is the runtime's ``Classification`` labels, spelled as
the runtime parses them (case-sensitive): :data:`CLEARANCES`. Any other value raises ``ValueError``
before any RPC, admission included. The runtime would not refuse an unknown label; it would quietly
read at ``Public``, which shows up as an unexplained ``PERMISSION_DENIED`` (replay, proof) or a
``CLEARANCE_DENIED`` view (get_decision).

**Sending it is an assertion, not a grant.** The runtime honours the header only on a data plane in
the ``allow`` subject-header posture, i.e. behind a trusted gateway. A plane in ``deny`` posture
(``SEAM_GRPC_SUBJECT_HEADERS=deny``, the credential-only posture) and a peer-cert plane strip it at
the edge, so the read there is at ``Public`` whatever this option says. The header is not part of
the #508 call signature.
"""

from __future__ import annotations

from typing import Optional, Sequence, Tuple

CLEARANCE_HEADER = "x-seam-clearance"

CLEARANCE_PUBLIC = "Public"
CLEARANCE_INTERNAL = "Internal"
CLEARANCE_CONFIDENTIAL = "Confidential"
CLEARANCE_FINANCIAL = "Financial"
CLEARANCE_PII = "Pii"
CLEARANCE_PHI = "Phi"

# In the runtime enum's declaration order; used for the error message.
_ORDER = (
    CLEARANCE_PUBLIC,
    CLEARANCE_INTERNAL,
    CLEARANCE_CONFIDENTIAL,
    CLEARANCE_FINANCIAL,
    CLEARANCE_PII,
    CLEARANCE_PHI,
)

#: Exactly the labels seam-runtime's ``Classification::from_str`` accepts.
CLEARANCES = frozenset(_ORDER)

_ALLOWED = ", ".join(_ORDER)

Metadata = Optional[Sequence[Tuple[str, object]]]


def _check_clearance(verb: str, clearance: Optional[str]) -> None:
    """Refuse anything but ``None`` or one of :data:`CLEARANCES`, before any RPC is made."""
    if clearance is None:
        return
    # The isinstance test comes first: a list would otherwise raise TypeError (unhashable) from the
    # set lookup instead of the documented ValueError.
    if not isinstance(clearance, str) or clearance not in CLEARANCES:
        raise ValueError(
            f"{verb}: clearance {clearance!r} is not one of {_ALLOWED} "
            "(exact, case-sensitive; omit it to send no x-seam-clearance)"
        )


def _with_clearance(md: Metadata, clearance: Optional[str]) -> Metadata:
    """``md`` plus the clearance header; ``md`` itself (possibly ``None``) when there is none."""
    if clearance is None:
        return md
    return [*(md or ()), (CLEARANCE_HEADER, clearance)]
