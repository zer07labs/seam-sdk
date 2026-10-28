"""Reading ``DecisionRecordView.seal_attestation`` — why a record was sealed, after the fact (0.61.0).

A record fetched with ``GetDecision`` carries, since runtime 0.61.0, a ``SealAttestation``: why the
record was sealed and, for a commit, the runtime's own collective outcome for the round that sealed
it (``seam.api.v1``, ``DecisionRecordView.seal_attestation`` field 12 and the ``SealAttestation``
message — cited by field, not by line: the proto lives in another repository that nothing here
tracks or gates).

The generated surface makes three wrong readings easy, and :func:`seal_attestation_of` closes each:

1. **Reading the payload when it means nothing.** The runtime always sets the attestation, and
   ``availability`` says whether its payload is meaningful — ONLY under ``RECORDED``. Under every
   other state ``seal_reason`` is the zero value and ``collective_outcome`` is absent, but a caller
   reading the raw message cannot tell "unspecified" from "not read". This module does not read the
   payload at all outside ``RECORDED``: ``seal_reason`` and ``collective_outcome`` are ``None``
   whatever the wire carries.

2. **Reading an unknown availability as permission to read the payload.** The proto's growth policy
   is normative: a client MUST read any ``availability`` it does not recognise — INCLUDING
   ``SEAL_ATTESTATION_AVAILABILITY_UNSPECIFIED`` — as WITHHELD, never as RECORDED, and any
   ``seal_reason`` it does not recognise as unknown. Both read as ``"UNRECOGNIZED"`` here, and
   neither raises: the proto states a *reading* rule, not a fail-to-FailPolicy rule, so raising
   would refuse a read the runtime calls benign. ``"UNRECOGNIZED"`` is deliberately distinct from
   the runtime's own ``"UNAVAILABLE"``. The remedies differ: upgrade this SDK, versus retry.

3. **Reading absence as zero.** ``seal_attestation`` itself is absent only on a runtime older than
   the field, and :func:`seal_attestation_of` returns ``None`` there — "this record does not answer
   the question", never "nothing was attested".

**The one place a record read can raise** is the collective outcome inside a ``RECORDED`` commit
attestation: its ``CollectiveVerdict`` keeps that enum's own, fail-closed growth policy, and the
``SealAttestation`` doc defers to it rather than overriding it. An unknown verdict there raises
:class:`~seam_sdk.UnknownCollectiveVerdictError`, exactly as it does on the immediate response.
``get_decision`` itself never raises on this: it returns the raw view, and decoding is opt-in.

**Trust standing.** The attestation is chain-bound (an operator alteration breaks the runtime's own
chain re-verify) but **not client-verifiable**: it is not a TCT input, so
:meth:`~seam_sdk.SeamClient.verify_decision` does not cover it. Treat it as the runtime's statement,
not as something this SDK checked.

**Train A reads ``NOT_RECORDED``.** Runtime 0.61.x authors no attestations, so every live record
reads ``"NOT_RECORDED"`` (or another non-recorded state) until a runtime that writes them seals it.
That is a normal state, not an error. For such a record, the seal-time immediate response is the
only source of its collective outcome.

**Clearance.** Opening the attestation goes through the same decrypt gate as
``GetCommitmentProof``. This SDK sends no ``x-seam-clearance`` header, so every read is at the
default PUBLIC clearance, and a record whose handling rule needs more reads ``"CLEARANCE_DENIED"``
— never an error on the call.

**The two policy scalars beside it stay raw.** ``DecisionRecordView.policy_version`` (``str``) and
``policy_rules_digest`` (``bytes``) are plain proto3 scalars with no presence and no enum, so there
is nothing to decode: an empty ``policy_version`` means staged under no policy (or a solo or legacy
record), and ``policy_rules_digest`` has length 0 when no policy bound and 32 bytes otherwise. They
are display values. They **cannot** be fed back into :func:`seam_sdk.record_digest_v4`, which
distinguishes ``None`` from ``""``/``b""`` — a distinction these presence-less fields have already
lost — and which needs inputs the view does not carry. Read ``policy_enforcement`` with
:func:`seam_sdk.policy_enforcement_of` for "was this gated, and by what?".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb

from ._collective import CollectiveOutcome, _decode_collective

# The availability states this SDK version names. Anything outside the map — UNSPECIFIED included —
# reads "UNRECOGNIZED", which the growth policy says to treat as WITHHELD.
_AVAILABILITY_NAMES = {
    pb.SEAL_ATTESTATION_AVAILABILITY_RECORDED: "RECORDED",
    pb.SEAL_ATTESTATION_AVAILABILITY_NOT_RECORDED: "NOT_RECORDED",
    pb.SEAL_ATTESTATION_AVAILABILITY_KEY_UNAVAILABLE: "KEY_UNAVAILABLE",
    pb.SEAL_ATTESTATION_AVAILABILITY_ARCHIVED: "ARCHIVED",
    pb.SEAL_ATTESTATION_AVAILABILITY_CLEARANCE_DENIED: "CLEARANCE_DENIED",
    pb.SEAL_ATTESTATION_AVAILABILITY_UNAVAILABLE: "UNAVAILABLE",
}

_REASON_NAMES = {
    pb.SEAL_REASON_COMMIT: "COMMIT",
    pb.SEAL_REASON_CANCEL: "CANCEL",
    pb.SEAL_REASON_EXPIRE_TTL: "EXPIRE_TTL",
    pb.SEAL_REASON_EXPIRE_SUSPEND_CAP: "EXPIRE_SUSPEND_CAP",
}

_UNRECOGNIZED = "UNRECOGNIZED"


@dataclass(frozen=True)
class SealAttestation:
    """The runtime's sealed statement of why a decision record was sealed.

    Frozen for the same reason a decoded verdict is: this is the runtime's claim, and a caller must
    not be able to edit it and pass it on as though it came from the wire.

    Deliberately **three fields, no convenience booleans and no raw integers**. A caller writes
    ``att.availability == "RECORDED"``; a ``recorded`` boolean would be a second truthiness to keep
    in step with the first, and the raw values stay reachable on ``view.seal_attestation`` for
    diagnostics. Same rule :class:`~seam_sdk.PolicyEnforcement` and
    :class:`~seam_sdk.CollectiveOutcome` follow.
    """

    #: ``"RECORDED" | "NOT_RECORDED" | "KEY_UNAVAILABLE" | "ARCHIVED" | "CLEARANCE_DENIED" |
    #: "UNAVAILABLE" | "UNRECOGNIZED"`` — closed set.
    #:
    #: Only ``"RECORDED"`` means the payload below was read. ``"NOT_RECORDED"`` (sealed by a runtime
    #: that wrote none; every 0.61.x record) is normal. ``"KEY_UNAVAILABLE"`` is crypto-shred — the
    #: structural columns and ``policy_enforcement`` still answer. ``"ARCHIVED"`` means cold storage;
    #: cold-replay the archive bundle. ``"CLEARANCE_DENIED"`` means this read's clearance (PUBLIC —
    #: this SDK sends none) is below the record's decrypt floor. ``"UNAVAILABLE"`` is the runtime
    #: saying it could not read it (a transient fault, where a retry may succeed, or an attestation
    #: it cannot decode). ``"UNRECOGNIZED"`` is THIS SDK not knowing the value, UNSPECIFIED included;
    #: read it as withheld, and upgrade.
    availability: str
    #: ``None`` unless :attr:`availability` is ``"RECORDED"``; then
    #: ``"COMMIT" | "CANCEL" | "EXPIRE_TTL" | "EXPIRE_SUSPEND_CAP" | "UNRECOGNIZED"`` — closed set.
    seal_reason: Optional[str]
    #: The runtime's own collective outcome for the commit that sealed this record — so it
    #: describes that round, never a later re-drive. Set **only** when :attr:`availability` is
    #: ``"RECORDED"``, :attr:`seal_reason` is ``"COMMIT"``, and the wire carries one; ``None``
    #: otherwise. An absent one under RECORDED + COMMIT is ``None``, not an error: absence makes no
    #: claim, which is the fail-closed direction.
    collective_outcome: Optional[CollectiveOutcome]


def seal_attestation_of(view: "pb.DecisionRecordView") -> Optional[SealAttestation]:
    """Decode ``view.seal_attestation`` from a ``GetDecision`` record. See the module docstring.

    Returns ``None`` **iff the field is absent** — a runtime older than 0.61.0. Otherwise an instance,
    whatever the availability; ``"NOT_RECORDED"`` and the other non-recorded states are normal
    results, not errors.

    Never raises on an availability or seal reason, recognised or not. Raises
    :class:`~seam_sdk.UnknownCollectiveVerdictError` (carrying ``view.decision_id``) **only** when a
    RECORDED commit attestation carries a collective outcome whose verdict this SDK does not know,
    UNSPECIFIED included — that enum's growth policy is fail-closed.

    Python does not enforce the annotation, and ``HasField`` raises ``ValueError`` for a message type
    with no ``seal_attestation`` field. That is a programming error surfacing as one.
    """
    if not view.HasField("seal_attestation"):
        return None

    att = view.seal_attestation
    availability = _AVAILABILITY_NAMES.get(att.availability, _UNRECOGNIZED)
    if availability != "RECORDED":
        # The payload is meaningful ONLY under RECORDED, so it is not read at all here — whatever
        # the wire carries. Withhold rather than guess.
        return SealAttestation(
            availability=availability, seal_reason=None, collective_outcome=None
        )

    seal_reason = _REASON_NAMES.get(att.seal_reason, _UNRECOGNIZED)
    collective = None
    if seal_reason == "COMMIT" and att.HasField("collective_outcome"):
        collective = _decode_collective(att.collective_outcome, view.decision_id)
    return SealAttestation(
        availability=availability,
        seal_reason=seal_reason,
        collective_outcome=collective,
    )
