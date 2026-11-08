"""Reading ``DecisionRecordView.allocation`` — which experiment arm a record was allocated to (0.76.0).

A record fetched with ``GetDecision`` carries, since runtime 0.76.0 (Branchpoint BP-8), an
``AllocationView``: whether the experiment allocation sealed inside the record's encrypted commitment
(the commitment's ``0x02`` Allocation trailer) could be read and, if so, what it says
(``seam.api.v1``, ``DecisionRecordView.allocation`` field 13, the ``AllocationView`` and
``Allocation`` messages and the ``AllocationAvailability`` enum — cited by field, not by line: the
proto lives in another repository that nothing here tracks or gates).

The shape and the reading rules are :func:`~seam_sdk.seal_attestation_of`'s, deliberately, and
:func:`allocation_of` closes the same three wrong readings:

1. **Reading the payload when it means nothing.** A runtime that has the field always sets it, and
   ``availability`` says whether ``allocation`` means anything — ONLY under ``RECORDED``. This
   module does not read the inner ``Allocation`` at all outside ``RECORDED``: :attr:`AllocationView
   .allocation` is ``None`` whatever the wire carries.

2. **Reading an unknown availability as permission to read the payload.** The proto's growth policy
   is normative: a client MUST read any ``availability`` it does not recognise — INCLUDING
   ``ALLOCATION_AVAILABILITY_UNSPECIFIED`` — as WITHHELD, never as RECORDED or NOT_RECORDED. It reads
   as ``"UNRECOGNIZED"`` here and never raises: the proto states a *reading* rule, not a
   fail-to-FailPolicy rule. ``"UNRECOGNIZED"`` is deliberately distinct from the runtime's own
   ``"UNAVAILABLE"``; the remedies differ (upgrade this SDK, versus retry or upgrade the runtime).

3. **Reading absence as zero.** ``allocation`` itself is absent only on a runtime older than the
   field, and :func:`allocation_of` returns ``None`` there — "this record does not answer the
   question", never "this decision ran outside any experiment" (that is ``"NOT_RECORDED"``).

**There is no raising path.** Unlike the seal attestation, the allocation carries no fail-closed
enum: every inner field is a plain proto3 scalar. ``mode`` (``split`` or ``holdout`` today) stays a
raw string — the proto gives it no enum and no growth policy, so this SDK does not invent a closed
set a later runtime would break.

**Trust standing.** The allocation is chain-bound (via ``ciphertext_digest``; an operator alteration
breaks the runtime's own chain re-verify) but **not client-verifiable**: it is not a TCT input, so
:meth:`~seam_sdk.SeamClient.verify_decision` does not cover it, and an independent verifier that
checks ``ciphertext_digest`` only (this repository's ``verify/``) never opens it. Treat it as the
runtime's statement, not as something this SDK checked.

**Live records read ``NOT_RECORDED`` until a runtime writes the trailer.** Runtime 0.76.0 can read
an Allocation trailer but writes none, so every live record reads ``"NOT_RECORDED"`` (or another
non-recorded state). That is a normal state, not an error — it also means "ran outside any
experiment" once a runtime does write them.

**Clearance.** Opening the allocation goes through the same decrypt gate as ``seal_attestation``.
This SDK sends no ``x-seam-clearance`` header, so every read is at the default PUBLIC clearance,
and a record whose handling rule needs more reads ``"CLEARANCE_DENIED"`` — never an error on the
call.

**``"UNAVAILABLE"`` is two things.** The runtime could not open or decode the commitment: a
transient store or KMS fault (a retry may succeed), or a trailer that runtime cannot decode (which
persists until the RUNTIME is upgraded — upgrading this SDK does not help). Either way the
allocation is withheld.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb

# The availability states this SDK version names. Anything outside the map — UNSPECIFIED included —
# reads "UNRECOGNIZED", which the growth policy says to treat as WITHHELD.
_AVAILABILITY_NAMES = {
    pb.ALLOCATION_AVAILABILITY_RECORDED: "RECORDED",
    pb.ALLOCATION_AVAILABILITY_NOT_RECORDED: "NOT_RECORDED",
    pb.ALLOCATION_AVAILABILITY_KEY_UNAVAILABLE: "KEY_UNAVAILABLE",
    pb.ALLOCATION_AVAILABILITY_ARCHIVED: "ARCHIVED",
    pb.ALLOCATION_AVAILABILITY_CLEARANCE_DENIED: "CLEARANCE_DENIED",
    pb.ALLOCATION_AVAILABILITY_UNAVAILABLE: "UNAVAILABLE",
}

_UNRECOGNIZED = "UNRECOGNIZED"


@dataclass(frozen=True)
class Allocation:
    """The sealed experiment allocation of one decision — field for field the v1 body of the
    commitment's Allocation trailer, as the runtime read it.

    Frozen: this is the runtime's claim, and a caller must not be able to edit it and pass it on as
    though it came from the wire. Every field is the raw proto3 scalar, presence-less on the wire:
    a field a later runtime phase fills reads as ``""`` or ``0`` until then, never ``None``.
    """

    #: ``"split"`` or ``"holdout"`` today. A raw string, not a closed set: the proto declares no enum.
    mode: str
    experiment_id: str
    #: The arm id; empty for a holdout.
    variant_id: str
    #: The action the experiment arm chose.
    intended_action: str
    #: The action actually served (equal to :attr:`intended_action` for a split).
    served_action: str
    #: The ALLOCATION probability of this arm, in [0, 1] — never the within-variant action
    #: propensity. Passed through exactly as decoded (no clamping, no rounding).
    allocation_propensity: float
    #: The exploration budget in basis points, at most 10000 (0 for a split).
    budget_bp: int
    budget_epoch: int
    #: The experiment config snapshot the allocation was made under.
    snapshot_id: str
    #: The keyed tag of the allocation unit (32 lowercase hex); never the unit itself.
    unit_tag: str
    #: The caller-supplied unit's digest (43-char base64url); empty unless the point requires one.
    unit_digest: str
    #: The bucketing algorithm version.
    bucket_version: int
    #: The public kid (8 hex) of the commitment key that derived the bucket salt.
    commitment_kid: str
    #: The decision point; empty until the point is recorded.
    decision_point: str


@dataclass(frozen=True)
class AllocationView:
    """Whether a record's sealed allocation could be read, and if so what it says.

    Deliberately **two fields, no convenience booleans and no raw integers**, by the same rule as
    :class:`~seam_sdk.SealAttestation`: a caller writes ``view.availability == "RECORDED"``, and the
    raw values stay reachable on ``record.allocation`` for diagnostics.
    """

    #: ``"RECORDED" | "NOT_RECORDED" | "KEY_UNAVAILABLE" | "ARCHIVED" | "CLEARANCE_DENIED" |
    #: "UNAVAILABLE" | "UNRECOGNIZED"`` — closed set.
    #:
    #: Only ``"RECORDED"`` means :attr:`allocation` was read. ``"NOT_RECORDED"`` (the decision ran
    #: outside any experiment, or was sealed by a runtime that wrote none — every 0.76.0 record) is
    #: normal. ``"KEY_UNAVAILABLE"`` is crypto-shred. ``"ARCHIVED"`` means cold storage; cold-replay
    #: the archive bundle. ``"CLEARANCE_DENIED"`` means this read's clearance (PUBLIC — this SDK
    #: sends none) is below the record's decrypt floor. ``"UNAVAILABLE"`` is the runtime saying it
    #: could not open or decode it (transient, or a trailer that runtime cannot decode).
    #: ``"UNRECOGNIZED"`` is THIS SDK not knowing the value, UNSPECIFIED included; read it as
    #: withheld, and upgrade.
    availability: str
    #: Set **only** when :attr:`availability` is ``"RECORDED"`` and the wire carries the inner
    #: message; ``None`` otherwise. An absent one under RECORDED is ``None``, not an error: absence
    #: makes no claim, which is the fail-closed direction.
    allocation: Optional[Allocation]


def allocation_of(view: "pb.DecisionRecordView") -> Optional[AllocationView]:
    """Decode ``view.allocation`` from a ``GetDecision`` record. See the module docstring.

    Returns ``None`` **iff the field is absent** — a runtime older than 0.76.0. Otherwise an
    instance, whatever the availability; ``"NOT_RECORDED"`` and the other non-recorded states are
    normal results, not errors.

    Never raises on any wire value. Python does not enforce the annotation, and ``HasField`` raises
    ``ValueError`` for a message type with no ``allocation`` field. That is a programming error
    surfacing as one.
    """
    if not view.HasField("allocation"):
        return None

    wire = view.allocation
    availability = _AVAILABILITY_NAMES.get(wire.availability, _UNRECOGNIZED)
    if availability != "RECORDED" or not wire.HasField("allocation"):
        # The payload is meaningful ONLY under RECORDED, so it is not read at all otherwise —
        # whatever the wire carries. Withhold rather than guess.
        return AllocationView(availability=availability, allocation=None)

    a = wire.allocation
    return AllocationView(
        availability=availability,
        allocation=Allocation(
            mode=a.mode,
            experiment_id=a.experiment_id,
            variant_id=a.variant_id,
            intended_action=a.intended_action,
            served_action=a.served_action,
            allocation_propensity=a.allocation_propensity,
            budget_bp=a.budget_bp,
            budget_epoch=a.budget_epoch,
            snapshot_id=a.snapshot_id,
            unit_tag=a.unit_tag,
            unit_digest=a.unit_digest,
            bucket_version=a.bucket_version,
            commitment_kid=a.commitment_kid,
            decision_point=a.decision_point,
        ),
    )
