"""Fail-closed decoding of ``DecisionResponse.collective_outcome`` (C5).

This is the `CollectiveVerdict` twin of :mod:`seam_sdk._authorize`'s verdict decoding, and it exists
for the same reason: the proto's growth policy is normative and fail-closed, and the *generated*
surface makes the wrong thing easy in two independent ways.

1. ``collective_outcome`` is ``optional``. On a response that does not carry it — an older runtime,
   or ``GetDecision``/``ReplayDecision``, which per the proto never carry it — reading
   ``resp.collective_outcome.verdict`` yields ``COLLECTIVE_VERDICT_UNSPECIFIED`` with no signal that
   the field was absent rather than zero. Absent and UNSPECIFIED are distinct wire states and this
   module keeps them distinct: absent returns ``None``, UNSPECIFIED raises.

2. proto3 makes ``0`` the silent default, so the natural negative test —
   ``if verdict != COLLECTIVE_VERDICT_DECLINED: proceed`` — **allows on every unrecognized value**,
   including UNSPECIFIED and including any value a future runtime adds. That is exactly the
   inversion the growth policy forbids:

       GROWTH POLICY (normative, copied from AuthorizeVerdict's): any value a client does not
       recognize — INCLUDING COLLECTIVE_VERDICT_UNSPECIFIED — MUST route to the adapter's
       FailPolicy, never to allow. The server never emits UNSPECIFIED.

So an unrecognized verdict raises rather than returning a value a caller can accidentally read as
permission. Raising is the only shape with no truthiness that can go the wrong way.

**This module never re-derives the verdict from the counters.** The proto is explicit that
``approve_count``/``reject_count``/``abstain_count`` are observability, and that a client-side tally
is self-grading and unverifiable — which is the whole reason ``verdict`` exists as a field. The
counters are carried through untouched for display; nothing here branches on them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb

from .errors import UnknownCollectiveVerdictError

# The closed verdict set this SDK version understands. Anything outside it — including the zero
# value — is a failure, per the growth policy quoted above.
_VERDICT_NAMES = {
    pb.COLLECTIVE_VERDICT_APPROVED: "APPROVED",
    pb.COLLECTIVE_VERDICT_DECLINED: "DECLINED",
    pb.COLLECTIVE_VERDICT_SPLIT: "SPLIT",
    pb.COLLECTIVE_VERDICT_ESCALATED: "ESCALATED",
    pb.COLLECTIVE_VERDICT_NO_VOTES: "NO_VOTES",
}


@dataclass(frozen=True)
class CollectiveOutcome:
    """The runtime's own judgment of what a panel decided, as it derived it from the actual tally.

    ``verdict`` is the judgment and the only field to branch on. The counters are observability:
    they are here so a caller can *show* the tally, not so it can recompute the verdict from them.

    ``declared_participant_count`` is not redundant with the vote counts, and the gap between them
    is the point — MACP's ``unanimous`` algorithm uses DECLARED participants as its denominator, so
    a panel of 3 with 2 APPROVE votes is denied for not all having voted.
    """

    verdict: (
        str  # "APPROVED" | "DECLINED" | "SPLIT" | "ESCALATED" | "NO_VOTES" — closed set
    )
    approve_count: int
    reject_count: int  # REJECT and BLOCK both, matching the runtime's own fold
    abstain_count: int  # includes ESCALATE / REVIEW
    declared_participant_count: int
    stated_value_contradicted_tally: bool

    @property
    def approved(self) -> bool:
        """True **only** for an unambiguous APPROVED verdict.

        Deliberately the sole boolean on this type, and deliberately positive: every other verdict —
        DECLINED, SPLIT, ESCALATED, NO_VOTES — is not an approval, and an unrecognized one never
        reaches here because :func:`collective_outcome_of` raised before constructing this object.
        There is no ``declined`` twin, because ``not approved`` must stay the safe reading."""
        return self.verdict == "APPROVED"


def collective_outcome_of(resp: "pb.DecisionResponse") -> Optional[CollectiveOutcome]:
    """Decode ``resp.collective_outcome``, fail-closed.

    Returns ``None`` **iff the field is absent** — the runtime did not carry one on this response
    (an older runtime, or a read verb that never does). ``None`` is not "the panel decided nothing";
    it is "this response does not answer the question", and a caller must decide what that means for
    its own fail policy rather than being handed a value.

    Raises :class:`UnknownCollectiveVerdictError` for ``COLLECTIVE_VERDICT_UNSPECIFIED`` or any
    value this SDK version does not know — never an implicit allow.
    """
    if not resp.HasField("collective_outcome"):
        return None

    outcome = resp.collective_outcome
    name = _VERDICT_NAMES.get(outcome.verdict)
    if name is None:
        raise UnknownCollectiveVerdictError(int(outcome.verdict), resp.decision_id)

    return CollectiveOutcome(
        verdict=name,
        approve_count=outcome.approve_count,
        reject_count=outcome.reject_count,
        abstain_count=outcome.abstain_count,
        declared_participant_count=outcome.declared_participant_count,
        stated_value_contradicted_tally=outcome.stated_value_contradicted_tally,
    )
