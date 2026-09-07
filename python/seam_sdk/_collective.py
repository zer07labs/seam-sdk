"""Fail-closed decoding of ``collective_outcome`` — on a ``DecisionResponse`` or a
``SessionStep`` (C5).

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
from typing import Optional, Union

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
    a panel of 3 with 2 APPROVE votes is denied for not all having voted. It is **unanimous's**
    denominator and not the universal one: a QUORUM round's denominator is
    ``effective_threshold``, and reading the declared count as quorum's is the specific misreading
    the proto records as having let a round that MISSED its bar seal with an APPROVED verdict.
    """

    verdict: (
        str  # "APPROVED" | "DECLINED" | "SPLIT" | "ESCALATED" | "NO_VOTES" — closed set
    )
    approve_count: int
    reject_count: int  # REJECT and BLOCK both, matching the runtime's own fold
    abstain_count: int  # includes ESCALATE / REVIEW
    declared_participant_count: int
    stated_value_contradicted_tally: bool
    #: The quorum round's EFFECTIVE APPROVAL THRESHOLD — how many APPROVE ballots the round actually
    #: needed, after any bound policy override REPLACED the wire's ``required_approvals``. This is
    #: quorum's denominator; :attr:`declared_participant_count` is unanimous's.
    #:
    #: ``None`` means NOT APPLICABLE, and a caller must never read it as zero. The field is
    #: ``optional`` on the wire for exactly that reason: decision mode has no threshold concept, so
    #: a present-but-meaningless ``0`` would be a fabricated claim rather than a missing one — and
    #: ``0`` is the more dangerous of the two to fabricate, because "zero approvals needed" reads as
    #: satisfied by every round. Absence also covers the producer's narrower fail-silent path (an
    #: unreadable round state), which is why the proto promises presence on a quorum commit-terminal
    #: step *whose round state is readable* rather than on every quorum step.
    effective_threshold: Optional[int] = None

    @property
    def approved(self) -> bool:
        """True **only** for an unambiguous APPROVED verdict.

        Deliberately the sole boolean on this type, and deliberately positive: every other verdict —
        DECLINED, SPLIT, ESCALATED, NO_VOTES — is not an approval, and an unrecognized one never
        reaches here because :func:`collective_outcome_of` raised before constructing this object.
        There is no ``declined`` twin, because ``not approved`` must stay the safe reading."""
        return self.verdict == "APPROVED"


def collective_outcome_of(
    resp: Union["pb.DecisionResponse", "pb.SessionStep"],
) -> Optional[CollectiveOutcome]:
    """Decode ``resp.collective_outcome``, fail-closed. Accepts a ``DecisionResponse`` **or** a
    ``SessionStep``.

    Returns ``None`` **iff the field is absent** — the runtime did not carry one on this response
    (an older runtime, or a read verb that never does). ``None`` is not "the panel decided nothing";
    it is "this response does not answer the question", and a caller must decide what that means for
    its own fail policy rather than being handed a value.

    **On a ``SessionStep``, absent is the common case and does not mean "not supported".** The field
    is present ONLY on the step that applied the commit envelope and sealed the session; it is absent
    on every open/propose/vote/ballot step, and also on the sealed-idempotent replay and the
    pending-commitment seal retry
    (``seam.api.v1``, ``SessionStep.collective_outcome`` field 4 — cited by field, not by line: the
    proto lives in another repository that nothing here tracks or gates). Read ``None`` from a
    non-terminal step as "not yet decided", never as a missing feature.

    One decoder, two message types, on purpose: the hazard being guarded is a property of the FIELD —
    ``optional`` presence over an open enum whose zero value is UNSPECIFIED — not of the message that
    carries it. A second implementation per message type would be a second place for the fail-open
    inversion to reappear.

    Python accepted a ``SessionStep`` here by accident before this was declared — both ``HasField``
    and ``decision_id`` happen to exist on it — but an accident is not a contract, and TypeScript's
    branded types rejected the same call outright. The union is the contract; the behaviour is
    unchanged.

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
        # `HasField`, never a bare read: `effective_threshold` is `optional uint32`, so proto3 hands
        # back `0` when it is absent — and unlike the counters, `0` is not a harmless zero here. It
        # is a threshold every round meets. Presence is the only thing that separates "this mode has
        # no bar" from "the bar is nothing", and this is the one place that distinction is made.
        effective_threshold=(
            outcome.effective_threshold
            if outcome.HasField("effective_threshold")
            else None
        ),
    )
