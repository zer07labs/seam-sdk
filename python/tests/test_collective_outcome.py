"""`CollectiveVerdict` must fail closed — including on a value that does not exist yet.

The proto's growth policy is normative and is copied verbatim from `AuthorizeVerdict`'s:

    any value a client does not recognize — INCLUDING COLLECTIVE_VERDICT_UNSPECIFIED — MUST route
    to the adapter's FailPolicy, never to allow. The server never emits UNSPECIFIED.

Two properties of the *generated* surface make the wrong thing easy, and both are tested here:

  * `collective_outcome` is `optional`, so absent and UNSPECIFIED are distinct wire states that a
    naive read flattens into each other;
  * proto3 makes 0 the silent default, so `verdict != DECLINED` — the natural negative test —
    allows on every unrecognized value.

The out-of-range case is the one that matters most and is the easiest to omit: it is the only test
that proves the default branch is *reachable*, and it stands in for the verdict a future runtime
adds after this SDK version shipped.
"""

from __future__ import annotations

import pytest

from seam_sdk import (
    CollectiveOutcome,
    UnknownCollectiveVerdictError,
    collective_outcome_of,
)
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb


def _resp(**outcome_kwargs) -> pb.DecisionResponse:
    resp = pb.DecisionResponse(decision_id="dec-1")
    resp.collective_outcome.CopyFrom(pb.CollectiveOutcome(**outcome_kwargs))
    return resp


# ── absent is not a verdict ────────────────────────────────────────────────────────────────────────


def test_absent_collective_outcome_returns_none_not_a_verdict() -> None:
    """A response that carries no outcome answers the question 'what did the panel decide?' with
    'this response does not say' — not with UNSPECIFIED, and not with a value."""
    resp = pb.DecisionResponse(decision_id="dec-1")
    assert not resp.HasField("collective_outcome")
    assert collective_outcome_of(resp) is None


def test_absent_is_distinguishable_from_unspecified() -> None:
    """The whole reason the field is `optional`. Reading through the raw proto conflates them; the
    decoder must not."""
    absent = pb.DecisionResponse(decision_id="dec-1")
    unspecified = _resp(verdict=pb.COLLECTIVE_VERDICT_UNSPECIFIED)

    # Raw proto: indistinguishable — both read as 0.
    assert (
        absent.collective_outcome.verdict == unspecified.collective_outcome.verdict == 0
    )

    # Decoded: distinct outcomes. None vs a raise.
    assert collective_outcome_of(absent) is None
    with pytest.raises(UnknownCollectiveVerdictError):
        collective_outcome_of(unspecified)


# ── unrecognized values fail closed ────────────────────────────────────────────────────────────────


def test_unspecified_raises_rather_than_returning_a_value() -> None:
    with pytest.raises(UnknownCollectiveVerdictError) as exc:
        collective_outcome_of(_resp(verdict=pb.COLLECTIVE_VERDICT_UNSPECIFIED))
    assert exc.value.raw_value == 0
    assert exc.value.decision_id == "dec-1"
    assert "never allow" in str(exc.value)


def test_a_verdict_this_sdk_version_does_not_know_raises() -> None:
    """The case the growth policy exists for: a value added by a runtime newer than this SDK.

    Without this test the default branch is unreachable in the suite, and an implementation that
    happened to map every *current* value would pass while silently allowing the next one.
    """
    resp = pb.DecisionResponse(decision_id="dec-1")
    resp.collective_outcome.CopyFrom(pb.CollectiveOutcome())
    # Assign past the closed set — proto3 open enums permit this on the wire, which is exactly why
    # the client must handle it.
    resp.collective_outcome.verdict = 99

    with pytest.raises(UnknownCollectiveVerdictError) as exc:
        collective_outcome_of(resp)
    assert exc.value.raw_value == 99


def test_the_error_survives_pickling() -> None:
    """Matches UnknownVerdictError's own discipline — adapters move these across process
    boundaries, and Exception's default pickling would replay __init__ with the formatted message,
    which this two-arg __init__ rejects."""
    import pickle

    original = UnknownCollectiveVerdictError(99, "dec-1")
    revived = pickle.loads(pickle.dumps(original))
    assert revived.raw_value == 99
    assert revived.decision_id == "dec-1"


# ── recognized values decode, and `approved` is the only boolean ───────────────────────────────────


@pytest.mark.parametrize(
    ("value", "name"),
    [
        (pb.COLLECTIVE_VERDICT_APPROVED, "APPROVED"),
        (pb.COLLECTIVE_VERDICT_DECLINED, "DECLINED"),
        (pb.COLLECTIVE_VERDICT_SPLIT, "SPLIT"),
        (pb.COLLECTIVE_VERDICT_ESCALATED, "ESCALATED"),
        (pb.COLLECTIVE_VERDICT_NO_VOTES, "NO_VOTES"),
    ],
)
def test_every_defined_verdict_decodes(value: int, name: str) -> None:
    outcome = collective_outcome_of(_resp(verdict=value))
    assert outcome is not None
    assert outcome.verdict == name


def test_only_approved_is_approved() -> None:
    """`approved` must be true for exactly one verdict. SPLIT in particular is real dissent sealed
    as a failed approval ATTEMPT — a helper that read it as approval would invert the panel."""
    for value, name in [
        (pb.COLLECTIVE_VERDICT_APPROVED, "APPROVED"),
        (pb.COLLECTIVE_VERDICT_DECLINED, "DECLINED"),
        (pb.COLLECTIVE_VERDICT_SPLIT, "SPLIT"),
        (pb.COLLECTIVE_VERDICT_ESCALATED, "ESCALATED"),
        (pb.COLLECTIVE_VERDICT_NO_VOTES, "NO_VOTES"),
    ]:
        outcome = collective_outcome_of(_resp(verdict=value))
        assert outcome is not None
        assert outcome.approved is (name == "APPROVED"), (
            f"{name} read as approved={outcome.approved}"
        )


def test_there_is_no_declined_boolean() -> None:
    """`not approved` must stay the safe reading. A `declined` twin would invite
    `if not o.declined: proceed`, which allows on SPLIT, ESCALATED and NO_VOTES alike."""
    assert not hasattr(CollectiveOutcome, "declined")


# ── the counters are carried, never consulted ──────────────────────────────────────────────────────


def test_counters_are_carried_through_untouched() -> None:
    outcome = collective_outcome_of(
        _resp(
            verdict=pb.COLLECTIVE_VERDICT_APPROVED,
            approve_count=2,
            reject_count=0,
            abstain_count=1,
            declared_participant_count=3,
            stated_value_contradicted_tally=True,
        )
    )
    assert outcome is not None
    assert (outcome.approve_count, outcome.reject_count, outcome.abstain_count) == (
        2,
        0,
        1,
    )
    assert outcome.declared_participant_count == 3
    assert outcome.stated_value_contradicted_tally is True


def test_the_verdict_is_never_re_derived_from_the_counters() -> None:
    """The proto states outright that the counters are observability and that a client-side tally is
    self-grading and unverifiable — which is the whole reason `verdict` is a field.

    So a tally that CONTRADICTS the verdict must decode to the verdict the runtime sent. If this
    ever fails, someone has taught the client to grade the server's own judgment.
    """
    outcome = collective_outcome_of(
        _resp(
            verdict=pb.COLLECTIVE_VERDICT_DECLINED,
            approve_count=5,  # a naive tally would call this APPROVED
            reject_count=0,
            abstain_count=0,
            declared_participant_count=5,
        )
    )
    assert outcome is not None
    assert outcome.verdict == "DECLINED"
    assert outcome.approved is False
