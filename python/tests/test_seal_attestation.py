"""``seal_attestation_of`` — reading why a fetched record was sealed (runtime 0.61.0, seam-sdk#273).

The case table lives in ``fixtures/seal_attestation_cases.json`` and the TypeScript suite reads the
same file, so the two decoders are held to one table rather than two that can drift.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import pickle

import pytest

from seam_sdk import (
    CollectiveOutcome,
    SealAttestation,
    UnknownCollectiveVerdictError,
    collective_outcome_of,
    policy_enforcement_of,
    seal_attestation_of,
)
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb

CASES_PATH = pathlib.Path(__file__).parent / "fixtures" / "seal_attestation_cases.json"
CASES = json.loads(CASES_PATH.read_text(encoding="utf-8"))["cases"]


def _collective(wire: dict) -> pb.CollectiveOutcome:
    msg = pb.CollectiveOutcome(
        verdict=wire["verdict"],
        approve_count=wire["approve_count"],
        reject_count=wire["reject_count"],
        abstain_count=wire["abstain_count"],
        declared_participant_count=wire["declared_participant_count"],
        stated_value_contradicted_tally=wire["stated_value_contradicted_tally"],
    )
    if wire["effective_threshold"] is not None:
        msg.effective_threshold = wire["effective_threshold"]
    return msg


def _view(attestation: dict | None) -> pb.DecisionRecordView:
    view = pb.DecisionRecordView(decision_id="dec-273")
    if attestation is None:
        return view
    view.seal_attestation.availability = attestation["availability"]
    view.seal_attestation.seal_reason = attestation["seal_reason"]
    if attestation["collective"] is not None:
        view.seal_attestation.collective_outcome.CopyFrom(
            _collective(attestation["collective"])
        )
    # Presence of the attestation must not hinge on a non-default field being set: an all-zero
    # attestation (UNSPECIFIED) is still present on the wire.
    view.seal_attestation.SetInParent()
    return view


def test_the_case_table_is_not_empty() -> None:
    """Anti-vacuity: a renamed or emptied fixture would make the parametrised test pass on nothing."""
    assert len(CASES) >= 15


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_the_shared_case_table(case: dict) -> None:
    view = _view(case["attestation"])
    expect = case["expect"]

    if expect == "raise":
        with pytest.raises(UnknownCollectiveVerdictError) as exc:
            seal_attestation_of(view)
        assert exc.value.raw_value == case["attestation"]["collective"]["verdict"]
        assert exc.value.decision_id == "dec-273"
        return

    got = seal_attestation_of(view)
    if expect is None:
        assert got is None
        return

    assert isinstance(got, SealAttestation)
    assert got.availability == expect["availability"]
    assert got.seal_reason == expect["seal_reason"]
    if expect["collective"] is None:
        assert got.collective_outcome is None
    else:
        assert got.collective_outcome == CollectiveOutcome(**expect["collective"])


@pytest.mark.parametrize(
    "value",
    [v.number for v in pb.SealAttestationAvailability.DESCRIPTOR.values],
    ids=[v.name for v in pb.SealAttestationAvailability.DESCRIPTOR.values],
)
def test_every_availability_the_stubs_define_decodes_without_raising(
    value: int,
) -> None:
    """Parametrised from the enum descriptor, not from this SDK's own name map: a value a later
    regeneration adds lands here and must read "UNRECOGNIZED" (WITHHELD) until it is named, rather
    than raising or being read as RECORDED."""
    view = _view({"availability": value, "seal_reason": 1, "collective": None})
    got = seal_attestation_of(view)
    assert got is not None
    name = pb.SealAttestationAvailability.Name(value).removeprefix(
        "SEAL_ATTESTATION_AVAILABILITY_"
    )
    if name == "UNSPECIFIED":
        assert got.availability == "UNRECOGNIZED"
    else:
        assert got.availability == name
    if got.availability != "RECORDED":
        assert got.seal_reason is None


@pytest.mark.parametrize(
    "value",
    [v.number for v in pb.SealReason.DESCRIPTOR.values],
    ids=[v.name for v in pb.SealReason.DESCRIPTOR.values],
)
def test_every_seal_reason_the_stubs_define_decodes_under_recorded(value: int) -> None:
    view = _view({"availability": 1, "seal_reason": value, "collective": None})
    got = seal_attestation_of(view)
    assert got is not None
    name = pb.SealReason.Name(value).removeprefix("SEAL_REASON_")
    assert got.seal_reason == ("UNRECOGNIZED" if name == "UNSPECIFIED" else name)


def test_the_sealed_collective_decodes_exactly_like_the_immediate_one() -> None:
    """AC3: one verdict mapping, not two. The record's sealed collective and the immediate
    response's top-level one decode to equal objects, ``effective_threshold`` presence included."""
    for threshold in (None, 0, 2):
        wire = {
            "verdict": pb.COLLECTIVE_VERDICT_SPLIT,
            "approve_count": 1,
            "reject_count": 1,
            "abstain_count": 1,
            "declared_participant_count": 3,
            "stated_value_contradicted_tally": False,
            "effective_threshold": threshold,
        }
        view = _view({"availability": 1, "seal_reason": 1, "collective": wire})
        resp = pb.DecisionResponse(decision_id="dec-273")
        resp.collective_outcome.CopyFrom(_collective(wire))

        sealed = seal_attestation_of(view)
        assert sealed is not None
        assert sealed.collective_outcome == collective_outcome_of(resp)
        assert sealed.collective_outcome.effective_threshold == threshold


def test_the_unknown_verdict_error_survives_pickling() -> None:
    view = _view(
        {
            "availability": 1,
            "seal_reason": 1,
            "collective": {
                "verdict": 99,
                "approve_count": 0,
                "reject_count": 0,
                "abstain_count": 0,
                "declared_participant_count": 0,
                "stated_value_contradicted_tally": False,
                "effective_threshold": None,
            },
        }
    )
    with pytest.raises(UnknownCollectiveVerdictError) as exc:
        seal_attestation_of(view)
    revived = pickle.loads(pickle.dumps(exc.value))
    assert (revived.raw_value, revived.decision_id) == (99, "dec-273")


def test_seal_attestation_is_frozen_with_exactly_three_fields() -> None:
    """AC6. Adding a convenience boolean or a raw-int field must be a visible edit to this test."""
    assert [f.name for f in dataclasses.fields(SealAttestation)] == [
        "availability",
        "seal_reason",
        "collective_outcome",
    ]
    att = SealAttestation(
        availability="NOT_RECORDED", seal_reason=None, collective_outcome=None
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        att.availability = "RECORDED"  # type: ignore[misc]


@pytest.mark.parametrize("message", ["DecisionResponse", "SessionStep", "ReplayView"])
def test_a_message_without_the_field_raises_rather_than_answering(message: str) -> None:
    """Python does not enforce the annotation. A non-carrier is a programming error and surfaces as
    one, rather than a ``None`` that reads as "an older runtime"."""
    with pytest.raises(ValueError, match='no "seal_attestation" field'):
        seal_attestation_of(getattr(pb, message)())


def test_a_wire_round_trip_decodes_the_same() -> None:
    wire = {
        "verdict": pb.COLLECTIVE_VERDICT_APPROVED,
        "approve_count": 3,
        "reject_count": 0,
        "abstain_count": 0,
        "declared_participant_count": 3,
        "stated_value_contradicted_tally": False,
        "effective_threshold": 3,
    }
    view = _view({"availability": 1, "seal_reason": 1, "collective": wire})
    revived = pb.DecisionRecordView.FromString(view.SerializeToString())
    assert seal_attestation_of(revived) == seal_attestation_of(view)
    assert seal_attestation_of(revived).collective_outcome.approved is True


def test_an_all_zero_attestation_is_present_not_absent() -> None:
    """An attestation whose every field is the zero value is still PRESENT on the wire (explicit
    presence on a message field), and must read UNRECOGNIZED rather than collapse to "older
    runtime"."""
    view = pb.DecisionRecordView(decision_id="dec-273")
    view.seal_attestation.SetInParent()
    revived = pb.DecisionRecordView.FromString(view.SerializeToString())
    got = seal_attestation_of(revived)
    assert got == SealAttestation(
        availability="UNRECOGNIZED", seal_reason=None, collective_outcome=None
    )


def test_policy_enforcement_still_answers_on_a_key_unavailable_record() -> None:
    """The proto: after crypto-shred "the structural columns and ``policy_enforcement`` still
    answer". The two decoders are independent; a withheld attestation does not withhold the other."""
    view = _view({"availability": 3, "seal_reason": 0, "collective": None})
    view.policy_enforcement.enforced = True
    view.policy_enforcement.policy_id = "p-1"
    assert seal_attestation_of(view).availability == "KEY_UNAVAILABLE"
    pe = policy_enforcement_of(view)
    assert pe is not None and pe.enforced and pe.policy_id == "p-1"


def test_the_descriptor_claims_the_stay_raw_decision_rests_on() -> None:
    """``seal_attestation`` and its ``collective_outcome`` have presence, so ``HasField`` gates
    them; ``policy_version`` / ``policy_rules_digest`` have none, which is why they stay raw (there
    is no absent-vs-empty distinction to preserve). A descriptor change turns this red rather than
    leaving the module docstring quietly wrong."""
    view_fields = pb.DecisionRecordView.DESCRIPTOR.fields_by_name
    assert view_fields["seal_attestation"].number == 12
    assert view_fields["seal_attestation"].has_presence is True
    assert view_fields["policy_version"].number == 9
    assert view_fields["policy_version"].has_presence is False
    assert view_fields["policy_rules_digest"].number == 10
    assert view_fields["policy_rules_digest"].has_presence is False
    att_fields = pb.SealAttestation.DESCRIPTOR.fields_by_name
    assert att_fields["collective_outcome"].has_presence is True
    assert att_fields["availability"].has_presence is False
    assert att_fields["seal_reason"].has_presence is False


@pytest.mark.parametrize(
    "value",
    [
        v.number
        for v in pb.SealAttestationAvailability.DESCRIPTOR.values
        if v.number != pb.SEAL_ATTESTATION_AVAILABILITY_RECORDED
    ]
    + [99],
    ids=[
        v.name
        for v in pb.SealAttestationAvailability.DESCRIPTOR.values
        if v.number != pb.SEAL_ATTESTATION_AVAILABILITY_RECORDED
    ]
    + ["unknown-99"],
)
@pytest.mark.parametrize("verdict", [pb.COLLECTIVE_VERDICT_APPROVED, 99])
def test_no_availability_but_recorded_reads_the_payload(
    value: int, verdict: int
) -> None:
    """AC2, over every availability: a payload carrying ``seal_reason=COMMIT`` and a collective is
    NOT read outside RECORDED — not decoded (APPROVED does not surface) and not validated (an
    unknown verdict does not raise). The payload is meaningful only under RECORDED."""
    view = _view(
        {
            "availability": value,
            "seal_reason": pb.SEAL_REASON_COMMIT,
            "collective": {
                "verdict": verdict,
                "approve_count": 1,
                "reject_count": 0,
                "abstain_count": 0,
                "declared_participant_count": 1,
                "stated_value_contradicted_tally": False,
                "effective_threshold": 1,
            },
        }
    )
    got = seal_attestation_of(view)
    assert got is not None
    assert got.availability != "RECORDED"
    assert got.seal_reason is None
    assert got.collective_outcome is None
