"""``allocation_of`` — reading which experiment arm a fetched record was allocated to (runtime 0.76.0,
Branchpoint BP-8).

The case table lives in ``fixtures/allocation_cases.json`` and the TypeScript suite reads the same
file, so the two decoders are held to one table rather than two that can drift.
"""

from __future__ import annotations

import dataclasses
import json
import math
import pathlib
import struct

import pytest

from seam_sdk import Allocation, AllocationView, allocation_of, seal_attestation_of
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb

CASES_PATH = pathlib.Path(__file__).parent / "fixtures" / "allocation_cases.json"
CASES = json.loads(CASES_PATH.read_text(encoding="utf-8"))["cases"]

FIELDS = [
    "mode",
    "experiment_id",
    "variant_id",
    "intended_action",
    "served_action",
    "allocation_propensity",
    "budget_bp",
    "budget_epoch",
    "snapshot_id",
    "unit_tag",
    "unit_digest",
    "bucket_version",
    "commitment_kid",
    "decision_point",
]


def _inner(wire: dict) -> pb.Allocation:
    fields = dict(wire)
    fields["budget_epoch"] = int(fields["budget_epoch"])
    return pb.Allocation(**fields)


def _view(wire: dict | None) -> pb.DecisionRecordView:
    view = pb.DecisionRecordView(decision_id="dec-bp8")
    if wire is None:
        return view
    view.allocation.availability = wire["availability"]
    if wire["allocation"] is not None:
        view.allocation.allocation.CopyFrom(_inner(wire["allocation"]))
        # An all-zero inner message is still present on the wire.
        view.allocation.allocation.SetInParent()
    # Presence of the view must not hinge on a non-default field: an all-zero (UNSPECIFIED) view is
    # still present.
    view.allocation.SetInParent()
    return view


def _expected(expect: dict | None) -> AllocationView | None:
    if expect is None:
        return None
    inner = None
    if expect["allocation"] is not None:
        fields = dict(expect["allocation"])
        fields["budget_epoch"] = int(fields["budget_epoch"])
        inner = Allocation(**fields)
    return AllocationView(availability=expect["availability"], allocation=inner)


def test_the_case_table_is_not_empty() -> None:
    assert len(CASES) >= 20


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_the_shared_case_table(case: dict) -> None:
    got = allocation_of(_view(case["wire"]))
    assert got == _expected(case["expect"])
    # And identically after a wire round trip — presence survives serialisation.
    revived = pb.DecisionRecordView.FromString(_view(case["wire"]).SerializeToString())
    assert allocation_of(revived) == got


@pytest.mark.parametrize(
    "value",
    [v.number for v in pb.AllocationAvailability.DESCRIPTOR.values],
    ids=[v.name for v in pb.AllocationAvailability.DESCRIPTOR.values],
)
def test_every_availability_the_stubs_define_decodes_without_raising(
    value: int,
) -> None:
    """Parametrised from the enum descriptor, not from this SDK's own name map: a value a later
    regeneration adds lands here and must read "UNRECOGNIZED" (WITHHELD) until it is named, rather
    than raising or being read as RECORDED."""
    view = _view({"availability": value, "allocation": None})
    got = allocation_of(view)
    assert got is not None
    name = pb.AllocationAvailability.Name(value).removeprefix(
        "ALLOCATION_AVAILABILITY_"
    )
    assert got.availability == ("UNRECOGNIZED" if name == "UNSPECIFIED" else name)


@pytest.mark.parametrize(
    "value",
    [
        v.number
        for v in pb.AllocationAvailability.DESCRIPTOR.values
        if v.number != pb.ALLOCATION_AVAILABILITY_RECORDED
    ]
    + [7, 99],
    ids=[
        v.name
        for v in pb.AllocationAvailability.DESCRIPTOR.values
        if v.number != pb.ALLOCATION_AVAILABILITY_RECORDED
    ]
    + ["unknown-7", "unknown-99"],
)
def test_no_availability_but_recorded_reads_the_payload(value: int) -> None:
    """Over every availability: a populated inner Allocation is NOT read outside RECORDED."""
    view = pb.DecisionRecordView(decision_id="dec-bp8")
    view.allocation.availability = value
    view.allocation.allocation.mode = "split"
    view.allocation.allocation.experiment_id = "exp-1"
    view.allocation.allocation.allocation_propensity = 0.5
    got = allocation_of(view)
    assert got is not None
    assert got.availability != "RECORDED"
    assert got.allocation is None


@pytest.mark.parametrize("bits", [0x8000000000000000, 0x7FF8000000000001])
def test_negative_zero_and_nan_propensities_pass_through_bit_exact(bits: int) -> None:
    """JSON cannot carry -0.0 or NaN, so the shared table cannot either. The decoder does no
    clamping or normalising: the double it returns is the double on the wire, bit for bit."""
    value = struct.unpack("<d", struct.pack("<Q", bits))[0]
    view = pb.DecisionRecordView(decision_id="dec-bp8")
    view.allocation.availability = pb.ALLOCATION_AVAILABILITY_RECORDED
    view.allocation.allocation.allocation_propensity = value
    revived = pb.DecisionRecordView.FromString(view.SerializeToString())
    got = allocation_of(revived)
    assert got is not None and got.allocation is not None
    out = got.allocation.allocation_propensity
    assert struct.pack("<d", out) == struct.pack("<d", value)
    if bits == 0x8000000000000000:
        assert out == 0.0 and math.copysign(1.0, out) == -1.0
    else:
        assert math.isnan(out)


def test_budget_epoch_keeps_full_uint64_precision() -> None:
    view = pb.DecisionRecordView(decision_id="dec-bp8")
    view.allocation.availability = pb.ALLOCATION_AVAILABILITY_RECORDED
    view.allocation.allocation.budget_epoch = 2**64 - 1
    revived = pb.DecisionRecordView.FromString(view.SerializeToString())
    got = allocation_of(revived)
    assert got.allocation.budget_epoch == 2**64 - 1
    assert isinstance(got.allocation.budget_epoch, int)


def test_the_dataclasses_are_frozen_with_exactly_their_fields() -> None:
    """Adding a convenience boolean or a raw-int field must be a visible edit to this test."""
    assert [f.name for f in dataclasses.fields(AllocationView)] == [
        "availability",
        "allocation",
    ]
    assert [f.name for f in dataclasses.fields(Allocation)] == FIELDS
    view = AllocationView(availability="NOT_RECORDED", allocation=None)
    with pytest.raises(dataclasses.FrozenInstanceError):
        view.availability = "RECORDED"  # type: ignore[misc]
    got = allocation_of(_view(CASES_BY_NAME["RECORDED split"]["wire"]))
    with pytest.raises(dataclasses.FrozenInstanceError):
        got.allocation.variant_id = "arm-a"  # type: ignore[misc,union-attr]


CASES_BY_NAME = {c["name"]: c for c in CASES}


def test_the_dataclass_mirrors_the_proto_field_for_field() -> None:
    """``Allocation`` is the proto message field for field and in tag order; a field a later
    regeneration adds turns this red rather than being silently dropped by the decoder."""
    proto = sorted(pb.Allocation.DESCRIPTOR.fields, key=lambda f: f.number)
    assert [f.name for f in proto] == FIELDS
    assert [f.number for f in proto] == list(range(1, 15))


@pytest.mark.parametrize("message", ["DecisionResponse", "SessionStep", "ReplayView"])
def test_a_message_without_the_field_raises_rather_than_answering(message: str) -> None:
    """Python does not enforce the annotation. A non-carrier is a programming error and surfaces as
    one, rather than a ``None`` that reads as "an older runtime"."""
    with pytest.raises(ValueError, match='no "allocation" field'):
        allocation_of(getattr(pb, message)())


def test_the_descriptor_claims_the_decoder_rests_on() -> None:
    """``allocation`` and its inner ``allocation`` have presence, so ``HasField`` gates them; the
    inner scalars have none, which is why they decode as raw values rather than Optionals. A
    descriptor change turns this red rather than leaving the module docstring quietly wrong."""
    field = pb.DecisionRecordView.DESCRIPTOR.fields_by_name["allocation"]
    assert field.number == 13 and field.has_presence is True
    view_fields = pb.AllocationView.DESCRIPTOR.fields_by_name
    assert view_fields["availability"].number == 1
    assert view_fields["availability"].has_presence is False
    assert view_fields["allocation"].number == 2
    assert view_fields["allocation"].has_presence is True
    assert all(not f.has_presence for f in pb.Allocation.DESCRIPTOR.fields)


def test_the_allocation_and_the_seal_attestation_decode_independently() -> None:
    """A withheld allocation does not withhold the seal attestation, and vice versa."""
    view = pb.DecisionRecordView(decision_id="dec-bp8")
    view.allocation.availability = pb.ALLOCATION_AVAILABILITY_CLEARANCE_DENIED
    view.seal_attestation.availability = pb.SEAL_ATTESTATION_AVAILABILITY_NOT_RECORDED
    assert allocation_of(view).availability == "CLEARANCE_DENIED"
    assert seal_attestation_of(view).availability == "NOT_RECORDED"
    only_seal = pb.DecisionRecordView(decision_id="dec-bp8")
    only_seal.seal_attestation.SetInParent()
    assert allocation_of(only_seal) is None
    assert seal_attestation_of(only_seal) is not None
