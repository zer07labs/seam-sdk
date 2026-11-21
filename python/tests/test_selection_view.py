"""SessionStep.selection — the live option-selection view (runtime 0.105.0, seam-runtime#1834, #399).

``optional SelectionView selection = 8`` is present on every step of a selection session and absent on
every other session. Presence means "this is a selection session", never "the threshold is met";
``has_winner`` is the rule's verdict over the entries accepted so far. It is not sealed, so it is never
verifier input: the winner a verifier trusts is the one ``verify_selection`` recomputes from the sealed
``SelectionRecord``.

The hand-written wrappers return the generated ``SessionStep`` unchanged (DECISIONS 2026-11-21), so these
tests pin the wire number (field 8: field 7 is ``decided_value``) and that presence survives the wrappers.
"""

from __future__ import annotations

import asyncio

from seam_sdk import SeamClient
from seam_sdk._gen.seam.api.v1 import seam_pb2 as pb
from seam_sdk.aio import SeamClient as AioSeamClient


def _step_with_view(has_winner: bool, winner: str) -> pb.SessionStep:
    return pb.SessionStep(
        state="Open",
        selection=pb.SelectionView(has_winner=has_winner, winner_proposal_id=winner),
    )


def test_selection_is_field_8_and_the_view_fields_are_1_and_2() -> None:
    fields = pb.SessionStep.DESCRIPTOR.fields_by_name
    assert fields["selection"].number == 8
    assert fields["decided_value"].number == 7
    view = pb.SelectionView.DESCRIPTOR.fields_by_name
    assert view["has_winner"].number == 1
    assert view["winner_proposal_id"].number == 2
    # Hand-encoded wire bytes (tag 8, length-delimited) decode into the view, so the number is the
    # runtime's, not just whatever the stub happens to call it.
    inner = b"\x08\x01" + b"\x12\x02p2"  # has_winner=true, winner_proposal_id="p2"
    step = pb.SessionStep.FromString(b"\x42" + bytes([len(inner)]) + inner)
    assert step.HasField("selection")
    assert step.selection.has_winner is True
    assert step.selection.winner_proposal_id == "p2"


def test_an_empty_view_is_still_present_presence_is_not_a_threshold() -> None:
    step = pb.SessionStep.FromString(b"\x42\x00")
    assert step.HasField("selection")
    assert step.selection.has_winner is False
    assert step.selection.winner_proposal_id == ""
    assert not pb.SessionStep(state="Open").HasField("selection")


class _StepRecorder:
    def __init__(self, step: pb.SessionStep):
        self._step = step

    def __getattr__(self, name):
        def record(req, **kw):
            return self._step

        return record


def test_submit_proposal_returns_the_live_view_with_its_presence() -> None:
    client = SeamClient.connect("127.0.0.1:1")  # lazy channel, never dialed
    client._coord = _StepRecorder(_step_with_view(True, "p-1"))
    step = client.submit_proposal("s", "agent-a", "p-1", "approve")
    assert step.HasField("selection")
    assert step.selection.has_winner and step.selection.winner_proposal_id == "p-1"

    client._coord = _StepRecorder(_step_with_view(False, ""))
    step = client.submit_proposal("s", "agent-a", "p-1", "approve")
    assert step.HasField("selection") and not step.selection.has_winner

    client._coord = _StepRecorder(pb.SessionStep(state="Open"))
    assert not client.submit_proposal("s", "agent-a", "p-1", "approve").HasField(
        "selection"
    )


def test_async_submit_proposal_returns_the_live_view_with_its_presence() -> None:
    class _AioStep:
        def __init__(self, step: pb.SessionStep):
            self._step = step

        def __getattr__(self, name):
            async def record(req, **kw):
                return self._step

            return record

    async def scenario() -> None:
        client = AioSeamClient.connect("127.0.0.1:1")  # lazy channel, never dialed
        client._coord = _AioStep(_step_with_view(True, "p-2"))
        step = await client.submit_proposal("s", "agent-a", "p-2", "approve")
        assert step.HasField("selection") and step.selection.winner_proposal_id == "p-2"
        client._coord = _AioStep(pb.SessionStep(state="Open"))
        assert not (
            await client.submit_proposal("s", "agent-a", "p-2", "approve")
        ).HasField("selection")
        await client.close()

    asyncio.run(scenario())
