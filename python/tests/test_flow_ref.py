"""Flows A7 (S4): `flow_ref_of(event)` over `seam.event.v1` `SeamEvent.flow_ref` (tag 28).

Attributed, UNSEALED, and absence is normal: an event without the stamp reads `None`, never a
default-valued `FlowRef`.
"""

from __future__ import annotations

from seam_sdk import flow_ref_of
from seam_sdk._gen.seam.event.v1 import seam_event_pb2 as ev


def test_absent_flow_ref_is_none():
    assert flow_ref_of(ev.SeamEvent(event_id="e1")) is None


def test_present_flow_ref_is_returned():
    e = ev.SeamEvent(flow_ref=ev.FlowRef(flow_id="flow-loans", rev=3, env="live"))
    ref = flow_ref_of(e)
    assert isinstance(ref, ev.FlowRef)
    assert (ref.flow_id, ref.rev, ref.env) == ("flow-loans", 3, "live")


def test_an_empty_but_set_flow_ref_is_present():
    """Presence is the message's, not its fields': a set-but-empty stamp is returned, and it survives
    a wire round-trip as present."""
    e = ev.SeamEvent()
    e.flow_ref.SetInParent()
    assert flow_ref_of(e) == ev.FlowRef()
    assert flow_ref_of(ev.SeamEvent.FromString(e.SerializeToString())) is not None


def test_the_tag_is_28():
    assert ev.SeamEvent.DESCRIPTOR.fields_by_name["flow_ref"].number == 28
