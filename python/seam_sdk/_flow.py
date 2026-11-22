"""Flows A7 (S4): ``SeamEvent.flow_ref`` (``seam.event.v1`` tag 28), read presence-aware.

A Flows event carries the ``FlowRef {flow_id, rev, env}`` its session was opened under. The stamp is
**attributed, not sealed**: it sits outside record digest v4 and outside every commitment digest, so it
says which flow the runtime attributed the event to and proves nothing. Evidence is the sealed record
(the v6 env in field 12, the chain genesis), never this field. A consumer must not treat it as evidence.

**Absence is normal** (ruling 6): an event with no ``flow_ref`` is a non-Flows session, an ungoverned
seal, or a namespace that maps to no (flow, env). It is never an error and never a refusal.

The record-side accessor waits for ``seam.api.v1`` to carry ``flow_ref``; only the event form exists.
"""

from __future__ import annotations

from typing import Optional

from seam_sdk._gen.seam.event.v1 import seam_event_pb2 as _ev


def flow_ref_of(event: _ev.SeamEvent) -> Optional[_ev.FlowRef]:
    """The event's ``FlowRef``, or ``None`` when it carries none.

    Attributed, UNSEALED: outside every digest, so it names the flow the runtime attributed the event to
    and is not evidence of it. Absence is normal (a non-Flows session, or an unmapped namespace) and is
    never an error. Read with ``HasField``, so an absent message is ``None``, never a default-valued
    ``FlowRef`` that would read as ``flow_id=""``.
    """
    return event.flow_ref if event.HasField("flow_ref") else None
