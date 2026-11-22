"""Flows A7 (S4): ``flow_ref``, read presence-aware, from an event or a record.

A Flows event carries the ``FlowRef {flow_id, rev, env}`` its session was opened under. The stamp is
**attributed, not sealed**: it sits outside record digest v4 and outside every commitment digest, so it
says which flow the runtime attributed the event to and proves nothing. Evidence is the sealed record
(the v6 env in field 12, the chain genesis), never this field. A consumer must not treat it as evidence.

**Absence is normal** (ruling 6): an event with no ``flow_ref`` is a non-Flows session, an ungoverned
seal, or a namespace that maps to no (flow, env). It is never an error and never a refusal.

It reads ``seam.event.v1`` ``SeamEvent.flow_ref`` (tag 28) and, since runtime 0.112.0, the same
``FlowRef`` on ``seam.api.v1`` ``DecisionRecordView`` (14), ``SessionStep`` (9) and ``WhoAmIResponse`` (5).
The runtime has no writer for any of them yet, so every one reads ``None`` until it does.
"""

from __future__ import annotations

from typing import Optional, Union

from seam_sdk._gen.seam.api.v1 import seam_pb2 as _pb
from seam_sdk._gen.seam.event.v1 import seam_event_pb2 as _ev

#: Every message that carries ``flow_ref``. A message outside this set raises ``TypeError``: a caller
#: passing the wrong object must not read "no flow".
FlowRefCarrier = Union[
    _ev.SeamEvent, _pb.DecisionRecordView, _pb.SessionStep, _pb.WhoAmIResponse
]
_CARRIERS = (_ev.SeamEvent, _pb.DecisionRecordView, _pb.SessionStep, _pb.WhoAmIResponse)


def flow_ref_of(event: FlowRefCarrier) -> Optional[_ev.FlowRef]:
    """The ``FlowRef`` an event, decision record, session step or WhoAmI answer carries, or ``None``.

    Attributed, UNSEALED: outside every digest, so it names the flow the runtime attributed the event to
    and is not evidence of it. Absence is normal (a non-Flows session, or an unmapped namespace) and is
    never an error. Read with ``HasField``, so an absent message is ``None``, never a default-valued
    ``FlowRef`` that would read as ``flow_id=""``.
    """
    if not isinstance(event, _CARRIERS):
        raise TypeError(
            f"flow_ref_of takes {', '.join(c.__name__ for c in _CARRIERS)}, not {type(event).__name__}"
        )
    return event.flow_ref if event.HasField("flow_ref") else None
