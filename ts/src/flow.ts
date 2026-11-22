// Flows W2 (A7, S4): the flow attribution a `seam.event.v1` event carries (tag 28).
//
// Normative: seam-runtime `docs/specs/seam-event.v1.md` (tag 28 `flow_ref`). Since runtime 0.112.0 the
// same `FlowRef` is on `seam.api.v1` `DecisionRecordView` (14), `SessionStep` (9) and `WhoAmIResponse`
// (5); the runtime has no writer for any of them yet, so each reads `undefined` until it does.

import type { DecisionRecordView, SessionStep, WhoAmIResponse } from "../gen/seam/api/v1/seam_pb.js";
import type { FlowRef, SeamEvent } from "../gen/seam/event/v1/seam_event_pb.js";

/** Every generated message that carries `flow_ref`. */
export type FlowRefCarrier = SeamEvent | DecisionRecordView | SessionStep | WhoAmIResponse;

/** The flow an event, decision record, session step or WhoAmI answer is attributed to — its `flow_ref`
 * — or `undefined` when it carries none.
 *
 * **Attributed, UNSEALED.** `flow_ref` is in no digest, checksum or signature, and its `rev` never enters
 * any byte, so nothing here proves it: treat it as a routing and display hint, never as evidence. The
 * verified flow binding is the chain (tag 29, through its genesis) and, from W4, the v6 commitment's env.
 *
 * **Absence is normal.** Unattributed sessions, ungoverned namespaces and every event emitted before the
 * writer ships carry no `flow_ref`; `undefined` is an ordinary answer, not an error. */
export function flowRefOf(event: FlowRefCarrier): FlowRef | undefined {
  return event.flowRef ?? undefined;
}
