// Flows W2 (A7, S4): the flow attribution a `seam.event.v1` event carries (tag 28).
//
// Normative: seam-runtime `docs/specs/seam-event.v1.md` (tag 28 `flow_ref`). The api-side twin (the
// record's and WhoAmI's `flow_ref`) waits for `seam.api.v1` to carry the field; this reader is the event
// half only.

import type { FlowRef, SeamEvent } from "../gen/seam/event/v1/seam_event_pb.js";

/** The flow this event's session (or namespace) is attributed to — `SeamEvent.flow_ref` (tag 28) — or
 * `undefined` when the event carries none.
 *
 * **Attributed, UNSEALED.** `flow_ref` is in no digest, checksum or signature, and its `rev` never enters
 * any byte, so nothing here proves it: treat it as a routing and display hint, never as evidence. The
 * verified flow binding is the chain (tag 29, through its genesis) and, from W4, the v6 commitment's env.
 *
 * **Absence is normal.** Unattributed sessions, ungoverned namespaces and every event emitted before the
 * writer ships carry no `flow_ref`; `undefined` is an ordinary answer, not an error. */
export function flowRefOf(event: SeamEvent): FlowRef | undefined {
  return event.flowRef ?? undefined;
}
