// Flows W2 (A7, S4): `flowRefOf(event)` over the generated `seam.event.v1` `SeamEvent` (tag 28).
// Attributed and UNSEALED; absence is normal and reads as `undefined`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { FlowRefSchema, SeamEventSchema, flowRefOf } from "../src/index.js";

test("flowRefOf: returns the event's FlowRef (tag 28), through the wire", () => {
  const ev = create(SeamEventSchema, {
    eventId: "e-1",
    flowRef: create(FlowRefSchema, { flowId: "flow-loans", rev: 2n ** 63n, env: "live" }),
  });
  const decoded = fromBinary(SeamEventSchema, toBinary(SeamEventSchema, ev));
  const ref = flowRefOf(decoded);
  assert.ok(ref);
  assert.equal(ref.flowId, "flow-loans");
  assert.equal(ref.rev, 2n ** 63n);
  assert.equal(ref.env, "live");
});

test("flowRefOf: absence is normal — an event without tag 28 gives undefined", () => {
  assert.equal(flowRefOf(create(SeamEventSchema, { eventId: "e-2" })), undefined);
  const decoded = fromBinary(SeamEventSchema, toBinary(SeamEventSchema, create(SeamEventSchema, {})));
  assert.equal(flowRefOf(decoded), undefined);
});

test("flowRefOf: an empty FlowRef that is present on the wire is still present", () => {
  // Message presence, not field defaults: a present-but-empty FlowRef is attribution with empty fields.
  const ev = create(SeamEventSchema, { flowRef: create(FlowRefSchema, {}) });
  const ref = flowRefOf(fromBinary(SeamEventSchema, toBinary(SeamEventSchema, ev)));
  assert.ok(ref);
  assert.equal(ref.flowId, "");
});

test("flowRefOf: the seam.api.v1 carriers (record 14, step 9, WhoAmI 5) read the same way", async () => {
  const api = await import("../gen/seam/api/v1/seam_pb.js");
  const ref = create(FlowRefSchema, { flowId: "flow-loans", rev: 2n, env: "sandbox" });
  for (const [schema, tag] of [
    [api.DecisionRecordViewSchema, 14],
    [api.SessionStepSchema, 9],
    [api.WhoAmIResponseSchema, 5],
  ] as const) {
    assert.equal(schema.fields.find((f) => f.name === "flow_ref")?.number, tag, schema.typeName);
    assert.equal(flowRefOf(create(schema, {})), undefined, schema.typeName);
    const decoded = fromBinary(schema, toBinary(schema, create(schema, { flowRef: ref })));
    assert.equal(flowRefOf(decoded)?.flowId, "flow-loans", schema.typeName);
  }
});
