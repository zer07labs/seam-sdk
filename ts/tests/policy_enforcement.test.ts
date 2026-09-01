// `policyEnforcement` must keep "the runtime did not say" apart from "the runtime said no".
//
// The TS hazard is NOT the same shape as Python's, and this suite is written against the real one.
// In `seam_sdk._policy` the two states are *value-identical*: `resp.policy_enforcement` compares
// equal whether the field is absent or present-with-`enforced=False`, and only `HasField` separates
// them. protobuf-es models presence natively — absent is `undefined`, present is an object — so here
// they are distinguishable *by value*. What collapses them is every idiomatic read:
//
//     if (resp.policyEnforcement?.enforced) { … }   // WRONG — falsy for BOTH states
//     if (!resp.policyEnforcement?.enforced) { … }  // WRONG — true for BOTH states
//
// `undefined` and `false` are different values and the same truthiness, and truthiness is what a
// caller actually writes. So the property under test is not "can these be told apart" (the generated
// surface already can) but "does the decoder hand back something whose falsiness cannot answer a
// question the runtime never answered" — which is why absent returns `undefined` and present-false
// returns an object that is itself truthy.
//
// Every message here is built with `create(...)`; nothing reads a fixture or depends on the ambient
// generated surface beyond the three schemas imported below.

import { test } from "node:test";
import assert from "node:assert/strict";
import { create, toBinary, fromBinary } from "@bufbuild/protobuf";

import {
  DecisionResponseSchema,
  PolicyEnforcementSchema,
  SessionStepSchema,
} from "../gen/seam/api/v1/seam_pb.js";
import { policyEnforcementOf } from "../src/client.js";

/** A `SessionStep` in `state`, with `policyEnforcement` absent unless `pe` is given. */
function step(
  pe?: { enforced: boolean; policyId?: string },
  state = "open",
): ReturnType<typeof create<typeof SessionStepSchema>> {
  const s = create(SessionStepSchema, { state });
  if (pe !== undefined) s.policyEnforcement = create(PolicyEnforcementSchema, pe);
  return s;
}

/** A `DecisionResponse`, same convention. */
function resp(
  pe?: { enforced: boolean; policyId?: string },
): ReturnType<typeof create<typeof DecisionResponseSchema>> {
  const r = create(DecisionResponseSchema, { decisionId: "dec-1" });
  if (pe !== undefined) r.policyEnforcement = create(PolicyEnforcementSchema, pe);
  return r;
}

test("a SessionStep compiles as an argument at all — protobuf-es brands message types", () => {
  // The assertion is partly the *compilation* of this file: `SessionStep` and `DecisionResponse`
  // carry distinct `$typeName` brands, so a decoder typed to one rejects the other with TS2345.
  // Kept as a real call so it cannot be dropped as dead code.
  assert.equal(policyEnforcementOf(step()), undefined);
});

// ── The phase: these two tests together are the whole point ───────────────────────────────────────

test("an absent field returns undefined — not an instance reporting enforced=false", () => {
  assert.equal(policyEnforcementOf(step()), undefined);
  assert.equal(policyEnforcementOf(resp()), undefined);
});

test("present with enforced=false returns an INSTANCE, not undefined", () => {
  // Returning `undefined` here would be the fail-open inversion: it would report "the runtime never
  // told me" for a response on which the runtime explicitly said "no policy gated this".
  const fromStep = policyEnforcementOf(step({ enforced: false }));
  const fromResp = policyEnforcementOf(resp({ enforced: false }));
  for (const got of [fromStep, fromResp]) {
    assert.notEqual(got, undefined);
    assert.equal(got?.enforced, false);
  }
});

test("the decoder separates the two states that every truthiness read collapses", () => {
  const absent = step();
  const present = step({ enforced: false });

  // What a caller would naturally write: identical for both, in both directions.
  assert.equal(!absent.policyEnforcement?.enforced, !present.policyEnforcement?.enforced);
  assert.equal(Boolean(absent.policyEnforcement?.enforced), false);
  assert.equal(Boolean(present.policyEnforcement?.enforced), false);

  // What the decoder gives: distinguishable, and distinguishable *by truthiness* rather than only
  // by an explicit `=== undefined` the caller has to remember to write.
  assert.equal(policyEnforcementOf(absent), undefined);
  assert.ok(policyEnforcementOf(present));
});

// ── policyId: absent and explicitly-empty are different answers ───────────────────────────────────

test("policyId is undefined when absent, and never the empty string", () => {
  assert.equal(policyEnforcementOf(step({ enforced: false }))?.policyId, undefined);
  assert.equal(policyEnforcementOf(step({ enforced: true }))?.policyId, undefined);
});

test("policyId is '' when explicitly empty — collapsing it to undefined is this module's own bug", () => {
  const got = policyEnforcementOf(step({ enforced: true, policyId: "" }));
  assert.equal(got?.policyId, "");
  assert.notEqual(got?.policyId, undefined);
});

test("policyId carries through unchanged when set", () => {
  assert.equal(
    policyEnforcementOf(step({ enforced: true, policyId: "pol-42" }))?.policyId,
    "pol-42",
  );
});

// ── The two carriers must not drift apart ─────────────────────────────────────────────────────────

test("a SessionStep and a DecisionResponse decode identically", () => {
  // Field numbers differ (3 on SessionStep, 7 on DecisionResponse) and both have explicit presence,
  // so one decoder covers both. A second implementation per carrier is a second place to invert.
  assert.deepEqual(
    policyEnforcementOf(step({ enforced: true, policyId: "pol-1" })),
    policyEnforcementOf(resp({ enforced: true, policyId: "pol-1" })),
  );
  assert.deepEqual(policyEnforcementOf(step()), policyEnforcementOf(resp()));
});

test("state does not influence the decoder", () => {
  // `state` is free-form and the decoder never reads it. Asserted as irrelevance rather than
  // dressed up as several cases: a loop over state strings proves one property, not four.
  for (const state of ["open", "proposed", "voted", "ballot", "sealed", ""]) {
    assert.equal(policyEnforcementOf(step(undefined, state)), undefined, `absent/${state}`);
    assert.equal(
      policyEnforcementOf(step({ enforced: true, policyId: "p" }, state))?.policyId,
      "p",
      `present/${state}`,
    );
  }
});

// ── Through the wire, not just through `create` ───────────────────────────────────────────────────

test("an empty submessage on the wire decodes to an instance, not to undefined", () => {
  // The shape a runtime actually emits for "policy checked, none applied": tag 3, wire type 2,
  // length 0 — three bytes, no payload. Building it in-process proves the decoder; round-tripping it
  // proves the *state* survives serialization, which is where an absent/empty confusion would hide.
  const wire = toBinary(SessionStepSchema, step({ enforced: false }));
  assert.equal(Buffer.from(wire).toString("hex").includes("1a00"), true);

  const back = fromBinary(SessionStepSchema, wire);
  assert.notEqual(back.policyEnforcement, undefined);
  const got = policyEnforcementOf(back);
  assert.notEqual(got, undefined);
  assert.equal(got?.enforced, false);
  assert.equal(got?.policyId, undefined);
});

test("a wire message with no policy_enforcement bytes decodes to undefined", () => {
  const wire = toBinary(SessionStepSchema, step(undefined, "open"));
  assert.equal(Buffer.from(wire).toString("hex").includes("1a00"), false);
  assert.equal(policyEnforcementOf(fromBinary(SessionStepSchema, wire)), undefined);
});

test("an explicitly-empty policy_id survives the wire as '' rather than becoming absent", () => {
  const wire = toBinary(SessionStepSchema, step({ enforced: true, policyId: "" }));
  const got = policyEnforcementOf(fromBinary(SessionStepSchema, wire));
  assert.equal(got?.policyId, "");
});

// ── The returned value is the SDK's, not the wire's ───────────────────────────────────────────────

test("the result is a plain SDK object, not the generated message", () => {
  const s = step({ enforced: true, policyId: "pol-1" });
  const got = policyEnforcementOf(s);

  // protobuf-es brands every generated message with `$typeName`. Handing one back would leak the
  // generated surface into the SDK's contract and re-couple callers to the stub tree.
  assert.equal((got as unknown as Record<string, unknown>).$typeName, undefined);
  assert.notEqual(got, s.policyEnforcement);
  assert.deepEqual(Object.keys(got as object).sort(), ["enforced", "policyId"]);
});

test("policyId is always a present property, even when its value is undefined", () => {
  // Mirrors the Python dataclass, where `policy_id` is always an attribute. `"policyId" in got`
  // must not be how a caller distinguishes absent — the VALUE is the answer, one way only.
  const got = policyEnforcementOf(step({ enforced: false }));
  assert.equal("policyId" in (got as object), true);
  assert.equal(got?.policyId, undefined);
});
