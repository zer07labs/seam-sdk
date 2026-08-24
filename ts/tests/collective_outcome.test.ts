// `CollectiveVerdict` must fail closed — including on a value that does not exist yet.
//
// The proto's growth policy is normative and is copied verbatim from `AuthorizeVerdict`'s:
//
//     any value a client does not recognize — INCLUDING COLLECTIVE_VERDICT_UNSPECIFIED — MUST route
//     to the adapter's FailPolicy, never to allow. The server never emits UNSPECIFIED.
//
// Two properties of the *generated* surface make the wrong thing easy, and both are tested here:
// `collectiveOutcome` is `optional`, so absent and UNSPECIFIED are distinct wire states a naive read
// flattens together; and proto3 makes 0 the silent default, so `verdict !== DECLINED` — the natural
// negative test — allows on every unrecognized value.
//
// The out-of-range case is the one that matters most and is the easiest to omit: it is the only test
// that proves the default branch is reachable, and it stands in for the verdict a future runtime adds
// after this SDK version shipped.

import { test } from "node:test";
import assert from "node:assert/strict";
import { create } from "@bufbuild/protobuf";

import {
  CollectiveVerdict,
  CollectiveOutcomeSchema,
  DecisionResponseSchema,
} from "../gen/seam/api/v1/seam_pb.js";
import { collectiveOutcomeOf, UnknownCollectiveVerdictError } from "../src/client.js";

const DEFINED: [CollectiveVerdict, string][] = [
  [CollectiveVerdict.APPROVED, "APPROVED"],
  [CollectiveVerdict.DECLINED, "DECLINED"],
  [CollectiveVerdict.SPLIT, "SPLIT"],
  [CollectiveVerdict.ESCALATED, "ESCALATED"],
  [CollectiveVerdict.NO_VOTES, "NO_VOTES"],
];

function resp(outcome?: Partial<{ verdict: number } & Record<string, unknown>>) {
  const r = create(DecisionResponseSchema, { decisionId: "dec-1" });
  if (outcome !== undefined) {
    r.collectiveOutcome = create(CollectiveOutcomeSchema, outcome as never);
  }
  return r;
}

// ── absent is not a verdict ──────────────────────────────────────────────────────────────────────

test("an absent collectiveOutcome returns undefined, not a verdict", () => {
  const r = resp();
  assert.equal(r.collectiveOutcome, undefined);
  assert.equal(collectiveOutcomeOf(r), undefined);
});

test("absent is distinguishable from UNSPECIFIED", () => {
  // The whole reason the field is `optional`. Reading through the raw message conflates them via
  // optional chaining collapsing to undefined; the decoder must keep them apart.
  const absent = resp();
  const unspecified = resp({ verdict: CollectiveVerdict.UNSPECIFIED });

  assert.equal(collectiveOutcomeOf(absent), undefined);
  assert.throws(() => collectiveOutcomeOf(unspecified), UnknownCollectiveVerdictError);
});

// ── unrecognized values fail closed ──────────────────────────────────────────────────────────────

test("UNSPECIFIED throws rather than returning a value", () => {
  assert.throws(
    () => collectiveOutcomeOf(resp({ verdict: CollectiveVerdict.UNSPECIFIED })),
    (e: unknown) => {
      assert.ok(e instanceof UnknownCollectiveVerdictError);
      assert.equal(e.rawValue, 0);
      assert.equal(e.decisionId, "dec-1");
      assert.match(e.message, /never allow/);
      return true;
    },
  );
});

test("a verdict this SDK version does not know throws", () => {
  // The case the growth policy exists for: a value added by a runtime newer than this SDK. Without
  // it the default branch is unreachable in the suite, and an implementation that mapped every
  // CURRENT value would pass while silently allowing the next one.
  const r = resp({ verdict: 99 });
  assert.throws(
    () => collectiveOutcomeOf(r),
    (e: unknown) => {
      assert.ok(e instanceof UnknownCollectiveVerdictError);
      assert.equal(e.rawValue, 99);
      return true;
    },
  );
});

// ── recognized values decode ─────────────────────────────────────────────────────────────────────

test("every defined verdict decodes to its name", () => {
  for (const [value, name] of DEFINED) {
    const outcome = collectiveOutcomeOf(resp({ verdict: value }));
    assert.equal(outcome?.verdict, name, `${name} did not decode`);
  }
});

test("the decoded surface exposes no boolean that inverts on an unhandled verdict", () => {
  // The Python twin asserts `approved` is the ONLY boolean and there is no `declined`. TypeScript's
  // interface has no methods at all, so the equivalent property is that the union is closed — a
  // caller must switch on a named verdict rather than negate one.
  for (const [value, name] of DEFINED) {
    const outcome = collectiveOutcomeOf(resp({ verdict: value }));
    assert.ok(outcome);
    assert.equal(typeof outcome.verdict, "string");
    // SPLIT in particular is real dissent sealed as a failed approval ATTEMPT: it must never read
    // as an approval.
    assert.equal(outcome.verdict === "APPROVED", name === "APPROVED");
  }
});

// ── the counters are carried, never consulted ────────────────────────────────────────────────────

test("counters are carried through untouched", () => {
  const outcome = collectiveOutcomeOf(
    resp({
      verdict: CollectiveVerdict.APPROVED,
      approveCount: 2,
      rejectCount: 0,
      abstainCount: 1,
      declaredParticipantCount: 3,
      statedValueContradictedTally: true,
    }),
  );
  assert.ok(outcome);
  assert.deepEqual(
    [outcome.approveCount, outcome.rejectCount, outcome.abstainCount],
    [2, 0, 1],
  );
  assert.equal(outcome.declaredParticipantCount, 3);
  assert.equal(outcome.statedValueContradictedTally, true);
});

test("the verdict is never re-derived from the counters", () => {
  // The proto states outright that the counters are observability and that a client-side tally is
  // self-grading and unverifiable — which is the whole reason `verdict` is a field. So a tally that
  // CONTRADICTS the verdict must decode to the verdict the runtime sent. If this ever fails,
  // someone has taught the client to grade the server's own judgment.
  const outcome = collectiveOutcomeOf(
    resp({
      verdict: CollectiveVerdict.DECLINED,
      approveCount: 5, // a naive tally would call this APPROVED
      rejectCount: 0,
      abstainCount: 0,
      declaredParticipantCount: 5,
    }),
  );
  assert.equal(outcome?.verdict, "DECLINED");
});
