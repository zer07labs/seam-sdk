// `allocationOf` — reading which experiment arm a fetched record was allocated to (runtime 0.76.0,
// Branchpoint BP-8).
//
// The case table is `python/tests/fixtures/allocation_cases.json`, read by path: the Python suite
// runs the same file, so the two decoders are held to one table rather than two that drift. Wire
// values there are raw enum integers so an unknown value can be expressed; protobuf-es accepts an
// out-of-range number on an open enum at runtime, which is exactly the case under test. Field names
// are the proto's snake_case and `budget_epoch` is a decimal string (a uint64 JSON cannot carry).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { create, toBinary, fromBinary } from "@bufbuild/protobuf";
import type { DescMessage } from "@bufbuild/protobuf";
import { FeatureSet_FieldPresence } from "@bufbuild/protobuf/wkt";

import {
  AllocationAvailability,
  AllocationSchema,
  AllocationViewSchema,
  DecisionRecordViewSchema,
  SealAttestationAvailability,
  SealAttestationSchema,
} from "../gen/seam/api/v1/seam_pb.js";
import {
  allocationOf,
  sealAttestationOf,
  type Allocation,
  type AllocationView,
} from "../src/client.js";
import * as root from "../src/index.js";

interface WireAllocation {
  mode: string;
  experiment_id: string;
  variant_id: string;
  intended_action: string;
  served_action: string;
  allocation_propensity: number;
  budget_bp: number;
  budget_epoch: string;
  snapshot_id: string;
  unit_tag: string;
  unit_digest: string;
  bucket_version: number;
  commitment_kid: string;
  decision_point: string;
}
interface WireView {
  availability: number;
  allocation: WireAllocation | null;
}
interface Case {
  name: string;
  wire: WireView | null;
  expect: null | { availability: string; allocation: WireAllocation | null };
}

const CASES: Case[] = JSON.parse(
  readFileSync(
    fileURLToPath(
      new URL("../../python/tests/fixtures/allocation_cases.json", import.meta.url),
    ),
    "utf8",
  ),
).cases;

function inner(w: WireAllocation) {
  return create(AllocationSchema, {
    mode: w.mode,
    experimentId: w.experiment_id,
    variantId: w.variant_id,
    intendedAction: w.intended_action,
    servedAction: w.served_action,
    allocationPropensity: w.allocation_propensity,
    budgetBp: w.budget_bp,
    budgetEpoch: BigInt(w.budget_epoch),
    snapshotId: w.snapshot_id,
    unitTag: w.unit_tag,
    unitDigest: w.unit_digest,
    bucketVersion: w.bucket_version,
    commitmentKid: w.commitment_kid,
    decisionPoint: w.decision_point,
  });
}

function view(w: WireView | null) {
  const v = create(DecisionRecordViewSchema, { decisionId: "dec-bp8" });
  if (w === null) return v;
  v.allocation = create(AllocationViewSchema, {
    availability: w.availability,
    ...(w.allocation === null ? {} : { allocation: inner(w.allocation) }),
  });
  return v;
}

function expected(w: WireAllocation): Allocation {
  return {
    mode: w.mode,
    experimentId: w.experiment_id,
    variantId: w.variant_id,
    intendedAction: w.intended_action,
    servedAction: w.served_action,
    allocationPropensity: w.allocation_propensity,
    budgetBp: w.budget_bp,
    budgetEpoch: BigInt(w.budget_epoch),
    snapshotId: w.snapshot_id,
    unitTag: w.unit_tag,
    unitDigest: w.unit_digest,
    bucketVersion: w.bucket_version,
    commitmentKid: w.commitment_kid,
    decisionPoint: w.decision_point,
  };
}

const roundTrip = (v: ReturnType<typeof view>) =>
  fromBinary(DecisionRecordViewSchema, toBinary(DecisionRecordViewSchema, v));

test("the shared case table is not empty (anti-vacuity)", () => {
  assert.ok(CASES.length >= 20, `only ${CASES.length} cases`);
});

for (const c of CASES) {
  test(`shared table: ${c.name}`, () => {
    for (const v of [view(c.wire), roundTrip(view(c.wire))]) {
      const got = allocationOf(v);
      if (c.expect === null) {
        assert.equal(got, undefined);
        continue;
      }
      assert.deepEqual(got, {
        availability: c.expect.availability as AllocationView["availability"],
        allocation:
          c.expect.allocation === null ? undefined : expected(c.expect.allocation),
      } satisfies AllocationView);
    }
  });
}

test("every availability the stubs define decodes without throwing; UNSPECIFIED reads UNRECOGNIZED", () => {
  // Driven from the generated enum, not this SDK's own map: a value a later regeneration adds lands
  // here and must read "UNRECOGNIZED" (WITHHELD) until it is named.
  const values = Object.values(AllocationAvailability).filter(
    (x): x is number => typeof x === "number",
  );
  assert.ok(values.length >= 7);
  for (const value of values) {
    const got = allocationOf(view({ availability: value, allocation: null }));
    assert.ok(got);
    const name = AllocationAvailability[value]!;
    assert.equal(got.availability, name === "UNSPECIFIED" ? "UNRECOGNIZED" : name);
  }
});

test("no availability but RECORDED reads the payload", () => {
  const values = Object.values(AllocationAvailability)
    .filter((x): x is number => typeof x === "number")
    .filter((x) => x !== AllocationAvailability.RECORDED)
    .concat([7, 99]);
  for (const value of values) {
    const v = create(DecisionRecordViewSchema, {
      decisionId: "dec-bp8",
      allocation: create(AllocationViewSchema, {
        availability: value,
        allocation: create(AllocationSchema, { mode: "split", allocationPropensity: 0.5 }),
      }),
    });
    const got = allocationOf(v);
    assert.ok(got);
    assert.notEqual(got.availability, "RECORDED");
    assert.equal(got.allocation, undefined);
  }
});

test("-0 and NaN propensities pass through unchanged (JSON cannot carry them)", () => {
  for (const p of [-0, Number.NaN]) {
    const v = create(DecisionRecordViewSchema, {
      decisionId: "dec-bp8",
      allocation: create(AllocationViewSchema, {
        availability: AllocationAvailability.RECORDED,
        allocation: create(AllocationSchema, { allocationPropensity: p }),
      }),
    });
    const got = allocationOf(roundTrip(v));
    assert.ok(got?.allocation);
    assert.ok(Object.is(got.allocation.allocationPropensity, p), `${p}`);
  }
});

test("budgetEpoch is a bigint with full uint64 precision", () => {
  const max = 2n ** 64n - 1n;
  const v = create(DecisionRecordViewSchema, {
    decisionId: "dec-bp8",
    allocation: create(AllocationViewSchema, {
      availability: AllocationAvailability.RECORDED,
      allocation: create(AllocationSchema, { budgetEpoch: max }),
    }),
  });
  const got = allocationOf(roundTrip(v));
  assert.equal(typeof got?.allocation?.budgetEpoch, "bigint");
  assert.equal(got?.allocation?.budgetEpoch, max);
});

test("the results are plain objects with exactly their always-present properties", () => {
  const withheld = allocationOf(
    view({ availability: AllocationAvailability.NOT_RECORDED, allocation: null }),
  );
  assert.ok(withheld);
  assert.deepEqual(Object.keys(withheld).sort(), ["allocation", "availability"]);
  assert.equal("$typeName" in withheld, false);
  const recorded = allocationOf(view(CASES.find((c) => c.name === "RECORDED split")!.wire));
  assert.ok(recorded?.allocation);
  assert.equal("$typeName" in recorded.allocation, false);
  assert.deepEqual(Object.keys(recorded.allocation), [
    "mode",
    "experimentId",
    "variantId",
    "intendedAction",
    "servedAction",
    "allocationPropensity",
    "budgetBp",
    "budgetEpoch",
    "snapshotId",
    "unitTag",
    "unitDigest",
    "bucketVersion",
    "commitmentKid",
    "decisionPoint",
  ]);
});

test("the allocation and the seal attestation decode independently", () => {
  const v = create(DecisionRecordViewSchema, {
    decisionId: "dec-bp8",
    allocation: create(AllocationViewSchema, {
      availability: AllocationAvailability.CLEARANCE_DENIED,
    }),
    sealAttestation: create(SealAttestationSchema, {
      availability: SealAttestationAvailability.NOT_RECORDED,
    }),
  });
  assert.equal(allocationOf(v)?.availability, "CLEARANCE_DENIED");
  assert.equal(sealAttestationOf(v)?.availability, "NOT_RECORDED");
  const onlySeal = create(DecisionRecordViewSchema, {
    decisionId: "dec-bp8",
    sealAttestation: create(SealAttestationSchema, {}),
  });
  assert.equal(allocationOf(onlySeal), undefined);
  assert.ok(sealAttestationOf(onlySeal));
});

test("a JavaScript non-carrier reads as absent, never as a recorded allocation", () => {
  assert.equal(allocationOf({} as unknown as Parameters<typeof allocationOf>[0]), undefined);
});

test("allocationOf is exported from the package root", () => {
  assert.equal(root.allocationOf, allocationOf);
});

test("the field numbers and presence the TSDoc rests on are what the schemas say", () => {
  const field = (schema: DescMessage, name: string) => {
    const f = schema.fields.find((x) => x.name === name);
    assert.ok(f, `${schema.typeName} has no field ${name}`);
    return f;
  };
  assert.equal(field(DecisionRecordViewSchema, "allocation").number, 13);
  assert.equal(
    field(DecisionRecordViewSchema, "allocation").presence,
    FeatureSet_FieldPresence.EXPLICIT,
  );
  assert.equal(field(AllocationViewSchema, "availability").number, 1);
  assert.equal(field(AllocationViewSchema, "allocation").number, 2);
  assert.equal(
    field(AllocationViewSchema, "allocation").presence,
    FeatureSet_FieldPresence.EXPLICIT,
  );
  assert.deepEqual(
    [...AllocationSchema.fields].sort((a, b) => a.number - b.number).map((f) => f.number),
    Array.from({ length: 14 }, (_, i) => i + 1),
  );
  for (const f of AllocationSchema.fields)
    assert.equal(f.presence, FeatureSet_FieldPresence.IMPLICIT, f.name);
});
