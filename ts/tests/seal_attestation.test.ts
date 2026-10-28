// `sealAttestationOf` — reading why a fetched record was sealed (runtime 0.61.0, seam-sdk#273).
//
// The case table is `python/tests/fixtures/seal_attestation_cases.json`, read by path: the Python
// suite runs the same file, so the two decoders are held to one table rather than two that drift.
// Wire values there are raw enum integers so an unknown value can be expressed; protobuf-es accepts
// an out-of-range number on an open enum at runtime, which is exactly the case under test.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { create, toBinary, fromBinary } from "@bufbuild/protobuf";
import type { DescMessage } from "@bufbuild/protobuf";
import { FeatureSet_FieldPresence } from "@bufbuild/protobuf/wkt";

import {
  CollectiveOutcomeSchema,
  CollectiveVerdict,
  DecisionRecordViewSchema,
  DecisionResponseSchema,
  PolicyEnforcementSchema,
  SealAttestationAvailability,
  SealAttestationSchema,
  SealReason,
} from "../gen/seam/api/v1/seam_pb.js";
import {
  collectiveOutcomeOf,
  policyEnforcementOf,
  sealAttestationOf,
  UnknownCollectiveVerdictError,
  type CollectiveOutcome,
} from "../src/client.js";

interface WireCollective {
  verdict: number;
  approve_count: number;
  reject_count: number;
  abstain_count: number;
  declared_participant_count: number;
  stated_value_contradicted_tally: boolean;
  effective_threshold: number | null;
}
interface WireAttestation {
  availability: number;
  seal_reason: number;
  collective: WireCollective | null;
}
interface Case {
  name: string;
  attestation: WireAttestation | null;
  expect:
    | null
    | "raise"
    | {
        availability: string;
        seal_reason: string | null;
        collective: ExpectedCollective | null;
      };
}

const CASES: Case[] = JSON.parse(
  readFileSync(
    fileURLToPath(
      new URL(
        "../../python/tests/fixtures/seal_attestation_cases.json",
        import.meta.url,
      ),
    ),
    "utf8",
  ),
).cases;

function collective(w: WireCollective) {
  return create(CollectiveOutcomeSchema, {
    verdict: w.verdict,
    approveCount: w.approve_count,
    rejectCount: w.reject_count,
    abstainCount: w.abstain_count,
    declaredParticipantCount: w.declared_participant_count,
    statedValueContradictedTally: w.stated_value_contradicted_tally,
    ...(w.effective_threshold === null
      ? {}
      : { effectiveThreshold: w.effective_threshold }),
  });
}

function view(a: WireAttestation | null) {
  const v = create(DecisionRecordViewSchema, { decisionId: "dec-273" });
  if (a === null) return v;
  v.sealAttestation = create(SealAttestationSchema, {
    availability: a.availability,
    sealReason: a.seal_reason,
    ...(a.collective === null
      ? {}
      : { collectiveOutcome: collective(a.collective) }),
  });
  return v;
}

/** The fixture's `expect.collective` is the decoded form in Python's snake_case, with `verdict`
 * already a name — the shared table states the result, not a second wire encoding. */
interface ExpectedCollective extends Omit<WireCollective, "verdict"> {
  verdict: CollectiveOutcome["verdict"];
}

function expectedCollective(w: ExpectedCollective): CollectiveOutcome {
  return {
    verdict: w.verdict,
    approveCount: w.approve_count,
    rejectCount: w.reject_count,
    abstainCount: w.abstain_count,
    declaredParticipantCount: w.declared_participant_count,
    statedValueContradictedTally: w.stated_value_contradicted_tally,
    effectiveThreshold: w.effective_threshold ?? undefined,
  };
}

test("the shared case table is not empty (anti-vacuity)", () => {
  assert.ok(CASES.length >= 15, `only ${CASES.length} cases`);
});

for (const c of CASES) {
  test(`shared table: ${c.name}`, () => {
    const v = view(c.attestation);
    if (c.expect === "raise") {
      assert.throws(
        () => sealAttestationOf(v),
        (e: unknown) =>
          e instanceof UnknownCollectiveVerdictError &&
          e.rawValue === c.attestation!.collective!.verdict &&
          e.decisionId === "dec-273",
      );
      return;
    }
    const got = sealAttestationOf(v);
    if (c.expect === null) {
      assert.equal(got, undefined);
      return;
    }
    assert.ok(got);
    assert.equal(got.availability, c.expect.availability);
    assert.equal(got.sealReason, c.expect.seal_reason ?? undefined);
    if (c.expect.collective === null)
      assert.equal(got.collectiveOutcome, undefined);
    else
      assert.deepEqual(
        got.collectiveOutcome,
        expectedCollective(c.expect.collective),
      );
  });
}

test("every availability the stubs define decodes without throwing; UNSPECIFIED reads UNRECOGNIZED", () => {
  // Driven from the generated enum, not this SDK's own map: a value a later regeneration adds lands
  // here and must read "UNRECOGNIZED" (WITHHELD) until it is named.
  for (const value of Object.values(SealAttestationAvailability).filter(
    (x): x is number => typeof x === "number",
  )) {
    const got = sealAttestationOf(
      view({
        availability: value,
        seal_reason: SealReason.COMMIT,
        collective: null,
      }),
    );
    assert.ok(got);
    const name = SealAttestationAvailability[value]!;
    assert.equal(
      got.availability,
      name === "UNSPECIFIED" ? "UNRECOGNIZED" : name,
    );
    if (got.availability !== "RECORDED")
      assert.equal(got.sealReason, undefined);
  }
});

test("every seal reason the stubs define decodes under RECORDED; UNSPECIFIED reads UNRECOGNIZED", () => {
  for (const value of Object.values(SealReason).filter(
    (x): x is number => typeof x === "number",
  )) {
    const got = sealAttestationOf(
      view({
        availability: SealAttestationAvailability.RECORDED,
        seal_reason: value,
        collective: null,
      }),
    );
    const name = SealReason[value]!;
    assert.equal(
      got?.sealReason,
      name === "UNSPECIFIED" ? "UNRECOGNIZED" : name,
    );
  }
});

test("no availability but RECORDED reads the payload — not decoded, not validated", () => {
  const nonRecorded = Object.values(SealAttestationAvailability)
    .filter((x): x is number => typeof x === "number")
    .filter((x) => x !== SealAttestationAvailability.RECORDED)
    .concat([99]);
  for (const availability of nonRecorded) {
    for (const verdict of [CollectiveVerdict.APPROVED, 99]) {
      const got = sealAttestationOf(
        view({
          availability,
          seal_reason: SealReason.COMMIT,
          collective: {
            verdict,
            approve_count: 1,
            reject_count: 0,
            abstain_count: 0,
            declared_participant_count: 1,
            stated_value_contradicted_tally: false,
            effective_threshold: 1,
          },
        }),
      );
      assert.ok(got);
      assert.notEqual(got.availability, "RECORDED");
      assert.equal(got.sealReason, undefined);
      assert.equal(got.collectiveOutcome, undefined);
    }
  }
});

test("the sealed collective decodes exactly like the immediate one, effectiveThreshold presence included", () => {
  for (const threshold of [null, 0, 2]) {
    const w: WireCollective = {
      verdict: CollectiveVerdict.SPLIT,
      approve_count: 1,
      reject_count: 1,
      abstain_count: 1,
      declared_participant_count: 3,
      stated_value_contradicted_tally: false,
      effective_threshold: threshold,
    };
    const sealed = sealAttestationOf(
      view({
        availability: SealAttestationAvailability.RECORDED,
        seal_reason: SealReason.COMMIT,
        collective: w,
      }),
    );
    const immediate = collectiveOutcomeOf(
      create(DecisionResponseSchema, {
        decisionId: "dec-273",
        collectiveOutcome: collective(w),
      }),
    );
    assert.deepEqual(sealed?.collectiveOutcome, immediate);
    assert.equal(
      sealed?.collectiveOutcome?.effectiveThreshold,
      threshold ?? undefined,
    );
  }
});

test("a toBinary/fromBinary round-trip decodes the same", () => {
  const v = view({
    availability: SealAttestationAvailability.RECORDED,
    seal_reason: SealReason.COMMIT,
    collective: {
      verdict: CollectiveVerdict.APPROVED,
      approve_count: 3,
      reject_count: 0,
      abstain_count: 0,
      declared_participant_count: 3,
      stated_value_contradicted_tally: false,
      effective_threshold: 3,
    },
  });
  const revived = fromBinary(
    DecisionRecordViewSchema,
    toBinary(DecisionRecordViewSchema, v),
  );
  assert.deepEqual(sealAttestationOf(revived), sealAttestationOf(v));
  assert.equal(
    sealAttestationOf(revived)?.collectiveOutcome?.verdict,
    "APPROVED",
  );
});

test("an all-zero attestation is present on the wire and reads UNRECOGNIZED, not 'older runtime'", () => {
  const v = create(DecisionRecordViewSchema, {
    decisionId: "dec-273",
    sealAttestation: create(SealAttestationSchema, {}),
  });
  const revived = fromBinary(
    DecisionRecordViewSchema,
    toBinary(DecisionRecordViewSchema, v),
  );
  assert.deepEqual(sealAttestationOf(revived), {
    availability: "UNRECOGNIZED",
    sealReason: undefined,
    collectiveOutcome: undefined,
  });
});

test("the result is a plain object with exactly three always-present properties", () => {
  const got = sealAttestationOf(
    view({
      availability: SealAttestationAvailability.NOT_RECORDED,
      seal_reason: 0,
      collective: null,
    }),
  );
  assert.ok(got);
  assert.deepEqual(Object.keys(got).sort(), [
    "availability",
    "collectiveOutcome",
    "sealReason",
  ]);
  assert.equal("$typeName" in got, false);
});

test("policyEnforcementOf still answers on a KEY_UNAVAILABLE record", () => {
  const v = view({
    availability: SealAttestationAvailability.KEY_UNAVAILABLE,
    seal_reason: 0,
    collective: null,
  });
  v.policyEnforcement = create(PolicyEnforcementSchema, {
    enforced: true,
    policyId: "p-1",
  });
  assert.equal(sealAttestationOf(v)?.availability, "KEY_UNAVAILABLE");
  assert.deepEqual(policyEnforcementOf(v), { enforced: true, policyId: "p-1" });
});

test("the field numbers and presence the TSDoc rests on are what the schemas say", () => {
  const field = (schema: DescMessage, name: string) => {
    const f = schema.fields.find((x) => x.name === name);
    assert.ok(f, `${schema.typeName} has no field ${name}`);
    return f;
  };
  assert.equal(field(DecisionRecordViewSchema, "seal_attestation").number, 12);
  assert.equal(
    field(DecisionRecordViewSchema, "seal_attestation").presence,
    FeatureSet_FieldPresence.EXPLICIT,
  );
  assert.equal(field(DecisionRecordViewSchema, "policy_version").number, 9);
  assert.equal(
    field(DecisionRecordViewSchema, "policy_version").presence,
    FeatureSet_FieldPresence.IMPLICIT,
  );
  assert.equal(
    field(DecisionRecordViewSchema, "policy_rules_digest").number,
    10,
  );
  assert.equal(
    field(DecisionRecordViewSchema, "policy_rules_digest").presence,
    FeatureSet_FieldPresence.IMPLICIT,
  );
  assert.equal(
    field(SealAttestationSchema, "collective_outcome").presence,
    FeatureSet_FieldPresence.EXPLICIT,
  );
});
