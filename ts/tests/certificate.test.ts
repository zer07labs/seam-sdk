// cert-ref (runtime 0.91.0): `DecisionSealed.certificate` (tag 19) and its closed int32 provenance.

import { test } from "node:test";
import assert from "node:assert/strict";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";

import {
  CERTIFICATE_PROVENANCE_AGENT_ASSERTED,
  CERTIFICATE_PROVENANCE_UNSPECIFIED,
  WIRE_FEATURE_CERT_REF,
  certificateProvenance,
  certificateRefOf,
} from "../src/index.js";
import {
  CertificateRefSchema,
  DecisionSealedSchema,
} from "../gen/seam/event/v1/seam_event_pb.js";

const ID = "sha256:" + "ab".repeat(32);

test("an absent certificate reads as undefined", () => {
  assert.equal(certificateRefOf(create(DecisionSealedSchema, {})), undefined);
});

test("an agent-asserted certificate round-trips through the wire", () => {
  const ds = create(DecisionSealedSchema, {
    certificate: create(CertificateRefSchema, { id: ID, provenance: 1 }),
  });
  const back = fromBinary(DecisionSealedSchema, toBinary(DecisionSealedSchema, ds));
  assert.deepEqual(certificateRefOf(back), {
    id: ID,
    provenance: CERTIFICATE_PROVENANCE_AGENT_ASSERTED,
  });
});

test("an unknown or unset provenance is the least trusted reading, never evidence", () => {
  for (const p of [0, 2, 7, -1, 2 ** 31 - 1]) {
    const ds = create(DecisionSealedSchema, {
      certificate: create(CertificateRefSchema, { id: ID, provenance: p }),
    });
    assert.equal(certificateRefOf(ds)?.provenance, CERTIFICATE_PROVENANCE_UNSPECIFIED, String(p));
  }
  assert.equal(certificateProvenance(1.5), CERTIFICATE_PROVENANCE_UNSPECIFIED);
});

test("the wire feature name is the spec's", () => {
  assert.equal(WIRE_FEATURE_CERT_REF, "feature_flag.cert_ref");
});

test("a malformed id reads exactly as absent", () => {
  for (const bad of ["", "sha256:" + "AB".repeat(32), "sha256:" + "ab".repeat(31), "decision-cert:" + ID, ID + "\n"]) {
    const ds = create(DecisionSealedSchema, {
      certificate: create(CertificateRefSchema, { id: bad, provenance: 1 }),
    });
    assert.equal(certificateRefOf(ds), undefined, JSON.stringify(bad));
  }
});
