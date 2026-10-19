// `contextDigestV4` — the `seam.audit.context-provenance.v4` sub-digest (wire tag 11).
//
// The four digests are the runtime's own pins (seam-event.v1.md's vector table and seam-runtime
// `scripts/v4-digest-reference.py` @ 1ac5de5), and `python/tests/test_context_digest_v4.py` asserts
// the same four, so the two languages cannot drift apart without one going red.

import { test } from "node:test";
import assert from "node:assert/strict";
import { create } from "@bufbuild/protobuf";

import {
  contextDigestV4,
  ContextProvenanceError,
  RECEIPT_KEY_STATUSES,
  type ContextProvenanceBinding,
} from "../src/crypto.js";
import { ContextBindingSchema } from "../gen/seam/api/v1/seam_pb.js";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

const EMPTY_CONTEXT = "f1e62208be1f1dfef0dc474cc655cedc546bcfcd4d4ea25bd7bc98188f6aab8f";
const ONE_CONTEXT = "8e87a93fd65b0d756817d2dbe3d9346542a2ad8272cc525f2df23d4b73802f85";
const V4_RECEIPT_CONTEXT = "3475464e934ac07ea03e6afbcda58f05446517c7df876b11e1a3260db035bf15";
const D3_POPULATED_CONTEXT = "2e8e7cdb4739248e9781080f65acf8108c5359dc8f4ed3373ad61239cadb2f98";

const ONE: ContextProvenanceBinding = {
  ctxRef: "sha256:aa",
  fidelity: "Digest",
  classification: "Internal",
  version: 1,
  derivedFrom: ["x", "y"],
};
const RECEIPT: ContextProvenanceBinding = {
  ctxRef: "acdp://reg.example.com/ctx-1",
  fidelity: "Reference",
  classification: "Confidential",
  version: 2,
  derivedFrom: [],
  contentHash: "sha256:aa",
  receiptHash: "sha256:bb",
  keyStatus: "CurrentlyAuthorized",
  resolvedStatus: "active",
  receiptKeyStatus: "Historical",
};
const RETRACTED: ContextProvenanceBinding = {
  ctxRef: "acdp://reg.example.com/ctx-1",
  fidelity: "Digest",
  classification: "Internal",
  version: 1,
  derivedFrom: [],
  contentHash: "sha256:aa",
  keyStatus: "CurrentlyAuthorized",
  resolvedStatus: "retracted",
};

test("matches the runtime's four pins", () => {
  assert.equal(hex(contextDigestV4([])), EMPTY_CONTEXT);
  assert.equal(hex(contextDigestV4([ONE])), ONE_CONTEXT);
  assert.equal(hex(contextDigestV4([RECEIPT])), V4_RECEIPT_CONTEXT);
  assert.equal(hex(contextDigestV4([RETRACTED])), D3_POPULATED_CONTEXT);
});

test("a generated ContextBinding is accepted as-is, and carries receiptKeyStatus", () => {
  for (const d of [ONE, RECEIPT, RETRACTED]) {
    const b = create(ContextBindingSchema, d as never);
    assert.equal(hex(contextDigestV4([b])), hex(contextDigestV4([d])));
  }
  assert.equal(create(ContextBindingSchema, RECEIPT as never).receiptKeyStatus, "Historical");
  assert.equal(create(ContextBindingSchema, ONE as never).receiptKeyStatus, undefined);
});

test("the receipt slot is bound, and stored order is hashed, never sorted", () => {
  assert.notEqual(
    hex(contextDigestV4([{ ...RECEIPT, receiptKeyStatus: "Current" }])),
    V4_RECEIPT_CONTEXT,
  );
  assert.notEqual(hex(contextDigestV4([ONE, RECEIPT])), hex(contextDigestV4([RECEIPT, ONE])));
});

test("unpaired receipt slots are refused before hashing", () => {
  for (const bad of [
    { ...RECEIPT, receiptKeyStatus: undefined },
    { ...RETRACTED, receiptKeyStatus: "Current" },
  ]) {
    assert.throws(
      () => contextDigestV4([ONE, bad]),
      (e: unknown) =>
        e instanceof ContextProvenanceError && e.index === 1 && e.field === "receipt_key_status",
    );
  }
});

test("an out-of-vocabulary receiptKeyStatus is refused", () => {
  assert.deepEqual([...RECEIPT_KEY_STATUSES], ["Current", "Historical"]);
  for (const v of ["historical", "CURRENT", "Revoked", ""]) {
    assert.throws(
      () => contextDigestV4([{ ...RECEIPT, receiptKeyStatus: v }]),
      ContextProvenanceError,
    );
  }
});

test("a wrong type is a TypeError, not a digest", () => {
  assert.throws(() => contextDigestV4([{ ...ONE, version: "1" as never }]), TypeError);
  assert.throws(() => contextDigestV4(ONE as never), TypeError);
});
