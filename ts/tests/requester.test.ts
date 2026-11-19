// RT4 (runtime 0.95.0, seam-runtime#1776): the requester id rule, mirrored from the runtime spec's own
// accept/refuse table (`docs/specs/session-open.md` §Requester). Same cases as python/tests/test_requester.py.

import { test } from "node:test";
import assert from "node:assert/strict";

import { REQUESTER_ID_MAX_BYTES, REQUESTER_ID_MIN_BYTES, validRequesterId } from "../src/index.js";
import { requesterMessage } from "../src/requester.js";
import { RequesterKind } from "../gen/seam/api/v1/seam_pb.js";

const ACCEPTED = ["p_a", "p_" + "a".repeat(REQUESTER_ID_MAX_BYTES - 2), "p_0123456789abcdefABCDEF", "p_x.y_z:w-v"];

const REFUSED = [
  "",
  "p_",
  "p_" + "a".repeat(REQUESTER_ID_MAX_BYTES - 1), // 129 bytes
  "alice@example.com",
  "p_alice@example.com",
  "google-oauth2|1048",
  "auth0|5f7c",
  "0123abcd",
  "P_abc",
  "q_abc",
  "p_a b",
  "p_a\n",
  "p_é",
  "p_a/b",
  "p_a=b",
];

test("the bounds are the runtime spec's", () => {
  assert.deepEqual([REQUESTER_ID_MIN_BYTES, REQUESTER_ID_MAX_BYTES], [3, 128]);
});

test("every accepted id in the spec table validates", () => {
  for (const id of ACCEPTED) assert.equal(validRequesterId(id), true, id);
});

test("every refused id in the spec table is refused", () => {
  for (const id of REFUSED) assert.equal(validRequesterId(id), false, JSON.stringify(id));
});

test("a non-string is refused without throwing", () => {
  for (const v of [undefined, null, 7, new Uint8Array([0x70, 0x5f, 0x61])]) assert.equal(validRequesterId(v), false);
});

test("requesterMessage: absent stays absent, a valid id is a HUMAN requester", () => {
  assert.equal(requesterMessage(undefined), undefined);
  const r = requesterMessage("p_abc")!;
  assert.equal(r.kind, RequesterKind.HUMAN);
  assert.equal(r.id, "p_abc");
});

test("requesterMessage: a refused id throws a RangeError that never echoes it", () => {
  for (const id of ["alice@example.com", "auth0|5f7c", ""]) {
    assert.throws(
      () => requesterMessage(id),
      (e: unknown) => e instanceof RangeError && (id === "" || !e.message.includes(id)),
    );
  }
});
