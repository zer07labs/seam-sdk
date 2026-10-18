// P4 session ids and P5 decision ids (`src/ids.ts`), checked against the runtime's stated rules.
// Mirrors `python/tests/test_ids.py`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

import * as sdk from "../src/index.js";
import {
  InvalidDecisionIdError,
  InvalidSessionIdError,
  decisionIdForSession,
  isValidSessionId,
  parseDecisionId,
  validateSessionId,
} from "../src/ids.js";

const V4 = "8f14e45f-ceea-467a-9575-6c2b2a1f8d3e";
const V7 = "01890a5d-ac96-774b-bcce-b302099a8057";

const ACCEPTED = [
  V4,
  V7,
  randomUUID(),
  "A".repeat(22), // the token floor: 16 random bytes in unpadded base64url
  "abc-DEF_0123456789xyzQ",
  "t".repeat(128), // the byte cap, exactly
  // 36 characters, hyphenated, but NOT a UUID ('g' is not hex): it never takes the UUID branch, so
  // the token rule judges it, and it passes.
  "gggggggg-gggg-gggg-gggg-gggggggggggg",
];

const REFUSED = [
  V4.toUpperCase(), // parses as a UUID, so judged only as one: not canonical lowercase
  "8f14e45f-ceea-167a-9575-6c2b2a1f8d3e", // a v1 UUID
  "00000000-0000-0000-0000-000000000000", // nil
  "A".repeat(21), // one short of the token floor
  "t".repeat(129), // over the byte cap
  "has space in it-------",
  "colon:inside:the:token:",
  "",
  "é".repeat(22), // outside the charset (and 44 bytes)
  "\ud800".repeat(22), // a lone surrogate is not valid UTF-8
];

test("accepted session ids", () => {
  for (const sid of ACCEPTED) {
    assert.equal(validateSessionId(sid), sid, sid);
    assert.ok(isValidSessionId(sid), sid);
  }
});

test("refused session ids, without echoing the id", () => {
  for (const sid of REFUSED) {
    assert.ok(!isValidSessionId(sid), sid);
    assert.throws(
      () => validateSessionId(sid),
      (err: unknown) => {
        assert.ok(err instanceof InvalidSessionIdError, sid);
        if (sid) assert.ok(!err.message.includes(sid), "the id is not echoed, matching the runtime");
        return true;
      },
    );
  }
});

test("a non-string session id is refused, not a TypeError", () => {
  assert.ok(!isValidSessionId(null));
  assert.ok(!isValidSessionId(undefined));
  assert.throws(() => validateSessionId(123 as unknown as string), InvalidSessionIdError);
});

test("decision id round-trips", () => {
  const did = decisionIdForSession("acme", V4);
  assert.equal(did, `dec:acme:${V4}`);
  assert.deepEqual(parseDecisionId(did), { tenant: "acme", sessionId: V4 });
});

test("malformed decision ids are refused", () => {
  for (const did of [
    "acme:" + V4, // no prefix
    // no ':' after the prefix, so no tenant half (a UUID's hyphens are not separators)
    "dec:" + V4,
    "dec::" + V4, // empty tenant
    "dec:ac.me:" + V4, // tenant charset
    "dec:acme:" + V4.toUpperCase(), // session half judged by P4
    // an extra ':' lands in the session half, where P4 refuses it
    "dec:acme:extra:" + V4,
    "dec:acme:short",
  ]) {
    assert.throws(() => parseDecisionId(did), InvalidDecisionIdError, did);
  }
});

test("building refuses what parsing refuses", () => {
  assert.throws(() => decisionIdForSession("acme", "short"), InvalidDecisionIdError);
  assert.throws(() => decisionIdForSession("a".repeat(129), V4), InvalidDecisionIdError);
});

test("the helpers are exported from the package root", () => {
  for (const name of [
    "DECISION_ID_PREFIX",
    "InvalidDecisionIdError",
    "InvalidSessionIdError",
    "decisionIdForSession",
    "isValidSessionId",
    "parseDecisionId",
    "validateSessionId",
  ]) {
    assert.ok(name in sdk, name);
  }
});
