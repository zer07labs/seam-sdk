// `SESSION_UNAVAILABLE` (seam-runtime k8s P6): classification and the opt-in `withSessionRetry` loop —
// the twin of `python/tests/test_session_retry.py`. The client's ticket drop is in `unit_plumbing`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Code } from "@connectrpc/connect";
import {
  DEFAULT_RETRY_BUDGET_MS,
  isRetryable,
  isSessionUnavailable,
  SESSION_UNAVAILABLE_REASON,
  UnavailableError,
  withSessionRetry,
} from "../src/index.js";
import { refusal, sessionUnavailable } from "./session_unavailable.js";

test("SESSION_UNAVAILABLE is classified retryable, with its RetryInfo", () => {
  const err = sessionUnavailable(12);
  assert.ok(err instanceof UnavailableError);
  assert.equal(err.reason, SESSION_UNAVAILABLE_REASON);
  assert.equal(err.retryAfter, 12);
  assert.ok(isSessionUnavailable(err) && isRetryable(err));
});

const OTHERS: [string, Error][] = [
  ["bare-unavailable", refusal(Code.Unavailable, undefined)],
  ["challenge-refused", refusal(Code.Unavailable, "CHALLENGE_REFUSED", 1)],
  ["reason-on-wrong-code", refusal(Code.Internal, SESSION_UNAVAILABLE_REASON)],
  ["denied", refusal(Code.PermissionDenied, "POLICY_DENIED")],
  ["non-rpc", new Error("boom")],
];

test("every other error is not retryable", () => {
  for (const [name, err] of OTHERS) {
    assert.equal(isSessionUnavailable(err), false, name);
    assert.equal(isRetryable(err), false, name);
  }
});

function script(...errors: Error[]) {
  const s = {
    calls: 0,
    call: async () => {
      s.calls += 1;
      const e = errors.shift();
      if (e) throw e;
      return "ok";
    },
  };
  return s;
}

async function run(s: ReturnType<typeof script>, opts: Parameters<typeof withSessionRetry>[1] = {}) {
  const slept: number[] = [];
  const out = await withSessionRetry(s.call, {
    random: () => 1,
    sleep: async (ms) => void slept.push(ms),
    ...opts,
  });
  return { out, slept };
}

test("retries until success, honouring RetryInfo plus capped exponential jitter", async () => {
  const s = script(sessionUnavailable(2), sessionUnavailable(1), sessionUnavailable());
  const { out, slept } = await run(s);
  assert.equal(out, "ok");
  assert.equal(s.calls, 4);
  assert.deepEqual(slept, [2250, 1500, 1000]);
});

test("full jitter over the capped exponential", async () => {
  const s = script(...Array.from({ length: 7 }, () => sessionUnavailable()));
  const { slept } = await run(s, { random: () => 0.5 });
  assert.deepEqual(slept, [125, 250, 500, 1000, 2000, 4000, 4000]);
});

test("the default budget outlasts a full 30s lease; an overrun throws the last error as-is", async () => {
  assert.ok(DEFAULT_RETRY_BUDGET_MS > 30_000);
  const ok = await run(script(sessionUnavailable(30)));
  assert.deepEqual(ok.slept, [30_250]);
  const second = sessionUnavailable(30);
  const s = script(sessionUnavailable(30), second);
  await assert.rejects(run(s), (e) => e === second);
  assert.equal(s.calls, 2);
});

test("maxAttempts counts the first call", async () => {
  const s = script(...Array.from({ length: 5 }, () => sessionUnavailable()));
  await assert.rejects(run(s, { maxAttempts: 3 }), UnavailableError);
  assert.equal(s.calls, 3);
});

test("every other error propagates on the first attempt, unslept", async () => {
  for (const [name, err] of OTHERS) {
    const s = script(err);
    const slept: number[] = [];
    await assert.rejects(
      withSessionRetry(s.call, { sleep: async (ms) => void slept.push(ms) }),
      (e) => e === err,
    );
    assert.equal(s.calls, 1, name);
    assert.deepEqual(slept, [], name);
  }
});
