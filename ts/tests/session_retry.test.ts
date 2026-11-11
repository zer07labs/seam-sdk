// `SESSION_UNAVAILABLE` (seam-runtime k8s P6): classification and the opt-in `withSessionRetry` loop —
// the twin of `python/tests/test_session_retry.py`. The client's ticket drop is in `unit_plumbing`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Code } from "@connectrpc/connect";
import {
  loadShedRetryClassifier,
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


test("quota retries are opt-in and honour RetryInfo", async () => {
  const e = refusal(Code.ResourceExhausted, "QUOTA_EXCEEDED", 2);
  const baseline = script(e);
  await assert.rejects(run(baseline), (err) => err === e);
  assert.equal(baseline.calls, 1);
  const s = script(e);
  const { out, slept } = await run(s, { classifier: loadShedRetryClassifier });
  assert.equal(out, "ok");
  assert.deepEqual(slept, [2250]);
  for (const other of [
    refusal(Code.Unavailable, "QUOTA_EXCEEDED"),
    refusal(Code.ResourceExhausted, "CHALLENGE_REFUSED"),
    refusal(Code.ResourceExhausted, "other"), new Error("stop"),
  ]) assert.equal(loadShedRetryClassifier(other), undefined);
});

test("custom classifiers supply delay, can refuse, and cannot bypass budget or attempts", async () => {
  const e = new Error("custom");
  const s = script(e);
  const { slept } = await run(s, { classifier: () => ({ delayMs: 3000 }) });
  assert.deepEqual(slept, [3250]);
  for (const opts of [
    { classifier: () => undefined },
    { classifier: () => ({ delayMs: 3000 }), budgetMs: 2999 },
    { classifier: () => ({ delayMs: 3000 }), maxAttempts: 1 },
  ]) {
    const s = script(e);
    await assert.rejects(run(s, opts), (err) => err === e);
    assert.equal(s.calls, 1);
  }
  for (const delayMs of [-1, Infinity, NaN]) {
    await assert.rejects(run(script(e), { classifier: () => ({ delayMs }) }), RangeError);
  }
});

test("negative server RetryInfo retains default retry and the original error", async () => {
  const err = sessionUnavailable(-1);
  assert.ok(err instanceof UnavailableError);
  assert.equal(err.retryAfter, -1); // Real signed protobuf Duration.
  for (const jitter of [0, 0.5]) {
    const s = script(err, err);
    const slept: number[] = [];
    await assert.rejects(withSessionRetry(s.call, {
      maxAttempts: 2,
      random: () => jitter,
      sleep: async ms => { slept.push(ms); },
    }), e => e === err);
    assert.equal(s.calls, 2);
    assert.deepEqual(slept, [jitter * 250]); // Zero server delay, ordinary jitter retained.
  }
});

test("built-in classifier clamps negative server delays for every retry class", () => {
  for (const [code, reason, freshChallenge] of [
    [Code.Unavailable, "SESSION_UNAVAILABLE", false],
    [Code.ResourceExhausted, "QUOTA_EXCEEDED", false],
    [Code.Unavailable, "CHALLENGE_REFUSED", true],
  ] as const) {
    const decision = loadShedRetryClassifier(refusal(code, reason, -1));
    assert.equal(decision?.delayMs, 0);
    assert.equal(decision?.freshChallenge ?? false, freshChallenge);
  }
});
