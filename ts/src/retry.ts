// Opt-in retry for the runtime's `SESSION_UNAVAILABLE` refusal (seam-runtime k8s P6) — the twin of
// Python's `seam_sdk/retry.py`; read its module docstring for the full rule.
//
// The SDK never retries on its own (D-WRITES-EXCLUDED); this is a helper a caller wraps around a call
// it chooses to retry. It re-invokes `call`, so every attempt is a fresh SDK call: it re-signs its
// credential and, when the ticket is cold, re-admits. Only `isRetryable` errors are retried — every
// other error, including every other `UNAVAILABLE`, propagates on the first attempt.
//
// The delay before attempt n+1 is `retryAfter + U(0, min(maxDelayMs, baseDelayMs * 2**(n-1)))`. The
// default 40s budget outlasts the runtime's 30s lease TTL, so one lapsed lease is always waited out. It
// bounds the time spent waiting, not the calls: each attempt keeps its own `timeoutMs`. It does NOT
// outlast a tenant move (`TENANT_MOVING`, also `isRetryable`; 5s `RetryInfo`): the source cell drains
// until its live sessions finish, so pass a `budgetMs` sized for that drain. When the next
// delay would overrun the budget, the last error is thrown as-is. Wrap unary calls only.

import { isRetryable, SeamRpcError } from "./errors.js";

/** Total milliseconds a retry loop may spend waiting between attempts. Longer than the 30s lease TTL. */
export const DEFAULT_RETRY_BUDGET_MS = 40_000;

export interface SessionRetryOptions {
  /** Total wait budget across attempts, in ms. Default {@link DEFAULT_RETRY_BUDGET_MS}. */
  budgetMs?: number;
  /** Base of the jittered exponential, in ms. Default 250. */
  baseDelayMs?: number;
  /** Cap on the jittered exponential, in ms. Default 8000. */
  maxDelayMs?: number;
  /** Attempts in all, the first included. Default 10. */
  maxAttempts?: number;
  /** Injected for tests. */
  sleep?: (ms: number) => Promise<void>;
  /** Injected for tests: a draw from [0, 1). */
  random?: () => number;
}

/** Run `call()`, re-invoking it on `SESSION_UNAVAILABLE` with bounded, jittered backoff. `call` makes
 * ONE SDK call, e.g. `withSessionRetry(() => client.submitProposal(...))`. */
export async function withSessionRetry<T>(
  call: () => Promise<T>,
  opts: SessionRetryOptions = {},
): Promise<T> {
  const budgetMs = opts.budgetMs ?? DEFAULT_RETRY_BUDGET_MS;
  const baseDelayMs = opts.baseDelayMs ?? 250;
  const maxDelayMs = opts.maxDelayMs ?? 8_000;
  const maxAttempts = opts.maxAttempts ?? 10;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const random = opts.random ?? Math.random;
  let waited = 0;
  for (let attempt = 1; ; attempt++) {
    try {
      return await call();
    } catch (e) {
      if (!isRetryable(e) || attempt >= maxAttempts) throw e;
      const retryAfterMs = ((e as SeamRpcError).retryAfter ?? 0) * 1000;
      const delay =
        retryAfterMs + random() * Math.min(maxDelayMs, baseDelayMs * 2 ** (attempt - 1));
      if (waited + delay > budgetMs) throw e;
      await sleep(delay);
      waited += delay;
    }
  }
}
