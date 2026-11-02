// `reportOutcome(…, { reward, metrics, observedAt })` (Branchpoint BP-2 / plan 47 OI-R1) and
// `serverWireFeatures()` (OI-R6) — the TS twin of python/tests/test_report_outcome_reward.py, sharing its
// golden bytes so the two SDKs are pinned to the same wire.

import { test } from "node:test";
import assert from "node:assert/strict";
import { create, toBinary } from "@bufbuild/protobuf";
import type { DescMessage, DescMethodUnary, MessageInitShape } from "@bufbuild/protobuf";
import type { Transport, UnaryResponse } from "@connectrpc/connect";
import { ReportOutcomeRequestSchema } from "../gen/seam/api/v1/seam_pb.js";
import {
  InvalidArgumentError,
  OUTCOME_METRICS_MAX,
  SeamClient,
  WIRE_FEATURE_ENROLL_KIND,
  WIRE_FEATURE_OUTCOME_OBSERVED_AT,
  WIRE_FEATURE_OUTCOME_REWARD_METRICS,
} from "../src/index.js";

// Hand-derived: 0a 08 "dec:t:s1" | 10 01 | 1a 02 "qa" | 22 09 "review-77" (python GOLDEN_PRE_BP2).
const GOLDEN_PRE_BP2 = "0a086465633a743a733110011a02716122097265766965772d3737";
// + reward=0.5 | metrics={"latency_ms": 12} | observed_at_millis=1700000000123 (python GOLDEN_FULL).
const GOLDEN_FULL =
  GOLDEN_PRE_BP2 + "29000000000000e03f" + "32150a0a6c6174656e63795f6d73110000000000002840" + "38fbd095ffbc31";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** The request init the client handed the transport, serialized as the wire would carry it. */
function wire(input: Record<string, unknown>): string {
  return hex(
    toBinary(
      ReportOutcomeRequestSchema,
      create(ReportOutcomeRequestSchema, input as MessageInitShape<typeof ReportOutcomeRequestSchema>),
    ),
  );
}

function clientRecording(): { client: SeamClient; inputs: Record<string, unknown>[] } {
  const inputs: Record<string, unknown>[] = [];
  const transport = {
    async unary<I extends DescMessage, O extends DescMessage>(
      method: DescMethodUnary<I, O>,
      _signal: AbortSignal | undefined,
      _timeoutMs: number | undefined,
      _headers: HeadersInit | undefined,
      input: MessageInitShape<I>,
    ): Promise<UnaryResponse<I, O>> {
      inputs.push(input as Record<string, unknown>);
      return {
        stream: false,
        service: method.parent,
        method,
        header: new Headers(),
        trailer: new Headers(),
        message: create(method.output, { recorded: true } as unknown as MessageInitShape<O>),
      };
    },
    async stream() {
      throw new Error("no streams here");
    },
  } as unknown as Transport;
  return { client: new SeamClient(transport), inputs };
}

const report = (c: SeamClient, extra: Record<string, unknown> = {}) =>
  c.reportOutcome("dec:t:s1", true, { idempotencyKey: "review-77", verifiedBy: "qa", ...extra });

test("omitting every new argument is byte-identical to the previous release", async () => {
  const { client, inputs } = clientRecording();
  assert.equal(await report(client), true);
  assert.equal(wire(inputs[0]!), GOLDEN_PRE_BP2);
  for (const k of ["reward", "metrics", "observedAtMillis"]) assert.equal(k in inputs[0]!, false);
});

test("the fields ride on the wire, byte-identical to the Python SDK", async () => {
  const { client, inputs } = clientRecording();
  await report(client, { reward: 0.5, metrics: { latency_ms: 12 }, observedAt: 1_700_000_000_123 });
  assert.equal(wire(inputs[0]!), GOLDEN_FULL);
  // Every accepted observedAt form lands on the same u64.
  await report(client, { observedAt: 1_700_000_000_123n });
  await report(client, { observedAt: new Date(1_700_000_000_123) });
  await report(client, { observedAt: 0 });
  assert.deepEqual(
    inputs.slice(1).map((i) => i.observedAtMillis),
    [1_700_000_000_123n, 1_700_000_000_123n, 0n],
  );
});

test("each field is independent, and reward 0 is present", async () => {
  const { client, inputs } = clientRecording();
  await report(client, { reward: 0 });
  await report(client, { metrics: { a: 1 } });
  assert.deepEqual(Object.keys(inputs[0]!).filter((k) => ["reward", "metrics", "observedAtMillis"].includes(k)), [
    "reward",
  ]);
  assert.equal(inputs[0]!.reward, 0);
  assert.deepEqual(inputs[1]!.metrics, { a: 1 });
  assert.equal("reward" in inputs[1]!, false);
});

test("an empty metrics object is absent (the v1 digest)", async () => {
  const { client, inputs } = clientRecording();
  await report(client, { metrics: {} });
  assert.equal("metrics" in inputs[0]!, false);
  assert.equal(wire(inputs[0]!), GOLDEN_PRE_BP2);
});

test("metric key bounds are the runtime's", async () => {
  const { client, inputs } = clientRecording();
  const keys = { a: 1, ["z" + "9".repeat(62)]: 2, a_b_0: 3 };
  await report(client, { metrics: keys });
  await report(client, { metrics: Object.fromEntries(Array.from({ length: 16 }, (_, i) => [`k${i}`, i])) });
  assert.deepEqual(inputs[0]!.metrics, keys);
  assert.equal(Object.keys(inputs[1]!.metrics as object).length, OUTCOME_METRICS_MAX);
});

const BAD: [Record<string, unknown>, RegExp][] = [
  [{ reward: NaN }, /reward must be a finite/],
  [{ reward: Infinity }, /reward must be a finite/],
  [{ reward: -Infinity }, /reward must be a finite/],
  [{ reward: "0.5" }, /reward must be a number/],
  [{ reward: true }, /reward must be a number/],
  [{ metrics: { a: NaN } }, /metrics values must be a finite/],
  [{ metrics: { a: false } }, /metrics values must be a number/],
  [{ metrics: Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`k${i}`, 0])) }, /at most 16/],
  [{ metrics: { "": 1 } }, /metrics key/],
  [{ metrics: { Latency: 1 } }, /metrics key/],
  [{ metrics: { "9lives": 1 } }, /metrics key/],
  [{ metrics: { _a: 1 } }, /metrics key/],
  [{ metrics: { "a-b": 1 } }, /metrics key/],
  [{ metrics: { "a\n": 1 } }, /metrics key/],
  [{ metrics: { é: 1 } }, /metrics key/],
  [{ metrics: { ["a".repeat(64)]: 1 } }, /metrics key/],
  [{ metrics: [["a", 1]] }, /metrics must be a plain object/],
  [{ metrics: new Map([["a", 1]]) }, /metrics must be a plain object/],
  [{ metrics: null }, /metrics must be a plain object/],
  [{ observedAt: -1 }, /before the Unix epoch/],
  [{ observedAt: 1n << 64n }, /u64/],
  [{ observedAt: 1.5 }, /integer number of ms/],
  [{ observedAt: Number.MAX_SAFE_INTEGER + 1 }, /integer number of ms/],
  [{ observedAt: new Date(NaN) }, /invalid Date/],
  [{ observedAt: new Date(-1) }, /before the Unix epoch/],
  [{ observedAt: "2023-01-01" }, /observedAt must be a Date/],
];

test("an invalid value is refused before any RPC", async () => {
  const { client, inputs } = clientRecording();
  for (const [extra, msg] of BAD) {
    await assert.rejects(
      report(client, extra),
      (e: unknown) => e instanceof InvalidArgumentError && msg.test(String(e)),
      `accepted or mis-refused ${String(Object.keys(extra))}`,
    );
  }
  assert.equal(inputs.length, 0, "an invalid outcome field must never reach the wire");
});

test("the key is checked first, as on the runtime", async () => {
  const { client, inputs } = clientRecording();
  await assert.rejects(
    client.reportOutcome("d", true, { idempotencyKey: "", reward: NaN }),
    (e: unknown) => e instanceof InvalidArgumentError && /idempotencyKey/.test(String(e)),
  );
  assert.equal(inputs.length, 0);
});

// ── serverWireFeatures ─────────────────────────────────────────────────────────────────────────────

function clientWithFeatures(features: string[]) {
  const client = SeamClient.connect("http://127.0.0.1:1"); // never dialed
  const seen: { req: unknown; opts: Record<string, unknown> }[] = [];
  (client as unknown as { trust: unknown }).trust = {
    serverInfo: async (req: unknown, opts: Record<string, unknown>) => {
      seen.push({ req, opts });
      return { runtimeVersion: "0.73.0", wireFeatures: features };
    },
  };
  return { client, seen };
}

test("serverWireFeatures returns the list, sends an empty request, forwards the timeout", async () => {
  const feats = [WIRE_FEATURE_ENROLL_KIND, WIRE_FEATURE_OUTCOME_OBSERVED_AT, WIRE_FEATURE_OUTCOME_REWARD_METRICS];
  const { client, seen } = clientWithFeatures(feats);
  const got = await client.serverWireFeatures({ timeoutMs: 1234 });
  assert.deepEqual(got, ["enroll.kind", "outcome.observed_at", "outcome.reward_metrics"]);
  assert.notEqual(got, feats, "a copy, not the response's own array");
  assert.deepEqual(seen[0]!.req, {});
  assert.equal(seen[0]!.opts.timeoutMs, 1234);
  assert.equal("headers" in seen[0]!.opts, false);
  assert.deepEqual(await clientWithFeatures([]).client.serverWireFeatures(), []);
});

test("the feature names are the runtime's vocabulary", () => {
  assert.equal(WIRE_FEATURE_ENROLL_KIND, "enroll.kind");
  assert.equal(WIRE_FEATURE_OUTCOME_OBSERVED_AT, "outcome.observed_at");
  assert.equal(WIRE_FEATURE_OUTCOME_REWARD_METRICS, "outcome.reward_metrics");
  assert.equal(OUTCOME_METRICS_MAX, 16);
});
