// `EvaluationRequest.confidence` is EXPLICIT PRESENCE on the wire (proto `optional double`;
// protobuf-es v2 maps it to `confidence?: number`). Omitting the key is absence — the runtime
// never fabricates a value into the caller's intent. `0` must survive as `0`, never collapse into
// absence. This pins the contract at two levels: the raw proto round-trip (toBinary/fromBinary),
// and the `submitEvaluation` wrapper itself (server-free, via a recording fake Transport, mirroring
// unit_plumbing.test.ts). Also covers `submitObjection`'s severity default and `authorize`'s new
// `subjects` plumbing (A-3/A-4 — signature-neutral, additive to `subject`).

import { test } from "node:test";
import assert from "node:assert/strict";
import { create, toBinary, fromBinary } from "@bufbuild/protobuf";
import type { DescMessage, DescMethodUnary, MessageInitShape } from "@bufbuild/protobuf";
import type { Transport, UnaryResponse } from "@connectrpc/connect";

import { Agent, SeamClient } from "../src/client.js";
import { AuthorizeVerdict, EvaluationRequestSchema } from "../gen/seam/api/v1/seam_pb.js";

const SEED = new Uint8Array(32).fill(7);

interface Recorded {
  method: string;
  input: Record<string, unknown>;
}

/** Server-free Transport that records the wire method + init object. `Authorize` answers ALLOW
 * (so `authorize()` doesn't throw `UnknownVerdictError` on the fake's zero-valued default);
 * `Admit` answers a non-empty ticket (so the admission round-trip has something to cache).
 * Everything else answers `{}`. */
function fakeTransport(calls: Recorded[]): Transport {
  return {
    async unary<I extends DescMessage, O extends DescMessage>(
      method: DescMethodUnary<I, O>,
      _signal: AbortSignal | undefined,
      _timeoutMs: number | undefined,
      _header: HeadersInit | undefined,
      input: MessageInitShape<I>,
    ): Promise<UnaryResponse<I, O>> {
      calls.push({ method: method.name, input: input as Record<string, unknown> });
      let out: Record<string, unknown> = {};
      if (method.name === "Authorize") out = { verdict: AuthorizeVerdict.ALLOW };
      if (method.name === "Admit") out = { ticket: new Uint8Array([1]), expiresAtMs: 9_999_999_999_999n };
      return {
        stream: false,
        service: method.parent,
        method,
        header: new Headers(),
        trailer: new Headers(),
        message: create(method.output, out as MessageInitShape<O>),
      };
    },
    stream() {
      throw new Error("not used in this suite");
    },
  };
}

// ── Raw proto presence: toBinary/fromBinary round-trip ────────────────────────────────────────

test("EvaluationRequest.confidence: absent stays undefined through a binary round-trip", () => {
  const msg = create(EvaluationRequestSchema, {
    sessionId: "s",
    evaluator: "e",
    proposalId: "p",
    recommendation: "APPROVE",
  });
  const roundTripped = fromBinary(EvaluationRequestSchema, toBinary(EvaluationRequestSchema, msg));
  assert.equal(roundTripped.confidence, undefined);
});

test("EvaluationRequest.confidence: 0 survives a binary round-trip as 0, not absence", () => {
  const msg = create(EvaluationRequestSchema, {
    sessionId: "s",
    evaluator: "e",
    proposalId: "p",
    recommendation: "APPROVE",
    confidence: 0,
  });
  const roundTripped = fromBinary(EvaluationRequestSchema, toBinary(EvaluationRequestSchema, msg));
  assert.equal(roundTripped.confidence, 0);
  assert.notEqual(roundTripped.confidence, undefined);
});

// ── The wrapper itself: submitEvaluation must not `?? 0` the caller's intent ──────────────────

test("submitEvaluation omits confidence when the caller gives none", async () => {
  const calls: Recorded[] = [];
  const client = new SeamClient(fakeTransport(calls));
  await client.submitEvaluation("s", "evaluator-a", "p-1", "APPROVE");
  assert.equal(calls[0]!.method, "SubmitEvaluation");
  assert.ok(!("confidence" in calls[0]!.input), "confidence key must be absent, not undefined-valued");
});

test("submitEvaluation sends confidence 0 when the caller explicitly passes 0", async () => {
  const calls: Recorded[] = [];
  const client = new SeamClient(fakeTransport(calls));
  await client.submitEvaluation("s", "evaluator-a", "p-1", "APPROVE", { confidence: 0 });
  assert.equal(calls[0]!.input.confidence, 0);
});

test("submitEvaluation omits rationaleRef when absent, and sends it when given", async () => {
  const calls: Recorded[] = [];
  const client = new SeamClient(fakeTransport(calls));
  await client.submitEvaluation("s", "evaluator-a", "p-1", "APPROVE");
  assert.ok(!("rationaleRef" in calls[0]!.input));

  calls.length = 0;
  await client.submitEvaluation("s", "evaluator-a", "p-1", "APPROVE", {
    rationaleRef: "sha256:" + "a".repeat(64),
  });
  assert.equal(calls[0]!.input.rationaleRef, "sha256:" + "a".repeat(64));
});

test("submitObjection defaults severity to empty (server applies MACP's `medium` default)", async () => {
  const calls: Recorded[] = [];
  const client = new SeamClient(fakeTransport(calls));
  await client.submitObjection("s", "objector-a", "p-1", "too risky");
  assert.equal(calls[0]!.method, "SubmitObjection");
  assert.equal(calls[0]!.input.severity, "");
  assert.equal(calls[0]!.input.reason, "too risky");

  calls.length = 0;
  await client.submitObjection("s", "objector-a", "p-1", "too risky", { severity: "high" });
  assert.equal(calls[0]!.input.severity, "high");
});

// ── `subjects` plumbing on `authorize` (A-3/A-4) ────────────────────────────────────────────────

test("authorize sends subjects alongside the deprecated singular subject, without changing callSig", async () => {
  const agent = new Agent(SEED);

  const calls1: Recorded[] = [];
  await new SeamClient(fakeTransport(calls1)).authorize(agent, "tool", { k: 1 }, {
    subjects: ["a", "b"],
  });
  const withSubjects = calls1.find((c) => c.method === "Authorize")!;
  assert.deepEqual(withSubjects.input.subjects, ["a", "b"]);
  assert.equal(withSubjects.input.subject, "");

  const calls2: Recorded[] = [];
  await new SeamClient(fakeTransport(calls2)).authorize(agent, "tool", { k: 1 });
  const withoutSubjects = calls2.find((c) => c.method === "Authorize")!;
  assert.deepEqual(withoutSubjects.input.subjects, []);

  // callSig must be identical whether or not `subjects` is supplied — it is not part of the
  // signed payload (A-3): ticket, digest, toolName, agentId only.
  assert.deepEqual(withoutSubjects.input.callSig, withSubjects.input.callSig);
});
