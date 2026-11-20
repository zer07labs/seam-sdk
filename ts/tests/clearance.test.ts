// `clearance` on the decision reads (#384): `x-seam-clearance` on getDecision, replayDecision,
// getCommitmentProof (and verifyDecision, through it). Omitted, the wire is exactly as before; each of
// the six runtime labels is sent verbatim, with or without a credential and on both attempts of the
// #275 refresh retry; anything else throws InvalidArgumentError before any RPC (the runtime would
// silently read an unknown label as Public). Mirrors python/tests/test_clearance.py.

import { test } from "node:test";
import assert from "node:assert/strict";
import { create } from "@bufbuild/protobuf";
import type { DescMessage, DescMethodUnary, MessageInitShape } from "@bufbuild/protobuf";
import { Code } from "@connectrpc/connect";
import type { Transport, UnaryResponse } from "@connectrpc/connect";
import { ed25519 } from "@noble/curves/ed25519";

import {
  Agent,
  CLEARANCES,
  CLEARANCE_CONFIDENTIAL,
  CLEARANCE_FINANCIAL,
  CLEARANCE_HEADER,
  CLEARANCE_INTERNAL,
  CLEARANCE_PHI,
  CLEARANCE_PII,
  CLEARANCE_PUBLIC,
  IssuerMismatchError,
  SeamClient,
  type Clearance,
} from "../src/index.js";
import { requestSigPayload } from "../src/crypto.js";
import { InvalidArgumentError, UnauthenticatedError } from "../src/errors.js";

const TICKET = new Uint8Array([1, 2, 3, 9, 9]);
const DECISION = "d-384";
const LABELS = ["Public", "Internal", "Confidential", "Financial", "Pii", "Phi"] as const;

interface Recorded {
  method: string;
  input: Record<string, unknown>;
  headers?: HeadersInit;
}

function wire() {
  const calls: Recorded[] = [];
  const reject: Record<string, number> = {};
  let admits = 0;
  const transport = {
    async unary<I extends DescMessage, O extends DescMessage>(
      method: DescMethodUnary<I, O>,
      _signal: AbortSignal | undefined,
      _timeoutMs: number | undefined,
      headers: HeadersInit | undefined,
      input: MessageInitShape<I>,
    ): Promise<UnaryResponse<I, O>> {
      calls.push({ method: method.name, input: input as Record<string, unknown>, headers });
      let out: unknown = {};
      if (method.name === "IssueChallenge") out = { receiverAid: "aid:pubkey:ed25519:recv", nonce: "n1" };
      else if (method.name === "Admit") {
        admits += 1;
        out = { ticket: new Uint8Array([100 + admits]), expiresAtMs: BigInt(Date.now() + 60_000) };
      } else if ((reject[method.name] ?? 0) > 0) {
        reject[method.name]! -= 1;
        throw new UnauthenticatedError("ticket rejected", Code.Unauthenticated);
      } else if (method.name === "GetCommitmentProof") out = { issuerAid: "aid:served" };
      return {
        stream: false,
        service: method.parent,
        method,
        header: new Headers(),
        trailer: new Headers(),
        message: create(method.output, out as MessageInitShape<O>),
      };
    },
    async stream(): Promise<never> {
      throw new Error("no streams here");
    },
  } as unknown as Transport;
  return { calls, reject, client: new SeamClient(transport) };
}

function seed(client: SeamClient, aid: string): void {
  (
    client as unknown as { tickets: Map<string, { ticket: Uint8Array; refreshAtMs: number }> }
  ).tickets.set(aid, { ticket: TICKET, refreshAtMs: Date.now() + 60_000 });
}

type Opts = { credential?: Agent; clearance?: Clearance };
// verb -> [the RPC it lands on, how to call it]. verifyDecision lands on GetCommitmentProof and then
// fails the issuer check against the canned proof, which is after the wire and irrelevant here.
const VERBS: Record<string, [string, (c: SeamClient, o?: Opts) => Promise<unknown>]> = {
  getDecision: ["GetDecision", (c, o) => c.getDecision(DECISION, o)],
  replayDecision: ["ReplayDecision", (c, o) => c.replayDecision(DECISION, o)],
  getCommitmentProof: ["GetCommitmentProof", (c, o) => c.getCommitmentProof(DECISION, o)],
  verifyDecision: [
    "GetCommitmentProof",
    (c, o) =>
      c.verifyDecision(DECISION, "aid:expected", o).catch((e) => {
        if (!(e instanceof IssuerMismatchError)) throw e;
      }),
  ],
};

const lastOf = (calls: Recorded[], rpc: string) => calls.filter((c) => c.method === rpc).at(-1)!;
const hdrs = (r: Recorded) => r.headers as Record<string, string> | undefined;

test("clearance: omitted leaves the wire exactly as before, on every decision read", async () => {
  for (const [verb, [rpc, invoke]] of Object.entries(VERBS)) {
    const { calls, client } = wire();
    await invoke(client);
    assert.equal(lastOf(calls, rpc).headers, undefined, `${verb}: headers sent with no option`);
    await invoke(client, {});
    assert.equal(lastOf(calls, rpc).headers, undefined, `${verb}: headers sent with {}`);

    const cred = new Agent(new Uint8Array(32).fill(3));
    seed(client, cred.aid);
    await invoke(client, { credential: cred });
    assert.deepEqual(Object.keys(hdrs(lastOf(calls, rpc))!).sort(), [
      "x-seam-call-sig-bin",
      "x-seam-ticket-bin",
    ]);
  }
});

test("clearance: each label is sent verbatim without a credential", async () => {
  for (const [verb, [rpc, invoke]] of Object.entries(VERBS)) {
    for (const label of LABELS) {
      const { calls, client } = wire();
      await invoke(client, { clearance: label });
      const sent = lastOf(calls, rpc);
      assert.deepEqual(hdrs(sent), { [CLEARANCE_HEADER]: label }, `${verb}/${label}`);
      assert.equal(sent.input.decisionId, DECISION);
    }
  }
});

test("clearance: with a credential it rides beside the #508 signature, which is unchanged", async () => {
  const cred = new Agent(new Uint8Array(32).fill(3));
  for (const [verb, [rpc, invoke]] of Object.entries(VERBS)) {
    const { calls, client } = wire();
    seed(client, cred.aid);
    await invoke(client, { credential: cred, clearance: "Financial" });
    const h = hdrs(lastOf(calls, rpc))!;
    assert.deepEqual(Object.keys(h).sort(), ["x-seam-call-sig-bin", CLEARANCE_HEADER, "x-seam-ticket-bin"]);
    assert.equal(h[CLEARANCE_HEADER], "Financial", verb);
    const payload = requestSigPayload(TICKET, `/seam.api.v1.SeamCoordination/${rpc}`, DECISION, "");
    const sig = Buffer.from(h["x-seam-call-sig-bin"]!, "base64");
    assert.ok(ed25519.verify(sig, payload, ed25519.getPublicKey(cred.seed)), `${verb}: signature`);
  }
});

test("clearance: both attempts of the #275 refresh retry carry it", async () => {
  const cred = new Agent(new Uint8Array(32).fill(3));
  for (const [verb, [rpc, invoke]] of Object.entries(VERBS)) {
    const { calls, reject, client } = wire();
    seed(client, cred.aid);
    reject[rpc] = 1;
    await invoke(client, { credential: cred, clearance: "Phi" });
    const sent = calls.filter((c) => c.method === rpc);
    assert.equal(sent.length, 2, `${verb}: one rejection, one retry`);
    for (const s of sent) assert.equal(hdrs(s)![CLEARANCE_HEADER], "Phi", verb);
    assert.notEqual(hdrs(sent[0]!)!["x-seam-ticket-bin"], hdrs(sent[1]!)!["x-seam-ticket-bin"]);
  }
});

test("clearance: anything else throws InvalidArgumentError before any RPC, admission included", async () => {
  const circular: Record<string, unknown> = {};
  circular.self = circular;
  const bad: unknown[] = ["PUBLIC", "public", "", " Public", "Public ", "Restricted", "PII", 1, 1n, null, ["Public"], {}, circular];
  const cred = new Agent(new Uint8Array(32).fill(3)); // no seeded ticket: admission would go first
  for (const [verb, [, invoke]] of Object.entries(VERBS)) {
    for (const b of bad) {
      const { calls, client } = wire();
      await assert.rejects(
        invoke(client, { credential: cred, clearance: b as Clearance }),
        (e: unknown) => e instanceof InvalidArgumentError && /clearance/.test((e as Error).message),
        `${verb}: ${String(b)}`,
      );
      assert.deepEqual(calls, [], `${verb}: ${String(b)} reached the wire`);
    }
  }
});

test("clearance: the label set is exported and closed", () => {
  assert.deepEqual([...CLEARANCES].sort(), [...LABELS].sort());
  assert.equal(CLEARANCE_HEADER, "x-seam-clearance");
  assert.deepEqual(
    [CLEARANCE_PUBLIC, CLEARANCE_INTERNAL, CLEARANCE_CONFIDENTIAL, CLEARANCE_FINANCIAL, CLEARANCE_PII, CLEARANCE_PHI],
    [...LABELS],
  );
});

test("clearance: only the decision reads accept it (a compile-time pin)", () => {
  // Never executed: typecheck is what proves these. Each line must stay a type error.
  const typeOnly = (c: SeamClient): void => {
    // @ts-expect-error clearance is a DecisionReadOptions field, not a general call option
    void c.getEscalation("e", { clearance: "Public" });
    // @ts-expect-error the label set is closed and case-sensitive
    void c.getDecision("d", { clearance: "PUBLIC" });
  };
  assert.equal(typeof typeOnly, "function");
});
