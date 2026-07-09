import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { connect as tcpConnect } from "node:net";
import { Agent, IssuerMismatchError, SeamClient } from "../src/client.js";

const BIN = process.env.SEAM_GRPC_BIN;
const SKIP = !BIN && !process.env.SEAM_GRPC_ADDR;

function waitPort(port: number, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tryOnce = () => {
      const s = tcpConnect(port, "127.0.0.1");
      s.once("connect", () => { s.destroy(); resolve(); });
      s.once("error", () => { s.destroy(); Date.now() > deadline ? reject(new Error("no server")) : setTimeout(tryOnce, 50); });
    };
    tryOnce();
  });
}

/** Run `fn` against a server: an already-running `SEAM_GRPC_ADDR`, or a spawned `SEAM_GRPC_BIN`.
 * SEAM_DEV_INSECURE lets the dev binary boot with the public dev seed AND enrol the demo tenant
 * (the [42;32] agent these tests admit as) — both required since the server refuses a public
 * identity by default (runtime security hardening). Distinct ports avoid cross-test collisions. */
async function withServer(port: number, fn: (addr: string) => Promise<void>): Promise<void> {
  const addr = process.env.SEAM_GRPC_ADDR ?? `127.0.0.1:${port}`;
  let proc: ReturnType<typeof spawn> | undefined;
  if (BIN && !process.env.SEAM_GRPC_ADDR) {
    proc = spawn(BIN, {
      env: { ...process.env, SEAM_GRPC_LISTEN: addr, SEAM_DEV_INSECURE: "1" },
      stdio: "ignore",
    });
    await waitPort(Number(addr.split(":")[1]));
  }
  try {
    await fn(addr);
  } finally {
    proc?.kill();
  }
}

const demoAgent = () => new Agent(new Uint8Array(32).fill(42));

test("full round trip: admit → decide → seal → read → verify", { skip: SKIP }, async () => {
  await withServer(8098, async (addr) => {
    const client = SeamClient.connect(`http://${addr}`);
    const agent = demoAgent();
    const dec = await client.runDecision(agent, "ts-1", ["fraud-v3", "risk-v2"], [["fraud-v3", "BLOCK"], ["risk-v2", "BLOCK"]]);
    assert.equal(dec.decidedValue, "BLOCK");
    assert.equal(dec.outcome, "Resolved");
    assert.equal((await client.getDecision(dec.decisionId)).outcome, "Resolved");
    assert.equal((await client.replayDecision(dec.decisionId)).chainVerified, true);
    const issuer = await client.issuerAid();
    assert.equal(await client.verifyDecision(dec.decisionId, issuer), true);
    // A wrong pinned issuer is a key-substitution signal — a DISTINCT error, not a bland false.
    await assert.rejects(
      client.verifyDecision(dec.decisionId, "aid:pubkey:ed25519:" + "A".repeat(43)),
      IssuerMismatchError,
    );
  });
});

test("session lifecycle: open → propose → vote → commit seals", { skip: SKIP }, async () => {
  await withServer(8097, async (addr) => {
    const client = SeamClient.connect(`http://${addr}`);
    await client.openSession(demoAgent(), { sessionId: "ts-sess", participants: ["lead", "peer"] });
    await client.submitProposal("ts-sess", "lead", "p1", "BLOCK");
    await client.submitVote("ts-sess", "peer", "p1", "APPROVE");
    const step = await client.submitCommit("ts-sess", "c1", "BLOCK");
    assert.equal(step.state, "Resolved");
    assert.ok(step.decisionId);
  });
});

test("6.2 budget loop: hard breach suspends, raising resume continues and seals", { skip: SKIP }, async () => {
  await withServer(8096, async (addr) => {
    const client = SeamClient.connect(`http://${addr}`);
    await client.openSession(demoAgent(), {
      sessionId: "ts-budget",
      participants: ["lead", "peer"],
      limits: { tokens: 1000n },
    });
    // The proposal reports the full allowance — applied, ledger now exhausted.
    await client.submitProposal("ts-budget", "lead", "p1", "BLOCK", { tokens: 1000n, costMicros: 40n });
    // The next step breaches the hard token limit: Suspended (a resolved step, not a thrown error).
    let step = await client.submitVote("ts-budget", "peer", "p1", "APPROVE");
    assert.equal(step.state, "Suspended");
    // The R9 approver raises the token dimension and resumes.
    await client.resumeSession("ts-budget", { raise: { tokens: 5000n } });
    // Re-submit (the breached vote was never applied): now within budget → continues, then seals.
    step = await client.submitVote("ts-budget", "peer", "p1", "APPROVE");
    assert.notEqual(step.state, "Suspended");
    step = await client.submitCommit("ts-budget", "c1", "BLOCK");
    assert.equal(step.state, "Resolved");
    assert.ok(step.decisionId);
  });
});
