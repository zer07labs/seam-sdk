import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { connect as tcpConnect } from "node:net";
import { Agent, IssuerMismatchError, SeamClient } from "../src/client.js";
import { SeamAdminClient } from "../src/admin.js";

const BIN = process.env.SEAM_GRPC_BIN;
const SKIP = !BIN && !process.env.SEAM_GRPC_ADDR;

/** Boot seam-grpc with BOTH planes (dev-open) on distinct ports; run `fn`, then tear down. Needs
 * SEAM_GRPC_BIN (a spawned binary) — used by the budget-resume loop, whose R9 resume is on the mgmt plane. */
async function withPlanes(
  dataPort: number,
  mgmtPort: number,
  fn: (dataAddr: string, mgmtUrl: string) => Promise<void>,
): Promise<void> {
  const proc = spawn(BIN!, {
    env: {
      ...process.env,
      SEAM_GRPC_LISTEN: `127.0.0.1:${dataPort}`,
      SEAM_GRPC_MGMT_LISTEN: `127.0.0.1:${mgmtPort}`,
      SEAM_DEV_INSECURE: "1",
    },
    stdio: "ignore",
  });
  try {
    await waitPort(dataPort);
    await waitPort(mgmtPort);
    await fn(`127.0.0.1:${dataPort}`, `http://127.0.0.1:${mgmtPort}`);
  } finally {
    proc.kill();
  }
}

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

test("H4: request features never affect the sealed record", { skip: SKIP }, async () => {
  await withServer(8095, async (addr) => {
    const client = SeamClient.connect(`http://${addr}`);
    const votes: [string, string][] = [["fraud-v3", "BLOCK"], ["risk-v2", "BLOCK"]];
    const plain = await client.runDecision(demoAgent(), "ts-feat-off", ["fraud-v3", "risk-v2"], votes);
    const feat = await client.runDecision(demoAgent(), "ts-feat-on", ["fraud-v3", "risk-v2"], votes, {
      amount_band: "high",
      channel: "card-present",
    });
    assert.equal(feat.decidedValue, plain.decidedValue);
    assert.equal(feat.outcome, plain.outcome);
    assert.ok(feat.policyVersion.length > 0); // the serving read routed a policy
    const recPlain = await client.getDecision(plain.decisionId);
    const recFeat = await client.getDecision(feat.decisionId);
    assert.equal(recFeat.outcome, recPlain.outcome);
    assert.equal(recFeat.classification, recPlain.classification);
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

test("6.2 budget loop: hard breach suspends, mgmt-plane resume continues and seals", { skip: !BIN }, async () => {
  // Resume moved to the management plane (rt-D: SeamCoordination.ResumeSession is now a tombstone), so
  // this needs both planes; the dev-open mgmt plane accepts the R9 resume without an operator token.
  await withPlanes(8217, 8218, async (dataAddr, mgmtUrl) => {
    const client = SeamClient.connect(`http://${dataAddr}`);
    const admin = SeamAdminClient.connect(mgmtUrl);
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
    // The R9 approver raises the token dimension and resumes — now via SeamAdmin (mgmt plane), named.
    await admin.resumeSession("ts-budget", "op:approver", { raise: { tokens: 5000n } });
    // Re-submit (the breached vote was never applied): now within budget → continues, then seals.
    step = await client.submitVote("ts-budget", "peer", "p1", "APPROVE");
    assert.notEqual(step.state, "Suspended");
    step = await client.submitCommit("ts-budget", "c1", "BLOCK");
    assert.equal(step.state, "Resolved");
    assert.ok(step.decisionId);
  });
});
