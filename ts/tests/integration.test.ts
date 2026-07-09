import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { connect as tcpConnect } from "node:net";
import { Agent, IssuerMismatchError, SeamClient } from "../src/client.js";

const BIN = process.env.SEAM_GRPC_BIN;
const ADDR = process.env.SEAM_GRPC_ADDR ?? "127.0.0.1:8098";

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

test("full round trip: admit → decide → seal → read → verify", { skip: !BIN && !process.env.SEAM_GRPC_ADDR }, async () => {
  let proc: ReturnType<typeof spawn> | undefined;
  if (BIN) {
    proc = spawn(BIN, { env: { ...process.env, SEAM_GRPC_LISTEN: ADDR }, stdio: "ignore" });
    await waitPort(Number(ADDR.split(":")[1]));
  }
  try {
    const client = SeamClient.connect(`http://${ADDR}`);
    const agent = new Agent(new Uint8Array(32).fill(42));
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
  } finally {
    proc?.kill();
  }
});
