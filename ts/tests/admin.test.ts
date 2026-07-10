// Live management-plane tests — GDPR erasure preview→confirm→erase + bearer auth.
//
// The admin surface (`SeamAdmin`) is served on a SEPARATE management listener (`SEAM_GRPC_MGMT_LISTEN`)
// from the data plane. These tests spawn a `seam-grpc` with BOTH planes up and drive the erasure flow
// against the enrolled demo tenant. Env-gated like integration.test.ts: needs `SEAM_GRPC_BIN`, else skips.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { connect as tcpConnect } from "node:net";
import { Code, ConnectError } from "@connectrpc/connect";

import { Agent, SeamClient } from "../src/client.js";
import { SeamAdminClient } from "../src/admin.js";
import { SeamRpcError, UnauthenticatedError } from "../src/errors.js";

const BIN = process.env.SEAM_GRPC_BIN;
const SKIP = !BIN;
const TENANT = "design-partner"; // the demo tenant SEAM_DEV_INSECURE enrols the [42;32] agent under

function waitPort(port: number, timeoutMs = 8000): Promise<void> {
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

/** Boot seam-grpc with both planes on distinct ports; run `fn`, then tear down. */
async function withPlanes(
  dataPort: number,
  mgmtPort: number,
  token: string | undefined,
  fn: (dataAddr: string, mgmtUrl: string) => Promise<void>,
): Promise<void> {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    SEAM_GRPC_LISTEN: `127.0.0.1:${dataPort}`,
    SEAM_GRPC_MGMT_LISTEN: `127.0.0.1:${mgmtPort}`,
    SEAM_DEV_INSECURE: "1",
  };
  if (token) env.SEAM_MGMT_TOKEN = token;
  const proc = spawn(BIN!, { env, stdio: "ignore" });
  try {
    await waitPort(dataPort);
    await waitPort(mgmtPort);
    await fn(`127.0.0.1:${dataPort}`, `http://127.0.0.1:${mgmtPort}`);
  } finally {
    proc.kill();
  }
}

async function sealOne(dataAddr: string): Promise<{ subject: string; decisionId: string }> {
  const client = SeamClient.connect(`http://${dataAddr}`);
  const agent = new Agent(new Uint8Array(32).fill(42));
  const dec = await client.runDecision(agent, "ts-admin-seal", ["fraud-v3", "risk-v2"], [["fraud-v3", "BLOCK"], ["risk-v2", "BLOCK"]]);
  assert.equal(dec.outcome, "Resolved");
  return { subject: agent.aid, decisionId: dec.decisionId };
}

test("erasure: preview → confirm → erase (+ empty-tenant & wrong-count rejections)", { skip: SKIP }, async () => {
  await withPlanes(8201, 8202, undefined, async (dataAddr, mgmtUrl) => {
    const { subject, decisionId } = await sealOne(dataAddr);
    const admin = SeamAdminClient.connect(mgmtUrl); // unauthenticated dev mgmt plane

    const preview = await admin.previewErasure(TENANT, subject);
    assert.ok(preview.wouldErase.includes(decisionId));
    assert.ok(!preview.alreadyErased.includes(decisionId));
    const count = BigInt(preview.wouldErase.length);

    // Empty tenant is refused (erasure never crosses tenants). Surfaced as a typed SeamRpcError — and,
    // being non-breaking, still a ConnectError.
    await assert.rejects(admin.eraseSubject("", subject, count), (e: unknown) =>
      e instanceof SeamRpcError && e instanceof ConnectError);
    // Wrong confirm count is refused.
    await assert.rejects(admin.eraseSubject(TENANT, subject, count + 1n), (e: unknown) =>
      e instanceof SeamRpcError);

    // Right count → populated, signed certificate.
    const cert = await admin.eraseSubject(TENANT, subject, count);
    assert.equal(cert.subject, subject);
    assert.ok(cert.erased.includes(decisionId));
    assert.ok(cert.signature.length > 0);
    assert.ok(cert.issuerAid.length > 0);

    // Second preview → already erased, no new destruction.
    const after = await admin.previewErasure(TENANT, subject);
    assert.ok(after.alreadyErased.includes(decisionId));
    assert.ok(!after.wouldErase.includes(decisionId));
  });
});

test("eraseSubjectConfirmed convenience path", { skip: SKIP }, async () => {
  await withPlanes(8205, 8206, undefined, async (dataAddr, mgmtUrl) => {
    const { subject, decisionId } = await sealOne(dataAddr);
    const admin = SeamAdminClient.connect(mgmtUrl);
    const cert = await admin.eraseSubjectConfirmed(TENANT, subject);
    assert.ok(cert.erased.includes(decisionId));
  });
});

test("management bearer auth: missing/wrong → UNAUTHENTICATED, right → ok", { skip: SKIP }, async () => {
  const token = "s3cr3t-operator-token";
  await withPlanes(8203, 8204, token, async (dataAddr, mgmtUrl) => {
    const { subject } = await sealOne(dataAddr);

    const anon = SeamAdminClient.connect(mgmtUrl);
    await assert.rejects(anon.previewErasure(TENANT, subject), (e: unknown) =>
      e instanceof UnauthenticatedError && e.code === Code.Unauthenticated);

    const wrong = SeamAdminClient.connect(mgmtUrl, { token: "nope" });
    await assert.rejects(wrong.previewErasure(TENANT, subject), (e: unknown) =>
      e instanceof UnauthenticatedError);

    const ok = SeamAdminClient.connect(mgmtUrl, { token });
    const preview = await ok.previewErasure(TENANT, subject);
    assert.ok(Array.isArray(preview.wouldErase));
  });
});

test("streamEvents (drain) yields the DECISION_SEALED event", { skip: SKIP }, async () => {
  await withPlanes(8207, 8208, undefined, async (dataAddr, mgmtUrl) => {
    const { decisionId } = await sealOne(dataAddr);
    const admin = SeamAdminClient.connect(mgmtUrl);

    const events = [];
    for await (const ev of admin.streamEvents({ follow: false })) events.push(ev);
    assert.ok(events.length > 0, "expected at least the DECISION_SEALED event");
    const sealed = events.filter((e) => e.kind === "DECISION_SEALED");
    assert.ok(sealed.length > 0, `kinds seen: ${events.map((e) => e.kind).join(",")}`);
    assert.ok(sealed.some((e) => e.decisionId === decisionId));
  });
});
