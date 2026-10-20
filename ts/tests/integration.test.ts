import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { connect as tcpConnect, createServer, type AddressInfo } from "node:net";
import { Code, ConnectError, createClient } from "@connectrpc/connect";
import { createGrpcTransport } from "@connectrpc/connect-node";
import { Agent, IssuerMismatchError, SeamClient } from "../src/client.js";
import { SeamAdminClient } from "../src/admin.js";
import { requestSig } from "../src/crypto.js";
import { UnauthenticatedError } from "../src/errors.js";
import { SeamCoordination } from "../gen/seam/api/v1/seam_pb.js";
import { governanceEnv, mintOperatorToken } from "./operator_token.js";

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
      ...governanceEnv(),
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
      env: { ...process.env, ...governanceEnv(), SEAM_GRPC_LISTEN: addr, SEAM_DEV_INSECURE: "1" },
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
    const dec = await client.runDecision(agent, "ts-1-sid-0123456789abcdef", ["fraud-v3", "risk-v2"], [["fraud-v3", "BLOCK"], ["risk-v2", "BLOCK"]]);
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
    const plain = await client.runDecision(demoAgent(), "ts-feat-off-sid-0123456789abcdef", ["fraud-v3", "risk-v2"], votes);
    const feat = await client.runDecision(demoAgent(), "ts-feat-on-sid-0123456789abcdef", ["fraud-v3", "risk-v2"], votes, {
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
    await client.openSession(demoAgent(), { sessionId: "ts-sess-sid-0123456789abcdef", participants: ["lead", "peer"] });
    await client.submitProposal("ts-sess-sid-0123456789abcdef", "lead", "p1", "BLOCK");
    await client.submitVote("ts-sess-sid-0123456789abcdef", "peer", "p1", "APPROVE");
    const step = await client.submitCommit("ts-sess-sid-0123456789abcdef", "c1", "BLOCK");
    assert.equal(step.state, "Resolved");
    assert.ok(step.decisionId);
  });
});

test("6.2 budget loop: hard breach suspends, mgmt-plane resume continues and seals", { skip: !BIN }, async () => {
  // Resume moved to the management plane (rt-D: SeamCoordination.ResumeSession is now a tombstone), so
  // this needs both planes; since seam-runtime #1156 there is no dev-open mgmt plane, so the R9
  // approver presents an operator token.
  await withPlanes(8217, 8218, async (dataAddr, mgmtUrl) => {
    const client = SeamClient.connect(`http://${dataAddr}`);
    const admin = SeamAdminClient.connect(mgmtUrl, { token: mintOperatorToken(["session:resume"]) });
    await client.openSession(demoAgent(), {
      sessionId: "ts-budget-sid-0123456789abcdef",
      participants: ["lead", "peer"],
      limits: { tokens: 1000n },
    });
    // The proposal reports the full allowance — applied, ledger now exhausted.
    await client.submitProposal("ts-budget-sid-0123456789abcdef", "lead", "p1", "BLOCK", { tokens: 1000n, costMicros: 40n });
    // The next step breaches the hard token limit: Suspended (a resolved step, not a thrown error).
    let step = await client.submitVote("ts-budget-sid-0123456789abcdef", "peer", "p1", "APPROVE");
    assert.equal(step.state, "Suspended");
    // The R9 approver raises the token dimension and resumes — now via SeamAdmin (mgmt plane), named.
    await admin.resumeSession("ts-budget-sid-0123456789abcdef", "op:approver", { raise: { tokens: 5000n } });
    // Re-submit (the breached vote was never applied): now within budget → continues, then seals.
    step = await client.submitVote("ts-budget-sid-0123456789abcdef", "peer", "p1", "APPROVE");
    assert.notEqual(step.state, "Suspended");
    step = await client.submitCommit("ts-budget-sid-0123456789abcdef", "c1", "BLOCK");
    assert.equal(step.state, "Resolved");
    assert.ok(step.decisionId);
  });
});

// ── The per-request credential against a deny plane (request-credential plan step 4, #264) ───────
//
// `SEAM_ENFORCE_SUBJECT=1` + `SEAM_GRPC_SUBJECT_HEADERS=deny` is the credential-only posture (#710,
// #508): the gRPC plane strips `x-seam-subject` at its edge, so a subject-scoped read proves its caller
// in band (`x-seam-ticket-bin` + `x-seam-call-sig-bin`) or has no subject at all. The runtime's own
// end-to-end shape is `seam-runtime/integration/tests/subject_headers_deny.rs`. The refused cases are
// the anti-vacuity control: without them this would keep passing against a plane that trusted the
// header again. Always spawned (needs SEAM_GRPC_BIN): the posture is the thing under test.

const GET_DECISION = "/seam.api.v1.SeamCoordination/GetDecision";
const REPLAY_DECISION = "/seam.api.v1.SeamCoordination/ReplayDecision";

/** An OS-allocated port — not a fixed one (see python/tests/live_server.py, #85). */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address() as AddressInfo;
      srv.close(() => resolve(port));
    });
  });
}

async function withDenyPlane(fn: (baseUrl: string) => Promise<void>): Promise<void> {
  const port = await freePort();
  // The port must be OURS: if anything already accepts there, readiness below could not tell that
  // stranger from this server (the #85 defect live_server.py closes for Python).
  await assert.rejects(waitPort(port, 0), "port was already accepting before spawn");
  let output = "";
  const proc = spawn(BIN!, {
    env: {
      ...process.env,
      ...governanceEnv(),
      SEAM_GRPC_LISTEN: `127.0.0.1:${port}`,
      SEAM_DEV_INSECURE: "1",
      SEAM_ENFORCE_SUBJECT: "1",
      SEAM_GRPC_SUBJECT_HEADERS: "deny",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  // Keep the server's own output (bounded), so a boot refusal names its cause instead of timing out.
  const keep = (b: Buffer) => { output = (output + b.toString()).slice(-4000); };
  proc.stdout!.on("data", keep);
  proc.stderr!.on("data", keep);
  try {
    try {
      await waitPort(port, 15000);
    } catch {
      throw new Error(`seam-grpc did not serve on ${port} (exit ${proc.exitCode}). Its output:\n${output}`);
    }
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    proc.kill();
  }
}

async function seal(client: SeamClient, agent: Agent, tag: string): Promise<string> {
  // RunDecision proves identity from its body presentation, so it seals on a deny plane unaided.
  const dec = await client.runDecision(agent, tag, ["fraud-v3", "risk-v2"], [["fraud-v3", "BLOCK"], ["risk-v2", "BLOCK"]]);
  assert.equal(dec.outcome, "Resolved");
  return dec.decisionId;
}

test("deny plane: a credentialed read succeeds, the same read without one is refused", { skip: !BIN }, async () => {
  await withDenyPlane(async (baseUrl) => {
    const client = SeamClient.connect(baseUrl);
    const agent = demoAgent();
    try {
      const id = await seal(client, agent, "ts-deny-cred-sid-0123456789abcdef");
      // WITH the credential: the reads succeed.
      assert.equal((await client.getDecision(id, { credential: agent })).decisionId, id);
      assert.equal((await client.replayDecision(id, { credential: agent })).chainVerified, true);
      // WITHOUT it — same client, same calls: refused as an identity failure, typed.
      await assert.rejects(client.getDecision(id), UnauthenticatedError);
      await assert.rejects(client.replayDecision(id), UnauthenticatedError);
      // A client bound to the agent (#202) attaches the credential without a per-call option.
      const bound = SeamClient.connect(baseUrl, { agent });
      try {
        assert.equal((await bound.getDecision(id)).decisionId, id);
      } finally {
        bound.close();
      }
    } finally {
      client.close();
    }
  });
});

test("deny plane: a header subject and a wrong-context signature are both refused", { skip: !BIN }, async () => {
  // Built by hand, because the client always signs the call it is making: an asserted
  // `x-seam-subject` header (stripped at the edge), and an honest signature — right key, right
  // ticket — re-pointed at another resource or another verb.
  await withDenyPlane(async (baseUrl) => {
    const client = SeamClient.connect(baseUrl);
    const agent = demoAgent();
    try {
      const first = await seal(client, agent, "ts-deny-a-sid-0123456789abcdef");
      const second = await seal(client, agent, "ts-deny-b-sid-0123456789abcdef");
      const ticket = await client.admit(agent);
      const coord = createClient(SeamCoordination, createGrpcTransport({ baseUrl }));
      const cred = (rpcName: string, resourceId: string) => ({
        "x-seam-ticket-bin": Buffer.from(ticket).toString("base64"),
        "x-seam-call-sig-bin": Buffer.from(requestSig(agent.seed, ticket, rpcName, resourceId, "")).toString("base64"),
      });
      const unauthenticated = (e: unknown) => e instanceof ConnectError && e.code === Code.Unauthenticated;

      // Control: the hand-built credential is accepted when it names exactly this call — so the
      // refusals below are about the binding, not about how the headers were assembled.
      assert.equal((await coord.getDecision({ decisionId: first }, { headers: cred(GET_DECISION, first) })).decisionId, first);
      assert.equal(
        (await coord.replayDecision({ decisionId: first }, { headers: cred(REPLAY_DECISION, first) })).chainVerified,
        true,
      );

      // The pre-#508 client: the subject asserted as a header and nothing else.
      await assert.rejects(coord.getDecision({ decisionId: first }, { headers: { "x-seam-subject": agent.aid } }), unauthenticated);
      // A signature for decision `second`, presented against `first`.
      await assert.rejects(coord.getDecision({ decisionId: first }, { headers: cred(GET_DECISION, second) }), unauthenticated);
      // A signature for GetDecision on `first`, presented on ReplayDecision of `first`.
      await assert.rejects(coord.replayDecision({ decisionId: first }, { headers: cred(GET_DECISION, first) }), unauthenticated);
    } finally {
      client.close();
    }
  });
});

// ── #275 Phase 2 (D-SUBMIT-RETRY): a submit* refreshed and resent, against the real engine ──────
// Mirrors python/tests/test_integration.py. sessionStatus exposes neither tally nor budget, so the
// tally is read from the resolving commit's collectiveOutcome.approveCount, and the debit from the
// hard budget gate (a step at/over a hard limit is refused + Suspended).

const VOTE_TOKENS = 600n;
type TicketMap = Map<string, { ticket: Uint8Array; refreshAtMs: number }>;
const ticketsOf = (c: SeamClient) => (c as unknown as { tickets: TicketMap }).tickets;

async function voteThenResendTwice(client: SeamClient, agent: Agent, sid: string, tokens: bigint) {
  const credential = { credential: agent };
  await client.openSession(agent, {
    sessionId: sid,
    participants: ["lead", "peer"],
    limits: { tokens },
    credential: agent,
  });
  await client.submitProposal(sid, "lead", "p1", "BLOCK", undefined, credential);

  // 4(a): corrupt the cached live ticket's last byte; the vote is refused, refreshed, resent.
  const entry = ticketsOf(client).get(agent.aid)!;
  const corrupted = Uint8Array.from(entry.ticket);
  corrupted[corrupted.length - 1]! ^= 0xff;
  entry.ticket = corrupted;
  const usage = { tokens: VOTE_TOKENS, costMicros: 10n };
  const first = await client.submitVote(sid, "peer", "p1", "APPROVE", usage, credential);
  const afterA = ticketsOf(client).get(agent.aid)!.ticket;
  assert.notDeepEqual([...afterA], [...corrupted], "4(a): the refresh re-admitted");
  // 4(b): the same vote resent under the same ticket — refused as a replay, refreshed, deduped.
  const same = await client.submitVote(sid, "peer", "p1", "APPROVE", usage, credential);
  const afterB = ticketsOf(client).get(agent.aid)!.ticket;
  assert.notDeepEqual([...afterB], [...afterA], "4(b) anti-vacuity: the identical resend was refreshed");
  // 4(c): a different usage — a different body, so no replay; the engine dedupes it alone.
  const other = await client.submitVote(sid, "peer", "p1", "APPROVE", { tokens: VOTE_TOKENS * 3n, costMicros: 99n }, credential);
  assert.deepEqual([...ticketsOf(client).get(agent.aid)!.ticket], [...afterB]);
  return [first, same, other];
}

test("#275 P2 deny plane: a refreshed submitVote lands once; resends are deduped; a resolving resend returns the sealed id", { skip: !BIN }, async () => {
  await withDenyPlane(async (baseUrl) => {
    const client = SeamClient.connect(baseUrl);
    const agent = demoAgent();
    const sid = "ts-submit-retry-sid-0123456789abcdef";
    try {
      for (const step of await voteThenResendTwice(client, agent, sid, 1000n)) {
        assert.ok(!["Resolved", "Suspended", "Cancelled", "Expired"].includes(step.state), step.state);
        assert.equal(step.decisionId ?? "", "");
        assert.equal(step.collectiveOutcome, undefined);
        assert.equal(step.policyEnforcement, undefined);
      }
      const commit = await client.submitCommit(sid, "c1", "BLOCK", undefined, { credential: agent });
      assert.equal(commit.state, "Resolved", "the vote was debited more than once");
      assert.ok(commit.decisionId && commit.collectiveOutcome);
      assert.equal(commit.collectiveOutcome.approveCount, 1, "three sends of one vote tally once");

      // 4(d): the resolving step resent.
      const beforeD = Uint8Array.from(ticketsOf(client).get(agent.aid)!.ticket);
      const resent = await client.submitCommit(sid, "c1", "BLOCK", undefined, { credential: agent });
      assert.notDeepEqual(
        [...ticketsOf(client).get(agent.aid)!.ticket],
        [...beforeD],
        "4(d) anti-vacuity: the identical commit was refused as a replay and refreshed",
      );
      assert.equal(resent.decisionId, commit.decisionId);
      assert.equal(resent.collectiveOutcome, undefined);
      if (resent.policyEnforcement) assert.deepEqual(resent.policyEnforcement, commit.policyEnforcement);
      else if (!commit.policyEnforcement) assert.equal(resent.policyEnforcement, undefined);
      assert.equal((await client.getDecision(commit.decisionId!, { credential: agent })).decisionId, commit.decisionId);
    } finally {
      client.close();
    }
  });
});

test("#275 P2 deny plane: the refreshed vote is debited (exactly once, with the test above)", { skip: !BIN }, async () => {
  await withDenyPlane(async (baseUrl) => {
    const client = SeamClient.connect(baseUrl);
    const agent = demoAgent();
    const sid = "ts-submit-debit-sid-0123456789abcdef";
    try {
      await voteThenResendTwice(client, agent, sid, VOTE_TOKENS);
      const commit = await client.submitCommit(sid, "c1", "BLOCK", undefined, { credential: agent });
      assert.equal(commit.state, "Suspended", "the vote was never debited");
    } finally {
      client.close();
    }
  });
});
