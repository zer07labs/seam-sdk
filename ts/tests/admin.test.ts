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
import { errorMappingInterceptor, SeamRpcError, UnauthenticatedError } from "../src/errors.js";
import { OperatorDpopKey, mgmtDpopGrpcHtu, mgmtDpopProof } from "../src/dpop.js";
import { createClient } from "@connectrpc/connect";
import { createGrpcTransport } from "@connectrpc/connect-node";
import { SeamAdmin } from "../gen/seam/api/v1/seam_pb.js";
import {
  governanceEnv,
  mintOperatorToken,
  tamperSignature,
  STREAM_ID,
} from "./operator_token.js";

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

/** Boot seam-grpc with both planes on distinct ports; run `fn`, then tear down. The management plane is
 * unlocked only for operator tokens signed by a key in the signed root's `operator_keys` (seam-runtime
 * #1156 — no root LOCKS it, even under SEAM_DEV_INSECURE; there is no dev-open flow any more), so every
 * call below presents one minted by `admin()`. */
async function withPlanes(
  dataPort: number,
  mgmtPort: number,
  fn: (dataAddr: string, mgmtUrl: string) => Promise<void>,
): Promise<void> {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...governanceEnv(),
    SEAM_GRPC_LISTEN: `127.0.0.1:${dataPort}`,
    SEAM_GRPC_MGMT_LISTEN: `127.0.0.1:${mgmtPort}`,
    SEAM_DEV_INSECURE: "1",
  };
  const proc = spawn(BIN!, { env, stdio: "ignore" });
  try {
    await waitPort(dataPort);
    await waitPort(mgmtPort);
    await fn(`127.0.0.1:${dataPort}`, `http://127.0.0.1:${mgmtPort}`);
  } finally {
    proc.kill();
  }
}

/** An admin client holding a fresh operator token for `scopes` — fresh per destructive call, since a
 * destructive verb burns the token's jti. */
function admin(mgmtUrl: string, ...scopes: string[]): SeamAdminClient {
  return SeamAdminClient.connect(mgmtUrl, { token: mintOperatorToken(scopes) });
}

async function sealOne(dataAddr: string): Promise<{ subject: string; decisionId: string }> {
  const client = SeamClient.connect(`http://${dataAddr}`);
  const agent = new Agent(new Uint8Array(32).fill(42));
  const dec = await client.runDecision(agent, "ts-admin-seal-sid-0123456789abcdef", ["fraud-v3", "risk-v2"], [["fraud-v3", "BLOCK"], ["risk-v2", "BLOCK"]]);
  assert.equal(dec.outcome, "Resolved");
  return { subject: agent.aid, decisionId: dec.decisionId };
}

test("erasure: preview → confirm → erase (+ empty-tenant & wrong-count rejections)", { skip: SKIP }, async () => {
  await withPlanes(8201, 8202, async (dataAddr, mgmtUrl) => {
    const { subject, decisionId } = await sealOne(dataAddr);
    const preview = await admin(mgmtUrl, "erasure:preview").previewErasure(TENANT, subject);
    assert.ok(preview.wouldErase.includes(decisionId));
    assert.ok(!preview.alreadyErased.includes(decisionId));
    const count = BigInt(preview.wouldErase.length);

    // Empty tenant is refused (erasure never crosses tenants). Surfaced as a typed SeamRpcError — and,
    // being non-breaking, still a ConnectError.
    await assert.rejects(admin(mgmtUrl, "erasure:execute").eraseSubject("", subject, count), (e: unknown) =>
      e instanceof SeamRpcError && e instanceof ConnectError);
    // Wrong confirm count is refused.
    await assert.rejects(admin(mgmtUrl, "erasure:execute").eraseSubject(TENANT, subject, count + 1n), (e: unknown) =>
      e instanceof SeamRpcError);

    // Right count → populated, signed certificate.
    const cert = await admin(mgmtUrl, "erasure:execute").eraseSubject(TENANT, subject, count);
    assert.equal(cert.subject, subject);
    assert.ok(cert.erased.includes(decisionId));
    assert.ok(cert.signature.length > 0);
    assert.ok(cert.issuerAid.length > 0);

    // Second preview → already erased, no new destruction.
    const after = await admin(mgmtUrl, "erasure:preview").previewErasure(TENANT, subject);
    assert.ok(after.alreadyErased.includes(decisionId));
    assert.ok(!after.wouldErase.includes(decisionId));
  });
});

test("eraseSubjectConfirmed convenience path", { skip: SKIP }, async () => {
  await withPlanes(8205, 8206, async (dataAddr, mgmtUrl) => {
    const { subject, decisionId } = await sealOne(dataAddr);
    const cert = await admin(mgmtUrl, "erasure:preview", "erasure:execute").eraseSubjectConfirmed(
      TENANT,
      subject,
    );
    assert.ok(cert.erased.includes(decisionId));
  });
});

test(
  "management operator-token auth: missing/wrong/tampered → UNAUTHENTICATED, valid → ok",
  { skip: SKIP },
  async () => {
    // The management plane authenticates compact-JWS operator tokens against the installed operator_keys
    // root (rt-D / CP-18d; the shared SEAM_MGMT_TOKEN bearer was removed in seam-runtime #175). Holds
    // against BOTH pre- and post-#175 runtimes — the operator-token path is already live.
    await withPlanes(8203, 8204, async (_dataAddr, mgmtUrl) => {
      // previewErasure requires the erasure:preview scope (non-destructive → no jti needed).
      const token = mintOperatorToken(["erasure:preview"]);
      const subject = "aid:pubkey:ed25519:zzz"; // any subject — this pins AUTH, not the erase flow

      const anon = SeamAdminClient.connect(mgmtUrl);
      await assert.rejects(
        anon.previewErasure(TENANT, subject),
        (e: unknown) => e instanceof UnauthenticatedError && e.code === Code.Unauthenticated,
      );

      // A non-JWS bearer → the operator-keys-only plane refuses the old shared-bearer shape.
      const wrong = SeamAdminClient.connect(mgmtUrl, { token: "nope" });
      await assert.rejects(
        wrong.previewErasure(TENANT, subject),
        (e: unknown) => e instanceof UnauthenticatedError,
      );

      // A JWS-shaped token with a corrupted signature → a hard verification failure, never a downgrade.
      const tampered = SeamAdminClient.connect(mgmtUrl, { token: tamperSignature(token) });
      await assert.rejects(
        tampered.previewErasure(TENANT, subject),
        (e: unknown) => e instanceof UnauthenticatedError,
      );

      const ok = SeamAdminClient.connect(mgmtUrl, { token });
      const preview = await ok.previewErasure(TENANT, subject);
      assert.ok(Array.isArray(preview.wouldErase));
    });
  },
);

test("streamEvents (drain) yields the DECISION_SEALED event", { skip: SKIP }, async () => {
  await withPlanes(8207, 8208, async (dataAddr, mgmtUrl) => {
    const { decisionId } = await sealOne(dataAddr);
    const events = [];
    for await (const ev of admin(mgmtUrl, "audit:read").streamEvents({ streamId: STREAM_ID, follow: false })) events.push(ev);
    assert.ok(events.length > 0, "expected at least the DECISION_SEALED event");
    const sealed = events.filter((e) => e.kind === "DECISION_SEALED");
    assert.ok(sealed.length > 0, `kinds seen: ${events.map((e) => e.kind).join(",")}`);
    assert.ok(sealed.some((e) => e.decisionId === decisionId));
  });
});

// ── DPoP-bound operator tokens (seam-sdk#290) — the TS twin of python/tests/test_mgmt_dpop_live.py ──
//
// The spawned listener is loopback (DPoP optional), but a token carrying `cnf.jkt` must come with a valid
// proof on every listener, so everything the SDK sends is checked exactly as a required listener checks
// it. Every refusal carries the runtime's one fixed message, so an unrelated 401 cannot pass for one.

const DPOP_REFUSED = "management call refused: DPoP proof of possession failed";
const DPOP_KEY = OperatorDpopKey.fromSeed(new Uint8Array(32).fill(0x42));
const DPOP_OTHER = OperatorDpopKey.fromSeed(new Uint8Array(32).fill(0x07));
const DEMO_NAMESPACE = "design-partner/fraud"; // python/tests/governing_root.py DEMO_NAMESPACE

function isDpopRefusal(e: unknown): boolean {
  return e instanceof UnauthenticatedError && e.message.includes(DPOP_REFUSED);
}

test("DPoP: a bound token is accepted, and each misuse is refused with the fixed message", { skip: SKIP }, async (t) => {
  // 8221/8222: free of every other live suite's ports, since node --test runs files in parallel.
  await withPlanes(8221, 8222, async (_dataAddr, mgmtUrl) => {
    const bound = (scope: string, jkt = DPOP_KEY.jkt) => mintOperatorToken([scope], { cnfJkt: jkt });
    const signed = (scope: string) =>
      SeamAdminClient.connect(mgmtUrl, { token: bound(scope), dpopKey: DPOP_KEY });
    // A raw client with no auth interceptor, for the requests the SDK refuses to build.
    const raw = createClient(
      SeamAdmin,
      createGrpcTransport({ baseUrl: mgmtUrl, interceptors: [errorMappingInterceptor()] }),
    );
    const htu = mgmtDpopGrpcHtu("/seam.api.v1.SeamAdmin/ListTenants");
    const proof = (tok: string, body: Uint8Array) => mgmtDpopProof(DPOP_KEY, tok, { htm: "POST", htu, body });

    // Each case is its own subtest, so the first failure cannot hide the rest.
    await t.test("accepted: ListTenants", async () => {
      assert.ok(Array.isArray(await signed("tenant:list").listTenants()));
    });
    await t.test("accepted: EnrollTenant", async () => {
      const agent = new Agent(Uint8Array.from({ length: 32 }, (_, i) => i + 1));
      const view = await signed("tenant:enroll").enrollTenant(agent.aid, TENANT, DEMO_NAMESPACE);
      assert.equal(view.tenant, TENANT);
    });
    await t.test("accepted: a StreamEvents drain", async () => {
      const drained = [];
      for await (const ev of signed("audit:read").streamEvents({ streamId: STREAM_ID, follow: false })) drained.push(ev);
      assert.ok(Array.isArray(drained));
    });
    await t.test("accepted: five calls on one client, each re-signed", async () => {
      const many = signed("tenant:list"); // each proof is burned; a client that reused one fails on call 2
      for (let i = 0; i < 5; i++) await many.listTenants();
    });
    await t.test("refused: a bound token sent as Bearer", async () => {
      const tok = bound("tenant:list");
      await assert.rejects(raw.listTenants({}, { headers: { authorization: `Bearer ${tok}` } }), isDpopRefusal);
    });
    await t.test("refused: a token bound to another key", async () => {
      const tok = bound("tenant:list", DPOP_OTHER.jkt);
      await assert.rejects(
        raw.listTenants({}, { headers: { authorization: `DPoP ${tok}`, dpop: proof(tok, new Uint8Array()) } }),
        isDpopRefusal,
      );
    });
    await t.test("refused: a replayed proof", async () => {
      const tok = bound("tenant:list");
      const replayed = { authorization: `DPoP ${tok}`, dpop: proof(tok, new Uint8Array()) };
      await raw.listTenants({}, { headers: replayed }); // first use: accepted
      await assert.rejects(raw.listTenants({}, { headers: replayed }), isDpopRefusal);
    });
    await t.test("refused: an iat 120 s stale", async () => {
      const stale = SeamAdminClient.connect(mgmtUrl, {
        token: bound("tenant:list"),
        dpopKey: DPOP_KEY,
        clock: () => Math.floor(Date.now() / 1000) - 120,
      });
      await assert.rejects(stale.listTenants(), isDpopRefusal);
    });
    await t.test("refused: a seam_bd over other bytes", async () => {
      const tok = bound("tenant:list");
      await assert.rejects(
        raw.listTenants({}, { headers: { authorization: `DPoP ${tok}`, dpop: proof(tok, new Uint8Array([0])) } }),
        isDpopRefusal,
      );
    });
  });
});
