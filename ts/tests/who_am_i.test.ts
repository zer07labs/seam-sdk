// `whoAmI` — the caller's resolved identity over `SeamTrust/WhoAmI` (runtime 0.71.0, OI-R7).
//
// Mirrors python/tests/test_who_am_i.py. Unlike `serverInfo` the verb is subject-bearing: with a
// credential (explicit or the bound agent) it carries a `seam-request-call-v1` credential that binds
// the verb ONLY — an empty resource id and an empty body digest, the framing the runtime's
// `Binding::ReadNoResource` and the HTTP twin `GET /v1/whoami` share. Without one it sends no
// credential headers. The four fields come back as the server sent them, and a runtime without the
// method rejects with the typed `UnimplementedError`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { ConnectError, Code, createRouterTransport } from "@connectrpc/connect";
import { ed25519 } from "@noble/curves/ed25519";
import { SeamAdmission } from "../gen/seam/api/v1/seam_pb.js";
import { Agent, SeamClient } from "../src/client.js";
import { ENROLMENT_KIND_OUTCOME_REPORTER } from "../src/admin.js";
import { requestSigPayload } from "../src/crypto.js";
import { UnimplementedError, errorMappingInterceptor } from "../src/errors.js";

const SEED = Uint8Array.from({ length: 32 }, (_, i) => i);
const TICKET = new Uint8Array([1, 2, 3, 9, 9]);
const RPC = "/seam.api.v1.SeamTrust/WhoAmI";
const ANSWER = {
  tenant: "acme",
  namespace: "fraud",
  kind: ENROLMENT_KIND_OUTCOME_REPORTER,
  subjectEnforcement: true,
};

type Seen = { req: unknown; opts: Record<string, unknown> };

/** A SeamClient whose `trust` stub records the request and call options and answers `answer`. */
function clientWithTrust(agent?: Agent, answer: object = ANSWER): { client: SeamClient; seen: Seen[] } {
  const client = SeamClient.connect("http://127.0.0.1:1", agent ? { agent } : undefined); // never dialed
  const seen: Seen[] = [];
  (client as unknown as { trust: unknown }).trust = {
    whoAmI: async (req: unknown, opts: Record<string, unknown>) => {
      seen.push({ req, opts });
      return answer;
    },
  };
  return { client, seen };
}

/** Seeds the signer's ticket cache directly — the network-free way to give it one. */
function seedTicket(client: SeamClient, aid: string): void {
  (client as unknown as { tickets: Map<string, { ticket: Uint8Array; refreshAtMs: number }> }).tickets.set(aid, {
    ticket: TICKET,
    refreshAtMs: Date.now() + 60_000,
  });
}

function assertVerbOnlyCredential(opts: Record<string, unknown>, signer: Agent): void {
  const headers = opts.headers as Record<string, string> | undefined;
  assert.ok(headers, "no credential headers");
  assert.deepEqual(Object.keys(headers).sort(), ["x-seam-call-sig-bin", "x-seam-ticket-bin"]);
  assert.deepEqual([...Buffer.from(headers["x-seam-ticket-bin"]!, "base64")], [...TICKET]);
  const payload = requestSigPayload(TICKET, RPC, "", ""); // no resource id, no body digest
  const sig = Buffer.from(headers["x-seam-call-sig-bin"]!, "base64");
  assert.ok(ed25519.verify(sig, payload, ed25519.getPublicKey(signer.seed)), "signature does not verify");
}

test("whoAmI (unbound): returns the four fields with no credential headers", async () => {
  const { client, seen } = clientWithTrust();
  assert.deepEqual(await client.whoAmI(), ANSWER);
  assert.equal(seen.length, 1);
  assert.deepEqual(seen[0]!.req, {});
  assert.equal(seen[0]!.opts.headers, undefined);
});

test("whoAmI (bound agent): carries a verb-only credential", async () => {
  const agent = new Agent(SEED);
  const { client, seen } = clientWithTrust(agent);
  seedTicket(client, agent.aid);
  assert.deepEqual(await client.whoAmI(), ANSWER);
  assertVerbOnlyCredential(seen[0]!.opts, agent);
});

test("whoAmI (credential=): carries a verb-only credential and forwards the timeout", async () => {
  const agent = new Agent(SEED);
  const { client, seen } = clientWithTrust();
  seedTicket(client, agent.aid);
  await client.whoAmI({ credential: agent, timeoutMs: 1234 });
  assertVerbOnlyCredential(seen[0]!.opts, agent);
  assert.equal(seen[0]!.opts.timeoutMs, 1234);
});

test("whoAmI: the empty triple is returned, not refused", async () => {
  const empty = { tenant: "", namespace: "", kind: "", subjectEnforcement: false };
  assert.deepEqual(await clientWithTrust(undefined, empty).client.whoAmI(), empty);
});

test("whoAmI: a runtime without the method rejects with UnimplementedError", async () => {
  const transport = createRouterTransport(
    ({ service }) => {
      service(SeamAdmission, {});
    },
    { transport: { interceptors: [errorMappingInterceptor()] } },
  );
  const client = new SeamClient(transport as ConstructorParameters<typeof SeamClient>[0]);
  await assert.rejects(client.whoAmI(), (e: unknown) => {
    assert.ok(e instanceof UnimplementedError, `expected UnimplementedError, got ${String(e)}`);
    assert.ok(e instanceof ConnectError);
    assert.equal(e.code, Code.Unimplemented);
    return true;
  });
});
