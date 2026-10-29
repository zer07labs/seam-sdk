// `serverInfo` — the runtime's version over `SeamTrust/ServerInfo` (runtime 0.63.0, seam-sdk#307).
//
// Two layers:
//   * server-free unit tests that stub `trust` (the wrapper sends an empty request with no `headers`
//     key, even on an agent-bound client, and returns `runtimeVersion` verbatim);
//   * an in-memory router transport with no `SeamTrust` registered — a stand-in for a pre-0.63.0
//     runtime, which registers the service but lacks the method; both answer UNIMPLEMENTED — proving
//     the rejection arrives as the typed `UnimplementedError` through `errorMappingInterceptor`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { ConnectError, Code, createRouterTransport } from "@connectrpc/connect";
import { SeamAdmission } from "../gen/seam/api/v1/seam_pb.js";
import { Agent, SeamClient } from "../src/client.js";
import { UnimplementedError, errorMappingInterceptor } from "../src/errors.js";

const SEED = Uint8Array.from({ length: 32 }, (_, i) => i);

type Seen = { req: unknown; opts: Record<string, unknown> };

/** A SeamClient whose `trust` stub records the request and call options and returns `version`. */
function clientWithTrust(version: string, agent?: Agent): { client: SeamClient; seen: Seen[] } {
  const client = SeamClient.connect("http://127.0.0.1:1", agent ? { agent } : undefined); // never dialed
  const seen: Seen[] = [];
  (client as unknown as { trust: unknown }).trust = {
    serverInfo: async (req: unknown, opts: Record<string, unknown>) => {
      seen.push({ req, opts });
      return { runtimeVersion: version };
    },
  };
  return { client, seen };
}

for (const [label, agent] of [
  ["unbound", undefined],
  ["agent-bound", new Agent(SEED)],
] as const) {
  test(`serverInfo (${label}): returns the version verbatim with no credential headers`, async () => {
    const { client, seen } = clientWithTrust("0.63.0", agent);
    assert.equal(await client.serverInfo(), "0.63.0");
    assert.equal(seen.length, 1);
    assert.deepEqual(seen[0].req, {});
    assert.equal("headers" in seen[0].opts, false);
  });
}

test("serverInfo: forwards the caller's timeout", async () => {
  const { client, seen } = clientWithTrust("0.63.0");
  await client.serverInfo({ timeoutMs: 1234 });
  assert.equal(seen[0].opts.timeoutMs, 1234);
});

test("serverInfo: the value is not normalised, and an empty one is returned, not refused", async () => {
  assert.equal(await clientWithTrust(" 0.63.0-rc.1+build ").client.serverInfo(), " 0.63.0-rc.1+build ");
  assert.equal(await clientWithTrust("").client.serverInfo(), "");
});

test("serverInfo: a runtime without the method rejects with UnimplementedError", async () => {
  // Some service must be registered for the router to answer at all; SeamTrust deliberately is not.
  const transport = createRouterTransport(
    ({ service }) => {
      service(SeamAdmission, {});
    },
    { transport: { interceptors: [errorMappingInterceptor()] } },
  );
  const client = new SeamClient(transport as ConstructorParameters<typeof SeamClient>[0]);
  await assert.rejects(client.serverInfo(), (e: unknown) => {
    assert.ok(e instanceof UnimplementedError, `expected UnimplementedError, got ${String(e)}`);
    assert.ok(e instanceof ConnectError);
    assert.equal(e.code, Code.Unimplemented);
    return true;
  });
});
