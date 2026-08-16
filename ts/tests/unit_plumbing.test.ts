// Server-free wrapper plumbing over a recording fake Transport: per-call deadlines (data plane 2s,
// management plane 30s, streams unbounded), the SeamAdmin grant/party wrappers, the proto-owned
// budget default (0, never a client-side 32), the coalescing ticket refresh (adopt, don't stampede),
// the TRANSFORM protocol-violation error, and streamEvents' drain-only ack guard + AbortSignal
// cancellation. Mirrors the Python suite's test_lifecycle_and_timeouts / test_ticket_lifecycle.

import { test } from "node:test";
import assert from "node:assert/strict";
import { create } from "@bufbuild/protobuf";
import type {
  DescMessage,
  DescMethodStreaming,
  DescMethodUnary,
  MessageInitShape,
  MessageShape,
} from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import type { StreamResponse, Transport, UnaryResponse } from "@connectrpc/connect";

import {
  Agent,
  DEFAULT_TIMEOUT_MS,
  SeamClient,
} from "../src/client.js";
import { DEFAULT_ADMIN_TIMEOUT_MS, SeamAdminClient } from "../src/admin.js";
import {
  InvalidArgumentError,
  ProtocolViolationError,
  SeamRpcError,
  UnauthenticatedError,
} from "../src/errors.js";
import { AuthorizeVerdict } from "../gen/seam/api/v1/seam_pb.js";

const SEED = new Uint8Array(32).fill(7);

interface Recorded {
  method: string;
  input: Record<string, unknown>;
  timeoutMs?: number;
  signal?: AbortSignal;
}

type UnaryHandler = (
  method: string,
  input: Record<string, unknown>,
) => unknown | Promise<unknown>;
type StreamHandler = (
  method: string,
  input: Record<string, unknown>,
  signal: AbortSignal | undefined,
) => AsyncIterable<unknown>;

/** A Transport whose unary/stream calls are answered by `handle`/`streamHandle` and recorded —
 * the wire method name, the request init, and the exact `timeoutMs`/`signal` call options the
 * client wrappers plumbed through. */
function fakeTransport(
  calls: Recorded[],
  handle: UnaryHandler,
  streamHandle?: StreamHandler,
): Transport {
  return {
    async unary<I extends DescMessage, O extends DescMessage>(
      method: DescMethodUnary<I, O>,
      signal: AbortSignal | undefined,
      timeoutMs: number | undefined,
      _header: HeadersInit | undefined,
      input: MessageInitShape<I>,
    ): Promise<UnaryResponse<I, O>> {
      calls.push({ method: method.name, input: input as Record<string, unknown>, timeoutMs, signal });
      const out = await handle(method.name, input as Record<string, unknown>);
      return {
        stream: false,
        service: method.parent,
        method,
        header: new Headers(),
        trailer: new Headers(),
        message: create(method.output, out as MessageInitShape<O>),
      };
    },
    async stream<I extends DescMessage, O extends DescMessage>(
      method: DescMethodStreaming<I, O>,
      signal: AbortSignal | undefined,
      timeoutMs: number | undefined,
      _header: HeadersInit | undefined,
      input: AsyncIterable<MessageInitShape<I>>,
    ): Promise<StreamResponse<I, O>> {
      const first = (await input[Symbol.asyncIterator]().next()).value as Record<string, unknown>;
      calls.push({ method: method.name, input: first, timeoutMs, signal });
      if (!streamHandle) throw new Error(`no stream handler for ${method.name}`);
      const out = streamHandle(method.name, first, signal);
      const message = (async function* () {
        for await (const m of out) yield create(method.output, m as MessageInitShape<O>);
      })();
      return {
        stream: true,
        service: method.parent,
        method,
        header: new Headers(),
        trailer: new Headers(),
        message,
      };
    },
  };
}

// ── Management plane: every wrapper is deadline-bounded (default 30s, overridable) ───────────────

/** Every unary management-plane wrapper with a minimal call — the TS twin of the Python suite's
 * ADMIN_CALLS table, extended with the grant/party wrappers. `streamEvents` is excluded
 * deliberately: it is the one method that must NOT default to a deadline (tested below). */
const ADMIN_CALLS: Record<
  string,
  (a: SeamAdminClient, o?: { timeoutMs?: number }) => Promise<unknown>
> = {
  previewErasure: (a, o) => a.previewErasure("acme", "cust-42", o),
  eraseSubject: (a, o) => a.eraseSubject("acme", "cust-42", 0n, undefined, o),
  eraseSubjectConfirmed: (a, o) => a.eraseSubjectConfirmed("acme", "cust-42", undefined, o),
  enrollTenant: (a, o) => a.enrollTenant("aid:x", "acme", "ns", o),
  listTenants: (a, o) => a.listTenants(o),
  registerParty: (a, o) => a.registerParty("p", new Uint8Array(32), o),
  removeParty: (a, o) => a.removeParty("p", o),
  placeGrant: (a, o) => a.placeGrant("acme", "from", "to", "op:x", 9999999999999n, o),
  revokeGrant: (a, o) => a.revokeGrant("acme", "from", "to", "op:x", o),
  listGrants: (a, o) => a.listGrants(o),
  resumeSession: (a, o) => a.resumeSession("s", "op:approver", o),
  placeLegalHold: (a, o) => a.placeLegalHold("d", o),
  releaseLegalHold: (a, o) => a.releaseLegalHold("d", o),
  enforceRetention: (a, o) => a.enforceRetention(1n, 2n, 3n, undefined, o),
  auditTrail: (a, o) => a.auditTrail(o),
  reportEventsConsumed: (a, o) => a.reportEventsConsumed(1n, o),
};

test("every admin wrapper passes the 30s default deadline, and an override, on every RPC it makes", async () => {
  for (const [name, invoke] of Object.entries(ADMIN_CALLS)) {
    const calls: Recorded[] = [];
    const admin = new SeamAdminClient(fakeTransport(calls, () => ({})));
    await invoke(admin);
    assert.ok(calls.length > 0, `${name} made no RPC`);
    for (const c of calls)
      assert.equal(c.timeoutMs, DEFAULT_ADMIN_TIMEOUT_MS, `${name} → ${c.method} lost the default deadline`);

    calls.length = 0;
    await invoke(admin, { timeoutMs: 123 });
    for (const c of calls)
      assert.equal(c.timeoutMs, 123, `${name} → ${c.method} lost the timeout override`);
  }
});

test("the admin default deadline is generous but finite", () => {
  // The value is a judgement call and may change; being FINITE is not. >= 10s because
  // management-plane work (erasure, retention) is operator-cadence, not hot-path.
  assert.ok(DEFAULT_ADMIN_TIMEOUT_MS >= 10_000 && Number.isFinite(DEFAULT_ADMIN_TIMEOUT_MS));
  assert.equal(DEFAULT_TIMEOUT_MS, 2_000); // Python parity: DEFAULT_TIMEOUT_S = 2.0
});

// ── The grant/party wrappers put the right request on the wire ───────────────────────────────────

test("placeGrant / revokeGrant / listGrants / removeParty wrap SeamAdmin verbatim", async () => {
  const calls: Recorded[] = [];
  const admin = new SeamAdminClient(
    fakeTransport(calls, (method) =>
      method === "ListGrants"
        ? { grants: [{ tenant: "acme", fromNs: "from", toNs: "to", grantor: "op:x", expiresAt: 5n }] }
        : {},
    ),
  );

  await admin.placeGrant("acme", "from", "to", "op:x", 5n);
  assert.equal(calls[0]!.method, "PlaceGrant");
  assert.deepEqual(calls[0]!.input, { tenant: "acme", fromNs: "from", toNs: "to", grantor: "op:x", expiresAt: 5n });

  await admin.revokeGrant("acme", "from", "to", "op:y");
  assert.equal(calls[1]!.method, "RevokeGrant");
  assert.deepEqual(calls[1]!.input, { tenant: "acme", fromNs: "from", toNs: "to", revoker: "op:y" });

  const grants = await admin.listGrants();
  assert.equal(calls[2]!.method, "ListGrants");
  assert.equal(grants.length, 1);
  assert.equal(grants[0]!.tenant, "acme");
  assert.equal(grants[0]!.expiresAt, 5n);

  await admin.removeParty("party-1");
  assert.equal(calls[3]!.method, "RemoveParty");
  assert.deepEqual(calls[3]!.input, { partyId: "party-1" });
});

// ── Data plane: the 2s default deadline rides every RPC a call fans out to ───────────────────────

/** A minimal data-plane fake: challenge → ticket → ALLOW, with per-ticket revocation and an
 * optional hook to defer an Authorize rejection (to stage the refresh race deterministically). */
function fakeSeam() {
  const state = {
    admits: 0,
    serial: 0,
    revoked: new Set<number>(),
    // When set, an Authorize against a revoked ticket parks here instead of rejecting at once.
    deferRejections: false,
    pending: [] as Array<() => void>,
  };
  const handle: UnaryHandler = (method, input) => {
    if (method === "IssueChallenge") return { receiverAid: "aid:pubkey:ed25519:recv", nonce: "n1" };
    if (method === "Admit") {
      state.admits += 1;
      state.serial += 1;
      return { ticket: new Uint8Array([state.serial]), expiresAtMs: BigInt(Date.now() + 60_000) };
    }
    if (method === "Authorize") {
      const t = (input.ticket as Uint8Array)[0]!;
      if (state.revoked.has(t)) {
        const reject = () => {
          throw new UnauthenticatedError("ticket revoked", Code.Unauthenticated);
        };
        if (!state.deferRejections) return reject();
        return new Promise((_res, rej) => {
          state.pending.push(() => rej(new UnauthenticatedError("ticket revoked", Code.Unauthenticated)));
        });
      }
      return { verdict: AuthorizeVerdict.ALLOW, reason: "", authorizeId: "az-1", policyVersion: "p1" };
    }
    if (method === "OpenSession" || method === "ResumeSession") return {};
    return {};
  };
  return { state, handle };
}

test("authorize carries the deadline on every RPC of its fan-out (challenge, admit, authorize)", async () => {
  const calls: Recorded[] = [];
  const { handle } = fakeSeam();
  const client = new SeamClient(fakeTransport(calls, handle));
  const r = await client.authorize(new Agent(SEED), "tool", { k: 1 });
  assert.ok(r.allowed);
  assert.deepEqual(calls.map((c) => c.method), ["IssueChallenge", "Admit", "Authorize"]);
  for (const c of calls) assert.equal(c.timeoutMs, DEFAULT_TIMEOUT_MS);

  calls.length = 0;
  await client.authorize(new Agent(SEED), "tool", { k: 1 }, { timeoutMs: 250 });
  for (const c of calls) assert.equal(c.timeoutMs, 250, `${c.method} lost the override`);
});

test("unary data-plane wrappers default to the 2s deadline and accept an override", async () => {
  const calls: Recorded[] = [];
  const client = new SeamClient(fakeTransport(calls, () => ({})));
  await client.sessionStatus("s");
  await client.getDecision("d", { timeoutMs: 77 });
  assert.equal(calls[0]!.timeoutMs, DEFAULT_TIMEOUT_MS);
  assert.equal(calls[1]!.timeoutMs, 77);
});

// ── Budget default: 0 ⇒ the server owns the default; the client never re-states 32 ───────────────

test("openSession / resumeSession send budget 0 when unspecified (the proto owns the default)", async () => {
  const calls: Recorded[] = [];
  const { handle } = fakeSeam();
  const client = new SeamClient(fakeTransport(calls, handle));
  await client.openSession(new Agent(SEED), { sessionId: "s", participants: ["a", "b"] });
  const open = calls.find((c) => c.method === "OpenSession")!;
  assert.equal(open.input.budget, 0);

  await client.resumeSession("s");
  const resume = calls.find((c) => c.method === "ResumeSession")!;
  assert.equal(resume.input.budget, 0);

  const adminCalls: Recorded[] = [];
  const admin = new SeamAdminClient(fakeTransport(adminCalls, () => ({})));
  await admin.resumeSession("s", "op:approver");
  assert.equal(adminCalls[0]!.input.budget, 0);
});

// ── Ticket refresh: adopt a concurrently-minted ticket, never stampede ───────────────────────────

test("a caller holding a stale ticket ADOPTS the concurrently-refreshed one instead of re-admitting", async () => {
  const calls: Recorded[] = [];
  const seam = fakeSeam();
  const client = new SeamClient(fakeTransport(calls, seam.handle));
  const agent = new Agent(SEED);

  assert.ok((await client.authorize(agent, "t", {})).allowed); // warm: one shared ticket
  assert.equal(seam.state.admits, 1);

  // Mass revocation: both in-flight authorizes will fail on ticket 1, but their rejections are
  // DELIVERED one at a time, so the second caller reaches the refresh path only after the first
  // has already minted ticket 2 — the exact staggering that made the old delete+re-admit stampede.
  seam.state.revoked.add(1);
  seam.state.deferRejections = true;
  const p1 = client.authorize(agent, "t", { k: 1 });
  const p2 = client.authorize(agent, "t", { k: 2 });
  while (seam.state.pending.length < 2) await new Promise((r) => setTimeout(r, 1));

  seam.state.deferRejections = false;
  seam.state.pending.shift()!(); // reject caller 1 → it refreshes (admit #2) and retries
  assert.ok((await p1).allowed);
  assert.equal(seam.state.admits, 2);

  seam.state.pending.shift()!(); // reject caller 2 → it must ADOPT ticket 2, not mint a third
  assert.ok((await p2).allowed);
  assert.equal(
    seam.state.admits,
    2,
    "the second rejected caller re-admitted instead of adopting the fresh ticket — refresh stampede",
  );
});

test("a caller holding the CURRENT (dead) ticket does re-admit", async () => {
  // The other side of the branch — a refresh that never refreshes would retry the rejected ticket.
  const calls: Recorded[] = [];
  const seam = fakeSeam();
  const client = new SeamClient(fakeTransport(calls, seam.handle));
  const agent = new Agent(SEED);
  await client.authorize(agent, "t", {});
  seam.state.revoked.add(1);
  assert.ok((await client.authorize(agent, "t", {})).allowed);
  assert.equal(seam.state.admits, 2);
});

// ── TRANSFORM without a rewrite is a typed protocol violation ────────────────────────────────────

test("a TRANSFORM verdict with no transformed_input throws ProtocolViolationError", async () => {
  const calls: Recorded[] = [];
  const seam = fakeSeam();
  const client = new SeamClient(
    fakeTransport(calls, (method, input) =>
      method === "Authorize"
        ? { verdict: AuthorizeVerdict.TRANSFORM, authorizeId: "az-9" }
        : seam.handle(method, input),
    ),
  );
  await assert.rejects(client.authorize(new Agent(SEED), "t", {}), (e: unknown) => {
    assert.ok(e instanceof ProtocolViolationError, "must be the typed violation, not a bare Error");
    assert.equal((e as ProtocolViolationError).name, "ProtocolViolationError");
    assert.equal((e as ProtocolViolationError).authorizeId, "az-9");
    return true;
  });
});

// ── streamEvents: drain-only ack guard, unbounded default, AbortSignal cancellation ──────────────

test("streamEvents throws eagerly on ack+follow (ack is drain-only per the proto)", () => {
  const admin = new SeamAdminClient(fakeTransport([], () => ({})));
  assert.throws(
    () => admin.streamEvents({ ack: true, follow: true }),
    (e: unknown) => e instanceof InvalidArgumentError && (e as InvalidArgumentError).code === Code.InvalidArgument,
  );
});

test("streamEvents defaults to NO deadline and passes an override through", async () => {
  const calls: Recorded[] = [];
  // eslint-disable-next-line require-yield
  const admin = new SeamAdminClient(
    fakeTransport(calls, () => ({}), async function* () {}),
  );
  for await (const _ of admin.streamEvents()) void _;
  assert.equal(calls[0]!.timeoutMs, undefined, "a finite default would kill a healthy live tail");
  for await (const _ of admin.streamEvents({ timeoutMs: 500 })) void _;
  assert.equal(calls[1]!.timeoutMs, 500);
});

test("streamEvents: aborting the passed AbortSignal terminates a follow-tail", async () => {
  const calls: Recorded[] = [];
  const admin = new SeamAdminClient(
    fakeTransport(calls, () => ({}), async function* (_method, _input, signal) {
      let seq = 0n;
      for (;;) {
        if (signal?.aborted) throw new ConnectError("the operation was canceled", Code.Canceled);
        yield { kind: "AUDIT_ENTRY", seq: seq++ };
        await new Promise((r) => setTimeout(r, 1));
      }
    }),
  );

  const ctl = new AbortController();
  let seen = 0;
  await assert.rejects(
    (async () => {
      for await (const _ of admin.streamEvents({ follow: true, signal: ctl.signal })) {
        if (++seen === 3) ctl.abort();
      }
    })(),
    (e: unknown) =>
      e instanceof SeamRpcError && (e as SeamRpcError).code === Code.Canceled,
  );
  assert.ok(seen >= 3, "the tail must have been live before the abort");
  assert.equal(calls[0]!.signal, ctl.signal, "the caller's signal must reach the transport");
});
