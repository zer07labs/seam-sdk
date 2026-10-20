// Server-free wrapper plumbing over a recording fake Transport: per-call deadlines (data plane 2s,
// management plane 30s, streams unbounded), the SeamAdmin grant/party wrappers, the proto-owned
// budget default (0, never a client-side 32), the coalescing ticket refresh (adopt, don't stampede),
// the TRANSFORM protocol-violation error, and streamEvents' drain-only ack guard + AbortSignal
// cancellation. Mirrors the Python suite's test_lifecycle_and_timeouts / test_ticket_lifecycle.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { create, toBinary } from "@bufbuild/protobuf";
import type {
  DescMessage,
  DescMethodStreaming,
  DescMethodUnary,
  MessageInitShape,
  MessageShape,
} from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import type { StreamResponse, Transport, UnaryResponse } from "@connectrpc/connect";
import { ed25519 } from "@noble/curves/ed25519";

import {
  Agent,
  DEFAULT_TIMEOUT_MS,
  SeamClient,
  UnknownVerdictError,
  type RunDecisionVote,
} from "../src/client.js";
import { jcsCanonicalize, requestSigPayload, toolInputDigest } from "../src/crypto.js";
import { DEFAULT_ADMIN_TIMEOUT_MS, SeamAdminClient } from "../src/admin.js";
import { createIdentityFile, loadIdentityFacts, loadIdentityFile } from "../src/identity.js";
import {
  FailedPreconditionError,
  InvalidArgumentError,
  NotFoundError,
  ProtocolViolationError,
  SeamRpcError,
  UnauthenticatedError,
  UnavailableError,
} from "../src/errors.js";
import {
  ApprovalRequestRequestSchema,
  AuthorizeVerdict,
  BallotChoice,
  BallotRequestSchema,
  CommitRequestSchema,
  EvaluationRequestSchema,
  ObjectionRequestSchema,
  OpenSessionRequestSchema,
  ProposalRequestSchema,
  SessionRefSchema,
  ReportOutcomeRequestSchema,
  VoteRequestSchema,
} from "../gen/seam/api/v1/seam_pb.js";

const SEED = new Uint8Array(32).fill(7);

interface Recorded {
  method: string;
  input: Record<string, unknown>;
  timeoutMs?: number;
  signal?: AbortSignal;
  headers?: HeadersInit;
}

type UnaryHandler = (
  method: string,
  input: Record<string, unknown>,
  headers?: HeadersInit,
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
      headers: HeadersInit | undefined,
      input: MessageInitShape<I>,
    ): Promise<UnaryResponse<I, O>> {
      calls.push({
        method: method.name,
        input: input as Record<string, unknown>,
        timeoutMs,
        signal,
        headers,
      });
      const out = await handle(method.name, input as Record<string, unknown>, headers);
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
  enrollTenant: (a, o) => a.enrollTenant("aid:x", "acme", "ns", undefined, o),
  "enrollTenant[pop]": (a, o) =>
    a.enrollTenant("aid:x", "acme", "ns", new Agent(new Uint8Array(32)).enrolmentProof("acme", "ns"), o),
  listTenants: (a, o) => a.listTenants(o),
  revokeTenant: (a, o) => a.revokeTenant("aid:x", o),
  registerParty: (a, o) => a.registerParty("p", new Uint8Array(32), o),
  removeParty: (a, o) => a.removeParty("p", o),
  placeGrant: (a, o) => a.placeGrant("acme", "from", "to", "op:x", 9999999999999n, o),
  revokeGrant: (a, o) => a.revokeGrant("acme", "from", "to", "op:x", o),
  listGrants: (a, o) => a.listGrants(o),
  resumeSession: (a, o) => a.resumeSession("s", "op:approver", o),
  listLegalHolds: (a, o) => a.listLegalHolds(o),
  placeLegalHold: (a, o) => a.placeLegalHold("d", o),
  releaseLegalHold: (a, o) => a.releaseLegalHold("d", o),
  enforceRetention: (a, o) => a.enforceRetention(1n, 2n, 3n, undefined, o),
  auditTrail: (a, o) => a.auditTrail(o),
  reportEventsConsumed: (a, o) => a.reportEventsConsumed(1n, o),
  redriveEvents: (a, o) => a.redriveEvents("acme", 1n, o),
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

test("placeGrant / revokeGrant / listGrants / removeParty / revokeTenant wrap SeamAdmin verbatim", async () => {
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

  await admin.revokeTenant("aid:x");
  assert.equal(calls[4]!.method, "RevokeTenant");
  assert.deepEqual(calls[4]!.input, { subjectAid: "aid:x" });
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
  await client.getEscalation("az-1", { timeoutMs: 88 });
  assert.equal(calls[0]!.timeoutMs, DEFAULT_TIMEOUT_MS);
  assert.equal(calls[1]!.timeoutMs, 77);
  assert.equal(calls[2]!.method, "GetEscalation");
  assert.equal(calls[2]!.input.authorizeId, "az-1");
  assert.equal(calls[2]!.timeoutMs, 88);
});

// ── The per-request credential (`seam-request-call-v1`, #508): every target verb ─────────────────

const CREDENTIAL_TICKET = new Uint8Array([1, 2, 3, 9, 9]);

/** A minimal handler covering only what `openSession`'s own admission handshake needs
 * (`IssueChallenge`/`Admit`, for the unrelated acting `agent`) — every other RPC just gets `{}`. */
function minimalHandle(method: string): unknown {
  if (method === "IssueChallenge") return { receiverAid: "aid:pubkey:ed25519:recv", nonce: "n1" };
  if (method === "Admit") return { ticket: new Uint8Array([9]), expiresAtMs: BigInt(Date.now() + 60_000) };
  return {};
}

/** Seeds the credential's OWN ticket cache directly — `credentialHeaders` reuses whatever
 * `authorize()`/`admit()` would for this agent, so this is the network-free way to give it one. */
function seedCredentialTicket(client: SeamClient, aid: string): void {
  (
    client as unknown as {
      tickets: Map<string, { ticket: Uint8Array; refreshAtMs: number }>;
    }
  ).tickets.set(aid, { ticket: CREDENTIAL_TICKET, refreshAtMs: Date.now() + 60_000 });
}

interface CredentialSpec {
  rpc: string;
  bodyless: boolean;
  resourceId?: string;
  schema?: Parameters<typeof create>[0];
  invoke: (c: SeamClient, cred: Agent | undefined) => Promise<unknown>;
}

/** The same 16 verbs as `test_credential_wiring.py`'s `CALLS` table — rpc full name, bodyless vs.
 * bodied (and its request schema, to recompute the expected digest independently), and how to
 * invoke it with/without `credential`. */
const CREDENTIAL_CALLS: Record<string, CredentialSpec> = {
  OpenSession: {
    rpc: "/seam.api.v1.SeamCoordination/OpenSession",
    bodyless: false,
    schema: OpenSessionRequestSchema,
    invoke: (c, cred) =>
      c.openSession(new Agent(SEED), { sessionId: "s1", participants: ["a", "b"], credential: cred }),
  },
  SubmitProposal: {
    rpc: "/seam.api.v1.SeamCoordination/SubmitProposal",
    bodyless: false,
    schema: ProposalRequestSchema,
    invoke: (c, cred) => c.submitProposal("s1", "a", "p1", "opt", undefined, { credential: cred }),
  },
  SubmitVote: {
    rpc: "/seam.api.v1.SeamCoordination/SubmitVote",
    bodyless: false,
    schema: VoteRequestSchema,
    invoke: (c, cred) => c.submitVote("s1", "a", "p1", "yes", undefined, { credential: cred }),
  },
  ReportOutcome: {
    rpc: "/seam.api.v1.SeamCoordination/ReportOutcome",
    bodyless: false,
    schema: ReportOutcomeRequestSchema,
    invoke: (c, cred) => c.reportOutcome("d1", true, { idempotencyKey: "review-77", credential: cred }),
  },
  SubmitEvaluation: {
    rpc: "/seam.api.v1.SeamCoordination/SubmitEvaluation",
    bodyless: false,
    schema: EvaluationRequestSchema,
    invoke: (c, cred) => c.submitEvaluation("s1", "a", "p1", "APPROVE", { credential: cred }),
  },
  SubmitObjection: {
    rpc: "/seam.api.v1.SeamCoordination/SubmitObjection",
    bodyless: false,
    schema: ObjectionRequestSchema,
    invoke: (c, cred) => c.submitObjection("s1", "a", "p1", "reason", { credential: cred }),
  },
  SubmitCommit: {
    rpc: "/seam.api.v1.SeamCoordination/SubmitCommit",
    bodyless: false,
    schema: CommitRequestSchema,
    invoke: (c, cred) => c.submitCommit("s1", "c1", "approve", undefined, { credential: cred }),
  },
  SubmitApprovalRequest: {
    rpc: "/seam.api.v1.SeamCoordination/SubmitApprovalRequest",
    bodyless: false,
    schema: ApprovalRequestRequestSchema,
    invoke: (c, cred) =>
      c.submitApprovalRequest("s1", "a", "r1", "approve", 2, undefined, { credential: cred }),
  },
  SubmitBallot: {
    rpc: "/seam.api.v1.SeamCoordination/SubmitBallot",
    bodyless: false,
    schema: BallotRequestSchema,
    invoke: (c, cred) =>
      c.submitBallot("s1", "a", "r1", BallotChoice.APPROVE, "", undefined, { credential: cred }),
  },
  CancelSession: {
    rpc: "/seam.api.v1.SeamCoordination/CancelSession",
    bodyless: false,
    schema: SessionRefSchema,
    invoke: (c, cred) => c.cancelSession("s1", { credential: cred }),
  },
  ExpireSession: {
    rpc: "/seam.api.v1.SeamCoordination/ExpireSession",
    bodyless: false,
    schema: SessionRefSchema,
    invoke: (c, cred) => c.expireSession("s1", { credential: cred }),
  },
  SessionStatus: {
    rpc: "/seam.api.v1.SeamCoordination/SessionStatus",
    bodyless: true,
    resourceId: "s1",
    invoke: (c, cred) => c.sessionStatus("s1", { credential: cred }),
  },
  GetDecision: {
    rpc: "/seam.api.v1.SeamCoordination/GetDecision",
    bodyless: true,
    resourceId: "d1",
    invoke: (c, cred) => c.getDecision("d1", { credential: cred }),
  },
  ReplayDecision: {
    rpc: "/seam.api.v1.SeamCoordination/ReplayDecision",
    bodyless: true,
    resourceId: "d1",
    invoke: (c, cred) => c.replayDecision("d1", { credential: cred }),
  },
  GetEscalation: {
    rpc: "/seam.api.v1.SeamAuthorization/GetEscalation",
    bodyless: true,
    resourceId: "az-1",
    invoke: (c, cred) => c.getEscalation("az-1", { credential: cred }),
  },
  GetCommitmentProof: {
    rpc: "/seam.api.v1.SeamCoordination/GetCommitmentProof",
    bodyless: true,
    resourceId: "d1",
    invoke: (c, cred) => c.getCommitmentProof("d1", { credential: cred }),
  },
};

function expectedBodyDigest(spec: CredentialSpec, recordedInput: Record<string, unknown>): string {
  if (spec.bodyless || !spec.schema) return "";
  const msg = create(spec.schema, recordedInput as MessageInitShape<typeof spec.schema>);
  return toolInputDigest(toBinary(spec.schema, msg));
}

test("credential=: omitted sends no headers, on every one of the 16 target verbs", async () => {
  for (const [name, spec] of Object.entries(CREDENTIAL_CALLS)) {
    const calls: Recorded[] = [];
    const client = new SeamClient(fakeTransport(calls, minimalHandle));
    await spec.invoke(client, undefined);
    const call = calls.find((c) => c.method === name);
    assert.ok(call, `${name}: RPC not observed`);
    assert.equal(call!.headers, undefined, `${name}: headers sent despite no credential`);
  }
});

test("credential=: attaches a ticket + signature that verifies, on every one of the 16 target verbs", async () => {
  const credential = new Agent(new Uint8Array(32).fill(3));
  const pubkey = ed25519.getPublicKey(credential.seed);
  for (const [name, spec] of Object.entries(CREDENTIAL_CALLS)) {
    const calls: Recorded[] = [];
    const client = new SeamClient(fakeTransport(calls, minimalHandle));
    seedCredentialTicket(client, credential.aid);
    await spec.invoke(client, credential);
    const call = calls.find((c) => c.method === name);
    assert.ok(call, `${name}: RPC not observed`);
    const headers = call!.headers as Record<string, string>;
    assert.deepEqual(Object.keys(headers).sort(), ["x-seam-call-sig-bin", "x-seam-ticket-bin"]);
    assert.equal(
      Buffer.from(headers["x-seam-ticket-bin"]!, "base64").toString("hex"),
      Buffer.from(CREDENTIAL_TICKET).toString("hex"),
      `${name}: wrong ticket on the wire`,
    );

    const bodyDigest = expectedBodyDigest(spec, call!.input);
    const expectedPayload = requestSigPayload(CREDENTIAL_TICKET, spec.rpc, spec.resourceId ?? "", bodyDigest);
    const sig = Buffer.from(headers["x-seam-call-sig-bin"]!, "base64");
    assert.ok(ed25519.verify(sig, expectedPayload, pubkey), `${name}: signature does not verify`);
  }
});

test("credential=: a different credential's key does not verify the signature", async () => {
  const credA = new Agent(new Uint8Array(32).fill(3));
  const credB = new Agent(new Uint8Array(32).fill(5));
  for (const name of ["SubmitVote", "GetDecision"]) {
    const spec = CREDENTIAL_CALLS[name]!;
    const calls: Recorded[] = [];
    const client = new SeamClient(fakeTransport(calls, minimalHandle));
    seedCredentialTicket(client, credA.aid);
    await spec.invoke(client, credA);
    const call = calls.find((c) => c.method === name)!;
    const headers = call.headers as Record<string, string>;
    const sig = Buffer.from(headers["x-seam-call-sig-bin"]!, "base64");
    const bodyDigest = expectedBodyDigest(spec, call.input);
    const payload = requestSigPayload(CREDENTIAL_TICKET, spec.rpc, spec.resourceId ?? "", bodyDigest);
    assert.equal(
      ed25519.verify(sig, payload, ed25519.getPublicKey(credB.seed)),
      false,
      `${name}: signature verified against the WRONG credential's key`,
    );
  }
});

// ── A client bound to an Agent (seam-sdk#202): the bound agent is the default credential ─────────

function assertSignedBy(name: string, spec: CredentialSpec, call: Recorded, signer: Agent): void {
  const headers = call.headers as Record<string, string> | undefined;
  assert.ok(headers, `${name}: no headers on a bound client`);
  const sig = Buffer.from(headers!["x-seam-call-sig-bin"]!, "base64");
  const payload = requestSigPayload(
    CREDENTIAL_TICKET,
    spec.rpc,
    spec.resourceId ?? "",
    expectedBodyDigest(spec, call.input),
  );
  assert.ok(ed25519.verify(sig, payload, ed25519.getPublicKey(signer.seed)), `${name}: wrong signer`);
}

test("bound agent: every target verb attaches its credential, and an explicit credential wins", async () => {
  const bound = new Agent(new Uint8Array(32).fill(3));
  const explicit = new Agent(new Uint8Array(32).fill(5));
  for (const [name, spec] of Object.entries(CREDENTIAL_CALLS)) {
    const calls: Recorded[] = [];
    const client = new SeamClient(fakeTransport(calls, minimalHandle), undefined, { agent: bound });
    seedCredentialTicket(client, bound.aid);
    seedCredentialTicket(client, explicit.aid);

    await spec.invoke(client, undefined);
    assertSignedBy(name, spec, calls.find((c) => c.method === name)!, bound);

    calls.length = 0;
    await spec.invoke(client, explicit);
    const call = calls.find((c) => c.method === name)!;
    assertSignedBy(name, spec, call, explicit);
    const sig = Buffer.from((call.headers as Record<string, string>)["x-seam-call-sig-bin"]!, "base64");
    const payload = requestSigPayload(
      CREDENTIAL_TICKET,
      spec.rpc,
      spec.resourceId ?? "",
      expectedBodyDigest(spec, call.input),
    );
    assert.equal(ed25519.verify(sig, payload, ed25519.getPublicKey(bound.seed)), false, `${name}: bound key used`);
  }
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

// ── Verdict decoding: every named verdict round-trips; an unknown one never implicitly allows ────

test("authorize decodes every named verdict, with TRANSFORM carrying transformedInput", async () => {
  const seam = fakeSeam();
  const cases: [AuthorizeVerdict, "ALLOW" | "DENY" | "TRANSFORM" | "ESCALATE"][] = [
    [AuthorizeVerdict.ALLOW, "ALLOW"],
    [AuthorizeVerdict.DENY, "DENY"],
    [AuthorizeVerdict.TRANSFORM, "TRANSFORM"],
    [AuthorizeVerdict.ESCALATE, "ESCALATE"],
  ];
  for (const [wire, name] of cases) {
    const client = new SeamClient(
      fakeTransport([], (method, input) =>
        method === "Authorize"
          ? {
              verdict: wire,
              authorizeId: "01AUTHZ",
              policyVersion: "policy-v1",
              transformedInput:
                wire === AuthorizeVerdict.TRANSFORM
                  ? new TextEncoder().encode('{"redacted":true}')
                  : new Uint8Array(0),
            }
          : seam.handle(method, input),
      ),
    );
    const r = await client.authorize(new Agent(SEED), "t", {});
    assert.equal(r.verdict, name);
    assert.equal(r.authorizeId, "01AUTHZ");
    assert.equal(r.policyVersion, "policy-v1");
    assert.equal(r.allowed, name === "ALLOW");
    if (name === "TRANSFORM") {
      assert.deepEqual(r.transformedInput, new TextEncoder().encode('{"redacted":true}'));
    } else {
      assert.equal(r.transformedInput, undefined);
    }
  }
});

test("an unrecognized verdict (incl. UNSPECIFIED) throws UnknownVerdictError, never an implicit allow", async () => {
  const seam = fakeSeam();
  const client = new SeamClient(
    fakeTransport([], (method, input) =>
      method === "Authorize"
        ? { verdict: AuthorizeVerdict.AUTHORIZE_VERDICT_UNSPECIFIED, authorizeId: "az-0" }
        : seam.handle(method, input),
    ),
  );
  await assert.rejects(client.authorize(new Agent(SEED), "t", {}), (e: unknown) => {
    assert.ok(e instanceof UnknownVerdictError, "must be the typed error, not an implicit allow");
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

test("authorize(canonical) is byte-identical to authorize(toolInput), and derives nothing", async () => {
  // The TypeScript half of seam-sdk#60 ask 1. `canonical` must be a way to AVOID a derivation, not a
  // second implementation of one — so the two forms are compared request-for-request rather than
  // just both being asserted to work.
  const toolInput = { zeta: 1, alpha: [true, null, "x"], n: 2.5 };
  const canonical = jcsCanonicalize(toolInput);

  const byObject: Recorded[] = [];
  await new SeamClient(fakeTransport(byObject, fakeSeam().handle)).authorize(new Agent(SEED), "t", toolInput);
  const byBytes: Recorded[] = [];
  await new SeamClient(fakeTransport(byBytes, fakeSeam().handle)).authorize(new Agent(SEED), "t", undefined, {
    canonical,
  });

  const a = byObject.find((c) => c.method === "Authorize")!.input;
  const b = byBytes.find((c) => c.method === "Authorize")!.input;
  assert.equal(a.toolInputDigest, b.toolInputDigest);
  assert.deepEqual(a.toolInput, b.toolInput);
});

test("authorize rejects toolInput and canonical together rather than picking one", async () => {
  // Silently preferring either is the exact shape of failure the option exists to remove: a
  // disagreement resolved quietly, inside a signed digest, where nobody looks.
  const client = new SeamClient(fakeTransport([], fakeSeam().handle));
  await assert.rejects(
    () => client.authorize(new Agent(SEED), "t", { a: 1 }, { canonical: jcsCanonicalize({ a: 1 }) }),
    /mutually exclusive/,
  );
  await assert.rejects(
    () => client.authorize(new Agent(SEED), "t", undefined, { canonical: new Uint8Array(0) }),
    /empty/,
  );
});

test("listLegalHolds keeps an empty tenant distinct from no filter", async () => {
  // `tenant: ""` filters the reserved legacy tenant; omitted is no filter at all. Proto3 `optional`
  // tells them apart on the wire, so the wrapper must pass each filter only when the caller set it.
  const calls: Recorded[] = [];
  const admin = new SeamAdminClient(fakeTransport(calls, () => ({ legalHolds: [] })));
  await admin.listLegalHolds();
  await admin.listLegalHolds({ tenant: "", cursor: "dec:9", limit: 5 });
  const [unfiltered, filtered] = calls.map((c) => c.input);
  assert.equal(unfiltered.tenant, undefined);
  assert.equal(unfiltered.cursor, undefined);
  assert.equal(unfiltered.limit, undefined);
  assert.equal(filtered.tenant, "");
  assert.equal(filtered.cursor, "dec:9");
  assert.equal(filtered.limit, 5);
});

test("place/releaseLegalHold send x-seam-tenant only when a tenant is given (runtime #1037)", async () => {
  const calls: Recorded[] = [];
  const admin = new SeamAdminClient(fakeTransport(calls, () => ({})));
  await admin.placeLegalHold("dec:1");
  await admin.releaseLegalHold("dec:1");
  await admin.placeLegalHold("dec:pre", { tenant: "acme" });
  await admin.releaseLegalHold("dec:pre", { tenant: "acme", timeoutMs: 5 });
  await admin.placeLegalHold("dec:pre", { tenant: "" });
  assert.deepEqual(
    calls.map((c) => [c.method, c.input.decisionId]),
    [
      ["PlaceLegalHold", "dec:1"],
      ["ReleaseLegalHold", "dec:1"],
      ["PlaceLegalHold", "dec:pre"],
      ["ReleaseLegalHold", "dec:pre"],
      ["PlaceLegalHold", "dec:pre"],
    ],
  );
  const tenantOf = (c: Recorded) =>
    c.headers === undefined ? undefined : new Headers(c.headers).get("x-seam-tenant");
  // Omitted: no headers at all — identical to the pre-#1037 call.
  assert.equal(calls[0]!.headers, undefined);
  assert.equal(calls[1]!.headers, undefined);
  assert.equal(tenantOf(calls[2]!), "acme");
  assert.equal(tenantOf(calls[3]!), "acme");
  assert.equal(calls[3]!.timeoutMs, 5);
  // Presence, not truthiness: "" is sent for the runtime to refuse as present-but-empty.
  assert.equal(tenantOf(calls[4]!), "");
});

test("reportOutcome sends the idempotency key and refuses an invalid one before any RPC", async () => {
  const calls: Recorded[] = [];
  const client = new SeamClient(fakeTransport(calls, () => ({ recorded: true })));
  await client.reportOutcome("d1", true, { idempotencyKey: "review-77", verifiedBy: "qa" });
  assert.equal(calls[0]!.input.idempotencyKey, "review-77");
  assert.equal(calls[0]!.input.verifiedBy, "qa");
  await client.reportOutcome("d1", false, { idempotencyKey: " ~" + "x".repeat(126) });

  calls.length = 0;
  for (const bad of ["", "x".repeat(129), "tab\there", "naïve", "line\n", "\x7f"]) {
    await assert.rejects(
      client.reportOutcome("d1", true, { idempotencyKey: bad }),
      (e: unknown) => e instanceof InvalidArgumentError && /idempotencyKey/.test(String(e)),
      `accepted invalid key ${JSON.stringify(bad)}`,
    );
  }
  assert.equal(calls.length, 0, "an invalid key must never reach the wire");
});

test("submitVote carries the vote reason (#207), and sends empty when omitted", async () => {
  const calls: Recorded[] = [];
  const client = new SeamClient(fakeTransport(calls, () => ({})));
  await client.submitVote("s1", "a", "p1", "no", undefined, { reason: "exceeds the approved budget" });
  await client.submitVote("s1", "a", "p1", "yes");
  assert.equal(calls[0]!.input.reason, "exceeds the approved budget");
  assert.equal(calls[1]!.input.reason, "");
});

test("runDecision carries per-vote reasons (seam-aegis#119): pairs and triples mix, a pair sends empty", async () => {
  const calls: Recorded[] = [];
  const { handle } = fakeSeam();
  const client = new SeamClient(fakeTransport(calls, handle));
  await client.runDecision(new Agent(SEED), "s", ["a", "b", "c"], [
    ["a", "APPROVE", "within the approved budget"],
    ["b", "REJECT"],
    ["c", "ABSTAIN", ""],
  ]);
  const rd = calls.find((c) => c.method === "RunDecision")!;
  assert.deepEqual(rd.input.votes, [
    { agent: "a", value: "APPROVE", reason: "within the approved budget" },
    { agent: "b", value: "REJECT", reason: "" },
    { agent: "c", value: "ABSTAIN", reason: "" },
  ]);
});

test("runDecision refuses a malformed vote before any RPC", async () => {
  const calls: Recorded[] = [];
  const { handle } = fakeSeam();
  const client = new SeamClient(fakeTransport(calls, handle));
  for (const bad of [["a"], ["a", "v", "r", "x"]]) {
    await assert.rejects(
      client.runDecision(new Agent(SEED), "s", ["a"], [["a", "y"], bad as unknown as RunDecisionVote]),
      (e: unknown) => e instanceof TypeError && /votes\[1\]/.test(String(e)),
    );
  }
  assert.equal(calls.length, 0, "no RPC at all — not even the IssueChallenge handshake");
});

// ── #1176: redriveEvents (DLQ retry by reference) ─────────────────────────────────────────────────

test("redriveEvents sends tenant/fromSeq, and toSeq/eventId only when given; refuses an empty tenant", async () => {
  const calls: Recorded[] = [];
  const admin = new SeamAdminClient(
    fakeTransport(calls, () => ({ outcomes: [{ seq: 7n, status: "redriven", redriveSeq: 99n }] })),
  );
  const out = await admin.redriveEvents("acme", 7n);
  assert.equal(calls[0]!.method, "RedriveEvents");
  const one = calls[0]!.input as { tenant: string; fromSeq: bigint; toSeq?: bigint; eventId?: string };
  assert.equal(one.tenant, "acme");
  assert.equal(one.fromSeq, 7n);
  assert.equal(one.toSeq, undefined);
  assert.equal(one.eventId, undefined);
  assert.equal(out[0]!.status, "redriven");

  await admin.redriveEvents("acme", 7n, { toSeq: 9n });
  await admin.redriveEvents("acme", 7n, { eventId: "ev-1" });
  assert.equal((calls[1]!.input as { toSeq?: bigint }).toSeq, 9n);
  assert.equal((calls[2]!.input as { eventId?: string }).eventId, "ev-1");

  await assert.rejects(admin.redriveEvents("", 7n), (e: unknown) => e instanceof InvalidArgumentError);
  assert.equal(calls.length, 3);
});

// ── Refresh-once on the credentialed reads, reportOutcome and the seven submit* steps (#275) ─────
// Mirrors python/tests/test_credential_refresh.py. Baseline: a pre-seeded live ticket, so "one
// extra admit" is exactly two admission RPCs (IssueChallenge + Admit). Phase 1 added the reads and
// reportOutcome; Phase 2 (D-SUBMIT-RETRY) the seven steps. What the RUNTIME does with a step resend
// (dedupe, the sealed early return, no second debit) is proven live, in integration.test.ts.

const SUBMITS = [
  "SubmitProposal",
  "SubmitVote",
  "SubmitEvaluation",
  "SubmitObjection",
  "SubmitCommit",
  "SubmitApprovalRequest",
  "SubmitBallot",
] as const;
const REFRESHING = [
  "SessionStatus",
  "GetDecision",
  "ReplayDecision",
  "GetCommitmentProof",
  "GetEscalation",
  "ReportOutcome",
  ...SUBMITS,
] as const;
const EXCLUDED = ["OpenSession", "CancelSession", "ExpireSession"] as const;
const REFRESH_WRITES = Object.keys(CREDENTIAL_CALLS).filter(
  (n) => !(REFRESHING as readonly string[]).includes(n),
);

/** A scripted wire for the credential path: `reject[method]` refuses that verb UNAUTHENTICATED that
 * many times; `fail[method]` throws the given error on every call of it. Admit mints `[100 + n]`. */
function refreshWire() {
  const state = {
    admits: 0,
    reject: {} as Record<string, number>,
    fail: {} as Record<string, Error>,
  };
  const handle: UnaryHandler = (method) => {
    const err = state.fail[method];
    if (err) throw err;
    if (method === "IssueChallenge") return { receiverAid: "aid:pubkey:ed25519:recv", nonce: "n1" };
    if (method === "Admit") {
      state.admits += 1;
      return { ticket: new Uint8Array([100 + state.admits]), expiresAtMs: BigInt(Date.now() + 60_000) };
    }
    if ((state.reject[method] ?? 0) > 0) {
      state.reject[method]! -= 1;
      throw new UnauthenticatedError("ticket rejected", Code.Unauthenticated);
    }
    if (method === "ReportOutcome") return { recorded: true };
    return {};
  };
  return { state, handle };
}

const ADMISSION_RPCS = new Set(["IssueChallenge", "Admit"]);
const admissionCount = (calls: Recorded[]) => calls.filter((c) => ADMISSION_RPCS.has(c.method)).length;
const ticketHex = (call: Recorded) =>
  Buffer.from((call.headers as Record<string, string>)["x-seam-ticket-bin"]!, "base64").toString("hex");

test("#275: each credentialed read, reportOutcome and submit* step refreshes a rejected ticket once and recovers", async () => {
  const cred = new Agent(new Uint8Array(32).fill(3));
  for (const name of REFRESHING) {
    const calls: Recorded[] = [];
    const wire = refreshWire();
    wire.state.reject[name] = 1;
    const client = new SeamClient(fakeTransport(calls, wire.handle));
    seedCredentialTicket(client, cred.aid);
    const out = await CREDENTIAL_CALLS[name]!.invoke(client, cred);
    if (name === "ReportOutcome") assert.equal(out, true);
    const sent = calls.filter((c) => c.method === name);
    assert.equal(sent.length, 2, `${name}: exactly one retry`);
    assert.equal(admissionCount(calls), 2, `${name}: exactly one extra admit`);
    assert.equal(ticketHex(sent[0]!), Buffer.from(CREDENTIAL_TICKET).toString("hex"));
    assert.equal(ticketHex(sent[1]!), "65", `${name}: the retry must carry the NEW ticket`);
  }
});

test("#275: a second rejection propagates UnauthenticatedError after exactly two sends", async () => {
  const cred = new Agent(new Uint8Array(32).fill(3));
  for (const name of REFRESHING) {
    const calls: Recorded[] = [];
    const wire = refreshWire();
    wire.state.reject[name] = 2;
    const client = new SeamClient(fakeTransport(calls, wire.handle));
    seedCredentialTicket(client, cred.aid);
    await assert.rejects(CREDENTIAL_CALLS[name]!.invoke(client, cred), UnauthenticatedError);
    assert.equal(calls.filter((c) => c.method === name).length, 2, `${name}: looped`);
    assert.equal(admissionCount(calls), 2);
  }
});

test("#275: no credential, no bound agent — one send, no admission, no retry", async () => {
  for (const name of REFRESHING) {
    const calls: Recorded[] = [];
    const wire = refreshWire();
    wire.state.reject[name] = 1;
    const client = new SeamClient(fakeTransport(calls, wire.handle));
    await assert.rejects(CREDENTIAL_CALLS[name]!.invoke(client, undefined), UnauthenticatedError);
    assert.equal(calls.filter((c) => c.method === name).length, 1, name);
    assert.equal(admissionCount(calls), 0, name);
  }
});

test("#275: the retry is re-signed under the new ticket over the identical body", async () => {
  const cred = new Agent(new Uint8Array(32).fill(3));
  const pubkey = ed25519.getPublicKey(cred.seed);
  for (const name of REFRESHING) {
    const spec = CREDENTIAL_CALLS[name]!;
    const calls: Recorded[] = [];
    const wire = refreshWire();
    wire.state.reject[name] = 1;
    const client = new SeamClient(fakeTransport(calls, wire.handle));
    seedCredentialTicket(client, cred.aid);
    await spec.invoke(client, cred);
    const [first, retry] = calls.filter((c) => c.method === name) as [Recorded, Recorded];
    const digest = expectedBodyDigest(spec, retry.input);
    assert.equal(expectedBodyDigest(spec, first.input), digest, `${name}: body changed on retry`);
    const sig = Buffer.from((retry.headers as Record<string, string>)["x-seam-call-sig-bin"]!, "base64");
    const res = spec.resourceId ?? "";
    assert.ok(ed25519.verify(sig, requestSigPayload(new Uint8Array([101]), spec.rpc, res, digest), pubkey));
    assert.equal(
      ed25519.verify(sig, requestSigPayload(CREDENTIAL_TICKET, spec.rpc, res, digest), pubkey),
      false,
      `${name}: the retry's signature still binds the OLD ticket`,
    );
  }
});

test("#275: reportOutcome resends the byte-identical request (idempotency key included)", async () => {
  const cred = new Agent(new Uint8Array(32).fill(3));
  const calls: Recorded[] = [];
  const wire = refreshWire();
  wire.state.reject.ReportOutcome = 1;
  const client = new SeamClient(fakeTransport(calls, wire.handle));
  seedCredentialTicket(client, cred.aid);
  assert.equal(
    await client.reportOutcome("d1", false, { idempotencyKey: "review-77", credential: cred }),
    true,
  );
  const [a, b] = calls.filter((c) => c.method === "ReportOutcome") as [Recorded, Recorded];
  const bytes = (r: Recorded) =>
    Buffer.from(
      toBinary(
        ReportOutcomeRequestSchema,
        create(ReportOutcomeRequestSchema, r.input as MessageInitShape<typeof ReportOutcomeRequestSchema>),
      ),
    ).toString("hex");
  assert.equal(bytes(a), bytes(b));
  assert.equal(b.input.idempotencyKey, "review-77");
});

test("#275: a non-UNAUTHENTICATED error is never retried and never touches the ticket", async () => {
  const cred = new Agent(new Uint8Array(32).fill(3));
  const calls: Recorded[] = [];
  const wire = refreshWire();
  wire.state.fail.GetDecision = new NotFoundError("no such decision", Code.NotFound);
  const client = new SeamClient(fakeTransport(calls, wire.handle));
  seedCredentialTicket(client, cred.aid);
  await assert.rejects(client.getDecision("d1", { credential: cred }), NotFoundError);
  assert.equal(calls.filter((c) => c.method === "GetDecision").length, 1);
  assert.equal(admissionCount(calls), 0);
});

test("#275: a refused refresh admission propagates typed, once, and nothing is resent", async () => {
  const cred = new Agent(new Uint8Array(32).fill(3));
  const calls: Recorded[] = [];
  const wire = refreshWire();
  wire.state.reject.SessionStatus = 1;
  wire.state.fail.IssueChallenge = new UnavailableError("CHALLENGE_REFUSED", Code.Unavailable);
  const client = new SeamClient(fakeTransport(calls, wire.handle));
  seedCredentialTicket(client, cred.aid);
  await assert.rejects(client.sessionStatus("s1", { credential: cred }), UnavailableError);
  assert.equal(calls.filter((c) => c.method === "SessionStatus").length, 1);
  assert.equal(calls.filter((c) => c.method === "IssueChallenge").length, 1, "refresh looped");
});

test("#275: the three excluded writes are unchanged — one send on UNAUTHENTICATED, no re-admit", async () => {
  // D-WRITES-EXCLUDED, narrowed from ten in Phase 2: everything not retried is exactly these three.
  assert.deepEqual([...REFRESH_WRITES].sort(), [...EXCLUDED].sort());
  const cred = new Agent(new Uint8Array(32).fill(3));
  for (const name of REFRESH_WRITES) {
    const calls: Recorded[] = [];
    const wire = refreshWire();
    wire.state.reject[name] = 1;
    const client = new SeamClient(fakeTransport(calls, wire.handle));
    seedCredentialTicket(client, cred.aid);
    await assert.rejects(CREDENTIAL_CALLS[name]!.invoke(client, cred), UnauthenticatedError);
    assert.equal(calls.filter((c) => c.method === name).length, 1, `${name} was retried`);
    // openSession presents the unrelated acting agent (IssueChallenge only); none may Admit.
    assert.equal(wire.state.admits, 0, `${name} re-admitted`);
  }
});

// ── Phase 2 (D-SUBMIT-RETRY): the seven steps ───────────────────────────────────────────────────

/** Each step's request schema, to compare the two attempts' serialized bytes. */
const SUBMIT_SCHEMAS = {
  SubmitProposal: ProposalRequestSchema,
  SubmitVote: VoteRequestSchema,
  SubmitEvaluation: EvaluationRequestSchema,
  SubmitObjection: ObjectionRequestSchema,
  SubmitCommit: CommitRequestSchema,
  SubmitApprovalRequest: ApprovalRequestRequestSchema,
  SubmitBallot: BallotRequestSchema,
} as const;

test("#275 P2: each submit* resends a byte-identical body under a different call signature", async () => {
  const cred = new Agent(new Uint8Array(32).fill(3));
  for (const name of SUBMITS) {
    const schema = SUBMIT_SCHEMAS[name];
    const calls: Recorded[] = [];
    const wire = refreshWire();
    wire.state.reject[name] = 1;
    const client = new SeamClient(fakeTransport(calls, wire.handle));
    seedCredentialTicket(client, cred.aid);
    await CREDENTIAL_CALLS[name]!.invoke(client, cred);
    const [a, b] = calls.filter((c) => c.method === name) as [Recorded, Recorded];
    const bytes = (r: Recorded) =>
      Buffer.from(
        toBinary(schema as DescMessage, create(schema as DescMessage, r.input as never)),
      ).toString("hex");
    assert.equal(bytes(a), bytes(b), `${name}: the body changed on the resend`);
    const sig = (r: Recorded) => (r.headers as Record<string, string>)["x-seam-call-sig-bin"];
    assert.notEqual(sig(a), sig(b), `${name}: the resend reused the rejected signature`);
  }
});

test("#275 P2: submitVote carries usage unchanged on the resend", async () => {
  const cred = new Agent(new Uint8Array(32).fill(3));
  const calls: Recorded[] = [];
  const wire = refreshWire();
  wire.state.reject.SubmitVote = 1;
  const client = new SeamClient(fakeTransport(calls, wire.handle));
  seedCredentialTicket(client, cred.aid);
  await client.submitVote("s1", "a", "p1", "APPROVE", { tokens: 600n, costMicros: 7n }, { credential: cred });
  const [a, b] = calls.filter((c) => c.method === "SubmitVote") as [Recorded, Recorded];
  assert.deepEqual(a.input.usage, b.input.usage);
  assert.equal((b.input.usage as { tokens: bigint }).tokens, 600n);
});

test("#275 P2: a refused refresh admission on a submit* step propagates typed and nothing is resent", async () => {
  const cred = new Agent(new Uint8Array(32).fill(3));
  for (const name of SUBMITS) {
    const calls: Recorded[] = [];
    const wire = refreshWire();
    wire.state.reject[name] = 1;
    wire.state.fail.IssueChallenge = new UnavailableError("CHALLENGE_REFUSED", Code.Unavailable);
    const client = new SeamClient(fakeTransport(calls, wire.handle));
    seedCredentialTicket(client, cred.aid);
    await assert.rejects(CREDENTIAL_CALLS[name]!.invoke(client, cred), UnavailableError);
    assert.equal(calls.filter((c) => c.method === name).length, 1, `${name}: resent after a failed refresh`);
    assert.equal(calls.filter((c) => c.method === "IssueChallenge").length, 1, `${name}: refresh looped`);
  }
});

test("#275 P2: the runtime's sealed answer to a resend is passed through as success, untouched", async () => {
  const cred = new Agent(new Uint8Array(32).fill(3));
  const calls: Recorded[] = [];
  const wire = refreshWire();
  wire.state.reject.SubmitVote = 1;
  const handle: UnaryHandler = (method, input, headers) => {
    const out = wire.handle(method, input, headers);
    return method === "SubmitVote" ? { state: "Cancelled", decisionId: "dec-sealed" } : out;
  };
  const client = new SeamClient(fakeTransport(calls, handle));
  seedCredentialTicket(client, cred.aid);
  const step = await client.submitVote("s1", "a", "p1", "APPROVE", undefined, { credential: cred });
  assert.equal(step.decisionId, "dec-sealed");
  assert.equal(step.collectiveOutcome, undefined);
  assert.equal(step.policyEnforcement, undefined);
  assert.equal(calls.filter((c) => c.method === "SubmitVote").length, 2);
});

test("#275 P2: FAILED_PRECONDITION on the resend (a swept session) propagates typed, not retried", async () => {
  const cred = new Agent(new Uint8Array(32).fill(3));
  const calls: Recorded[] = [];
  const wire = refreshWire();
  wire.state.reject.SubmitVote = 1;
  let sends = 0;
  const handle: UnaryHandler = (method, input, headers) => {
    if (method === "SubmitVote" && ++sends === 2) {
      throw new FailedPreconditionError(
        "session s1 expired (sealed by the session sweeper)",
        Code.FailedPrecondition,
      );
    }
    return wire.handle(method, input, headers);
  };
  const client = new SeamClient(fakeTransport(calls, handle));
  seedCredentialTicket(client, cred.aid);
  await assert.rejects(
    client.submitVote("s1", "a", "p1", "APPROVE", undefined, { credential: cred }),
    (e: unknown) => e instanceof FailedPreconditionError && /session sweeper/.test((e as Error).message),
  );
  assert.equal(sends, 2);
});

test("#275 P2: 32 concurrent rejected submit* steps coalesce to ONE re-admit", async () => {
  const N = 32;
  const calls: Recorded[] = [];
  const seam = credentialedSeam();
  const client = new SeamClient(fakeTransport(calls, seam.handle));
  const agent = new Agent(SEED);
  await client.admit(agent);
  assert.equal(seam.state.admits, 1);

  seam.state.revoked.add(1);
  seam.state.deferRejections = true;
  const all = Array.from({ length: N }, (_, i) => CREDENTIAL_CALLS[SUBMITS[i % SUBMITS.length]!]!.invoke(client, agent));
  await waitPending(seam.state, N);
  seam.state.deferRejections = false;
  for (const rej of seam.state.pending.splice(0)) rej();

  const out = (await Promise.all(all)) as { state: string }[];
  assert.ok(out.every((r) => r.state === "Open"));
  assert.equal(seam.state.admits - 1, 1, `${N} rejected steps caused ${seam.state.admits - 1} re-admits`);
  for (const name of SUBMITS) {
    const sent = calls.filter((c) => c.method === name);
    assert.equal(sent.length % 2, 0, `${name}: every rejected step was resent exactly once`);
  }
});

// ── Phase 1 verifier notes ─────────────────────────────────────────────────────────────────────

test("#275: an explicit credential on a bound client refreshes the SIGNER's ticket, not the bound agent's", async () => {
  const bound = new Agent(new Uint8Array(32).fill(5));
  const cred = new Agent(new Uint8Array(32).fill(3));
  const calls: Recorded[] = [];
  const wire = refreshWire();
  wire.state.reject.SessionStatus = 1;
  const client = new SeamClient(fakeTransport(calls, wire.handle), undefined, { agent: bound });
  seedCredentialTicket(client, bound.aid);
  seedCredentialTicket(client, cred.aid);
  await client.sessionStatus("s1", { credential: cred });
  const tickets = (client as unknown as { tickets: Map<string, { ticket: Uint8Array }> }).tickets;
  assert.deepEqual([...tickets.get(cred.aid)!.ticket], [101], "the signer's ticket is the one refreshed");
  assert.deepEqual([...tickets.get(bound.aid)!.ticket], [...CREDENTIAL_TICKET], "the bound agent's ticket is untouched");
});

test("#274 × #275: the bootstrap file's recorded aid is the key a bound client's refresh admits as and re-caches under", async () => {
  // createIdentityFile → loadIdentityFacts gives a seed-free consumer the AID; the full loader's
  // agent, bound to a client, must refresh a rejected ticket under exactly that AID.
  const dir = mkdtempSync(join(tmpdir(), "seam-seam-"));
  try {
    const { path, aid } = createIdentityFile(join(dir, "id.json"), {
      agentId: "ap-clerk",
      tenant: "acme",
      endpoint: "x:1",
    });
    const facts = loadIdentityFacts(path);
    const loaded = loadIdentityFile(path);
    assert.equal(facts.aid, aid);
    assert.equal(loaded.aid, aid);
    for (const name of ["GetDecision", "SubmitVote"] as const) {
      const calls: Recorded[] = [];
      const wire = refreshWire();
      wire.state.reject[name] = 1;
      const client = new SeamClient(fakeTransport(calls, wire.handle), undefined, { agent: loaded.agent });
      seedCredentialTicket(client, facts.aid);
      await CREDENTIAL_CALLS[name]!.invoke(client, undefined);
      assert.equal(calls.filter((c) => c.method === name).length, 2, `${name}: one retry`);
      const admit = calls.find((c) => c.method === "Admit")!;
      const presentation = JSON.parse(new TextDecoder().decode(admit.input.presentationJson as Uint8Array));
      assert.equal(presentation.sender_aid, facts.aid, `${name}: the refresh admitted as the file's AID`);
      const tickets = (client as unknown as { tickets: Map<string, { ticket: Uint8Array }> }).tickets;
      assert.deepEqual([...tickets.keys()], [facts.aid]);
      assert.deepEqual([...tickets.get(facts.aid)!.ticket], [101]);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("#275: retry=false invalidates the rejected ticket, then throws — one send, no admission", async () => {
  const cred = new Agent(new Uint8Array(32).fill(3));
  const calls: Recorded[] = [];
  const wire = refreshWire();
  wire.state.reject.SessionStatus = 1;
  const client = new SeamClient(fakeTransport(calls, wire.handle));
  seedCredentialTicket(client, cred.aid);
  const inner = client as unknown as {
    tickets: Map<string, unknown>;
    coord: { sessionStatus: (i: unknown, o: unknown) => Promise<unknown> };
    credentialedCall: (
      credential: Agent,
      rpc: string,
      resourceId: string,
      opts: undefined,
      send: (headers: Record<string, string> | undefined) => Promise<unknown>,
      body: undefined,
      retry: boolean,
    ) => Promise<unknown>;
  };
  await assert.rejects(
    inner.credentialedCall.call(
      client,
      cred,
      "/seam.api.v1.SeamCoordination/SessionStatus",
      "s1",
      undefined,
      (headers) => inner.coord.sessionStatus({ sessionId: "s1" }, { headers }),
      undefined,
      false,
    ),
    UnauthenticatedError,
  );
  assert.equal(calls.filter((c) => c.method === "SessionStatus").length, 1);
  assert.equal(admissionCount(calls), 0);
  assert.equal(inner.tickets.has(cred.aid), false, "the rejected ticket was invalidated");
});

/** fakeSeam plus credentialed coordination reads that reject a revoked ticket (read from the
 * `x-seam-ticket-bin` header) exactly as its Authorize does — deferral included. */
function credentialedSeam() {
  const seam = fakeSeam();
  const base = seam.handle;
  const handle: UnaryHandler = (method, input, headers) => {
    const step = (SUBMITS as readonly string[]).includes(method);
    if (method !== "SessionStatus" && method !== "GetDecision" && !step) return base(method, input, headers);
    const h = headers as Record<string, string> | undefined;
    const t = h ? Buffer.from(h["x-seam-ticket-bin"]!, "base64")[0]! : -1;
    if (t < 0 || seam.state.revoked.has(t)) {
      const err = () => new UnauthenticatedError("ticket revoked", Code.Unauthenticated);
      if (!seam.state.deferRejections) throw err();
      return new Promise((_res, rej) => seam.state.pending.push(() => rej(err())));
    }
    if (step) return { state: "Open" };
    return method === "SessionStatus" ? { state: "Open" } : { decisionId: input.decisionId };
  };
  return { state: seam.state, handle };
}

async function waitPending(state: { pending: unknown[] }, n: number): Promise<void> {
  while (state.pending.length < n) await new Promise((r) => setTimeout(r, 1));
}

test("#275: 32 concurrent rejected reads coalesce to ONE re-admit", async () => {
  const N = 32;
  const calls: Recorded[] = [];
  const seam = credentialedSeam();
  const client = new SeamClient(fakeTransport(calls, seam.handle));
  const agent = new Agent(SEED);
  await client.admit(agent);
  assert.equal(seam.state.admits, 1);

  seam.state.revoked.add(1);
  seam.state.deferRejections = true;
  const all = Array.from({ length: N }, (_, i) => client.getDecision(`d${i}`, { credential: agent }));
  await waitPending(seam.state, N);
  seam.state.deferRejections = false;
  for (const rej of seam.state.pending.splice(0)) rej();

  const out = await Promise.all(all);
  assert.deepEqual(out.map((r) => r.decisionId), Array.from({ length: N }, (_, i) => `d${i}`));
  assert.equal(seam.state.admits - 1, 1, `${N} rejected reads caused ${seam.state.admits - 1} re-admits`);
});

test("#275: a concurrent authorize and sessionStatus rejection share ONE re-admit", async () => {
  const calls: Recorded[] = [];
  const seam = credentialedSeam();
  const client = new SeamClient(fakeTransport(calls, seam.handle));
  const agent = new Agent(SEED);
  await client.authorize(agent, "t", {});
  assert.equal(seam.state.admits, 1);

  seam.state.revoked.add(1);
  seam.state.deferRejections = true;
  const a = client.authorize(agent, "t", { k: 1 });
  const s = client.sessionStatus("s1", { credential: agent });
  await waitPending(seam.state, 2);
  seam.state.deferRejections = false;
  for (const rej of seam.state.pending.splice(0)) rej();

  assert.ok((await a).allowed);
  assert.equal((await s).state, "Open");
  assert.equal(seam.state.admits, 2, "authorize and the read each paid their own re-admit");
});
