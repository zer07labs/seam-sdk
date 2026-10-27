// `SeamAdminClient.connect(url, { token, dpopKey })` — the management-plane DPoP interceptor (seam-sdk#290).
//
// A raw `node:http2` server taps each stream BEFORE any Connect adapter: it collects the request body,
// strips the 5-byte gRPC frame prefix, and records those bytes and the headers. Each assertion is made
// against the bytes the server RECEIVED; nothing here re-serialises a decoded message.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import http2 from "node:http2";
import type { AddressInfo } from "node:net";
import { test } from "node:test";

import { create, toBinary } from "@bufbuild/protobuf";
import { ed25519 } from "@noble/curves/ed25519";

import { SeamAdminClient } from "../src/admin.js";
import { DpopError, DpopKeyError, OperatorDpopKey } from "../src/dpop.js";
import { SeamRpcError } from "../src/errors.js";
import { SeamEventSchema } from "../gen/seam/event/v1/seam_event_pb.js";
import { SeamEvents } from "../gen/seam/api/v1/seam_pb.js";
import { dpopAuth, onlyMessage } from "../src/dpop_interceptor.js";

const KEY = OperatorDpopKey.fromSeed(new Uint8Array(32).fill(0x42));
const OTHER = OperatorDpopKey.fromSeed(new Uint8Array(32).fill(0x07));

const b64e = (b: Uint8Array | Buffer) => Buffer.from(b).toString("base64url");
const b64d = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));
const sha = (b: Uint8Array) => b64e(createHash("sha256").update(b).digest());

function token(claims: Record<string, unknown>): string {
  const seg = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${seg({ alg: "EdDSA", typ: "JWT" })}.${seg({ sub: "op", ...claims })}.c2ln`;
}
const BOUND = token({ aud: "seam-runtime", cnf: { jkt: KEY.jkt } });

interface Call {
  path: string;
  headers: http2.IncomingHttpHeaders;
  message: Uint8Array;
}

function frame(msg: Uint8Array): Buffer {
  const out = Buffer.alloc(5 + msg.length);
  out.writeUInt32BE(msg.length, 1);
  out.set(msg, 5);
  return out;
}

/** A gRPC server that records every request's raw message bytes and answers each method minimally. */
async function withServer(
  fn: (url: string, calls: Call[]) => Promise<void>,
  opts: { failWith?: number; hold?: boolean } = {},
): Promise<void> {
  const calls: Call[] = [];
  const server = http2.createServer();
  server.on("stream", (stream, headers) => {
    const chunks: Buffer[] = [];
    stream.on("data", (c: Buffer) => chunks.push(c));
    stream.on("end", () => {
      const body = Buffer.concat(chunks);
      assert.equal(body[0], 0, "uncompressed frame");
      const len = body.readUInt32BE(1);
      assert.equal(body.length, 5 + len, "exactly one framed message");
      const path = String(headers[":path"]);
      calls.push({ path, headers, message: new Uint8Array(body.subarray(5)) });
      stream.respond({ ":status": 200, "content-type": "application/grpc+proto" }, { waitForTrailers: true });
      stream.on("wantTrailers", () =>
        stream.sendTrailers(
          opts.failWith === undefined
            ? { "grpc-status": "0" }
            : { "grpc-status": String(opts.failWith), "grpc-message": "injected" },
        ),
      );
      if (opts.hold) {
        // One event, then the stream stays open until the client goes away.
        stream.write(frame(toBinary(SeamEventSchema, create(SeamEventSchema, { seq: 1n }))));
        stream.on("error", () => {});
        return;
      }
      if (opts.failWith === undefined) {
        const reply = path.endsWith("/StreamEvents")
          ? toBinary(SeamEventSchema, create(SeamEventSchema, { seq: 1n }))
          : new Uint8Array();
        stream.end(frame(reply));
      } else {
        stream.end();
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`, calls);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

function checkProof(c: Call, opts: { aud?: string; token?: string } = {}) {
  const tok = opts.token ?? BOUND;
  const aud = opts.aud ?? "seam-runtime";
  assert.equal(c.headers.authorization, `DPoP ${tok}`);
  const proof = String(c.headers.dpop);
  const at = proof.lastIndexOf(".");
  assert.ok(ed25519.verify(b64d(proof.slice(at + 1)), new TextEncoder().encode(proof.slice(0, at)), b64d(KEY.x)));
  const [h, cl] = proof.split(".").slice(0, 2).map((s) => JSON.parse(Buffer.from(s!, "base64url").toString()));
  assert.deepEqual(h, { typ: "dpop+jwt", alg: "EdDSA", jwk: KEY.publicJwk() });
  assert.equal(cl.htm, "POST");
  assert.equal(cl.htu, `grpc://${aud}${c.path}`);
  assert.equal(cl.seam_bd, sha(c.message));
  assert.equal(cl.ath, sha(new TextEncoder().encode(tok)));
  return cl;
}

// ── the proof binds the bytes the server received ───────────────────────────────────────────────

test("enrollTenant: the proof binds the received bytes", () =>
  withServer(async (url, calls) => {
    const admin = SeamAdminClient.connect(url, { token: BOUND, dpopKey: KEY });
    try {
      await admin.enrollTenant("aid:x", "acme", "ns");
    } finally {
      admin.close();
    }
    assert.equal(calls.length, 1);
    assert.ok(calls[0]!.message.length > 0);
    checkProof(calls[0]!);
  }));

test("listTenants: an empty message, one-slash htu", () =>
  withServer(async (url, calls) => {
    const admin = SeamAdminClient.connect(url, { token: BOUND, dpopKey: KEY });
    try {
      await admin.listTenants();
    } finally {
      admin.close();
    }
    assert.equal(calls[0]!.message.length, 0);
    assert.equal(checkProof(calls[0]!).htu, "grpc://seam-runtime/seam.api.v1.SeamAdmin/ListTenants");
  }));

test("streamEvents: the one request message is signed and still sent", () =>
  withServer(async (url, calls) => {
    const admin = SeamAdminClient.connect(url, { token: BOUND, dpopKey: KEY });
    const seqs: bigint[] = [];
    try {
      for await (const ev of admin.streamEvents({ streamId: "s1", fromSeq: 7n })) seqs.push(ev.seq);
    } finally {
      admin.close();
    }
    assert.deepEqual(seqs, [1n]);
    assert.equal(calls[0]!.path, "/seam.api.v1.SeamEvents/StreamEvents");
    assert.ok(calls[0]!.message.length > 0, "streamId and fromSeq reached the wire");
    checkProof(calls[0]!);
  }));

test("aud: from the token, explicit wins, default when absent", async () => {
  const cases: Array<[Record<string, unknown>, string | undefined, string]> = [
    [{ aud: "ops.internal", cnf: { jkt: KEY.jkt } }, undefined, "ops.internal"],
    [{ aud: "seam-runtime", cnf: { jkt: KEY.jkt } }, "cell-7", "cell-7"],
    [{ cnf: { jkt: KEY.jkt } }, undefined, "seam-runtime"],
  ];
  for (const [claims, aud, want] of cases) {
    await withServer(async (url, calls) => {
      const tok = token(claims);
      const admin = SeamAdminClient.connect(url, { token: tok, dpopKey: KEY, ...(aud ? { aud } : {}) });
      try {
        await admin.listTenants();
      } finally {
        admin.close();
      }
      checkProof(calls[0]!, { aud: want, token: tok });
    });
  }
});

test("the clock hook sets iat", () =>
  withServer(async (url, calls) => {
    const admin = SeamAdminClient.connect(url, { token: BOUND, dpopKey: KEY, clock: () => 1234 });
    try {
      await admin.listTenants();
    } finally {
      admin.close();
    }
    assert.equal(checkProof(calls[0]!).iat, 1234);
  }));

// ── every call is freshly signed ────────────────────────────────────────────────────────────────

test("consecutive and concurrent calls carry distinct proofs", () =>
  withServer(async (url, calls) => {
    const admin = SeamAdminClient.connect(url, { token: BOUND, dpopKey: KEY, clock: () => 1 });
    try {
      await admin.listTenants();
      await admin.listTenants();
      await Promise.all(Array.from({ length: 14 }, () => admin.listTenants()));
    } finally {
      admin.close();
    }
    assert.equal(calls.length, 16);
    for (const c of calls) checkProof(c);
    assert.equal(new Set(calls.map((c) => checkProof(c).jti)).size, 16);
  }));

test("a failed call is not resent by the transport", () =>
  withServer(
    async (url, calls) => {
      const admin = SeamAdminClient.connect(url, { token: BOUND, dpopKey: KEY });
      try {
        await assert.rejects(admin.listTenants(), SeamRpcError);
      } finally {
        admin.close();
      }
      assert.equal(calls.length, 1);
    },
    { failWith: 14 },
  ));

test("the tenant header rides alongside DPoP", () =>
  withServer(async (url, calls) => {
    const admin = SeamAdminClient.connect(url, { token: BOUND, dpopKey: KEY });
    try {
      await admin.placeLegalHold("dec:1", { tenant: "acme" });
    } finally {
      admin.close();
    }
    assert.equal(calls[0]!.headers["x-seam-tenant"], "acme");
    checkProof(calls[0]!);
  }));

test("a retried call is re-signed on every attempt", () =>
  withServer(
    async (url, calls) => {
      const admin = SeamAdminClient.connect(url, { token: BOUND, dpopKey: KEY });
      try {
        for (let attempt = 0; attempt < 3; attempt++) {
          await assert.rejects(admin.listTenants(), SeamRpcError);
        }
      } finally {
        admin.close();
      }
      assert.equal(calls.length, 3);
      assert.equal(new Set(calls.map((c) => checkProof(c).jti)).size, 3, "a resent proof would be burned");
    },
    { failWith: 14 },
  ));

test("a stream cancelled mid-flight rejects and is not resent", () =>
  withServer(
    async (url, calls) => {
      const admin = SeamAdminClient.connect(url, { token: BOUND, dpopKey: KEY });
      const ac = new AbortController();
      const seqs: bigint[] = [];
      try {
        await assert.rejects(
          (async () => {
            for await (const ev of admin.streamEvents({ streamId: "s1", follow: true, signal: ac.signal })) {
              seqs.push(ev.seq);
              ac.abort();
            }
          })(),
        );
      } finally {
        admin.close();
      }
      assert.deepEqual(seqs, [1n]);
      assert.equal(calls.length, 1);
      checkProof(calls[0]!);
    },
    { hold: true },
  ));

test("a streaming request with zero or two messages is refused before sending", async () => {
  async function* of(...ms: unknown[]) {
    yield* ms;
  }
  assert.equal(await onlyMessage(of("only")), "only");
  await assert.rejects(onlyMessage(of()), (e: unknown) => e instanceof DpopError && /got none/.test(String(e)));
  await assert.rejects(onlyMessage(of(1, 2)), (e: unknown) => e instanceof DpopError && /more than one/.test(String(e)));

  let reachedNext = false;
  const next = (async () => {
    reachedNext = true;
    return {} as never;
  }) as never;
  const req = (messages: AsyncIterable<unknown>) =>
    ({ stream: true, method: SeamEvents.method.streamEvents, header: new Headers(), message: messages }) as never;
  const interceptor = dpopAuth(BOUND, KEY, "seam-runtime", undefined);
  await assert.rejects(interceptor(next)(req(of())), DpopError);
  await assert.rejects(interceptor(next)(req(of({}, {}))), DpopError);
  assert.equal(reachedNext, false, "a refused stream never reaches the transport");
});

// ── guaranteed-to-fail pairings are refused before any connection ───────────────────────────────

test("misuse is refused with DpopKeyError before connecting", () => {
  const cases: Array<[Record<string, unknown>, RegExp]> = [
    [{ dpopKey: KEY }, /needs token/],
    [{ dpopKey: KEY, token: "" }, /needs token/],
    [{ dpopKey: KEY, token: token({ aud: "seam-runtime" }) }, /not DPoP-bound/],
    [{ dpopKey: OTHER, token: BOUND }, /bound to key/],
    [{ token: BOUND }, /DPoP-bound/],
    [{ dpopKey: KEY, token: token({ aud: ["a", "b"], cnf: { jkt: KEY.jkt } }) }, /not a single string/],
    [{ dpopKey: KEY, token: "not-a-jws" }, /compact JWS/],
    [{ dpopKey: KEY, token: token({ cnf: { jkt: 7 } }) }, /malformed/],
  ];
  // Port 1: nothing listens there, and connect() is lazy — a refusal must come from the checks.
  for (const [opts, match] of cases) {
    assert.throws(() => SeamAdminClient.connect("http://127.0.0.1:1", opts), (e: unknown) => {
      assert.ok(e instanceof DpopKeyError, String(e));
      assert.match((e as Error).message, match);
      return true;
    });
  }
});

test("bad arguments are refused with DpopError", () => {
  const cases: Array<Record<string, unknown>> = [
    { token: "tok", aud: "x" },
    { token: "tok", clock: () => 1 },
    { dpopKey: new Uint8Array(32), token: BOUND },
    { dpopKey: KEY, token: BOUND, aud: "a/b" },
    { dpopKey: KEY, token: BOUND, clock: 5 },
    { dpopKey: KEY, token: BOUND, clock: () => 1.5 },
    { dpopKey: KEY, token: BOUND, clock: () => true },
    { dpopKey: KEY, token: BOUND, clock: () => -1 },
    { dpopKey: KEY, token: token({ aud: "has space", cnf: { jkt: KEY.jkt } }) },
  ];
  for (const opts of cases) {
    assert.throws(() => SeamAdminClient.connect("http://127.0.0.1:1", opts), DpopError, JSON.stringify(opts));
  }
});

test("null reads as absent, like Python's None", () => {
  for (const opts of [
    { token: "tok", dpopKey: null },
    { token: "tok", aud: null, clock: null },
    { token: BOUND, dpopKey: KEY, aud: null, clock: null },
  ]) {
    SeamAdminClient.connect("http://127.0.0.1:1", opts as never).close();
  }
});

// ── the Bearer path is unchanged ────────────────────────────────────────────────────────────────

test("unbound and opaque tokens still go as Bearer; no token sends none", async () => {
  const pathological = "a." + b64e(Buffer.from("[".repeat(5000))) + ".c";
  for (const tok of ["tok", token({ aud: "seam-runtime" }), pathological, undefined]) {
    await withServer(async (url, calls) => {
      const admin = SeamAdminClient.connect(url, tok === undefined ? {} : { token: tok });
      try {
        await admin.listTenants();
      } finally {
        admin.close();
      }
      assert.equal(calls[0]!.headers.authorization, tok === undefined ? undefined : `Bearer ${tok}`);
      assert.equal(calls[0]!.headers.dpop, undefined);
    });
  }
});
