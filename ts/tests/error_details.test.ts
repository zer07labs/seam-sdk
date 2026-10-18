// P11 — Seam's error class, read off `grpc-status-details-bin`: `reason`, `macpCode`, `retryAfter`.
//
// The runtime attaches a `google.rpc.ErrorInfo` (domain `seam.zer07labs.com`) to every refusal, and a
// `google.rpc.RetryInfo` to a load-shed. These tests encode the three messages by hand, from the
// `google.rpc` field numbers, so neither side borrows the other's decoder. Mirrors
// `python/tests/test_error_details.py`.
//
// Field numbers: `Status{code=1, message=2, details=3 (Any)}`, `Any{type_url=1, value=2}`,
// `ErrorInfo{reason=1, domain=2, metadata=3 (map<string,string>)}`, `RetryInfo{retry_delay=1
// (Duration{seconds=1, nanos=2})}`.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as http2 from "node:http2";
import type { AddressInfo } from "node:net";
import { create } from "@bufbuild/protobuf";
import type { DescMessage, DescMethodUnary, MessageInitShape } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import type { Transport, UnaryResponse } from "@connectrpc/connect";

import { Agent, SeamClient } from "../src/client.js";
import {
  PermissionDeniedError,
  ResourceExhaustedError,
  SeamRpcError,
  toSeamError,
} from "../src/errors.js";

const DOMAIN = "seam.zer07labs.com";
const KEY = "grpc-status-details-bin";
const te = new TextEncoder();

function varint(n: number): number[] {
  let v = BigInt(n);
  const out: number[] = [];
  for (;;) {
    const b = Number(v & 0x7fn);
    v >>= 7n;
    if (v) out.push(b | 0x80);
    else {
      out.push(b);
      return out;
    }
  }
}

const cat = (...parts: (Uint8Array | number[])[]) =>
  new Uint8Array(parts.flatMap((p) => Array.from(p)));
const ld = (num: number, payload: Uint8Array) =>
  cat(varint((num << 3) | 2), varint(payload.length), payload);
const vi = (num: number, value: number) => cat(varint(num << 3), varint(value));
const anyOf = (typeName: string, value: Uint8Array) =>
  cat(ld(1, te.encode(`type.googleapis.com/${typeName}`)), ld(2, value));

function errorInfo(reason: string, metadata: Record<string, string> = {}, domain = DOMAIN): Uint8Array {
  let body = cat(ld(1, te.encode(reason)), ld(2, te.encode(domain)));
  for (const [k, v] of Object.entries(metadata)) {
    body = cat(body, ld(3, cat(ld(1, te.encode(k)), ld(2, te.encode(v)))));
  }
  return anyOf("google.rpc.ErrorInfo", body);
}

function retryInfo(seconds: number, nanos = 0): Uint8Array {
  const duration = cat(seconds ? vi(1, seconds) : [], nanos ? vi(2, nanos) : []);
  return anyOf("google.rpc.RetryInfo", ld(1, duration));
}

const statusOf = (code: number, ...details: Uint8Array[]) =>
  cat(vi(1, code), ld(2, te.encode("refused")), ...details.map((d) => ld(3, d)));

/** A `ConnectError` carrying only the raw trailer in `metadata` — the fallback path. */
function mapped(code: Code, blob: Uint8Array): SeamRpcError {
  const md = new Headers({ [KEY]: Buffer.from(blob).toString("base64") });
  return toSeamError(new ConnectError("refused", code, md)) as SeamRpcError;
}

/** The same refusal as Connect's own gRPC transport delivers it: `details` already parsed. */
function parsed(code: Code, ...anys: Uint8Array[]): SeamRpcError {
  const details = anys.map((a) => {
    let type = "";
    let value: Uint8Array = new Uint8Array(0);
    // Each `anys` entry is `ld(1, type_url) ++ ld(2, value)`; re-read them with the test's own framing.
    let i = 0;
    while (i < a.length) {
      const num = a[i]! >> 3;
      let len = 0;
      let shift = 0;
      let j = i + 1;
      for (;;) {
        const b = a[j++]!;
        len |= (b & 0x7f) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
      }
      const body = a.subarray(j, j + len);
      if (num === 1) type = new TextDecoder().decode(body).replace("type.googleapis.com/", "");
      else value = body;
      i = j + len;
    }
    return { type, value };
  });
  // The constructor's type names only outgoing details; a received error carries `{ type, value }`.
  const received = details as unknown as ConstructorParameters<typeof ConnectError>[3];
  return toSeamError(new ConnectError("refused", code, undefined, received)) as SeamRpcError;
}

test("a protocol refusal carries its macpCode (metadata fallback and parsed details agree)", () => {
  for (const err of [
    mapped(Code.PermissionDenied, statusOf(7, errorInfo("PROTOCOL", { macp_code: "FORBIDDEN" }))),
    parsed(Code.PermissionDenied, errorInfo("PROTOCOL", { macp_code: "FORBIDDEN" })),
  ]) {
    assert.ok(err instanceof PermissionDeniedError);
    assert.equal(err.reason, "PROTOCOL");
    assert.equal(err.macpCode, "FORBIDDEN");
  }
});

test("an unknown macpCode is surfaced raw, not dropped", () => {
  // MACP grows codes on its own schedule; a code this SDK cannot name must still be routable.
  const err = mapped(Code.InvalidArgument, statusOf(3, errorInfo("PROTOCOL", { macp_code: "SOME_FUTURE_CODE" })));
  assert.equal(err.macpCode, "SOME_FUTURE_CODE");
});

test("the PERMISSION_DENIED classes are told apart by reason", () => {
  // POLICY_DENIED moved from FAILED_PRECONDITION to PERMISSION_DENIED, which it now shares with two
  // other classes. The status cannot tell them apart; the reason can.
  for (const reason of ["POLICY_DENIED", "SCOPE_DENIED", "FACT_ATTESTOR_REJECTED"]) {
    const err = mapped(Code.PermissionDenied, statusOf(7, errorInfo(reason)));
    assert.ok(err instanceof PermissionDeniedError);
    assert.equal(err.reason, reason);
  }
});

test("macpCode is only read on a PROTOCOL reason", () => {
  // Every other class has no macp_code by contract; a stray key is ignored, not surfaced.
  const err = mapped(Code.PermissionDenied, statusOf(7, errorInfo("POLICY_DENIED", { macp_code: "FORBIDDEN" })));
  assert.equal(err.reason, "POLICY_DENIED");
  assert.equal(err.macpCode, undefined);
});

test("a foreign domain is not Seam's error class", () => {
  const err = mapped(
    Code.PermissionDenied,
    statusOf(7, errorInfo("PROTOCOL", { macp_code: "FORBIDDEN" }, "example.com")),
  );
  assert.equal(err.reason, undefined);
  assert.equal(err.macpCode, undefined);
});

test("a load-shed surfaces retryAfter (seconds)", () => {
  for (const err of [
    mapped(Code.ResourceExhausted, statusOf(8, errorInfo("QUOTA_EXCEEDED"), retryInfo(2, 500_000_000))),
    parsed(Code.ResourceExhausted, errorInfo("QUOTA_EXCEEDED"), retryInfo(2, 500_000_000)),
  ]) {
    assert.ok(err instanceof ResourceExhaustedError);
    assert.equal(err.reason, "QUOTA_EXCEEDED");
    assert.ok(Math.abs(err.retryAfter! - 2.5) < 1e-9, `retryAfter ${err.retryAfter}`);
    assert.equal(err.macpCode, undefined);
  }
});

test("no details means undefined everywhere", () => {
  const err = toSeamError(new ConnectError("x", Code.Internal)) as SeamRpcError;
  assert.deepEqual([err.reason, err.macpCode, err.retryAfter], [undefined, undefined, undefined]);
});

test("a malformed payload fails soft", () => {
  // The typed error must never be displaced by a failure to read metadata about it.
  const cases: [string, Uint8Array][] = [
    ["bad-key", new Uint8Array([0xff])],
    ["truncated-length", cat([0x1a, 0x05], te.encode("ab"))],
    ["truncated-any", statusOf(7, new Uint8Array([0x0a, 0xff]))],
    ["overlong-varint", cat([0x08], new Array(11).fill(0xff))],
  ];
  for (const [name, blob] of cases) {
    const err = mapped(Code.PermissionDenied, blob);
    assert.ok(err instanceof PermissionDeniedError, name);
    assert.deepEqual([err.reason, err.macpCode, err.retryAfter], [undefined, undefined, undefined], name);
  }
});

// ── End to end: through a real HTTP/2 gRPC response's trailers ──────────────────────────────────────

test("reason and macpCode survive a real call (Connect's own trailer parsing)", async () => {
  const blob = Buffer.from(statusOf(7, errorInfo("PROTOCOL", { macp_code: "FORBIDDEN" })))
    .toString("base64")
    .replace(/=+$/, ""); // gRPC sends -bin metadata unpadded
  const server = http2.createServer();
  server.on("stream", (stream) => {
    stream.on("data", () => {});
    stream.on("end", () => {
      // A trailers-only response: the status rides the single HEADERS frame.
      stream.respond(
        {
          ":status": 200,
          "content-type": "application/grpc",
          "grpc-status": "7",
          "grpc-message": "refused",
          [KEY]: blob,
        },
        { endStream: true },
      );
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  const client = SeamClient.connect(`http://127.0.0.1:${port}`);
  try {
    await assert.rejects(client.authorize(new Agent(new Uint8Array(32).fill(9)), "t", {}), (err: unknown) => {
      assert.ok(err instanceof PermissionDeniedError, `got ${String(err)}`);
      assert.equal(err.reason, "PROTOCOL");
      assert.equal(err.macpCode, "FORBIDDEN");
      return true;
    });
  } finally {
    client.close();
    await new Promise<void>((r) => server.close(() => r()));
  }
});

// ── The challenge request type ──────────────────────────────────────────────────────────────────────

test("IssueChallenge sends an IssueChallengeRequest, not google.protobuf.Empty (P11)", async () => {
  const seen: { method: string; inputType: string; messageType: unknown }[] = [];
  const transport: Transport = {
    async unary<I extends DescMessage, O extends DescMessage>(
      method: DescMethodUnary<I, O>,
      _signal: AbortSignal | undefined,
      _timeoutMs: number | undefined,
      _headers: HeadersInit | undefined,
      input: MessageInitShape<I>,
    ): Promise<UnaryResponse<I, O>> {
      seen.push({
        method: method.name,
        inputType: method.input.typeName,
        messageType: (input as { $typeName?: unknown }).$typeName,
      });
      if (method.name !== "IssueChallenge") {
        throw new ConnectError("refused", Code.PermissionDenied);
      }
      return {
        stream: false,
        service: method.parent,
        method,
        header: new Headers(),
        trailer: new Headers(),
        message: create(method.output, {
          nonce: "bm9uY2U",
          receiverAid: "aid:pubkey:receiver",
        } as unknown as MessageInitShape<O>),
      };
    },
    async stream() {
      throw new Error("no streams here");
    },
  };
  const client = new SeamClient(transport);
  await assert.rejects(client.authorize(new Agent(new Uint8Array(32).fill(9)), "t", {}));
  const challenges = seen.filter((s) => s.method === "IssueChallenge");
  assert.ok(challenges.length > 0, "no IssueChallenge was sent");
  for (const c of challenges) {
    assert.equal(c.inputType, "seam.api.v1.IssueChallengeRequest");
    assert.equal(c.messageType, "seam.api.v1.IssueChallengeRequest");
  }
});
