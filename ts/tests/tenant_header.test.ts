// `x-seam-tenant` on every data-plane call, and `WRONG_CELL` (seam-runtime k8s P15, D123). Mirrors
// `python/tests/test_tenant_header.py`.
//
// The router routes on the header before authentication, so it must ride IssueChallenge and Admit —
// the two calls that carry no tenant of their own — which is exactly what `admit()` sends. Asserted
// on a real HTTP/2 server's received headers: what matters is what reaches the wire.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as http2 from "node:http2";
import type { AddressInfo } from "node:net";
import { create, toBinary } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";

import { ChallengeSchema } from "../gen/seam/api/v1/seam_pb.js";
import { Agent, SeamClient } from "../src/client.js";
import {
  FailedPreconditionError,
  WRONG_CELL_REASON,
  isRetryable,
  isWrongCell,
  toSeamError,
  type SeamRpcError,
} from "../src/errors.js";
import { TENANT_HEADER, tenantHeaderInterceptor } from "../src/tenant.js";

const te = new TextEncoder();

/** IssueChallenge answers a real challenge; every other call is refused, ending `admit()` at Admit. */
async function withServer(run: (url: string, seen: [string, string | undefined][]) => Promise<void>) {
  const seen: [string, string | undefined][] = [];
  const server = http2.createServer();
  server.on("stream", (stream, headers) => {
    const path = String(headers[":path"]);
    const verb = path.slice(path.lastIndexOf("/") + 1);
    const tenant = headers[TENANT_HEADER];
    seen.push([verb, Array.isArray(tenant) ? tenant.join(",") : tenant]);
    stream.on("data", () => {});
    stream.on("end", () => {
      if (verb === "IssueChallenge") {
        const body = toBinary(ChallengeSchema, create(ChallengeSchema, { nonce: "bm9uY2U", receiverAid: "aid:pubkey:r" }));
        const frame = Buffer.alloc(5 + body.length);
        frame.writeUInt32BE(body.length, 1);
        frame.set(body, 5);
        stream.respond({ ":status": 200, "content-type": "application/grpc" }, { waitForTrailers: true });
        stream.on("wantTrailers", () => stream.sendTrailers({ "grpc-status": "0" }));
        stream.end(frame);
      } else {
        stream.respond(
          { ":status": 200, "content-type": "application/grpc", "grpc-status": "7", "grpc-message": "refused" },
          { endStream: true },
        );
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  try {
    await run(`http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
}

async function admitOnce(client: SeamClient) {
  try {
    await assert.rejects(client.admit(new Agent(new Uint8Array(32).fill(7))));
  } finally {
    client.close();
  }
}

test("connect({ tenant }) sends x-seam-tenant on IssueChallenge and Admit", async () => {
  await withServer(async (url, seen) => {
    await admitOnce(SeamClient.connect(url, { tenant: "acme" }));
    assert.deepEqual(seen, [
      ["IssueChallenge", "acme"],
      ["Admit", "acme"],
    ]);
  });
});

test("no tenant sends no header — the direct-to-cell path is unchanged", async () => {
  await withServer(async (url, seen) => {
    await admitOnce(SeamClient.connect(url));
    assert.deepEqual(seen, [
      ["IssueChallenge", undefined],
      ["Admit", undefined],
    ]);
  });
});

test("an empty or non-string tenant is refused before anything is opened", () => {
  for (const bad of ["", 7 as unknown as string]) {
    assert.throws(() => tenantHeaderInterceptor(bad), /tenant/);
    assert.throws(() => SeamClient.connect("http://127.0.0.1:1", { tenant: bad }), /tenant/);
  }
});

test("a header the call already names is kept, not overwritten", async () => {
  const req = { header: new Headers({ [TENANT_HEADER]: "explicit" }) };
  const next = async (r: typeof req) => r.header.get(TENANT_HEADER);
  // The interceptor's request type is Connect's; only `header` is read, so a minimal shape suffices.
  const got = await (tenantHeaderInterceptor("acme") as unknown as (n: typeof next) => typeof next)(next)(req);
  assert.equal(got, "explicit");
});

// ── WRONG_CELL ────────────────────────────────────────────────────────────────────────────────────

function varint(n: number): number[] {
  const out: number[] = [];
  for (;;) {
    const b = n & 0x7f;
    n >>>= 7;
    if (n) out.push(b | 0x80);
    else return [...out, b];
  }
}
const cat = (...parts: (Uint8Array | number[])[]) => new Uint8Array(parts.flatMap((p) => Array.from(p)));
const ld = (num: number, payload: Uint8Array) => cat(varint((num << 3) | 2), varint(payload.length), payload);

function refused(code: Code, reason: string, metadata: Record<string, string>): SeamRpcError {
  let info = cat(ld(1, te.encode(reason)), ld(2, te.encode("seam.zer07labs.com")));
  for (const [k, v] of Object.entries(metadata)) info = cat(info, ld(3, cat(ld(1, te.encode(k)), ld(2, te.encode(v)))));
  const any = cat(ld(1, te.encode("type.googleapis.com/google.rpc.ErrorInfo")), ld(2, info));
  const status = cat(varint(1 << 3), varint(code), ld(2, te.encode("refused")), ld(3, any));
  const md = new Headers({ "grpc-status-details-bin": Buffer.from(status).toString("base64") });
  return toSeamError(new ConnectError("refused", code, md)) as SeamRpcError;
}

const WRONG_CELL_META = { cell: "aws-stg-b", root_snapshot_id: "snap-41", root_generated_at: "2026-10-25T12:00:00Z" };

test("WRONG_CELL is typed, exposes its metadata, and is never retryable", () => {
  const err = refused(Code.FailedPrecondition, WRONG_CELL_REASON, WRONG_CELL_META);
  assert.ok(err instanceof FailedPreconditionError);
  assert.equal(err.reason, "WRONG_CELL");
  assert.deepEqual(err.errorMetadata, WRONG_CELL_META);
  assert.ok(isWrongCell(err));
  assert.equal(isRetryable(err), false);
});

test("errorMetadata is a copy, and absent without a detail", () => {
  const err = refused(Code.FailedPrecondition, WRONG_CELL_REASON, WRONG_CELL_META);
  err.errorMetadata!.cell = "mutated";
  assert.equal(err.errorMetadata!.cell, "aws-stg-b");
  const bare = toSeamError(new ConnectError("refused", Code.FailedPrecondition)) as SeamRpcError;
  assert.equal(bare.errorMetadata, undefined);
  assert.equal(isWrongCell(bare), false);
});

test("another FAILED_PRECONDITION reason is not WRONG_CELL", () => {
  const err = refused(Code.FailedPrecondition, "stream_id_mismatch", {});
  assert.deepEqual(err.errorMetadata, {});
  assert.equal(isWrongCell(err), false);
});
