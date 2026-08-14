// The typed-error taxonomy's discrimination contract, and the deadline behaviour against a server
// that accepts connections but never answers (the TS twin of Python's test_lifecycle_and_timeouts):
// a hanging call must come back as a typed DeadlineExceededError inside its budget, and close()
// must be idempotent and actually tear the HTTP/2 session down.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as http2 from "node:http2";
import { Code, ConnectError } from "@connectrpc/connect";

import { SeamClient } from "../src/client.js";
import { SeamAdminClient } from "../src/admin.js";
import {
  DeadlineExceededError,
  InternalError,
  NotFoundError,
  ProtocolViolationError,
  SeamRpcError,
  UnauthenticatedError,
  toSeamError,
} from "../src/errors.js";

// ── instanceof discrimination ────────────────────────────────────────────────────────────────────

test("a retyped error matches its OWN subclass and no sibling", () => {
  const e = toSeamError(new ConnectError("gone", Code.NotFound));
  assert.ok(e instanceof NotFoundError);
  assert.ok(e instanceof SeamRpcError);
  // The regression this pins: ConnectError's duck-typed Symbol.hasInstance matched ANY ConnectError
  // against ANY subclass, so a NOT_FOUND was `instanceof UnauthenticatedError` — which silently sent
  // every server error down authorize()'s ticket-refresh-and-retry path.
  assert.ok(!(e instanceof UnauthenticatedError), "a NotFound must not match a sibling subclass");
  // The non-breaking guarantee: the retype is in place, so it is still a ConnectError with its code.
  assert.ok(e instanceof ConnectError);
  assert.equal((e as SeamRpcError).code, Code.NotFound);
});

test("a raw ConnectError matches NO SeamRpcError subclass until retyped", () => {
  const raw = new ConnectError("nope", Code.Unauthenticated);
  assert.ok(!(raw instanceof SeamRpcError));
  assert.ok(!(raw instanceof UnauthenticatedError));
  assert.ok(toSeamError(raw) instanceof UnauthenticatedError);
});

test("retyping is idempotent and unknown codes fall back to InternalError", () => {
  const e = toSeamError(new ConnectError("x", Code.NotFound));
  assert.equal(toSeamError(e), e);
  const odd = toSeamError(new ConnectError("odd", Code.Canceled));
  assert.ok(odd instanceof InternalError);
  assert.equal((odd as SeamRpcError).code, Code.Canceled, "the original code is preserved");
});

test("directly-constructed subclasses discriminate too", () => {
  const e = new UnauthenticatedError("bad token", Code.Unauthenticated);
  assert.ok(e instanceof UnauthenticatedError && e instanceof SeamRpcError && e instanceof ConnectError);
  assert.ok(!(e instanceof NotFoundError));
});

test("ProtocolViolationError is a typed client-side error carrying its name and authorize id", () => {
  const e = new ProtocolViolationError("TRANSFORM without transformed_input", "az-1");
  assert.ok(e instanceof ProtocolViolationError && e instanceof Error);
  assert.equal(e.name, "ProtocolViolationError");
  assert.equal(e.authorizeId, "az-1");
  assert.ok(!(e instanceof SeamRpcError), "an OK-status payload violation is not an RPC error");
});

// ── Deadlines against a hanging server, and close() ──────────────────────────────────────────────

/** An HTTP/2 server that accepts sessions and requests but never answers — the wedged-server shape.
 * Returns its port, the set of live sessions, and a closer. */
function hangingServer(): Promise<{
  port: number;
  sessions: Set<http2.ServerHttp2Session>;
  close: () => void;
}> {
  const server = http2.createServer();
  const sessions = new Set<http2.ServerHttp2Session>();
  server.on("session", (s) => {
    sessions.add(s);
    s.on("close", () => sessions.delete(s));
    // A client-side abort() surfaces here as GOAWAY(CANCEL) → a session 'error'; that abrupt
    // teardown is exactly what the close() test exercises, so it must not crash the process.
    s.on("error", () => {});
  });
  server.on("stream", (st) => {
    // Never respond — but the wedged stream is torn down WITH the session error when the client
    // aborts, and an unhandled stream 'error' crashes the process, so it must be swallowed too.
    st.on("error", () => {});
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as { port: number };
      resolve({
        port: addr.port,
        sessions,
        close: () => {
          for (const s of sessions) s.destroy();
          server.close();
        },
      });
    });
  });
}

test("a hanging data-plane call surfaces as DeadlineExceededError inside its budget", async () => {
  const srv = await hangingServer();
  const client = SeamClient.connect(`http://127.0.0.1:${srv.port}`);
  try {
    const started = Date.now();
    await assert.rejects(
      client.sessionStatus("s", { timeoutMs: 150 }),
      (e: unknown) => e instanceof DeadlineExceededError && (e as SeamRpcError).code === Code.DeadlineExceeded,
    );
    assert.ok(Date.now() - started < 3_000, "must fail within the deadline, not hang");
  } finally {
    client.close();
    srv.close();
  }
});

test("a hanging management call surfaces as DeadlineExceededError inside its budget", async () => {
  const srv = await hangingServer();
  const admin = SeamAdminClient.connect(`http://127.0.0.1:${srv.port}`);
  try {
    const started = Date.now();
    await assert.rejects(
      admin.previewErasure("acme", "cust-42", { timeoutMs: 150 }),
      (e: unknown) => e instanceof DeadlineExceededError,
    );
    assert.ok(Date.now() - started < 3_000);
  } finally {
    admin.close();
    srv.close();
  }
});

test("close() tears the HTTP/2 session down and is idempotent (both clients)", async () => {
  const srv = await hangingServer();
  try {
    const client = SeamClient.connect(`http://127.0.0.1:${srv.port}`);
    await assert.rejects(client.sessionStatus("s", { timeoutMs: 150 })); // opens the session
    assert.equal(srv.sessions.size, 1, "the client must hold one live session");
    client.close();
    const deadline = Date.now() + 2_000;
    while (srv.sessions.size > 0 && Date.now() < deadline)
      await new Promise((r) => setTimeout(r, 10));
    assert.equal(srv.sessions.size, 0, "close() must release the connection");
    client.close(); // idempotent — a repeated close must not throw

    const admin = SeamAdminClient.connect(`http://127.0.0.1:${srv.port}`);
    await assert.rejects(admin.previewErasure("t", "s", { timeoutMs: 150 }));
    admin.close();
    admin.close();
  } finally {
    srv.close();
  }
});
