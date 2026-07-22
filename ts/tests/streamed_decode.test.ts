// Phase 6 — the streamed-event authenticity surface (TS).
//
// Server-free unit tests over verifyStreamedRecordDigest + KNOWN_KINDS, driven from the runtime's
// record_digest_v2 KAT, plus an env-gated live check that a streamed SESSION_LIFECYCLE carries its payload
// and a streamed v2 DECISION_SEALED recomputes.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { connect as tcpConnect } from "node:net";
import { readFileSync } from "node:fs";
import { create } from "@bufbuild/protobuf";
import {
  SeamEventSchema,
  DecisionSealedSchema,
  type SeamEvent,
} from "../gen/seam/event/v1/seam_event_pb.js";
import { Agent, SeamClient } from "../src/client.js";
import {
  SeamAdminClient,
  KNOWN_KINDS,
  verifyStreamedRecordDigest,
} from "../src/admin.js";

const vectors = JSON.parse(
  readFileSync(new URL("../../conformance/vectors.json", import.meta.url), "utf8"),
);

const BIN = process.env.SEAM_GRPC_BIN;

function katEvent(): SeamEvent {
  const v = vectors.record_digest_v2;
  const i = v.inputs;
  const payload = create(DecisionSealedSchema, {
    decisionId: i.decision_id,
    tenant: i.tenant,
    namespace: i.namespace,
    outcome: i.outcome,
    sealedAt: BigInt(i.sealed_at),
    schemaVersion: i.schema_version,
    ciphertextDigest: Buffer.from(i.ciphertext_digest_hex, "hex"),
    mode: i.mode, // Some in the KAT; policy_version / supersedes stay unset (undefined)
  });
  return create(SeamEventSchema, {
    kind: "DECISION_SEALED",
    payload,
    digest: Buffer.from(v.digest_hex, "hex"),
  });
}

// ── Unit ──────────────────────────────────────────────────────────────────────────────────────────────

test("KNOWN_KINDS includes the A14 kinds", () => {
  assert.ok(KNOWN_KINDS.has("SESSION_LIFECYCLE"));
  assert.ok(KNOWN_KINDS.has("CHAIN_HEAD_ATTESTATION"));
  assert.equal(KNOWN_KINDS.size, 8);
});

test("verifyStreamedRecordDigest: genuine → true, rewrite → false, strip → false", () => {
  assert.equal(verifyStreamedRecordDigest(katEvent()), true);

  const rewritten = katEvent();
  rewritten.payload!.outcome = "Expired";
  assert.equal(verifyStreamedRecordDigest(rewritten), false);

  const stripped = katEvent();
  stripped.payload!.ciphertextDigest = new Uint8Array(0);
  assert.equal(verifyStreamedRecordDigest(stripped), false);
});

test("verifyStreamedRecordDigest: v1 and non-DECISION_SEALED throw", () => {
  const v1 = katEvent();
  v1.payload!.schemaVersion = 1;
  assert.throws(() => verifyStreamedRecordDigest(v1));
  assert.throws(() => verifyStreamedRecordDigest(create(SeamEventSchema, { kind: "SESSION_LIFECYCLE" })));
});

// ── Live ──────────────────────────────────────────────────────────────────────────────────────────────

function waitPort(port: number, timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tryOnce = () => {
      const s = tcpConnect(port, "127.0.0.1");
      s.once("connect", () => {
        s.destroy();
        resolve();
      });
      s.once("error", () => {
        s.destroy();
        Date.now() > deadline ? reject(new Error("no server")) : setTimeout(tryOnce, 50);
      });
    };
    tryOnce();
  });
}

test(
  "streamed events carry the A14 payloads live (SESSION_LIFECYCLE + v2 ciphertext_digest)",
  { skip: !BIN },
  async () => {
    const dataPort = 8215;
    const mgmtPort = 8216;
    const proc = spawn(BIN!, {
      env: {
        ...process.env,
        SEAM_GRPC_LISTEN: `127.0.0.1:${dataPort}`,
        SEAM_GRPC_MGMT_LISTEN: `127.0.0.1:${mgmtPort}`,
        SEAM_DEV_INSECURE: "1",
      },
      stdio: "ignore",
    });
    try {
      await waitPort(dataPort);
      await waitPort(mgmtPort);
      const data = SeamClient.connect(`http://127.0.0.1:${dataPort}`);
      const admin = SeamAdminClient.connect(`http://127.0.0.1:${mgmtPort}`);
      const agent = new Agent(new Uint8Array(32).fill(42));

      // Interactive open → SESSION_LIFECYCLE; one-shot decision → v2 DECISION_SEALED.
      await data.openSession(agent, { sessionId: "p6-ts", participants: ["lead", "peer"] });
      const dec = await data.runDecision(agent, "p6d", ["fraud-v3", "risk-v2"], [
        ["fraud-v3", "BLOCK"],
        ["risk-v2", "BLOCK"],
      ]);
      assert.equal(dec.outcome, "Resolved");

      let lifecycle: SeamEvent | undefined;
      let sealed: SeamEvent | undefined;
      const kindsSeen = new Set<string>();
      for await (const ev of admin.streamEvents({ follow: false, ack: false })) {
        kindsSeen.add(ev.kind); // an unknown kind would still iterate, never throw
        if (ev.kind === "SESSION_LIFECYCLE") lifecycle = ev;
        else if (ev.kind === "DECISION_SEALED" && ev.payload?.decisionId === dec.decisionId)
          sealed = ev;
      }

      for (const k of kindsSeen) assert.ok(KNOWN_KINDS.has(k), `unexpected kind ${k}`);

      assert.ok(lifecycle, "the interactive open must emit a SESSION_LIFECYCLE");
      assert.equal(lifecycle!.sessionLifecycle!.phase, "opened");
      assert.ok(lifecycle!.sessionLifecycle!.openedAtMillis > 0n);

      assert.ok(sealed, "the sealed decision must appear on the stream");
      assert.equal(sealed!.payload!.schemaVersion, 2);
      assert.equal(sealed!.payload!.ciphertextDigest.length, 32);
      assert.equal(verifyStreamedRecordDigest(sealed!), true);
    } finally {
      proc.kill();
    }
  },
);
