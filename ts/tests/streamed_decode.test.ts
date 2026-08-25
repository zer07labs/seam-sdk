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
import { RecordDigestStripError } from "../src/crypto.js";

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

test("KNOWN_KINDS includes the A14 kinds and the authorize outbox kind", () => {
  assert.ok(KNOWN_KINDS.has("SESSION_LIFECYCLE"));
  assert.ok(KNOWN_KINDS.has("CHAIN_HEAD_ATTESTATION"));
  assert.ok(KNOWN_KINDS.has("AUTHORIZE_EVALUATED"));
  assert.equal(KNOWN_KINDS.size, 9);
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

test("verifyStreamedRecordDigest: a schema version NEWER than v3 throws, never computes under a known tag", () => {
  // Computing a v4+ digest with the v3 domain tag would return `false` for a genuine record — a
  // silent authenticity downgrade. It must refuse, exactly like the v1 not-recomputable path. This
  // test read `= 3` until the v3 arm landed; the boundary moves with the SDK's knowledge.
  const v4 = katEvent();
  v4.payload!.schemaVersion = 4;
  assert.throws(
    () => verifyStreamedRecordDigest(v4),
    /not recomputable|only v2/,
  );
});

// ── v3: the streamed arm, its strip refusals, and the tag-13 absence that must NOT be one ──────────────

function katV3Event(name = "record_digest_v3"): SeamEvent {
  const v = vectors[name];
  const i = v.inputs;
  const payload = create(DecisionSealedSchema, {
    decisionId: i.decision_id,
    tenant: i.tenant,
    namespace: i.namespace,
    outcome: i.outcome,
    sealedAt: BigInt(i.sealed_at),
    schemaVersion: i.schema_version,
    ciphertextDigest: Buffer.from(i.ciphertext_digest_hex, "hex"),
    contextDigest: Buffer.from(i.context_digest_hex, "hex"),
    participationDigest: Buffer.from(i.participation_digest_hex, "hex"),
    ...(i.mode !== null ? { mode: i.mode } : {}),
    ...(i.policy_version !== null ? { policyVersion: i.policy_version } : {}),
    ...(i.supersedes !== null ? { supersedes: i.supersedes } : {}),
    ...(i.policy_rules_digest_hex !== null
      ? { policyRulesDigest: Buffer.from(i.policy_rules_digest_hex, "hex") }
      : {}),
  });
  return create(SeamEventSchema, {
    kind: "DECISION_SEALED",
    payload,
    digest: Buffer.from(v.digest_hex, "hex"),
  });
}

test("verifyStreamedRecordDigest v3: genuine → true, rewrite → false", () => {
  assert.equal(verifyStreamedRecordDigest(katV3Event()), true);

  const rewritten = katV3Event();
  rewritten.payload!.outcome = "Expired";
  assert.equal(verifyStreamedRecordDigest(rewritten), false);
});

test("verifyStreamedRecordDigest v3: binds tags 11 and 12 into the preimage", () => {
  // Without this, the arm could be quietly computing v2's formula and still pass the green case —
  // v2's columns are a subset of v3's, so the green case alone does not prove the new slots are fed.
  for (const field of ["contextDigest", "participationDigest"] as const) {
    const ev = katV3Event();
    const perturbed = Uint8Array.from(ev.payload![field]);
    perturbed[0] ^= 0x01;
    ev.payload![field] = perturbed;
    assert.equal(verifyStreamedRecordDigest(ev), false, field);
  }
});

test("verifyStreamedRecordDigest v3: a stripped tag 11/12 THROWS, distinctly from a mismatch", () => {
  for (const [field, tag] of [
    ["contextDigest", 11],
    ["participationDigest", 12],
  ] as const) {
    const ev = katV3Event();
    ev.payload![field] = new Uint8Array(0);
    assert.throws(
      () => verifyStreamedRecordDigest(ev),
      (err: unknown) => {
        assert.ok(
          err instanceof RecordDigestStripError,
          `${field}: not a strip error`,
        );
        assert.equal(err.wireTag, tag);
        // The spec's field NAME, not the camelCase wire accessor — a caller routing a refusal to an
        // alert or a metric label must not have to translate. Python's twin asserts the same pair.
        assert.equal(
          err.field,
          tag === 11 ? "context_digest" : "participation_digest",
        );
        return true;
      },
      field,
    );
  }
});

test("verifyStreamedRecordDigest v3: a wrong-length tag 11/12 THROWS rather than framing", () => {
  // A present-but-31-byte digest is malformed, not a mismatch. Framing it would produce a
  // well-formed digest over a value no sealer ever wrote.
  for (const field of ["contextDigest", "participationDigest"] as const) {
    const ev = katV3Event();
    ev.payload![field] = ev.payload![field].slice(0, 31);
    assert.throws(
      () => verifyStreamedRecordDigest(ev),
      RecordDigestStripError,
      field,
    );
  }
});

test("verifyStreamedRecordDigest v3: an absent policyRulesDigest verifies GREEN as opt(None)", () => {
  // Absent tag 13 is legitimate — no policy bound, today's common case. The generated field is an
  // EMPTY Uint8Array, never undefined, so `?? null` would not fire and the value would frame as
  // opt(Some(empty)) — five bytes where the sealer wrote one — failing a genuine record.
  assert.equal(
    verifyStreamedRecordDigest(katV3Event("record_digest_v3_absent_policy")),
    true,
  );
});

test("verifyStreamedRecordDigest v3: absent and present tag 13 are different digests", () => {
  // The guard on the guard: if these coincided, the test above would pass under a formula that
  // ignores tag 13 entirely.
  assert.notEqual(
    vectors.record_digest_v3.digest_hex,
    vectors.record_digest_v3_absent_policy.digest_hex,
  );
});

test("verifyStreamedRecordDigest v3: a stripped tag 10 is FALSE, not a strip throw", () => {
  // Tag 10 keeps its older shape. The spec makes a tag-10 strip a REFUSE for every schemaVersion >= 2
  // — a failing verdict, which for a boolean helper is `false` — but attaches the distinct-reporting
  // requirement only to tags 11/12.
  const ev = katV3Event();
  ev.payload!.ciphertextDigest = new Uint8Array(0);
  assert.equal(verifyStreamedRecordDigest(ev), false);
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
