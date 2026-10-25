// Phase 6 — the streamed-event authenticity surface (TS).
//
// Server-free unit tests over verifyStreamedRecordDigest + KNOWN_KINDS, driven from the runtime's
// record_digest_v4 KATs (real digests over real columns), plus an env-gated live check that a streamed
// SESSION_LIFECYCLE carries its payload and a streamed v4 DECISION_SEALED recomputes. Mirrors
// `python/tests/test_streamed_decode.py`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { connect as tcpConnect } from "node:net";
import { readFileSync } from "node:fs";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
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
import { STREAM_ID, governanceEnv, mintOperatorToken } from "./operator_token.js";
import { RecordDigestStripError, UnsupportedRecordDigestVersion } from "../src/crypto.js";

const vectors = JSON.parse(
  readFileSync(new URL("../../conformance/vectors.json", import.meta.url), "utf8"),
);

const BIN = process.env.SEAM_GRPC_BIN;

/** A v4 DECISION_SEALED whose payload + wire digest are a committed record_digest_v4 vector. */
function katEvent(name = "record_digest_v4"): SeamEvent {
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
    classification: i.classification,
    participantsDigest: Buffer.from(i.participants_digest_hex, "hex"),
    trustBasisCommitment: i.trust_basis_commitment,
    authMethod: i.auth_method,
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

// ── Unit ──────────────────────────────────────────────────────────────────────────────────────────────

test("KNOWN_KINDS includes the A14 kinds and the authorize outbox kind", () => {
  assert.ok(KNOWN_KINDS.has("SESSION_LIFECYCLE"));
  assert.ok(KNOWN_KINDS.has("CHAIN_HEAD_ATTESTATION"));
  assert.ok(KNOWN_KINDS.has("AUTHORIZE_EVALUATED"));
  assert.ok(KNOWN_KINDS.has("POLICY_DENIED"));
  assert.equal(KNOWN_KINDS.size, 10);
});

test("verifyStreamedRecordDigest: genuine → true, rewrite → false", () => {
  assert.equal(verifyStreamedRecordDigest(katEvent()), true);

  const rewritten = katEvent();
  rewritten.payload!.outcome = "Expired"; // rewrite a structural column, keep the wire digest
  assert.equal(verifyStreamedRecordDigest(rewritten), false);
});

test("verifyStreamedRecordDigest: binds every mandatory field (tags 11, 12, 14-17)", () => {
  // Rewriting one, validly shaped, is a `false`. Without this the arm could be computing a formula
  // over a subset of the columns and still pass the green case.
  const rewrites: [string, unknown][] = [
    ["contextDigest", new Uint8Array(32)],
    ["participationDigest", new Uint8Array(32)],
    ["classification", "Public"],
    ["participantsDigest", new Uint8Array(32)],
    ["trustBasisCommitment", "rewritten"],
    ["authMethod", "rewritten"],
  ];
  for (const [field, value] of rewrites) {
    const ev = katEvent();
    const p = ev.payload! as unknown as Record<string, unknown>;
    assert.notDeepEqual(p[field], value, field);
    p[field] = value;
    assert.equal(verifyStreamedRecordDigest(ev), false, field);
  }
});

test("verifyStreamedRecordDigest: any schema version but 4 is cannot-verify, never false", () => {
  // v1-v3 are retired (P7), and v5 is unknown. Recomputing a v3 record under the v4 tag would
  // fabricate a tamper verdict on a genuine record, and a retained v3 formula no longer exists.
  for (const version of [1, 2, 3, 5]) {
    const ev = katEvent();
    ev.payload!.schemaVersion = version;
    assert.throws(() => verifyStreamedRecordDigest(ev), UnsupportedRecordDigestVersion, `v${version}`);
  }
});

test("verifyStreamedRecordDigest: a non-DECISION_SEALED event is refused", () => {
  assert.throws(() => verifyStreamedRecordDigest(create(SeamEventSchema, { kind: "SESSION_LIFECYCLE" })));
});

// ── Strips: tags 11, 12 and 14-17 throw; tag 13's absence is legitimate; tag 10's is false ────────────

const MANDATORY = [
  ["contextDigest", "context_digest", 11],
  ["participationDigest", "participation_digest", 12],
  ["classification", "classification", 14],
  ["participantsDigest", "participants_digest", 15],
  ["trustBasisCommitment", "trust_basis_commitment", 16],
  ["authMethod", "auth_method", 17],
] as const;

/** The wire key of an explicit zero-length occurrence of each tag (field number << 3 | 2, varint). */
const EMPTY_ON_THE_WIRE: Record<string, number[]> = {
  contextDigest: [0x5a, 0x00],
  participationDigest: [0x62, 0x00],
  policyRulesDigest: [0x6a, 0x00],
  classification: [0x72, 0x00],
  participantsDigest: [0x7a, 0x00],
  trustBasisCommitment: [0x82, 0x01, 0x00],
  authMethod: [0x8a, 0x01, 0x00],
};

function spliceEmpty(ev: SeamEvent, field: string): SeamEvent {
  // proto3 is last-wins, so appending an explicit empty occurrence overwrites the genuine value on
  // decode. The payload is a nested message, so splice into the payload's own bytes.
  const raw = toBinary(DecisionSealedSchema, ev.payload!);
  const spliced = new Uint8Array([...raw, ...EMPTY_ON_THE_WIRE[field]]);
  const payload = fromBinary(DecisionSealedSchema, spliced);
  assert.equal(
    (payload as unknown as Record<string, { length: number }>)[field].length,
    0,
    "the splice landed",
  );
  return create(SeamEventSchema, { kind: ev.kind, payload, digest: ev.digest });
}

function assertStrip(ev: SeamEvent, field: string, tag: number) {
  assert.throws(
    () => verifyStreamedRecordDigest(ev),
    (err: unknown) => {
      assert.ok(err instanceof RecordDigestStripError, `${field}: not a strip error`);
      // The spec's field NAME, not the camelCase wire accessor — a caller routing a refusal to an
      // alert or a metric label must not have to translate. Python's twin asserts the same pair.
      assert.equal(err.field, field);
      assert.equal(err.wireTag, tag);
      return true;
    },
    field,
  );
}

test("verifyStreamedRecordDigest: a stripped mandatory field THROWS, distinctly from a mismatch", () => {
  // So an operator can tell "someone removed a field" from "someone rewrote one".
  for (const [key, field, tag] of MANDATORY) {
    const ev = katEvent();
    const p = ev.payload! as unknown as Record<string, unknown>;
    p[key] = typeof p[key] === "string" ? "" : new Uint8Array(0);
    assertStrip(ev, field, tag);
  }
});

test("verifyStreamedRecordDigest: an explicitly encoded empty mandatory field is the same strip", () => {
  // `length === 0` is absence however the bytes arose. proto3 obliges a decoder to ACCEPT an
  // explicitly encoded zero-length field, so a hostile producer can put one on the wire even though a
  // conforming one never will — it must land on the same refusal as an omitted field.
  for (const [key, field, tag] of MANDATORY) {
    assertStrip(spliceEmpty(katEvent(), key), field, tag);
  }
});

test("verifyStreamedRecordDigest: a wrong-length mandatory digest THROWS rather than framing", () => {
  // A present-but-31-byte digest is malformed, not a mismatch. Framing it would produce a
  // well-formed digest over a value no sealer ever wrote.
  for (const field of ["contextDigest", "participationDigest", "participantsDigest"] as const) {
    const ev = katEvent();
    ev.payload![field] = ev.payload![field].slice(0, 31);
    assert.throws(() => verifyStreamedRecordDigest(ev), RecordDigestStripError, field);
  }
});

test("verifyStreamedRecordDigest: an absent policyRulesDigest verifies GREEN as opt(None)", () => {
  // Absent tag 13 is legitimate — no policy bound. The generated field is an EMPTY Uint8Array, never
  // undefined, so `?? null` would not fire and the value would frame as opt(Some(empty)) — five bytes
  // where the sealer wrote one — failing a genuine record.
  assert.equal(verifyStreamedRecordDigest(katEvent("record_digest_v4_absent_policy")), true);
});

test("verifyStreamedRecordDigest: an explicitly encoded empty policyRulesDigest verifies GREEN", () => {
  // The tag-13 counterpart of the strip splice: `0x6a 0x00` must be opt(None), identical to omission.
  const ev = spliceEmpty(katEvent("record_digest_v4_absent_policy"), "policyRulesDigest");
  assert.equal(verifyStreamedRecordDigest(ev), true);
});

test("verifyStreamedRecordDigest: absent and present tag 13 are different digests", () => {
  // The guard on the guard: if these coincided, the tests above would pass under a formula that
  // ignores tag 13 entirely.
  assert.notEqual(
    vectors.record_digest_v4.digest_hex,
    vectors.record_digest_v4_absent_policy.digest_hex,
  );
});

test("verifyStreamedRecordDigest: a stripped tag 10 is FALSE, not a strip throw", () => {
  // Tag 10 keeps its older shape. The spec makes a tag-10 strip a REFUSE — a failing verdict, which
  // for a boolean helper is `false` — but attaches the distinct-reporting requirement only to tags
  // 11, 12 and 14-17.
  const ev = katEvent();
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
  "streamed events carry the A14 payloads live (SESSION_LIFECYCLE + ciphertext_digest)",
  { skip: !BIN },
  async () => {
    const dataPort = 8215;
    const mgmtPort = 8216;
    const proc = spawn(BIN!, {
      env: {
        ...process.env,
      ...governanceEnv(),
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
      const admin = SeamAdminClient.connect(`http://127.0.0.1:${mgmtPort}`, {
        token: mintOperatorToken(["audit:read"]),
      });
      const agent = new Agent(new Uint8Array(32).fill(42));

      // Interactive open → SESSION_LIFECYCLE; one-shot decision → v4 DECISION_SEALED.
      await data.openSession(agent, { sessionId: "p6-ts-sid-0123456789abcdef", participants: ["lead", "peer"] });
      const dec = await data.runDecision(agent, "p6d-sid-0123456789abcdef", ["fraud-v3", "risk-v2"], [
        ["fraud-v3", "BLOCK"],
        ["risk-v2", "BLOCK"],
      ]);
      assert.equal(dec.outcome, "Resolved");

      let lifecycle: SeamEvent | undefined;
      let sealed: SeamEvent | undefined;
      const kindsSeen = new Set<string>();
      for await (const ev of admin.streamEvents({ streamId: STREAM_ID, follow: false, ack: false })) {
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
      // The protocol pass (P7) retired v1-v3: the runtime seals v4 and nothing else, and this SDK
      // recomputes v4 and nothing else. Against a runtime that predates the pass this assertion is
      // the one that goes red, by design: a v3 record is cannot-verify here, not a guess.
      assert.equal(
        sealed!.payload!.schemaVersion,
        4,
        `record schema_version ${sealed!.payload!.schemaVersion}; this SDK recomputes only v4`,
      );
      assert.equal(sealed!.payload!.ciphertextDigest.length, 32);
      assert.equal(verifyStreamedRecordDigest(sealed!), true);
    } finally {
      proc.kill();
    }
  },
);
