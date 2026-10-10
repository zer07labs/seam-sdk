// `verifyPartyAnchor`'s `tenant` option (seam-sdk#172 / seam-runtime #903 Phase 3).
//
// Two layers, mirroring `verify_attestation.test.ts`:
//   * server-free unit tests that stub `trust` (the wrapper defaults `tenant` to `""` when omitted
//     and forwards it verbatim when given, and never rejects on a `false`);
//   * an env-gated live round-trip (register a counterparty key on the management plane under a
//     tenant-bound operator, then verify a valid / tampered / unknown / wrong-tenant anchor on the
//     data plane).
//
// Unlike `verifyPartyAttestation`'s `ChainHeadAttestation`, which carries its own `tenant` field,
// `Anchor` is deliberately tenant-agnostic (`seam-runtime/docs/specs/audit-anchor.md`) — tenant lives
// on `VerifyAnchorRequest` itself, a sibling of `partyId`/`anchor`. And unlike that KAT-pinned test, no
// conformance vector exists for `Anchor` (`conformance/vectors.json` has no `anchor` key): the signing
// payload — `SHA256(chainHead || littleEndianU64(timestampMillis))`, then a detached Ed25519 signature
// over that digest — has no domain separator or framing ambiguity, so this test self-signs.
//
// Because `registerParty`'s gRPC/facade layer refuses a fleet-wide (no-tenant-claim) operator since
// seam-runtime #903 Phase 1, a live test can no longer register an UNtenanted party at all — the
// "defaults to the untenanted partition" guarantee is proven by the server-free unit tests instead.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { connect as tcpConnect } from "node:net";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { create } from "@bufbuild/protobuf";
import { SeamClient } from "../src/client.js";
import { SeamAdminClient } from "../src/admin.js";
import { AnchorSchema, type Anchor } from "../gen/seam/api/v1/seam_pb.js";
import { governanceEnv, mintOperatorToken } from "./operator_token.js";

const BIN = process.env.SEAM_GRPC_BIN;
const SKIP = !BIN;
// Any tenant id — registerParty takes none on the wire (the operator token's own `tenant` claim is
// what the runtime binds to; see RegisterPartyRequest), so this pins AUTH, not a registration scope.
const TENANT = "verify-anchor-counterparties";

// ── A self-signed Anchor — no conformance vector needed (see module comment above) ──────────────────

function leU64(n: bigint): Uint8Array {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(n);
  return new Uint8Array(buf);
}

function anchorPayload(chainHead: Uint8Array, timestampMillis: bigint): Uint8Array {
  return sha256(Buffer.concat([Buffer.from(chainHead), Buffer.from(leU64(timestampMillis))]));
}

function signedAnchor(
  seed: Uint8Array,
  opts?: { chainHead?: Uint8Array; timestampMillis?: bigint },
): Anchor {
  const chainHead = opts?.chainHead ?? new Uint8Array(32).fill(0x68); // "h" * 32
  const timestampMillis = opts?.timestampMillis ?? 1_700_000_000_000n;
  const signature = ed25519.sign(anchorPayload(chainHead, timestampMillis), seed);
  return create(AnchorSchema, { chainHead, timestampMillis, signature });
}

const ANCHOR_SEED = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const anchorPubkey = () => ed25519.getPublicKey(ANCHOR_SEED);

// ── Unit: the wrapper contract, server-free ───────────────────────────────────────────────────────────

/** A SeamClient whose `trust` stub records the request and returns a preset `valid`. */
function clientWithTrust(valid: boolean): {
  client: SeamClient;
  seen: () => { partyId: string; anchor: Anchor; tenant: string } | undefined;
} {
  const client = SeamClient.connect("http://127.0.0.1:1"); // lazy transport; never dialed
  let captured: { partyId: string; anchor: Anchor; tenant: string } | undefined;
  (client as unknown as { trust: unknown }).trust = {
    verifyPartyAnchor: async (req: { partyId: string; anchor: Anchor; tenant: string }) => {
      captured = req;
      return { valid };
    },
  };
  return { client, seen: () => captured };
}

test("verifyPartyAnchor: omitting tenant sends \"\" on the wire", async () => {
  const { client, seen } = clientWithTrust(true);
  const anchor = signedAnchor(ANCHOR_SEED);
  assert.equal(await client.verifyPartyAnchor("bank-A", anchor), true);
  assert.equal(seen()?.partyId, "bank-A");
  assert.equal(seen()?.tenant, "");
  assert.deepEqual(seen()?.anchor.chainHead, anchor.chainHead);
});

test("verifyPartyAnchor: an explicit tenant is forwarded verbatim", async () => {
  const { client, seen } = clientWithTrust(true);
  const anchor = signedAnchor(ANCHOR_SEED);
  assert.equal(await client.verifyPartyAnchor("bank-A", anchor, { tenant: "acme" }), true);
  assert.equal(seen()?.tenant, "acme");
});

test("verifyPartyAnchor: a false verdict resolves false, never rejects", async () => {
  const { client } = clientWithTrust(false);
  const anchor = signedAnchor(ANCHOR_SEED);
  assert.equal(await client.verifyPartyAnchor("bank-A", anchor, { tenant: "acme" }), false);
});

// ── Live: register (mgmt plane) → verify (data plane), env-gated ─────────────────────────────────────

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

/** registerParty is authority-establishing (rt-D) and, since seam-runtime #903 Phase 1, refuses a
 * fleet-wide operator — the mgmt plane's `operator_keys` trust root comes from the signed
 * governing root every spawn is handed (governanceEnv, seam-runtime #1156) so a tenant-bound `grant:create` token can authorize
 * it. The data plane is unaffected: `operator_keys` is the trust root for the management plane only, so
 * verifyPartyAnchor stays dev-open as before. */
async function withPlanes(
  dataPort: number,
  mgmtPort: number,
  fn: (dataAddr: string, mgmtUrl: string) => Promise<void>,
): Promise<void> {
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
    await fn(`127.0.0.1:${dataPort}`, `http://127.0.0.1:${mgmtPort}`);
  } finally {
    proc.kill();
  }
}

test(
  "verifyPartyAnchor live: registered + matching tenant → true; tampered / unknown / wrong tenant / omitted tenant → false",
  { skip: SKIP },
  async () => {
    await withPlanes(8211, 8212, async (dataAddr, mgmtUrl) => {
      const data = SeamClient.connect(`http://${dataAddr}`);
      const admin = SeamAdminClient.connect(mgmtUrl, {
        token: mintOperatorToken(["grant:create"], { tenant: TENANT }),
      });
      await admin.registerParty("bank-A", anchorPubkey());

      // Unlike verifyPartyAttestation (whose tenant lives on the ATTESTATION message), Anchor is
      // tenant-agnostic: the tenant is the caller's own option, a sibling of partyId/anchor. It must
      // match the registration tenant (TENANT) or an otherwise-valid anchor still comes back false,
      // having been looked up in the wrong partition.

      // 1. a registered party's untampered anchor, with the matching tenant, verifies
      const anchor = signedAnchor(ANCHOR_SEED);
      assert.equal(
        await data.verifyPartyAnchor("bank-A", anchor, { tenant: TENANT }),
        true,
      );

      // 2. a tampered signature must not verify
      const badSig = signedAnchor(ANCHOR_SEED);
      badSig.signature = Uint8Array.from(badSig.signature);
      badSig.signature[0] ^= 0x01;
      assert.equal(await data.verifyPartyAnchor("bank-A", badSig, { tenant: TENANT }), false);

      // 3. a tampered field (timestampMillis is part of the signed preimage) must not verify
      const badField = signedAnchor(ANCHOR_SEED);
      badField.timestampMillis += 1n;
      assert.equal(await data.verifyPartyAnchor("bank-A", badField, { tenant: TENANT }), false);

      // 4. an unknown party never verifies
      assert.equal(
        await data.verifyPartyAnchor("bank-B", anchor, { tenant: TENANT }),
        false,
      );

      // 5. a different tenant never verifies this party's anchor
      assert.equal(
        await data.verifyPartyAnchor("bank-A", anchor, { tenant: "some-other-tenant" }),
        false,
      );

      // 6. omitting tenant defaults to "" (the untenanted partition) — also wrong for this party
      assert.equal(await data.verifyPartyAnchor("bank-A", anchor), false);
    });
  },
);
