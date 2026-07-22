// `verifyPartyAttestation` — the A14 network-mode counterparty check.
//
// Two layers: server-free unit tests that stub `trust` (the wrapper builds the right request and returns
// the server's boolean verdict, never rejecting on a `false`), and an env-gated live round-trip that
// registers a counterparty key on the management plane and verifies a valid / tampered / unknown
// attestation on the data plane — mirroring the runtime's A4 trio
// (`seamd/tests/grpc.rs::grpc_verify_party_attestation_trio`).
//
// The live valid case pins the runtime's committed `chain_head_attestation` KAT (seed + precomputed
// signature), so the test does not re-derive the signature framing. Regenerated from seam-runtime
// conformance_vectors.json `chain_head_attestation`.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { connect as tcpConnect } from "node:net";
import { ed25519 } from "@noble/curves/ed25519";
import { create } from "@bufbuild/protobuf";
import { SeamClient } from "../src/client.js";
import { SeamAdminClient } from "../src/admin.js";
import {
  ChainHeadAttestationSchema,
  type ChainHeadAttestation,
} from "../gen/seam/event/v1/seam_event_pb.js";

const BIN = process.env.SEAM_GRPC_BIN;
const SKIP = !BIN;

// ── The runtime chain_head_attestation KAT ────────────────────────────────────────────────────────────
const KAT_SEED = Uint8Array.from(Buffer.from("07".repeat(32), "hex"));
function katAttestation(): ChainHeadAttestation {
  return create(ChainHeadAttestationSchema, {
    attestedLen: 1000n,
    attestedHead: Uint8Array.from(Buffer.from("ab".repeat(32), "hex")),
    attestedAt: 1700000000000n,
    issuerAid: "aid:pubkey:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw",
    digestSchema: 2,
    signature: Uint8Array.from(
      Buffer.from(
        "5169458689b92af81fbbfbd1bd07aff82cb68993919837232a1b54204a0e565e" +
          "e58791b607c40a48dae6a9dbf8c6129e7028fdbd0e14095d7a4c0a99c775a90a",
        "hex",
      ),
    ),
  });
}
const katPubkey = () => ed25519.getPublicKey(KAT_SEED);

// ── Unit: the wrapper contract, server-free ───────────────────────────────────────────────────────────

/** A SeamClient whose `trust` stub records the request and returns a preset `valid`. */
function clientWithTrust(valid: boolean): {
  client: SeamClient;
  seen: () => { partyId: string; attestation: ChainHeadAttestation } | undefined;
} {
  const client = SeamClient.connect("http://127.0.0.1:1"); // lazy transport; never dialed
  let captured:
    | { partyId: string; attestation: ChainHeadAttestation }
    | undefined;
  (client as unknown as { trust: unknown }).trust = {
    verifyPartyAttestation: async (req: {
      partyId: string;
      attestation: ChainHeadAttestation;
    }) => {
      captured = req;
      return { valid };
    },
  };
  return { client, seen: () => captured };
}

test("verifyPartyAttestation: builds the request and returns true", async () => {
  const { client, seen } = clientWithTrust(true);
  const att = katAttestation();
  assert.equal(await client.verifyPartyAttestation("bank-A", att), true);
  assert.equal(seen()?.partyId, "bank-A");
  assert.equal(seen()?.attestation.attestedLen, att.attestedLen);
  assert.deepEqual(seen()?.attestation.signature, att.signature);
});

test("verifyPartyAttestation: a false verdict resolves false, never rejects", async () => {
  const { client } = clientWithTrust(false);
  assert.equal(await client.verifyPartyAttestation("bank-A", katAttestation()), false);
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

async function withPlanes(
  dataPort: number,
  mgmtPort: number,
  fn: (dataAddr: string, mgmtUrl: string) => Promise<void>,
): Promise<void> {
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
    await fn(`127.0.0.1:${dataPort}`, `http://127.0.0.1:${mgmtPort}`);
  } finally {
    proc.kill();
  }
}

test(
  "verifyPartyAttestation live: registered valid → true; tampered sig / tampered field / unknown → false",
  { skip: SKIP },
  async () => {
    await withPlanes(8209, 8210, async (dataAddr, mgmtUrl) => {
      const data = SeamClient.connect(`http://${dataAddr}`);
      const admin = SeamAdminClient.connect(mgmtUrl);
      await admin.registerParty("bank-A", katPubkey());

      // 1. a registered party's untampered attestation verifies
      assert.equal(await data.verifyPartyAttestation("bank-A", katAttestation()), true);

      // 2. a tampered signature must not verify
      const badSig = katAttestation();
      badSig.signature = Uint8Array.from(badSig.signature);
      badSig.signature[0] ^= 0x01;
      assert.equal(await data.verifyPartyAttestation("bank-A", badSig), false);

      // 3. a tampered field (part of the signed preimage) must not verify
      const badField = katAttestation();
      badField.attestedLen += 1n;
      assert.equal(await data.verifyPartyAttestation("bank-A", badField), false);

      // 4. an unknown party never verifies
      assert.equal(await data.verifyPartyAttestation("bank-B", katAttestation()), false);
    });
  },
);
