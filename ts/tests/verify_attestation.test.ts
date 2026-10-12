// `verifyPartyAttestation` — the A14 network-mode counterparty check.
//
// Two layers: server-free unit tests that stub `trust` (the wrapper builds the right request and returns
// the server's boolean verdict, never rejecting on a `false`), and an env-gated live round-trip that
// registers a counterparty key on the management plane and verifies a valid / tampered / unknown
// attestation on the data plane — mirroring the runtime's A4 trio
// (`seamd/tests/grpc.rs::grpc_verify_party_attestation_trio`).
//
// The live valid case pins the runtime's committed **v2** chain-head KAT
// (`conformance/chain_head_attestation_v2_vector.json`: seed + precomputed signature over its own tenant),
// so the test does not re-derive the signature framing. It must be v2: the party is registered under a
// tenant, and since seam-runtime #835 step 4 a tenant's attestation verifies under v2 only (the v1 KAT
// relabelled to a tenant is refused). The server-free unit tests keep the shared v1 KAT from
// `conformance/vectors.json` (empty tenant), the SAME source `conformance.test.ts` reads.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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
import { governanceEnv, mintOperatorToken } from "./operator_token.js";

const BIN = process.env.SEAM_GRPC_BIN;
const SKIP = !BIN;
// ── The runtime chain_head_attestation KATs, from conformance/ ─────────────────────────────────────────
const readConformance = (name: string) =>
  JSON.parse(readFileSync(new URL(`../../conformance/${name}`, import.meta.url), "utf8"));
const VECTOR = readConformance("vectors.json").chain_head_attestation;
const V2_VECTOR = readConformance("chain_head_attestation_v2_vector.json");
// The tenant the v2 KAT is signed over. registerParty takes no tenant on the wire (the operator token's
// own `tenant` claim is what the runtime binds to; see RegisterPartyRequest), so the token is minted for
// this tenant and the party lands in the partition the signed attestation names.
const TENANT: string = V2_VECTOR.inputs.tenant;
const KAT_SEED = Uint8Array.from(Buffer.from(VECTOR.inputs.issuer_seed_hex, "hex"));

function attestationFrom(v: typeof VECTOR, tenant: string): ChainHeadAttestation {
  return create(ChainHeadAttestationSchema, {
    attestedLen: BigInt(v.inputs.attested_len),
    attestedHead: Uint8Array.from(Buffer.from(v.inputs.attested_head_hex, "hex")),
    attestedAt: BigInt(v.inputs.attested_at),
    issuerAid: v.issuer_aid as string,
    digestSchema: v.inputs.digest_schema,
    tenant,
    signature: Uint8Array.from(Buffer.from(v.signature_hex, "hex")),
  });
}
// The v1 KAT, with the EMPTY tenant it was signed for (v1 never signs a tenant, so since seam-runtime
// #835 step 4 it verifies only under ""). Used by the server-free unit tests.
const katAttestation = (): ChainHeadAttestation => attestationFrom(VECTOR, "");
// The v2 KAT: `tenant` (wire tag 7) is INSIDE the signature, so it is exactly the tenant the runtime
// signed over — any other value breaks verification.
const v2KatAttestation = (): ChainHeadAttestation => attestationFrom(V2_VECTOR, TENANT);

test("the v1 and v2 KATs share one issuer (the live test registers one pubkey)", () => {
  assert.equal(V2_VECTOR.inputs.issuer_seed_hex, VECTOR.inputs.issuer_seed_hex);
  assert.equal(V2_VECTOR.issuer_aid, VECTOR.issuer_aid);
});
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

/** registerParty is authority-establishing (rt-D) and, since seam-runtime #903 Phase 1, refuses a
 * fleet-wide operator — the mgmt plane's `operator_keys` trust root comes from the signed
 * governing root every spawn is handed (governanceEnv, seam-runtime #1156) so a tenant-bound `grant:create` token can authorize
 * it (seam-sdk#175 / seam-runtime#996). The data plane is unaffected: `operator_keys` is the trust root
 * for the management plane only, so verifyPartyAttestation stays dev-open as before. */
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
  "verifyPartyAttestation live: registered valid → true; tampered sig / tampered field / unknown → false",
  { skip: SKIP },
  async () => {
    await withPlanes(8209, 8210, async (dataAddr, mgmtUrl) => {
      const data = SeamClient.connect(`http://${dataAddr}`);
      const admin = SeamAdminClient.connect(mgmtUrl, {
        token: mintOperatorToken(["grant:create"], { tenant: TENANT }),
      });
      await admin.registerParty("bank-A", katPubkey());

      // Every call below sends the v2 KAT, whose SIGNED tenant is TENANT: registerParty bound "bank-A"
      // under TENANT (the operator token's claim, since RegisterPartyRequest has no tenant field of its
      // own), and verifyPartyAttestation looks the party up under the ATTESTATION's own tenant — since
      // seam-runtime #835 step 4 that is the signed tenant, verified under v2 only. A v1 attestation
      // relabelled to TENANT is refused there, which is why this cannot use the v1 KAT.

      // 1. a registered party's untampered attestation verifies
      assert.equal(await data.verifyPartyAttestation("bank-A", v2KatAttestation()), true);

      // 2. a tampered signature must not verify
      const badSig = v2KatAttestation();
      badSig.signature = Uint8Array.from(badSig.signature);
      badSig.signature[0] ^= 0x01;
      assert.equal(await data.verifyPartyAttestation("bank-A", badSig), false);

      // 3. a tampered field (part of the signed preimage) must not verify
      const badField = v2KatAttestation();
      badField.attestedLen += 1n;
      assert.equal(await data.verifyPartyAttestation("bank-A", badField), false);

      // 4. an unknown party never verifies
      assert.equal(await data.verifyPartyAttestation("bank-B", v2KatAttestation()), false);
    });
  },
);
