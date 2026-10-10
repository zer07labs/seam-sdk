// `verifyPartyAttestation` — the A14 network-mode counterparty check.
//
// Two layers: server-free unit tests that stub `trust` (the wrapper builds the right request and returns
// the server's boolean verdict, never rejecting on a `false`), and an env-gated live round-trip that
// registers a counterparty key on the management plane and verifies a valid / tampered / unknown
// attestation on the data plane — mirroring the runtime's A4 trio
// (`seamd/tests/grpc.rs::grpc_verify_party_attestation_trio`).
//
// The live valid case pins the runtime's committed `chain_head_attestation` KAT (seed + precomputed
// signature), so the test does not re-derive the signature framing. Loaded from
// `conformance/vectors.json`'s `chain_head_attestation` entry — the SAME source `conformance.test.ts`
// reads for the signature-verification unit test — so a runtime KAT regen updates one file and reddens
// both tests, instead of leaving a hand-copied literal here silently stale.

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
// Any tenant id — registerParty takes none on the wire (the operator token's own `tenant` claim is what
// the runtime binds to; see RegisterPartyRequest), so this pins AUTH, not a registration scope.
const TENANT = "verify-counterparties";

// ── The runtime chain_head_attestation KAT, from conformance/vectors.json ────────────────────────────
const vectors = JSON.parse(
  readFileSync(new URL("../../conformance/vectors.json", import.meta.url), "utf8"),
);
const VECTOR = vectors.chain_head_attestation;
const KAT_SEED = Uint8Array.from(Buffer.from(VECTOR.inputs.issuer_seed_hex, "hex"));
// `tenant` (wire tag 7) is UNSIGNED — setting it here never invalidates the KAT signature, which is
// computed over the preimage without it. Defaults to "" (the untenanted/fleet partition), matching
// every pre-#903 caller; the live test below overrides it to match the tenant its operator token
// registered the party under.
function katAttestation(opts?: { tenant?: string }): ChainHeadAttestation {
  return create(ChainHeadAttestationSchema, {
    attestedLen: BigInt(VECTOR.inputs.attested_len),
    attestedHead: Uint8Array.from(Buffer.from(VECTOR.inputs.attested_head_hex, "hex")),
    attestedAt: BigInt(VECTOR.inputs.attested_at),
    issuerAid: VECTOR.issuer_aid as string,
    digestSchema: VECTOR.inputs.digest_schema,
    tenant: opts?.tenant ?? "",
    signature: Uint8Array.from(Buffer.from(VECTOR.signature_hex, "hex")),
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

      // Every call below carries `tenant: TENANT` on the attestation: registerParty bound "bank-A"
      // under TENANT (the operator token's claim, since RegisterPartyRequest has no tenant field of
      // its own), and verifyPartyAttestation looks the party up under the ATTESTATION's own (unsigned)
      // tenant, not the caller's — the two must agree or a correctly-registered, untampered
      // attestation still comes back false, having found no party in the (wrong) tenant partition it
      // looked under.

      // 1. a registered party's untampered attestation verifies
      assert.equal(
        await data.verifyPartyAttestation("bank-A", katAttestation({ tenant: TENANT })),
        true,
      );

      // 2. a tampered signature must not verify
      const badSig = katAttestation({ tenant: TENANT });
      badSig.signature = Uint8Array.from(badSig.signature);
      badSig.signature[0] ^= 0x01;
      assert.equal(await data.verifyPartyAttestation("bank-A", badSig), false);

      // 3. a tampered field (part of the signed preimage) must not verify
      const badField = katAttestation({ tenant: TENANT });
      badField.attestedLen += 1n;
      assert.equal(await data.verifyPartyAttestation("bank-A", badField), false);

      // 4. an unknown party never verifies
      assert.equal(
        await data.verifyPartyAttestation("bank-B", katAttestation({ tenant: TENANT })),
        false,
      );
    });
  },
);
