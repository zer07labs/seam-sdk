// Test-only operator-token minter — simulates a control-plane-minted management token.
//
// The management plane authenticates compact-JWS operator tokens against the `operator_keys` trust root
// installed from a SEAM_REGISTRY_SNAPSHOT (rt-D / CP-18d; the shared SEAM_MGMT_TOKEN bearer was removed in
// seam-runtime #175). This mints one with the golden operator key whose PUBLIC half is pinned in
// conformance/registry_snapshot_operator_keys.json — so a runtime spawned with that snapshot (and no shared
// token) accepts these tokens and refuses everything else. The SEED is a well-known TEST key.

import { ed25519 } from "@noble/curves/ed25519";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// The golden operator key (seed → the public_key_hex pinned in the snapshot fixture's operator_keys).
// Matches seam-runtime/crates/seamd/tests/scoped_auth_grpc.rs (SEED_HEX / PUBKEY_HEX).
const SEED_HEX = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
const PUBKEY_HEX = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";

/** Path to the operator-keys registry snapshot to hand the runtime via SEAM_REGISTRY_SNAPSHOT. */
export const REGISTRY_SNAPSHOT_PATH = fileURLToPath(
  new URL("../../conformance/registry_snapshot_operator_keys.json", import.meta.url),
);

const enc = new TextEncoder();
function b64url(b: Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}

/** A valid compact-JWS operator token carrying `scopes`, signed by the golden operator key. */
export function mintOperatorToken(
  scopes: string[],
  opts?: { aud?: string; ttlSecs?: number },
): string {
  const iat = Math.floor(Date.now() / 1000);
  const aud = opts?.aud ?? "seam-runtime";
  const exp = iat + (opts?.ttlSecs ?? 600);
  const header = JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: PUBKEY_HEX });
  const payload = JSON.stringify({ sub: "op-test", scopes, aud, iat, exp });
  const signing = `${b64url(enc.encode(header))}.${b64url(enc.encode(payload))}`;
  const sig = ed25519.sign(enc.encode(signing), Buffer.from(SEED_HEX, "hex"));
  return `${signing}.${b64url(sig)}`;
}

/** Return `token` with its JWS signature corrupted — same 64-byte length (so this exercises the
 * signature-VERIFICATION path, not a length check), a flipped bit making it invalid. */
export function tamperSignature(token: string): string {
  const i = token.lastIndexOf(".");
  const sig = Buffer.from(token.slice(i + 1), "base64url");
  sig[0] ^= 0x01;
  return `${token.slice(0, i)}.${b64url(sig)}`;
}

/** Detach-sign a registry snapshot so the runtime will actually install it.
 *
 * Returns `[pubkeyHex, sigPath]` for SEAM_SNAPSHOT_PUBKEY and SEAM_REGISTRY_SNAPSHOT_SIG.
 *
 * A snapshot carrying a trust-bearing section — `operator_keys`, `capability_registry` or
 * `namespaces` — must be signature-verified before the runtime installs it, and a current runtime
 * REFUSES TO BOOT without that. Anyone who can influence the file could otherwise install their own
 * operator key and own the management plane.
 *
 * This harness spawned an unsigned snapshot, so on a current runtime the server never came up and the
 * management-plane test failed with a bare `no server`. Nobody noticed because the CI job that runs
 * these has never executed — see the note on `integration` in .github/workflows/ci.yml.
 *
 * `SEAM_ALLOW_UNSIGNED_SNAPSHOT=1` would also work and is the wrong choice: it is the runtime's own
 * migration escape hatch for the signing rollout. Signing means this exercises the path production
 * uses and will not break when the hatch is removed. Mirrors python/tests/operator_token.py's
 * `sign_snapshot`; the two must stay in step.
 *
 * The signing key is deliberately NOT the operator key above — snapshot-signature verification is
 * independent of the snapshot's own operator_keys trust root.
 */
export function signSnapshot(snapshotPath: string): [string, string] {
  const data = readFileSync(snapshotPath);
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) seed[i] = i; // well-known TEST key
  const sigPath = join(mkdtempSync(join(tmpdir(), "seam-snap-")), "snapshot.sig");
  writeFileSync(sigPath, Buffer.from(ed25519.sign(data, seed)).toString("hex"));
  return [Buffer.from(ed25519.getPublicKey(seed)).toString("hex"), sigPath];
}
