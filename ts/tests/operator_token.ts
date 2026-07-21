// Test-only operator-token minter — simulates a control-plane-minted management token.
//
// The management plane authenticates compact-JWS operator tokens against the `operator_keys` trust root
// installed from a SEAM_REGISTRY_SNAPSHOT (rt-D / CP-18d; the shared SEAM_MGMT_TOKEN bearer was removed in
// seam-runtime #175). This mints one with the golden operator key whose PUBLIC half is pinned in
// conformance/registry_snapshot_operator_keys.json — so a runtime spawned with that snapshot (and no shared
// token) accepts these tokens and refuses everything else. The SEED is a well-known TEST key.

import { ed25519 } from "@noble/curves/ed25519";
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

/** Return `token` with its JWS signature corrupted — a valid shape, an invalid signature. */
export function tamperSignature(token: string): string {
  const head = token.slice(0, token.lastIndexOf("."));
  return `${head}.${token.endsWith("AA") ? "BB" : "AA"}`;
}
