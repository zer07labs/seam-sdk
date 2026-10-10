// Test-only operator-token minter — simulates a control-plane-minted management token.
//
// The management plane authenticates compact-JWS operator tokens against the `operator_keys` of the
// signed governing root (seam-runtime #1156; the shared SEAM_MGMT_TOKEN bearer was removed in #175). This
// mints one with the golden operator key whose PUBLIC half that root carries (python/tests/governing_root.py)
// — so a runtime spawned with `governanceEnv()` accepts these tokens and refuses everything else. The SEED
// is a well-known TEST key.

import { ed25519 } from "@noble/curves/ed25519";
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// The golden operator key (seed → the public_key_hex pinned in the snapshot fixture's operator_keys).
// Matches seam-runtime/crates/seamd/tests/scoped_auth_grpc.rs (SEED_HEX / PUBKEY_HEX).
const SEED_HEX = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
const PUBKEY_HEX = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";

const enc = new TextEncoder();
function b64url(b: Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}

/** A valid compact-JWS operator token carrying `scopes`, signed by the golden operator key.
 *
 * `opts.tenant`, when given, binds the token to that tenant (U-RT-6) — required since seam-runtime
 * #903 Phase 1 for any operator calling `registerParty`/`removeParty`, which now refuse a fleet-wide
 * (no-tenant-claim) operator (seam-runtime's own `scoped_auth_grpc.rs::mint_with_tenant`). Omitted
 * (the default) mints a fleet-wide token, byte-identical to the pre-#903 shape. */
export function mintOperatorToken(
  scopes: string[],
  opts?: { aud?: string; ttlSecs?: number; tenant?: string },
): string {
  const iat = Math.floor(Date.now() / 1000);
  const aud = opts?.aud ?? "seam-runtime";
  const exp = iat + (opts?.ttlSecs ?? 600);
  const header = JSON.stringify({ alg: "EdDSA", typ: "JWT", kid: PUBKEY_HEX });
  // A fresh jti on every mint: a destructive-scope verb requires one and burns it, so mint per
  // destructive request (seam-runtime testing.rs `demo_operator_bearer`).
  const claims: Record<string, unknown> = { sub: "op-test", scopes, aud, iat, exp, jti: randomUUID() };
  if (opts?.tenant !== undefined) claims.tenant = opts.tenant;
  const payload = JSON.stringify(claims);
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

/** The env that points a spawned seam-grpc at a signed governing root (seam-runtime #1156: no root is a
 * boot refusal, and SEAM_DEV_INSECURE installs no governance). Inherited as-is when the caller's env
 * already carries SEAM_CONFIG_ROOT_URL (CI exports one); otherwise the default root + demo tenant
 * document are written to a temp dir by python/tests/governing_root.py, the single writer of these
 * documents, so the two suites cannot drift. */
export function governanceEnv(): NodeJS.ProcessEnv {
  if (process.env.SEAM_CONFIG_ROOT_URL) return {};
  const script = fileURLToPath(new URL("../../python/tests/governing_root.py", import.meta.url));
  const venv = fileURLToPath(new URL("../../python/.venv/bin/python", import.meta.url));
  const python = existsSync(venv) ? venv : "python3";
  const dir = mkdtempSync(join(tmpdir(), "seam-governance-"));
  const out = execFileSync(python, [script, dir], { encoding: "utf8" });
  const env: NodeJS.ProcessEnv = {};
  for (const line of out.split("\n")) {
    const i = line.indexOf("=");
    if (i > 0) env[line.slice(0, i)] = line.slice(i + 1);
  }
  return env;
}
