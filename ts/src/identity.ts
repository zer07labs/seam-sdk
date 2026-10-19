// Identity custody: create and load the bootstrap file (schema v1) — seam-sdk#201.
//
// One JSON file plus one env pointer (`SEAM_BOOTSTRAP_FILE`). Python's `seam_sdk/identity.py` owns the
// schema; this module mirrors it so a file written by any SDK loads in every other:
//
//   {"version": 1, "seed_hex": "<64 hex>", "agent_id": "...", "tenant": "...", "endpoint": "host:port",
//    "aid": "aid:pubkey:ed25519:<43 b64url>"}
//
// `aid` is optional (seam-sdk#274, D-AID-RECORD): `createIdentityFile` records the derived AID as the
// last key, and the schema version stays 1. A file without it loads unchanged. When it is present,
// `loadIdentityFile` verifies it against the AID derived from `seed_hex` and refuses a wrong shape or a
// mismatch. Every loader since #201 ignores unknown keys, so such a file also loads in older releases.
//
// Unknown extra keys are ignored on load. The file layout is byte-for-byte Python's
// `json.dumps(..., indent=2) + "\n"` (ASCII-escaped), so the files are interchangeable.
//
// The seed leaves this module in exactly one direction: from disk into an `Agent` on load.
// `createIdentityFile` generates it, writes it, and returns `{ path, aid }` — never the seed.

import * as fs from "node:fs";
import * as nodePath from "node:path";
import { inspect } from "node:util";

import { Agent } from "./client.js";

/** Names the bootstrap file when {@link loadIdentityFile} is given no path. */
export const ENV_POINTER = "SEAM_BOOTSTRAP_FILE";
/** The only bootstrap schema this SDK reads and writes. */
export const SCHEMA_VERSION = 1;

// The shape of a recorded `aid`: the Ed25519 AID form, 32 bytes as unpadded b64url.
const AID_RE = /^aid:pubkey:ed25519:[A-Za-z0-9_-]{43}$/;

/** The bootstrap file is missing, malformed, fails validation, or cannot be created. Always loud.
 * `cause` carries the underlying fs/JSON error, when there is one. */
export class IdentityFileError extends Error {
  override readonly name: string = "IdentityFileError";
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
  }
}

/** The process identity loaded from a bootstrap file. The seed is held only inside `agent`; neither
 * `toString`, `util.inspect` nor `JSON.stringify` of this object prints it. */
export class LoadedIdentity {
  constructor(
    readonly agent: Agent,
    /** Registry identity for scope lookup (may equal the AID). */
    readonly agentId: string,
    readonly tenant: string,
    /** The data-plane endpoint this process talks to. */
    readonly endpoint: string,
  ) {
    Object.freeze(this);
  }

  get aid(): string {
    return this.agent.aid;
  }

  toString(): string {
    return (
      `LoadedIdentity(aid=${JSON.stringify(this.aid)}, agentId=${JSON.stringify(this.agentId)}, ` +
      `tenant=${JSON.stringify(this.tenant)}, endpoint=${JSON.stringify(this.endpoint)})`
    );
  }

  /** `JSON.stringify` gets the public fields only — never the agent, which holds the seed. */
  toJSON(): { aid: string; agentId: string; tenant: string; endpoint: string } {
    return { aid: this.aid, agentId: this.agentId, tenant: this.tenant, endpoint: this.endpoint };
  }

  /** `util.inspect` / `console.log` must not walk into `agent` (whose `seed` is a public field). */
  [inspect.custom](): string {
    return this.toString();
  }
}

function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function errCode(e: unknown): string | undefined {
  return typeof e === "object" && e !== null ? (e as { code?: string }).code : undefined;
}

function pyRepr(v: unknown): string {
  // Close enough to Python's `!r` for an error message; the value is attacker-free (it is our file).
  return v === undefined ? "None" : JSON.stringify(v);
}

/** Load the process identity from `path`, or from `$SEAM_BOOTSTRAP_FILE` when `path` is omitted.
 *
 * A recorded `aid` is verified, not trusted: it must have the AID shape (else `"aid is malformed"`) and
 * equal the AID derived from `seed_hex` (else `"recorded aid does not match seed_hex"`). A file without
 * `aid` loads as before. */
export function loadIdentityFile(path?: string): LoadedIdentity {
  const resolved = path ?? process.env[ENV_POINTER] ?? "";
  if (!resolved) {
    throw new IdentityFileError(
      `no bootstrap file: pass a path or set $${ENV_POINTER} (one JSON + env pointer is the custody contract)`,
    );
  }
  let raw: string;
  try {
    raw = fs.readFileSync(resolved, "utf8");
  } catch (e) {
    if (errCode(e) === "ENOENT") {
      throw new IdentityFileError(`bootstrap file not found: ${resolved}`, { cause: e });
    }
    throw new IdentityFileError(`cannot read bootstrap file ${resolved}: ${errText(e)}`, { cause: e });
  }
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch (e) {
    throw new IdentityFileError(`bootstrap file is not valid JSON: ${resolved}: ${errText(e)}`, { cause: e });
  }
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw new IdentityFileError(`bootstrap file is not a JSON object: ${resolved}`);
  }
  const obj = data as Record<string, unknown>;

  if (obj.version !== SCHEMA_VERSION) {
    throw new IdentityFileError(
      `bootstrap schema version ${pyRepr(obj.version)} unsupported (want ${SCHEMA_VERSION})`,
    );
  }
  const seedHex = obj.seed_hex ?? "";
  if (typeof seedHex !== "string" || seedHex.length !== 64) {
    throw new IdentityFileError("seed_hex must be exactly 64 hex chars (a 32-byte Ed25519 seed)");
  }
  if (!/^[0-9a-fA-F]{64}$/.test(seedHex)) {
    throw new IdentityFileError("seed_hex is not valid hex");
  }
  const seed = Uint8Array.from(Buffer.from(seedHex, "hex"));

  // A required field must be a non-empty string (as the Go SDK does; every writer emits strings).
  const missing = (["agent_id", "tenant", "endpoint"] as const).filter(
    (k) => typeof obj[k] !== "string" || obj[k] === "",
  );
  if (missing.length > 0) {
    throw new IdentityFileError(`bootstrap file missing required field(s): ${missing.join(", ")}`);
  }
  const hasAid = Object.prototype.hasOwnProperty.call(obj, "aid");
  if (hasAid && (typeof obj.aid !== "string" || !AID_RE.test(obj.aid))) {
    throw new IdentityFileError("aid is malformed");
  }
  const agent = new Agent(seed);
  if (hasAid && obj.aid !== agent.aid) {
    throw new IdentityFileError("recorded aid does not match seed_hex");
  }
  return new LoadedIdentity(
    agent,
    obj.agent_id as string,
    obj.tenant as string,
    obj.endpoint as string,
  );
}

/** The schema-v1 file bytes, laid out exactly as Python's `json.dumps(obj, indent=2) + "\n"`
 * (default `ensure_ascii=True`: every code unit outside printable ASCII is `\uXXXX`-escaped), with the
 * seed's derived `aid` as the last key. */
export function identityFileBody(
  seed: Uint8Array,
  fields: { agentId: string; tenant: string; endpoint: string },
): Uint8Array {
  const json = JSON.stringify(
    {
      version: SCHEMA_VERSION,
      seed_hex: Buffer.from(seed).toString("hex"),
      agent_id: fields.agentId,
      tenant: fields.tenant,
      endpoint: fields.endpoint,
      aid: new Agent(seed).aid,
    },
    null,
    2,
  ).replace(/[\u007f-￿]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
  return new TextEncoder().encode(json + "\n");
}

/**
 * Generate a new agent identity and write it to `path` as a schema-v1 bootstrap file.
 *
 * Returns `{ path, aid }`. The seed is never returned: load the file with {@link loadIdentityFile} in
 * the process that will use it. The file also records that `aid` as its last key, so the public
 * identity can be read back without the seed.
 *
 * The write is atomic and never clobbers. The bytes go to a sibling temp file opened
 * `O_CREAT|O_EXCL|O_WRONLY|O_NOFOLLOW` with mode `0600` (re-applied with `fchmod` so the umask cannot
 * widen it), are `fsync`-ed, and are then published with a hard link, which fails if anything — a file,
 * a directory, a symlink, a dangling symlink — already exists at `path`. The temp name is then unlinked
 * and the directory `fsync`-ed. A reader never sees a partial file, and an existing file is left
 * byte-for-byte unchanged. Throws {@link IdentityFileError} on refusal.
 */
export function createIdentityFile(
  path: string,
  fields: { agentId: string; tenant: string; endpoint: string },
): { path: string; aid: string } {
  for (const [name, value] of [
    ["agent_id", fields?.agentId],
    ["tenant", fields?.tenant],
    ["endpoint", fields?.endpoint],
  ] as const) {
    if (typeof value !== "string" || value === "") {
      throw new IdentityFileError(`${name} must be a non-empty string`);
    }
  }

  const final = path;
  const agent = Agent.generate();
  const body = identityFileBody(agent.seed, fields);

  const directory = nodePath.dirname(nodePath.resolve(final));
  const nonce = Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(8))).toString("hex");
  const tmp = nodePath.join(directory, `.${nodePath.basename(final)}.${nonce}.tmp`);
  const { O_WRONLY, O_CREAT, O_EXCL, O_NOFOLLOW } = fs.constants;
  const flags = O_WRONLY | O_CREAT | O_EXCL | (O_NOFOLLOW ?? 0);

  let fd: number;
  try {
    fd = fs.openSync(tmp, flags, 0o600);
  } catch (e) {
    throw new IdentityFileError(`cannot create bootstrap file in ${directory}: ${errText(e)}`, { cause: e });
  }
  try {
    try {
      if (process.platform !== "win32") fs.fchmodSync(fd, 0o600);
      let off = 0;
      while (off < body.length) off += fs.writeSync(fd, body, off, body.length - off);
      fs.fsyncSync(fd);
    } catch (e) {
      throw new IdentityFileError(`cannot write bootstrap file in ${directory}: ${errText(e)}`, { cause: e });
    } finally {
      fs.closeSync(fd);
    }
    try {
      fs.linkSync(tmp, final);
    } catch (e) {
      if (errCode(e) === "EEXIST") {
        throw new IdentityFileError(`refusing to overwrite existing path: ${final}`, { cause: e });
      }
      throw new IdentityFileError(`cannot publish bootstrap file ${final}: ${errText(e)}`, { cause: e });
    }
  } finally {
    try {
      fs.unlinkSync(tmp);
    } catch (e) {
      if (errCode(e) !== "ENOENT") throw e;
    }
  }
  fsyncDir(directory);
  return { path: final, aid: agent.aid };
}

function fsyncDir(directory: string): void {
  // Makes the new directory entry durable on POSIX. Windows cannot open a directory; skip there.
  if (process.platform === "win32") return;
  let fd: number;
  try {
    fd = fs.openSync(directory, fs.constants.O_RDONLY);
  } catch (e) {
    throw new IdentityFileError(`cannot fsync ${directory}: ${errText(e)}`, { cause: e });
  }
  try {
    fs.fsyncSync(fd);
  } catch (e) {
    throw new IdentityFileError(`cannot fsync ${directory}: ${errText(e)}`, { cause: e });
  } finally {
    fs.closeSync(fd);
  }
}
