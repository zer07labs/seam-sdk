// seam-sdk#201: Agent.generate() and the schema-v1 bootstrap file (create/load).
// Mirrors python/tests/test_identity_file.py case by case, plus one cross-language case: a file written
// by Python's `create_identity_file` (the committed fixture) loads here with the AID Python derived.

import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import { dirname, join } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { inspect } from "node:util";

import {
  Agent,
  IdentityFileError,
  LoadedIdentity,
  createIdentityFile,
  loadIdentityFile,
} from "../src/index.js";
import { ENV_POINTER, identityFileBody } from "../src/identity.js";

const posix = process.platform !== "win32";
const FIELDS = { agentId: "ap-clerk", tenant: "acme", endpoint: "seam.example:443" };
const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "identity_v1_python.json");
// Derived by Python for the fixture's seed: `load_identity_file(FIXTURE).aid`.
const FIXTURE_AID = "aid:pubkey:ed25519:9x_uM2PCzXE8pt6di2RwwKCkod7W5kctdLdoIVtKep4";
const FIXTURE_SEED_HEX = "ddc1524b29efe5bc1b9e9ea141b2a4740ba3e4d52f781afa3c1ffb3a3970580c";

const dirs: string[] = [];
function tmpDir(): string {
  const d = fs.mkdtempSync(join(os.tmpdir(), "seam-identity-"));
  dirs.push(d);
  return d;
}
after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

function assertIdentityError(fn: () => unknown, match: RegExp | string): void {
  assert.throws(fn, (e: unknown) => {
    assert.ok(e instanceof IdentityFileError, `expected IdentityFileError, got ${String(e)}`);
    if (typeof match === "string") assert.ok(e.message.includes(match), e.message);
    else assert.match(e.message, match);
    return true;
  });
}

test("generate is 32 fresh CSPRNG bytes", () => {
  const a = Agent.generate();
  const b = Agent.generate();
  assert.equal(a.seed.length, 32);
  assert.notEqual(hex(a.seed), hex(b.seed));
  assert.notEqual(a.aid, b.aid);
});

test("round-trip AID equality", () => {
  const dir = tmpDir();
  const { path, aid } = createIdentityFile(join(dir, "id.json"), FIELDS);
  const loaded = loadIdentityFile(path);
  assert.equal(loaded.aid, aid);
  assert.equal(loaded.agent.aid, aid);
  assert.deepEqual([loaded.agentId, loaded.tenant, loaded.endpoint], ["ap-clerk", "acme", "seam.example:443"]);
});

test("create never returns the seed", () => {
  const dir = tmpDir();
  const result = createIdentityFile(join(dir, "id.json"), FIELDS);
  assert.deepEqual(Object.keys(result).sort(), ["aid", "path"]);
  assert.ok(Object.values(result).every((x) => typeof x === "string"));
  const seedHex = JSON.parse(fs.readFileSync(result.path, "utf8")).seed_hex as string;
  assert.ok(Object.values(result).every((x) => !x.includes(seedHex)));
  assert.ok(!JSON.stringify(result).includes(seedHex));
  assert.ok(!("seed" in result));
});

test("toString / inspect / JSON of a loaded identity do not print the seed", () => {
  const dir = tmpDir();
  const { path } = createIdentityFile(join(dir, "id.json"), FIELDS);
  const loaded = loadIdentityFile(path);
  assert.ok(loaded instanceof LoadedIdentity);
  const seedHex = hex(loaded.agent.seed);
  const seedDec = Array.from(loaded.agent.seed).join(", ");
  for (const rendered of [
    String(loaded),
    `${loaded}`,
    inspect(loaded),
    inspect(loaded, { depth: Infinity, showHidden: true }),
    inspect({ wrapped: loaded }, { depth: Infinity }),
    JSON.stringify(loaded),
  ]) {
    assert.ok(!rendered.includes(seedHex), rendered);
    assert.ok(!rendered.includes(seedDec), rendered);
    assert.ok(rendered.includes(loaded.aid), rendered);
  }
});

test("file is schema v1 with the adapters field names", () => {
  const dir = tmpDir();
  const { path } = createIdentityFile(join(dir, "id.json"), FIELDS);
  const data = JSON.parse(fs.readFileSync(path, "utf8"));
  assert.deepEqual(Object.keys(data), ["version", "seed_hex", "agent_id", "tenant", "endpoint"]);
  assert.equal(data.version, 1);
  assert.equal(data.seed_hex.length, 64);
});

test("mode is 0600 under umask 0", { skip: !posix && "POSIX file modes" }, () => {
  const dir = tmpDir();
  const old = process.umask(0);
  let path: string;
  try {
    ({ path } = createIdentityFile(join(dir, "id.json"), FIELDS));
  } finally {
    process.umask(old);
  }
  assert.equal(fs.lstatSync(path).mode & 0o777, 0o600);
});

test("second create refuses and leaves bytes unchanged", () => {
  const dir = tmpDir();
  const { path } = createIdentityFile(join(dir, "id.json"), FIELDS);
  const before = fs.readFileSync(path);
  assertIdentityError(() => createIdentityFile(path, FIELDS), "refusing to overwrite");
  assert.deepEqual(fs.readFileSync(path), before);
});

for (const dangling of [false, true]) {
  test(`symlink at the target is refused (dangling=${dangling})`, { skip: !posix && "POSIX symlinks" }, () => {
    const dir = tmpDir();
    const target = join(dir, "elsewhere.json");
    if (!dangling) fs.writeFileSync(target, "untouched");
    const link = join(dir, "id.json");
    fs.symlinkSync(target, link);
    assertIdentityError(() => createIdentityFile(link, FIELDS), "refusing to overwrite");
    assert.ok(fs.lstatSync(link).isSymbolicLink());
    if (dangling) assert.ok(!fs.existsSync(target));
    else assert.equal(fs.readFileSync(target, "utf8"), "untouched");
  });
}

test("no temp file is left behind", () => {
  const dir = tmpDir();
  const { path } = createIdentityFile(join(dir, "id.json"), FIELDS);
  assertIdentityError(() => createIdentityFile(path, FIELDS), "refusing to overwrite");
  assert.deepEqual(fs.readdirSync(dir).sort(), ["id.json"]);
});

for (const [field, key] of [
  ["agent_id", "agentId"],
  ["tenant", "tenant"],
  ["endpoint", "endpoint"],
] as const) {
  test(`empty ${field} is refused before anything is written`, () => {
    const dir = tmpDir();
    assertIdentityError(() => createIdentityFile(join(dir, "id.json"), { ...FIELDS, [key]: "" }), field);
    assert.deepEqual(fs.readdirSync(dir), []);
  });
}

test("an existing adapters file (extra keys) still loads", () => {
  const dir = tmpDir();
  const seed = Uint8Array.from({ length: 32 }, (_, i) => i);
  const p = join(dir, "partner.json");
  fs.writeFileSync(
    p,
    JSON.stringify({
      version: 1,
      seed_hex: hex(seed),
      agent_id: "qa-confirm",
      tenant: "t1",
      endpoint: "localhost:50051",
      comment: "extra keys are ignored",
    }),
  );
  const loaded = loadIdentityFile(p);
  assert.equal(hex(loaded.agent.seed), hex(seed));
  assert.equal(loaded.aid, new Agent(seed).aid);
});

test("env pointer is read when no path is given", () => {
  const dir = tmpDir();
  const { path, aid } = createIdentityFile(join(dir, "id.json"), FIELDS);
  const saved = process.env[ENV_POINTER];
  try {
    process.env[ENV_POINTER] = path;
    assert.equal(loadIdentityFile().aid, aid);
    delete process.env[ENV_POINTER];
    assertIdentityError(() => loadIdentityFile(), ENV_POINTER);
  } finally {
    if (saved === undefined) delete process.env[ENV_POINTER];
    else process.env[ENV_POINTER] = saved;
  }
});

for (const [data, match] of [
  [{ version: 2 }, "version"],
  [{ version: 1, seed_hex: "ab" }, "64 hex"],
  [{ version: 1, seed_hex: "zz".repeat(32) }, "not valid hex"],
  [{ version: 1, seed_hex: "ab".repeat(32), agent_id: "a", tenant: "t" }, "endpoint"],
  [[1, 2], "JSON object"],
] as const) {
  test(`malformed file is loud: ${match}`, () => {
    const dir = tmpDir();
    const p = join(dir, "bad.json");
    fs.writeFileSync(p, JSON.stringify(data));
    assertIdentityError(() => loadIdentityFile(p), match);
  });
}

test("missing file is loud", () => {
  const dir = tmpDir();
  assertIdentityError(() => loadIdentityFile(join(dir, "nope.json")), "not found");
});

// ── Cross-language ───────────────────────────────────────────────────────────────────────────────

test("a file written by Python's create_identity_file loads with Python's AID", () => {
  const loaded = loadIdentityFile(FIXTURE);
  assert.equal(loaded.aid, FIXTURE_AID);
  assert.equal(hex(loaded.agent.seed), FIXTURE_SEED_HEX);
  assert.deepEqual([loaded.agentId, loaded.tenant, loaded.endpoint], ["ap-clerk", "acmé", "seam.example:443"]);
});

test("the TS writer lays the file out byte-for-byte as Python does", () => {
  // Same seed + fields as the fixture -> the same bytes, including Python's ensure_ascii escape of "é".
  const body = identityFileBody(Buffer.from(FIXTURE_SEED_HEX, "hex"), {
    agentId: "ap-clerk",
    tenant: "acmé",
    endpoint: "seam.example:443",
  });
  assert.deepEqual(Buffer.from(body), fs.readFileSync(FIXTURE));
});
