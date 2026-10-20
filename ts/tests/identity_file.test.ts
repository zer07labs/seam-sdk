// seam-sdk#201: Agent.generate() and the schema-v1 bootstrap file (create/load).
// Mirrors python/tests/test_identity_file.py case by case, plus one cross-language case: a file written
// by Python's `create_identity_file` (the committed fixture) loads here with the AID Python derived.

import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import { dirname, join } from "node:path";
import { after, mock, test } from "node:test";
import { fileURLToPath } from "node:url";
import { inspect } from "node:util";

import {
  Agent,
  IdentityFacts,
  IdentityFileError,
  LoadedIdentity,
  createIdentityFile,
  loadIdentityFacts,
  loadIdentityFile,
} from "../src/index.js";
import { ENV_POINTER, identityFileBody, seedCodec } from "../src/identity.js";

const posix = process.platform !== "win32";
const FIELDS = { agentId: "ap-clerk", tenant: "acme", endpoint: "seam.example:443" };
const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
// The pre-#274 layout (no `aid`): the legacy case.
const FIXTURE = join(FIXTURES, "identity_v1_python.json");
// Written by Python's writer from FIXTURE_SEED_HEX (seam-sdk#274): records `aid` as the last key.
const AID_FIXTURE = join(FIXTURES, "identity_v1_aid_python.json");
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
  assert.deepEqual(Object.keys(data), ["version", "seed_hex", "agent_id", "tenant", "endpoint", "aid"]);
  assert.equal(data.version, 1);
  assert.equal(data.seed_hex.length, 64);
});

test("a created file records the returned aid", () => {
  const dir = tmpDir();
  const { path, aid } = createIdentityFile(join(dir, "id.json"), FIELDS);
  const data = JSON.parse(fs.readFileSync(path, "utf8"));
  assert.equal(data.aid, aid);
  assert.equal(new Agent(Buffer.from(data.seed_hex, "hex")).aid, aid);
});

function withAid(aid: unknown): Record<string, unknown> {
  return { version: 1, seed_hex: FIXTURE_SEED_HEX, agent_id: "a", tenant: "t", endpoint: "e:1", aid };
}

for (const [name, aid, message] of [
  ["mismatch", new Agent(Uint8Array.from({ length: 32 }, (_, i) => i)).aid, "recorded aid does not match seed_hex"],
  ["short", FIXTURE_AID.slice(0, -1), "aid is malformed"],
  ["long", FIXTURE_AID + "A", "aid is malformed"],
  ["wrong-alg", FIXTURE_AID.replace("ed25519", "ed448"), "aid is malformed"],
  ["non-b64url", FIXTURE_AID.slice(0, -1) + "=", "aid is malformed"],
  ["empty", "", "aid is malformed"],
  ["null", null, "aid is malformed"],
  ["number", 42, "aid is malformed"],
  ["list", [FIXTURE_AID], "aid is malformed"],
] as const) {
  test(`a bad recorded aid is refused: ${name}`, () => {
    const dir = tmpDir();
    const p = join(dir, "bad.json");
    fs.writeFileSync(p, JSON.stringify(withAid(aid)));
    assert.throws(
      () => loadIdentityFile(p),
      (e: unknown) => e instanceof IdentityFileError && e.message === message,
    );
  });
}

test("a matching recorded aid loads", () => {
  const dir = tmpDir();
  const p = join(dir, "ok.json");
  fs.writeFileSync(p, JSON.stringify(withAid(FIXTURE_AID)));
  assert.equal(loadIdentityFile(p).aid, FIXTURE_AID);
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

test("a legacy file written by Python (no aid) loads with Python's AID", () => {
  assert.ok(!("aid" in JSON.parse(fs.readFileSync(FIXTURE, "utf8"))));
  const loaded = loadIdentityFile(FIXTURE);
  assert.equal(loaded.aid, FIXTURE_AID);
  assert.equal(hex(loaded.agent.seed), FIXTURE_SEED_HEX);
  assert.deepEqual([loaded.agentId, loaded.tenant, loaded.endpoint], ["ap-clerk", "acmé", "seam.example:443"]);
});

test("a file written by Python with a recorded aid loads with that aid", () => {
  const loaded = loadIdentityFile(AID_FIXTURE);
  assert.equal(loaded.aid, FIXTURE_AID);
  assert.equal(JSON.parse(fs.readFileSync(AID_FIXTURE, "utf8")).aid, FIXTURE_AID);
  assert.equal(hex(loaded.agent.seed), FIXTURE_SEED_HEX);
});

test("the TS writer lays the file out byte-for-byte as Python does", () => {
  // Same seed + fields as the fixture -> the same bytes, including Python's ensure_ascii escape of "é"
  // and the recorded `aid` as the last key.
  const body = identityFileBody(Buffer.from(FIXTURE_SEED_HEX, "hex"), {
    agentId: "ap-clerk",
    tenant: "acmé",
    endpoint: "seam.example:443",
  });
  assert.deepEqual(Buffer.from(body), fs.readFileSync(AID_FIXTURE));
});

// ── seam-sdk#274 (D-FACTS-API, D-LEGACY-AID, D-FACTS-CHECKS): the seed-free facts loader ─────────────

const FACT_FIELDS = ["agentId", "tenant", "endpoint", "aid"] as const;
const factsOf = (x: { agentId: string; tenant: string; endpoint: string; aid: string }) =>
  FACT_FIELDS.map((f) => x[f]);
// A 64-char seed with whitespace. TS always refused it on shape; Python's message changed to match.
const WS_SEED_PLAN = "00 ".repeat(21) + "0";
const WS_SEED_DECODES = "00".repeat(31) + "  ";

test("identity facts: exactly the four public fields, no signing capability", () => {
  const facts = loadIdentityFacts(AID_FIXTURE);
  assert.ok(facts instanceof IdentityFacts);
  assert.deepEqual(Object.keys(facts), [...FACT_FIELDS]);
  for (const name of ["seed", "seedHex", "seed_hex", "agent", "privateKey", "signingKey", "sign"]) {
    assert.ok(!(name in facts), name);
  }
  assert.ok(FACT_FIELDS.every((f) => typeof facts[f] === "string"));
  assert.ok(Object.isFrozen(facts));
});

for (const [name, fixture] of [
  ["legacy", FIXTURE],
  ["aid", AID_FIXTURE],
] as const) {
  test(`identity facts render only the four fields: ${name}`, () => {
    const facts = loadIdentityFacts(fixture);
    for (const rendered of [
      String(facts),
      inspect(facts, { depth: Infinity, showHidden: true }),
      JSON.stringify(facts),
    ]) {
      assert.ok(!/[0-9a-fA-F]{64}/.test(rendered), rendered);
      assert.ok(rendered.includes(FIXTURE_AID), rendered);
    }
    assert.deepEqual(JSON.parse(JSON.stringify(facts)), {
      agentId: "ap-clerk",
      tenant: "acmé",
      endpoint: "seam.example:443",
      aid: FIXTURE_AID,
    });
  });
}

test("a file that records aid is served without decoding the seed", () => {
  // Criterion 2: the spied decoder refuses; the facts loader never calls it on a Phase-3 file, and the
  // full loader (and the facts loader on a legacy file, which must derive) does.
  const spy = mock.method(seedCodec, "decodeSeed", () => {
    throw new Error("seed decoded");
  });
  try {
    assert.deepEqual(factsOf(loadIdentityFacts(AID_FIXTURE)), ["ap-clerk", "acmé", "seam.example:443", FIXTURE_AID]);
    assert.equal(spy.mock.callCount(), 0);
    assert.throws(() => loadIdentityFile(AID_FIXTURE), /seed decoded/);
    assert.throws(() => loadIdentityFacts(FIXTURE), /seed decoded/);
    assert.equal(spy.mock.callCount(), 2);
  } finally {
    spy.mock.restore();
  }
});

test("identity facts agree with the full loader on every field", () => {
  const dir = tmpDir();
  const { path: created } = createIdentityFile(join(dir, "created.json"), FIELDS);
  const partner = join(dir, "partner.json");
  fs.writeFileSync(
    partner,
    JSON.stringify({
      version: 1,
      seed_hex: hex(Uint8Array.from({ length: 32 }, (_, i) => i)),
      agent_id: "qa-confirm",
      tenant: "t1",
      endpoint: "localhost:50051",
      comment: "extra keys are ignored",
    }),
  );
  for (const p of [FIXTURE, AID_FIXTURE, created, partner]) {
    assert.deepEqual(factsOf(loadIdentityFacts(p)), factsOf(loadIdentityFile(p)), p);
  }
  assert.equal(loadIdentityFacts(FIXTURE).aid, FIXTURE_AID);
});

test("identity facts read the env pointer", () => {
  const dir = tmpDir();
  const { path, aid } = createIdentityFile(join(dir, "id.json"), FIELDS);
  const saved = process.env[ENV_POINTER];
  try {
    process.env[ENV_POINTER] = path;
    assert.equal(loadIdentityFacts().aid, aid);
    delete process.env[ENV_POINTER];
    assert.equal(messageOf(() => loadIdentityFacts()), messageOf(() => loadIdentityFile()));
    assertIdentityError(() => loadIdentityFacts(), ENV_POINTER);
  } finally {
    if (saved === undefined) delete process.env[ENV_POINTER];
    else process.env[ENV_POINTER] = saved;
  }
});

test("a mismatched recorded aid is a claim to facts and a refusal to the full loader", () => {
  const dir = tmpDir();
  const other = new Agent(Uint8Array.from({ length: 32 }, (_, i) => i)).aid;
  const p = join(dir, "claim.json");
  fs.writeFileSync(p, JSON.stringify(withAid(other)));
  assert.equal(loadIdentityFacts(p).aid, other);
  assert.throws(
    () => loadIdentityFile(p),
    (e: unknown) => e instanceof IdentityFileError && e.message === "recorded aid does not match seed_hex",
  );
});

function messageOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof IdentityFileError, String(e));
    return e.message;
  }
  assert.fail("expected an IdentityFileError");
}

const SEED = "ab".repeat(32);
const SEED_LEN = "seed_hex must be exactly 64 hex chars (a 32-byte Ed25519 seed)";
for (const [name, body, message] of [
  ["wrong-version", { version: 2 }, "bootstrap schema version 2 unsupported (want 1)"],
  ["short-seed", { version: 1, seed_hex: "ab" }, SEED_LEN],
  ["absent-seed", { version: 1 }, SEED_LEN],
  ["number-seed", { version: 1, seed_hex: 7 }, SEED_LEN],
  ["non-hex-seed", { version: 1, seed_hex: "zz".repeat(32) }, "seed_hex is not valid hex"],
  ["ws-seed-plan", { version: 1, seed_hex: WS_SEED_PLAN }, "seed_hex is not valid hex"],
  ["ws-seed-decodes", { version: 1, seed_hex: WS_SEED_DECODES }, "seed_hex is not valid hex"],
  ["bad-seed-and-missing-fields", { version: 1, seed_hex: "zz".repeat(32) }, "seed_hex is not valid hex"],
  [
    "missing-endpoint",
    { version: 1, seed_hex: SEED, agent_id: "a", tenant: "t" },
    "bootstrap file missing required field(s): endpoint",
  ],
  [
    "missing-all-fields",
    { version: 1, seed_hex: SEED },
    "bootstrap file missing required field(s): agent_id, tenant, endpoint",
  ],
  ["malformed-aid", withAid(FIXTURE_AID.slice(0, -1)), "aid is malformed"],
  ["empty-aid", withAid(""), "aid is malformed"],
  ["null-aid", withAid(null), "aid is malformed"],
  ["number-aid", withAid(42), "aid is malformed"],
  ["list", [1, 2], undefined],
  ["not-json", "{not json", undefined],
] as const) {
  test(`both loaders refuse a bad file identically: ${name}`, () => {
    const dir = tmpDir();
    const p = join(dir, "bad.json");
    fs.writeFileSync(p, typeof body === "string" ? body : JSON.stringify(body));
    const full = messageOf(() => loadIdentityFile(p));
    assert.equal(messageOf(() => loadIdentityFacts(p)), full);
    if (message !== undefined) assert.equal(full, message);
  });
}

test("both loaders refuse a missing file identically", () => {
  const p = join(tmpDir(), "nope.json");
  const full = messageOf(() => loadIdentityFile(p));
  assert.equal(messageOf(() => loadIdentityFacts(p)), full);
  assert.equal(full, `bootstrap file not found: ${p}`);
});
