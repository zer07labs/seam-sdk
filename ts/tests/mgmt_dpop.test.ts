// Management-plane DPoP proofs (seam-sdk#290) — the TypeScript twin of python/tests/test_mgmt_dpop.py.
//
// Asserts against `conformance/mgmt_dpop_vector.json`. Its `golden` group is the runtime's own vector,
// compared byte for byte; `derived` pins five-way SDK agreement. There is NO bless mode.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { inspect } from "node:util";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { ed25519 } from "@noble/curves/ed25519";

import {
  DEFAULT_OPERATOR_AUD,
  DpopError,
  DpopKeyError,
  MGMT_DPOP_MAX_BODY_BYTES,
  MGMT_DPOP_MAX_IAT,
  MGMT_DPOP_MAX_JTI_BYTES,
  OperatorDpopKey,
  mgmtDpopGrpcHtu,
  mgmtDpopHttpHeaders,
  mgmtDpopHttpHtu,
  mgmtDpopProof,
  newMgmtDpopJti,
} from "../src/index.js";
import { peekTokenClaims, tokenCnfJkt } from "../src/dpop.js";

const here = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(here, "..", "..", "conformance", "mgmt_dpop_vector.json"), "utf8"));
const G = V.golden;

const hex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
const b64d = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));
const seg = (proof: string, i: number) => Buffer.from(proof.split(".")[i]!, "base64url").toString("utf8");
const golden = () => OperatorDpopKey.fromJwk(G.jwk);

test("the vector is present and populated", () => {
  assert.ok(V.derived.length >= 5);
  assert.ok(V.jwk_rejects.length >= 10);
  assert.ok(V.http_htu.length >= 5 && V.http_htu_rejects.length >= 3);
});

// ── golden ──────────────────────────────────────────────────────────────────────────────────────

test("golden key outputs", () => {
  const k = OperatorDpopKey.fromSeed(hex(G.seed_hex));
  assert.equal(k.x, G.x);
  assert.equal(k.jkt, G.jkt);
  assert.equal(golden().jkt, G.jkt);
});

test("golden proof is byte-exact", () => {
  const htu = mgmtDpopGrpcHtu(G.method, G.aud);
  assert.equal(htu, G.htu);
  const proof = mgmtDpopProof(golden(), G.token, {
    htm: G.htm,
    htu,
    body: hex(G.message_hex),
    iat: G.iat,
    jti: G.jti,
  });
  assert.equal(proof, G.proof);
  assert.equal(seg(proof, 0), G.header_json);
  assert.equal(seg(proof, 1), G.claims_json);
  const claims = JSON.parse(seg(proof, 1));
  assert.equal(claims.ath, G.ath);
  assert.equal(claims.seam_bd, G.seam_bd);
});

test("a proof verifies under the public key", () => {
  const k = golden();
  const proof = mgmtDpopProof(k, "a.b.c", { htm: "POST", htu: "grpc://x/y.Z/W", body: new Uint8Array() });
  const at = proof.lastIndexOf(".");
  assert.ok(ed25519.verify(b64d(proof.slice(at + 1)), new TextEncoder().encode(proof.slice(0, at)), b64d(k.x)));
});

test("a one-byte seed change changes the proof", () => {
  const seed = hex(G.seed_hex);
  seed[0]! ^= 1;
  const p = mgmtDpopProof(OperatorDpopKey.fromSeed(seed), G.token, {
    htm: "POST",
    htu: G.htu,
    body: hex(G.message_hex),
    iat: G.iat,
    jti: G.jti,
  });
  assert.notEqual(p, G.proof);
});

// ── derived (five-way agreement) ────────────────────────────────────────────────────────────────

for (const c of V.derived) {
  test(`derived: ${c.name}`, () => {
    const body = hex(c.message_hex);
    if (c.url !== undefined) {
      assert.equal(mgmtDpopHttpHtu(c.url), c.htu);
      const h = mgmtDpopHttpHeaders(golden(), G.token, c.htm, c.url, body, { iat: c.iat, jti: c.jti });
      assert.deepEqual(h, { Authorization: `DPoP ${G.token}`, DPoP: c.proof });
    }
    const proof = mgmtDpopProof(golden(), G.token, { htm: c.htm, htu: c.htu, body, iat: c.iat, jti: c.jti });
    assert.equal(proof, c.proof);
    assert.equal(JSON.parse(seg(proof, 1)).seam_bd, c.seam_bd);
  });
}

for (const c of V.grpc_htu) {
  test(`grpc htu: ${c.htu}`, () => assert.equal(mgmtDpopGrpcHtu(c.method, c.aud), c.htu));
}

test("grpc htu defaults to the runtime audience", () => {
  assert.equal(DEFAULT_OPERATOR_AUD, "seam-runtime");
  assert.equal(mgmtDpopGrpcHtu("/a.B/C"), "grpc://seam-runtime/a.B/C");
});

test("grpc htu refuses a bad method or aud", () => {
  for (const m of ["", "a.B/C", "/a.B/C\n", "/a.B/é"]) assert.throws(() => mgmtDpopGrpcHtu(m), DpopError, m);
  for (const a of ["", "has space", "a/b", "café", "x\n"]) {
    assert.throws(() => mgmtDpopGrpcHtu("/a.B/C", a), DpopError, a);
  }
});

for (const c of V.http_htu) {
  test(`http htu: ${c.url}`, () => assert.equal(mgmtDpopHttpHtu(c.url), c.htu));
}

for (const c of V.http_htu_rejects) {
  test(`http htu reject: ${c.reason}`, () => assert.throws(() => mgmtDpopHttpHtu(c.url), DpopError));
}

// ── key loading ─────────────────────────────────────────────────────────────────────────────────

for (const c of V.jwk_rejects) {
  test(`jwk reject: ${c.reason}`, () => {
    assert.throws(() => OperatorDpopKey.fromJwk(c.jwk), DpopKeyError);
    assert.throws(() => OperatorDpopKey.fromJwk(JSON.stringify(c.jwk)), DpopKeyError);
  });
}

for (const c of V.jwk_accepts) {
  test(`jwk accept: ${c.reason}`, () => assert.equal(OperatorDpopKey.fromJwk(c.jwk).jkt, G.jkt));
}

test("jwk text that is not JSON, or nested too deeply", () => {
  assert.throws(() => OperatorDpopKey.fromJwk("{kty: OKP"), /not valid JSON/);
  assert.throws(() => OperatorDpopKey.fromJwk("[".repeat(100_000)), DpopKeyError);
});

test("fromSeed refuses a bad seed", () => {
  for (const s of [new Uint8Array(0), new Uint8Array(31), new Uint8Array(33), "x".repeat(32)]) {
    assert.throws(() => OperatorDpopKey.fromSeed(s as Uint8Array), DpopKeyError);
  }
});

test("fromSeed copies the seed", () => {
  const seed = hex(G.seed_hex);
  const k = OperatorDpopKey.fromSeed(seed);
  seed.fill(0);
  assert.equal(k.jkt, G.jkt);
});

test("the key never shows its private half", () => {
  const k = golden();
  for (const text of [String(k), `${k}`, inspect(k), inspect({ k }), JSON.stringify(k), JSON.stringify({ k })]) {
    assert.ok(!text.includes(G.jwk.d), text);
    assert.ok(!text.includes(G.seed_hex), text);
    assert.ok(text.includes(G.jkt), text);
  }
  assert.deepEqual(k.publicJwk(), { kty: "OKP", crv: "Ed25519", x: G.x });
  assert.deepEqual(Object.keys(k).sort(), ["jkt", "x"]);
});

test("the proof header never carries d", () => {
  const p = mgmtDpopProof(golden(), "a.b.c", { htm: "POST", htu: "grpc://x/y.Z/W", body: new Uint8Array() });
  assert.ok(!("d" in JSON.parse(seg(p, 0)).jwk));
});

// ── defaults and local refusals ─────────────────────────────────────────────────────────────────

test("default jti is a fresh 22-char base64url", () => {
  const a = newMgmtDpopJti();
  assert.notEqual(a, newMgmtDpopJti());
  assert.equal(a.length, 22);
  assert.equal(b64d(a).length, 16);
});

test("default iat is now, and two default proofs differ", () => {
  const before = Math.floor(Date.now() / 1000);
  const k = golden();
  const p1 = mgmtDpopProof(k, "a.b.c", { htm: "POST", htu: "grpc://x/y.Z/W", body: new Uint8Array(), iat: 1 });
  const p2 = mgmtDpopProof(k, "a.b.c", { htm: "POST", htu: "grpc://x/y.Z/W", body: new Uint8Array(), iat: 1 });
  assert.notEqual(p1, p2);
  const iat = JSON.parse(seg(mgmtDpopProof(k, "a.b.c", { htm: "POST", htu: "grpc://x/y.Z/W", body: new Uint8Array() }), 1)).iat;
  assert.ok(iat >= before && iat <= Math.floor(Date.now() / 1000));
});

const OK = { htm: "POST", htu: "grpc://x/y.Z/W", body: new Uint8Array(), iat: 1, jti: "j" };

test("local refusals", () => {
  const bad: Array<[string, unknown]> = [
    ["htm", ""],
    ["htm", "PO ST"],
    ["htu", ""],
    ["htu", "grpc://x/é"],
    ["htu", "grpc://x/\n"],
    ["body", "not bytes"],
    ["body", new Uint8Array(MGMT_DPOP_MAX_BODY_BYTES + 1)],
    ["iat", -1],
    ["iat", 1.5],
    ["iat", Number.NaN],
    ["iat", 2 ** 53],
    ["jti", ""],
    ["jti", "é"],
    ["jti", "j".repeat(MGMT_DPOP_MAX_JTI_BYTES + 1)],
  ];
  for (const [field, value] of bad) {
    assert.throws(() => mgmtDpopProof(golden(), "a.b.c", { ...OK, [field]: value } as never), DpopError, field);
  }
  mgmtDpopProof(golden(), "a.b.c", { ...OK, body: new Uint8Array(MGMT_DPOP_MAX_BODY_BYTES) });
  mgmtDpopProof(golden(), "a.b.c", { ...OK, jti: "j".repeat(MGMT_DPOP_MAX_JTI_BYTES) });
  assert.equal(MGMT_DPOP_MAX_IAT, V.iat_max);
  mgmtDpopProof(golden(), "a.b.c", { ...OK, iat: MGMT_DPOP_MAX_IAT });
});

test("bad tokens and an oversized proof are refused", () => {
  for (const t of ["", "has space", "café", null]) {
    assert.throws(() => mgmtDpopProof(golden(), t as string, OK), DpopError);
  }
  assert.throws(() => mgmtDpopProof(golden(), "a.b.c", { ...OK, htu: "grpc://x/" + "a".repeat(8192) }), /refuses one over/);
  assert.throws(() => mgmtDpopProof(new Uint8Array(32) as never, "a.b.c", OK), DpopError);
});

test("errors are typed", () => {
  const e = new DpopKeyError("x");
  assert.ok(e instanceof DpopError && e instanceof Error);
  assert.equal(e.name, "DpopKeyError");
});

// ── token peeking (diagnostics only) ────────────────────────────────────────────────────────────

const tok = (claims: object) => {
  const s = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${s({ alg: "EdDSA" })}.${s(claims)}.c2ln`;
};

test("peek reads cnf and aud", () => {
  const c = peekTokenClaims(tok({ aud: "seam-runtime", cnf: { jkt: "abc" } }));
  assert.equal(c.aud, "seam-runtime");
  assert.equal(tokenCnfJkt(c), "abc");
  assert.equal(tokenCnfJkt(peekTokenClaims(tok({ sub: "x" }))), undefined);
});

test("peek refuses a non-JWS and a malformed cnf", () => {
  for (const t of ["only.two", "a.!!!.c", "a.bm90LWpzb24.c", "a.WzFd.c"]) {
    assert.throws(() => peekTokenClaims(t), DpopKeyError, t);
  }
  for (const cnf of [{ jkt: 1 }, "abc", { x5t: "y" }, [1]]) {
    assert.throws(() => tokenCnfJkt({ cnf }), DpopKeyError);
  }
});

test("a malformed JWK's error never quotes the JWK text", () => {
  const d = Buffer.alloc(32, 0x42).toString("base64url");
  for (const bad of [`{"kty":"OKP","crv":"Ed25519","d":"${d}","x":undefined}`, `["${d}",u]`, `{"d":"${d}"`]) {
    try {
      OperatorDpopKey.fromJwk(bad);
      assert.fail("accepted a malformed JWK");
    } catch (e) {
      assert.ok(e instanceof DpopKeyError);
      for (let i = 0; i + 4 <= d.length; i++) assert.ok(!e.message.includes(d.slice(i, i + 4)), e.message);
    }
  }
});

test("the key exposes no signing method", () => {
  const k = OperatorDpopKey.fromSeed(new Uint8Array(32).fill(0x42));
  assert.equal("sign" in k, false);
});
