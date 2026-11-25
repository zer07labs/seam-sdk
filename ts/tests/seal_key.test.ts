// Deep-cleanup S-4 (seam-runtime #2031, runtime 0.123.0): every commitment TCT is a self-attestation by a
// short-lived seal key the pinned issuer certifies (`docs/specs/seam-commitment-digest.v6.md` §Seal key).
// These are the regression guards for verifyTct's seal-key rule and the frozen certificate vector
// `conformance/seal_key_cert_vector.json` (copied byte-for-byte from the runtime, never hand-edited).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";

import {
  type Commitment,
  parseSealKeyCert,
  sealAid,
  seamCommitmentDigest,
  verifySealKeyCert,
  verifyTct,
} from "../src/crypto.js";
import { commitmentFromVector } from "./vector_commitment.js";
import { b64, certMember, jkt, mintSealKeyTct, sealKeyCert, signWith, untaggedAid } from "./seal_key_mint.js";

const CONF = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "conformance");
const conf = (f: string) => JSON.parse(readFileSync(join(CONF, f), "utf8"));
const hex = (h: string) => new Uint8Array(Buffer.from(h, "hex"));
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

const V = conf("seal_key_cert_vector.json");

// ── The frozen certificate vector ────────────────────────────────────────────────────────────────

test("the seal-key certificate vector rebuilds, hashes and verifies under the pinned issuer", () => {
  const cert = hex(V.cert_hex);
  const sig = hex(V.sig_hex);
  const pk = hex(V.seal_pk_hex);
  assert.equal(V.domain, "seam.seal-key-cert.v1");
  // The bytes, rebuilt from the fields by the spec's layout.
  assert.equal(toHex(sealKeyCert(pk, BigInt(V.not_before_ms), BigInt(V.not_after_ms), V.issuer_aid)), V.cert_hex);
  assert.equal(toHex(sha256(cert)), V.cert_digest_hex);
  // The issuer of seed 7×32 signed the digest; its AID is the vector's.
  const issuerSeed = hex(V.issuer_seed_hex);
  assert.equal(untaggedAid(ed25519.getPublicKey(issuerSeed)), V.issuer_aid);
  assert.equal(toHex(ed25519.getPublicKey(hex(V.seal_seed_hex))), V.seal_pk_hex);
  assert.ok(ed25519.verify(sig, sha256(cert), ed25519.getPublicKey(issuerSeed)));
  // The ext member is the base64url of the same bytes.
  assert.deepEqual(V.ext_member, { cert: b64(cert), sig: b64(sig) });
  // The library parses and verifies it, and names the seal AID.
  const f = verifySealKeyCert(V.issuer_aid, cert, sig);
  assert.ok(f);
  assert.deepEqual(f, parseSealKeyCert(cert));
  assert.equal(toHex(f!.sealPk), V.seal_pk_hex);
  assert.equal(f!.notBeforeMs, BigInt(V.not_before_ms));
  assert.equal(f!.notAfterMs, BigInt(V.not_after_ms));
  assert.equal(f!.issuerAid, V.issuer_aid);
  assert.equal(sealAid(f!.sealPk), V.seal_aid);
});

test("one flipped certificate byte anywhere, or another pinned issuer, is refused", () => {
  const cert = hex(V.cert_hex);
  const sig = hex(V.sig_hex);
  for (let i = 0; i < cert.length; i++) {
    const bad = cert.slice();
    bad[i] ^= 1;
    assert.equal(verifySealKeyCert(V.issuer_aid, bad, sig), null, `byte ${i}`);
  }
  for (let i = 0; i < sig.length; i++) {
    const bad = sig.slice();
    bad[i] ^= 1;
    assert.equal(verifySealKeyCert(V.issuer_aid, cert, bad), null, `sig byte ${i}`);
  }
  const other = untaggedAid(ed25519.getPublicKey(new Uint8Array(32).fill(8)));
  assert.equal(verifySealKeyCert(other, cert, sig), null);
});

test("every prefix of the certificate, and a trailing byte, is refused by the parser", () => {
  const cert = hex(V.cert_hex);
  for (let cut = 0; cut < cert.length; cut++) assert.equal(parseSealKeyCert(cert.subarray(0, cut)), null, `prefix ${cut}`);
  assert.equal(parseSealKeyCert(new Uint8Array([...cert, 0])), null);
  // The ticket-intermediate domain under the same layout is not a seal-key certificate.
  const pk = hex(V.seal_pk_hex);
  const ticket = sealKeyCert(pk, 1n, 2n, "a", "seam.ticket-intermediate.v1");
  assert.equal(parseSealKeyCert(ticket), null);
  // An inverted window, and a not_after beyond i64::MAX ms.
  assert.equal(parseSealKeyCert(sealKeyCert(pk, 21n, 20n, "a")), null);
  assert.equal(parseSealKeyCert(sealKeyCert(pk, 0n, 2n ** 64n - 1n, "a")), null);
  // An issuer AID of 63 bytes, and one that is not UTF-8.
  assert.equal(parseSealKeyCert(sealKeyCert(pk, 0n, 1n, "a".repeat(63))), null);
  assert.ok(parseSealKeyCert(sealKeyCert(pk, 0n, 1n, "a".repeat(62))));
  const notUtf8 = Buffer.concat([
    Buffer.from(sealKeyCert(pk, 0n, 1n, "")).subarray(0, 4 + 21 + 4 + 32 + 16),
    Buffer.from([1, 0, 0, 0, 0xff]),
  ]);
  assert.equal(parseSealKeyCert(new Uint8Array(notUtf8)), null);
});

// ── verifyTct under the seal-key rule ────────────────────────────────────────────────────────────

const ISSUER_SEED = new Uint8Array(32).fill(7);
const ISSUER = untaggedAid(ed25519.getPublicKey(ISSUER_SEED));
const C: Commitment = {
  id: "c-seal-key",
  action: "transfer",
  authority: "treasury",
  supersedes: null,
  auth_method: "pinned-key",
  trust_basis: "attested",
  committer: "",
  explanation: [],
};
const STATEMENT = { type: "seam:commitment", commitment_digest: seamCommitmentDigest(C) };
const mint = (o: Partial<Parameters<typeof mintSealKeyTct>[0]> = {}) =>
  mintSealKeyTct({ issuerSeed: ISSUER_SEED, statement: STATEMENT, ...o });
const ok = (jws: string) => verifyTct(ISSUER, jws, C, 0);

test("a minted seal-key token verifies (the control every refusal below depends on)", () => {
  assert.equal(ok(mint()), true);
  // ... and only under the pinned issuer: not under the seal AID, not under another issuer.
  const sealPk = ed25519.getPublicKey(
    sha256(Buffer.concat([Buffer.from("seam.seal-key.fixed.v1"), Buffer.from(ISSUER_SEED)])),
  );
  assert.equal(verifyTct(untaggedAid(sealPk), mint(), C, 0), false);
  assert.equal(verifyTct(untaggedAid(ed25519.getPublicKey(new Uint8Array(32).fill(8))), mint(), C, 0), false);
});

test("the runtime's own seal-key token verifies, and the old issuer-signed one is refused", () => {
  const t = conf("vectors.json").tct;
  const commitment = commitmentFromVector(t.inputs.commitment);
  assert.equal(verifyTct(t.issuer_aid, t.signed_artifact_jws, commitment, 1_700_000_001), true);
  // seam-runtime origin/main before #2031: signed directly by the issuer (iss == issuer), same digest.
  assert.equal(OLD_ISSUER_SIGNED_TCT.split(".").length, 3);
  assert.equal(verifyTct(t.issuer_aid, OLD_ISSUER_SIGNED_TCT, commitment, 1_700_000_001), false);
  // A freshly minted issuer-signed token (no certificate) is refused too.
  const p = JSON.parse(Buffer.from(mint().split(".")[1], "base64url").toString());
  const issuerPk = ed25519.getPublicKey(ISSUER_SEED);
  Object.assign(p, { iss: ISSUER, sub: ISSUER, aud: ISSUER, cnf: { jkt: jkt(issuerPk) } });
  delete p.ext["com.zer07labs.seam.seal-key-cert"];
  assert.equal(ok(signWith(ISSUER_SEED, JSON.stringify({ alg: "EdDSA", typ: "aitp-tct+jwt" }), JSON.stringify(p))), false);
});

test("a certificate window over the 1 h + 30 s cap is refused; exactly the cap verifies", () => {
  assert.equal(ok(mint({ notBeforeMs: 0n, notAfterMs: 3_630_000n })), true);
  assert.equal(ok(mint({ notBeforeMs: 0n, notAfterMs: 3_630_001n })), false);
});

test("iat outside the certificate window is refused, with no grace; the boundaries verify", () => {
  const w = { notBeforeMs: 10_000n, notAfterMs: 20_000n };
  assert.equal(ok(mint({ ...w, iat: 10 })), true);
  assert.equal(ok(mint({ ...w, iat: 20 })), true);
  assert.equal(ok(mint({ ...w, iat: 9 })), false);
  assert.equal(ok(mint({ ...w, iat: 21 })), false);
  // A window that is not whole seconds: iat·1000 must still lie inside it.
  assert.equal(ok(mint({ notBeforeMs: 10_001n, notAfterMs: 19_999n, iat: 10 })), false);
  // iat must be a JSON integer.
  for (const iat of ["10", 10.5, true, null, 2 ** 60]) assert.equal(ok(mint({ ...w, iat })), false, String(iat));
  assert.equal(ok(mint({ ...w, edit: (p) => delete p.iat })), false, "absent iat");
});

test("a certificate naming the wrong issuer is refused", () => {
  const other = new Uint8Array(32).fill(8);
  // The pinned key signs a certificate naming another AID.
  assert.equal(ok(mint({ certIssuerAid: untaggedAid(ed25519.getPublicKey(other)) })), false);
  // The tagged spelling of the pinned issuer is a different string: refused, the compare is exact.
  assert.equal(ok(mint({ certIssuerAid: "aid:pubkey:ed25519:" + b64(ed25519.getPublicKey(ISSUER_SEED)) })), false);
  // A forger certifies a seal key under their own AID and key: refused against the pin.
  assert.equal(
    ok(mint({ certSignerSeed: other, certIssuerAid: untaggedAid(ed25519.getPublicKey(other)) })),
    false,
  );
  // A forger's key signs a certificate naming the pinned issuer.
  assert.equal(ok(mint({ certSignerSeed: other })), false);
});

test("a mismatched or malformed ext certificate member is refused", () => {
  const K = "com.zer07labs.seam.seal-key-cert";
  const cases: Record<string, (p: Record<string, any>) => void> = {
    "a third member": (p) => (p.ext[K].x = 1),
    "only cert": (p) => delete p.ext[K].sig,
    "padded cert": (p) => (p.ext[K].cert += "=".repeat((4 - (p.ext[K].cert.length % 4)) % 4 || 4)),
    "standard alphabet": (p) => (p.ext[K].sig = Buffer.from(p.ext[K].sig, "base64url").toString("base64").replace(/=+$/, "") + "+"),
    "non-canonical trailing bits": (p) => {
      const s: string = p.ext[K].sig; // 64 bytes -> 86 chars, the last carries 4 spare bits
      const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
      p.ext[K].sig = s.slice(0, -1) + alpha[alpha.indexOf(s.at(-1)!) ^ 1];
    },
    "cert is a number": (p) => (p.ext[K].cert = 1),
    "member is a string": (p) => (p.ext[K] = "x"),
    "member absent": (p) => delete p.ext[K],
    "an extra ext namespace": (p) => (p.ext["org.example"] = {}),
    "a certificate for a different seal key than the signer": (p) => {
      p.ext[K] = certMember({ issuerSeed: ISSUER_SEED, sealSeed: new Uint8Array(32).fill(0x5e), statement: {} });
    },
  };
  for (const [name, edit] of Object.entries(cases)) assert.equal(ok(mint({ edit })), false, name);
});

test("a certificate with trailing bytes is refused", () => {
  const sealPk = ed25519.getPublicKey(
    sha256(Buffer.concat([Buffer.from("seam.seal-key.fixed.v1"), Buffer.from(ISSUER_SEED)])),
  );
  const cert = sealKeyCert(sealPk, 0n, 900_000n, ISSUER);
  assert.equal(ok(mint({ cert })), true, "control: the same cert, untouched");
  assert.equal(ok(mint({ cert: new Uint8Array([...cert, 0]) })), false);
});

test("iss/sub/aud and cnf must be the seal key", () => {
  const issuerPk = ed25519.getPublicKey(ISSUER_SEED);
  assert.equal(ok(mint({ edit: (p) => (p.iss = ISSUER) })), false);
  assert.equal(ok(mint({ edit: (p) => (p.aud = ISSUER) })), false);
  assert.equal(ok(mint({ edit: (p) => (p.cnf = { jkt: jkt(issuerPk) }) })), false);
  assert.equal(ok(mint({ edit: (p) => delete p.cnf })), false);
});

test("a small-order R in the certificate signature is refused (verify_strict)", () => {
  // Swap R for the identity encoding; whatever S is, the strict verifier refuses before the equation.
  const cert = hex(V.cert_hex);
  const sig = hex(V.sig_hex);
  for (const r of ["0100000000000000000000000000000000000000000000000000000000000000",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"]) {
    const bad = sig.slice();
    bad.set(hex(r), 0);
    assert.equal(verifySealKeyCert(V.issuer_aid, cert, bad), null, r);
  }
  // A small-order pinned issuer key is refused outright.
  const weak = "aid:pubkey:" + b64(hex("0100000000000000000000000000000000000000000000000000000000000000"));
  assert.equal(verifySealKeyCert(weak, sealKeyCert(hex(V.seal_pk_hex), 0n, 1n, weak), sig), null);
});

/** `conformance/vectors.json`'s `tct.signed_artifact_jws` at seam-sdk origin/main before S-4: signed
 * directly by the issuer of seed 7×32, `iss == sub == aud ==` the issuer, no certificate. */
const OLD_ISSUER_SIGNED_TCT =
  "eyJhbGciOiJFZERTQSIsInR5cCI6ImFpdHAtdGN0K2p3dCJ9.eyJhdWQiOiJhaWQ6cHVia2V5OjZrcHNZLUtjVWdxLTlWQjdFeTdGLVpWSGRxNi12bnVTUWg3cWFSUkcwaXciLCJjbmYiOnsiamt0IjoiLS02SU01bDBPb3NMajl5V3NrSVNZaFVBM25fM0NVUlFrbXJZTVNoYV9jayJ9LCJleHAiOjQ4NTM2MDAwMDAsImV4dCI6eyJjb20uemVyMDdsYWJzLnNlYW0iOnsiY29tbWl0bWVudF9kaWdlc3QiOiIwYzczZWRjNmMyYWE4N2VkYjI1MDk0NzY3ODFlZmE0NmMyYzJlOTdjYzU4ZTFhYTJkZjI5MjMyN2ZjZGJhZWEyIiwidHlwZSI6InNlYW06Y29tbWl0bWVudCJ9fSwiZ3JhbnRzIjpbImFpdHAuYXR0ZXN0YXRpb24iXSwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJhaWQ6cHVia2V5OjZrcHNZLUtjVWdxLTlWQjdFeTdGLVpWSGRxNi12bnVTUWg3cWFSUkcwaXciLCJqdGkiOiJjNzMyMWNlNC02MmYxLTRlMzgtYWMyMy0yMTJkYzllMDA1NWIiLCJzdWIiOiJhaWQ6cHVia2V5OjZrcHNZLUtjVWdxLTlWQjdFeTdGLVpWSGRxNi12bnVTUWg3cWFSUkcwaXciLCJ2ZXIiOiJhaXRwLzAuMyJ9.eFz7GD8-3OLNdmuf267Tz8xbq8pJmEPRYq416FF0k7-NfkK2C22Q7btJC-BN0RliaB5qfmHQgrk0voBOjqXnDw";
