// The README's TypeScript DPoP snippet, run as written against a raw node:http2 SeamAdmin (seam-sdk#290).
//
// The snippet lives verbatim between the README:dpop markers below; python/tests/test_readme_dpop_snippets.py
// checks the README still quotes exactly those lines. The key is the PUBLIC test vector's (seed 0x42 x 32).

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import http2 from "node:http2";
import type { AddressInfo } from "node:net";
import { test } from "node:test";

import { ed25519 } from "@noble/curves/ed25519";

import { OperatorDpopKey, SeamAdminClient } from "../src/index.js";

const KEY = OperatorDpopKey.fromSeed(new Uint8Array(32).fill(0x42));
const b64 = (b: Uint8Array | Buffer) => Buffer.from(b).toString("base64url");
const seg = (o: object) => b64(Buffer.from(JSON.stringify(o)));
const TOKEN = `${seg({ alg: "EdDSA", typ: "JWT" })}.${seg({ aud: "seam-runtime", cnf: { jkt: KEY.jkt } })}.c2ln`;
const JWK = JSON.stringify({ kty: "OKP", crv: "Ed25519", x: KEY.x, d: b64(new Uint8Array(32).fill(0x42)) });

/** The README snippet, verbatim between the markers. */
async function readmeSnippet() {
  // README:dpop:begin
  const dpopKey = OperatorDpopKey.fromJwk(process.env.SEAM_OPERATOR_DPOP_JWK!);
  const admin = SeamAdminClient.connect(process.env.SEAM_MGMT_URL!, {
    token: process.env.SEAM_OPERATOR_TOKEN!,
    dpopKey,
  });
  const tenants = await admin.listTenants();
  // README:dpop:end
  admin.close();
  return tenants;
}

test("the README's TypeScript DPoP snippet signs ListTenants", async () => {
  const seen: { path: string; headers: http2.IncomingHttpHeaders; message: Buffer }[] = [];
  const server = http2.createServer();
  server.on("stream", (stream, headers) => {
    const chunks: Buffer[] = [];
    stream.on("data", (c: Buffer) => chunks.push(c));
    stream.on("end", () => {
      const body = Buffer.concat(chunks);
      seen.push({ path: String(headers[":path"]), headers, message: body.subarray(5) });
      stream.respond({ ":status": 200, "content-type": "application/grpc+proto" }, { waitForTrailers: true });
      stream.on("wantTrailers", () => stream.sendTrailers({ "grpc-status": "0" }));
      stream.end(Buffer.alloc(5)); // one empty ListTenantsResponse
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const saved = { ...process.env };
  try {
    process.env.SEAM_OPERATOR_DPOP_JWK = JWK;
    process.env.SEAM_OPERATOR_TOKEN = TOKEN;
    process.env.SEAM_MGMT_URL = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    assert.deepEqual(await readmeSnippet(), []);
  } finally {
    process.env = saved;
    await new Promise<void>((r) => server.close(() => r()));
  }
  assert.equal(seen.length, 1);
  const [call] = seen;
  assert.equal(call!.path, "/seam.api.v1.SeamAdmin/ListTenants");
  assert.equal(call!.headers.authorization, `DPoP ${TOKEN}`);
  const proof = String(call!.headers.dpop);
  const at = proof.lastIndexOf(".");
  assert.ok(ed25519.verify(Buffer.from(proof.slice(at + 1), "base64url"), Buffer.from(proof.slice(0, at)), Buffer.from(KEY.x, "base64url")));
  const claims = JSON.parse(Buffer.from(proof.split(".")[1]!, "base64url").toString());
  assert.equal(claims.htu, "grpc://seam-runtime/seam.api.v1.SeamAdmin/ListTenants");
  assert.equal(claims.seam_bd, b64(createHash("sha256").update(call!.message).digest()));
});
