import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { buildPresentation, verifyTct } from "../src/crypto.ts";

const vectors = JSON.parse(
  readFileSync(new URL("../../conformance/vectors.json", import.meta.url), "utf8"),
);

test("pinned-key presentation is byte-exact", () => {
  const { inputs, presentation } = vectors.admission;
  const got = buildPresentation(
    Buffer.from(inputs.agent_seed_hex, "hex"),
    inputs.receiver_aid,
    inputs.pop_nonce,
    inputs.now_ms,
  );
  assert.deepEqual(got, presentation);
});

test("TCT verify: valid → true, tampered → false", () => {
  const t = vectors.tct;
  assert.equal(verifyTct(t.issuer_aid, t.signed_artifact_jws, t.inputs.commitment, 1700000001), true);
  assert.equal(
    verifyTct(t.issuer_aid, t.signed_artifact_jws, { ...t.inputs.commitment, action: "ALLOW" }, 1700000001),
    false,
  );
});

test("TCT verify fails closed on malformed/expired/forged", () => {
  const t = vectors.tct;
  const c = t.inputs.commitment;
  const jws = t.signed_artifact_jws as string;
  const iss = t.issuer_aid as string;
  const [h, p, s] = jws.split(".");
  const cases: [string, string, string, number][] = [
    ["expired", iss, jws, 9_999_999_999],
    ["not-3-parts", iss, "not.a", 1_700_000_001],
    ["wrong-issuer-key", "aid:pubkey:ed25519:" + "A".repeat(43), jws, 1_700_000_001],
    ["unsupported-aid", "did:web:example.com", jws, 1_700_000_001],
    ["tampered-signature", iss, `${h}.${p}.${s.slice(0, -4)}AAAA`, 1_700_000_001],
  ];
  for (const [name, issuer, token, now] of cases) {
    assert.equal(verifyTct(issuer, token, c, now), false, `${name} must fail closed`);
  }
});
