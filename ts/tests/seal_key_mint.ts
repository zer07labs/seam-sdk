// Test support: mint commitment TCTs in the S-4 seal-key shape (seam-runtime #2031,
// `docs/specs/seam-commitment-digest.v6.md` §Seal key), so a test can re-sign an edited token and the
// only thing that changes is the claim under test. Written from the spec, not through `src/crypto.ts`.

import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";

const enc = new TextEncoder();
export const b64 = (b: Uint8Array | string) => Buffer.from(b).toString("base64url");

/** The runtime's test seal-key seed (`SeededSealKeys`): `sha256("seam.seal-key.fixed.v1" ‖ issuer_seed)`. */
export function seededSealSeed(issuerSeed: Uint8Array): Uint8Array {
  return sha256(Buffer.concat([Buffer.from("seam.seal-key.fixed.v1"), Buffer.from(issuerSeed)]));
}

function framed(b: Uint8Array): Buffer {
  const n = Buffer.alloc(4);
  n.writeUInt32LE(b.length);
  return Buffer.concat([n, Buffer.from(b)]);
}

/** `framed(domain) ‖ framed(pk) ‖ le64(nb) ‖ le64(na) ‖ framed(issuer_aid)`. */
export function sealKeyCert(
  sealPk: Uint8Array,
  notBeforeMs: bigint,
  notAfterMs: bigint,
  issuerAid: string,
  domain = "seam.seal-key-cert.v1",
): Uint8Array {
  const t = Buffer.alloc(16);
  t.writeBigUInt64LE(notBeforeMs, 0);
  t.writeBigUInt64LE(notAfterMs, 8);
  return new Uint8Array(
    Buffer.concat([framed(enc.encode(domain)), framed(sealPk), t, framed(enc.encode(issuerAid))]),
  );
}

export function jkt(pk: Uint8Array): string {
  return b64(sha256(enc.encode(`{"crv":"Ed25519","kty":"OKP","x":"${b64(pk)}"}`)));
}

export interface MintOpts {
  issuerSeed: Uint8Array;
  /** Defaults to the runtime's seeded derivation. */
  sealSeed?: Uint8Array;
  /** Defaults to `[0, 900_000]` ms. */
  notBeforeMs?: bigint;
  notAfterMs?: bigint;
  /** The AID the certificate names; defaults to the issuer's untagged AID. */
  certIssuerAid?: string;
  /** Raw certificate bytes, overriding the built one (e.g. with a trailing byte). */
  cert?: Uint8Array;
  /** The key that signs the certificate; defaults to `issuerSeed`. */
  certSignerSeed?: Uint8Array;
  iat?: unknown;
  exp?: number;
  statement: Record<string, unknown>;
  /** Last word on the payload before signing. */
  edit?: (p: Record<string, any>) => void;
}

export const untaggedAid = (pk: Uint8Array) => "aid:pubkey:" + b64(pk);

/** The `{cert, sig}` member over a certificate the issuer seed signs. */
export function certMember(o: MintOpts): { cert: string; sig: string } {
  const sealPk = ed25519.getPublicKey(o.sealSeed ?? seededSealSeed(o.issuerSeed));
  const cert =
    o.cert ??
    sealKeyCert(
      sealPk,
      o.notBeforeMs ?? 0n,
      o.notAfterMs ?? 900_000n,
      o.certIssuerAid ?? untaggedAid(ed25519.getPublicKey(o.issuerSeed)),
    );
  return { cert: b64(cert), sig: b64(ed25519.sign(sha256(cert), o.certSignerSeed ?? o.issuerSeed)) };
}

/** Sign `header.payload` with a seal seed (re-sign an edited token). */
export function signWith(seed: Uint8Array, header: string, payload: string): string {
  const input = `${b64(header)}.${b64(payload)}`;
  return `${input}.${b64(ed25519.sign(enc.encode(input), seed))}`;
}

/** A complete seal-key commitment TCT. */
export function mintSealKeyTct(o: MintOpts): string {
  const sealSeed = o.sealSeed ?? seededSealSeed(o.issuerSeed);
  const sealPk = ed25519.getPublicKey(sealSeed);
  const aid = untaggedAid(sealPk);
  const p: Record<string, any> = {
    ver: "aitp/0.3",
    iss: aid,
    sub: aid,
    aud: aid,
    cnf: { jkt: jkt(sealPk) },
    iat: o.iat === undefined ? 0 : o.iat,
    exp: o.exp ?? 4_000_000_000,
    grants: ["aitp.attestation"],
    ext: { "com.zer07labs.seam": o.statement, "com.zer07labs.seam.seal-key-cert": certMember(o) },
  };
  o.edit?.(p);
  return signWith(sealSeed, JSON.stringify({ alg: "EdDSA", typ: "aitp-tct+jwt" }), JSON.stringify(p));
}
