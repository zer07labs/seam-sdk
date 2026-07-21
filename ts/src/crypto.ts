// Client-side crypto for the Seam SDK — pure stock primitives (Ed25519 + SHA-256), no native binding.
//
// The admission proof-of-possession is Ed25519 over SHA-256 of a documented, domain-separated canonical
// byte layout (RFC-AITP-0002 §3); the seed never leaves the client. Conformance vectors in
// `conformance/vectors.json` (generated from the Rust reference) pin the exact bytes.

import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";

const enc = new TextEncoder();
const PROOF_DOMAIN = enc.encode("aitp-pinned-key-v1\0");
const NUL = new Uint8Array([0]);

function b64urlNoPad(b: Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}
function b64urlDecode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}
function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
function uuidFromBytes(b: Uint8Array): string {
  const h = Buffer.from(b.subarray(0, 16)).toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

export interface Presentation {
  sender_aid: string;
  descriptor: { type: string; subject: string; proof: string; public_key: string };
  message_id: string;
  timestamp: number;
  pop_nonce: string;
}

export interface Commitment {
  id: string;
  action: string;
  authority: string;
  auth_method: string;
  trust_basis: string;
  supersedes?: string;
}

/** The agent's `aid:pubkey:ed25519:` identity for a 32-byte Ed25519 public key. */
export function aidFromPubkey(pub: Uint8Array): string {
  return "aid:pubkey:ed25519:" + b64urlNoPad(pub);
}

/** Build the pinned-key admission presentation the Seam server verifies. */
export function buildPresentation(
  agentSeed: Uint8Array,
  receiverAid: string,
  popNonce: string,
  nowMs: number,
): Presentation {
  const pub = ed25519.getPublicKey(agentSeed);
  const senderAid = aidFromPubkey(pub);
  const messageId = uuidFromBytes(sha256(concat(enc.encode("seam-pop-mid"), enc.encode(popNonce))));
  const timestamp = Math.floor(nowMs / 1000);
  const ts = new Uint8Array(8);
  new DataView(ts.buffer).setBigInt64(0, BigInt(timestamp), false); // big-endian i64

  const proofInput = concat(
    PROOF_DOMAIN,
    enc.encode(senderAid),
    NUL,
    enc.encode(receiverAid),
    NUL,
    enc.encode(messageId),
    NUL,
    ts,
    NUL,
    b64urlDecode(popNonce),
  );
  const proof = b64urlNoPad(ed25519.sign(sha256(proofInput), agentSeed));

  return {
    sender_aid: senderAid,
    descriptor: { type: "pinned_key", subject: senderAid, proof, public_key: b64urlNoPad(pub) },
    message_id: messageId,
    timestamp,
    pop_nonce: popNonce,
  };
}

function aidToPubkey(aid: string): Uint8Array {
  for (const prefix of ["aid:pubkey:ed25519:", "aid:pubkey:"]) {
    if (aid.startsWith(prefix)) return b64urlDecode(aid.slice(prefix.length));
  }
  throw new Error(`unsupported AID form: ${aid}`);
}

// An 8-byte big-endian length prefix — frames each digest field unambiguously (a `\0` separator would let
// boundary-shifted fields collide, since the fields are arbitrary text that may contain that byte).
function lenPrefix(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(b.length), false);
  return out;
}

function seamCommitmentDigest(c: Commitment): string {
  const fields = [
    enc.encode("seam-commitment-digest:v1"),
    enc.encode(c.id),
    enc.encode(c.action),
    enc.encode(c.authority),
    enc.encode(c.supersedes ?? ""),
    enc.encode(c.auth_method),
    enc.encode(c.trust_basis),
  ];
  const parts: Uint8Array[] = [];
  for (const f of fields) {
    parts.push(lenPrefix(f), f);
  }
  return Buffer.from(sha256(concat(...parts))).toString("hex");
}

/** Independently verify a sealed commitment's rooted TCT — zero server trust, stock crypto only. */
export function verifyTct(
  issuerAid: string,
  tctJws: string,
  commitment: Commitment,
  nowS?: number,
): boolean {
  // Any malformed/forged input must fail closed (return false), never throw.
  try {
    const parts = tctJws.split(".");
    if (parts.length !== 3) return false;
    const [h, p, s] = parts;
    // zip215:false → RFC 8032 strictness, matching the Python/Rust verifiers (no non-canonical sigs).
    if (!ed25519.verify(b64urlDecode(s), enc.encode(`${h}.${p}`), aidToPubkey(issuerAid), { zip215: false }))
      return false;
    const header = JSON.parse(Buffer.from(h, "base64url").toString());
    const payload = JSON.parse(Buffer.from(p, "base64url").toString());
    if (header.alg !== "EdDSA" || header.typ !== "aitp-tct+jwt") return false;
    if (!(payload.iss === payload.sub && payload.sub === payload.aud && payload.aud === issuerAid))
      return false;
    const now = nowS ?? Math.floor(Date.now() / 1000);
    if (now >= (payload.exp ?? 0)) return false; // RFC 7519: reject at/after expiry
    return (payload.grants ?? []).includes("seam-commitment-digest:" + seamCommitmentDigest(commitment));
  } catch {
    return false;
  }
}

// ── A14 authenticity framing (seam-event.v1) ─────────────────────────────────────────────────────────
// frame(x) = u32le(len) || x ; opt(x) = 0x00 if null else 0x01 || frame(x). Transcribed from
// `seam-event.v1.md`. NOTE the u32 LITTLE-endian length prefix here — distinct from `lenPrefix` above
// (8-byte big-endian, the commitment-digest framing). These let a client verify a chain-head attestation
// or recompute a v2 record digest in-language, from the published spec alone.

function frameLE(b: Uint8Array): Uint8Array {
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, b.length, true); // little-endian
  return concat(len, b);
}

function optLE(s: string | null | undefined): Uint8Array {
  if (s === null || s === undefined) return new Uint8Array([0]);
  return concat(new Uint8Array([1]), frameLE(enc.encode(s)));
}

function u64le(n: number | bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), true);
  return out;
}
function u32le(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, true);
  return out;
}

/** Recompute a v2 `DECISION_SEALED` record digest (`seam.audit.record-digest.v2`) from its on-wire
 * structural columns + `ciphertextDigest` (SHA256(ciphertext), tag 10) — compare to the wire `digest`
 * (tag 19) to catch a payload rewrite (A14 design-a). Preimage order is NOT wire-tag order; the `opt`
 * presence byte is raw, so `null` and `""` are distinct. */
export function recordDigestV2(d: {
  decisionId: string;
  tenant: string;
  namespace: string;
  ciphertextDigest: Uint8Array;
  sealedAt: number | bigint;
  outcome: string;
  mode: string | null;
  policyVersion: string | null;
  supersedes: string | null;
  schemaVersion?: number;
}): Uint8Array {
  const pre = concat(
    frameLE(enc.encode("seam.audit.record-digest.v2")),
    frameLE(enc.encode(d.decisionId)),
    frameLE(enc.encode(d.tenant)),
    frameLE(enc.encode(d.namespace)),
    frameLE(d.ciphertextDigest),
    frameLE(u64le(d.sealedAt)),
    frameLE(enc.encode(d.outcome)),
    optLE(d.mode),
    optLE(d.policyVersion),
    optLE(d.supersedes),
    frameLE(u32le(d.schemaVersion ?? 2)),
  );
  return sha256(pre);
}

function chainHeadAttestationDigest(a: {
  attestedLen: number | bigint;
  attestedHead: Uint8Array;
  attestedAt: number | bigint;
  digestSchema: number;
  issuerAid: string;
}): Uint8Array {
  const pre = concat(
    frameLE(enc.encode("seam.audit.chain-head-attestation.v1")),
    frameLE(u64le(a.attestedLen)),
    frameLE(a.attestedHead),
    frameLE(u64le(a.attestedAt)),
    frameLE(u32le(a.digestSchema)),
    frameLE(enc.encode(a.issuerAid)),
  );
  return sha256(pre);
}

/** Verify a chain-head attestation's Ed25519 signature against the PINNED issuer AID (A14). `true` iff the
 * signature checks out over the recomputed digest; `false` on any tamper. The key comes from `issuerAid`
 * (pinned out of band), never from the attestation itself. */
export function verifyChainHeadAttestation(
  issuerAid: string,
  a: {
    attestedLen: number | bigint;
    attestedHead: Uint8Array;
    attestedAt: number | bigint;
    digestSchema: number;
    signature: Uint8Array;
  },
): boolean {
  try {
    const digest = chainHeadAttestationDigest({ ...a, issuerAid });
    return ed25519.verify(a.signature, digest, aidToPubkey(issuerAid), { zip215: false });
  } catch {
    return false;
  }
}
