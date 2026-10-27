// Management-plane DPoP (seam-sdk#290; grammar: docs/specs/mgmt-dpop.md, a pinned copy of the runtime's).
//
// An operator token minted with a key binding (`cnf.jkt`) is refused as Bearer: every management call
// must carry `authorization: DPoP <token>` plus a fresh RFC 9449 proof — a compact JWS signed by the
// Ed25519 key the management console revealed once, next to the token. The proof binds the call
// (`htm`/`htu`), the token (`ath`) and the exact request bytes (`seam_bd`), and the runtime burns each one
// on first use, so every attempt is signed anew.
//
// Every string reaching a signed JSON object is printable ASCII (enforced below), so `JSON.stringify`
// emits the same bytes as every other SDK's encoder. `conformance/mgmt_dpop_vector.json` pins them.

import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";

/** The runtime's operator audience when `SEAM_RUNTIME_AUD` is unset — the authority of every gRPC `htu`. */
export const DEFAULT_OPERATOR_AUD = "seam-runtime";
/** The runtime refuses a proof larger than this. */
export const MGMT_DPOP_MAX_PROOF_BYTES = 8 * 1024;
/** The runtime buffers at most this much request body (HTTP) or message (gRPC) to bind it. */
export const MGMT_DPOP_MAX_BODY_BYTES = 1024 * 1024;
/** The runtime refuses a longer `jti`. */
export const MGMT_DPOP_MAX_JTI_BYTES = 256;
/** The largest `iat` every SDK accepts: `Number.MAX_SAFE_INTEGER` (2^53 - 1). */
export const MGMT_DPOP_MAX_IAT = Number.MAX_SAFE_INTEGER;

const B64URL = /^[A-Za-z0-9_-]*$/;
// Visible ASCII (a header value: no space) and printable ASCII (space allowed). JavaScript's `$` never
// matches before a trailing newline without the `m` flag, unlike Python's.
const TOKEN_CHARS = /^[\x21-\x7e]+$/;
const PRINTABLE = /^[\x20-\x7e]+$/;
// RFC 9110 `token`: what an HTTP method is allowed to be.
const METHOD = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/** A DPoP input the SDK refuses locally, before any network call. Never thrown for a wire error. */
export class DpopError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DpopError";
  }
}

/** The key, or the token it is meant to be bound to, cannot work: a malformed JWK, a JWK whose `x` is
 * not the public half of its `d`, a token of valid characters that is not a compact JWS or carries no
 * `cnf.jkt`, a `cnf.jkt` naming a different key, a missing token, or a token whose `aud` is a list. */
export class DpopKeyError extends DpopError {
  constructor(message: string) {
    super(message);
    this.name = "DpopKeyError";
  }
}

const enc = new TextEncoder();

function b64url(b: Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}

function b64url32(name: string, value: unknown): Uint8Array {
  if (typeof value !== "string") throw new DpopKeyError(`JWK member "${name}" must be a string`);
  // A length of 1 mod 4 is not base64 at all.
  if (!B64URL.test(value) || value.length % 4 === 1) {
    throw new DpopKeyError(`JWK member "${name}" must be unpadded base64url`);
  }
  const raw = new Uint8Array(Buffer.from(value, "base64url"));
  if (raw.length !== 32) {
    throw new DpopKeyError(`JWK member "${name}" must decode to 32 bytes, got ${raw.length}`);
  }
  // Stray low bits in the last character decode to the same bytes but a different thumbprint.
  if (b64url(raw) !== value) throw new DpopKeyError(`JWK member "${name}" is not canonical base64url`);
  return raw;
}

function sha256b64url(data: Uint8Array): string {
  return b64url(sha256(data));
}

function json(obj: object): Uint8Array {
  return enc.encode(JSON.stringify(obj));
}

/** The Ed25519 key an operator token is bound to.
 *
 * Load it from the JWK the management console reveals once, next to the token —
 * `{"kty":"OKP","crv":"Ed25519","x":...,"d":...}` — with {@link OperatorDpopKey.fromJwk}. Keep that JWK as
 * secret as the token. The private half lives in a private field: `toString`, `util.inspect` and
 * `JSON.stringify` show only the thumbprint. */
/** Signs with a key's private seed. Module-private, so the seed's only use is never part of the published API. */
let signWith: (key: OperatorDpopKey, message: Uint8Array) => Uint8Array;

export class OperatorDpopKey {
  readonly #seed: Uint8Array;
  /** The public key, unpadded base64url — the JWK's `x`. */
  readonly x: string;
  /** The RFC 7638 thumbprint the runtime compares against the token's `cnf.jkt`. */
  readonly jkt: string;

  private constructor(seed: Uint8Array) {
    this.#seed = Uint8Array.from(seed);
    this.x = b64url(ed25519.getPublicKey(this.#seed));
    // RFC 7638: SHA-256 over the required members in lexicographic order, no whitespace.
    this.jkt = sha256b64url(json({ crv: "Ed25519", kty: "OKP", x: this.x }));
  }

  /** A key from its raw 32-byte Ed25519 seed (the JWK's `d`, decoded). The bytes are copied. */
  static fromSeed(seed: Uint8Array): OperatorDpopKey {
    if (!(seed instanceof Uint8Array) || seed.length !== 32) {
      throw new DpopKeyError("an Ed25519 seed must be exactly 32 bytes");
    }
    return new OperatorDpopKey(seed);
  }

  /** A key from a private OKP/Ed25519 JWK, as JSON text or an already-parsed object. `x` is checked
   * against the public key derived from `d`, so a reveal pasted with a typo fails here, by name. `kid`
   * and other members that do not contradict an Ed25519 signing key are ignored. */
  static fromJwk(jwk: string | Record<string, unknown>): OperatorDpopKey {
    let obj: unknown = jwk;
    if (typeof jwk === "string") {
      try {
        obj = JSON.parse(jwk);
      } catch (e) {
        if (e instanceof RangeError) throw new DpopKeyError("JWK is not valid JSON: nested too deeply");
        // Never quote the parser's message: V8's carries the text around the error, which can be part of `d`.
        throw new DpopKeyError("JWK is not valid JSON");
      }
    }
    if (typeof obj !== "object" || obj === null || Array.isArray(obj)) {
      throw new DpopKeyError("JWK must be a JSON object");
    }
    const m = obj as Record<string, unknown>;
    const has = (k: string) => Object.prototype.hasOwnProperty.call(m, k);
    if (m.kty !== "OKP") throw new DpopKeyError('JWK "kty" must be "OKP"');
    if (m.crv !== "Ed25519") throw new DpopKeyError('JWK "crv" must be "Ed25519"');
    if (has("alg") && m.alg !== "EdDSA" && m.alg !== "Ed25519") {
      throw new DpopKeyError('JWK "alg", when present, must be "EdDSA" or "Ed25519"');
    }
    if (has("use") && m.use !== "sig") throw new DpopKeyError('JWK "use", when present, must be "sig"');
    if (!has("d")) throw new DpopKeyError('JWK has no "d": a public JWK cannot sign proofs');
    if (!has("x")) throw new DpopKeyError('JWK has no "x"');
    const seed = b64url32("d", m.d);
    b64url32("x", m.x);
    const key = new OperatorDpopKey(seed);
    if (key.x !== m.x) throw new DpopKeyError('JWK "x" is not the public key of its "d"');
    return key;
  }

  /** The public JWK, in the member order a proof header carries it. */
  publicJwk(): { kty: "OKP"; crv: "Ed25519"; x: string } {
    return { kty: "OKP", crv: "Ed25519", x: this.x };
  }

  static {
    signWith = (key, message) => ed25519.sign(message, key.#seed);
  }

  toString(): string {
    return `OperatorDpopKey(jkt=${JSON.stringify(this.jkt)})`;
  }

  toJSON(): { jkt: string } {
    return { jkt: this.jkt };
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }
}

/** A fresh proof id: 16 random bytes as unpadded base64url (22 characters). */
export function newMgmtDpopJti(): string {
  return b64url(globalThis.crypto.getRandomValues(new Uint8Array(16)));
}

function checkToken(token: unknown): string {
  if (typeof token !== "string" || token.length === 0) {
    throw new DpopError("the operator token must be a non-empty string");
  }
  if (!TOKEN_CHARS.test(token)) throw new DpopError("the operator token must be printable ASCII with no spaces");
  return token;
}

/** Inputs to {@link mgmtDpopProof}. `iat` defaults to now and `jti` to a fresh random id; pass them only
 * to reproduce a vector. */
export interface MgmtDpopProofInput {
  /** The HTTP method — `"POST"` for every gRPC call. */
  htm: string;
  /** The call's target as the runtime compares it: {@link mgmtDpopGrpcHtu} or {@link mgmtDpopHttpHtu}. */
  htu: string;
  /** The exact HTTP body, or the protobuf-encoded request message without its 5-byte frame. */
  body: Uint8Array;
  iat?: number;
  jti?: string;
}

/** The compact-JWS proof for one management call. Each proof is burned on first use, so never reuse
 * one: sign every attempt, retries included. */
export function mgmtDpopProof(key: OperatorDpopKey, token: string, input: MgmtDpopProofInput): string {
  if (!(key instanceof OperatorDpopKey)) throw new DpopError("key must be an OperatorDpopKey");
  checkToken(token);
  const { htm, htu, body } = input;
  if (typeof htm !== "string" || !METHOD.test(htm)) throw new DpopError("htm must be an HTTP method token");
  if (typeof htu !== "string" || !PRINTABLE.test(htu)) {
    throw new DpopError("htu must be a non-empty printable-ASCII string");
  }
  if (!(body instanceof Uint8Array)) throw new DpopError("body must be a Uint8Array");
  if (body.length > MGMT_DPOP_MAX_BODY_BYTES) {
    throw new DpopError(
      `the request body is ${body.length} bytes; the runtime binds at most ${MGMT_DPOP_MAX_BODY_BYTES} and refuses a larger one`,
    );
  }
  const iat = input.iat ?? Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(iat) || iat < 0) {
    throw new DpopError("iat must be a non-negative integer number of seconds");
  }
  const jti = input.jti ?? newMgmtDpopJti();
  if (typeof jti !== "string" || !PRINTABLE.test(jti)) {
    throw new DpopError("jti must be a non-empty printable-ASCII string");
  }
  if (jti.length > MGMT_DPOP_MAX_JTI_BYTES) {
    throw new DpopError(`jti must be at most ${MGMT_DPOP_MAX_JTI_BYTES} bytes`);
  }

  // Member order is the spec's; insertion order is preserved for these non-integer keys.
  const header = { typ: "dpop+jwt", alg: "EdDSA", jwk: key.publicJwk() };
  const claims = {
    jti,
    htm,
    htu,
    iat,
    ath: sha256b64url(enc.encode(token)),
    seam_bd: sha256b64url(body),
  };
  const signingInput = `${b64url(json(header))}.${b64url(json(claims))}`;
  const proof = `${signingInput}.${b64url(signWith(key, enc.encode(signingInput)))}`;
  if (proof.length > MGMT_DPOP_MAX_PROOF_BYTES) {
    throw new DpopError(
      `the proof is ${proof.length} bytes; the runtime refuses one over ${MGMT_DPOP_MAX_PROOF_BYTES}`,
    );
  }
  return proof;
}

/** `grpc://<aud><full method>` for a gRPC management call, e.g.
 * `grpc://seam-runtime/seam.api.v1.SeamAdmin/EnrollTenant`. `aud` is the runtime's operator audience,
 * not the dialled address. */
export function mgmtDpopGrpcHtu(method: string, aud: string = DEFAULT_OPERATOR_AUD): string {
  if (typeof method !== "string" || !method.startsWith("/") || !PRINTABLE.test(method)) {
    throw new DpopError('method must be a full gRPC method path such as "/pkg.Service/Method"');
  }
  if (typeof aud !== "string" || !TOKEN_CHARS.test(aud) || aud.includes("/")) {
    throw new DpopError("aud must be a non-empty printable-ASCII string with no spaces or '/'");
  }
  return `grpc://${aud}${method}`;
}

function firstOf(s: string, chars: string): number {
  let at = s.length;
  for (const c of chars) {
    const i = s.indexOf(c);
    if (i >= 0 && i < at) at = i;
  }
  return at;
}

/** The `htu` the runtime compares an HTTP management call against: `https://<authority><path>`.
 *
 * The scheme becomes `https`, the host is lower-cased, a default port (`:443` for https, `:80` for http)
 * is dropped, and the query and fragment are dropped. The path is kept exactly; an empty one becomes `/`.
 * A URL carrying userinfo is refused. An explicit grammar, not `URL` — which would normalise the path —
 * so every SDK derives the same `htu` from the same string. The port is 1-5 digits.
 *
 * Send the request to exactly this URL. `fetch`/`URL` normalise paths (dot-segments such as `/a/../b`
 * collapse), and a path the `htu` does not name makes the runtime refuse the proof. */
export function mgmtDpopHttpHtu(url: string): string {
  if (typeof url !== "string" || !TOKEN_CHARS.test(url)) {
    throw new DpopError("url must be a non-empty visible-ASCII string (no spaces): percent-encode any other character, and send the request to that same encoded URL");
  }
  const sepAt = url.indexOf("://");
  const scheme = sepAt < 0 ? "" : url.slice(0, sepAt).toLowerCase();
  if (scheme !== "http" && scheme !== "https") {
    throw new DpopError("url must be an absolute http:// or https:// URL");
  }
  const rest = url.slice(sepAt + 3);
  const cut = firstOf(rest, "/?#");
  const authority = rest.slice(0, cut);
  const tail = rest.slice(cut);
  const path = tail.slice(0, firstOf(tail, "?#"));
  if (authority.includes("@")) throw new DpopError("url must not carry userinfo");
  let host: string;
  let portText: string;
  if (authority.startsWith("[")) {
    const close = authority.indexOf("]");
    if (close < 2) throw new DpopError("url has a malformed IPv6 literal");
    host = authority.slice(0, close + 1);
    const after = authority.slice(close + 1);
    if (after && !after.startsWith(":")) throw new DpopError("url has a malformed IPv6 literal");
    portText = after.slice(1);
  } else {
    const colon = authority.indexOf(":");
    host = colon < 0 ? authority : authority.slice(0, colon);
    portText = colon < 0 ? "" : authority.slice(colon + 1);
    if (portText.includes(":")) {
      throw new DpopError("url has more than one ':' in its authority; bracket an IPv6 literal");
    }
  }
  if (!host) throw new DpopError("url has no host");
  host = host.toLowerCase();
  let port: number | undefined;
  if (portText) {
    if (!/^[0-9]{1,5}$/.test(portText) || Number(portText) > 65535) throw new DpopError("url has an invalid port");
    port = Number(portText);
  }
  const auth = port !== undefined && port !== (scheme === "https" ? 443 : 80) ? `${host}:${port}` : host;
  return `https://${auth}${path || "/"}`;
}

/** `{ Authorization: "DPoP <token>", DPoP: <proof> }` for one call to the HTTP management plane. Add both
 * headers to the request you send, with exactly `body` as its body (empty for a GET). Call this once per
 * request — never reuse the headers for a retry. */
export function mgmtDpopHttpHeaders(
  key: OperatorDpopKey,
  token: string,
  method: string,
  url: string,
  body: Uint8Array = new Uint8Array(),
  opts: { iat?: number; jti?: string } = {},
): { Authorization: string; DPoP: string } {
  const proof = mgmtDpopProof(key, token, { htm: method, htu: mgmtDpopHttpHtu(url), body, ...opts });
  return { Authorization: `DPoP ${token}`, DPoP: proof };
}

/** @internal The operator token's claims, decoded WITHOUT verifying it — local diagnostics only (does it
 * carry `cnf.jkt`, does that match the key, what is its `aud`); the runtime is the verifier. */
export function peekTokenClaims(token: string): Record<string, unknown> {
  checkToken(token);
  const parts = token.split(".");
  if (parts.length !== 3 || !B64URL.test(parts[1]!) || parts[1]!.length % 4 === 1) {
    throw new DpopKeyError("the operator token is not a compact JWS");
  }
  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(parts[1]!, "base64url")));
  } catch {
    throw new DpopKeyError("the operator token's payload is not JSON");
  }
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    throw new DpopKeyError("the operator token's payload is not a JSON object");
  }
  return payload as Record<string, unknown>;
}

/** @internal `cnf.jkt`, `undefined` when the token is unbound; throws on a malformed `cnf`. */
export function tokenCnfJkt(claims: Record<string, unknown>): string | undefined {
  if (!Object.prototype.hasOwnProperty.call(claims, "cnf") || claims.cnf === null) return undefined;
  const cnf = claims.cnf as Record<string, unknown>;
  if (typeof cnf !== "object" || Array.isArray(cnf) || typeof cnf.jkt !== "string") {
    throw new DpopKeyError("the operator token's cnf claim is malformed");
  }
  return cnf.jkt;
}
