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
/** A UTF-16 string containing an unpaired surrogate — not valid Unicode, and not encodable to UTF-8.
 * `TextEncoder` substitutes U+FFFD rather than failing, so any digest taken over such a string is one
 * that Python (`UnicodeEncodeError`) and Rust (`String` is always well-formed) cannot produce: a
 * cross-language divergence in a value the whole point of which is to be identical everywhere. */
function hasLoneSurrogate(s: string): boolean {
  return /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);
}

function uuidFromBytes(b: Uint8Array): string {
  const h = Buffer.from(b.subarray(0, 16)).toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

/** The runtime's derived-UUID rule (seam-runtime `docs/specs/authorize.v1.md`, P9).
 *
 * `h = SHA-256(tag || 0x00 || data)`; the id is `h[0..16]` with the RFC 9562 version-4 and variant bits
 * forced (`h[6] = (h[6] & 0x0f) | 0x40`, `h[8] = (h[8] & 0x3f) | 0x80`), rendered as the lowercase
 * hyphenated form the wire carries. One primitive serves every derived id — the PoP `message_id` and the
 * commitment TCT `jti` — so a new one is a call, not a second transcription. Pinned by
 * `conformance/vectors.json`'s `derived_uuid` block. `tag` must be ASCII. */
export function derivedUuid(tag: string, data: Uint8Array): string {
  if (typeof tag !== "string" || !/^[\x00-\x7f]*$/.test(tag)) throw new TypeError("tag must be ASCII");
  if (!(data instanceof Uint8Array)) throw new TypeError("data must be a Uint8Array");
  const h = sha256(concat(enc.encode(tag), NUL, data)).slice(0, 16);
  h[6] = (h[6] & 0x0f) | 0x40;
  h[8] = (h[8] & 0x3f) | 0x80;
  return uuidFromBytes(h);
}

/** Domain tag of the PoP `message_id` derivation (P9). */
export const POP_MESSAGE_ID_TAG = "seam-pop-mid-v1";
/** Domain tag of the commitment TCT `jti` derivation (P9). */
export const TCT_JTI_TAG = "seam-tct-jti-v1";

/** The admission `message_id`: `derivedUuid("seam-pop-mid-v1", pop_nonce_ascii)`.
 *
 * The input is the nonce's base64url ASCII text exactly as sent, not its decoded bytes. */
export function popMessageId(popNonce: string): string {
  if (typeof popNonce !== "string" || !/^[\x00-\x7f]*$/.test(popNonce))
    throw new TypeError("pop_nonce must be ASCII");
  return derivedUuid(POP_MESSAGE_ID_TAG, enc.encode(popNonce));
}

export interface Presentation {
  sender_aid: string;
  descriptor: { type: string; subject: string; proof: string; public_key: string };
  message_id: string;
  timestamp: number;
  pop_nonce: string;
}

/** The `kind` words `seam-explanation-digest:v1` frames — lowercase ASCII, exactly; never the proto enum name. */
export const EXPLANATION_KINDS = ["vote", "evaluation", "objection", "ballot"] as const;

/** One sealed explanation entry, as the digest frames it (snake_case, like {@link Commitment}).
 * `confidence` / `rationale_ref` absent (`undefined` or `null`) is NOT the same as a stated `0.0` /
 * empty string — the two produce different digests, which is the point of the digest. */
export interface ExplanationEntryInput {
  /** One of {@link EXPLANATION_KINDS}; anything else is refused. */
  kind: string;
  participant: string;
  proposal_id: string;
  value: string;
  reason: string;
  confidence?: number | null;
  rationale_ref?: string | null;
}

export interface Commitment {
  id: string;
  action: string;
  authority: string;
  auth_method: string;
  trust_basis: string;
  supersedes?: string | null;
  /** The verified AID that committed (#802); absent/empty encodes as the empty field. */
  committer?: string | null;
  /** The sealed explanation entries (#804), in sealed order. When present (even `[]`) they are
   * recomputed into field 8 and, if {@link explanation_digest} is also given, must agree with it. */
  explanation?: ExplanationEntryInput[] | null;
  /** The published `seam-explanation-digest:v1` (32 raw bytes, or 64 hex chars). Used as field 8 only
   * when no `explanation` entries are supplied; an empty value counts as "not published". */
  explanation_digest?: Uint8Array | string | null;
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
  // message_id: derived from the nonce (no RNG) under the P9 rule — see `popMessageId`.
  const messageId = popMessageId(popNonce);
  const timestamp = Math.floor(nowMs / 1000);
  // ASCII-decimal, matching message_id's text encoding
  const ts = enc.encode(String(timestamp));

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

function frame(b: Uint8Array): Uint8Array {
  return concat(lenPrefix(b), b);
}

/** UTF-8 of a digest field, refusing a string that has no UTF-8 form (see {@link hasLoneSurrogate}). */
function utf8Field(s: string, what: string): Uint8Array {
  if (typeof s !== "string") throw new TypeError(`${what} must be a string`);
  if (hasLoneSurrogate(s)) throw new Error(`${what} contains a lone surrogate`);
  return enc.encode(s);
}

/**
 * `seam-explanation-digest:v1` over a sealed explanation — 32 raw bytes.
 *
 * `SHA-256(F("seam-explanation-digest:v1") ‖ be64(count) ‖ Σ ENTRY)`, where
 * `ENTRY = F(kind) ‖ F(participant) ‖ F(proposal_id) ‖ F(value) ‖ F(reason) ‖ CONF ‖ REF`,
 * `CONF = 0x00 | 0x01 ‖ be64(IEEE-754 bits)`, `REF = 0x00 | 0x01 ‖ F(rationale_ref)`. Entries are hashed
 * in the given (sealed) order — never sorted or de-duplicated. An absent confidence and a stated `0.0` are
 * different bytes. Throws on an unknown kind or a non-canonical confidence (NaN, ±Infinity, outside
 * `[0, 1]`, or `-0.0`) rather than hashing it. Normative: `seam-runtime/docs/specs/seam-commitment-digest.v3.md`.
 */
export function explanationDigest(entries: readonly ExplanationEntryInput[]): Uint8Array {
  if (!Array.isArray(entries)) throw new TypeError("explanation must be an array");
  const count = new Uint8Array(8);
  new DataView(count.buffer).setBigUint64(0, BigInt(entries.length), false);
  const parts: Uint8Array[] = [frame(enc.encode("seam-explanation-digest:v1")), count];
  for (const e of entries) {
    if (!(EXPLANATION_KINDS as readonly string[]).includes(e.kind))
      throw new Error(`unknown explanation kind ${JSON.stringify(e.kind)}`);
    parts.push(
      frame(enc.encode(e.kind)),
      frame(utf8Field(e.participant, "participant")),
      frame(utf8Field(e.proposal_id, "proposal_id")),
      frame(utf8Field(e.value, "value")),
      frame(utf8Field(e.reason, "reason")),
    );
    const conf = e.confidence;
    if (conf === undefined || conf === null) {
      parts.push(new Uint8Array([0]));
    } else {
      if (typeof conf !== "number" || !Number.isFinite(conf) || conf < 0 || conf > 1 || Object.is(conf, -0))
        throw new Error(`non-canonical confidence ${String(conf)}`);
      const c = new Uint8Array(9);
      c[0] = 1;
      new DataView(c.buffer).setFloat64(1, conf, false);
      parts.push(c);
    }
    const ref = e.rationale_ref;
    parts.push(
      ref === undefined || ref === null
        ? new Uint8Array([0])
        : concat(new Uint8Array([1]), frame(utf8Field(ref, "rationale_ref"))),
    );
  }
  return sha256(concat(...parts));
}

function publishedExplanationDigest(d: Uint8Array | string | null | undefined): Uint8Array | undefined {
  if (d === undefined || d === null) return undefined;
  let b: Uint8Array;
  if (typeof d === "string") {
    if (!/^([0-9a-fA-F]{2})*$/.test(d)) throw new Error("explanation_digest is not hex");
    b = new Uint8Array(Buffer.from(d, "hex"));
  } else {
    b = d;
  }
  // The proto `bytes explanation_digest` is an empty array when unset; empty = "not published".
  return b.length === 0 ? undefined : b;
}

/** The explanation digest a commitment binds as field 8, checked when the entries are present.
 *
 * Mirrors the Python SDK's `_commitment_explanation_digest`: entries supplied (even `[]`) → recomputed,
 * and a published digest, if also supplied, must equal it (spec §Verification step 1) or this throws;
 * only a published digest → used as published (verifies *who* and *what*, not *why*); neither → the
 * digest of the empty explanation. */
function commitmentExplanationDigest(c: Commitment): Uint8Array {
  const published = publishedExplanationDigest(c.explanation_digest);
  if (c.explanation === undefined || c.explanation === null) return published ?? explanationDigest([]);
  const computed = explanationDigest(c.explanation);
  if (published !== undefined && Buffer.compare(Buffer.from(published), Buffer.from(computed)) !== 0)
    throw new Error("explanation_digest does not match the explanation entries");
  return computed;
}

/** `seam-commitment-digest:v3` (hex): SHA-256 over the length-prefixed domain tag and fields
 * `(id, action, authority, supersedes, auth_method, trust_basis, committer, explanation_digest)`.
 *
 * Every field is `F(x) = be64(len) || x` (no separator), so the digest is injective over the tuple. The
 * length prefixes are load-bearing: with a NUL separator instead, `("a\0b", "c")` and `("a", "b\0c")`
 * would collide — identical preimages, so one Commitment could verify under another's TCT — and these
 * fields are arbitrary text that may itself contain NUL. Never "simplify" them away. `supersedes` alone
 * carries a presence byte: `0x00` when absent (`undefined` or `null`), `0x01 || F(value)` when present —
 * so an absent prior and a present empty one are different digests. Field 8 is the 32 RAW bytes of the
 * explanation digest. v1 and v2 are deleted, not dual-verified. Mirrors the runtime byte-for-byte;
 * normative: `seam-runtime/docs/specs/seam-commitment-digest.v3.md`. */
export function seamCommitmentDigest(c: Commitment): string {
  const supersedes = c.supersedes;
  const parts = [
    frame(enc.encode("seam-commitment-digest:v3")),
    frame(utf8Field(c.id, "id")),
    frame(utf8Field(c.action, "action")),
    frame(utf8Field(c.authority, "authority")),
    supersedes === undefined || supersedes === null
      ? new Uint8Array([0])
      : concat(new Uint8Array([1]), frame(utf8Field(supersedes, "supersedes"))),
    frame(utf8Field(c.auth_method, "auth_method")),
    frame(utf8Field(c.trust_basis, "trust_basis")),
    frame(utf8Field(c.committer || "", "committer")),
    frame(commitmentExplanationDigest(c)),
  ];
  return Buffer.from(sha256(concat(...parts))).toString("hex");
}

/** The `ext` key a Seam commitment self-attestation carries its statement under (RFC-AITP-0005). */
export const COMMITMENT_EXT_KEY = "com.zer07labs.seam";
/** The only grant a commitment self-attestation TCT may carry. */
export const ATTESTATION_GRANT = "aitp.attestation";

/** True when any JSON object in `text` repeats a key. `JSON.parse` silently keeps the LAST duplicate,
 * so two parsers can read two different statements from one signed payload; this scan is what lets
 * {@link verifyTct} refuse such a payload, as Python's `object_pairs_hook` does. Keys are compared after
 * unescaping (`"a"` and `"a"` are the same key). Assumes `text` is valid JSON — the caller parses
 * it with `JSON.parse` as well, which refuses anything malformed. */
function jsonHasDuplicateKey(text: string): boolean {
  // One entry per open container: the keys seen so far for an object, `null` for an array.
  const stack: (Set<string> | null)[] = [];
  let expectKey = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      if (j >= text.length) throw new SyntaxError("unterminated JSON string");
      const top = stack[stack.length - 1];
      if (expectKey && top) {
        const key = JSON.parse(text.slice(i, j + 1)) as string;
        if (top.has(key)) return true;
        top.add(key);
        expectKey = false;
      }
      i = j;
    } else if (ch === "{") {
      stack.push(new Set());
      expectKey = true;
    } else if (ch === "[") {
      stack.push(null);
      expectKey = false;
    } else if (ch === "}" || ch === "]") {
      stack.pop();
      expectKey = false;
    } else if (ch === ",") {
      expectKey = !!stack[stack.length - 1];
    } else if (ch === ":") {
      expectKey = false;
    }
  }
  return false;
}

/** `JSON.parse` that refuses a duplicate object key anywhere in the document. */
function parseJsonNoDuplicates(text: string): unknown {
  const value: unknown = JSON.parse(text);
  if (jsonHasDuplicateKey(text)) throw new SyntaxError("duplicate JSON key");
  return value;
}

function isJsonObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Independently verify a sealed commitment's rooted TCT — zero server trust, stock crypto only.
 *
 * The TCT is an RFC-AITP-0005 self-attestation. Checks the EdDSA JWS against the issuer AID's key, the
 * self-issued claims (`typ`, `iss==sub==aud==issuerAid`, `exp`), that `grants` is exactly
 * `["aitp.attestation"]`, and that `ext` is exactly
 * `{"com.zer07labs.seam": {"type": "seam:commitment", "commitment_digest": <hex>}}` whose digest is
 * `seam-commitment-digest:v3` of this exact commitment — its decided content, its committer and its
 * sealed explanation. A duplicate JSON key anywhere in the header or payload, a statement carried in
 * `grants` (the retired v2 shape), or an extra grant verifies `false`. Explanation entries that disagree
 * with the published digest, an unknown kind, or a non-canonical confidence verify `false`; this never
 * throws. */
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
    const header = parseJsonNoDuplicates(Buffer.from(h, "base64url").toString());
    const payload = parseJsonNoDuplicates(Buffer.from(p, "base64url").toString());
    if (!isJsonObject(header) || !isJsonObject(payload)) return false;
    if (header.alg !== "EdDSA" || header.typ !== "aitp-tct+jwt") return false;
    if (!(payload.iss === payload.sub && payload.sub === payload.aud && payload.aud === issuerAid))
      return false;
    const now = nowS ?? Math.floor(Date.now() / 1000);
    // `exp` must be a JSON NUMBER, and is truncated to whole seconds before the comparison. Both
    // halves are load-bearing, and neither was true here before:
    //
    //   * `now >= payload.exp` let JS coerce. A string `exp` compares by numeric coercion, so
    //     `"1e10"` and `"10000000000"` were both ACCEPTED — Go's `payload["exp"].(float64)` and
    //     Java's `instanceof Number` refuse a string outright. Worse, `true` coerces to `1`: at any
    //     `now` below 1 the token VERIFIED. That last one is invisible at a realistic clock, which
    //     is why the shared vector pins `now = 0`.
    //   * the comparison was float-precise, so `exp = N + 0.5` was still valid at `now = N` while
    //     every other shim had already expired it. Go's comment calls this out by name: a
    //     float-precise compare "would accept it and drift from the shims".
    //
    // Go's rule is normative because Java and Kotlin already implement it, making it the 3-of-5
    // majority; it is the only one with a written rationale; and it is the strictest, which is the
    // safe direction for a token verifier. See DECISIONS.md.
    const exp = payload.exp;
    if (typeof exp !== "number" || !Number.isFinite(exp)) return false;
    // Bounded to int64 because the normative rule is: Go's `int64(exp)` is implementation-defined
    // when the value does not fit, and `exp: 1e300` verified on arm64 (saturating to MaxInt64) while
    // amd64 refused the identical token. JavaScript has no such hazard — `Math.trunc` is total — so
    // this bound buys TypeScript nothing alone. It is here so all five SDKs answer the same thing.
    // 2^63 is exactly representable as a double, so the comparison is exact.
    if (exp >= 9223372036854775808 || exp < -9223372036854775808) return false;
    if (now >= Math.trunc(exp)) return false; // RFC 7519: reject at/after expiry
    const grants = payload.grants;
    if (!Array.isArray(grants) || grants.length !== 1 || grants[0] !== ATTESTATION_GRANT) return false;
    const ext = payload.ext;
    if (!isJsonObject(ext)) return false;
    const extKeys = Object.keys(ext);
    if (extKeys.length !== 1 || extKeys[0] !== COMMITMENT_EXT_KEY) return false;
    const stmt = ext[COMMITMENT_EXT_KEY];
    if (!isJsonObject(stmt)) return false;
    const stmtKeys = Object.keys(stmt);
    if (stmtKeys.length !== 2 || !stmtKeys.includes("type") || !stmtKeys.includes("commitment_digest"))
      return false;
    if (stmt.type !== "seam:commitment") return false;
    // Exact string compare: the runtime emits lowercase hex, and an uppercase spelling is a different
    // statement, not a normalization opportunity.
    return stmt.commitment_digest === seamCommitmentDigest(commitment);
  } catch {
    return false;
  }
}

// ── RFC 8785 (JCS) canonicalization + the Authorize call binding ─────────────────────────────────────
// `toolInputDigest` is what `callSig` signs and what the advisory audit row records — a one-way door
// pinned by the runtime's cross-language vector (`conformance/authorize_jcs_digest_vector.json`), which
// must match the Python SDK byte-for-byte. There is deliberately NO bless mode: a mismatch is a
// CONTRACT BREAK, not a prompt to regenerate.
//
// ES6 is JCS's native habitat: `String(number)` IS the required Number::toString rendering, default
// string sort IS UTF-16 code-unit order, and `JSON.stringify` of a *string* IS the minimal escaping.

const MAX_SAFE = 9007199254740992n; // 2^53 — inside this range a bigint's own decimal form IS its JCS rendering

/** Render a bigint the way JCS renders it, or refuse it — never silently a different number.
 *
 * JCS numbers are IEEE doubles, so the only integers that can appear in canonical output are the
 * ones ES6 `Number::toString` prints as themselves. That is the predicate, stated literally.
 *
 * The obvious alternative — "is it exactly representable as a double" — is wrong, and wrong in the
 * direction that signs a digest over a value nobody supplied: `2n ** 60n` IS exactly representable,
 * and `String(Number(2n ** 60n))` is `"1152921504606847000"`, not `"1152921504606846976"`. The two
 * answers diverge from about 2^55.
 *
 * Returning `rendered` rather than `text` is defence in depth, not load-bearing, and it is worth
 * being precise about which: the guard above already requires the two to be equal, so on every
 * accepted value they are provably the same string. It is written this way so that if the guard is
 * ever weakened, what escapes is still the ES6 rendering — matching Python — rather than the bigint's
 * own decimal form. Byte-identity with Python is what actually holds the line, pinned by
 * `conformance/authorize_jcs_int_extended.json`.
 */
function jcsBigInt(v: bigint): string {
  const text = v.toString();
  if (v <= MAX_SAFE && v >= -MAX_SAFE) return text;
  const asNumber = Number(v);
  if (!Number.isFinite(asNumber))
    throw new Error(`integer ${text} is too large to represent as an IEEE double, so JCS cannot render it`);
  const rendered = String(asNumber);
  if (rendered !== text)
    throw new Error(
      `integer ${text} is not JCS-renderable as itself: canonicalizing it would emit ${rendered}, a different value. ` +
        `JSON numbers are IEEE doubles; this integer is not one a double prints back unchanged, so digesting it ` +
        `would sign a value nobody supplied.`,
    );
  return rendered;
}

/** Is this a plain data object — the thing Python's `isinstance(v, dict)` accepts and nothing else?
 *
 * `typeof v === "object"` is true of `Date`, `Map`, `Set`, `RegExp`, typed arrays, boxed primitives
 * and every class instance, and JCS walked all of them with `Object.keys`. What came out was
 * whatever their own enumerable properties happened to be, which is not what any of them mean —
 * measured, before this guard:
 *
 *     jcsCanonicalize(new Date(0))            -> {}
 *     jcsCanonicalize(new Map([["a", 1]]))    -> {}
 *     jcsCanonicalize(new Set([1, 2]))        -> {}
 *     jcsCanonicalize(new Number(5))          -> {}
 *     jcsCanonicalize(new Uint8Array([1, 2])) -> {"0":1,"1":2}
 *     jcsCanonicalize(new String("x"))        -> {"0":"x"}
 *     jcsCanonicalize(new (class { x = 1 })()) -> {"x":1}
 *
 * The last three matter for being different: they did NOT collapse to `{}`, they serialized their
 * indices or their fields. So "none of these keep state in own enumerable properties" is a
 * generalization the examples themselves refute, and refusing a class instance is a real narrowing
 * of something that worked — not the removal of a meaningless digest. It is refused anyway, because
 * Python refuses the same input and agreement about what has a digest is the property being bought.
 *
 * Which means `{ deadline: new Date("2026-01-01") }` and `{ deadline: new Date("2030-01-01") }` had
 * the SAME `tool_input_digest`, and `call_sig` signed it. That is digest aliasing on an input a
 * TypeScript caller produces without thinking about it — a `Date` in a request object — and it is
 * the same defect class as the u64 wrap and the surrogate key, in the third place the rule lives.
 * Python raises `TypeError: datetime is not JSON-serializable` on the identical input.
 *
 * The test is deliberately a RULE and not a denylist of `Date | Map | Set | ...`: an enumeration is
 * only ever correct until someone passes the exotic type it forgot, and "silently digests an object
 * with none of its contents" is not a failure mode worth leaving one more hole in. An object
 * qualifies iff its prototype is a ROOT — `null`, or something whose own prototype is `null`. A
 * plain `{}` and `Object.create(null)` pass; `Date`, `Map`, `Set`, `Uint8Array`, `new Number(5)` and
 * class instances all sit one link further down the chain and do not.
 *
 * Testing the chain's DEPTH rather than `proto === Object.prototype` is what keeps this correct
 * across realms: an object from a `vm` context or another frame has a different `Object.prototype`,
 * and an identity check would refuse a perfectly ordinary data bag. Its prototype's prototype is
 * still `null`. */
function isPlainObject(v: object): boolean {
  const proto: unknown = Object.getPrototypeOf(v);
  return proto === null || Object.getPrototypeOf(proto as object) === null;
}

/** Name the type that was refused and the one-liner that converts it — an error reading only "not
 * serializable" leaves the caller hunting for which field of a nested request object was the
 * problem, which is the whole reason they reached for a digest library instead of writing one. */
function notPlainObjectMessage(v: object): string {
  const tag = Object.prototype.toString.call(v).slice(8, -1);
  // `||`, not `??`: an anonymous class (`new (class { x = 1 })()`) has `constructor.name === ""` —
  // present, and useless. That produced a message opening " is not JSON-serializable".
  const ctor = (v.constructor as { name?: string } | undefined)?.name || "";
  // A class instance's tag IS "Object", so the tag alone would render the self-contradicting
  // "Object is not JSON-serializable: JCS canonicalizes plain objects". Name what it actually is.
  const [what, fix] =
    tag === "Object"
      ? [
          // `Object.create({ a: 1 })` has a non-root prototype and a `constructor` of `Object`, so
          // naming the constructor produced "an instance of Object is not JSON-serializable: JCS
          // canonicalizes plain objects" — the self-contradiction this branch exists to avoid,
          // one prototype link further out than the case it was written for.
          ctor && ctor !== "Object" ? `an instance of ${ctor}` : "an object with a non-root prototype",
          "spread it: `{ ...value }`",
        ]
      : [
          `a ${ctor || tag}`,
          {
            Date: "pass `date.toISOString()`",
            Map: "pass `Object.fromEntries(map)`",
            Set: "pass `[...set]`",
            RegExp: "pass `regexp.source`",
          }[tag] ?? "convert it to plain JSON data first",
        ];
  return (
    `${what} is not JSON-serializable: JCS canonicalizes plain objects, arrays, strings, numbers, ` +
    `booleans and null, and nothing else. Canonicalizing this would emit only its own enumerable ` +
    `properties — for most such types, none at all — so the digest would not bind its contents. ` +
    `To digest it, ${fix}.`
  );
}

function jcsWrite(v: unknown): string {
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "number":
      if (!Number.isFinite(v)) throw new Error("NaN and Infinity cannot be canonicalized (RFC 8785)");
      return v === 0 ? "0" : String(v); // String(-0) is "0", matching ES6 ToString
    case "bigint":
      return jcsBigInt(v);
    case "string":
      // A lone surrogate cannot encode to UTF-8; Python raises on it (UnicodeEncodeError) and the
      // Rust runtime cannot represent it — silently emitting `\udXXX` here would let TS digest a
      // string no other implementation can, a cross-language divergence in a signed digest.
      if (hasLoneSurrogate(v))
        throw new Error("lone surrogate in string cannot be canonicalized (not valid Unicode)");
      return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(jcsWrite).join(",") + "]";
  if (typeof v === "object") {
    if (!isPlainObject(v)) throw new TypeError(notPlainObjectMessage(v));
    const o = v as Record<string, unknown>;
    // Default Array.prototype.sort() compares UTF-16 code units — exactly RFC 8785 §3.2.3.
    const keys = Object.keys(o).sort();
    return (
      "{" +
      keys
        .map((k) => {
          // The same refusal as the string case above, in the position it was missing from. A key is
          // as much a part of the canonical bytes as a value: `{"\ud800": 1}` canonicalized here
          // while Python raised `UnicodeEncodeError` on the identical input, so TS could digest an
          // object no other implementation can represent — in a value whose entire purpose is to be
          // identical everywhere. Checked before `JSON.stringify`, which emits the `\udXXX` escape
          // quite happily.
          if (hasLoneSurrogate(k))
            throw new Error(
              `lone surrogate in object key ${JSON.stringify(k)} cannot be canonicalized ` +
                `(not valid Unicode)`,
            );
          return JSON.stringify(k) + ":" + jcsWrite(o[k]);
        })
        .join(",") +
      "}"
    );
  }
  throw new TypeError(`${typeof v} is not JSON-serializable`);
}

/** RFC 8785 (JCS) canonical JSON bytes — sorted keys (UTF-16 code-unit order), ES6 number rendering,
 * minimal string escaping, UTF-8 encoded, no whitespace. */
export function jcsCanonicalize(obj: unknown): Uint8Array {
  return enc.encode(jcsWrite(obj));
}

/** `"sha256:<hex>"` over already-canonical JCS bytes (from {@link jcsCanonicalize}). */
export function toolInputDigest(canonical: Uint8Array): string {
  return "sha256:" + Buffer.from(sha256(canonical)).toString("hex");
}

/** Domain separation for the per-call proof-of-possession. `v2` because the signed payload grew
 * from `ticket || digest` to additionally cover `toolName` and `agentId`; the distinct tag means a
 * v1 signature can NEVER verify as a v2 one, so an SDK/runtime version skew is a clean rejection
 * rather than a parse ambiguity. Bump only in lockstep with the runtime. */
export const CALL_SIG_CONTEXT = "seam-authorize-call-v2";

/** The exact bytes `callSig` signs — `frame(context) || frame(ticket) || frame(toolInputDigest) ||
 * frame(toolName) || frame(agentId)`, where `frame(x) = u32le(len(x)) || x` over UTF-8.
 *
 * Length prefixing is load-bearing now that the payload is multi-field: concatenating raw would
 * frame `("read","x")` and `("read_x","")` identically, re-opening the re-pointing gap this closes.
 * Lengths are BYTE counts — `enc.encode` before measuring, never `.length` on the string.
 *
 * `agentId` is the raw wire value (the empty string when omitted, signed verbatim rather than
 * skipped), matching the server's framing at verify time.
 *
 * Pinned by `conformance/call_sig_payload_vector.json`, whose bytes were generated by executing the
 * runtime's Rust `call_sig_payload` — so this must match Python byte-for-byte, and both must match
 * the runtime. */
export function callSigPayload(
  ticket: Uint8Array,
  toolInputDigest: string,
  toolName: string,
  agentId: string,
): Uint8Array {
  const parts = [
    enc.encode(CALL_SIG_CONTEXT),
    ticket,
    enc.encode(toolInputDigest),
    enc.encode(toolName),
    enc.encode(agentId),
  ];
  const out = new Uint8Array(parts.reduce((n, p) => n + 4 + p.length, 0));
  const view = new DataView(out.buffer);
  let off = 0;
  for (const p of parts) {
    view.setUint32(off, p.length, true); // little-endian
    out.set(p, off + 4);
    off += 4 + p.length;
  }
  return out;
}

/** The per-call proof-of-possession for `authorize()`: Ed25519 by the agent key over
 * {@link callSigPayload}.
 *
 * Binding the *digest* stops a captured signature being re-pointed at a different input; binding
 * the *toolName* and *agentId* stops it being re-pointed at a different tool call or registry agent
 * while the ticket is live; binding the *ticket bytes* stops replay against a later ticket.
 *
 * `toolName` and `agentId` are required and have no defaults on purpose: a default would let an
 * existing caller keep compiling while emitting a signature the runtime rejects as
 * `UNAUTHENTICATED: admission ticket is not valid` — which names the wrong artifact entirely. */
export function callSig(
  agentSeed: Uint8Array,
  ticket: Uint8Array,
  digest: string,
  toolName: string,
  agentId: string,
): Uint8Array {
  return ed25519.sign(callSigPayload(ticket, digest, toolName, agentId), agentSeed);
}

// ── The per-request credential (`seam-request-call-v1`, #508) ──────────────────────────────────────
// A DIFFERENT domain tag from `seam-authorize-call-v2` above, deliberately, so a captured Authorize
// callSig is never spendable as a request credential and vice versa. See `plans/archive/request-credential.md`
// for the full contract; pinned by `conformance/request_sig_payload_vector.json`, generated from the
// runtime's Rust reference.
export const REQUEST_SIG_CONTEXT = "seam-request-call-v1";

/** The exact bytes `requestSig` signs — `frame(context) || frame(ticket) || frame(rpcFullName) ||
 * frame(resourceId) || frame(bodyDigest)`, where `frame(x) = u32le(len(x)) || x`. Lengths are BYTE
 * counts, not character counts.
 *
 * `rpcFullName` is the gRPC full method path on BOTH transports (e.g.
 * `"/seam.api.v1.SeamCoordination/GetDecision"`), never the HTTP route pattern — that is what makes
 * one credential valid over either plane for a bodyless verb. For a bodyless read, `resourceId` is
 * the verb's id argument and `bodyDigest` is the empty string. For a bodied verb over gRPC,
 * `resourceId` is the empty string (the id lives inside the message) and `bodyDigest` covers the
 * whole DECODED request message, without the 5-byte gRPC length-prefixed-message header — see
 * {@link toolInputDigest} for the `"sha256:<hex>"` formatting.
 *
 * This function pins the FRAMING only, not the digest computation — see
 * `conformance/request_sig_payload_vector.json`'s `body_input_hex` cases, which separately pin that
 * a digest taken after parse-and-re-encode diverges from one taken over the exact wire bytes. */
export function requestSigPayload(
  ticket: Uint8Array,
  rpcFullName: string,
  resourceId: string,
  bodyDigest: string,
): Uint8Array {
  const parts = [
    enc.encode(REQUEST_SIG_CONTEXT),
    ticket,
    enc.encode(rpcFullName),
    enc.encode(resourceId),
    enc.encode(bodyDigest),
  ];
  const out = new Uint8Array(parts.reduce((n, p) => n + 4 + p.length, 0));
  const view = new DataView(out.buffer);
  let off = 0;
  for (const p of parts) {
    view.setUint32(off, p.length, true); // little-endian
    out.set(p, off + 4);
    off += 4 + p.length;
  }
  return out;
}

/** The per-request credential a caller sends as `x-seam-ticket-bin` + `x-seam-call-sig-bin` (gRPC)
 * or `x-seam-ticket` + `x-seam-call-sig` (base64, HTTP) alongside a request, to prove identity in
 * band on a deployment that strips `x-seam-subject` at its edge (`SEAM_SUBJECT_HEADERS=deny`, #710):
 * Ed25519 by the agent key over {@link requestSigPayload}.
 *
 * Binding `rpcFullName` stops a captured signature for one verb being re-pointed at a more
 * privileged one over the same ticket and resource id (e.g. `GetDecision` → the decrypted
 * `GetCommitmentProof`). Binding `resourceId`/`bodyDigest` stops it being re-pointed at a different
 * resource or request body. Binding the ticket bytes stops replay against a later one. */
export function requestSig(
  agentSeed: Uint8Array,
  ticket: Uint8Array,
  rpcFullName: string,
  resourceId: string,
  bodyDigest: string,
): Uint8Array {
  return ed25519.sign(
    requestSigPayload(ticket, rpcFullName, resourceId, bodyDigest),
    agentSeed,
  );
}

// ── A14 authenticity framing (seam-event.v1) ─────────────────────────────────────────────────────────
// frame(x) = u32le(len) || x ; opt(x) = 0x00 if null else 0x01 || frame(x). Transcribed from
// `seam-event.v1.md`. NOTE the u32 LITTLE-endian length prefix here — distinct from `lenPrefix` above
// (8-byte big-endian, the commitment-digest framing). These let a client verify a chain-head attestation
// or recompute a v4 record digest in-language, from the published spec alone.

function frameLE(b: Uint8Array): Uint8Array {
  const len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, b.length, true); // little-endian
  return concat(len, b);
}

function optLE(s: string | null | undefined): Uint8Array {
  if (s === null || s === undefined) return new Uint8Array([0]);
  return concat(new Uint8Array([1]), frameLE(enc.encode(s)));
}

// `name` is the caller's slot, so a refusal says which field was out of range rather than leaving the
// caller to guess which of five integer slots in a preimage it was. See `uintSlot` for why the check
// is here at all: without it `setBigUint64`/`setUint32` wrap silently, and two distinct inputs reach
// one digest — the one thing a digest exists to prevent.
function u64le(name: string, n: number | bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, uintSlot(name, n, 64), true);
  return out;
}
function u32le(name: string, n: number | bigint): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, Number(uintSlot(name, n, 32)), true);
  return out;
}

// ── v4 record digest (P7) ────────────────────────────────────────────────────────────────────────

/** The four v4 sub-digests (tags 11/12/13/15) are fixed-width by the spec. A wrong-length value is
 * refused rather than framed, because framing one would produce a garbage digest that a caller reports
 * as a *rewrite* — mislabelling "this field is malformed" as "someone altered the record". */
const SUB_DIGEST_LEN = 32;

/**
 * A v4 record is missing a field the formula requires (wire tag 11, 12, 14, 15, 16 or 17), or carries
 * a malformed sub-digest.
 *
 * **This is deliberately not a digest mismatch, and must never be reported as one.** The spec
 * (`seam-event.v1.md`, "Strip semantics for tags 11-17") makes those six fields mandatory on every
 * payload and requires a consumer to *refuse* — never to substitute an empty value; there is no older
 * formula to fall back to. Absent-when-required is a strip attack, and an operator has to be able to
 * tell "someone removed a field" from "someone rewrote one", because the two have different responses.
 *
 * Throwing is what makes that distinction structural rather than advisory: a mismatch is an unequal
 * return value, a strip is a thrown error, and no caller can conflate them by accident.
 *
 * Lives here rather than in `errors.ts` for the same reason the Python twin lives in `crypto.py`:
 * this module deliberately imports nothing but the two noble primitives, so a caller can verify a
 * record digest without pulling in `@connectrpc/connect` or the generated protobuf surface. It is
 * still re-exported from the package root via `export *`.
 */
export class RecordDigestStripError extends Error {
  override readonly name: string = "RecordDigestStripError";
  constructor(
    message: string,
    /** The spec's field name, e.g. `context_digest`. */
    readonly field: string,
    /** The `DecisionSealed` wire tag the field occupies — 11 through 17. */
    readonly wireTag: number,
  ) {
    super(message);
  }
}

/** `opt` over raw bytes. Same presence byte as `optLE`, which takes a `string`. */
function optBytesLE(b: Uint8Array | null | undefined): Uint8Array {
  if (b === null || b === undefined) return new Uint8Array([0]);
  return concat(new Uint8Array([1]), frameLE(b));
}

// The %TypedArray%.prototype accessors, captured once. These read INTERNAL SLOTS, so they cannot be
// shadowed by an own property on the instance — which is the whole reason they are used below instead
// of the obvious `value.length` / `value.byteLength`.
const TA_PROTO = Object.getPrototypeOf(Uint8Array.prototype) as object;
const taGet = (name: string) =>
  Object.getOwnPropertyDescriptor(TA_PROTO, name)!.get! as (this: unknown) => never;
const taLength = taGet("length");
const taByteLength = taGet("byteLength");
const taByteOffset = taGet("byteOffset");
const taBuffer = taGet("buffer");

/** Bytes, in the sense the framing needs: a one-byte-per-element view over an `ArrayBuffer`,
 * measured by what it actually holds.
 *
 * **Everything here is read through internal slots, never through properties on the instance.** A
 * real `Uint8Array` can have its `length` shadowed —
 * `Object.defineProperty(new Uint8Array(0), "length", { value: 32 })`, or a subclass with a `length`
 * getter — and the two readers downstream then disagree: `frameLE` writes a length prefix of 32 from
 * the shadowed property, while `concat`'s `set` copies the internal `[[ArrayLength]]` of 0. The
 * result is 32 zero bytes under a prefix that says 32 — byte-identical to a legitimate all-zeros
 * digest. That is the same alias this module refuses everywhere else, arriving through a right-typed
 * object with lying metadata rather than a wrong-typed one, which is why no amount of type-checking
 * would have caught it. Python's twin reaches the same place through `memoryview(...).tobytes()`,
 * which reads the C buffer that no Python method can override — deliberately NOT `bytes(value)`,
 * which honors a `__bytes__` override and would ask the object what it would like to be hashed as.
 *
 * Element size is checked as `byteLength === length` — both internal — rather than
 * `BYTES_PER_ELEMENT`, which is an ordinary property and shadowable like any other. Wide-element
 * views are refused rather than reinterpreted because their backing bytes are in HOST order, so
 * accepting one would make the digest depend on the machine that computed it; every length prefix in
 * this module is explicitly little-endian to prevent exactly that. */
function asBytes(value: unknown): Uint8Array | null {
  if (!ArrayBuffer.isView(value)) return null;
  try {
    const byteLength = taByteLength.call(value) as unknown as number;
    if ((taLength.call(value) as unknown as number) !== byteLength) return null;
    return new Uint8Array(
      taBuffer.call(value) as unknown as ArrayBuffer,
      taByteOffset.call(value) as unknown as number,
      byteLength,
    );
  } catch {
    // Not a TypedArray at all (a `DataView` — the getters reject the receiver), or its buffer has
    // been detached. Either way there are no bytes here to hash.
    return null;
  }
}

/** One of the four v4 sub-digests (wire tags 11/12/13/15), validated as the spec requires: tags 11, 12
 * and 15 are mandatory, tag 13 is genuinely optional, and all four must be exactly 32 bytes when
 * present. `optional` selects which of those two contracts applies.
 *
 * Every refusal here is a `RecordDigestStripError`, whatever the proximate cause — absent, wrong
 * type, wrong length. From the caller's side those are one condition: *this field is not a usable
 * 32-byte digest, so no v4 digest exists*. Splitting them into different error types would push the
 * work of re-joining them onto every caller, for no gain.
 *
 * A mandatory slot read off the wire arrives as an empty array when absent (`length === 0` IS absence
 * on tags 11/12/15), so the empty value is the same strip as `null`, reported as such.
 *
 * The type check is not defensive padding — it is the sharp edge. A 32-CHARACTER STRING has
 * `.length === 32`, so it passes a length-only gate, and `Uint8Array.prototype.set` then coerces each
 * character via ToNumber → NaN → 0. The result is a *well-formed digest over 32 zero bytes*, which
 * collides exactly with a legitimate all-zeros digest: not a mismatch a verifier would catch, but an
 * alias. That is the same class of collision the spec's framing rules exist to prevent. */
function subDigest(
  name: string,
  tag: number,
  value: unknown,
  optional: boolean,
): Uint8Array | null {
  const empty = !optional && asBytes(value)?.length === 0;
  if (value === null || value === undefined || empty) {
    if (optional) return null;
    throw new RecordDigestStripError(
      `a v4 record carries no ${name} (wire tag ${tag}), which the v4 formula requires. This is a ` +
        `STRIP, not a digest mismatch: refuse the record and do not substitute an empty digest.`,
      name,
      tag,
    );
  }
  const bytes = asBytes(value);
  if (bytes === null) {
    throw new RecordDigestStripError(
      `${name} (wire tag ${tag}) is a ${typeof value}, not bytes — malformed. Refused rather than ` +
        `coerced: a non-bytes value of the right length would hash as 32 zero bytes and produce a ` +
        `well-formed digest over a field that was never supplied.`,
      name,
      tag,
    );
  }
  if (bytes.length !== SUB_DIGEST_LEN) {
    throw new RecordDigestStripError(
      `${name} (wire tag ${tag}) is ${bytes.length} bytes, not ${SUB_DIGEST_LEN} — malformed, so no ` +
        `v4 digest can be computed from it. Reported as a refusal rather than hashed, because ` +
        `hashing it would surface a malformed field as though the record had been rewritten.`,
      name,
      tag,
    );
  }
  return bytes;
}

/** A string slot of a digest preimage, validated before it is encoded.
 *
 * Two things `TextEncoder` would otherwise do silently, both of them producing a digest no other
 * Seam implementation can reproduce: encode a non-string (`undefined` → `"undefined"`, `null` →
 * `"null"`, `5` → `"5"`), and substitute U+FFFD for an unpaired surrogate. Python raises on both
 * (`AttributeError`, `UnicodeEncodeError`); Rust cannot represent either. Refusing here is what
 * keeps the three implementations agreeing on which inputs have a digest at all.
 *
 * Was `v3Text`, and guarded only the v3 record digest — so the v2 record digest (since deleted, with
 * v3, by P7) had every one of these holes for as long as it existed. Measured then, on the v2 preimage:
 *
 *     recordDigestV2({… outcome: "\ud800"})  and  recordDigestV2({… outcome: "\ufffd"})
 *       both -> b0bd8fdf…965a56bd        (TextEncoder substitutes U+FFFD: an ALIAS)
 *     recordDigestV2({… decisionId: 5})    -> digested the text "5"
 *     recordDigestV2({… tenant: null})     -> digested the text "null"
 *
 * The argument in this docstring never mentioned v3 — `TextEncoder` does not know which framing it
 * is serving — so the name was the only thing scoping it. Renamed rather than copied, for the same
 * reason `v3Uint` became `uintSlot`: a rule with one copy cannot drift between framings. */
function textSlot(name: string, value: unknown, optional: boolean): string | null {
  if (optional && (value === null || value === undefined)) return null;
  if (typeof value !== "string") {
    throw new TypeError(
      `${name} must be a string${optional ? " (or null/undefined when absent)" : ""}, not ` +
        `${value === null ? "null" : typeof value} — refused rather than coerced, because ` +
        `TextEncoder would encode it as its ToString and produce a digest over text the caller ` +
        `never supplied.`,
    );
  }
  if (hasLoneSurrogate(value)) {
    throw new TypeError(
      `${name} contains a lone surrogate, which is not valid Unicode and has no UTF-8 encoding. ` +
        `Refused rather than encoded as U+FFFD, which would produce a digest no other Seam ` +
        `implementation can reproduce.`,
    );
  }
  return value;
}

/** A mandatory v4 string slot (tags 14/16/17). Empty, `null` or `undefined` is a strip, never data:
 * the spec reads `length === 0` on these tags as absence, and absence is refused. */
function mandatoryText(name: string, tag: number, value: unknown): string {
  if (value === null || value === undefined || value === "") {
    throw new RecordDigestStripError(
      `a v4 record carries no ${name} (wire tag ${tag}), which the v4 formula requires. This is a ` +
        `STRIP, not a digest mismatch: refuse the record.`,
      name,
      tag,
    );
  }
  return textSlot(name, value, false)!;
}

/** A fixed-width unsigned integer slot, range-checked before `DataView` silently wraps it.
 * `setBigUint64`/`setUint32` apply ToBigUint64/ToUint32, so `2n ** 64n + 5n` writes the same eight
 * bytes as `5` — an alias, not an error. A `number` above 2^53 is refused outright: it is already
 * inexact, so the value hashed would be the nearest double rather than the integer the caller meant,
 * and Python (exact ints) would disagree. `bigint` is the way to express those.
 *
 * This was called `v3Uint` and guarded only the v3 record digest. Every one of those arguments is
 * about `DataView` and IEEE doubles, neither of which knows which framing it is serving — so v2 and
 * the chain-head attestation carried the identical aliases, demonstrated byte-for-byte, for as long
 * as they have existed. `u64le`/`u32le` now route through here, which is what makes the reasoning
 * apply where it always did. Renamed rather than duplicated: a rule with only one copy cannot drift
 * between framings, and a name saying "v3" on the function v2 depends on is a lie a reader has to
 * discover for themselves. */
/** The checks on a uint-slot argument that indict the CALLER rather than the value — split out of
 * {@link uintSlot} so `verifyChainHeadAttestation` can ask for them without the rest.
 *
 * The line is drawn at "could this have arrived over the wire?". A string, a boolean, a `null` or a
 * fractional number could not: protobuf decodes a `uint64` into a number or a bigint, always whole.
 * So each of those means the call was built wrong, and each must escape the verifier's blanket catch
 * instead of being reported as a failed attestation.
 *
 * `Number.isSafeInteger` is deliberately NOT here, and the boundary is worth being exact about.
 * `2 ** 60` is a whole number a caller could plausibly hold — it is exactly representable, it is
 * simply past the point where its NEIGHBOURS are — and Python, with exact integers, digests it
 * happily and answers `false` when the signature does not match. Hoisting that check would make
 * TypeScript throw where Python returns `false`: closing one divergence by opening another. It stays
 * inside {@link uintSlot}, where the verifier's catch turns it into the same `false` Python gives.
 *
 * Split rather than copied. Two functions each asserting what a uint slot may hold would be this
 * change's own subject one level up: a rule living in more than one place drifts, and the copies
 * stop agreeing about what a valid input is. */
function requireUintArgument(name: string, value: number | bigint): void {
  if (typeof value !== "number" && typeof value !== "bigint") {
    // `BigInt()` coerces far more than it looks like it does: `BigInt("5")` is `5n`, `BigInt(true)` is
    // `1n`, `BigInt([5])` is `5n`, and `BigInt("")` is `0n`. Each yields a digest that ALIASES the one
    // a legitimate caller produces — and the string case is not exotic: **proto3 JSON renders int64 as
    // a string**, so anyone feeding this from `JSON.parse` of a protobuf-JSON payload lands here on
    // the first record. Refused, and the message says what to pass instead.
    throw new TypeError(
      `${name} must be a number or bigint, not ${value === null ? "null" : typeof value} — refused ` +
        `rather than coerced. Note that proto3 JSON encodes int64 as a STRING: convert it with ` +
        `BigInt(...) at the boundary, where you can see it, rather than here, where it would silently ` +
        `become a digest.`,
    );
  }
  if (typeof value === "number" && !Number.isInteger(value)) {
    throw new RangeError(`${name} must be an integer, got ${value}`);
  }
}

/** The normalized bytes, or a `TypeError` naming what arrived instead.
 *
 * Through {@link asBytes}, which is this module's one definition of "is this a byte sequence" and
 * what `recordDigestV4` uses. The first cut wrote `value instanceof Uint8Array` — in the same change
 * whose `isPlainObject` docstring argues at length that realm-fragile identity checks are the wrong
 * instrument. It was: `vm.runInNewContext("new Uint8Array(32)")` verified before and raised after,
 * because a cross-realm `Uint8Array` is not `instanceof` ours. `asBytes` tests the buffer-protocol
 * shape instead, so a `Buffer`, a subclass, a view with a byte offset and a foreign-realm array all
 * pass, while a plain `number[]` (a `length` and indexes, no buffer) does not.
 *
 * Returns the normalization rather than just validating, so the digest is taken over the same bytes
 * that were checked — the shape Python settled on for the same reason. */
function requireBytes(name: string, value: Uint8Array): Uint8Array {
  const bytes = asBytes(value);
  if (bytes === null) {
    const got = value === null ? "null" : typeof value;
    throw new TypeError(
      `${name} must be a byte sequence, not ${got} — refused rather than coerced. Hex and base64 ` +
        `are strings, not bytes: decode at the boundary, where the encoding is visible.`,
    );
  }
  return bytes;
}

function uintSlot(name: string, value: number | bigint, bits: 32 | 64): bigint {
  requireUintArgument(name, value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new RangeError(
        `${name} exceeds 2^53 as a number and can no longer round-trip as an IEEE double — pass a ` +
          `bigint so the digest covers the integer you meant`,
      );
    }
  }
  const v = BigInt(value);
  if (v < 0n || v >= 1n << BigInt(bits)) {
    throw new RangeError(
      `${name} is ${v}, outside [0, 2^${bits}) — refused rather than wrapped, because the wrap is ` +
        `silent and aliases distinct values onto the same digest`,
    );
  }
  return v;
}

/** Domain tag of the v4 participants sub-digest (wire tag 15). */
export const PARTICIPANTS_DIGEST_DOMAIN_V4 = "seam.audit.participants.v4";
/** The only record-digest `schema_version` this SDK recomputes (P7). */
export const RECORD_DIGEST_SCHEMA_VERSION = 4;

/** A record's `schema_version` is not 4, so this SDK cannot verify it — **cannot-verify**, never a
 * pass and never a mismatch.
 *
 * `seam-event.v1.md` §"Record digest" makes v4 the only formula and requires a verifier to *refuse*
 * every other `schema_version` as unknown: it must never skip one and never default to a formula it
 * was not asked for. v1-v3 were retired by the runtime's protocol pass (P7); a record sealed under them
 * is not verifiable by this SDK, by design. `schemaVersion` carries the value refused. */
export class UnsupportedRecordDigestVersion extends Error {
  override readonly name: string = "UnsupportedRecordDigestVersion";
  constructor(
    /** The `schema_version` that was refused. */
    readonly schemaVersion: unknown,
  ) {
    super(
      `record digest schema_version ${String(schemaVersion)} cannot be verified: this SDK ` +
        `recomputes v${RECORD_DIGEST_SCHEMA_VERSION} only (v1-v3 were retired by P7)`,
    );
  }
}

/** `participants_digest` (wire tag 15) — `seam.audit.participants.v4`.
 *
 * `SHA256(frame(domain) || le32(count) || frame(id) for each id in STORED order)`: no sorting, no
 * de-duplication, and the count is a bare `le32`. The empty roster is a real 32-byte digest, never an
 * absent slot. Spec: `seam-event.v1.md` §"participants_digest". */
export function participantsDigestV4(participants: readonly string[]): Uint8Array {
  if (!Array.isArray(participants)) throw new TypeError("participants must be an array of strings");
  const ids = participants.map((x, i) => textSlot(`participants[${i}]`, x, false)!);
  return sha256(
    concat(
      frameLE(enc.encode(PARTICIPANTS_DIGEST_DOMAIN_V4)),
      u32le("participants.length", ids.length),
      ...ids.map((x) => frameLE(enc.encode(x))),
    ),
  );
}

/** Recompute a `DECISION_SEALED` record digest (`seam.audit.record-digest.v4`) — the only formula.
 *
 * Transcribed from `seam-event.v1.md` §"Record digest (v4)":
 *
 *     SHA256( frame(domain) ‖ frame(decision_id) ‖ frame(tenant) ‖ frame(namespace)
 *           ‖ frame(ciphertext_digest) ‖ frame(le64(sealed_at)) ‖ frame(outcome)
 *           ‖ opt(mode) ‖ opt(policy_version) ‖ opt(supersedes)
 *           ‖ frame(context_digest) ‖ frame(participation_digest) ‖ opt(policy_rules_digest)
 *           ‖ frame(classification) ‖ frame(participants_digest)
 *           ‖ frame(trust_basis_commitment) ‖ frame(auth_method) ‖ frame(le32(schema_version)) )
 *
 * The sub-digests (tags 11/12/13/15) arrive as **opaque 32-byte wire inputs**; their internal formulas
 * belong to the runtime and to auditors (except `participantsDigestV4`, which is public). This is a
 * wire-input recompute.
 *
 * Three things the spec singles out as easy to get wrong, all of them load-bearing:
 *
 * - **Digest slots are offset by one from the proto tags**, and new slots sit before `schemaVersion`,
 *   which is always last — a verifier selects the whole formula by `schema_version`, so position is
 *   fixed by the spec rather than by append order.
 * - **Tags 11, 12, 14, 15, 16 and 17 are framed and mandatory; tag 13 is opted.** Framing the
 *   mandatory digests is precisely what stops "no participants" from aliasing with "field stripped".
 *   `policyRulesDigest` is genuinely optional — absent means no policy was bound.
 * - **`null` is not an empty `Uint8Array`.** The empty digest is outside these slots' value domain
 *   ({absent} ∪ {32 bytes}), so this function never hashes it. Absence of tag 13 is spelled `null`
 *   here; a **wire** consumer maps `length === 0` to `null` first (`seam-event.v1` §"Presence on the
 *   wire") — that is `verifyStreamedRecordDigest`'s job. On a mandatory tag, empty is a strip. (The
 *   "present-but-empty is data" rule belongs to the opt STRING slots — `mode`, `policyVersion`,
 *   `supersedes` — where the empty string IS in the domain.)
 *
 * Strings hash as their **raw UTF-8 bytes with no normalization of any kind** — the spec names
 * normalization as the step "three of four implementations would implement differently, or skip".
 * `TextEncoder` is correct here precisely because it does not normalize; never call `.normalize()`
 * on an input.
 *
 * Throws {@link UnsupportedRecordDigestVersion} for any `schemaVersion` other than 4 (checked first),
 * and {@link RecordDigestStripError} when a mandatory field is absent or empty, or a sub-digest is not
 * 32 bytes. */
export function recordDigestV4(d: {
  decisionId: string;
  tenant: string;
  namespace: string;
  ciphertextDigest: Uint8Array;
  sealedAt: number | bigint;
  outcome: string;
  mode: string | null;
  policyVersion: string | null;
  supersedes: string | null;
  contextDigest: Uint8Array;
  participationDigest: Uint8Array;
  policyRulesDigest: Uint8Array | null;
  classification: string;
  participantsDigest: Uint8Array;
  trustBasisCommitment: string;
  authMethod: string;
  schemaVersion?: number | bigint;
}): Uint8Array {
  // The version gate comes first: a record of another version has no v4 digest at all, so nothing
  // below (including a strip check) is meaningful for it.
  const version = d.schemaVersion === undefined ? RECORD_DIGEST_SCHEMA_VERSION : d.schemaVersion;
  if (version !== RECORD_DIGEST_SCHEMA_VERSION && version !== BigInt(RECORD_DIGEST_SCHEMA_VERSION))
    throw new UnsupportedRecordDigestVersion(version);
  // Every slot is validated before a single byte is hashed. The rule is one sentence: **this
  // function refuses any input it cannot faithfully represent, rather than coercing it.** JavaScript
  // will happily turn a 32-character string into 32 zero bytes, `undefined` into `"undefined"`, and
  // 2^64+5 into 5 — each of which yields a perfectly well-formed digest over a value nobody supplied,
  // and two of which ALIAS onto digests a legitimate input could also produce. An alias is worse than
  // a mismatch: a mismatch is caught downstream, an alias is not caught at all.
  const contextDigest = subDigest("context_digest", 11, d.contextDigest, false)!;
  const participationDigest = subDigest("participation_digest", 12, d.participationDigest, false)!;
  const policyRulesDigest = subDigest("policy_rules_digest", 13, d.policyRulesDigest, true);
  const participantsDigest = subDigest("participants_digest", 15, d.participantsDigest, false)!;
  const classification = mandatoryText("classification", 14, d.classification);
  const trustBasisCommitment = mandatoryText("trust_basis_commitment", 16, d.trustBasisCommitment);
  const authMethod = mandatoryText("auth_method", 17, d.authMethod);
  const ciphertextDigest = asBytes(d.ciphertextDigest);
  if (ciphertextDigest === null) {
    throw new TypeError(
      `ciphertextDigest (wire tag 10) must be bytes, not a ${typeof d.ciphertextDigest} — refused ` +
        `rather than coerced to zero bytes`,
    );
  }
  const decisionId = textSlot("decisionId", d.decisionId, false)!;
  const tenant = textSlot("tenant", d.tenant, false)!;
  const namespace = textSlot("namespace", d.namespace, false)!;
  const outcome = textSlot("outcome", d.outcome, false)!;
  const mode = textSlot("mode", d.mode, true);
  const policyVersion = textSlot("policyVersion", d.policyVersion, true);
  const supersedes = textSlot("supersedes", d.supersedes, true);
  const sealedAt = uintSlot("sealedAt", d.sealedAt, 64);

  const pre = concat(
    frameLE(enc.encode("seam.audit.record-digest.v4")),
    frameLE(enc.encode(decisionId)),
    frameLE(enc.encode(tenant)),
    frameLE(enc.encode(namespace)),
    frameLE(ciphertextDigest),
    frameLE(u64le("sealedAt", sealedAt)),
    frameLE(enc.encode(outcome)),
    optLE(mode),
    optLE(policyVersion),
    optLE(supersedes),
    frameLE(contextDigest),
    frameLE(participationDigest),
    optBytesLE(policyRulesDigest),
    frameLE(enc.encode(classification)),
    frameLE(participantsDigest),
    frameLE(enc.encode(trustBasisCommitment)),
    frameLE(enc.encode(authMethod)),
    frameLE(u32le("schemaVersion", RECORD_DIGEST_SCHEMA_VERSION)),
  );
  return sha256(pre);
}

export const CHAIN_HEAD_ATTESTATION_DOMAIN_V1 = "seam.audit.chain-head-attestation.v1";
/** seam-runtime #835: the v1 frames under a new domain tag, then `frame(tenant)`. Pinned by
 * `conformance/chain_head_attestation_v2_vector.json`. */
export const CHAIN_HEAD_ATTESTATION_DOMAIN_V2 = "seam.audit.chain-head-attestation.v2";

/** `tenant === undefined` is the **v1** framing; a string is **v2** (`…v2`, then `frame(tenant)`). */
function chainHeadAttestationDigest(
  a: {
    attestedLen: number | bigint;
    attestedHead: Uint8Array;
    attestedAt: number | bigint;
    digestSchema: number;
    issuerAid: string;
  },
  tenant?: string,
): Uint8Array {
  const pre = concat(
    frameLE(enc.encode(tenant === undefined ? CHAIN_HEAD_ATTESTATION_DOMAIN_V1 : CHAIN_HEAD_ATTESTATION_DOMAIN_V2)),
    frameLE(u64le("attestedLen", a.attestedLen)),
    frameLE(a.attestedHead),
    frameLE(u64le("attestedAt", a.attestedAt)),
    frameLE(u32le("digestSchema", a.digestSchema)),
    frameLE(enc.encode(a.issuerAid)),
    ...(tenant === undefined ? [] : [frameLE(enc.encode(tenant))]),
  );
  return sha256(pre);
}

/** Verify a chain-head attestation's Ed25519 signature against the PINNED issuer AID (A14). `true` iff the
 * signature checks out over the recomputed digest; `false` on any tamper. The key comes from `issuerAid`
 * (pinned out of band), never from the attestation itself.
 *
 * `tenant` is the attestation's own payload tenant and selects exactly one signed framing, mirroring
 * seam-runtime #835 step 4 (strict, no fallback): empty verifies under **v1 only** (the system
 * partition; a v2 signature over `""` is refused), and non-empty under **v2 only**, so the tenant is always
 * inside the signature and relabelling it breaks verification. A v1 attestation carrying a non-empty tenant
 * — what the runtime minted before #835 step 3 — returns `false`; there is no grace period and no toggle.
 *
 * `tenant` is **required** — in the type, and at runtime for JavaScript callers, who bypass the type: an
 * attestation object without a string `tenant` throws `TypeError`. Pass the attestation's own tenant; the
 * generated `ChainHeadAttestation` message (`seam_event_pb`) satisfies this parameter and always carries it.
 * `tenant: ""` is still a valid, explicit answer: the system partition, v1. There is deliberately no
 * default, because a defaulted `""` let a caller who left `tenant` off verify the v1 signature alone and
 * never look at the tenant the attestation carries on the wire, so a v1 attestation relabelled to a tenant
 * came back `true`. */
export function verifyChainHeadAttestation(
  issuerAid: string,
  a: {
    attestedLen: number | bigint;
    attestedHead: Uint8Array;
    attestedAt: number | bigint;
    digestSchema: number;
    signature: Uint8Array;
    tenant: string;
  },
): boolean {
  // TYPES first, OUTSIDE the try — the same rule, and for the same reason, as Python's twin.
  //
  // This function's contract is "false on any tamper", and a blanket catch delivered it by
  // answering `false` to everything, including questions it was never asked. Measured against the
  // runtime's own KAT, before this block: a string `attestedLen`, a boolean one, a `null` one, a
  // string `digestSchema`, a string `attestedHead` and a non-string `issuerAid` all returned
  // `false` — while Python raised `TypeError` on every one of them.
  //
  // `false` is the wrong answer to a caller bug, and wrong in the expensive direction: it does not
  // say "you called this wrong", it says "this attestation did not verify". An operator handed that
  // goes looking for a compromised audit chain.
  //
  // `signature` is the deliberate exception, and it is a NARROWING rather than a repair. A hex
  // string worked here: `@noble/curves` types its signature parameter as `Hex = Uint8Array | string`
  // and decodes it, so `signature: "<64 bytes of hex>"` VERIFIED correctly before this block, and
  // now throws. Python has never accepted it. The choice is between one language coercing a string
  // that the other refuses, and both refusing — and the whole argument of this phase is that the
  // SDKs must agree on which inputs are accepted, so both refuse. Recorded in COMPATIBILITY.md §10
  // as a removal of working behaviour, because that is what it is.
  //
  // A wrong type cannot arrive from an attacker: attacker-controlled bytes decode, through protobuf,
  // into correctly-typed values with hostile CONTENTS. So raising here never converts an attack into
  // a crash. It converts a programming error into a visible programming error, and leaves every
  // genuinely untrusted input — out-of-range integers, a malformed AID, a wrong-length or forged
  // signature — answering `false` exactly as before.
  if (typeof issuerAid !== "string") {
    throw new TypeError(`issuerAid must be a string, not ${issuerAid === null ? "null" : typeof issuerAid}`);
  }
  // Checked before the property reads below, so a missing attestation is a named refusal rather than
  // `Cannot read properties of null (reading 'attestedLen')` — which is a caller bug reported as an
  // internal one, the same complaint this whole guard exists to answer.
  if (a === null || typeof a !== "object") {
    throw new TypeError(`the attestation must be an object, not ${a === null ? "null" : typeof a}`);
  }
  requireUintArgument("attestedLen", a.attestedLen);
  requireUintArgument("attestedAt", a.attestedAt);
  requireUintArgument("digestSchema", a.digestSchema);
  const attestedHead = requireBytes("attestedHead", a.attestedHead);
  const signature = requireBytes("signature", a.signature);
  // Required, and refused when absent rather than read as "": a defaulted "" was the v1 bypass (#835
  // step 4), and a JavaScript caller does not see the type that makes it required.
  const tenant = a.tenant;
  if (typeof tenant !== "string") {
    throw new TypeError(`tenant must be a string, not ${tenant === null ? "null" : typeof tenant}`);
  }
  const under = (framingTenant?: string): boolean => {
    try {
      const digest = chainHeadAttestationDigest({ ...a, attestedHead, issuerAid }, framingTenant);
      return ed25519.verify(signature, digest, aidToPubkey(issuerAid), { zip215: false });
    } catch {
      return false;
    }
  };
  return tenant !== "" ? under(tenant) : under();
}

// ── call_sig v3 (`seam-authorize-call-v3`, seam-runtime #1125 / #1059) ───────────────────────────────
// v3 additionally signs the attribution fields v2 left unsigned: subject, subjects, clientRequestId,
// sessionId and features. The runtime tries v3 first, then v2. v2 stays accepted for two published SDK
// minors after the first one that signs v3, and then it is refused. Pinned by
// `conformance/call_sig_v3_payload_vector.json`, generated by an independent implementation.
export const CALL_SIG_V3_CONTEXT = "seam-authorize-call-v3";

/** The inputs {@link callSigV3Payload} frames — each the exact WIRE value of the `AuthorizeRequest`. */
export interface CallSigV3Fields {
  ticket: Uint8Array;
  toolInputDigest: string;
  toolName: string;
  agentId: string;
  subject: string;
  /** Signed in the order SENT: never deduped, never sorted. */
  subjects: readonly string[];
  clientRequestId: string;
  sessionId: string;
  /** Signed sorted by (key bytes, value bytes), because a protobuf map has no order on the wire. */
  features: Readonly<Record<string, string>>;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

/** The exact bytes {@link callSigV3} signs:
 *
 * `frame(context) | frame(ticket) | frame(toolInputDigest) | frame(toolName) | frame(agentId) |
 * frame(subject) | frame(u32le(n)) | frame(subjects[i])... | frame(clientRequestId) | frame(sessionId) |
 * frame(u32le(m)) | (frame(key) | frame(value))...`, with `frame(x) = u32le(len(x)) | x` over UTF-8,
 * lengths in BYTES. The counts are framed too.
 *
 * Features sort on their UTF-8 **bytes**, not with `<` on strings: JavaScript compares strings by
 * UTF-16 code unit, which disagrees with byte order once a key mixes high-BMP and astral characters. */
export function callSigV3Payload(f: CallSigV3Fields): Uint8Array {
  const features = Object.entries(f.features)
    .map(([k, v]) => [enc.encode(k), enc.encode(v)] as const)
    .sort((a, b) => compareBytes(a[0], b[0]) || compareBytes(a[1], b[1]));
  return concat(
    frameLE(enc.encode(CALL_SIG_V3_CONTEXT)),
    frameLE(f.ticket),
    frameLE(enc.encode(f.toolInputDigest)),
    frameLE(enc.encode(f.toolName)),
    frameLE(enc.encode(f.agentId)),
    frameLE(enc.encode(f.subject)),
    frameLE(u32le("subjects.length", f.subjects.length)),
    ...f.subjects.map((s) => frameLE(enc.encode(s))),
    frameLE(enc.encode(f.clientRequestId)),
    frameLE(enc.encode(f.sessionId)),
    frameLE(u32le("features.length", features.length)),
    ...features.flatMap(([k, v]) => [frameLE(k), frameLE(v)]),
  );
}

/** The v3 per-call proof-of-possession for `authorize()`: Ed25519 by the agent key over
 * {@link callSigV3Payload}. On top of v2's bindings, it stops a captured signature being replayed with a
 * different subject, session, client request id or feature set while the ticket is live. Every field
 * is required, for the same reason {@link callSig} gives. */
export function callSigV3(agentSeed: Uint8Array, f: CallSigV3Fields): Uint8Array {
  return ed25519.sign(callSigV3Payload(f), agentSeed);
}

// ── Enrolment proof-of-possession (`seam-enroll-pop-v1`, seam-runtime #1157 / #1164, SDK #205) ─────────
// `EnrollTenantRequest.pop` is the subject AID's own consent to ONE enrolment: an Ed25519 signature, by
// the key the AID embeds, over the tenant and namespace it is being bound to. Without it a tenant-scoped
// operator could enrol any AID it has merely seen. Pinned by `conformance/enroll_pop_v1_payload_vector.json`,
// generated by an independent implementation.
export const ENROLL_POP_V1_CONTEXT = "seam-enroll-pop-v1";
export const ENROLL_POP_NONCE_MAX_LEN = 128;
const ENROLL_POP_NONCE = /^[A-Za-z0-9_-]{1,128}$/;

/** The inputs {@link enrollPopPayload} frames — each exactly what goes on the wire. */
export interface EnrollPopFields {
  subjectAid: string;
  tenant: string;
  namespace: string;
  /** Unix epoch MILLISECONDS; signed as 8 raw little-endian bytes. */
  issuedAtMs: number | bigint;
  nonce: string;
}

/** The parts of `EnrollTenantRequest.pop` (`EnrollPop`), produced by the AGENT being enrolled and
 * handed to the operator who calls `SeamAdminClient.enrollTenant(..., pop)`. Shaped like the generated
 * `EnrollPop`, so it can be passed where one is expected. `signature` is the RAW 64-byte Ed25519
 * signature, as gRPC carries it; {@link enrollProofToRest} gives the `POST /v1/tenants` form. The
 * runtime accepts a proof at most 5 minutes old and at most 60 s in the future. */
export interface EnrollProof {
  issuedAtMs: bigint;
  nonce: string;
  signature: Uint8Array;
}

/** Refuse a nonce the runtime would refuse: 1..=128 characters of `[A-Za-z0-9_-]`. Returns it unchanged;
 * throws a `RangeError` naming the rule otherwise (a `TypeError` for a non-string). */
export function validateEnrollPopNonce(nonce: string): string {
  if (typeof nonce !== "string") {
    throw new TypeError(`enrol pop nonce must be a string, got ${typeof nonce}`);
  }
  if (!ENROLL_POP_NONCE.test(nonce)) {
    throw new RangeError(
      `enrol pop nonce must be 1..=${ENROLL_POP_NONCE_MAX_LEN} characters of [A-Za-z0-9_-] (got ${nonce.length} characters)`,
    );
  }
  return nonce;
}

/** A fresh nonce: 16 random bytes as unpadded base64url — 22 characters, inside the contract. */
export function newEnrollPopNonce(): string {
  return b64urlNoPad(globalThis.crypto.getRandomValues(new Uint8Array(16)));
}

/** The exact bytes an enrolment proof signs:
 *
 * `frame("seam-enroll-pop-v1") | frame(subjectAid) | frame(tenant) | frame(namespace) |
 * frame(u64le(issuedAtMs)) | frame(nonce)`, with `frame(x) = u32le(len(x)) | x` over UTF-8, lengths in
 * BYTES. The runtime rebuilds this from the request it received, so every field must be the wire value. */
export function enrollPopPayload(f: EnrollPopFields): Uint8Array {
  return concat(
    frameLE(enc.encode(ENROLL_POP_V1_CONTEXT)),
    frameLE(enc.encode(f.subjectAid)),
    frameLE(enc.encode(f.tenant)),
    frameLE(enc.encode(f.namespace)),
    frameLE(u64le("issuedAtMs", f.issuedAtMs)),
    frameLE(enc.encode(f.nonce)),
  );
}

/** Sign an enrolment proof with the agent's own key. The subject AID is DERIVED from the seed — a proof
 * can only ever speak for the key that signs it — and the nonce is validated first. Prefer
 * `Agent.enrolmentProof`, which defaults `issuedAtMs` to now and `nonce` to a fresh random one. */
export function enrollPop(
  agentSeed: Uint8Array,
  f: { tenant: string; namespace: string; issuedAtMs: number | bigint; nonce: string },
): EnrollProof {
  validateEnrollPopNonce(f.nonce);
  const issuedAtMs = uintSlot("issuedAtMs", f.issuedAtMs, 64);
  const subjectAid = aidFromPubkey(ed25519.getPublicKey(agentSeed));
  const payload = enrollPopPayload({ ...f, subjectAid, issuedAtMs });
  return { issuedAtMs, nonce: f.nonce, signature: ed25519.sign(payload, agentSeed) };
}

/** `true` iff `signature` is `subjectAid`'s Ed25519 signature over {@link enrollPopPayload} of these
 * exact fields. Checks the binding only — freshness is the runtime's call, on its clock. */
export function verifyEnrollPop(f: EnrollPopFields, signature: Uint8Array): boolean {
  try {
    return ed25519.verify(signature, enrollPopPayload(f), aidToPubkey(f.subjectAid), { zip215: false });
  } catch {
    return false;
  }
}

/** The REST body's `pop` object: the signature as unpadded base64url. `issued_at_ms` is a JSON number,
 * so a value past 2^53 is refused rather than silently rounded. */
export function enrollProofToRest(p: EnrollProof): { issued_at_ms: number; nonce: string; signature: string } {
  if (p.issuedAtMs > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError("issuedAtMs exceeds 2^53 and cannot be carried as a JSON number");
  }
  return { issued_at_ms: Number(p.issuedAtMs), nonce: p.nonce, signature: b64urlNoPad(p.signature) };
}

// ── context_digest (wire tag 11) — seam.audit.context-provenance.v4 ──────────────────────────────

/** Domain tag of the v4 context-provenance sub-digest. `.v4` is the only formula: `.v1`-`.v3` are not
 * dispatched (`seam-event.v1.md` §"Sub-digest domain tags"). */
export const CONTEXT_PROVENANCE_DOMAIN_V4 = "seam.audit.context-provenance.v4";
/** The closed, PascalCase `receiptKeyStatus` vocabulary (`ContextBinding` tag 14). ACDP's own JSON
 * form is lowercase; Seam seals the variant name, so `"historical"` is refused, not case-folded. */
export const RECEIPT_KEY_STATUSES = ["Current", "Historical"] as const;

/** A binding cannot enter the `context-provenance.v4` preimage — refused **before** hashing.
 *
 * Thrown when `receiptKeyStatus` and `receiptHash` are not paired (the first is present *exactly
 * when* the second is) or when `receiptKeyStatus` is outside {@link RECEIPT_KEY_STATUSES}. The runtime
 * refuses such a record at seal, so hashing it as given would return a digest for a record that cannot
 * exist. `index` is the binding's position in stored order; `field` names the slot. The Python twin is
 * `ContextProvenanceError`, with the same two fields. */
export class ContextProvenanceError extends Error {
  constructor(
    message: string,
    readonly index: number,
    readonly field: string,
  ) {
    super(message);
    this.name = "ContextProvenanceError";
  }
}

/** The slots of one binding, in the generated `ContextBinding`'s camelCase — a resolved binding is
 * accepted as-is. An absent optional is `undefined` or `null`, never `""` (which is data). */
export interface ContextProvenanceBinding {
  ctxRef: string;
  fidelity: string;
  classification: string;
  lineageId?: string | null;
  version: number;
  derivedFrom?: readonly string[];
  contentHash?: string | null;
  receiptHash?: string | null;
  keyStatus?: string | null;
  resolvedStatus?: string | null;
  receiptKeyStatus?: string | null;
}

/** `context_digest` (wire tag 11) — `seam.audit.context-provenance.v4`.
 *
 * Transcribed from `seam-event.v1.md` §"context_digest":
 *
 *     SHA256( frame(domain) ‖ le32(len(bindings))
 *           ‖ per binding, STORED order:
 *                 frame(ctx_ref) ‖ frame(fidelity) ‖ frame(classification)
 *               ‖ opt(lineage_id) ‖ frame(le32(version))
 *               ‖ le32(len(derived_from)) ‖ frame(each)
 *               ‖ opt(content_hash) ‖ opt(receipt_hash) ‖ opt(key_status) ‖ opt(resolved_status)
 *               ‖ opt(receipt_key_status) )
 *
 * Stored order is hashed as given — nothing is sorted, de-duplicated or case-folded. `retraction` and
 * the revocation pair are not in the preimage. Throws {@link ContextProvenanceError} on an unpaired or
 * out-of-vocabulary `receiptKeyStatus`; every binding is checked before any byte is hashed. */
export function contextDigestV4(bindings: readonly ContextProvenanceBinding[]): Uint8Array {
  if (!Array.isArray(bindings)) throw new TypeError("bindings must be an array of ContextBinding");
  const parts: Uint8Array[] = [
    frameLE(enc.encode(CONTEXT_PROVENANCE_DOMAIN_V4)),
    u32le("bindings.length", bindings.length),
  ];
  bindings.forEach((bd, i) => {
    const at = (n: string) => `bindings[${i}].${n}`;
    const text = [
      textSlot(at("ctxRef"), bd.ctxRef, false)!,
      textSlot(at("fidelity"), bd.fidelity, false)!,
      textSlot(at("classification"), bd.classification, false)!,
    ];
    const lineage = textSlot(at("lineageId"), bd.lineageId, true);
    const version = u32le(at("version"), bd.version);
    const derivedIn: unknown = bd.derivedFrom ?? [];
    if (!Array.isArray(derivedIn)) throw new TypeError(`${at("derivedFrom")} must be an array`);
    const derived = derivedIn.map((d, j) => textSlot(`${at("derivedFrom")}[${j}]`, d, false)!);
    const tail = [
      textSlot(at("contentHash"), bd.contentHash, true),
      textSlot(at("receiptHash"), bd.receiptHash, true),
      textSlot(at("keyStatus"), bd.keyStatus, true),
      textSlot(at("resolvedStatus"), bd.resolvedStatus, true),
      textSlot(at("receiptKeyStatus"), bd.receiptKeyStatus, true),
    ];
    const receiptHash = tail[1];
    const receiptKeyStatus = tail[4];
    if ((receiptKeyStatus === null) !== (receiptHash === null)) {
      throw new ContextProvenanceError(
        `bindings[${i}]: receiptKeyStatus is present exactly when receiptHash is, and here ` +
          `${receiptKeyStatus === null ? "receiptHash" : "receiptKeyStatus"} stands alone. The ` +
          `runtime refuses this at seal; refuse it rather than hash it.`,
        i,
        "receipt_key_status",
      );
    }
    if (
      receiptKeyStatus !== null &&
      !(RECEIPT_KEY_STATUSES as readonly string[]).includes(receiptKeyStatus)
    ) {
      throw new ContextProvenanceError(
        `bindings[${i}]: receiptKeyStatus ${JSON.stringify(receiptKeyStatus)} is outside the closed ` +
          `vocabulary ${RECEIPT_KEY_STATUSES.join(" | ")} (PascalCase; ACDP's lowercase form is not it)`,
        i,
        "receipt_key_status",
      );
    }
    parts.push(
      ...text.map((t) => frameLE(enc.encode(t))),
      optLE(lineage),
      frameLE(version),
      u32le(at("derivedFrom.length"), derived.length),
      ...derived.map((d) => frameLE(enc.encode(d))),
      ...tail.map((t) => optLE(t)),
    );
  });
  return sha256(concat(...parts));
}
