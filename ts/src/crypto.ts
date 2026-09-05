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
    if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) return false;
    // Bounded to int64 because the normative rule is: Go's `int64(exp)` is implementation-defined
    // when the value does not fit, and `exp: 1e300` verified on arm64 (saturating to MaxInt64) while
    // amd64 refused the identical token. JavaScript has no such hazard — `Math.trunc` is total — so
    // this bound buys TypeScript nothing alone. It is here so all five SDKs answer the same thing.
    // 2^63 is exactly representable as a double, so the comparison is exact.
    if (payload.exp >= 9223372036854775808 || payload.exp < -9223372036854775808) return false;
    if (now >= Math.trunc(payload.exp)) return false; // RFC 7519: reject at/after expiry
    return (payload.grants ?? []).includes("seam-commitment-digest:" + seamCommitmentDigest(commitment));
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
  // Every slot below goes through the SAME guard v3 uses. It did not before, and the gap was not
  // theoretical: `ciphertextDigest: "0".repeat(32)` and `new Array(32).fill(0)` each produced the
  // identical digest to `new Uint8Array(32)`, because `Uint8Array.prototype.set` coerces every
  // element through ToNumber and a non-numeric character becomes `NaN` becomes `0`. Two distinct
  // inputs, one digest, in the v2 framing — while v3 refused all three and Python raised on them.
  const ciphertextDigest = asBytes(d.ciphertextDigest);
  if (ciphertextDigest === null) {
    throw new TypeError(
      `ciphertextDigest must be bytes, not a ${typeof d.ciphertextDigest} — refused rather than ` +
        `coerced to zero bytes, which would ALIAS a legitimate caller's digest`,
    );
  }
  const pre = concat(
    frameLE(enc.encode("seam.audit.record-digest.v2")),
    frameLE(enc.encode(textSlot("decisionId", d.decisionId, false)!)),
    frameLE(enc.encode(textSlot("tenant", d.tenant, false)!)),
    frameLE(enc.encode(textSlot("namespace", d.namespace, false)!)),
    frameLE(ciphertextDigest),
    frameLE(u64le("sealedAt", d.sealedAt)),
    frameLE(enc.encode(textSlot("outcome", d.outcome, false)!)),
    optLE(textSlot("mode", d.mode, true)),
    optLE(textSlot("policyVersion", d.policyVersion, true)),
    optLE(textSlot("supersedes", d.supersedes, true)),
    frameLE(u32le("schemaVersion", d.schemaVersion ?? 2)),
  );
  return sha256(pre);
}

// ── v3 record digest (B3) ────────────────────────────────────────────────────────────────────────

const V3_DIGEST_LEN = 32;

/**
 * A `schema_version = 3` record is missing a field the v3 formula requires (wire tag 11 or 12), or
 * carries one that is not 32 bytes.
 *
 * **This is deliberately not a digest mismatch, and must never be reported as one.** The spec
 * (`seam-event.v1.md`, "Strip semantics for tags 11/12/13") makes `context_digest` and
 * `participation_digest` mandatory on a v3 payload and requires a consumer to *refuse* — never to
 * substitute an empty digest, and never to fall back to the v2 formula. Absent-when-required is a
 * strip attack, and an operator has to be able to tell "someone removed a field" from "someone
 * rewrote one", because the two have different responses.
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
    /** The `DecisionSealed` wire tag the field occupies — 11, 12 or 13. */
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

/** One of the three v3 sub-digests (wire tags 11/12/13), validated as the spec requires: tags 11 and
 * 12 are mandatory, tag 13 is genuinely optional, and all three must be exactly 32 bytes when
 * present. `optional` selects which of those two contracts applies.
 *
 * Every refusal here is a `RecordDigestStripError`, whatever the proximate cause — absent, wrong
 * type, wrong length. From the caller's side those are one condition: *this field is not a usable
 * 32-byte digest, so no v3 digest exists*. Splitting them into different error types would push the
 * work of re-joining them onto every caller, for no gain.
 *
 * The type check is not defensive padding — it is the sharp edge. A 32-CHARACTER STRING has
 * `.length === 32`, so it passes a length-only gate, and `Uint8Array.prototype.set` then coerces each
 * character via ToNumber → NaN → 0. The result is a *well-formed digest over 32 zero bytes*, which
 * collides exactly with a legitimate all-zeros digest: not a mismatch a verifier would catch, but an
 * alias. That is the same class of collision the spec's framing rules exist to prevent. */
function v3SubDigest(
  name: string,
  tag: number,
  value: unknown,
  optional: boolean,
): Uint8Array | null {
  if (value === null || value === undefined) {
    if (optional) return null;
    throw new RecordDigestStripError(
      `a schema_version=3 record carries no ${name} (wire tag ${tag}), which the v3 formula ` +
        `requires. This is a STRIP, not a digest mismatch: refuse the record, do not substitute ` +
        `an empty digest and do not fall back to the v2 formula.`,
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
  if (bytes.length !== V3_DIGEST_LEN) {
    throw new RecordDigestStripError(
      `${name} (wire tag ${tag}) is ${bytes.length} bytes, not ${V3_DIGEST_LEN} — malformed, so no ` +
        `v3 digest can be computed from it. Reported as a refusal rather than hashed, because ` +
        `hashing it would surface a malformed field as though the record had been rewritten.`,
      name,
      tag,
    );
  }
  return bytes;
}

/** A string slot of the v3 preimage, validated before it is encoded.
 *
 * Two things `TextEncoder` would otherwise do silently, both of them producing a digest no other
 * Seam implementation can reproduce: encode a non-string (`undefined` → `"undefined"`, `null` →
 * `"null"`, `5` → `"5"`), and substitute U+FFFD for an unpaired surrogate. Python raises on both
 * (`AttributeError`, `UnicodeEncodeError`); Rust cannot represent either. Refusing here is what
 * keeps the three implementations agreeing on which inputs have a digest at all.
 *
 * Was `v3Text`, and guarded only the v3 record digest — so `recordDigestV2` had every one of these
 * holes for as long as it has existed. Measured before this change, on the v2 preimage:
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
 * what `recordDigestV3` uses. The first cut wrote `value instanceof Uint8Array` — in the same change
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

/** Recompute a v3 `DECISION_SEALED` record digest (`seam.audit.record-digest.v3`).
 *
 * v3 is v2 plus the three columns carrying the product's actual claims — what context the decision
 * consumed, who participated, and which policy rules gated the commitment. They arrive as **opaque
 * 32-byte sub-digests on the wire** (tags 11/12/13); their internal formulas belong to the runtime
 * and to auditors, and are deliberately not reimplemented here. This is a wire-input recompute,
 * exactly as `recordDigestV2` is.
 *
 * Three things the spec singles out as easy to get wrong, all of them load-bearing:
 *
 * - **Digest slots are offset by one from the proto tags.** `contextDigest` is preimage slot 10 but
 *   wire tag 11. The new slots are *inserted before* `schemaVersion`, never appended after it — a
 *   verifier selects the whole formula by `schema_version`, so position is fixed by the spec rather
 *   than by append order.
 * - **Slots 10 and 11 are framed; slot 12 is opted.** The asymmetry is deliberate: framing the two
 *   mandatory digests is precisely what stops "no participants" from aliasing with "field
 *   stripped". `policyRulesDigest` is genuinely optional — absent means no policy was bound.
 * - **`null` is not an empty `Uint8Array` — and at THIS layer they are two different refusals, not
 *   two different digests.** `opt(null)` is one byte and `opt(new Uint8Array())` five, so the
 *   presence byte does keep them apart in the preimage. But the empty digest is outside these slots'
 *   value domain ({absent} ∪ {32 bytes}), so this function never hashes it: it refuses it. Absence
 *   is spelled `null` here. A **wire** consumer must not pass an empty array through — on the wire
 *   `length === 0` IS absence (a total mapping, per `seam-event.v1` §"Presence on the wire"), so the
 *   caller maps it to `null` first; that is `verifyStreamedRecordDigest`'s job. (The
 *   "present-but-empty is data" rule is real, but belongs to the STRING slots — `mode`,
 *   `policyVersion`, `supersedes` — where the empty string IS in the domain.)
 *
 * Strings hash as their **raw UTF-8 bytes with no normalization of any kind** — the spec names
 * normalization as the step "three of four implementations would implement differently, or skip".
 * `TextEncoder` is correct here precisely because it does not normalize; never call `.normalize()`
 * on an input.
 *
 * Throws {@link RecordDigestStripError} when `contextDigest` or `participationDigest` is absent or
 * is not 32 bytes, and when a *present* `policyRulesDigest` is not 32 bytes. */
export function recordDigestV3(d: {
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
  schemaVersion?: number;
}): Uint8Array {
  // Every slot is validated before a single byte is hashed. The rule is one sentence: **this
  // function refuses any input it cannot faithfully represent, rather than coercing it.** JavaScript
  // will happily turn a 32-character string into 32 zero bytes, `undefined` into `"undefined"`, and
  // 2^64+5 into 5 — each of which yields a perfectly well-formed digest over a value nobody supplied,
  // and two of which ALIAS onto digests a legitimate input could also produce. An alias is worse than
  // a mismatch: a mismatch is caught downstream, an alias is not caught at all.
  const contextDigest = v3SubDigest("context_digest", 11, d.contextDigest, false)!;
  const participationDigest = v3SubDigest("participation_digest", 12, d.participationDigest, false)!;
  const policyRulesDigest = v3SubDigest("policy_rules_digest", 13, d.policyRulesDigest, true);
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
  const schemaVersion = uintSlot("schemaVersion", d.schemaVersion ?? 3, 32);

  const pre = concat(
    frameLE(enc.encode("seam.audit.record-digest.v3")),
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
    frameLE(u32le("schemaVersion", schemaVersion)),
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
    frameLE(u64le("attestedLen", a.attestedLen)),
    frameLE(a.attestedHead),
    frameLE(u64le("attestedAt", a.attestedAt)),
    frameLE(u32le("digestSchema", a.digestSchema)),
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
  try {
    const digest = chainHeadAttestationDigest({ ...a, attestedHead, issuerAid });
    return ed25519.verify(signature, digest, aidToPubkey(issuerAid), { zip215: false });
  } catch {
    return false;
  }
}
