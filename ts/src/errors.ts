// Seam SDK error taxonomy.
//
// `IssuerMismatchError` (in client.ts) is the one client-side semantic error. Server-returned failures
// arrive as Connect's `ConnectError` (which already carries a typed `.code`); this module retypes them to
// status-code-specific `SeamRpcError` subclasses so callers can `catch`/`instanceof` a specific error.
// The retype is **lossless and non-breaking** — it mutates the existing error's prototype in place, so the
// object still satisfies `instanceof ConnectError` and keeps its `code`/`message`/`metadata`/`details`.

import { Code, ConnectError, type Interceptor } from "@connectrpc/connect";

/**
 * The server answered something the wire contract forbids — e.g. a TRANSFORM verdict with no
 * `transformed_input`. Typed (not a bare `Error`) so adapters can route it to their hard-deny path:
 * a caller that gated on truthiness would otherwise execute the ORIGINAL, unredacted input.
 * Client-side (like `IssuerMismatchError`), not a `SeamRpcError` — the server returned an OK status;
 * the violation is in the payload.
 */
export class ProtocolViolationError extends Error {
  override readonly name: string = "ProtocolViolationError";
  constructor(
    message: string,
    readonly authorizeId: string = "",
  ) {
    super(message);
  }
}

/**
 * Base for every server-returned, status-typed error. Still a `ConnectError`.
 *
 * Two deliberate choices, both forced by `ConnectError`'s custom `Symbol.hasInstance`:
 *
 * 1. `Symbol.hasInstance` is overridden here with real prototype-chain semantics. The inherited
 *    ConnectError check matches ANY ConnectError against ANY subclass (it duck-types on
 *    `name === "ConnectError"` plus field shape, ignoring which class is on the right of
 *    `instanceof`) — so before this override, a NOT_FOUND error was `instanceof
 *    UnauthenticatedError`, which silently mis-routed every typed catch.
 *
 * 2. `name` stays `"ConnectError"` on this family. ConnectError's duck-typed `hasInstance`
 *    REQUIRES `name === "ConnectError"` for a non-direct instance to satisfy
 *    `instanceof ConnectError` — renaming would break this module's documented non-breaking
 *    guarantee (and cross-package copies of @connectrpc/connect). The class name is still
 *    available as `e.constructor.name`.
 */
export class SeamRpcError extends ConnectError {
  static [Symbol.hasInstance](v: unknown): boolean {
    return typeof v === "object" && v !== null && this.prototype.isPrototypeOf(v);
  }

  /** Seam's error class — `ErrorInfo.reason` (domain `seam.zer07labs.com`) from
   * `grpc-status-details-bin` — or `undefined` when the server sent no such detail.
   *
   * `PROTOCOL` means MACP refused the call and {@link macpCode} names why; `POLICY_DENIED`
   * (`PERMISSION_DENIED`) is the bound policy refusing a commitment; `QUOTA_EXCEEDED`
   * (`RESOURCE_EXHAUSTED`) is load-shed, with {@link retryAfter}; `CHALLENGE_REFUSED` (`UNAVAILABLE`,
   * an {@link UnavailableError}) is `IssueChallenge` refusing because the nonce store is at capacity —
   * **retryable** after {@link retryAfter}, never an identity failure. Branch on these, never on message
   * text. Decoded fail-soft: a malformed detail reads as absent, never displacing the typed error. */
  get reason(): string | undefined {
    return seamErrorInfo(this)?.reason;
  }

  /** `ErrorInfo.metadata` of the Seam-domain error detail, as a fresh object, or `undefined` when the
   * server sent no such detail.
   *
   * This is where a refusal's structured facts travel. `WRONG_CELL` ({@link WRONG_CELL_REASON}) carries
   * `cell`, `root_snapshot_id` and `root_generated_at`; `PROTOCOL` carries `macp_code` (also
   * {@link macpCode}). Keys are whatever the server sent, unfiltered: the runtime grows them on its own
   * schedule, and a client that cannot name a key must still be able to log it. A copy, so mutating it
   * changes nothing on the error. */
  get errorMetadata(): Record<string, string> | undefined {
    const info = seamErrorInfo(this);
    return info ? { ...info.metadata } : undefined;
  }

  /** MACP's own error code (`ErrorInfo.metadata["macp_code"]`) on a `PROTOCOL` refusal, or
   * `undefined`.
   *
   * Returned as the **raw string**, not an enum: MACP grows codes on its own schedule, and a client
   * that cannot name a new code must still be able to log and route it. Present **only** when
   * {@link reason} is `PROTOCOL` — every other error class has no `macp_code` by contract (seam-runtime
   * `docs/specs/error-model.md`), so a stray key on another reason is ignored rather than surfaced as if
   * it were one. */
  get macpCode(): string | undefined {
    const info = seamErrorInfo(this);
    if (!info || info.reason !== PROTOCOL_REASON) return undefined;
    return Object.prototype.hasOwnProperty.call(info.metadata, "macp_code")
      ? info.metadata.macp_code
      : undefined;
  }

  /** The server's `google.rpc.RetryInfo.retry_delay` in seconds, or `undefined` when it sent none.
   *
   * Carried on a load-shed refusal (`RESOURCE_EXHAUSTED`, reason `QUOTA_EXCEEDED`) and on a capacity
   * refusal of `IssueChallenge` (`UNAVAILABLE`, reason `CHALLENGE_REFUSED`); read off whatever status
   * carries it. The SDK **does not retry for you**: it surfaces the delay so the caller's own retry
   * policy can honour it before re-issuing. A refused admission challenge was never issued, so a retry
   * asks for a fresh one. */
  get retryAfter(): number | undefined {
    for (const d of statusDetails(this)) {
      if (d.type !== RETRY_INFO_TYPE) continue;
      try {
        return decodeRetryDelay(d.value);
      } catch {
        return undefined;
      }
    }
    return undefined;
  }
}

/** The `ErrorInfo.domain` every Seam refusal carries (seam-runtime `docs/specs/error-model.md`). */
export const SEAM_ERROR_DOMAIN = "seam.zer07labs.com";
/** The one `ErrorInfo.reason` that carries a `macp_code` — MACP's own protocol refusals. */
export const PROTOCOL_REASON = "PROTOCOL";
/** `ErrorInfo.reason` of an `UNAVAILABLE` (HTTP 503) refusal of a session-scoped verb because another
 * runtime replica holds the live session's lease, or the shared session store is unreachable
 * (seam-runtime k8s P6). `retryAfter` carries the holder's remaining lease (at most the 30s lease
 * TTL), or 1s while the store is down. A single-replica runtime never returns it. **Retryable** —
 * see {@link isSessionUnavailable} and {@link withSessionRetry}. */
export const SESSION_UNAVAILABLE_REASON = "SESSION_UNAVAILABLE";
/** `ErrorInfo.reason` of a `FAILED_PRECONDITION` refusal: the call reached a cell that does not hold the
 * caller's tenant (seam-runtime k8s P15, D123; runtime 0.58.0). {@link SeamRpcError.errorMetadata}
 * names the `cell` that answered and the fleet root it routed by (`root_snapshot_id`,
 * `root_generated_at`). **Never retryable:** the same call to the same endpoint reaches the same cell;
 * the remedy is the routing (a stale router root, or a wrong `x-seam-tenant`), not a retry. */
export const WRONG_CELL_REASON = "WRONG_CELL";

const STATUS_DETAILS_KEY = "grpc-status-details-bin";
const ERROR_INFO_TYPE = "google.rpc.ErrorInfo";
const RETRY_INFO_TYPE = "google.rpc.RetryInfo";
const utf8 = new TextDecoder("utf-8", { fatal: true });

type Field = { num: number; wt: number; v: bigint | Uint8Array | undefined };

function varint(buf: Uint8Array, i: number): [bigint, number] {
  let out = 0n;
  let shift = 0n;
  for (;;) {
    if (i >= buf.length || shift > 63n) throw new RangeError("truncated varint");
    const b = buf[i++];
    out |= BigInt(b & 0x7f) << shift;
    if (!(b & 0x80)) return [out, i];
    shift += 7n;
  }
}

/** The `(field_number, wire_type, value)` triples of one protobuf message. Length-delimited values are
 * bytes, varints are bigints; fixed32/fixed64 are skipped. Throws on a malformed buffer.
 *
 * Hand-rolled on purpose, as in the Python twin: decoding `google.rpc.Status` with real classes needs
 * the googleapis protos, and three tiny shapes are all that is read — `Status`/`Any`, `ErrorInfo`,
 * `RetryInfo` — with nothing trusted beyond "a string the server sent". */
function fields(buf: Uint8Array): Field[] {
  const out: Field[] = [];
  let i = 0;
  while (i < buf.length) {
    const [key, j] = varint(buf, i);
    i = j;
    const num = Number(key >> 3n);
    const wt = Number(key & 7n);
    let v: bigint | Uint8Array | undefined;
    if (wt === 0) {
      [v, i] = varint(buf, i);
    } else if (wt === 2) {
      const [n, k] = varint(buf, i);
      if (BigInt(k) + n > BigInt(buf.length)) throw new RangeError("truncated field");
      v = buf.subarray(k, k + Number(n));
      i = k + Number(n);
    } else if (wt === 1) {
      i += 8;
    } else if (wt === 5) {
      i += 4;
    } else {
      throw new RangeError(`unsupported wire type ${wt}`);
    }
    if (i > buf.length) throw new RangeError("truncated field");
    out.push({ num, wt, v });
  }
  return out;
}

/** The `google.rpc.Status.details` of an error as `(type, value)` pairs, `type` being the fully
 * qualified message name (`google.rpc.ErrorInfo`), or `[]`.
 *
 * Connect's gRPC transport has already parsed `grpc-status-details-bin` into `details`; that is read
 * first. A `ConnectError` built elsewhere (or by another transport) may carry only the raw trailer in
 * `metadata`, so that is decoded as the fallback. Fail-soft throughout: a malformed payload yields
 * `[]` — the typed error must never be displaced by a failure to read metadata about it. */
function statusDetails(e: ConnectError): { type: string; value: Uint8Array }[] {
  const parsed: { type: string; value: Uint8Array }[] = [];
  for (const d of e.details ?? []) {
    const t = (d as { type?: unknown }).type;
    const v = (d as { value?: unknown }).value;
    if (typeof t === "string" && v instanceof Uint8Array)
      parsed.push({ type: t.substring(t.lastIndexOf("/") + 1), value: v });
  }
  if (parsed.length > 0) return parsed;
  const raw = e.metadata?.get(STATUS_DETAILS_KEY);
  if (!raw) return [];
  try {
    const bytes = new Uint8Array(Buffer.from(raw, "base64"));
    const out: { type: string; value: Uint8Array }[] = [];
    for (const f of fields(bytes)) {
      if (f.num !== 3 || f.wt !== 2) continue;
      let typeUrl = "";
      let value: Uint8Array = new Uint8Array(0);
      for (const a of fields(f.v as Uint8Array)) {
        if (a.num === 1 && a.wt === 2) typeUrl = utf8.decode(a.v as Uint8Array);
        else if (a.num === 2 && a.wt === 2) value = a.v as Uint8Array;
      }
      out.push({ type: typeUrl.substring(typeUrl.lastIndexOf("/") + 1), value });
    }
    return out;
  } catch {
    return [];
  }
}

function decodeErrorInfo(value: Uint8Array): {
  reason: string;
  domain: string;
  metadata: Record<string, string>;
} {
  let reason = "";
  let domain = "";
  const metadata: Record<string, string> = Object.create(null);
  for (const f of fields(value)) {
    if (f.wt !== 2) continue;
    const v = f.v as Uint8Array;
    if (f.num === 1) reason = utf8.decode(v);
    else if (f.num === 2) domain = utf8.decode(v);
    else if (f.num === 3) {
      let mk = "";
      let mv = "";
      for (const e of fields(v)) {
        if (e.num === 1 && e.wt === 2) mk = utf8.decode(e.v as Uint8Array);
        else if (e.num === 2 && e.wt === 2) mv = utf8.decode(e.v as Uint8Array);
      }
      metadata[mk] = mv;
    }
  }
  return { reason, domain, metadata };
}

function seamErrorInfo(
  e: ConnectError,
): { reason: string; metadata: Record<string, string> } | undefined {
  for (const d of statusDetails(e)) {
    if (d.type !== ERROR_INFO_TYPE) continue;
    let info;
    try {
      info = decodeErrorInfo(d.value);
    } catch {
      return undefined;
    }
    if (info.domain === SEAM_ERROR_DOMAIN) return { reason: info.reason, metadata: info.metadata };
  }
  return undefined;
}

function signed64(v: bigint): bigint {
  return v >= 1n << 63n ? v - (1n << 64n) : v;
}

function decodeRetryDelay(value: Uint8Array): number | undefined {
  for (const f of fields(value)) {
    if (f.num !== 1 || f.wt !== 2) continue;
    let seconds = 0n;
    let nanos = 0n;
    for (const d of fields(f.v as Uint8Array)) {
      if (d.num === 1 && d.wt === 0) seconds = signed64(d.v as bigint);
      else if (d.num === 2 && d.wt === 0) nanos = signed64(d.v as bigint);
    }
    return Number(seconds) + Number(nanos) / 1e9;
  }
  return undefined;
}

export class InvalidArgumentError extends SeamRpcError {}
/** `FAILED_PRECONDITION` — the server's state does not admit the request yet.
 *
 * **A policy refusal of a session commit is no longer this error.** Until the protocol pass it was;
 * the runtime now answers a `POLICY_DENIED` with `PERMISSION_DENIED`, the MACP error-code registry's
 * status (RFC-MACP-0006 §13) — see {@link PermissionDeniedError}. */
export class FailedPreconditionError extends SeamRpcError {}
/** `PERMISSION_DENIED` — shared by four refusal classes, so **branch on** `reason`, **never on the
 * status or the message text**:
 *
 * - `POLICY_DENIED` — the bound coordination policy refused the commitment (ballots, objections,
 *   evaluation, or a round with no APPROVE/REJECT ballot at all, seam-runtime#565). Replay refusals
 *   (policy unavailable, policy mismatch, replay diverged) are `POLICY_DENIED` too. **Not terminal
 *   and not retryable as-is**: the session is still live; do the missing thing (cast ballots,
 *   address objections) and commit again. No `macpCode` by contract.
 * - `SCOPE_DENIED` — the caller's credential lacks the scope for the action (the R8 floor).
 * - `FACT_ATTESTOR_REJECTED` — a fact's attestor is not accepted.
 * - `PROTOCOL` with `macpCode` `FORBIDDEN` — MACP refused the sender. */
export class PermissionDeniedError extends SeamRpcError {}
/** `UNAUTHENTICATED` — a refused admission ticket / request credential, or a missing or invalid
 * management operator token. Thrown from `authorize`, a credentialed read (`sessionStatus`,
 * `getDecision`, `replayDecision`, `getCommitmentProof`/`verifyDecision`, `getEscalation`) or
 * `reportOutcome`, it is the SECOND rejection: the SDK already refreshed the ticket once (#275). Every
 * other credentialed write throws it on the first. Do not branch on the message: the runtime gives
 * every ticket failure, and some scope refusals, one byte-identical text. */
export class UnauthenticatedError extends SeamRpcError {}
export class NotFoundError extends SeamRpcError {}
export class AlreadyExistsError extends SeamRpcError {}
export class ResourceExhaustedError extends SeamRpcError {}
/** `UNAVAILABLE` — transport/server not reachable, or a capacity refusal the caller may retry. With
 * `reason` `CHALLENGE_REFUSED` it is `IssueChallenge` refusing because the runtime's nonce store is at
 * capacity (AITP 0.15.0; HTTP 503 on REST): **retryable** after `retryAfter`, with a fresh challenge.
 * Not an identity failure and not a hard fault; the per-peer limit is `QUOTA_EXCEEDED` on
 * {@link ResourceExhaustedError}. The SDK itself never retries a load-shed — including when it is
 * the refresh `Admit` of a credentialed call's one ticket refresh (#275): it propagates typed. */
export class UnavailableError extends SeamRpcError {}

/** True for the runtime's `SESSION_UNAVAILABLE` refusal (see {@link SESSION_UNAVAILABLE_REASON}). */
export function isSessionUnavailable(e: unknown): boolean {
  return e instanceof UnavailableError && e.reason === SESSION_UNAVAILABLE_REASON;
}

/** True when `e` is the runtime's `WRONG_CELL` refusal: a {@link FailedPreconditionError} whose
 * `reason` is {@link WRONG_CELL_REASON}. Never {@link isRetryable}. */
export function isWrongCell(e: unknown): boolean {
  return e instanceof FailedPreconditionError && e.reason === WRONG_CELL_REASON;
}

/** True when re-invoking the same SDK call, unchanged, is safe and is the remedy. Today that is exactly
 * {@link isSessionUnavailable}. Deliberately narrow: the runtime's other retryable refusals each need a
 * different recovery first (`CHALLENGE_REFUSED` a fresh challenge, a fact conflict a re-read chain
 * head), so a blind re-invoke is not their remedy. Classification only: the SDK still never retries
 * on its own; {@link withSessionRetry} is the opt-in loop. */
export function isRetryable(e: unknown): boolean {
  return isSessionUnavailable(e);
}
export class DeadlineExceededError extends SeamRpcError {}
export class UnimplementedError extends SeamRpcError {}
export class InternalError extends SeamRpcError {}

const BY_CODE: Partial<Record<Code, typeof SeamRpcError>> = {
  [Code.InvalidArgument]: InvalidArgumentError,
  [Code.FailedPrecondition]: FailedPreconditionError,
  [Code.PermissionDenied]: PermissionDeniedError,
  [Code.Unauthenticated]: UnauthenticatedError,
  [Code.NotFound]: NotFoundError,
  [Code.AlreadyExists]: AlreadyExistsError,
  [Code.ResourceExhausted]: ResourceExhaustedError,
  [Code.Unavailable]: UnavailableError,
  [Code.DeadlineExceeded]: DeadlineExceededError,
  [Code.Unimplemented]: UnimplementedError,
  [Code.Internal]: InternalError,
};

/**
 * Retype a `ConnectError` to its status-code-specific `SeamRpcError` subclass, in place. Lossless (same
 * object → `code`/`message`/`metadata`/`details` preserved) and still `instanceof ConnectError`. Non-Connect
 * values pass through unchanged.
 */
export function toSeamError(e: unknown): unknown {
  if (e instanceof ConnectError && !(e instanceof SeamRpcError)) {
    const cls = BY_CODE[e.code] ?? InternalError;
    Object.setPrototypeOf(e, cls.prototype);
  }
  return e;
}

/** A Connect interceptor that retypes unary-call errors to their `SeamRpcError` subclass. */
export function errorMappingInterceptor(): Interceptor {
  return (next) => async (req) => {
    try {
      return await next(req);
    } catch (e) {
      throw toSeamError(e);
    }
  };
}
