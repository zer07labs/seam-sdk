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
}

export class InvalidArgumentError extends SeamRpcError {}
export class FailedPreconditionError extends SeamRpcError {}
export class PermissionDeniedError extends SeamRpcError {}
export class UnauthenticatedError extends SeamRpcError {}
export class NotFoundError extends SeamRpcError {}
export class AlreadyExistsError extends SeamRpcError {}
export class ResourceExhaustedError extends SeamRpcError {}
export class UnavailableError extends SeamRpcError {}
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
