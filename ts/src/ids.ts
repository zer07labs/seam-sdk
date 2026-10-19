// Session and decision identifiers — the runtime's P4 / P5 rules, checked client-side.
//
// The server is authoritative for both. These helpers exist so a caller can build and parse ids
// without string-splitting by hand, and can catch a malformed id before spending an admission
// challenge on it (seam-runtime `docs/specs/session-open.md`: the presentation is verified before the
// id check, so a refused id still spends the nonce). Mirrors the Python SDK's `seam_sdk.ids`.
//
// * **Session id (P4).** Either a canonical lowercase UUID of version 4 or 7, or a token of at least
//   22 characters from `[A-Za-z0-9_-]`; at most 128 UTF-8 bytes either way. A 36-character hyphenated
//   id that parses as a UUID is judged **only** as a UUID — it does not fall back to the token rule —
//   so an uppercase UUID, or a v1 one, is refused even though its characters would pass as a token.
// * **Decision id (P5).** `dec:{tenant}:{session}`. Parsing strips `dec:`, splits on the **first**
//   `:`, and validates both halves: the tenant against `^[A-Za-z0-9_-]{1,128}$` and the session by
//   the P4 rule. Anything else is refused rather than guessed at — so an extra `:` lands in the session
//   half, where the P4 charset refuses it.

/** The literal every decision id starts with. */
export const DECISION_ID_PREFIX = "dec:";
/** The session-id byte cap (RFC-0004 §11.2 floor; Seam caps exactly there). */
export const SESSION_ID_MAX_BYTES = 128;
/** The token form's minimum length — 16 random bytes in unpadded base64url. */
export const SESSION_ID_TOKEN_MIN_LEN = 22;

const TOKEN = /^[A-Za-z0-9_-]+$/;
const TENANT = /^[A-Za-z0-9_-]{1,128}$/;
// "Parses as a UUID": 8-4-4-4-12 hex in either case. Judged only as a UUID once it matches.
const UUID_SHAPE = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/;
const CANONICAL_UUID_V4_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** A session id the runtime would refuse with `INVALID_SESSION_ID`. `reason` says which rule. */
export class InvalidSessionIdError extends Error {
  override readonly name: string = "InvalidSessionIdError";
  constructor(
    /** Which rule refused it, in words. */
    readonly reason: string,
  ) {
    // The id itself is deliberately not echoed, matching the runtime's refusal.
    super(`invalid session id: ${reason}`);
  }
}

/** A decision id that is not `dec:{tenant}:{session}` with both halves valid. */
export class InvalidDecisionIdError extends Error {
  override readonly name: string = "InvalidDecisionIdError";
  constructor(
    /** Which rule refused it, in words. */
    readonly reason: string,
  ) {
    super(`invalid decision id: ${reason}`);
  }
}

/** A parsed decision id. */
export interface DecisionId {
  tenant: string;
  sessionId: string;
}

/** Why `sessionId` is refused, or `null` when it is accepted. */
function sessionRefusal(sessionId: unknown): string | null {
  if (typeof sessionId !== "string") {
    return `must be a string, not ${sessionId === null ? "null" : typeof sessionId}`;
  }
  if (LONE_SURROGATE.test(sessionId)) return "is not valid UTF-8";
  if (Buffer.byteLength(sessionId, "utf8") > SESSION_ID_MAX_BYTES) {
    return `is over the ${SESSION_ID_MAX_BYTES}-byte cap`;
  }
  if (UUID_SHAPE.test(sessionId)) {
    if (CANONICAL_UUID_V4_V7.test(sessionId)) return null;
    return "a UUID-form id must be a canonical lowercase UUID of version 4 or 7";
  }
  if (!TOKEN.test(sessionId)) return "uses characters outside [A-Za-z0-9_-]";
  if (sessionId.length < SESSION_ID_TOKEN_MIN_LEN) {
    return `a token id must be at least ${SESSION_ID_TOKEN_MIN_LEN} characters`;
  }
  return null;
}

/** Return `sessionId` unchanged if the runtime's P4 rule accepts it; else throw
 * {@link InvalidSessionIdError}. `crypto.randomUUID()` always passes. */
export function validateSessionId(sessionId: string): string {
  const reason = sessionRefusal(sessionId);
  if (reason !== null) throw new InvalidSessionIdError(reason);
  return sessionId;
}

/** `true` iff the runtime's P4 rule accepts `sessionId`. */
export function isValidSessionId(sessionId: unknown): boolean {
  return sessionRefusal(sessionId) === null;
}

function checkTenant(tenant: unknown): string {
  if (typeof tenant !== "string" || !TENANT.test(tenant)) {
    throw new InvalidDecisionIdError("tenant must match ^[A-Za-z0-9_-]{1,128}$");
  }
  return tenant;
}

/** Build `dec:{tenant}:{sessionId}`, refusing a tenant or session the runtime would refuse. */
export function decisionIdForSession(tenant: string, sessionId: string): string {
  checkTenant(tenant);
  const reason = sessionRefusal(sessionId);
  if (reason !== null) throw new InvalidDecisionIdError(`session half: ${reason}`);
  return `${DECISION_ID_PREFIX}${tenant}:${sessionId}`;
}

/** Parse `dec:{tenant}:{session}`. Strips `dec:`, splits on the first `:`, and validates both halves;
 * refuses anything else with {@link InvalidDecisionIdError} rather than guessing. */
export function parseDecisionId(decisionId: string): DecisionId {
  if (typeof decisionId !== "string" || !decisionId.startsWith(DECISION_ID_PREFIX)) {
    throw new InvalidDecisionIdError("must start with 'dec:'");
  }
  const rest = decisionId.slice(DECISION_ID_PREFIX.length);
  const sep = rest.indexOf(":");
  if (sep < 0) throw new InvalidDecisionIdError("must be dec:{tenant}:{session}");
  const tenant = rest.slice(0, sep);
  const sessionId = rest.slice(sep + 1);
  checkTenant(tenant);
  const reason = sessionRefusal(sessionId);
  if (reason !== null) throw new InvalidDecisionIdError(`session half: ${reason}`);
  return { tenant, sessionId };
}
