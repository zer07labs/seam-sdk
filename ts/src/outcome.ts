// Branchpoint BP-2 / plan 47 OI-R1 outcome fields on `ReportOutcome` (`reward`, `metrics`,
// `observedAtMillis`) and the OI-R6 wire-feature names that gate them. The TS twin of
// `python/seam_sdk/_outcome.py`: same rules, same messages.
//
// The checks mirror the runtime's request-shape validation (`seamd::facade::validate_outcome_shape`) so
// a malformed value is refused BEFORE any RPC — an outcome report is permanent. The one runtime check
// that needs the sealed record (`observedAt` within `[sealed_at, now + 300 s]`) stays server-side.

import { Code } from "@connectrpc/connect";
import { InvalidArgumentError } from "./errors.js";

/** Enrolment accepts a `kind` (runtime 0.71.0+). seam-runtime `docs/specs/wire-features.md`. */
export const WIRE_FEATURE_ENROLL_KIND = "enroll.kind";
/** `ReportOutcome` accepts `reward` and `metrics` (runtime BP-2c). */
export const WIRE_FEATURE_OUTCOME_REWARD_METRICS = "outcome.reward_metrics";
/** `ReportOutcome` accepts `observedAt` (runtime BP-2c). */
export const WIRE_FEATURE_OUTCOME_OBSERVED_AT = "outcome.observed_at";

/** The most `metrics` entries one report may carry (`seamd::facade::OUTCOME_METRICS_MAX`). */
export const OUTCOME_METRICS_MAX = 16;

const METRIC_KEY = /^[a-z][a-z0-9_]{0,62}$/;
const U64_MAX = (1n << 64n) - 1n;

/** The source-event time: a `Date`, or integer milliseconds since the Unix epoch. */
export type ObservedAt = Date | number | bigint;

/** The BP-2 fields as they go on a `ReportOutcomeRequest` init — only the ones that are set. */
export interface OutcomeFieldsInit {
  reward?: number;
  metrics?: { [key: string]: number };
  observedAtMillis?: bigint;
}

function refuse(msg: string): never {
  throw new InvalidArgumentError(`reportOutcome: ${msg}`, Code.InvalidArgument);
}

function finite(name: string, v: unknown): number {
  if (typeof v !== "number") refuse(`${name} must be a number, got ${typeof v}`);
  if (!Number.isFinite(v)) {
    refuse(
      `${name} must be a finite number (NaN and ±infinity are refused); ` +
        "the runtime refuses it with INVALID_ARGUMENT",
    );
  }
  return v;
}

function observedAtMillis(t: unknown): bigint {
  let ms: bigint;
  if (t instanceof Date) {
    const n = t.getTime();
    if (Number.isNaN(n)) refuse("observedAt is an invalid Date");
    ms = BigInt(n);
  } else if (typeof t === "number") {
    if (!Number.isSafeInteger(t)) refuse("observedAt must be an integer number of ms since the Unix epoch");
    ms = BigInt(t);
  } else if (typeof t === "bigint") {
    ms = t;
  } else {
    refuse(`observedAt must be a Date or integer ms since the Unix epoch, got ${typeof t}`);
  }
  if (ms < 0n || ms > U64_MAX) refuse("observedAt must not be before the Unix epoch (ms must fit a u64)");
  return ms;
}

/** Validate the BP-2 fields the way the runtime does, returning only the set ones. An empty `metrics`
 * is the same as none (the v1 digest), so it is omitted. */
export function checkOutcomeFields(f: {
  reward?: number;
  metrics?: { [key: string]: number };
  observedAt?: ObservedAt;
}): OutcomeFieldsInit {
  const out: OutcomeFieldsInit = {};
  if (f.reward !== undefined) out.reward = finite("reward", f.reward);
  if (f.metrics !== undefined) {
    if (f.metrics === null || typeof f.metrics !== "object" || Array.isArray(f.metrics) || f.metrics instanceof Map) {
      refuse("metrics must be a plain object of string to number");
    }
    const entries = Object.entries(f.metrics);
    if (entries.length > OUTCOME_METRICS_MAX) {
      refuse(`metrics carries ${entries.length} entries; at most ${OUTCOME_METRICS_MAX} are accepted`);
    }
    const m: { [key: string]: number } = {};
    for (const [k, v] of entries) {
      // Not echoed: the runtime does not echo it either (caller text bound for a SIEM).
      if (!METRIC_KEY.test(k)) refuse("a metrics key does not match ^[a-z][a-z0-9_]{0,62}$");
      m[k] = finite("metrics values", v);
    }
    if (entries.length > 0) out.metrics = m;
  }
  if (f.observedAt !== undefined) out.observedAtMillis = observedAtMillis(f.observedAt);
  return out;
}
