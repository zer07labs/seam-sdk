// Builds the runtime's `SESSION_UNAVAILABLE` refusal (and its near misses) as Connect's gRPC transport
// delivers them: `details` already parsed. Shared by `session_retry.test.ts` and `unit_plumbing.test.ts`.

import { Code, ConnectError } from "@connectrpc/connect";
import { SESSION_UNAVAILABLE_REASON, TENANT_MOVING_REASON, toSeamError } from "../src/errors.js";

const te = new TextEncoder();

function varint(n: number): number[] {
  const out: number[] = [];
  let v = n;
  while (v >= 0x80) {
    out.push((v & 0x7f) | 0x80);
    v >>>= 7;
  }
  out.push(v);
  return out;
}
const ld = (num: number, payload: Uint8Array): number[] => [...varint((num << 3) | 2), ...varint(payload.length), ...payload];
const vi = (num: number, value: number): number[] => [...varint(num << 3), ...varint(value)];

/** A typed SDK error for `code` carrying `reason` (when given) and `RetryInfo` (when > 0). */
export function refusal(code: Code, reason: string | undefined, retrySeconds = 0): Error {
  const details: { type: string; value: Uint8Array }[] = [];
  if (reason !== undefined) {
    details.push({
      type: "google.rpc.ErrorInfo",
      value: new Uint8Array([...ld(1, te.encode(reason)), ...ld(2, te.encode("seam.zer07labs.com"))]),
    });
  }
  if (retrySeconds > 0) {
    details.push({ type: "google.rpc.RetryInfo", value: new Uint8Array(ld(1, new Uint8Array(vi(1, retrySeconds)))) });
  }
  const received = details as unknown as ConstructorParameters<typeof ConnectError>[3];
  return toSeamError(new ConnectError("busy", code, undefined, received)) as Error;
}

export const sessionUnavailable = (retrySeconds = 0) =>
  refusal(Code.Unavailable, SESSION_UNAVAILABLE_REASON, retrySeconds);

/** The runtime's `TENANT_MOVING` refusal (k8s P16): `FAILED_PRECONDITION` + `RetryInfo`. */
export const tenantMoving = (retrySeconds = 5) => refusal(Code.FailedPrecondition, TENANT_MOVING_REASON, retrySeconds);
