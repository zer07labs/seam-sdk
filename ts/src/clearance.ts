// The caller's decrypt clearance on the decision reads (#384). The wiring is in client.ts (the
// `DecisionReadOptions` verbs); this module holds the closed label set and the two helpers, mirroring
// python/seam_sdk/_clearance.py.

import { Code } from "@connectrpc/connect";

import { InvalidArgumentError } from "./errors.js";

/** The caller's decrypt clearance on the decision reads (#384), sent as `x-seam-clearance`.
 *
 * seam-runtime applies a namespace's decrypt-clearance floor on `GetDecision` (the seal attestation
 * and the experiment allocation on the view), `ReplayDecision` (runtime 0.101.0+) and
 * `GetCommitmentProof`, taking the caller's clearance from this header. An absent or unrecognised
 * value reads at `Public`, the lowest. The set is closed and exact: the runtime's `Classification`
 * labels, case-sensitive. Any other value throws `InvalidArgumentError` before any RPC, because the
 * runtime would not refuse it — it would quietly read at `Public`.
 *
 * Sending it is an assertion, not a grant: the runtime honours it only on a data plane in the `allow`
 * subject-header posture (behind a trusted gateway). A `deny`-posture plane
 * (`SEAM_GRPC_SUBJECT_HEADERS=deny`) and a peer-cert plane strip it, so the read there stays at
 * `Public`. It is not part of the #508 call signature. Mirrors `seam_sdk.CLEARANCE_*` / `CLEARANCES`. */
export const CLEARANCE_PUBLIC = "Public";
export const CLEARANCE_INTERNAL = "Internal";
export const CLEARANCE_CONFIDENTIAL = "Confidential";
export const CLEARANCE_FINANCIAL = "Financial";
export const CLEARANCE_PII = "Pii";
export const CLEARANCE_PHI = "Phi";
export type Clearance =
  | typeof CLEARANCE_PUBLIC
  | typeof CLEARANCE_INTERNAL
  | typeof CLEARANCE_CONFIDENTIAL
  | typeof CLEARANCE_FINANCIAL
  | typeof CLEARANCE_PII
  | typeof CLEARANCE_PHI;
const CLEARANCE_ORDER: readonly Clearance[] = [
  CLEARANCE_PUBLIC,
  CLEARANCE_INTERNAL,
  CLEARANCE_CONFIDENTIAL,
  CLEARANCE_FINANCIAL,
  CLEARANCE_PII,
  CLEARANCE_PHI,
];
/** Exactly the labels seam-runtime's `Classification::from_str` accepts. */
export const CLEARANCES: ReadonlySet<Clearance> = new Set<Clearance>(CLEARANCE_ORDER);
export const CLEARANCE_HEADER = "x-seam-clearance";

// A printable form of a rejected value that cannot itself throw (a BigInt or a circular object makes
// JSON.stringify throw TypeError, which would mask the documented InvalidArgumentError).
function describe(value: unknown): string {
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return typeof value;
  }
}

/** Refuse anything but `undefined` or one of {@link CLEARANCES}, before any RPC is made. @internal */
export function checkClearance(verb: string, clearance: unknown): void {
  if (clearance === undefined) return;
  if (typeof clearance !== "string" || !CLEARANCES.has(clearance as Clearance)) {
    throw new InvalidArgumentError(
      `${verb}: clearance ${describe(clearance)} is not one of ${CLEARANCE_ORDER.join(", ")} (exact, case-sensitive; omit it to send no x-seam-clearance)`,
      Code.InvalidArgument,
    );
  }
}

/** `headers` plus the clearance header; `headers` itself (possibly `undefined`) when there is none.
 * @internal */
export function withClearance(
  headers: Record<string, string> | undefined,
  clearance: Clearance | undefined,
): Record<string, string> | undefined {
  return clearance === undefined ? headers : { ...headers, [CLEARANCE_HEADER]: clearance };
}
