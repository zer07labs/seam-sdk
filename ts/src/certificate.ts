// cert-ref (runtime 0.91.0, #1638 part 1): `DecisionSealed.certificate` (`seam.event.v1` tag 19). The TS
// twin of `python/seam_sdk/_certificate.py`.
//
// The decision certificate a sealed decision's evaluations name. It is set only on a RESOLVED seal
// whose accepted evaluations carry exactly one distinct typed
// `rationaleRef = "decision-cert:sha256:<64 lowercase hex>"`. It is OUTSIDE record digest v4 and
// commitment digest v5: the sealed binding is the evaluation's `rationaleRef`, inside the TCT, never
// this field. So a consumer must not treat it as evidence, and the runtime never dereferences or
// verifies the certificate.
//
// `provenance` is a CLOSED set carried as `int32`, not a proto enum (the event descriptor encoding has
// no enum form; the wire bytes are those of a proto3 enum). Read it only through
// `certificateProvenance`: any value outside the set reads as UNSPECIFIED, the least trusted reading,
// never as evidence.

import type { DecisionSealed } from "../gen/seam/event/v1/seam_event_pb.js";

/** Unknown or unset: the least trusted reading. */
export const CERTIFICATE_PROVENANCE_UNSPECIFIED = 0;
/** The evaluating agent asserted the reference; the runtime checked only its shape. */
export const CERTIFICATE_PROVENANCE_AGENT_ASSERTED = 1;
/** Every provenance this SDK knows. Additive values may follow (a runtime-evaluated one arrives with Gate). */
export const CERTIFICATE_PROVENANCES: readonly number[] = Object.freeze([
  CERTIFICATE_PROVENANCE_UNSPECIFIED,
  CERTIFICATE_PROVENANCE_AGENT_ASSERTED,
]);

const ID = /^sha256:[0-9a-f]{64}$/;

/** The provenance as this SDK reads it: a known value as is, anything else as UNSPECIFIED. */
export function certificateProvenance(value: number): number {
  return Number.isInteger(value) && CERTIFICATE_PROVENANCES.includes(value)
    ? value
    : CERTIFICATE_PROVENANCE_UNSPECIFIED;
}

/** `DecisionSealed.certificate`, with `provenance` already normalised by `certificateProvenance`. */
export interface CertificateRefView {
  /** `sha256:<64 lowercase hex>`: the suffix after `decision-cert:` in the sealed `rationaleRef`. */
  readonly id: string;
  readonly provenance: number;
}

/**
 * The certificate a generated `DecisionSealed` names, or `undefined` when it names none (always on a
 * row sealed before runtime 0.91.0). A certificate whose `id` is not `sha256:<64 lowercase hex>` reads
 * exactly as absent (`seam-event.v1.md`). Not evidence: see the module comment.
 */
export function certificateRefOf(ds: DecisionSealed): CertificateRefView | undefined {
  const c = ds.certificate;
  if (c === undefined || !ID.test(c.id)) return undefined;
  return { id: c.id, provenance: certificateProvenance(c.provenance) };
}
