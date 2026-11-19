// RT4 (runtime 0.95.0, seam-runtime#1776): `OpenSessionRequest.requester` (`seam.api.v1` field 10). The TS
// twin of `python/seam_sdk/_requester.py`.
//
// The human principal a session was opened for, as the control plane's pseudonymous principal id (`p_` +
// a hash of issuer and subject). It is OPTIONAL caller-asserted metadata: it enters no digest, no event and
// no audit row, and the runtime stores it sealed as personal data.
//
// `RequesterKind` is request-only: no response message carries it, so no fail-closed reader here can meet
// an unknown value of it. The only kind the runtime accepts is `REQUESTER_KIND_HUMAN`, so `openSession`
// takes just the id and always sends that kind. (Over gRPC the kind is the proto enum; the runtime's own
// HTTP open route spells it `"human"` instead. This SDK speaks gRPC only.)
//
// The id rule mirrors the runtime's Ring-0 `seam_types::valid_requester_id` (spec
// `docs/specs/session-open.md` §Requester): `p_` followed by zero or more of `[A-Za-z0-9._:-]`, 3 to 128
// bytes in total. The runtime refuses anything else with INVALID_ARGUMENT. Checking it here turns a caller
// bug into a local `RangeError` before any RPC, and, like the runtime's refusal, the error never echoes
// the id: a raw email or IdP subject passed by mistake must not reach a log through an exception message.

import { create } from "@bufbuild/protobuf";

import { RequesterKind, RequesterSchema, type Requester } from "../gen/seam/api/v1/seam_pb.js";

/** The shortest accepted id (`p_` plus one character). */
export const REQUESTER_ID_MIN_BYTES = 3;
/** The longest accepted id: a 128-byte id is accepted, a 129-byte id is refused. */
export const REQUESTER_ID_MAX_BYTES = 128;

// ASCII-only charset, so the string length is the byte length.
const REQUESTER_ID = /^p_[A-Za-z0-9._:-]*$/;

/** Whether `requesterId` is an id the runtime accepts. Never throws. */
export function validRequesterId(requesterId: unknown): boolean {
  return (
    typeof requesterId === "string" &&
    requesterId.length >= REQUESTER_ID_MIN_BYTES &&
    requesterId.length <= REQUESTER_ID_MAX_BYTES &&
    REQUESTER_ID.test(requesterId)
  );
}

/** The wire `Requester` for `requesterId`; `undefined` (field absent) when it is `undefined`. Throws a
 * `RangeError` naming the rule, never the id, for an id the runtime would refuse. */
export function requesterMessage(requesterId: string | undefined): Requester | undefined {
  if (requesterId === undefined) return undefined;
  if (!validRequesterId(requesterId)) {
    throw new RangeError(
      "requester must be the control plane's pseudonymous principal id: 'p_' followed by " +
        "[A-Za-z0-9._:-], 3 to 128 bytes in total (a raw email or IdP subject is refused); " +
        "the value is not echoed",
    );
  }
  return create(RequesterSchema, { kind: RequesterKind.HUMAN, id: requesterId });
}
