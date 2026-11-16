// `conformance/vectors.json`'s `tct.inputs.commitment` carries each sealed voter verification record
// (#1687) with its byte fields as `*_hex` strings (`content_digest_hex`, `signature_hex`,
// `signer_certificate_hex`) — the seam-client emitter's projection. The digest takes them as bytes under
// their record names, so the tests read the vector through this one mapping, never a second copy of it.

import type { Commitment, ExplanationEntryInput, VoterVerificationInput } from "../src/crypto.js";

type RawRecord = Omit<VoterVerificationInput, "content_digest" | "signature" | "signer_certificate"> & {
  content_digest_hex: string;
  signature_hex: string;
  signer_certificate_hex: string;
};

export function voterRecordFromVector(r: RawRecord): VoterVerificationInput {
  const { content_digest_hex, signature_hex, signer_certificate_hex, ...rest } = r;
  return {
    ...rest,
    content_digest: content_digest_hex,
    signature: signature_hex,
    signer_certificate: signer_certificate_hex,
  };
}

/** The vector's commitment, with every `voter_verification` in the digest's input shape. */
export function commitmentFromVector(c: Record<string, any>): Commitment {
  return {
    ...c,
    explanation: (c.explanation as Record<string, any>[] | undefined)?.map(
      (e): ExplanationEntryInput => ({
        ...(e as ExplanationEntryInput),
        voter_verification:
          e.voter_verification === null || e.voter_verification === undefined
            ? null
            : voterRecordFromVector(e.voter_verification as RawRecord),
      }),
    ),
  } as Commitment;
}
