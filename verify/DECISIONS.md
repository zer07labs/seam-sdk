# Decisions — `seam-verify`

Trust claims this tool makes are one-way doors: once shipped, third parties rely on them. Each is recorded
here, earned before it is stated, and reversible only by retraction.

## D-034 — `verify/` moves from INTEGRITY to AUTHENTICITY

**Decision.** `seam-verify chain` gains `--issuer <AID>`, and the README's claim moves from *integrity*
(the chain links) to *authenticity* (Seam signed it). The plain `chain` behaviour is unchanged and remains
the integrity-only check; `--issuer` is strictly stronger.

**Why.** Integrity over an unkeyed SHA-256 chain with a public genesis proves only internal consistency — a
transport-controlling adversary can rebuild a self-consistent chain from any fork point, and integrity
passes it. Authenticity closes two holes an honest-looking chain can hide:

1. a **fabricated chain** — valid triples, no issuer-signed head;
2. a **payload rewrite** — a structural column changed after sealing, the `(prev, digest, checksum)` triple
   left intact so the chain still links.

`--issuer` verifies every `CHAIN_HEAD_ATTESTATION` against the **pinned** issuer key (signature +
head-at-position, refusing a stream with none), and recomputes every v2 `DECISION_SEALED`'s digest from its
payload — refusing a mismatch or a stripped `ciphertext_digest`.

**The claim is EARNED, not asserted (the protocol).** The README wording changed only after:

1. **The repro was watched fail.** The `payload_rewrite` golden — a genuine attested chain with one
   `outcome` flipped, the triple intact — was run both ways and the inversion observed:

   ```
   $ seam-verify chain tests/goldens/payload_rewrite.jsonl
   CHAIN VERIFIED                    → exit 0   (integrity is fooled — this is the hole)

   $ seam-verify chain tests/goldens/payload_rewrite.jsonl --issuer <AID>
   AUTHENTICITY VERIFICATION FAILED  → exit 2   (the recomputed v2 digest ≠ the wire digest)
   ```

   Pinned by `tests/authenticity.rs::a_payload_rewrite_is_caught_under_issuer_but_not_by_integrity`.

2. **Parity was proven.** The runtime's differential harness
   (`seam-runtime/crates/seam-verify/tests/differential.rs`) drives BOTH verifiers — this public one and the
   runtime's own — over the same streams and requires identical verdicts on the authenticity cases
   (attested → PASS, fabricated → FAIL, payload-rewrite → FAIL, spliced → FAIL). It runs in the runtime's CI
   (`differential-parity` job) against this repo's `main`, so a drift on the authenticity surface is caught
   at the source. Without that, a hand-transcribed verifier that quietly stopped checking `--issuer` would
   be a rubber stamp telling third parties forged chains are fine.

3. **The framing is KAT-pinned.** `chain_head_attestation` and `record_digest_v2` are checked byte-for-byte
   against the runtime's committed conformance vectors — in the Rust verifier
   (`src/verify.rs` unit tests) and in the Python + TS crypto shims (`conformance/vectors.json` +
   `test_conformance.py` / `conformance.test.ts`).

**Independence is untouched.** `--issuer` adds `ed25519-dalek` signature verification and a SHA-256 digest
recompute — both already-present, non-Seam crates. `cargo tree` still shows zero Seam crates; that gate is
what the entire claim rests on.

**Blast radius / reversal.** This is a public trust claim. Retracting it (reverting the README to INTEGRITY)
is expensive precisely because third parties will have relied on it. It is guarded by the three gates above:
if any regresses (the repro stops failing, the harness diverges, a KAT drifts), the claim is no longer
earned and the tests go red before a release can ship.
