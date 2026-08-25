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

---

## D-035 — the verifier implements `record_digest_v3`, and refuses a strip rather than guessing

**Decision.** `seam-verify` recomputes v3 `DECISION_SEALED` digests as well as v2, and gains two
refusals it did not have: a v3 record missing `context_digest` (tag 11) or `participation_digest`
(tag 12) is refused as a **STRIP**, reported distinctly from a digest mismatch; and a record
declaring `schema_version = 1` while carrying any digest-covered column (tags 10–13) is refused as a
**DOWNGRADE**.

**Why a strip is not a mismatch.** The two failures look the same from the outside — exit 2 — but
they mean different things to whoever is holding the stream, and collapsing them loses the more
serious one. A mismatch says *these bytes were altered*. A strip says *a field was removed*, and the
tempting handling of a removed field is what makes it dangerous: default it to an empty digest and
"nobody participated" becomes indistinguishable from "somebody deleted the participation record";
fall back to the v2 formula and you have implemented the downgrade the attacker wanted. So the
record is refused, and the wording says which of the two happened.

**Why the v1 refusal exists at all.** Records below `schema_version = 2` have no stream-recomputable
digest, so the recompute skips them. That skip is correct and it is also the one downgrade direction
the recompute cannot catch by construction: relabel a v3 record as v1 and there is no comparison
left to fail. The spec closes it — tag 10 is absent *only* on v1 payloads — so a v1 record carrying
any covered column is refusing an impossible shape, not a legitimate old one. Genuine v1 records
still verify.

**Earned, not asserted.** The repro was watched to fail before the fix and watched to be caught
after, through the shipped binary, against a stream built outside the Rust test harness (generated
from the Python implementation, so the fixture and the code under test have no common ancestor):

```
   $ seam-verify chain v3_stripped.jsonl
   CHAIN VERIFIED                    → exit 0   (integrity is fooled — this is the hole)

   $ seam-verify chain v3_stripped.jsonl --issuer <AID>
   AUTHENTICITY VERIFICATION FAILED  → exit 2

   a v3 DECISION_SEALED (dec:conformance) carries NO context_digest (wire tag 11).
     The v3 record-digest formula requires it. This is a STRIP, not a digest mismatch: the record
     is REFUSED — not defaulted to an empty digest, and not recomputed under the v2 formula.

   $ seam-verify chain v3_ok.jsonl --issuer <AID>
   CHAIN AUTHENTICATED               → exit 0   (records recomputed: 1)
```

Note the first line: the stripped stream and the intact one have the **same head**, because the
payload is not in the checksum. Integrity verification cannot see this attack at all, which is
exactly why the recompute has to.

Pinned by `tests/authenticity.rs` (strip-is-not-mismatch, and the downgrade guard parametrized per
column — a decoy guarding only tag 10 survived the first version of that test) and by
`tests/conformance.rs`, which drives every committed v3 vector through the real CLI.

**The transcription is clean-room, and that is the claim.** All three of this repo's implementations
— `verify/src/verify.rs`, `python/seam_sdk/crypto.py`, `ts/src/crypto.ts` — were written from the
published spec (`docs/seam-event.v1.md`, vendored verbatim from `seam-runtime`), never from the
runtime's Rust. Four independent implementations now agree on every committed vector, and agreement
between implementations that read each other would not have been evidence of anything.

**Independence is untouched.** v3 adds SHA-256 framing over bytes already in the wire types; no new
dependency. `cargo tree -e normal` still shows zero Seam crates.

**Blast radius / reversal.** The refusals are the risky half: a false STRIP or DOWNGRADE turns a good
stream red in an auditor's hands. Both are narrow — a v3 record with no tag 11/12 is unrepresentable
by a conforming producer, and a v1 record with a tag-10 column contradicts the spec — and both are
pinned by tests that were driven red before they were trusted. Reversal is a code change with no
data migration; nothing persisted depends on either refusal.
