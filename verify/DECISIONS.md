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

> Superseded in part by D-038: P7 retired v1-v3, so the v3 formula and the v1 DOWNGRADE guard are
> gone. The strip-is-not-a-mismatch rule below stands, extended to tags 14-17.

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

## D-036 — `bundle` verifies `seam-evidence-bundle.v1`, and is stricter than the runtime oracle in three places

**Decision.** `seam-verify bundle <DIR> --issuer <AID>` implements `docs/evidence-bundle.v1.md` §
Verifying, steps 1–6 in order, through the same library calls `chain --from-anchor --strict` makes. To
reach step 4 the crate now implements `seam-commitment-digest:v2`, `seam-explanation-digest:v1` and the
self-issued TCT check (`src/commitment.rs`), written from the runtime's spec text and held to the shared
`conformance/` vectors. No dependency was added.

**Where it differs from the runtime's internal oracle (`seam-verify-internal bundle`), on purpose:**

1. *A member the manifest lists but the directory lacks* is exit **2** (step 1 refuses), where the oracle
   exits 1 (an IO error). The spec puts "every listed file exists" inside step 1, which "refuses (exit 2)".
   Only an unreadable directory or `manifest.json` is exit 1: then nothing was read to refuse.
2. *A malformed `events.jsonl` or `anchor.json`* is exit **2**. The oracle passes `chain`'s exit 1 through.
   In a bundle these bytes are already hash-matched to the manifest, so a member that does not parse is a
   bundle that fails, not a caller's usage mistake.
3. *Two manifest claims the oracle does not read are checked:* `issuer.ed25519_public_key` must be the
   pinned AID's key, and `inclusion.anchor_attested_len` must be `anchor.json`'s `attested_len`. The spec
   says a verifier MUST refuse a manifest that disagrees with the other files. The `window_*` counts and
   offsets are not checked: their counting rules are the exporter's, not written in the spec, and a
   guessed rule would refuse genuine bundles.

Everything else matches the oracle exit code for exit code: a differential run over the four runtime-exported
fixtures and seventeen single-edit tampers agreed on all thirteen tampers these three do not cover.

**The TCT check is the runtime's, not the SDKs' looser one.** `grants` must be exactly
`["seam:commitment", "seam-commitment-digest:<hex>"]` (the spec's "exactly two grants, in this order";
the runtime compares the list), and `ver`, `cnf.jkt`, `iat` are checked as `aitp_tct::verify_tct` does.
The Python/TS shims check only that the digest grant is present.

**Not done.** `seam-event.v1.md` says a verifier that sees a sealed `resolved_status: retracted` should
raise an anomaly. `context.json` now makes that visible, but neither the spec's six steps nor the oracle
act on it, so this build does not either.

## D-037 — strict chain-head attestation dispatch (seam-runtime #835 step 4), and four calls it forced

The attestation's own `tenant` selects exactly one signed framing: empty → v1 only, non-empty → v2 only.
This mirrors seam-runtime #1303 (`seam-trust-aitp::verify_chain_head_attestation` and
`crates/seam-verify`). The owner principle is no backward compatibility, so there is no grace flag and
no toggle. `tenant_unbound` and the untenanted anchor's sole-tenant fallback are removed, as in the
runtime. Four choices went beyond a line-for-line mirror:

1. *The payload==envelope tenant check moved ahead of the pin and the signature.* It used to run after
   the signature, "so a mismatch is reported about a proven-genuine artifact". Under step 4 the payload
   tenant is signed, so a relabelled or stripped tenant would otherwise surface as a generic signature
   refusal. The runtime checks agreement first and reports `ATTESTATION TENANT MISMATCH`, so this build
   now does too. Both orders exit 2; only the stated reason differed.
2. *An anchor whose tenant has no chained event in the window is exit 2 (`NO VALID ATTESTATION`), not
   exit 1 (usage).* Before step 4 this was unreachable through the CLI, because the anchor was always
   attributed to a tenant present in the window. Now an untenanted anchor over a tenant window reaches
   it. The runtime fails it closed with exit 2, and so does this build.
3. *`--from-anchor` over a multi-tenant window is no longer a usage error.* The refusal existed only
   because an untenanted anchor could not be attributed. Every anchor now names the tenant it seeds,
   so the named tenant starts at its anchor and the others start at genesis, as in the runtime's
   `a_tenant_with_no_anchor_verifies_from_genesis_while_another_is_anchored`. `seam_verify::chain_anchored`
   takes the anchor's tenant for this. `bundle` still requires a window of exactly one tenant, because
   an evidence bundle is scoped to one.
4. *`--expect-anchor` follows the same attribution rule.* The runtime has no `--expect-anchor`; its
   sole-tenant fallback existed here only to match `--from-anchor`'s, and goes with it. An untenanted
   expect-anchor stands for `""`, and over a window with no `""` chain it reports TRUNCATED, the same
   folding an absent tenant already got.

A full-event `--from-anchor` now refuses a payload tenant that differs from its envelope
(`ANCHOR SELF-CONTRADICTS`, exit 2), as the runtime's `to_trust_attestation_from_envelope` does. Before
this, the SDK dropped the envelope tenant without checking it.

`fixtures/evidence-bundle/` was re-exported by the runtime's exporter at the #1303 commit, because the
0.44.0 export carried v1 tenant anchors that a step-4 verifier refuses. The runtime's internal oracle
verifies every re-exported directory, and the runtime's `differential` test passes against this build
(`SEAM_SDK_DIR` pointing at it).

## D-038 — record digest v4 only, and commitment digest v3 through a self-attestation TCT (seam-sdk#265)

**Decision.** `seam-verify` recomputes `DECISION_SEALED` digests under `seam.audit.record-digest.v4`
only, the runtime's P7 formula (tags 10-17). Every other `schema_version` is cannot-verify: 1-3 as
RETIRED, anything above 4 as NEWER THAN THIS VERIFIER. Tags 11, 12, 14, 15, 16 and 17 are mandatory;
absent or zero-length is a STRIP, reported apart from a mismatch, while a zero-length tag 13 is
`opt(None)`. Step 4 of `bundle` recomputes `seam-commitment-digest:v3` (the `supersedes` presence
byte) and accepts only the self-attestation TCT form: `typ` `aitp-tct+jwt`, EdDSA under the pinned
key, `iss == sub == aud`, grants exactly `["aitp.attestation"]`, and `ext` exactly
`{"com.zer07labs.seam":{"type":"seam:commitment","commitment_digest":<hex>}}`. A duplicate JSON
key anywhere in the header or claims is refused.

**Why no dual-verify.** The runtime retired v1-v3 with no compatibility window. Keeping the old
arms here would let this verifier pass records the runtime itself no longer accepts. It would also
keep D-035's relabel-to-v1 DOWNGRADE guard alive, and that guard existed only because v1 was
skipped. With one formula, a relabel lands on the same refusal as a genuine old record.

**Why duplicate keys are refused.** `serde_json::Value` keeps the last of two equal keys without
saying so. A token carrying `commitment_digest` twice would then verify under whichever value the
parser happened to keep, which may not be the value another verifier reads.

**Consequence.** Streams and evidence bundles sealed before P7 do not verify under this build.

**Fixtures.** `fixtures/evidence-bundle/` was re-exported at the runtime pin 1ac5de5 (the contract
freeze; first exported at e4c01ad, whose context-provenance.v3 digests no longer verify).
`full/`, `minimal/` and `shredded/` were captured from the temp directories of the runtime's own
`seam-verify-internal --test bundle`. That test never discloses the policy, so `full/` adds the policy
bytes recovered from the previous fixture (`schema_version` 1 → 3). Their SHA-256 equals the
chained `policy_rules_digest`. The manifest gains the matching `files` entry and `disclosed` item;
it is unsigned, so this edit forges nothing. `other-issuer/` is a real export from a postgres-backed
`seam-grpc` under issuer seed 9×32, made with `seam-ops export-evidence`. Its policy is withheld, with
the exporter's reason. All four verify under the runtime's internal oracle as well as here.

## D-039 — context-provenance.v4 only, and unpaired or unknown receipt key status is refused (seam-sdk#265)

**Decision.** Step 6 of `bundle` recomputes `context_digest` under `seam.audit.context-provenance.v4`
only (`src/bundle.rs` `context_digest`): the v3 grammar plus a fifth optional per-binding slot,
`receipt_key_status`, after `resolved_status`. v1-v3 are not dispatched, for the same reason D-038
has no dual-verify: record digest v4 seals only `.v4` at the contract freeze (runtime 1ac5de5).
Before anything is hashed, every binding is checked: `receipt_key_status` must be present exactly when
`receipt_hash` is, and must be `Current` or `Historical` (closed, PascalCase, never ACDP's lowercase
JSON form). A binding that breaks either rule is refused with its index, never hashed as given.

**Why refuse rather than hash.** `docs/evidence-bundle.v1.md` § `context.json` requires it, and the
runtime refuses the same record at seal and on read. Hashing an unpaired binding would only ever
produce a mismatch, which reports the wrong thing: a malformed disclosure, not a tampered one.

**Pinned by** the spec's vector (`8e87a93f…`, five receipt slots absent) and the runtime's
`V4_RECEIPT_CONTEXT` (`3475464e…`, all five populated) as unit tests in `src/bundle.rs`, and by the
re-exported fixtures, which the runtime's oracle and this verifier both accept.

## D-040 — the commitment TCT's `ver` is `aitp/0.3` only (AITP 0.17.0)

**Decision.** `verify_tct` accepts `ver == "aitp/0.3"` and nothing else (`src/commitment.rs`
`TCT_VER`). AITP 0.17.0 (spec bf00e75, fixture env-011) moved the literal from `aitp/0.2` with no
dual-accept, and the runtime mints `aitp/0.3` from that release on. Every commitment digest is
byte-identical; only the signed TCT changes. Same owner principle as D-037 and D-038: no backward
compatibility, so no grace flag.

**Consequence.** An evidence bundle or record whose commitment TCT was signed before the runtime's
AITP 0.17.0 deploy does not verify under this build. That is a history boundary by design.

**Fixtures.** Everything that carries a runtime-signed TCT was re-taken at seam-runtime a853f89
(branch `aitp-0.17.0`), byte-vendored, nothing hand-signed:
`conformance/commitment_digest_v3_vector.json` (only `cases[2].signed_artifact` changed),
`conformance/vectors.json` (only `tct.signed_artifact_jws`), and `fixtures/evidence-bundle/`.
In the bundles the DECISION_SEALED events embed the TCT, so `events.jsonl`, `anchor.json`,
`binding.json` and `manifest.json` move with it, while `context.json` is byte-identical.
`full/`, `minimal/` and `shredded/` come from the runtime's `fixture()`/`export()` in
`crates/seam-verify/tests/bundle.rs`, and `full/` re-applies D-038's `--disclose context,policy`
manifest edit over the unchanged `policy.json`. `other-issuer/` changed provenance: it is no longer a
postgres-backed `seam-grpc` + `seam-ops export-evidence` run, but the runtime's own export path
(`Seam::export_evidence_bundle` → `write_to_dir`) run in-process over the same `fixture()` under seed
9×32 (same AID). Its governing document carries the policy, so policy is now disclosed rather than
withheld. No test depended on that withholding. All four verify under the runtime's internal oracle at
a853f89.
