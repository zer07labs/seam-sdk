# Decisions

The durable record of `/reconcile` passes over `ASSUMPTIONS.md`. Each entry: the original
assumption, the independent recommender's analysis, the human verdict, and the resulting status.
`/ship` and any later reconciliation read this file instead of replaying the conversation that
produced it.

## 2026-08-23 — `plans/sdk-exec-w1-w7.md` Phase 3 (W4.3): does a new field enter the record-digest preimage?

W4.3 requires an **explicit, written** answer per new field, because "an unanswered question here is
how v1→v2 happened." Answering it in a PR comment and moving on is what this entry exists to prevent.

### None of the four landed contract changes enters the record-digest preimage

- **The question.** The batched regeneration added `DecisionResponse.policy_enforcement` (7),
  `.participant_verdicts` (8), `.collective_outcome` (9), `SessionStep.policy_enforcement` (3), and
  the quorum verbs. Does any of them change what `verify/` must hash — which would make this a
  digest **version bump**, not an additive field, and pull in the whole of W7?
- **Answer: no, and the reason is structural rather than a judgment call.** Every one of those
  fields is on a `seam.api.v1` **response** message. The record digest is computed over
  `DECISION_SEALED`'s payload columns — specified byte-exactly at
  `seam-runtime/docs/specs/seam-event.v1.md:379-393` — and `verify/src/wire.rs` mirrors the
  **event** wire only (`SeamEventPb`, `DecisionSealedPb`, `ErasureCertificatePb`, …). A response
  field is not a sealed column and never reaches the preimage.
- **The one event-wire addition in the same window** is `seam.event.v1 LearningOutcome.policy_key`
  (tag 3), found by the descriptor diff rather than by the PR list. `verify/` does not mirror
  `LearningOutcome` at all (grep: zero hits), so it does not reach the verifier either.
- **Consequence:** `verify/src/wire.rs` needs no change, `conformance/vectors.json` is untouched,
  and W7 does not apply to this regeneration.
- **The method, which outlives this answer:** the test is not "is the field new?" but **"is it a
  sealed column?"** Ask it against the event proto and `verify/src/wire.rs`, per field, every
  regeneration. `GetDecision`/`ReplayDecision` deliberately do **not** carry the three new response
  fields precisely because that *would* require a `DecisionRecord` schema + archive-format
  migration — the proto says so itself. The day a field lands on `DecisionSealed`, the answer flips
  and W7 engages.
- **Status:** RECORDED. Re-answer per regeneration; do not inherit this conclusion without redoing
  the check.

## 2026-08-16 — reconcile `plans/archive/adopt-runtime-2026-07.md`'s ASSUMPTIONS.md (8 entries)

Ranked by blast radius, highest first. The two dependency-floor entries are genuine one-way
doors (already-published breaking changes); the rest are low-stakes/reversible.

### The `protobuf` floor is derived from the generated stubs, not chosen
- **Recommender (Fable):** CONFIRM as-is. Verified `python/pyproject.toml`, `test_protobuf_floor.py`,
  and `CHANGELOG.md`'s 0.7.13 section directly: the floor (`protobuf>=7.35.1,<8`,
  `requires-python>=3.10`) shipped exactly as chosen, and the "confirm release framing before
  publishing" concern is moot — it published with an explicit breaking-change warning block
  already written up, since a minor bump was structurally impossible under "one version
  everywhere."
- **Verdict:** Confirm.
- **Status:** CONFIRMED.

### The `grpcio` floor is derived the same way, and needs the LATER of two versions
- **Recommender (Fable):** CONFIRM as-is. Same release-framing resolution as the protobuf floor;
  `grpcio>=1.64` and `test_grpcio_floor.py` still match, and the 1.64-not-1.63 reasoning (needs
  both halves of the registered-method convention) is empirically verified in the test itself.
- **Verdict:** Confirm.
- **Status:** CONFIRMED.

### `timeout` means per-RPC, not an overall call budget
- **Recommender (Opus):** CONFIRM as-is, plus a correction — the entry's own text said `authorize()`
  "can make up to four" wire calls, but its own enumeration (2 admit + 1 + 2 refresh + 1) sums to
  six, matching what `client.py`'s doc comment actually says. Verified TS carries the mirrored
  doc; no second consumer (checked `seam-aegis`) needs an overall budget yet — its production path
  already gets one via `seam-agent-core`.
- **Verdict:** Confirm + fix the "four" → "six" typo in the assumption record.
- **Status:** CONFIRMED. `ASSUMPTIONS.md` corrected.

### check-contract default mode is RPC-only; streamed-payload fields gate under STREAM=1
- **Recommender (Opus):** CONFIRM, but correct stale text. Verified `ci.yml` and `check-contract.sh`
  directly: CI already runs `STREAM=1 EVENTS=1` as permanent hard gates — the escalation this
  entry named as the eventual target already happened. The entry's "CI runs the default mode"
  clause is now false; the env-flag split design itself is unchanged and correct.
- **Verdict:** Confirm + correct the stale "CI runs default mode" text.
- **Status:** CONFIRMED. `ASSUMPTIONS.md` corrected.

### generate-local is the development baseline; the BSR is the release source
- **Recommender (Opus):** CONFIRM as-is. Verified `Makefile`, `ci.yml`, `publish.yml`, `README.md`,
  and `test_workflows_generate_through_the_makefile.py` — the dev/release split is intact and
  test-enforced (workflows can never silently fall back to raw `buf generate`).
- **Verdict:** Confirm.
- **Status:** CONFIRMED.

### The live attestation valid-case pins the runtime's chain_head_attestation KAT
- **Recommender (Opus):** CHANGE (mechanism only, not the underlying decision). Verified: Phase 5
  did add this KAT to `conformance/vectors.json` (byte-identical), but
  `python/tests/test_verify_attestation.py` and `ts/tests/verify_attestation.test.ts` were never
  rewired to load it — a runtime KAT regen would redden `test_conformance.py` while silently
  leaving the two hardcoded copies stale in any environment without the live-test binary. (A
  ship-gate verifier later noted `verify/src/verify.rs`'s Rust unit tests carry two more
  independent hardcoded copies of the same KAT — out of scope for this entry, which was
  specifically about the Python/TS live-attestation test; see the amended note in
  `ASSUMPTIONS.md`.)
- **Verdict:** Change now — rewire both attestation test files to load the KAT from
  `conformance/vectors.json`, matching the loader pattern `test_conformance.py`/`conformance.test.ts`
  already use, and delete the duplicated literals.
- **Status:** CONFIRMED (amended). Code changed: `python/tests/test_verify_attestation.py` and
  `ts/tests/verify_attestation.test.ts` now load `_VECTOR`/`VECTOR` from `conformance/vectors.json`
  instead of hand-copied literals. Verified: `pytest tests/test_verify_attestation.py` (2 passed, 1
  skipped — env-gated live test) and `tsc --noEmit` + `node --test tests/verify_attestation.test.ts`
  (2 passed, 1 skipped) both green after the rewire.

### The verify/ authenticity goldens are pinned to a runtime commit
- **Recommender (Opus):** CONFIRM as-is. Verified `verify/tests/goldens/` is populated and
  byte-for-byte identical (SHA-256) to seam-runtime commit `fd633c9`'s fixtures, that commit is
  real/reachable in the sibling checkout, and there's been no runtime-side drift since.
- **Verdict:** Confirm.
- **Status:** CONFIRMED.

### The streamed digest-recompute helper lives on the admin module, keyed to a single record
- **Recommender (Opus):** CONFIRM as-is. Verified `verify_streamed_record_digest`/
  `verifyStreamedRecordDigest` are behaviorally equivalent in both languages, both tested, and
  documented. No consumer has asked for the broader `verify_streamed_chain` since Phase 6 shipped.
- **Verdict:** Confirm.
- **Status:** CONFIRMED.

---

**Summary:** 7 confirmed as-is (2 corrected in text: timeout typo, check-contract stale claim), 1
confirmed-amended with a real code change (KAT pinning rewired to the shared conformance vector,
duplicated literals deleted). 0 changed in substance, 0 deferred. No follow-up code work needed
before the next `/ship` beyond what's already in this pass.
