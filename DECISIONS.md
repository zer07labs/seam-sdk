# Decisions

The durable record of `/reconcile` passes over `ASSUMPTIONS.md`. Each entry: the original
assumption, the independent recommender's analysis, the human verdict, and the resulting status.
`/ship` and any later reconciliation read this file instead of replaying the conversation that
produced it.

## 2026-08-23 — `plans/sdk-exec-w1-w7.md` Phase 6 (W1): publishing `verify/` to crates.io

Three decisions, taken together because publishing is irreversible and they interact.

### `verify/` ships as a LIBRARY as well as a binary

- **The question.** `verify/` was bin-only — `[[bin]]` and no `src/lib.rs`. A published bin-only
  crate is installable (`cargo install seam-verify`) but **not embeddable**: an auditor who wants
  verification inside their own pipeline must shell out and parse `--json`.
- **Verdict: lib + bin.** `src/lib.rs` holds the logic; `main.rs` is a shell over it, so the CLI and
  an embedding caller run **exactly the same code** and there is no second implementation to drift.
  A parse step between the answer and the decision is somewhere a wrong answer can be introduced,
  and embeddability is most of the reason to publish at all.
- **Accepted cost:** a public Rust API surface with its own semver obligations.
- **Consequence taken while doing it:** the CLI's certificate shape-sniffing moved into
  `Cert::parse_document`. While it was inline in the binary, an embedder had to reimplement it to
  accept the same files the CLI accepts — a second implementation of exactly the kind this crate
  exists to avoid.
- **Status:** DONE. A doctest verifies the shipped fixture **through the library API** (not the
  CLI), and asserts a wrong issuer fails closed.

### `verify/` keeps its own version, independent of the SDK's

- **The question.** `verify/` is `0.1.0` while the SDK is `0.7.42`. Publishing locks that in.
- **Verdict: deliberate — keep it independent.** `verify/` is its own cargo workspace with zero Seam
  dependencies, and an independent version lets it express **real semver**, which this SDK
  explicitly **cannot**: *"this SDK cannot express its own semver. A breaking change here ships under
  whatever number the runtime's history computes, which may be a patch"* (`CHANGELOG.md:9-12`).
  Binding the verifier to that would inherit a defect for the sake of a slogan.
- **Status:** CONFIRMED.

### The MSRV is derived, and the first number written down was wrong

- `rust-version` was **absent**, which crates.io accepts silently — a published crate without one
  gives a consumer no signal and they find out from a compile error.
- It was first written as **1.74**, from recalling `ed25519-dalek`'s floor. **That was wrong.** The
  resolved graph requires **1.85** (`prost` 0.14.4, `base64ct` 1.8.3, `zeroize` 1.9.0). A floor that
  is too low is worse than none: absent is honestly silent, a wrong number reads as a checked
  promise.
- **Verdict:** declare 1.85, and **derive rather than pin it** — `verify/tests/msrv.rs` reads
  `cargo metadata` and fails when a dependency outruns the declared floor, the same discipline
  `python/tests/test_protobuf_floor.py` applies to the protobuf floor and for the same reason
  (third-party crates raise their MSRVs on their own schedule, with nobody editing this manifest).
- **Status:** DONE, and the guard was driven red (declaring 1.74 fails, naming `base64ct`).

### Nothing is published yet, and that is the decision

`publish = false` → `publish = true` in the manifest, but **no `cargo publish` has run**. The
crates.io name claim is permanent and `seam-runtime/crates/seam-verify` carries the same package
name, so the first publish would decide the namespace for both. The rename is filed as
[`seam-runtime#419`](https://github.com/zer07labs/seam-runtime/issues/419) and **the real publish is
a human step until it closes** — `publish-verify` in `publish.yml` runs the independence proof, the
fixtures and `cargo publish --dry-run`, and stops there.

**And the value is stated honestly, per §9.** Acquisition was never the break: this repo is already
**public** and Apache-2.0, `verify/` is a standalone workspace by design, and its
zero-Seam-dependency claim is a **CI gate** (`ci.yml:283-292`), not a comment. Publishing is a
**distribution and trust-anchoring improvement** — not the thing that unblocks an audit. Anyone can
already clone and build it today.

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
