# Protocol pass 2026-10 — pre-vendor the runtime contract changes

> **📦 ARCHIVED 2026-10-27 — DELIVERED.** All six phases DONE. The original PR #270 merged ahead of the
> runtime's B11 order and was reverted (#271). It relanded as PR #272 (`9690e25`, 2026-10-19), which is
> reachable from `origin/main`, and closed issue [#265](https://github.com/zer07labs/seam-sdk/issues/265).
> The merge hold below has lifted and is kept as history. Both `ASSUMPTIONS.md` entries tagged to this
> plan (Phase 5, items 4–5 and 6a) are CONFIRMED (2026-10-18, /reconcile).

> **Issue:** [#265](https://github.com/zer07labs/seam-sdk/issues/265).
> **Owner plan:** `seam-runtime/plans/protocol-absorption-2026-10.md` on branch `protocol-pass-2026-10`.
> **Scoped plan this copies:** `seam-runtime/plans/cross-repo/seam-sdk-protocol-pass.md` on the same branch.
> **Runtime pin:** `protocol-pass-2026-10` @ `e4c01ad336e73cc5a373218029809fa708624ee4`. The vectors,
> specs and proto are vendored byte-identical from this commit. Anchors below are true at seam-sdk
> `dd5c58c` and runtime `e4c01ad3`. Re-check them before editing.
> **Merge hold:** this lands as a ready PR that is **not merged**. The hold lifts when runtime
> `protocol-pass-2026-10` merges, or when its release is about to be dispatched (owner release order,
> step 5). PR #257 set the precedent.

## Status

IMPLEMENTED; PR open and HELD (merge hold above). Phases 1–6 are DONE.

## Context

The runtime's 2026-10 protocol pass changes the wire in ways that break every SDK the moment the
runtime release ships:

- The PoP `message_id` is now derived with a domain tag and RFC 9562 v4 bits (P9).
- The record digest is v4 only (P7).
- Decision ids take the form `dec:{tenant}:{session}` (P5).
- Session ids have a rule (P4).
- Protocol errors carry a `macp_code` (P11).
- `IssueChallenge` takes a real request message (P3).
- Commitments are sealed as AITP self-attestation TCTs over commitment digest v3 (B3/B5).

Our SDKs must merge **before** the runtime release is dispatched. There is no compatibility window:
the owner principle is no backward compatibility. So there is no dual `message_id`, and digest
v1–v3 and commitment v2 are deleted, not kept behind a flag.

The **clean-room rule** holds throughout. Every digest and crypto construction is transcribed from
the runtime's published specs, protos, plans and vector JSON, never from `crates/**/*.rs`. Running
runtime binaries and tests is fine.

### Scope decision: items 10–15 are in

The launcher scoped this to "items 1–9". The scoped plan's own "Additions since 2026-10-17" section
(items 10–15) was written at `e4c01ad3`, the commit we pin. It folds those items into this same PR.
Item 7 also forces them: it requires `conformance/vectors.json` to be byte-identical to the runtime's
`conformance_vectors.json`, and the runtime's `sdk-digest-parity` CI job enforces that. That file
now carries the commitment v3 digest and the self-attestation JWS. A byte-identical vendor that
fails our own conformance suites would not be green. So:

- Items 10 and 11 are required by item 7.
- Item 12 (spec-pin) and item 13 (live governing root v3) are required for a green PR against the
  branch.
- Items 14 and 15 are docstring and comment edits.

**B7 (P-256) is still out.** The scoped plan's "Checked, not needed" section shows the SDK needs
nothing for it. This is recorded in `DECISIONS.md`.

## Delivers (copied from the scoped plan; SDK anchors re-verified)

1. **Derived `message_id` (P9).**
   - `h = SHA-256("seam-pop-mid-v1" ‖ 0x00 ‖ pop_nonce_ascii)`.
   - The id is `h[0..16]` with `h[6] = (h[6] & 0x0f) | 0x40` and `h[8] = (h[8] & 0x3f) | 0x80`,
     written as a lowercase hyphenated UUID.
   - Spec: runtime `docs/specs/authorize.v1.md`.
   - Add one shared `derived_uuid(tag, input)` primitive per language, tested against the vectors'
     `derived_uuid` block (`kat_derived_uuid_001`, `pop_message_id`, `tct_jti`).
2. **The presentation has exactly five fields (P8).** Audit only. All five SDKs already emit exactly
   `sender_aid`, `descriptor`, `message_id`, `timestamp` and `pop_nonce`. Pin it with a test.
3. **Record digest v4 only (P7).** Spec: runtime `docs/specs/seam-event.v1.md`, record digest v4 and
   participants digest v4.
   - Python, TS and `verify/` compute v4. v2 and v3 are deleted.
   - Any `schema_version` other than 4 raises a typed cannot-verify error.
   - The streamed-event arms read `DecisionSealed` tags 14–17.
   - Go, Java and Kotlin carry no record digest today, and that stays so (see below).
4. **Decision id `dec:{tenant}:{session}` (P5).** Add one parser and one builder in Python and TS:
   - strip `dec:`;
   - split on the first `:`;
   - the tenant must match `^[A-Za-z0-9_-]{1,128}$`;
   - the session must pass the P4 rule;
   - refuse anything else.

   Go, Java and Kotlin have no client surface, so this is N/A there.
5. **Session-id rule (P4).** Add an optional client-side validator in Python and TS. The server stays
   authoritative. The rule:
   - either a canonical lowercase UUID v4 or v7 (any 36-char input is judged only as a UUID);
   - or at least 22 chars of `[A-Za-z0-9_-]`;
   - at most 128 bytes either way.
6. **`macp_code` (P11).** Add a typed accessor on the Python `SeamError` and TS `SeamError`.
   - It reads `google.rpc.ErrorInfo` from `grpc-status-details-bin`, domain `seam.zer07labs.com`.
   - It returns the class `reason`, and `macp_code` only when `reason == "PROTOCOL"`.
   - The value is the raw string, so a future code is still readable; it is never a closed enum.
   - Python decodes with a hand-written stdlib protobuf reader, because `errors.py` must stay
     import-light.

   The HTTP JSON half does not apply: the SDK clients are gRPC-only.
6a. **`IssueChallenge(IssueChallengeRequest{})` (P3).** Python and TS send the new message.
   - A load-shed (`RESOURCE_EXHAUSTED` with reason `QUOTA_EXCEEDED` and `google.rpc.RetryInfo`)
     surfaces a typed `retry_after` on the error.
   - The SDK keeps its recorded never-retries policy, so it never retries in a tight loop.
     Adapters own backoff. Recorded as an UNCONFIRMED assumption.
7. **Vectors.** Re-vendor byte-identical from the pin:
   - `conformance/vectors.json` ← runtime `crates/seam-client/tests/conformance_vectors.json`;
   - the v4 extended file ← runtime `crates/seam-client/tests/conformance_vectors_extended.json`;
   - `commitment_digest_v3_vector.json` ← runtime
     `crates/seam-trust-aitp/tests/fixtures/commitment_digest_v3_vector.json`.

   Delete `record_digest_v3_extended.json`, its emitter, and `commitment_digest_v2_vector.json`.
8. **Proto.** Regenerate with `make generate-local RUNTIME=<branch checkout>`. The BSR module has no
   commit for the branch, so CI codegen needs a BSR push. That is a runtime-side step and a
   cross-repo need (see "Open questions").
9. **`COMPATIBILITY.md`.** Add one row: requires runtime ≥ the protocol-pass release (0.48.0 train),
   with no compatibility with earlier runtimes. The pin `e4c01ad3` is recorded.
10. **Commitment digest v3 plus the self-attestation TCT (B3/B5)**, in all six implementations.
    - Spec: runtime `docs/specs/seam-commitment-digest.v3.md`. `F(x) = be64(len) ‖ x`.
      `supersedes` is `0x00` when absent and `0x01 ‖ F(s)` when present.
    - The TCT must have:
      - `typ` = `aitp-tct+jwt`;
      - `iss == sub == aud`;
      - `grants == ["aitp.attestation"]`;
      - `ext` = exactly `{"com.zer07labs.seam": {"type": "seam:commitment", "commitment_digest": hex}}`,
        refusing a duplicate key;
      - the JWS verified with the pinned key.
    - v2 is deleted.
11. **Re-vendor the changed vectors** (folded into item 7). Rename the v2 vector tests to v3.
12. **Re-vendor the verbatim specs.** Copy `verify/docs/seam-event.v1.md` and
    `verify/docs/evidence-bundle.v1.md` whole from the pin. Each gets a `tracking
    protocol-pass-2026-10` header so `spec-pin` compares against the branch tip. Re-point the
    citations into them.
13. **Live governing root v3 (B10).** Change `python/tests/governing_root.py` from
    `schema_version: 1` to 3.
14. **Docstrings (B4).** Replace `rules.seam` with `rules["x-com.zer07labs.seam"]` in
    `client.py`, `aio.py` and `client.ts`.
15. **Proto comments (B8).** These arrive with the regenerated stubs. `ResolveContext` is
    pass-through, so there is no code change.

**Also in scope**, from the owner's /reconcile on 2026-10-17: repin the synthetic POLICY_DENIED
fixtures in `python/tests/test_status_mapping.py` to `PERMISSION_DENIED`, the new wire shape.

## Phases

### Phase 1 — Vectors, `derived_uuid` and `message_id` ×5

- **Status:** DONE.
- **Delivers:** items 1, 2, 7 (`vectors.json` part) and 11 (the vector half).
- **Depends on:** nothing.
- **Files:**
  - `conformance/vectors.json`
  - `python/seam_sdk/crypto.py`
  - `ts/src/crypto.ts`
  - `go/crypto/crypto.go`
  - `java/.../SeamCrypto.java`
  - `kotlin/.../SeamCrypto.kt`
  - the per-language conformance tests
- **Approach:**
  - Vendor `vectors.json` whole.
  - Add `derived_uuid(tag, input)` to each language, and route the PoP `message_id` through it.
  - The conformance suites drop the removed record-digest v2/v3 blocks. Phase 2 adds the v4 blocks.
  - Phase 1's vendor also changes the commitment digest and JWS. If a suite's commitment assertion
    fails, that language's commitment test is skipped until Phase 4 with an xfail-style marker
    naming Phase 4, or Phases 1 and 4 commit together. Either way, no commit is left red.
- **Edge cases:**
  - `tag ‖ 0x00 ‖ input` has a 0x00 separator.
  - The nonce is the base64url ASCII string, not decoded bytes.
- **Acceptance:** `kat_derived_uuid_001` gives `27b131ae-…`, `pop_message_id` gives `786ec92e-…`,
  and `tct_jti` gives `c7321ce4-…` in all five languages. The admission vector's `message_id` and
  proof recompute.
- **Tests:**
  - `kat_derived_uuid_001` ×5
  - `pop_message_id_matches_runtime_vectors` ×5
  - a five-field presentation pin (Python and TS)

### Phase 2 — Record digest v4 in Python and TS, streamed arms, event manifest

- **Status:** DONE.
- **Delivers:** item 3 (Python and TS), item 7 (the extended file), and the gate's exit 8 → 0.
- **Depends on:** Phase 1.
- **Files:**
  - `python/seam_sdk/crypto.py`, `admin.py`, `__init__.py`
  - `ts/src/crypto.ts`, `admin.ts`, `index.ts`
  - `conformance/vectors_extended.json` (the runtime's extended file)
  - `contract/event-field-manifest.txt`
  - the v3 tests, rewritten as v4
- **Approach:**
  - `record_digest_v4` uses the exact signature the runtime's `sdk-digest-parity` script calls.
  - Add `participants_digest_v4`.
  - `verify_streamed_record_digest` becomes v4-only. It reads tags 14–17, and any other version
    raises `UnsupportedRecordDigestVersion`, a `ValueError` subclass.
  - Delete v2/v3 and their exports.
  - Wire the four new `DecisionSealed` fields, then add them to the event manifest. This is a
    decision, not a `--write-manifest`.
- **Edge cases:**
  - `opt()` presence differs from an empty string.
  - `le32` for `schema_version`, `le64` for `sealed_at`.
  - A participants list with zero members.
  - `crypto.py` must stay stdlib-only, because the runtime loads it standalone.
- **Acceptance:**
  - `record_digest_v4` and `record_digest_v4_absent_policy` recompute in Python and TS.
  - Every extended v4 case recomputes.
  - A `schema_version` of 3 is refused as cannot-verify.
  - `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` exits 0.
- **Tests:**
  - `record_digest_v4_vectors`
  - `record_digest_v3_is_unknown_version`
  - the streamed-decode v4 tests

### Phase 3 — `verify/` record digest v4, goldens, evidence-bundle fixtures

- **Status:** DONE.
- **Delivers:** item 3 (Rust).
- **Depends on:** Phase 2, for the shared vectors.
- **Files:**
  - `verify/src/verify.rs`, `main.rs`, `bundle.rs`
  - `verify/tests/*.rs`
  - `verify/tests/goldens/*.jsonl`, re-vendored from the runtime's `crates/seam-verify/tests/goldens/`
  - `verify/fixtures/evidence-bundle/*`
- **Approach:**
  - Replace the v2/v3 dispatch with v4-only.
  - Drop the old link-only arm for `schema_version` below 2. Every version other than 4 is
    cannot-verify, because the spec refuses any other version.
  - Re-vendor the goldens from the runtime.
  - Re-export the bundle fixtures by running the branch runtime's exporter, as #257 did. If that
    cannot be run, regenerate them through the runtime's `evidence_bundle` test path.
  - Unit tests go inside `src/`, because `Cargo.toml` excludes some tests from the package.
- **Acceptance:**
  - `cargo test`, `clippy -D warnings` and `fmt --check` are green.
  - The runtime's `differential` and `evidence_bundle` tests pass with `SEAM_SDK_DIR` pointing at
    this `verify/`, run from the scratch runtime checkout.
- **Tests:** v4 vectors, unknown version → cannot-verify, re-vendored golden chains.

### Phase 4 — Commitment digest v3 plus the self-attestation TCT ×6

- **Status:** DONE.
- **Delivers:** item 10, and item 11 (the commitment vector).
- **Depends on:** Phase 1.
- **Files:**
  - the commitment code in all five crypto modules
  - `ts/src/client.ts`
  - `verify/src/commitment.rs`, `bundle.rs`
  - `conformance/commitment_digest_v3_vector.json`
  - the renamed v3 tests
- **Approach:**
  - Use the v3 framing from the spec.
  - Apply the TCT shape checks, in this order:
    1. the header `typ`;
    2. the signature with the pinned key;
    3. `iss == sub == aud`;
    4. `grants` equals exactly `["aitp.attestation"]`;
    5. `ext` has exactly one key, with exactly `type` and `commitment_digest`, and no duplicate key
       in the raw JSON;
    6. the digest equals the recomputed v3 value.
- **Edge cases:**
  - Empty versus absent `supersedes`.
  - A duplicate JSON key: parsers keep the last value, so detect duplicates explicitly.
  - Uppercase hex.
- **Acceptance:**
  - All three v3 vector cases recompute in ×5 + Rust.
  - The `vectors.json` commitment JWS verifies.
  - A statement placed in `grants`, an extra grant, or `iss != aud` is refused.
- **Tests:**
  - `commitment_digest_v3_vector`
  - `commitment_tct_statement_in_ext`
  - `commitment_tct_grants_must_be_attestation_only`
  - `commitment_tct_iss_ne_aud_refused`
  - `empty_vs_absent_supersedes_differ`

### Phase 5 — Errors, `IssueChallengeRequest`, decision and session ids (Python and TS)

- **Status:** DONE.
- **Delivers:** items 4, 5, 6 and 6a.
- **Depends on:** the regenerated stubs (done).
- **Files:**
  - `python/seam_sdk/errors.py`, `client.py`, `aio.py`, `ids.py` (new), `__init__.py`
  - `ts/src/errors.ts`, `client.ts`, `ids.ts` (new), `index.ts`
  - tests
- **Approach:**
  - **Errors:** the Python accessor is a minimal protobuf reader for `Status`, then `Any`, then
    `ErrorInfo` and `RetryInfo`, using stdlib only. TS uses the `@bufbuild/protobuf` `BinaryReader`.
    The accessors are `reason`, `macp_code` and `retry_after`.
  - **`IssueChallenge`:** sends `IssueChallengeRequest()`.
  - **ids:** `parse_decision_id`, `decision_id_for_session` and `validate_session_id`, each raising
    a typed `ValueError` subclass.
- **Edge cases:**
  - Malformed details bytes yield `None`, never a raise.
  - `macp_code` is present only when `reason == "PROTOCOL"`.
  - A non-`seam.zer07labs.com` domain is ignored.
  - A decision id with an extra colon puts the colon in the session half, which fails P4.
  - A 36-char non-UUID is refused even when it is 22 or more chars of the alphabet.
  - An uppercase UUID is refused.
- **Acceptance:** an error carrying `macp_code` is readable without string matching, and the
  decision-id refusals are typed.
- **Tests:**
  - `protocol_error_exposes_macp_code`
  - `decision_id_parse_refuses_extra_colon`
  - the session-id rule table
  - `issue_challenge_sends_request_message`
  - `retry_after_from_retry_info`

### Phase 6 — Specs, live root, docstrings, fixtures, CI pins, docs

- **Status:** DONE.
- **Delivers:** items 9, 12, 13, 14 and 15, plus the POLICY_DENIED fixture repin.
- **Depends on:** Phases 1–5.
- **Files:**
  - `verify/docs/*.md`
  - `python/tests/governing_root.py`, `test_status_mapping.py`
  - the docstrings
  - `.github/workflows/ci.yml` (`SEAM_RUNTIME_BUILD_REF`, the timeout)
  - `COMPATIBILITY.md`, `CHANGELOG.md`
- **Approach:**
  - Copy the specs whole and add a tracking header.
  - Pin `SEAM_RUNTIME_BUILD_REF=e4c01ad3…` with a 45-minute timeout.
  - Run the live Python and TS suites locally against `seam-grpc` built from the pin.
- **Acceptance:**
  - spec-pin is green against the branch.
  - The live suites pass locally against the branch runtime.
  - The citation guards are green.

## Long-term posture

- One `derived_uuid` primitive per language, shared by `message_id`, `jti` and future derived ids,
  so the next derived id is a call, not a transcription.
- The cannot-verify error is typed, so a future v5 is a new arm plus vectors, not a string match.
- `macp_code` stays an open string. Adding a code requires no SDK release.

## Enterprise concerns

- **Breaking.** Any runtime before the pass rejects these SDKs' `message_id`. CHANGELOG and
  COMPATIBILITY state this loudly, and the release follows the runtime version.
- **Audit.** Records from before v4 can no longer be verified offline by this SDK. Recreated
  environments make that acceptable (owner plan).
- **Security.** The duplicate-key refusal and the exact-grants check stop a TCT with smuggled
  statements.

## Open questions

- **BSR push (cross-repo).** CI's `make generate` pulls `buf.build/zer07labs/seam`, which has no
  branch commit. Until the runtime pushes the release proto, codegen-dependent CI jobs see the old
  proto. This is in the final report as a cross-repo need. We do not write the runtime repo.
- **Integration lane.** It builds the runtime from `SEAM_RUNTIME_BUILD_REF`, so it can run against
  the pin. If it fails only because of the proto source, document that in the PR.

## Plan review

Reviewer (Opus), verdict REVISE; every finding was taken:

1. Session-id rule was stricter than the spec: only a 36-char id that parses as a UUID is judged as
   one. Fixed; `test_ids.py` has the 36-char non-UUID token row.
2. The pinned commitment spec contradicts the vector on the TCT shape. The vector and owner plan B5
   are the source; the stale prose is a cross-repo note.
3. `record_digest_v4` takes 17 positional args in the parity script's order, and `crypto.py` imports
   neither `ids.py` nor `errors.py` (the vector's `decision_id` is `dec:conformance`).
4. Tags 14-17 are strip-checked like 11/12, in Python, TS and Rust.
5. Citations re-pointed in the phase that deleted their target.
6. `test_framing_rationale_is_documented.py` moved to `:v3`, with `:v2` in the deleted-literal check.
7. The bundle-fixture re-capture ran after the commitment v3 / TCT work in `verify/`.
8. `verify/src/wire.rs` and the `verify/` vector readers are in scope.
9. Wire-framing stays `supported: 3` in lockstep (DECISIONS.md).
10. The runtime's `SEAM_SDK_REF` bump is a cross-repo note.
11. The branch merges main rather than rebasing (no force-push); anchors re-checked.
12. The extended file is `conformance/vectors_extended.json` in the runtime's shape; readers and
    README references updated.
