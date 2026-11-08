# BP-8 SDK half — `DecisionRecordView.allocation` (AllocationView)

Branchpoint wave 3, seam-sdk row. Sources: `seam-experiments/plans/branchpoint.md` §BP-8 (origin/main e1565f2;
the presence and growth rules there are normative), `seam-experiments/plans/joint/shared-substrate.md` §J3 train 2,
runtime spec `seam-runtime/docs/specs/branchpoint-allocation.md` (@3645c10f2, #1652, seamd-v0.76.0), board
`../.waves/branchpoint/CHARTER.md`.

## Context

Runtime 0.76.0 (seam-runtime#1652, live on prd and partner) adds `DecisionRecordView.allocation = 13`. It is an
`AllocationView{availability = 1, allocation = 2}`, where `Allocation` has 14 presence-less scalars (tags 1–14) and
the enum `AllocationAvailability` runs from UNSPECIFIED=0 to UNAVAILABLE=6. The runtime has the reader only:
nothing writes the trailer until BP-9, so every live record reads `NOT_RECORDED`. The BSR module already carries
the field, and `make generate` pulls it.

**Main is red because of it.** The contract gate exits 6 in both the `python` and `typescript` jobs. The cause is
24 surface entries in the stubs that `contract/field-manifest.txt` lacks: 14 `Allocation/*` fields,
2 `AllocationView/*` fields, `DecisionRecordView/allocation` and 7 `AllocationAvailability#*` values. Main's push
CI is red (21:40Z), so `release-on-runtime` cannot publish 0.76.0 until this lands. This PR is the decision the
gate demands: the SDK **carries** the field, with a hand-written decoder.

Scope corrections against the resources:
- J3 train 2 bundles AllocationView with `decision_point=`/`allocation_unit=` (J4-a). Those fields are not in the
  BSR yet, so this PR carries **only** the BP-8 surface. J3 AC1 ("each train updates the manifest once") is met
  per runtime train: J4-a's fields will arrive in their own runtime release and get their own manifest diff.
- BP-8 AC6 ("verify/ still verifies a fixture sealed with the trailer") holds by construction. `verify/` never
  decodes commitment plaintext: `ciphertext_digest` is an opaque 32-byte input (`verify/src/verify.rs:811-861`),
  and the bundle path uses the trailer-free `seam-commitment-digest:v3`. AC6 still gets a real fixture, so that
  "by construction" becomes a test.
- The precedent for Go/Java/Kotlin is stubs only. None of them has a hand-written seal or policy decoder, and
  0.73.0 CHANGELOG says they "need nothing". They get regenerated stubs only.
- **CI-cost pass:** half of it already shipped as #336 (push restricted to main, PR cancel-in-progress;
  D-CI-PUSH-MAIN, D-CI-CONCURRENCY). This repo has **no merge queue**: ruleset 20588746 requires `ci-ok` only.
  The memory ledger listing seam-sdk as "Not yet" is stale.
- Version: a feature PR never bumps it. Main is already 0.76.0 via `release-on-runtime`'s chore commit.

## Phases

### P1 — Python `allocation_of` + manifest decision
- **Risk:** complex
- **Status:** DONE (2026-11-08). As planned; also extended `python/tests/test_field_manifest_gate.py`'s enum-name set and UNSPECIFIED pin (it pins every enum the manifest declares), and fixed two PROGRESS.md citations the citation gate refused.
- **Delivers:** `seam_sdk.allocation_of(view) -> Optional[AllocationView]`, frozen DTOs `AllocationView` and
  `Allocation`, the manifest carrying the 24 entries, and contract gate exit 0.
- **Depends on:** nothing.
- **Files:** `python/seam_sdk/_allocation.py` (new), `python/seam_sdk/__init__.py` (import plus an `__all__` group
  after the seal group), the `get_decision` docstrings at `python/seam_sdk/client.py` (~:1140) and
  `python/seam_sdk/aio.py` (~:863), `contract/field-manifest.txt` (via `--write-manifest`, after the decoder
  exists), `python/tests/fixtures/allocation_cases.json` (new, shared with TS), `python/tests/test_allocation.py`
  (new), `python/tests/test_integration.py`.
- **Approach:** mirror `_seal.py` (:73-163) exactly. It is the reviewed precedent for this growth policy, and a
  second, different reading rule for a sibling field would be a trap.
  - The availability name map leaves UNSPECIFIED out on purpose. Anything not in the map, UNSPECIFIED included,
    reads `"UNRECOGNIZED"` (withheld). `"UNRECOGNIZED"` is distinct from the runtime's `"UNAVAILABLE"`. It never
    raises.
  - `allocation_of` returns `None` **iff** `view.HasField("allocation")` is false (a runtime before 0.76.0).
    Otherwise it returns an `AllocationView` for every availability.
  - The payload is read **only** under `RECORDED`. Under every other state `allocation` is `None`, whatever the
    wire carries.
  - Under `RECORDED` with the inner message absent, `allocation` is `None`. This follows the seal precedent:
    absence makes no claim. The proto guarantees "present iff RECORDED", so this case is a runtime defect, not a
    state. Recorded as A-BP8S-1.
  - `Allocation` holds all 14 fields as their proto scalars: `str` for string fields, `float` for
    `allocation_propensity`, and `int` for `budget_bp`, `budget_epoch` and `bucket_version`.
  - Values are **not interpreted.** `mode` stays the raw string with no closed-set mapping: the runtime owns the
    vocabulary (`split`/`holdout`, J4-d adds behaviour), and refusing an unknown mode on a *read* would contradict
    the WITHHELD reading rule. The field docs state the "filled by" column (an empty string or 0 = not yet
    filled, e.g. `unit_digest` and `decision_point` until J4-a).
  - The field docs state the trust standing: chain-bound through `ciphertext_digest` → v4 → chain, not a TCT
    input, not client-verifiable, `verify_decision` does not cover it. They also state clearance (PUBLIC; may read
    `CLEARANCE_DENIED`).
  - Names: `AllocationView` and `Allocation` match the Python precedent, where `SealAttestation` shares the pb
    name. Python `__init__` re-exports only `BallotChoice` from pb (`__init__.py:26`), so nothing collides.
  - Rejected: a flattened single DTO with `availability` plus 14 optional fields. That loses the
    "payload only under RECORDED" shape and diverges from `SealAttestation`.
  - Manifest: run `scripts/check-contract.sh --write-manifest` **only after** the decoder and tests exist, then
    diff it. It must add exactly the 24 lines and remove none.
- **Edge cases:** `get_decision` is gRPC-only, so proto3 JSON's uint64-as-string never reaches this decoder. A
  `-0.0` or NaN `allocation_propensity` passes through **unchanged** (no reinterpretation; the runtime normalizes
  at seal time per the spec's trailer row 6). That is tested in a language-local unit test, because JSON cannot
  carry `-0.0`/NaN reliably. An absent field gives `None`; UNSPECIFIED and unknown integers (7, 99) give `"UNRECOGNIZED"` with
  allocation `None`; RECORDED with an all-default inner message keeps zeros and empty strings verbatim (`SetInParent`)
  and never reads them as absent; a non-RECORDED state with a payload on the wire gives `None`; an f64 boundary value
  passes through unchanged (1.0, 0.0001); a u64 above 2**53 keeps exact `int` precision.
- **Acceptance criteria:**
  1. `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` exits 0.
  2. `git diff contract/field-manifest.txt` is +24 lines, −0, and every added line is one of the listed entries.
  3. `from seam_sdk import allocation_of, AllocationView, Allocation` works, and `__all__` contains all three.
  4. Every table case in `allocation_cases.json` passes. The table covers all 7 stub enum values, unknown 7 and 99,
     absent, RECORDED with a full payload, RECORDED with an empty inner message, RECORDED without the inner
     message, a non-RECORDED state with a payload, and the boundary values (budget 0/10000, `budget_epoch` 2**63,
     empty fields 3/11/14, served == intended).
  5. Both DTOs are frozen: assignment raises `FrozenInstanceError`.
  6. A test iterates every `AllocationAvailability` value in the stub and asserts the decoder never raises.
  7. The integration test asserts `allocation_of(get_decision(...))` is **not None** (unconditionally: CI pulls
     `seamd:main` ≥ 0.76.0, `ci.yml:311`; the seal precedent `test_integration.py:80-82` is also unconditional),
     `.availability == "NOT_RECORDED"` and `.allocation is None`. A skip-on-None would make it pass while
     checking nothing.
  8. Ruff check and format are clean, and the full pytest suite is green, including
     `test_compatibility_citations_resolve.py` after any line shifts.
- **Tests:** `test_allocation.py` (table, frozen, enum sweep, field count = 14 matching the descriptor),
  `test_integration.py` addition.
- **Docs:** the `get_decision` docstrings name `allocation_of`.

### P2 — TS `allocationOf` parity
- **Risk:** complex
- **Status:** DONE (2026-11-08, Opus PASS, 1 round). Divergence: `test_shadowed_names_comment.py` needed no edit,
  because it derives the count word itself; only `ts/src/index.ts` changed.
- **Delivers:** `allocationOf(view): AllocationView | undefined` and readonly interfaces `AllocationView` and
  `Allocation`, exported from the package index. They behave exactly like Python.
- **Depends on:** P1 (shared fixture JSON).
- **Files:** `ts/src/client.ts` (beside `sealAttestationOf`, ~:460-584), `ts/src/index.ts` (the dual-declared names
  comment at :54-80: add `Allocation` and `AllocationView` and update the count word),
  `python/tests/test_shadowed_names_comment.py` (it pins the count word, :93/:246: "SIX" → "EIGHT", plus the
  prose "These six" (~:72) and "The last three differ from the first three" (~:78), where the new names count as
  decoded forms), `ts/tests/allocation.test.ts` (new;
  reads `python/tests/fixtures/allocation_cases.json` the same way `seal_attestation.test.ts:1-6` does),
  `ts/tests/integration.test.ts`.
- **Approach:** same rules as P1. `budgetEpoch` is a `bigint`, because protobuf-es types uint64 as bigint
  (`ts/gen/seam/api/v1/seam_pb.ts:2251`). Narrowing it to `number` would lose precision above 2**53. The JSON
  fixture carries `budget_epoch` as a decimal string, and each language parses it to `int` or `BigInt`, so a
  2**63 value round-trips in both. Availability and mode are string unions or raw strings, as in the seal
  interface.
- **Edge cases:** as P1, plus bigint equality in the fixture comparison and a JS caller passing a non-carrier
  (undefined field), which gives `undefined`.
- **Acceptance criteria:**
  1. `npm run typecheck`, `npm run build` and `npm test` are green in `ts/`.
  2. Every case in the shared fixture passes in TS with the same expected output as Python.
  3. `allocationOf` and both types are exported from the built package entry.
  4. The dual-declared names comment lists both names, says "EIGHT", classifies them correctly in its prose, and
     `test_shadowed_names_comment.py` passes.
  5. The TS integration test asserts NOT_RECORDED on runtime ≥ 0.76.0.
- **Tests:** `allocation.test.ts`, plus the integration addition.
- **Docs:** `getDecision` TSDoc (`client.ts` ~:1705).

### P3 — `verify/` AC6: an allocated evidence bundle verifies
- **Risk:** simple
- **Status:** DONE (2026-11-08, Opus GAPS then PASS on re-verify; comment-only residuals confirmed in the final verify). Divergence: the fixture is a real runtime export at 3645c10f2 (D-BP8S-5), not vendored trailer bytes; its `commitment.json` is byte-identical to `full/`'s, and the distinctness check is on the chained `ciphertext_digest`.
- **Delivers:** `verify/fixtures/evidence-bundle/allocated/`, a real bundle exported by the runtime from a record
  whose commitment carries a 0x02 Allocation trailer, plus a test that `seam-verify bundle` exits 0 on it.
- **Depends on:** nothing. Independent of P1 and P2.
- **Files:** `verify/fixtures/evidence-bundle/allocated/**` (new), `verify/tests/bundle.rs` (provenance paragraph
  in the header and one test).
- **Approach:** follow the existing fixture provenance rule (`verify/tests/bundle.rs:1-33`: no byte hand-invented,
  captured from the runtime's own exporter).
  - Work from a `git archive` export of seam-runtime @3645c10f2 (memory: never the shared checkout).
  - Run `crates/seam-verify/tests/bundle.rs::an_allocated_record_bundle_verifies`, with its temp-dir cleanup
    suppressed in the export only. That test seals through `seamd::testing::reseal_with_allocation`, then exports.
  - Copy the bundle into `verify/fixtures/evidence-bundle/allocated/`.
  - The test asserts exit 0 and the "signed binding ties" line. It also asserts that the fixture is distinct from
    the existing ones: its `DECISION_SEALED` `ciphertext_digest` differs from the `full/` target's, while its
    `commitment_digest` equals the target's (the trailer is not a digest:v3 input).
  - The provenance paragraph states that the record comes from a test-only reseal
    (`seamd::testing::reseal_with_allocation`: a fresh DEK, new id `d3-allocated-000000000`). It also states that
    the runtime test seals `bucket_version: 1` where the spec says 2, which does not matter to `verify/`. And it
    states the one export-only patch: the final `remove_dir_all` was replaced with a printed path.
  - **Pre-checked 2026-11-08:** the bundle captured from the 3645c10f2 export verifies with this repo's
    `seam-verify bundle --issuer <seed 7×32 AID>` (exit 0, "signed binding ties"). Version-refusal risk is
    retired. `verify/` links nothing of Seam's, and that stays
    true.
  - Rejected: vendoring `ALLOCATION_TRAILER_HEX`. That is commitment plaintext, which `verify/` never sees, so the
    test would prove nothing about the verifier.
- **Edge cases / failure modes:**
  - The runtime at 3645c10f2 may emit a bundle shape or TCT `ver` newer than the a853f89 fixtures. If this
    verifier refuses it, that is a **real finding** about verifier currency, not a reason to doctor bytes. Stop
    and report the refusal with the exact error. If the cause is unrelated to the trailer (for example an AITP
    version bump), file it as a blocker per the work-generation policy, and AC6 waits on that fix.
  - If the runtime test has no exporter seam to keep its output, add a minimal export-only patch in the scratch
    export and record the exact patch in the provenance paragraph.
- **Acceptance criteria:**
  1. `cargo test` passes in `verify/`, including the new test.
  2. `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` are clean.
  3. The header names the runtime commit, the test, and any export-only patch.
  4. `verify/Cargo.toml` dependencies are unchanged.
- **Tests:** `allocated_record_bundle_verifies` in `verify/tests/bundle.rs`.

### P4 — Docs, compatibility, changelog
- **Risk:** simple
- **Status:** DONE (2026-11-08, Opus GAPS then PASS, 2 rounds). As planned.
- **Delivers:** user-facing docs for the new decoder.
- **Depends on:** P1 and P2 (the README, COMPATIBILITY and CHANGELOG parts); P3 only for the DECISIONS line on
  AC6.
- **Files:** `README.md` ("Explaining a sealed record", ~:650-668: "two decoders" → three, plus an
  `allocation_of` example), `COMPATIBILITY.md` (a row in the table at :176-188, modelled on the seal row :183:
  requires runtime 0.76.0, *compatible* earlier = `None`/`undefined`, pinned from runtime @3645c10f2),
  `CHANGELOG.md` (an `### Added` entry under `## Unreleased`, plus a note that Go/Java/Kotlin are stubs only),
  `DECISIONS.md` (dated entry D-BP8S-1..: carry the field, WITHHELD rule, raw `mode`, bigint, RECORDED without the
  inner message, AC6 approach).
- **Acceptance criteria:** `test_compatibility_citations_resolve.py` passes, and the README's decoder count matches
  the exports.

### P5 — CI-cost pass (CI config only)
- **Risk:** simple
- **Status:** DONE (2026-11-08). As planned; the PR run's per-job 2vcpu durations are added to `docs/ci-cost.md` before merge (AC3).
- **Delivers:** smaller runners where measurements show no need for 4vcpu; `docs/ci-cost.md` with the measured
  before/after; DECISIONS entries.
- **Depends on:** nothing. It ships in the same PR.
- **Files:** `.github/workflows/ci.yml`, `.github/workflows/registry-drift.yml`,
  `.github/workflows/framework-coinstall.yml`, `docs/ci-cost.md` (new), `DECISIONS.md`. `scripts/test_ci_gate.py`
  pins no runner labels.
- **Measured (2026-10-09..11-08, 1,136 runs):**
  - The repo is public. GitHub-hosted standard minutes are free, and all billed spend is Blacksmith 4vcpu since
    #279 (10-19), about $0.008/min.
  - #336 already cut about 5,770 min to about 3,270 min per 30 days (~$46 → ~$26).
  - Every ci job averages 0.1–1.4 min of real time. The cost comes from 14 jobs each billed at least one minute.
  - Raw data: the session scratchpad `allruns.jsonl` and `jobs/`. The aggregates go into the doc.
- **Approach:**
  - **Runner downsizing (D-CI-RUNNER).** Move every `ci.yml` job except `integration` to
    `blacksmith-2vcpu-ubuntu-2404`, along with `registry-drift` and `framework-coinstall`. `integration` stays on
    4vcpu: it has a cold seamd build path under a 45-minute timeout, which is a measured need. java and kotlin
    (0.6 min average) move. This PR's run records their durations, and a slowdown is accepted and recorded, not
    re-pushed. The pass stays in this PR because the owner's brief says so. It is scoped so it needs no
    measure-and-revert push that would delay the release-unblocking merge. Publish, release, yank and promote workflows are untouched.
  - **Merge-queue path filter (D-CI-PATHS): not adopted, recorded.** The brief's `merge_group.base_sha` filter
    has nothing to attach to, because there is no queue. The PR-event analogue (a `changes` job gating go, java,
    kotlin, verify and verify-msrv) saves about 145 min per 30 days (~4%, ≈$1/mo, less after downsizing). In
    exchange it adds a new required job and skip-means-success logic to `ci-ok`, the gate that `publish.yml:63`
    and `release-on-runtime.yml:177` read by SHA. Python tests read across the whole repo, so the filter could
    never gate the expensive jobs. The cost of complexity in the release gate exceeds the saving. Revisit if a
    merge queue is adopted.
  - Duplicate runs and concurrency are already done by #336. Push-to-main runs are never cancelled, because the
    release gate reads them.
  - **Owner lever, not taken:** reverting #279 (Blacksmith → `ubuntu-latest`) would make non-publish CI $0 on a
    public repo (~$20/mo → $0). #279 was an org-level Blacksmith migration, so this is the owner's call. It gets
    one line in DEFERRED.md and in the report.
- **Acceptance criteria:**
  1. No job in publish, release, yank or promote changes (`git diff --stat` touches none of those files).
  2. `ci-ok`'s `needs` and the required-check set are unchanged.
  3. The PR's CI run is green on the new runners, and the doc records the per-job durations from that run.
  4. `scripts/test_ci_gate.py` passes.
  5. `docs/ci-cost.md` holds the before/after table, and DECISIONS holds D-CI-RUNNER and D-CI-PATHS.

## Long-term posture
- The shape of the public SDK API (`allocation_of`, `AllocationView`, `Allocation`) is an additive public surface.
  It mirrors `SealAttestation`, so it carries no new pattern-debt. Raw-string `mode` keeps J4-d's vocabulary
  growth non-breaking.
- No proto or wire change, so nothing here is a one-way door.
- The manifest diff is the deliberate, recorded decision the gate exists for.

## Enterprise concerns
- Failure domain: read-only decoding. It never raises, so no new error reaches a `get_decision` caller.
  Observability: callers distinguish `UNRECOGNIZED` (upgrade the SDK) from `UNAVAILABLE` (the runtime could not read it: a transient
  fault, where a retry may succeed, or a trailer that runtime cannot decode, which persists until the runtime is
  upgraded; proto ~:1192-1195).
- Rollback: revert the PR. The manifest returns to red on main, which is today's state.
- Release: merging turns main green, so `release-on-runtime` can publish 0.76.0.

## Open questions (decided, pending /reconcile)
- A-BP8S-1: RECORDED without the inner message gives `allocation=None` (seal precedent). Reversible.
- A-BP8S-2: path filter not adopted (numbers above). Reversible.

## Plan review
- **Round 1 (fresh Opus): REVISE, 10 items.** Applied:
  - integration assert made unconditional;
  - shadowed-names count and prose made explicit;
  - UNAVAILABLE semantics corrected;
  - `-0.0`/NaN pass-through cases added;
  - `BallotChoice` caveat added;
  - P3 distinctness assertion and provenance details added, version risk pre-checked live;
  - P4 dependency narrowed;
  - `test_ci_gate` hedge dropped;
  - the gRPC-only note added.
- **Not applied:** "move P5 to a separate PR". The owner's waves brief requires it in the same PR, so P5 is
  instead scoped to need no measure-and-revert push (integration stays on 4vcpu).
- **Round 2:** not needed. Every change was a narrowing or factual correction, and nothing changed structurally.
  Verdict: SOUND.
