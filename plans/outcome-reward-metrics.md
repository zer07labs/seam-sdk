# Plan: outcome reward / metrics / observed_at on the hand-written clients (Branchpoint BP-2, J3 train 1)

- **Source:** waves `outcome-ingestion` wave 3 brief (`.waves/outcome-ingestion/briefs/seam-sdk-w3.md`);
  `seam-experiments/plans/cross-repo/seam-sdk-branchpoint.md` §Train 1 (BP-2 part) as amended by
  `seam-experiments/plans/joint/shared-substrate.md` §J3 Train 1.
- **Locked to:** the seam-runtime release that ships BP-2c (`seamd::facade::OUTCOME_FIELDS_ACCEPTED = true`,
  advertising `outcome.reward_metrics` + `outcome.observed_at`).
- **Out of scope:** `run_decision(contexts=, context_refs=)` (train 1's other half, not in this wave's brief);
  train 2 (BP-8 / J4-a). Go / Java / Kotlin have no hand-written clients: their generated stubs have carried
  the three fields since 0.71.0 (BP-2a), so they need nothing.

## Ground truth (verified 2026-11-02)

- Proto: `ReportOutcomeRequest.reward = 5` (`optional double`), `.metrics = 6` (`map<string,double>`),
  `.observed_at_millis = 7` (`optional uint64`); `ReportOutcomeResponse.wire_features = 2`;
  `ServerInfoResponse.wire_features = 2` — `seam-runtime/crates/seam-api/proto/seam/api/v1/seam.proto:1302-1360`,
  in the BSR since 0.71.0. `contract/field-manifest.txt:408-410,413,440` already lists them;
  `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` exits 0 on a fresh `make generate`. **No manifest change.**
- Runtime validation (`seamd/src/facade.rs` `validate_outcome_shape`, order: key → gate → finite → count →
  key grammar → record load → `observed_at` window): reward and every metric value finite; ≤ 16 metrics;
  key `^[a-z][a-z0-9_]{0,62}$`; `observed_at_millis ∈ [record.sealed_at, now + 300 000]`; empty `metrics`
  is absent (v1 digest). With the gate off (0.71/0.72) any of the three is refused `INVALID_ARGUMENT`.
- Feature vocabulary: `seam-runtime/docs/specs/wire-features.md` — `outcome.reward_metrics`,
  `outcome.observed_at`; a client sends a gated field only while it is advertised, never probes.
- Current SDK: `python/seam_sdk/client.py:1165` / `aio.py:892` `report_outcome(decision_id, correct,
  verified_by=None, *, idempotency_key, credential, timeout) -> bool`; `server_info()` returns the version
  string only. TS `ts/src/client.ts:1790` `reportOutcome(decisionId, correct, { idempotencyKey, verifiedBy? })`,
  `serverInfo()` → `runtimeVersion`.

## Phases

### P1 — Python: `report_outcome(reward=, metrics=, observed_at=)` + `server_wire_features()`
- **Status:** TODO
- **Delivers:** keyword-only `reward: float | None`, `metrics: Mapping[str, float] | None`,
  `observed_at: datetime | int | None` (aware `datetime`, or integer ms since the epoch) on sync and async
  `report_outcome`; one shared `_check_outcome_fields` mirroring the runtime's shape checks (finite; `bool`
  refused; ≤ 16 keys; key grammar; `observed_at` a non-negative u64, naive `datetime` refused), raising
  `ValueError`/`TypeError` before any RPC. `server_wire_features()` (sync + async) → `tuple[str, ...]` from
  `ServerInfoResponse.wire_features`. Exported constants `WIRE_FEATURE_OUTCOME_REWARD_METRICS`,
  `WIRE_FEATURE_OUTCOME_OBSERVED_AT`, `WIRE_FEATURE_ENROLL_KIND`. Return type of `report_outcome` stays `bool`.
- **Tests:** `python/tests/test_report_outcome_reward.py` — fields on the wire (sync + aio); every invalid
  value refused with nothing sent; an omitting call serializes byte-identically to a pinned golden;
  `metrics={}` is absent on the wire; `server_wire_features` returns the list and sends an empty request.
- **Acceptance:** suite + ruff green; contract gate exits 0.

### P2 — TypeScript parity
- **Status:** TODO
- **Delivers:** `reportOutcome(id, correct, { idempotencyKey, verifiedBy?, reward?, metrics?, observedAt? })`
  (`observedAt: Date | number | bigint`, ms); `checkOutcomeFields` with the same rules and messages;
  `serverWireFeatures()`; exported `WIRE_FEATURE_*` constants.
- **Tests:** `ts/tests/report_outcome_reward.test.ts` — same cases as P1, including the byte-identical golden
  (same hex as Python) and Python/TS parity on the wire bytes for a full request.
- **Acceptance:** `npm run typecheck && npm run build && npm test` green.

### P3 — Docs + compatibility
- **Status:** TODO
- **Delivers:** `CHANGELOG.md` Unreleased entry (incl. the skew hazard: a pre-0.71 runtime silently drops the
  fields; 0.71/0.72 refuse them `INVALID_ARGUMENT`); `COMPATIBILITY.md` row naming the BP-2c runtime release;
  README outcome example if one exists.

## Release sequencing (decision D-W3-1, Opus, medium tier)

The proto does not change in BP-2c, so this PR's CI is green against BSR main today and does not wait on the
runtime merge. But the SDK version is stamped by `release-on-runtime.yml` on *any* runtime tag, so merging
early would ship the new kwargs in a release that is not BP-2c (the brief forbids releasing ahead of it).
Rule: keep the PR open and green; merge only once the runtime BP-2c train PR is merged or green and about to
merge, so the next SDK release is the BP-2c one. If the dispatch fires before this merge lands on a green main
(it refuses on a red/pending main), re-run `release-on-runtime.yml` via `workflow_dispatch` with the version.
If the runtime has not tagged BP-2c when everything else is done, report `blocked` naming exactly that.
