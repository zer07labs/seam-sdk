# Consolidation — 2026-08-14 full review of seam-sdk + the runtime contract boundary

The record of the 2026-08-14 sweep: plan triage (every claim re-verified against code in
`seam-sdk`, `seam-runtime`, and `seam-adapters` — never against a status table), a six-track
deep review, and the fix wave it produced. Companion to the plan archive notes in
`plans/archive/*` and the refreshed `build-agent-ingress.md`.

## Review tracks

1. **Python SDK** (client/admin/aio/errors/crypto + tests) — plan claims + bug hunt
2. **TypeScript SDK** — plan claims + bug hunt + Py↔TS parity diff
3. **`verify/` + `conformance/`** — authenticity phases, wire parsing, golden/vector drift
4. **Go/Java/Kotlin shims** — vector coverage matrix, cross-language crypto drift (tests actually run)
5. **Runtime contract boundary** — Phase-0 mirror fields, full RPC×SDK coverage matrix, CI/tooling, #175 bearer residual
6. **Agent-ingress delivery** — plan DoD vs what `seam-adapters` actually shipped

## Plan triage outcome

| Plan | Verdict | Action |
|---|---|---|
| `build-sdk-session-budget` | DELIVERED (deviations: raw-pb returns, node:test not vitest) | → `archive/` |
| `build-sdk-hardening-p110-h3-h4` | DELIVERED (residual: grants RPCs unwrapped — fixed below) | → `archive/` |
| `adopt-runtime-2026-07` | DELIVERED Phases 0–5 (+ partial 6); post-archive drift found (AUTHORIZE_EVALUATED) | → `archive/` |
| `build-agent-ingress` | **PENDING** — as of 2026-08-24 the §A scenes and §C `StepUsage` wiring have shipped (seam-adapters PR #42); the §B MCP server (seam-sdk #40) and the §D public-access DoD remain. See the residual backlog below. | refreshed in place |

## Findings and fixes

The code fixes below land in the companion code PR of the same sweep (this PR carries the
plan triage + this record); "fixed" describes that PR's content.

**P1 (all fixed this sweep unless noted):**

| Finding | Where | Fix |
|---|---|---|
| Verifier advisory list missing `AUTHORIZE_EVALUATED` (spec #251) → reproduced false refusal under `--strict`; differential harness had no such case | `verify/src/wire.rs` | advisory classification + tag-23 parse + spec-sync tripwire; differential cases added runtime-side |
| Generated types in public TS signatures unreachable (exports map exposes only `"."`; no schemas re-exported) → `verifyPartyAttestation` unconstructable by consumers | `ts/src/index.ts` | re-export types + schemas used by the public surface |
| Zero timeout/deadline support in TS (incl. destructive `eraseSubject`) | `ts/src/*` | per-call `timeoutMs` with Python-parity defaults |
| `SeamAdmin.RemoveParty`/`PlaceGrant`/`RevokeGrant`/`ListGrants` unwrapped in BOTH SDKs (register without revoke) | `python/seam_sdk/admin.py`, `ts/src/admin.ts` | wrappers added, both languages |
| `KNOWN_KINDS` missing `AUTHORIZE_EVALUATED` (both SDKs) | admin modules | added |
| No `py.typed` → consumers type-check the SDK as `Any` (PEP 561) | `python/` | marker + classifier shipped |
| Go module unversionable (nested module, root-only `vX.Y.Z` tags) | release workflow | also tags `go/vX.Y.Z` |

**P2 (fixed):** error-mapper crash on `code() -> None` + unpicklable `SeamRpcError` (Py);
missing `close()`/AbortSignal/`ProtocolViolationError`/error `name`s + ticket-refresh
adopt-semantics (TS); client-side `budget=32` default → `0` = server default (both);
`DeprecationWarning` on the tombstoned data-plane resume (both); `ack`+`follow` guard +
stream cancel handle + `schema_version > 2` refusal in `verify_streamed_record_digest`
(both); repeatable `--issuer` (key rotation), multi-positional-arg usage error, `--json` on
all error paths, wider audit-entry identity projection (`verify/`); per-language
check-contract probes + STREAM/EVENTS promoted to permanent hard gates (BSR verified to
carry the full surface) + check-contract in the TS CI job + stale CI comments (tooling);
fractional-`exp` truncation parity + `go/README.md` (Go); fixed→ephemeral test ports,
timeout-matrix completeness (Py tests).

**Verified non-issues:** goldens + all shared conformance vectors byte-identical to the
runtime; bearer/#175 drift fully resolved (operator tokens end-to-end, SDK PR #16); no
constant-time gaps in the shims; no fail-open path in `verify/` beyond the P1 above;
version lockstep py==ts intact (the sweep observed 0.7.21; the invariant is the point, not
the number, and it is CI-enforced by `ci.yml`'s `version-lockstep` job).

## Deliberate decisions (recorded, not bugs)

- **Raw-pb lifecycle returns stay.** Both plans promised DTO returns; both SDKs shipped raw
  generated messages, identically, tested, at v0.7.x. A DTO retrofit is now a breaking
  change with no behavioral payoff — revisit only at a major version.
- **Admin plane stays sync-only in Python** (no aio `SeamAdminClient`) — deliberate per
  ad3f3ac; now documented.
- **Go/Java/Kotlin stay crypto shims** (ADR). The "every SDK MUST" prose in the call-sig/JCS
  vectors is scoped to languages with an authorize surface; wiring those vectors is a named
  precondition of any future ergonomic client in these languages.

## Residual backlog (not fixed this sweep)

> **Swept 2026-08-24.** Four of the five bullets below were done or materially misstated. Each is
> retired *in place* with what closed it, rather than deleted — `plans/README.md` calls this file a
> **RECORD + BACKLOG**, and deleting the record loses why the item existed. Retirements are dated and
> cited so a reader can check them without trusting this line.

- **§A and §C RETIRED 2026-08-24; §B and §D still open.** `build-agent-ingress.md` refreshed scope:
  - ~~§A Suspended/resume + denied-admission example scenes~~ — **done** in `seam-adapters` PR #42
    (`9a05a04`, 2026-08-17): `seam-adapters/examples/fraud_budget/` drives a budget breach →
    `SUSPENDED` → `SeamAdminClient.resume_session` → seal, and
    `seam-adapters/examples/fraud_admission_denied/` refuses a never-enrolled identity at Admit.
    Both are self-asserting and wired into that repo's fake and live CI lanes.
  - **§B MCP server — STILL OPEN.** Tracked as seam-sdk
    [#40](https://github.com/zer07labs/seam-sdk/issues/40), deliberately unbuilt: no named customer
    for this surface yet. Note its tool mapping now predates the quorum verbs and needs revisiting.
  - ~~§C `StepUsage` wiring in adapters~~ — **done**, same PR #42.
    `seam-adapters/core/seam_agent_core/session_binder.py:43` defines it and threads it through
    propose/vote/commit; `transport_grpc.py:581-589` translates it to the SDK type at the RPC edge.
  - **§D public evaluation path — STILL OPEN.** `seam-adapters/compose/README.md:12-30` still
    requires a Cloudsmith entitlement and a private image-pull credential, so there is no
    stranger-reachable path.
- ~~No gradle wrapper in `java/`/`kotlin/`~~ — **RETIRED 2026-08-24, both halves.** The wrappers are
  committed and tracked (`cf23722`, PR #39), and both `gradle/wrapper/gradle-wrapper.properties`
  pin `gradle-8.7-bin.zip`. The "CI-installed gradle is unpinned" half is resolved by the same
  change: `.github/workflows/ci.yml`'s java and kotlin jobs invoke `./gradlew`, so the wrapper —
  not an ambient gradle — drives CI too.
- ~~`ErasureRequest.now_millis` unexposed in both erasure wrappers~~ — **RETIRED 2026-08-24.**
  Exposed on all four wrappers, both languages: `python/seam_sdk/admin.py:250-269` and `:271-290`;
  `ts/src/admin.ts:183-194` and `:198-210`. Shipped per `CHANGELOG.md`'s `now_millis` / `nowMillis`
  entry.
- **REWRITTEN 2026-08-24 — the observation holds, two of its clauses did not.** `seam-adapters`'
  lockfile does still resolve an old `seam-sdk` (`seam-adapters/uv.lock:3920-3922`), and that is
  *not* a consumer sitting in a broken band: it is an artifact of the unconditional editable path
  source at `seam-adapters/pyproject.toml:32`, so the lock records a sibling checkout rather than a
  resolved release. Dropped from the original bullet: the SDK version it named (long superseded),
  and the claim that the override is "documented as applying to partners/CI" — upstream has since
  **retracted** that framing at `seam-adapters/pyproject.toml:17-29`. The authoritative current
  statement lives in `build-agent-ingress.md`'s dated retraction block; `COMPATIBILITY.md` §2
  carries the consumer-facing version. Not a seam-sdk defect — recorded here only so the earlier
  wording is not read as still standing.
- ~~Differential-harness coverage for issuer *rotation* streams (multi-pin)~~ — **RETIRED
  2026-08-24, and it was never ours to fix.** The SDK verifier supports multi-pin
  (`verify/src/main.rs:296-298`, repeatable `--issuer`). The harness lives in **seam-runtime**
  (`crates/seam-verify/tests/differential.rs`) and already pins agreement: `two_issuer_attested_stream()`
  at `:177` plus the `rotation-both-issuers` and `rotation-new-issuer-only` cases at `:453-468`,
  landed in `28e26af`.
