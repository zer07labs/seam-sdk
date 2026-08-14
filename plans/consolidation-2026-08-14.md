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
| `build-agent-ingress` | **PENDING** — MCP server, Suspended/resume + denied-admission scenes, StepUsage wiring, public-access DoD all missing | refreshed in place |

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
version lockstep py==ts==0.7.21 intact.

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

- `build-agent-ingress.md` refreshed scope: §A Suspended/resume + denied-admission example
  scenes, §B MCP server, §C `StepUsage` wiring in adapters, §D public evaluation path (or an
  amended DoD).
- No gradle wrapper in `java/`/`kotlin/` (CI-installed gradle is unpinned; local builds need
  a toolchain). Needs a machine with gradle to generate the wrapper.
- `ErasureRequest.now_millis` unexposed in both erasure wrappers (exposed on
  `enforce_retention`; add on demand).
- seam-adapters: lock still resolves seam-sdk 0.7.9 against an SDK at 0.7.21; unconditional
  editable path source in root `pyproject.toml` documented as applying to partners/CI.
- Differential-harness coverage for issuer *rotation* streams (multi-pin) — the SDK verifier
  now supports it; the harness should pin agreement.
