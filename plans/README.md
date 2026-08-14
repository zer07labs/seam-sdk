# Build plans

All `seam-sdk` build plans live here, **git-tracked** (unlike `seam-runtime`, where `plans/` is
gitignored scratch). Convention as of 2026-08-14: **active/pending plans sit in `plans/`;
delivered plans move to `plans/archive/`** with a dated delivery-verification note prepended —
verdicts are verified against code in this repo, `seam-runtime`, and `seam-adapters`, never
against a status table alone.

## Active / pending

| Plan | Status |
|---|---|
| `build-agent-ingress.md` | **PENDING** — adapters + partner compose shipped in `seam-adapters` v0.1.0, but the plan's core scenes (Suspended→raise→resume, denied admission), the §B MCP server, §C `StepUsage` wiring, and the public-access DoD remain. See the refresh header in the plan. |
| `consolidation-2026-08-14.md` | **RECORD + BACKLOG** — the 2026-08-14 full-repo review (plan triage, 6-track code review of seam-sdk + the runtime contract boundary), the fixes applied, and the residual backlog. |

## Archived (delivered, verified)

| Plan | Delivered |
|---|---|
| `archive/build-sdk-session-budget.md` | Py + TS incremental session lifecycle + the enterprise-6.2 budget surface (suspend→raise→resume), live-verified against a real `seam-grpc`. Resume later moved to the management plane (rt-D); data-plane `resume_session` is a documented tombstone. *(PR #4.)* |
| `archive/build-sdk-hardening-p110-h3-h4.md` | Typed issuer-mismatch error (P1.10), `SeamAdminClient` with admin/erasure wrappers (H3), `features` on `run_decision` (H4), data-plane parity (H5), `SeamEvents` streaming + the typed-error taxonomy. Bearer model superseded by operator tokens (runtime #175 / SDK PR #16). *(PRs #5/#7/#8, versions 0.1.0→0.3.0.)* |
| `archive/adopt-runtime-2026-07.md` | SDK adoption of the runtime backlog-closeout landing: `verify_party_attestation` wrappers, `verify/` upgraded INTEGRITY→AUTHENTICITY (`chain --issuer`: attestation + digest-v2 recompute), conformance KATs, differential-harness parity. Phase 0 landed runtime-side as the `seam.event.v1` extraction. *(Merged; the #175 bearer residual closed by PR #16.)* |
