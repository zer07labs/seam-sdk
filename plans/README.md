# Build plans

All `seam-sdk` build plans — active and delivered — live here, **git-tracked** (unlike
`seam-runtime`, where `plans/` is gitignored scratch and completed plans move to
`docs/plans-archive/`). Everything below is delivered; a new in-flight plan just gets added
here and its row updated when done.

| Plan | Delivered |
|---|---|
| `build-sdk-session-budget.md` | Python + TypeScript incremental session lifecycle + the enterprise-6.2 budget surface (suspend→raise→resume), live-verified against a real `seam-grpc`. *(PR #4; moved here from the seam-runtime archive.)* |
| `build-sdk-hardening-p110-h3-h4.md` | Typed issuer-mismatch error (P1.10), `SeamAdminClient` with admin/erasure wrappers (H3), `features` on `run_decision` (H4), data-plane parity (H5), plus `SeamEvents` streaming + the typed-error taxonomy. Versions 0.1.0→0.3.0. *(PRs #5/#7/#8.)* |
| `adopt-runtime-2026-07.md` | SDK adoption of the runtime backlog-closeout landing (A14 authenticity, CP-09, `verify_party_attestation`): verifier upgraded from integrity to AUTHENTICITY (`--issuer` mode), Phases 0–6. *(Merged; #175 bearer drift flagged as residual.)* |
| `build-agent-ingress.md` | The "no way for an agent to enter a session" finding. Delivered outside this repo: framework adapters shipped as the `seam-adapters` repo (v0.1.0) on SDK 0.7.20. |
