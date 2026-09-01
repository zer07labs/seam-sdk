# Build plans

All `seam-sdk` build plans live here, **git-tracked** (unlike `seam-runtime`, where `plans/` is
gitignored scratch). Convention as of 2026-08-14: **active/pending plans sit in `plans/`;
delivered plans move to `plans/archive/`** with a dated delivery-verification note prepended —
verdicts are verified against code in this repo, `seam-runtime`, and `seam-adapters`, never
against a status table alone.

## Active / pending

| Plan | Status |
|---|---|
| `consumer-decoders-and-event-surface.md` | **IN PROGRESS** (2026-09-01) — issues [#87](https://github.com/zer07labs/seam-sdk/issues/87), [#88](https://github.com/zer07labs/seam-sdk/issues/88), [#85](https://github.com/zer07labs/seam-sdk/issues/85). Five phases in three PRs. Phases 1-2 shipped (#92); phases 3-4 are open in [#93](https://github.com/zer07labs/seam-sdk/pull/93) — `policy_enforcement_of` / `policyEnforcementOf`, the presence-aware decoder pair that stops an absent `policy_enforcement` reading as "no policy was enforced". Phase 5 adds `contract/event-field-manifest.txt`, closing the last unmanifested contract surface: 90 `seam.event.v1` fields, compared per language in both directions, exit 8. |
| `gate-blindness-hardening.md` | **DONE** — added here on 2026-09-01, having had no row at all despite being the plan this repo's whole vacuity discipline comes from: a gate whose result is decided by something other than the property it names. Cited by nearly every guard test added since. |
| `post-adoption-hardening-and-acdp-readiness.md` | **DONE** (2026-08-31) — all 10 phases shipped across PRs #79, #80, #81, #82, #83, #84, reconciled, with issue [#85](https://github.com/zer07labs/seam-sdk/issues/85) filed for a flaky required gate found on the way. 10 phases, pressure-tested by two Opus review rounds before any code (see its `## Plan review`). Closes the fail-open residue the last contract adoption left (`SessionStep.collective_outcome` is generated but unreachable safely), shuts the publish-time gencode/floor skew that let `v0.7.43` ship metadata it did not honour, and adds a **field-level** contract manifest so the next additive field cannot regenerate in unwired — the verb-level failure of [#49](https://github.com/zer07labs/seam-sdk/issues/49), one level down. Carries issues [#50](https://github.com/zer07labs/seam-sdk/issues/50), [#52](https://github.com/zer07labs/seam-sdk/issues/52), [#48](https://github.com/zer07labs/seam-sdk/issues/48), [#73](https://github.com/zer07labs/seam-sdk/issues/73), [#76](https://github.com/zer07labs/seam-sdk/issues/76). **Phase 9 (adopt ACDP P1a) is DONE** — the block cleared on 2026-08-31 when the runtime merged the proto (`7c1d16d`) and published the spec (`3b3d4ae`); the SDK re-pinned the vendored copy in #80 and adopted the five fields as declared-not-interpreted. |
| `build-agent-ingress.md` | **PENDING** — narrowed 2026-08-24. The §A core scenes (Suspended→raise→resume, denied admission) and §C `StepUsage` wiring shipped in `seam-adapters` PR #42; what remains is the **§B MCP server** (seam-sdk [#40](https://github.com/zer07labs/seam-sdk/issues/40), deliberately unbuilt — no named customer) and the **§D public-access DoD**. See the refresh header in the plan. |
| `consolidation-2026-08-14.md` | **RECORD + BACKLOG** — the 2026-08-14 full-repo review (plan triage, 6-track code review of seam-sdk + the runtime contract boundary), the fixes applied, and the residual backlog. Backlog swept 2026-08-24: four of five entries retired in place with citations; the survivors are §B/§D of `build-agent-ingress.md`. |

## Cross-repo asks

[`cross-repo/`](cross-repo/) holds plans that target **other** repos — currently seven asks against
`seam-runtime` ([#418–#423](https://github.com/zer07labs/seam-runtime/issues/418) and
[#525](https://github.com/zer07labs/seam-runtime/issues/525)) and one against `seam`
([#26](https://github.com/zer07labs/seam/issues/26)). They live here
because writing into a sibling repo needs a gate and reading one never does: the plan stays where it
was written, and the target repo fetches it. Each is paired with a tracking issue there. See
[`cross-repo/README.md`](cross-repo/README.md) for the index and what blocks what.

## Archived (delivered, verified)

| Plan | Delivered |
|---|---|
| `archive/record-digest-v3.md` | `record_digest_v3` in Python, TypeScript and `verify/` — all three transcribed clean-room from the published spec, agreeing with seam-runtime's fourth implementation on every committed vector. All phases delivered including the 6a/6b streamed arms (`admin.py`/`admin.ts` handle v2 and v3 and refuse anything newer) and the Phase 8 tag-13 divergence. Issue [#56](https://github.com/zer07labs/seam-sdk/issues/56), closed 2026-08-25; archived 2026-08-31 with its delivery verified against this tree. *(PRs #58, #63.)* |
| `archive/authorize-single-canonicalization.md` | Closed the double-canonicalization class in `Authorize`: canonicalization failures are typed `SeamError`s, the SDK's own retry path stops re-deriving, the int and float arms agree by construction, and a caller may supply the canonical bytes so exactly one derivation exists. Issue [#60](https://github.com/zer07labs/seam-sdk/issues/60), closed 2026-08-25. **Delivered 2026-08-25 but never indexed here at all** — the omission was found and fixed on 2026-08-31. *(PR #68.)* |
| `archive/close-out-w1-w7-loose-ends.md` | The loose ends #51 left: `verify/` now **compiled** at its declared MSRV in CI (not merely asserted), the 2026-08-14 residual backlog swept and retired in place with citations, the CrewAI/protobuf finding recorded in `COMPATIBILITY.md` + `DECISIONS.md` and re-derived weekly by a live resolution probe, and the six `seam-runtime` asks given a version-controlled home in `cross-repo/`. *(PR #53.)* |
| `archive/sdk-exec-w1-w7.md` | The W1–W7 exec workstream: one batched contract regeneration (additive, proven under `buf breaking --config FILE`), the release-exposure gates (CI-green gating, npm install gate, registry smoke, cross-language framing coverage, the wire-framing handshake), `COMPATIBILITY.md`, and the digest dual-verify obligation. Cross-repo asks filed as seam-runtime #418–#423 rather than delivered here. *(PR #51.)* |
| `archive/build-sdk-session-budget.md` | Py + TS incremental session lifecycle + the enterprise-6.2 budget surface (suspend→raise→resume), live-verified against a real `seam-grpc`. Resume later moved to the management plane (rt-D); data-plane `resume_session` is a documented tombstone. *(PR #4.)* |
| `archive/build-sdk-hardening-p110-h3-h4.md` | Typed issuer-mismatch error (P1.10), `SeamAdminClient` with admin/erasure wrappers (H3), `features` on `run_decision` (H4), data-plane parity (H5), `SeamEvents` streaming + the typed-error taxonomy. Bearer model superseded by operator tokens (runtime #175 / SDK PR #16). *(PRs #5/#7/#8, versions 0.1.0→0.3.0.)* |
| `archive/adopt-runtime-2026-07.md` | SDK adoption of the runtime backlog-closeout landing: `verify_party_attestation` wrappers, `verify/` upgraded INTEGRITY→AUTHENTICITY (`chain --issuer`: attestation + digest-v2 recompute), conformance KATs, differential-harness parity. Phase 0 landed runtime-side as the `seam.event.v1` extraction. *(Merged; the #175 bearer residual closed by PR #16.)* |
