# Cross-repo plans — asks `seam-sdk` filed against sibling repos

**Staging area, not the execution home.** Every plan here targets *another* repo. They live in
`seam-sdk` because the work that produced them ran from this checkout and sibling repos are
read-only from here — writing into another repo needs a gate; reading one never does. So the plan
stays where it was written and the target repo *fetches* it, either from a GitHub blob URL or, since
the repos are cloned side by side, straight off disk at
`../seam-sdk/plans/cross-repo/<file>.md`.

Move a plan into its target repo when that repo picks the work up, and leave a pointer here — one
plan, one home.

## Why these exist at all

The W1–W7 workstream ([`../archive/sdk-exec-w1-w7.md`](../archive/sdk-exec-w1-w7.md), PR #51) filed
six asks against `seam-runtime` and put the full detail **in the issue bodies**, writing no local
plan files. That deviated from the convention every other repo in this workspace follows
(`seam-adapters`, `seam-learning`, `seam-connectors` and `seam-runtime` all keep a
`plans/cross-repo/`), and it cost three things: the reasoning was not version-controlled here, it was
not discoverable from `plans/`, and an issue that is edited, closed or transferred takes the record
with it. The convention exists so the **plan** is the durable artifact and the **issue** is the
tracked ask. This directory closes that gap.

## Re-verify the anchors before acting

Every `file:line` in these plans was true when the ask was filed (**2026-08-23**), against
`seam-runtime` at that date. That repo merges frequently — it landed four PRs touching `seam.api.v1`
in the four days before these were written. **Check the anchor before editing anything**, and treat
a moved line as evidence the surrounding design may have moved too.

## The asks

| Plan | Target | Headline | Issue | State (2026-09-03) |
|---|---|---|---|---|
| [`seam-runtime-wire-framing-handshake.md`](seam-runtime-wire-framing-handshake.md) | seam-runtime | Carry `wire_framing_version` in the release dispatch so the SDK can refuse a release it has not adapted to | [#418](https://github.com/zer07labs/seam-runtime/issues/418) | ✅ **done** — landed and CLOSED COMPLETED 2026-08-26; the SDK flipped `runtime_emits_version` to true on 2026-09-03. The latch sat stale for that week, so the gate now also refuses a dispatch that carries the field while the latch reads false. |
| [`seam-runtime-verify-crate-rename.md`](seam-runtime-verify-crate-rename.md) | seam-runtime | Rename `crates/seam-verify` so two crates in one org stop sharing a package name | [#419](https://github.com/zer07labs/seam-runtime/issues/419) | 🟡 **hygiene** — downgraded from blocker; see the plan |
| [`seam-runtime-data-plane-bind-guard.md`](seam-runtime-data-plane-bind-guard.md) | seam-runtime | Give the data plane a `validate_mgmt_bind` equivalent | [#420](https://github.com/zer07labs/seam-runtime/issues/420) | 🔴 **live** |
| [`seam-runtime-evidence-bundle-export.md`](seam-runtime-evidence-bundle-export.md) | seam-runtime | A bearer-scoped evidence bundle — an export, not a cross-tenant read grant | [#421](https://github.com/zer07labs/seam-runtime/issues/421) | 🔴 **live** |
| [`seam-runtime-anchor-feed.md`](seam-runtime-anchor-feed.md) | seam-runtime | Publish a read-only anchor feed; without one no verifier can detect truncation | [#422](https://github.com/zer07labs/seam-runtime/issues/422) | 🔴 **live** — bounds what this SDK is allowed to claim |
| [`seam-runtime-commitment-digest-spec.md`](seam-runtime-commitment-digest-spec.md) | seam-runtime | Write the spec for `seam-commitment-digest:v1` | [#423](https://github.com/zer07labs/seam-runtime/issues/423) | 🔴 **live** |
| [`seam-runtime-acdp-p1a-spec-and-lockstep.md`](seam-runtime-acdp-p1a-spec-and-lockstep.md) | seam-runtime | File the ACDP downstream obligation their own plan says must not be forgotten, and sequence the `sdk-digest-parity` un-pin | [#525](https://github.com/zer07labs/seam-runtime/issues/525) | 🔴 **live** — coordination only; the contract half is already delivered and adopted (seam-sdk#80) |
| [`seam-hub-sdk-install-caveat.md`](seam-hub-sdk-install-caveat.md) | seam | The hub quickstart says `pip install seam-sdk` with no co-installability caveat | [#26](https://github.com/zer07labs/seam/issues/26) | 🔴 **live** — proposed diff attached in full |

## What blocks what

```
#418 (wire_framing_version)  ──►  seam-sdk flips runtime_emits_version to true   [DONE 2026-09-03]
                                  (contract/wire-framing.json — the gate now refuses, not warns)

#422 (anchor feed)           ──►  seam-sdk may claim truncation detection
                                  (guarded today by python/tests/test_retracted_claims.py)

#420 (bind guard)            ──►  #421 (evidence bundle) is worth designing
                                  (an auditor role over an unenforced read path is decoration)

#423 (commitment-digest spec) ─►  any second, independent implementation of that framing
```

`#419` blocks nothing since `seam-sdk` moved to Cloudsmith.

## Asks in other repos (no local plan — the issue body is the whole ask)

Small, self-contained asks that do not warrant a plan file. Listed here so `plans/` remains the one
place to find every outstanding cross-repo need.

| Ask | Target | Issue | State |
|---|---|---|---|
| Point `CLAUDE.md`'s services-table row at `seam-sdk`'s `COMPATIBILITY.md` — a one-line edit, filed rather than made directly per that file's own maintenance rules | `seam` | [#18](https://github.com/zer07labs/seam/issues/18) | 🔴 live |
| Heads-up that `seam-sdk` now probes framework co-installability weekly and will detect when CrewAI's pin is fixed — plus the finding that their `resolution-probe` cannot see it resolve | `seam-adapters` | [#57](https://github.com/zer07labs/seam-adapters/issues/57) | 🔴 live — informational, no action asked |

### Not filed: the upstream CrewAI pin

The root cause of `seam-sdk` [#48](https://github.com/zer07labs/seam-sdk/issues/48) is CrewAI's
`opentelemetry-exporter-otlp-proto-http~=1.42.0`, which cannot reach the release where
`opentelemetry-proto` lifted its own `protobuf<7` cap. That is a **third-party** repo
(`crewAIInc/crewAI`), and the same conflict has been reported there at least three times —
[#4511](https://github.com/crewAIInc/crewAI/issues/4511) asked for precisely this relaxation and was
auto-closed **NOT_PLANNED** by a stale bot after five days; [#4474](https://github.com/crewAIInc/crewAI/issues/4474)
and [#5845](https://github.com/crewAIInc/crewAI/issues/5845) went the same way.

So a fourth issue is unlikely to land on its own. Deliberately **not filed** pending an owner
decision on whether to engage upstream at all, and if so whether as an issue or a one-line PR. The
weekly probe means nothing is lost by waiting: it goes red the day the pin relaxes, whoever relaxes
it.
