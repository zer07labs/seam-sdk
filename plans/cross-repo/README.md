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

| Plan | Target | Headline | Issue | State (2026-08-24) |
|---|---|---|---|---|
| [`seam-runtime-wire-framing-handshake.md`](seam-runtime-wire-framing-handshake.md) | seam-runtime | Carry `wire_framing_version` in the release dispatch so the SDK can refuse a release it has not adapted to | [#418](https://github.com/zer07labs/seam-runtime/issues/418) | 🔴 **live** — the SDK half is landed with its latch deliberately **open** (warns, does not refuse) until this lands |
| [`seam-runtime-verify-crate-rename.md`](seam-runtime-verify-crate-rename.md) | seam-runtime | Rename `crates/seam-verify` so two crates in one org stop sharing a package name | [#419](https://github.com/zer07labs/seam-runtime/issues/419) | 🟡 **hygiene** — downgraded from blocker; see the plan |
| [`seam-runtime-data-plane-bind-guard.md`](seam-runtime-data-plane-bind-guard.md) | seam-runtime | Give the data plane a `validate_mgmt_bind` equivalent | [#420](https://github.com/zer07labs/seam-runtime/issues/420) | 🔴 **live** |
| [`seam-runtime-evidence-bundle-export.md`](seam-runtime-evidence-bundle-export.md) | seam-runtime | A bearer-scoped evidence bundle — an export, not a cross-tenant read grant | [#421](https://github.com/zer07labs/seam-runtime/issues/421) | 🔴 **live** |
| [`seam-runtime-anchor-feed.md`](seam-runtime-anchor-feed.md) | seam-runtime | Publish a read-only anchor feed; without one no verifier can detect truncation | [#422](https://github.com/zer07labs/seam-runtime/issues/422) | 🔴 **live** — bounds what this SDK is allowed to claim |
| [`seam-runtime-commitment-digest-spec.md`](seam-runtime-commitment-digest-spec.md) | seam-runtime | Write the spec for `seam-commitment-digest:v1` | [#423](https://github.com/zer07labs/seam-runtime/issues/423) | 🔴 **live** |

## What blocks what

```
#418 (wire_framing_version)  ──►  seam-sdk flips runtime_emits_version to true
                                  (contract/wire-framing.json — until then the gate warns, not refuses)

#422 (anchor feed)           ──►  seam-sdk may claim truncation detection
                                  (guarded today by python/tests/test_retracted_claims.py)

#420 (bind guard)            ──►  #421 (evidence bundle) is worth designing
                                  (an auditor role over an unenforced read path is decoration)

#423 (commitment-digest spec) ─►  any second, independent implementation of that framing
```

`#419` blocks nothing since `seam-sdk` moved to Cloudsmith.
