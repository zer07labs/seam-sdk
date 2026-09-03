# seam-runtime — carry `wire_framing_version` in the release dispatch

> **Owner:** `seam-runtime`. **Filed by:** `seam-sdk`, 2026-08-23.
> **Issue:** [zer07labs/seam-runtime#418](https://github.com/zer07labs/seam-runtime/issues/418)
> **Source:** `seam-sdk/plans/archive/sdk-exec-w1-w7.md` (W5.5), PR
> [seam-sdk#51](https://github.com/zer07labs/seam-sdk/pull/51).
> One plan, one home — if you copy this into `seam-runtime`, delete it here and leave a pointer.
> **Anchors were true on 2026-08-23; re-verify before editing.**

---

## Context

`seam-sdk` has **no independent version, by design**. A `seam-runtime` release fires a
`repository_dispatch`; the SDK's `release-on-runtime.yml` stamps both packages to match and tags;
`publish.yml` ships. "One version everywhere."

The consequence is structural: **a runtime wire-framing change automatically triggers an SDK release
whether or not the SDK has adapted to it.** That is not a hypothetical — it is the root cause of the
0.7.17–0.7.19 band. seam-runtime #286 moved the per-call proof-of-possession signature from v1
(`ticket ‖ digest`) to v2 (five length-framed fields). seam-sdk 0.7.17 published **eleven minutes
later**, still signing v1. Every `authorize()` returned `UNAUTHENTICATED: admission ticket is not
valid` while the ticket was fine.

`seam-sdk` has since closed four gates around this — CI-green gating, an npm install gate, a
post-publish registry smoke, cross-language framing coverage. **Every one of them detects the failure
after publication**, and a published version is immutable. None of them prevents it, because the tag
is cut before any of them can have an opinion.

## Delivers

A `wire_framing_version` field on the `seam-release` dispatch payload, so the consumer can refuse a
release it has not adapted to.

## Depends on

Nothing in `seam-runtime` — **and nothing is waiting any more**. The runtime landed the field and
this issue closed COMPLETED on 2026-08-26; `seam-sdk` armed its half on 2026-09-03. Kept as the
record of the ask and of what the SDK now relies on, not as an open request.

## Files (all in `seam-runtime`)

- Whichever workflow fires the `seam-release` `repository_dispatch` at `zer07labs/seam-sdk` —
  add the field to `client_payload`.
- Wherever the current framing version is decided, so the value has one source of truth rather than
  a literal in a workflow.

## Approach

- Current value: **2** (post-#286).
- **Bump it on a change to a crypto framing**: the per-call PoP payload, the pinned-key presentation
  preimage, the commitment digest's field tuple or domain tag, the record digest.
- **Do not bump it for an additive proto field or a new RPC verb.** Those cost the SDK's crypto shims
  nothing — Go/Java/Kotlin carry no generated transport — and conflating the two is what would make
  a framing bump feel routine enough to skip.

## What `seam-sdk` already did

- `contract/wire-framing.json` declares `supported: 2` plus the framing history.
- `release-on-runtime.yml` compares the dispatched value against it and **refuses to tag** on a
  mismatch, before anything is stamped — so a refusal leaves no commit, no tag, nothing published.
  *(This line used to say "before the token is minted" as well. That stopped being true on
  2026-08-24: the step had to move to* after *checkout, because it reads `contract/wire-framing.json`
  out of the repo — where it originally sat, it never once ran its comparison, it just crashed on a
  missing file and failed every release closed. `scripts/test_release_gate.py` now pins the ordering.)*

It could not be armed unilaterally: until the runtime emitted the field, every dispatch would have
looked like a mismatch and halted all releases. So `wire-framing.json` carries a
`runtime_emits_version` latch, which tolerated absent with a loud warning naming this issue.

**DELIVERED.** This landed and the issue closed COMPLETED on 2026-08-26; the SDK flipped the latch on
2026-09-03, so an absent field is now a refusal too. The latch sat stale for that week because nothing
watched it — so the gate additionally refuses a dispatch that *carries* the field while the latch reads
false, which is the one signal that cannot go stale alongside the latch itself.

## Acceptance criteria

1. A `seam-release` dispatch carries `wire_framing_version` in its `client_payload`.
2. The value has a single source of truth in `seam-runtime`, not a literal duplicated per workflow.
3. ~~Comment on this issue when it lands, so `seam-sdk` can flip `runtime_emits_version` to `true` and
   cite the confirmation.~~ **Met** — closed COMPLETED 2026-08-26, latch flipped 2026-09-03.

## Tests

- A release dry-run showing the field present in the payload.
- On the `seam-sdk` side (already implemented): the full truth table over
  (framing version present × latch × trigger type) is exercised by executing the gate's real script —
  absent+unlatched warns and proceeds; matching proceeds; **mismatch refuses**; **absent+latched
  refuses**, with a distinct message on a manual run telling the operator to supply the input rather
  than blaming the runtime; and **a dispatch carrying a framing version while the latch reads false
  refuses as proof the latch is stale**. That last branch is scoped to `repository_dispatch`, since an
  operator-typed value proves nothing about the runtime. *(This entry said "all four branches" until
  2026-09-03; the stale-latch and manual-diagnosis branches are what the SDK added when it armed the
  gate.)*

## Why this one first

From `seam-aegis/plans/exec/seam-sdk.md` W5.5 — the brief that drove the workstream, *not* the
`seam-sdk` plan named in this file's Source line: *"This is the single highest-value item in this
plan. Without it, everything else detects the breakage after publication instead of preventing
it."*
