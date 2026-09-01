# seam-runtime — file the ACDP downstream obligation, and sequence the `sdk-digest-parity` un-pin

> **Owner:** `seam-runtime`. **Filed by:** `seam-sdk`, 2026-08-31.
> **Issue:** [zer07labs/seam-runtime#525](https://github.com/zer07labs/seam-runtime/issues/525)
> **Source:** `seam-sdk/plans/post-adoption-hardening-and-acdp-readiness.md` (Phase 2 / Phase 9).
> One plan, one home — if you copy this into `seam-runtime`, delete it here and leave a pointer.
> **Anchors were verified on 2026-08-31 against `seam-runtime` `f4e105f` (origin/main) and the spec
> at `3b3d4ae`. Re-verify before editing** — this repo's previous ACDP anchors moved twice in a week.

---

## Read this first: most of the original ask is already delivered

This plan was drafted when ACDP P1a existed only on an unpushed branch, and it asked `seam-runtime`
to publish the four payload encodings and push the contract. **That has all happened.** Filing the
original text would ask for work that is done, so it is restated here as what is actually left.

Delivered, verified on 2026-08-31:

| What | Where | Verified how |
|---|---|---|
| Four `ContextBinding` receipt slots, tags 7–10, sealed into digest v3 | `7c1d16d` — *"populate the four D3 receipt slots in digest v3 (P1a, 0.7.69)"* (#520) | `git log origin/main` |
| P2 `retraction`, tag 11 — served on `ResolveContext`, never sealed | `3b3d4ae` (#523, 0.7.70) | same |
| The encodings published in `docs/specs/seam-event.v1.md` | `3b3d4ae`, +125/−28 vs the SDK's previous pin | `git diff 5d8c177 origin/main -- docs/specs/seam-event.v1.md` |
| The contract pushed to the BSR | `buf.build/zer07labs/seam` | decoded the module's `FileDescriptorSet`: `ContextBinding` carries `content_hash=7`, `receipt_hash=8`, `key_status=9`, `resolved_status=10`, `retraction=11` |

`seam-sdk` has already adopted the spec half — [seam-sdk#80](https://github.com/zer07labs/seam-sdk/pull/80)
refreshed the vendored copy and re-pinned `5d8c177` → `3b3d4ae`.

**Nothing below asks for contract work.** Three things remain, and all three are coordination.

---

## Ask 1 — the downstream obligation was never filed

`seam-runtime`'s own plan states the obligation, twice, in a call-out box:

> ⚠️ **Merging this publishes the contract.** The `contract` job `buf push`es to the BSR on merge
> (`.github/workflows/ci.yml:186-200`). The seam-sdk regeneration is a real downstream obligation —
> it is *not* part of this PR (cross-repo), but **it must be filed, not forgotten**.
>
> — `plans/acdp-p1a-receipt-slots.md:290-291`; the same sentence recurs at `plans/acdp-p2-retraction.md:1009`.

It was not filed. On 2026-08-31,
`gh issue list --repo zer07labs/seam-runtime --search ACDP --state all` returns **nothing
ACDP-related** in any state. The obligation exists only inside a plan file, which is exactly the
"forgotten" the call-out was written to prevent.

This issue is that filing. Nothing more is asked under Ask 1 than that it exist and be tracked.

## Ask 2 — sequence the `sdk-digest-parity` un-pin, don't let it be discovered

`crates/seam-client/examples/*` are deliberately pinned to emit **all-`None`** receipt slots:

> ⚠️ **`crates/seam-client/examples/*` MUST stay all-`None`.** Their output is diffed byte-for-byte
> against `zer07labs/seam-sdk`'s committed `conformance/vectors.json` by the **required**
> `sdk-digest-parity` job (`.github/workflows/ci.yml:299-341`,
> `scripts/sdk-digest-parity.sh:40,51,55`). Populating them turns that job red and is fixable only
> by a coordinated seam-sdk PR — a cross-repo lockstep, which this plan's solo filter excludes.
>
> — `plans/acdp-p1a-receipt-slots.md:103-107`, restated at `:439-441`

That pin is the right call and it is holding. The point of this ask is that **it is a deferral with
no scheduled end.** The moment a sealing site populates a slot for real, a *required* job in
`seam-runtime` goes red, and the only fix lives in another repository.

**What `seam-sdk` asks:** when you intend to un-pin, open the coordinated `seam-sdk` PR **first** and
let it merge, then un-pin. `conformance/vectors.json` is committed here
(`seam-sdk/conformance/vectors.json`), so the SDK side is a small, reviewable diff — but it cannot be
written *after* your required job is already red without leaving `seam-runtime`'s `main` broken in
the interval.

**What `seam-sdk` offers:** tell us the intended populated values and we will land the vectors ahead
of you, on our own schedule, so the un-pin is a one-line change on your side that merges green.

## Ask 3 — a merge-order courtesy on `docs/specs/seam-event.v1.md`

This one is no longer hypothetical; it fired while this plan was being written.

`seam-sdk` vendors your spec verbatim at `verify/docs/seam-event.v1.md` and proves the copy in CI —
`scripts/check_vendored_spec.py:22-38` asserts integrity, reachability and **currency**, and
currency failing is red by owner decision, not a warning (`.github/workflows/ci.yml:517-543`). The
copy had gone stale three times before that gate existed, once shipping a real verifier bug.

So when `7c1d16d` and `3b3d4ae` landed, `spec-pin` went red **on `seam-sdk`'s `main`** — runs
`33457207859` (`fbfff431`) and `33428449877` (`fa32409f`) both failed with exactly
`spec pin` + `ci-ok` — and red on every open pull request in the repo, none of which had touched the
spec. It stayed that way until someone diagnosed it by hand and refreshed the copy.

That is working as designed. The gate is *supposed* to be loud, and `seam-sdk` is not asking you to
soften it or to change your merge order for our convenience.

**The ask is a heads-up, not a gate:** when a PR changes `docs/specs/seam-event.v1.md`, say so where
`seam-sdk` can see it — a line in the PR body, a label, or a `seam-release`-style dispatch. Today
the notification channel *is* our red CI, which arrives with no attribution and looks like a defect
in whichever unrelated PR is in flight. Any of the three costs you one line and turns a diagnosis
into a task.

## What this copy of the spec does and does not claim

Stated here so it is not rediscovered as a discrepancy: `seam-sdk`'s vendored copy documents the
**runtime's event stream**, not the SDK's verifier coverage. `verify/src/verify.rs` does not compute
`context_digest` and does not read any of the four receipt slots. The spec describing them and the
verifier not implementing them are both correct simultaneously; the vendored copy's header now says
so explicitly.

The two vocabularies the slots carry are wire commitments and `seam-sdk` will not re-spell them:
`key_status` is **closed** and PascalCase, `resolved_status` is **open** and lowercase, and both are
byte-identical to what enters the digest preimage. A consumer that case-folds either gets a
different digest and no error.

## Delivers

An `ACDP` tracking issue that exists, a written sequence for the `sdk-digest-parity` un-pin, and a
notification channel for spec changes that is not another repository's red CI.

## Depends on

Nothing. All three asks are coordination on work that has already merged.

## Files (all in `seam-runtime`)

No source file has to change for Asks 1 and 3. Ask 2 touches
`crates/seam-client/examples/*` and `scripts/sdk-digest-parity.sh` **only when you choose to
un-pin** — this ask is about the order in which that happens, not about doing it now.

## Acceptance criteria

1. An ACDP tracking issue exists in `zer07labs/seam-runtime` and is discoverable by
   `gh issue list --search ACDP`.
2. The `sdk-digest-parity` un-pin has a written sequence naming which repo merges first.
3. A PR that changes `docs/specs/seam-event.v1.md` carries some marker `seam-sdk` can watch.

## Tests

None asked of `seam-runtime`. `seam-sdk`'s side is already covered: `scripts/check_vendored_spec.py`
(run in CI as `spec-pin`, against the live runtime through the GitHub API) and the `sdk-digest-parity`
job you already own.

## Scope note

`seam-sdk` wrote this plan and is not editing `seam-runtime`. Regenerating this SDK against tags
7–11 is `seam-sdk`'s own work and is tracked in
`seam-sdk/plans/post-adoption-hardening-and-acdp-readiness.md` (Phase 9); it is deliberately gated
behind that plan's Phase 5, so the contract gate *refuses* and names the new fields rather than
adopting them silently. Today it does not — the SDK regenerated from the BSR with all five new
fields present and every gate stayed green, which is the blindness Phase 5 closes.
