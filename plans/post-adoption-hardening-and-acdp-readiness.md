# Post-adoption hardening and ACDP P1a readiness

**Issues:** [#50](https://github.com/zer07labs/seam-sdk/issues/50) (close), [#52](https://github.com/zer07labs/seam-sdk/issues/52), [#48](https://github.com/zer07labs/seam-sdk/issues/48), [#73](https://github.com/zer07labs/seam-sdk/issues/73), [#76](https://github.com/zer07labs/seam-sdk/issues/76)
**Repo map / checkpoint trail:** [`PROGRESS.md`](../PROGRESS.md)
**Phases:** 10 — nine READY (one of them a cross-repo filing), one BLOCKED on `seam-runtime`.
**Execution order ≠ numbering:** run **Phase 6 first**, or immediately after Phase 1. It depends on nothing and is the only phase guarding a hazard that fires on every release; see its Sequencing note.

---

## Context

The premise this plan was commissioned under was *"seam-runtime has moved a long way, so the SDK must catch up on the contract."* **That is false, and it was checked rather than assumed.** Volume moved: `origin/main` went `0.7.62 → 0.7.68`. But over the SDK's actual gap — runtime `14dbe62` (the commit `c49d005` adopted) to `origin/main` — `seam.proto` changed by exactly **+6 lines, every one a comment** (`git diff --stat` = `1 file changed, 6 insertions(+)`), and `seam_event.proto` is **byte-identical** (same blob SHA at both ends). No RPC, message, field, or enum value was added. `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` returns **exit 0** against the stubs currently in the tree.

Those six comment lines reserve `ContextBinding` tags 7-10 for ACDP P1a, deliberately as a comment rather than proto3 `reserved` — because `reserved` makes a tag permanently unassignable and protoc would then reject P1a at the moment it used them. **So there is no contract-catch-up work in this plan, and `/implement` must not invent any.** (Two numbers in the commissioning brief were slightly off and are corrected for the record: the SDK's gap is 78 commits, not 270 — 270 measures a wider 30-day window; and the contract bracket is 0.7.62 → 0.7.68.)

What is actually here is three strands, and one insight ties two of them together.

**Strand 1 — the last adoption left a fail-open residue.** Issue #50's own closing checklist is satisfied on every point but one: both verbs are wired in Python and TS, `confidence` correctly maps `None` → field-absent in both languages with real in-process-server tests, and `contract/rpc-manifest.txt` declares both. But `SessionStep.collective_outcome` (proto tag 4), which landed in the *same* runtime commit, is generated and never surfaced. Both safe decoders are typed to `DecisionResponse` only — `python/seam_sdk/_collective.py:83` and `ts/src/client.ts:202`. `submit_commit` returns a `SessionStep`, and per `seam-runtime/crates/seam-api/proto/seam/api/v1/seam.proto:461-465` the field is present only on the commit-terminal step — so the incremental-session caller is precisely the one who needs the safe read and cannot get it. TypeScript is a hard compile block, because protobuf-es brands messages (`ts/gen/seam/api/v1/seam_pb.ts:942`). Python happens to work duck-typed and is therefore accidental, untyped and untested. `_collective.py:1-30` already documents why raw access is unsafe: the field is `optional`, so a naive read of an absent field yields `COLLECTIVE_VERDICT_UNSPECIFIED` (0) and the natural negative test allows on every unrecognised value — the exact inversion the proto's growth policy forbids.

**The insight: this is issue #49's failure, one level down.** `contract/rpc-manifest.txt` exists because a new *verb* could regenerate in and go unwired with CI green throughout — which is what happened to `SubmitApprovalRequest`/`SubmitBallot`. The gate is verb-complete but **field-sparse**: `scripts/check-contract.sh:249-275` set-compares the RPC surface in both directions, while `:228-241` probes exactly four hardcoded field names, all on `seam.event.v1`. A new field on an existing `seam.api.v1` message is invisible to every probe. That is how `collective_outcome` got in unwired — and it is the same hole that would let ACDP's `ContextBinding` tags 7-10 land unnoticed. Fixing the class, not just the instance, is Phase 5.

**Strand 2 — a published wheel's metadata is untrue, and the mechanism that allowed it is still open.** *(State as of planning. Phase 6 closed this and is marked DONE below — in particular "runs no pytest at all" and "install protobuf unconstrained" are no longer true of the python job. Line numbers here were re-derived after that change so they still resolve.)* `v0.7.43` (`ff0139a`, 2026-08-24 02:14:57Z) declares `protobuf>=7.35.1,<8` while bundling protoc **7.36.0** gencode; protobuf's runtime-version check rejects a runtime older than the gencode that produced a file, so a consumer whose closure caps protobuf below 7.36.0 resolves cleanly and then dies at `import seam_sdk`. PR #51 added `publish.yml`'s `ci-green` job 74 minutes later, which closes the path that release took. **It does not close the mechanism.** `publish.yml:316` runs `make generate` *again at publish time*, against unpinned remote plugins (`buf.gen.yaml:29,31,33`), and the python publish job runs no pytest at all — the string `gencode` appears nowhere in `.github/`, `scripts/`, or the `Makefile`. The two checks that look like they would catch it cannot: `publish.yml:390-401` and `registry-smoke` both install protobuf **unconstrained**, so newest-resolves-fine renders the skew invisible, and `publish.yml:511-514` says plainly that `registry-smoke` detects rather than prevents. A fully green release can still ship the identical defect. That is Phase 6.

Three facts decay issue #52's framing and are corrected here rather than restated. Its option (3) is **already satisfied** — tags jump `v0.7.43 → v0.7.47` (0.7.44-46 were never tagged) and `v0.7.47` carries `protobuf>=7.36.0,<8` — so no re-release is owed. Its yank argument rested on the release being *hours* old; it is now seven days, and a workspace-wide search finds **no lockfile anywhere pinning 0.7.43** (`seam-adapters/uv.lock:3920-3922` resolves the SDK as an editable path source, `seam-aegis` has no lockfile, and the only registry-resolved consumer is `seam-control-plane/package-lock.json:1639-1641` on npm at 0.3.0). And the issue names one version where the defect spans **at least four**: `v0.7.40` (2026-08-23T23:10Z) through `v0.7.43` all carry `protobuf>=7.35.1,<8`, all published within roughly three hours against the same unpinned codegen, with the fix landing in `f68572f` (PR #51 — the same PR that added `ci-green`, 74 minutes after `v0.7.43`). **The lower bound is not established by the floor string** — `protobuf>=7.35.1,<8` has been declared continuously since `v0.7.13` (verified per tag with `git show vX:python/pyproject.toml`). What bounds the band is the per-tag *gencode* version, which is not recoverable from this repo because `_gen/` is gitignored. So the honest statement is "at least 0.7.40-0.7.43, and it may reach back further", and Phases 7 and 10 must both say it that way.

**Strand 3 — ACDP P1a is real and imminent, but costs the SDK's digest layer nothing.** The brief said three P1a phases are committed on the runtime's `main`. They are not: they sit on the unmerged branch `feat/acdp-p1a-receipt-slots`. **Runtime Phase 4 is *committed*** — `cda620a` on that branch assigns tags 7-10 and carries real `content_hash`/`receipt_hash`/`key_status`/`resolved_status` fields, replacing the reserving comment. **And as of 2026-08-31T10:17-07:00 runtime Phase 6 — the spec rewrite — is committed too**, at `533f218`, together with the `seam-store` edit that used to sit beside it; that plan now marks its own Phase 6 `Status: DONE` (`seam-runtime/plans/acdp-p1a-receipt-slots.md:358-359`). All six P1a commits are on `feat/acdp-p1a-receipt-slots`, which is **not pushed** — `git ls-remote --heads origin feat/acdp-p1a-receipt-slots` is empty, so nothing is on `origin/main`, nothing is on the BSR, and there is no PR to review yet. The work is done; the *publication* is not. That makes Phase 2's lead time shorter than it looks. More importantly, the four receipt slots are sealed into `context_digest` = `seam.audit.context-provenance.v3` (`seam-runtime/docs/specs/seam-event.v1.md:534-544`, at `533f218`) — a *sub*-digest that `record_digest_v3` consumes as an opaque 32-byte value. The SDK deliberately does not implement it (`python/seam_sdk/crypto.py:606-610`: the sub-digests' *"internal formulas belong to the runtime and to auditors, and are deliberately not reimplemented here"*), and there is no context-binding digest function anywhere in `python/`, `ts/` or `verify/` — verified: `context_digest` appears only as an opaque input (`crypto.py:599,643,677`, `admin.py:141`), never as a formula. **So P1a requires no change to `record_digest_v2`/`v3` in any language, no new `schema_version` dispatch arm, and no `contract/wire-framing.json` bump.** `resolve_context` returns `pb.ContextBinding` directly, so the four fields appear automatically on the next `make generate`.

What P1a *does* create is two dated obligations and one precondition. The obligations: regenerate after runtime Phase 4 merges (its own plan says at `seam-runtime/plans/acdp-p1a-receipt-slots.md:289-291` that the SDK regeneration *"is a real downstream obligation — it is not part of this PR (cross-repo), but it must be filed, not forgotten"*), and refresh the vendored spec after runtime Phase 6 — which will announce itself, because `verify/docs/seam-event.v1.md` is byte-verbatim-pinned and `scripts/check_vendored_spec.py:34-38` fails on staleness by explicit decision, so every seam-sdk PR goes red the moment that section reaches the tracked ref. The precondition is the clean-room one, and **it has already been written — it just has not been published.** At the runtime's `origin/main`, `seam-event.v1.md:581-587` still says the four payload encodings *"are D3's to pin, and one of them is a trap"* — describing what must be stated without stating it — and `:568` still asserts the slots are reserved and absent. At `533f218` on the unpushed branch, both are gone: the slots are stated **filled** (`:569-572`), the versioning rule moved to `:574-578`, and all four encodings are pinned in a table naming the trap (`:586-593`). So Ask A is *"push the branch and merge it"*, not *"please write it"* — a materially cheaper ask. Note what this does **not** unblock: `../seam-runtime/docs/**` is a permitted sibling read, so the encodings are legible here today, but `check_vendored_spec.py`'s currency check runs against the tracked ref's tip, so nothing can be vendored or shipped until `533f218` reaches `origin/main`. **Every `seam-event.v1.md` and `acdp-p1a-receipt-slots.md` line number in this plan is stamped to `533f218` and must be re-verified at filing time — both files have already moved twice under this plan.** **That is what Phase 2 files upstream, early — and the lead time is days, not weeks.**

**Two stale in-repo claims that would have misdirected this work, corrected in Phase 1.** They are **not** in `PROGRESS.md` — that file was already rewritten at planning time, so its old lines 5-6/8/46 no longer exist and citing them would send `/implement` to the wrong file. (1) `plans/README.md:13` still says `record-digest-v3.md` is *"IN PROGRESS — Phases 1–5 delivered … Phase 6 remains BLOCKED"*; the plan body shows Phases 1-8 delivered (6a/6b/7/8 each marked DONE), the blocker explicitly cleared at `plans/archive/record-digest-v3.md:666-669`, and issue #56 closed. (2) `plans/archive/record-digest-v3.md:445-446` still says `COMPATIBILITY.md` §7 is made stale because *"version-block-origination is SDK-first per issue #56"* — that inversion **did not survive**; `COMPATIBILITY.md:337-355` is the settled text: new vectors originate in the runtime, and the sanctioned escape is a separate file, never a new block. Claim (2) is inside the file Phase 1 archives, so archiving it with a dated verification note is the fix; it is recorded here so the note says *why*.

**Baseline.** Working tree is green: **545 passed, 17 skipped** (`python`), **86 passed** across 8 `verify` binaries. Generated stubs are present (`gen/` 246 files, `python/seam_sdk/_gen/` 36, `ts/gen/` 2), so the suites run with no BSR login. The checkout is 5 releases behind `origin/main` (local `3c37532` = v0.7.63; `origin/main` = `ed9227e` = v0.7.68) — Phase 1 syncs. Two facts about that sync, measured rather than assumed: local `3c37532` ("docs: fill in repo-specific CLAUDE.md") is **unpushed**, so `HEAD` is *not* an ancestor of `origin/main` and the branches have diverged 1↔5; and `git diff --stat HEAD origin/main` is **three files** — `CLAUDE.md`, `python/pyproject.toml` and `ts/package.json`, the latter two version stamps only. **So the sync invalidates no line number this plan cites**, and no phase needs to re-derive its anchors after it.

### What this plan deliberately does NOT do

Stated so `/implement` does not invent it:

- **No regeneration for the +6 comment lines.** They have no wire effect; the contract gate is green.
- **No change to `record_digest_v2`/`v3`** in Python, TS or Rust; no new `schema_version` arm at `verify/src/verify.rs:668-674`; no `verify/proto/` change; no `contract/wire-framing.json` bump (its own `_comment` at `:31-33` says a bump is *not* for an additive field or a new verb).
- **No Go/Java/Kotlin work.** They carry no hand-written RPC layer — only crypto shims over generated stubs (`go/crypto/crypto.go`, `java/.../SeamCrypto.java`, `kotlin/.../SeamCrypto.kt`). A new verb or field costs them nothing.
- **No re-release for #52.** `v0.7.47` already carries the corrected floor.
- **No widening of the protobuf floor.** It is derived, not chosen; widening means pinning `buf.gen.yaml`'s remote plugins, which `DECISIONS.md:339-359` records as rejected with a stated re-open trigger ("a second framework becomes incompatible") that has **not** fired — a live probe confirms three of four frameworks resolve today.
- **No populated-slot ACDP conformance vectors.** The SDK cannot author them (no clean-room source until runtime Phase 6) and the runtime will not emit them — its plan pins its example bindings all-`None` specifically to keep `sdk-digest-parity` green (`seam-runtime/plans/acdp-p1a-receipt-slots.md:103-109`, at `533f218`).
- **Never `make clean`.** `Makefile:57-58` deletes all three stub trees and recovery needs a BSR login this session may not hold.

---

## Phases

### Phase 1 — Reset the plan-tracking state to the truth

**Status:** DONE (2026-08-31)

> **Divergence from the planned approach, and it made the phase bigger.** The plan said to give
> `plans/authorize-single-canonicalization.md` a missing index row. Checking it against code rather
> than against the index showed it is fully **delivered** — all five phases `Status: DONE`, issue #60
> closed 2026-08-25 — so an *Active* row would have recorded a falsehood. It was **archived** with its
> own dated delivery-verification note instead, which still satisfies acceptance 3 ("a row that did not
> exist before") and is what `plans/README.md:3-6` actually requires. Consequence worth noting: its
> `crates/**` clean-room wording at what is now `plans/archive/authorize-single-canonicalization.md:429`
> moved into the archive exemption rather than needing a correction, which is why acceptance 5 passes
> against only one edited file (`ASSUMPTIONS.md`) instead of two.

**Delivers:** an accurate `plans/` index and `PROGRESS.md`, a synced checkout, and a clean-room rule that no longer contradicts the build.

**Depends on:** nothing.

**Files:** `plans/README.md`, `plans/record-digest-v3.md` → `plans/archive/record-digest-v3.md`, `PROGRESS.md`, `ASSUMPTIONS.md` (one line — see the clean-room paragraph below), `plans/post-adoption-hardening-and-acdp-readiness.md` (this file's index row).

**Approach.** Sync to `origin/main` first. The branches have **diverged** — local `3c37532` is unpushed and `origin/main` carries 5 release commits — so this is a merge (or a rebase of that one docs commit), not a fast-forward. The whole diff is `CLAUDE.md` + two version stamps, so nothing downstream depends on the result; do it first only so the tree is not stale under later commits. Then verify `plans/record-digest-v3.md` is genuinely delivered **against code, not against its own status table** — `plans/README.md:3-6` requires exactly that for archival, and the whole reason this phase exists is that its status table and `PROGRESS.md`'s header disagree. Concretely: confirm `record_digest_v3` exists in all three languages, that `admin.py`/`admin.ts`'s streamed helpers carry a v3 arm (Phase 6a/6b), that `conformance/vectors.json` holds the `record_digest_v3` block, and that issue #56 is closed. Only then archive with the dated delivery-verification note the convention requires.

`PROGRESS.md` is single-occupant and the handover convention — visible in the previous occupant at `git show HEAD:PROGRESS.md` lines 11-13, and reproduced in the current file at `PROGRESS.md:38-43` — is a wholesale replace plus a blockquote naming the previous plan and an explicit "nothing here carries over"; the old trail is recovered from git history by design. This plan already wrote the new `PROGRESS.md` at planning time, so that half is done; this phase completes the archival half and reconciles the index. Add the previous plan's delivery/archive PR numbers to the blockquote once Phase 1's verification establishes them.

While in `plans/README.md`: it is already missing a row for `plans/authorize-single-canonicalization.md` (on disk, delivered 2026-08-25). Fix that omission in the same edit rather than leaving a known-stale index.

Also correct the two stale claims named in Context, and **tighten the clean-room wording**. `PROGRESS.md` already carries the corrected form (`:9-18`); the over-broad wording survives at **`ASSUMPTIONS.md:343-344`** (*"`../seam-runtime/crates/**` is unreadable under the clean-room constraint"*), which taken literally forbids the `.proto` — directly contradicting `Makefile:29`, where `generate-local` runs `buf generate ../seam-runtime` against the runtime's declared module path `crates/seam-api/proto`. The constraint's real target is the runtime's **Rust**, which is how `verify/DECISIONS.md:113-117` states it (*"never from the runtime's Rust"*). Restate that one line as: Rust sources are never read; `crates/seam-api/proto/**` is the published contract and is read via `buf`. The identical wording in `plans/archive/record-digest-v3.md:36` is **exempt** — it is a historical record of that plan's own constraint and is archived, not maintained. Rejected alternative: leaving it and relying on readers to infer the scope — it has already cost one session a re-litigation, and every future contract-adoption phase pays it again.

**Edge cases & failure modes.** The pull may conflict with the untracked `python/uv.lock` — it is untracked and unreferenced by CI; leave it alone, do not commit it. If delivery verification *fails* on any point, do **not** archive: re-scope `plans/record-digest-v3.md` to the genuine residue, leave it Active, and write the `PROGRESS.md` handover as "parked, not delivered" instead. Rewriting `PROGRESS.md` is destructive of 45KB of trail — it is committed, so git holds it, but confirm a clean tree before overwriting.

**Acceptance criteria.**
1. `git merge-base --is-ancestor origin/main HEAD` succeeds (the release commits are merged in) and `git log --oneline origin/main..HEAD` contains nothing beyond the "docs: fill in repo-specific CLAUDE.md" commit (`3c37532` if merged, a new sha if rebased — the Approach permits either, so match the subject, not the sha), this phase's commit, and at most one merge commit; `git status --short` shows no tracked modifications beyond this phase's.
2. `plans/archive/record-digest-v3.md` exists with a dated delivery-verification note naming what was checked in code; `plans/record-digest-v3.md` no longer exists.
3. `plans/README.md` has: `record-digest-v3` under Archived (its `**Phase 6 remains BLOCKED**` Active row at `:13` gone), an Active row for this plan, and a row for `authorize-single-canonicalization.md` that did not exist before.
4. No file outside `plans/archive/` claims `record-digest-v3` is blocked or in progress, and none claims issue #56 inverted the vector-origination rule.
5. `ASSUMPTIONS.md:343-344` excepts the proto; no file outside `plans/archive/` asserts that `../seam-runtime/crates/**` is never read without that exception.
6. `cd python && .venv/bin/pytest -q` is green (≥545 passed) — `test_retracted_claims.py` scans every `.md` this phase touches.

**Tests.** No new tests. The guard is existing: `python/tests/test_retracted_claims.py:27-30` globs every `*.md` including `plans/`, and `python/tests/test_compatibility_citations_resolve.py` checks every backticked `file:line` in `COMPATIBILITY.md`/`DECISIONS.md`. Run the full Python suite, not a subset.

**Docs.** This phase *is* the doc work. No `seam/` change: `seam/docs/OPEN-TASKS.md:3-8` scopes that file to items with no clean repo home, which this is not.

---

### Phase 2 — Write the ACDP cross-repo asks (**and file them** — restriction lifted mid-run)

**Status:** DONE (2026-08-31) — **both asks written AND FILED.** The scope restriction below was
lifted by the user mid-run ("Go to next phases, file the cross repo - requests"), which reverses this
phase's original "do not file" instruction. Filed as
[seam-runtime#525](https://github.com/zer07labs/seam-runtime/issues/525) and
[seam#26](https://github.com/zer07labs/seam/issues/26). Writing *files* into a sibling repo remains
un-authorized and neither issue did so.

**Divergence from the plan, and it is the substantive one:** Ask A as drafted asked `seam-runtime` to
publish the four payload encodings and push the contract. **That was already delivered** by the time
this phase ran — `7c1d16d` (P1a, #520) and `3b3d4ae` (P2, #523) are on runtime `main`, the spec is
published, and the BSR carries `ContextBinding` tags 7–11 (verified by decoding the module's
`FileDescriptorSet`). Filing the drafted text would have asked for finished work. Ask A was re-scoped
to the three things that *are* outstanding: the tracking issue their own plan says "must be filed,
not forgotten" and which was never filed; sequencing the `sdk-digest-parity` un-pin; and a heads-up
channel for spec changes that is not another repo's red CI.

**SCOPE RESTRICTION — set by the user on 2026-08-31, and it overrides this phase's original shape.** This plan and its implementation touch **`seam-sdk` only**. That means: write the two ask documents, which are `seam-sdk` files under `plans/cross-repo/`, and **do not create issues in `zer07labs/seam-runtime` or `zer07labs/seam`, do not comment on issues there, and do not edit any file outside this repo.** The `/plan` convention treats issue-filing as an unrestricted tracked ask rather than a cross-repo write; that convention is deliberately overridden here. **The consequence is real and must be reported, not buried: nobody upstream learns of these asks, so Phase 9 stays blocked until someone files them by hand.** Record them as un-filed in `PROGRESS.md` so the gap is visible rather than assumed done.

**Delivers:** two written asks, staged in this repo, ready for someone to file verbatim whenever the user chooses to.

**Depends on:** Phase 1 (for the corrected clean-room wording the ask cites).

**Files:** `plans/cross-repo/seam-runtime-acdp-p1a-spec-and-lockstep.md` (new), `plans/cross-repo/seam-hub-sdk-install-caveat.md` (new), `plans/cross-repo/README.md` (the ask table lives here — six rows today, #418-#423), `plans/README.md` (its cross-repo paragraph says "six asks against `seam-runtime`" and must stop being a count that is wrong).

**Approach.** Two asks, written to `plans/cross-repo/` — the established staging area — and **left there unfiled** per the scope restriction above. Each must be self-contained enough that filing it later is a copy-paste, not a re-derivation: state the ask, the evidence, and what the SDK is blocked on, with anchors re-verified at write time.

*Ask A, to `seam-runtime`.* There is **no ACDP tracking issue in that repo at all** today (confirmed: `gh issue list --repo zer07labs/seam-runtime --search ACDP --state all` returns nothing ACDP-related), so the downstream obligation their own plan says "must be filed, not forgotten" is unfiled in both repos. The ask has two parts. (i) Publish the four payload encodings into `docs/specs/seam-event.v1.md` — its runtime Phase 6 — *before or with* the proto merge, not after. **This is now a push-and-merge ask, not an authoring ask**: the rewrite is committed at `533f218` and marked DONE in their own plan, pinning all four encodings in a table (`:586-593`) and naming the trap (`resolved_status` is open and lowercase; applying the PascalCase rule by analogy is a cross-language mismatch). What is missing is publication — the branch is not even pushed to `origin`, so there is no PR, nothing on `origin/main`, and nothing the SDK's `spec-pin` gate can pin against. **Re-verify every `seam-event.v1.md` and `acdp-p1a-receipt-slots.md` anchor immediately before filing** — both moved between this plan's two review rounds, and `:568`/`:570-573`/`:581-587` as quoted are true only at the runtime's `origin/main`, not at `533f218`. (ii) Note that the SDK's `spec-pin` job goes red on every PR the moment that section changes (`scripts/check_vendored_spec.py:22-38`, `.github/workflows/ci.yml:517-543`), so the two repos want a merge-order courtesy. Do **not** cite `COMPATIBILITY.md` for that courtesy: §7 (`:328-364`) documents the coupling in the *other* direction (a merge here hits `seam-runtime`'s CI immediately) and does not describe a spec-side courtesy at all — the ask has to state it, not reference it.

*Ask B, to `seam`.* `seam/docs/sdk/01-base-concepts-and-quickstart.md:110` tells partners plainly `pip install seam-sdk`, and `04-requesting-access.md:14` repeats it, with no mention of the protobuf co-installability constraint that `COMPATIBILITY.md:203-262` documents in this repo. A partner following the hub quickstart alongside CrewAI hits a resolution refusal with no pointer. Draft the doc diff now while the context is held; the edit itself goes through the normal cross-repo gate later.

Rejected alternative: waiting until runtime Phase 4 merges to raise Ask A. That inverts the dependency — the spec is needed *before* the proto so the SDK can transcribe, and raising it after means the SDK is blocked at exactly the moment it is expected to regenerate.

**Edge cases & failure modes.** The runtime branch may be pushed or merged before anyone files these, so each ask must still read correctly post-merge — "publish the encodings now, the SDK is blocked" rather than "publish them first". Anchors into `seam-event.v1.md` and `acdp-p1a-receipt-slots.md` moved twice during this plan's review rounds; re-verify them at write time and stamp which runtime commit each was checked against, because an ask filed later against drifted line numbers is worse than no ask. Do not run `gh issue create` or `gh issue comment` in this phase at all.

**Acceptance criteria.**
1. `plans/cross-repo/seam-runtime-acdp-p1a-spec-and-lockstep.md` exists and carries Delivers / Depends on / Files / Approach / Acceptance criteria / Tests scoped to what `seam-runtime` must do.
2. `plans/cross-repo/seam-hub-sdk-install-caveat.md` exists with the proposed doc text for `seam/docs/sdk/` attached in full.
3. Each ask names the runtime commit its anchors were verified against, and the date.
4. **No issue was created or commented on in any repo, and no file outside `seam-sdk` was written or modified.** Verifiable: `git -C ../seam-runtime status --short` and `git -C ../seam status --short` are unchanged from before the phase.
5. `plans/cross-repo/README.md`'s ask table has a row for each with state **`UNFILED`**, and `plans/README.md`'s cross-repo paragraph no longer says "six".
6. `PROGRESS.md` records both asks as un-filed, so the blocked-ness of Phase 9 is visible rather than assumed handled.

**Tests.** None — this phase writes markdown. The Python suite must still pass because `test_retracted_claims.py` scans the new `.md` files.

**Docs.** The two cross-repo plan files are the deliverable. `seam/docs/sdk/` is flagged for change but not edited here.

---

### Phase 3 — Close the fail-open: `SessionStep.collective_outcome`

**Status:** DONE (2026-08-31) — no divergence. The TS compile error was reproduced before the fix (`TS2345`, exactly as predicted) and the `resp.decisionId ?? ""` coalesce was required, also as predicted.

**Delivers:** a safe, typed, tested read of the commit-terminal step's collective verdict in both Python and TypeScript.

**Depends on:** Phase 1.

**Files:** `python/seam_sdk/_collective.py`, `python/seam_sdk/__init__.py` (if the export surface changes), `ts/src/client.ts`, `ts/src/index.ts`, `python/tests/test_collective_outcome.py`, `ts/tests/collective_outcome.test.ts`, `CHANGELOG.md`.

**Approach.** Widen the accepted input of `collective_outcome_of` (`python/seam_sdk/_collective.py:83`) and `collectiveOutcomeOf` (`ts/src/client.ts:202`) from `DecisionResponse` to a union of `DecisionResponse | SessionStep`, keeping the existing fail-closed *logic* unchanged. This is right because the unsafety being guarded is a property of the *field* — `optional` presence plus an open enum whose zero value is `UNSPECIFIED` — not of the containing message, and the guard is already written correctly once. Duplicating it per message type would create two places for the fail-open inversion to reappear.

TypeScript needs a genuine union, not a loosened annotation: protobuf-es v2 brands messages (`ts/gen/seam/api/v1/seam_pb.ts:942`), so passing a `SessionStep` today is a compile error — **proven, not asserted**: `tsc` reports `TS2345 … Types of property '$typeName' are incompatible. Type '"seam.api.v1.SessionStep"' is not assignable to type '"seam.api.v1.DecisionResponse"'`. That is the whole reason a TS caller has no safe path. A union is the right shape and no overload or generic is needed — branding blocks *assignment*, not a structural read across a union — but **one line of the body must change**: `client.ts:207` passes `resp.decisionId` to `UnknownCollectiveVerdictError(rawValue: number, decisionId: string)` (`client.ts:144-146`), and on a `SessionStep` that property is `decisionId?: string | undefined` (`seam_pb.ts:951`), so the union narrows it to `string | undefined` and the call stops typechecking. Coalesce at the call site (`resp.decisionId ?? ""`); the error message already renders an empty id as `<none>` (`client.ts:149`). Python currently *works* on a `SessionStep` by duck typing (both `HasField` and `decision_id` happen to exist, and `decision_id` is `optional string`, so an absent one reads as `""`) — that is accidental, and the phase's job is to make it contracted and tested rather than to change behaviour.

Document at the call site that the field is present only on the commit-terminal step, per `seam-runtime/crates/seam-api/proto/seam/api/v1/seam.proto:461-465`, so an absent value on a non-terminal step reads as "not yet decided" rather than as a missing feature.

Rejected alternatives: a separate `collective_outcome_of_step` twin (two implementations of one fail-closed rule); surfacing the raw field and documenting the hazard (that is exactly what `_collective.py:1-30` argues against); waiting for a runtime change (the contract is already correct — this is purely an SDK-side surface gap).

**Edge cases & failure modes.** Absent field on a non-terminal step ⇒ `None`/`undefined`, never a fabricated `UNSPECIFIED`. `COLLECTIVE_VERDICT_UNSPECIFIED` explicitly set ⇒ raise/throw, matching the existing `DecisionResponse` behaviour. An unrecognised enum value from a newer runtime ⇒ raise/throw, never a permissive default — this is the inversion the phase exists to prevent. A `SessionStep` from a *non-commit* verb (`submit_proposal`, `submit_vote`) must behave identically to an absent field. `python/seam_sdk/_collective.py` must not grow an import — it is not itself import-light-constrained, but `crypto.py` and `errors.py` are (`python/tests/test_errors_is_import_light.py:87-100`) and this phase must not reach into them.

**Acceptance criteria.**
1. A TypeScript file calling `collectiveOutcomeOf(step)` where `step` is a `SessionStep` returned by `submitCommit` **compiles** — `cd ts && npm run typecheck` passes; it does not today.
2. The Python and TS test suites each contain a `SessionStep` case for: absent ⇒ none; explicit `UNSPECIFIED` ⇒ raises/throws; unknown numeric value ⇒ raises/throws.
3. No behaviour change for `DecisionResponse` — every pre-existing assertion in `python/tests/test_collective_outcome.py` and `ts/tests/collective_outcome.test.ts` still passes unmodified.
4. `CHANGELOG.md`'s `## Unreleased` section names the new capability.
5. `cd python && .venv/bin/pytest -q` green; `cd ts && npm run typecheck && npm test` green.

**Tests.** Extend `python/tests/test_collective_outcome.py` and `ts/tests/collective_outcome.test.ts` with the three `SessionStep` cases above plus a non-commit-verb step. Drive each new failure-path test **red first** (assert it fails before the fix) — the existing suite's convention, and the only way to know a fail-closed test is not vacuous.

**Docs.** `CHANGELOG.md` only. `README.md`'s surface note is Phase 4's.

---

### Phase 4 — Close issue #50: docs true-up and disposition

**Status:** DONE (2026-08-31). **Divergence, in our favour:** the phase's edge case allowed for the BSR probe being impossible without a `buf registry login`. It was possible — the module commit was re-probed (`4bf014bd5b194010b569ec6bbc006d60`), so the README carries a real stamp rather than the fallback disclaimer.

**Delivers:** issue #50 closed against evidence, and the two docs that describe the adopted surface made true.

**Depends on:** Phase 3 (the residue must be fixed before the issue can close).

**Files:** `CHANGELOG.md`, `README.md`.

**Approach.** `README.md:84-97` enumerates the adopted coordination surface and predates this adoption — it omits `SubmitEvaluation`/`SubmitObjection`, `AuthorizeRequest.subjects = 12` and `SessionStep.collective_outcome = 4`, and is dated against an older BSR module commit. Refresh it and re-record the module commit actually probed. Add the `CHANGELOG.md` `## Unreleased` entry that `c49d005` never wrote, covering the two verbs and `subjects` alongside Phase 3's addition.

Then close #50 with a comment that walks its own checklist and says what was found, including the one cosmetic divergence that must **not** be "fixed": the SDK's parameter is `recommendation`, matching the proto field, while the issue text says `evaluation`. `seam-adapters` bridges it positionally and documents the rename as a boundary spelling. Recording that prevents a future reader from "correcting" the SDK to disagree with the contract.

Rejected alternative: closing #50 in Phase 3's commit. The issue's checklist includes docs, and closing an issue whose docs half is unwritten is how the stale `README.md` happened in the first place.

**Edge cases & failure modes.** Re-probing the BSR module commit needs `buf registry login` against a **private** module this session may not hold; the current stubs do not record which commit built them. If the probe is not possible, say so in the blockquote — *"module commit not re-probed on <date>; the surface below is derived from the stubs in the tree"* — rather than restamping `7a28eb9417894fe29e33390bf2eccfaf` as if it had been re-verified. If `gh issue close` lacks scope, post the comment and report that the close is outstanding rather than claiming it. Do not restate issue #50's `confidence` framing verbatim in any doc — it refers to `EvaluationPayload`, which is not in `seam.api.v1` at all; the field is `EvaluationRequest.confidence`.

**Acceptance criteria.**
1. `README.md`'s surface blockquote (`:84-97`, which today names `collective_outcome = 9` on `DecisionResponse` and none of the below) names all three of `SubmitEvaluation`/`SubmitObjection`, `AuthorizeRequest.subjects = 12`, `SessionStep.collective_outcome = 4`, and either a re-probed module commit or an explicit statement that the probe was not possible.
2. `CHANGELOG.md` `## Unreleased` covers the two verbs, `subjects`, and Phase 3.
3. Issue #50 is closed with a comment stating, per checklist item, what was verified and where.
4. Python suite green — `test_retracted_claims.py` reads both edited files.

**Tests.** No new tests; the doc-guards are the test.

**Docs.** `README.md`, `CHANGELOG.md`.

---

### Phase 5 — A field-level contract manifest: fix the class, not the instance

**Status:** DONE (2026-08-31). **Divergence: the manifest is 228 entries, not the planned 223.** The plan's measurement was taken before ACDP P1a/P2 reached the BSR. Both extractors still agree at **223 against the local stub tree** — exactly as planned, all four canaries present, zero diff — but CI regenerates from the BSR on every run and sees **228**. The gate was built at 223, made to **refuse the five real ACDP fields** (exit 6, naming each in both languages, captured verbatim in `PROGRESS.md`), and only then were they adopted with the decision recorded in the manifest header. Committing 223 would have meant knowingly-red CI; adopting silently would have wasted the tripwire. The refusal happened, and it is on the record.

**Delivers:** `check-contract` refuses when a `seam.api.v1` message field appears in the generated stubs that the manifest does not declare — closing the hole that let `collective_outcome` regenerate in unwired, and arming the tripwire for ACDP tags 7-10.

**Depends on:** Phase 3 — a **policy** dependency, not a technical one. The manifest is derived from the generated stubs, which Phase 3 does not touch, so it would be byte-identical either way; the reason to sequence it after is that committing the manifest *blesses* the surface, and blessing `SessionStep.collective_outcome` while it is still unwired is the thing this phase exists to stop.

**Files:** `contract/field-manifest.txt` (new), `scripts/check-contract.sh`, `README.md` (contract-changes section), `python/tests/` (a new guard test), `.github/workflows/ci.yml` only if a new job is added.

**Approach.** Mirror `contract/rpc-manifest.txt` exactly one level down: a committed, machine-written declaration of every `seam.api.v1` message field, set-compared per language in both directions, with a `--write-manifest` escape that makes accepting a new field a one-command, reviewable diff. Both directions matter for the same reason they do for verbs — a field in the stubs but not the manifest means "something landed, decide whether to wire it"; a field in the manifest but not the stubs means "the contract lost something we depend on."

This is the right shape rather than a narrower ACDP-specific probe (an `ACDP=1` flag mirroring `STREAM=1`/`EVENTS=1` at `scripts/check-contract.sh:53`) because the narrow version treats ACDP as special when the actual defect is general: the gate has never watched fields, and that has now cost two unwired surfaces. A per-change probe also has to be remembered each time, which is the property `rpc-manifest.txt` was introduced to remove. The `STREAM=1`/`EVENTS=1` flags stay as they are — they gate *event* fields for a different reason (BSR publication lag) and are not what this replaces.

Scope the manifest to `seam.api.v1`. `seam.event.v1` fields are already covered by probes 2 and 3 and by the vendored-spec gate, and pulling them in would duplicate a gate that fails for different reasons.

**Edge cases & failure modes.** *Churn is the real cost and must be stated, not discovered:* every additive proto field now reddens CI until someone runs `--write-manifest`. That is the same trade already accepted for verbs, and it is the point — but the escape must be one documented command or the gate will be worked around. Measured, the surface is **223 fields over 65 `seam.api.v1` messages** — both extractors below agree on that set exactly, zero diff in either direction — and zero fields were added across the last 78 runtime commits, so the churn rate is low. Derive fields from the generated stubs, not by parsing `.proto` (the stubs are what ships, and `.proto` may not be present). The extraction points mirror `rpcs_python`/`rpcs_ts` (`scripts/check-contract.sh:158-166`): TypeScript from `@generated from field: … <name> = <tag>;` under the enclosing `Message<"seam.api.v1.X">`; Python from each `class X(_message.Message)` and the `<NAME>_FIELD_NUMBER: _ClassVar[int]` lines beneath it in `seam_pb2.pyi`, lowercased — **not** from `__slots__`, for the reason in the first hazard below.

Five hazards. The first two are live in the stubs today, not hypothetical:

- **`__slots__` silently drops keyword-named fields — do not extract from it.** `ResumeRequest.raise` (proto tag 3) and `AdminResumeRequest.raise` (tag 6) are real fields; protobuf-es emits both (`@generated from field: BudgetLimits raise = 3;`), but the `.pyi` generator cannot put a Python keyword in `__slots__` or in an attribute annotation, so it emits only `RAISE_FIELD_NUMBER` and a `**kwargs` catch-all in `__init__`. Measured: `__slots__` yields 221 fields, protobuf-es yields 223, and the two missing entries are exactly those. A `__slots__`-derived manifest is therefore **permanently red on two fields the escape hatch cannot clear** — and, worse for the gate's whole purpose, blind to any future field named `class`, `from`, `import`, `global`, `lambda`, `pass`, `return`, `in`, `is`, `not` or `and`. Extracting from `<NAME>_FIELD_NUMBER: _ClassVar[int]` lowercased is emitted for **every** field including these, and reconciles the two sides to 223 = 223.
- **Synthetic map-entry messages break naive symmetry.** Python's `.pyi` emits `AuthorizeRequest.FeaturesEntry` (`seam_pb2.pyi:106`) and `RunDecisionRequest.FeaturesEntry` (`:163`), each with `key`/`value`; protobuf-es emits **no** type for them (zero `Message<"seam.api.v1.*.*Entry">` in `ts/gen/seam/api/v1/seam_pb.ts`). A Python-derived manifest therefore carries 2 messages × 2 fields TS can never produce ⇒ a permanently red gate. The header rule must exclude them, and keep each `map` field as one entry on its owner (`AuthorizeRequest/features`) — which both extractors do produce. **Exclude by *nesting*, never by the `*Entry` name**: `AuditEntry` is a real top-level `seam.api.v1` message with two fields (`seq`, `decision_id`) that a name filter drops from *both* sides — symmetric, so the gate stays green while going blind to a real message, which is the failure this phase exists to prevent.
- **`--write-manifest` must name its authoritative side.** The RPC escape writes from Python only (`scripts/check-contract.sh:182`) and uses TS purely as the cross-check. Mirror that, and say so in the header — otherwise a TS-only field yields a failure the documented escape cannot clear. That failure is not hypothetical under the wrong extractor: it is exactly what `raise` produces.
- **The manifest records names, not tags or types**, exactly as `rpc-manifest.txt` records names, not signatures. A field *retagged* or *retyped* — a wire-breaking change — is invisible to it. Record that limit in the header so a later reader does not mistake the gate for a wire-compatibility check; `buf breaking` is what covers that.
- Field *removal* is a breaking contract change and must fail loudly rather than being silently rewritten. Handle the no-stubs case the way `check-contract.sh` already does (exit 3, `:88-97`), not by passing vacuously.

Note also that probe 1b already hardcodes two `seam.api.v1` **field** names (`AuthorizeRequest.call_sig`, `RunDecisionRequest.on_behalf_of`, `scripts/check-contract.sh:205-206`). Leave them — they are cheap and they name *why* those two matter — but the manifest subsumes their coverage, so do not add a third.

**Acceptance criteria.**
1. `contract/field-manifest.txt` exists and its header states: the spelling rule, which extractor `--write-manifest` writes from, that the Python side reads `*_FIELD_NUMBER` and **not** `__slots__` (with `raise` named as the reason), the exclusion of *nested* synthetic map-entry messages (and that `AuditEntry` is not one), and that the manifest tracks names only (not tags or types).
2. `scripts/check-contract.sh --write-manifest` regenerates it idempotently: running it twice produces no diff.
3. With the manifest as committed, `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` exits 0 against the current stubs.
4. **Falsifiable negative:** deleting one line from `contract/field-manifest.txt` makes the gate exit non-zero and name that field; adding a fabricated line does the same in the other direction. Both demonstrated in the test.
5. The failure message for a new field names the field and tells the reader to decide before running `--write-manifest`.
6. `scripts/test_ci_gate.py` still passes — if a CI job was added it is in `ci-ok`'s `needs:` (`scripts/test_ci_gate.py:79`) and not added to `ALLOWED_ADVISORY` (`:52`, asserted by the test at `:98`).
7. `README.md`'s contract-changes section documents the manifest and the one-command escape.
8. Both extractors agree: the Python-written manifest set-compares clean against the TypeScript extraction — **223 entries, zero diff in either direction** — with no synthetic map-entry residue on either side, and with `ResumeRequest/raise`, `AdminResumeRequest/raise`, `AuditEntry/seq` and `AuditEntry/decision_id` all present. Any count other than 223 means the extractor is wrong, not the manifest.

**Tests.** A new test in `python/tests/` driving the gate **both ways** against a temporary copy of the stubs — a manifest-missing-a-field case and a manifest-with-a-phantom-field case — plus an anti-vacuity assertion that the manifest is non-empty and covers a known field. Follow `scripts/test_ci_gate.py`'s pattern of executing the real shell rather than reimplementing its logic.

**Docs.** `README.md`. A `DECISIONS.md` entry recording why a whole-surface manifest beat a targeted probe, with `file:line` citations — note every citation there is CI-checked by `python/tests/test_compatibility_citations_resolve.py`.

---

### Phase 6 — Close the publish-time gencode/floor skew

**Status:** DONE (2026-08-31)

> **Divergence 1 — the half-publish fork was settled as option 2 (keep it in-job).** The plan's
> "strictly better" option was a shared validation job both `npm` and `python` `needs:`. It was
> rejected on inspection: the `python` job already builds, smokes, and uploads the *same*
> `dist/*.whl` in one step, so extracting validation would mean **rebuilding** the wheel in the gate
> and introducing a validated-vs-published skew — the exact class of defect this phase removes.
> Recorded in `DECISIONS.md` under "Accepted trade-off", with the reasoning that a half-published
> version is recoverable by a patch release and visible immediately, whereas a false-metadata wheel
> is neither and fails in the consumer's process.
>
> **Divergence 2 — the falsifiable negative found two real defects in this phase's own code, both
> invisible to review.** (a) The ancestry step's first draft ran `git fetch --no-tags --depth=0`,
> which git rejects outright ("depth 0 is not a positive number"); it would have failed every
> publish. (b) The floor step's inner pytest went red while the **step exited 0** — GitHub's implicit
> `bash -e {0}` would have masked how fragile that is, since a step's status is otherwise just its
> last command's, and a red protobuf-floor test followed by a green grpcio one publishes anyway. Both
> new steps now carry an explicit `set -euo pipefail`, and the harness deliberately runs them with a
> plain `bash -c` so removing it goes red. (c) A third, found by the verify gate rather than by me:
> the floor guards **skip** when the generated tree is absent, and pytest exits 0 when everything
> skips — so the step could pass having measured nothing, which is the failure shape it exists to
> remove. It now asserts the stubs are present before invoking pytest, with a test for that case.
>
> **Divergence 3 — this phase broke more citations than it first repointed, and the guard only
> covers two documents.** Inserting into `publish.yml` shifted the needles COMPATIBILITY.md anchors
> for the npm and PyPI registry URLs, and `test_compatibility_citations_resolve.py` caught those. It
> does **not** scan `PROGRESS.md` or this plan, and the 75-line `DECISIONS.md` prepend plus the
> 11-line `COMPATIBILITY.md` paragraph silently invalidated anchors throughout both — including the
> one Phase 7 navigates `COMPATIBILITY.md` by, and one that had come to point at a bare `fi`. The
> verify gate found them; nothing mechanical was watching. It took **three rounds**: repointing by
> hand missed six and re-broke one, the mechanical sweep that replaced it read only explicit
> `path:line` citations and missed four more in the bare `:line` form that inherits its path from
> earlier in the sentence, and only the third round was clean. No count is recorded, in either
> document — each round produced a different one, and keeping the number in two places is how the
> two records came to contradict each other on it. That failure is the finding, not a footnote to it: this is
> exactly the rot the guard's own docstring records happening the day COMPATIBILITY.md was written,
> and the lesson is that the guard's *scope* is the gap — an unchecked document rots the same way,
> just invisibly, and a human repointing by eye rots it again. `PROGRESS.md` and this plan are the
> most-cited unguarded documents in the repo; adding them to the `DOCS` dict is a real candidate,
> deliberately not done here (out of phase scope), and the case for it is now evidence.
>
> Not fixed here, as the plan directed: `ci-green` still executes from `publish.yml` *as it exists on
> the tagged ref*, so it remains only as strong as branch protection. The ancestry check materially
> narrows that but does not close it.

**Delivers:** a green publish gate that actually implies the published wheel's metadata is true.

**Depends on:** nothing (independent of 1-5).

**Sequencing — run this first, or immediately after Phase 1.** It is numbered 6 for readability, not for order. It is the only phase guarding a hazard that is *actively firing*: the release cadence follows the runtime, five tags shipped in the three days to 2026-08-31 (`v0.7.64`-`v0.7.68`), and every one of them went through the same un-re-derived publish path. The declared floor and the emitted gencode are currently **equal** (`pyproject.toml:50` `protobuf>=7.36.0,<8`; `_gen/seam/api/v1/seam_pb2.py:12-18` gencode `7, 36, 0`), so there is **zero headroom** — the very next remote-plugin bump between a green CI run and a publish-time `make generate` reproduces the 0.7.43 defect exactly. Phases 3-5 fix real gaps but none of them is losing ground while it waits.

**Files:** `.github/workflows/publish.yml`, `scripts/test_publish_gate.py`, `COMPATIBILITY.md` (the dependency-floors note), `DECISIONS.md`.

**Approach.** Two guards, because they assert different things and the cheaper one does not subsume the stronger.

*(a) Re-derive after the publish-time regeneration.* `publish.yml:316` runs `make generate` a second time; immediately after it, run the two floor assertions that are pure file reads — `python/tests/test_protobuf_floor.py:72` (`test_the_declared_floor_is_at_least_the_gencode_in_the_generated_stubs`) and `:88` (the cap check). They need only pytest. Mirror for grpcio, noting `python/tests/test_grpcio_floor.py:38` imports `grpc` at module level, so either install grpcio in that job or select the file-only tests.

*(b) Install the wheel at its own declared floor before upload.* Change the pre-upload smoke at `publish.yml:390-401` to `pip install "protobuf==$FLOOR" dist/*.whl`, with `$FLOOR` parsed from `pyproject.toml`, then import. This is the stronger guard and the one whose absence *is* the 0.7.43 story: it asserts the metadata is **true end-to-end** rather than re-checking a derivation. It is feasible today — the current floor 7.36.0 exists on PyPI. Keep the existing unconstrained smoke too; the two answer different questions ("does it work with the newest?" and "does it work at the minimum we promise?").

Also add the branch-ancestry assertion that `version-check` (`publish.yml:150-188`) lacked at planning — it is there now, at `:176`, added by this phase: tags are not branch-scoped and `ci.yml:19` runs on every branch push, so a tag pushed at a green **feature-branch** commit that never reached `main` publishes cleanly today. `git merge-base --is-ancestor "$GITHUB_SHA" origin/main` closes it.

Rejected: pinning `buf.gen.yaml`'s remote plugins for reproducibility. It collides with the already-recorded rejection at `DECISIONS.md:339-359` and freezes the codegen pipeline; (a) and (b) buy reproducibility *of correctness* without that cost.

**Edge cases & failure modes.** If the floor pin is unavailable on the index at publish time, the job must fail loudly rather than fall back to unconstrained (a silent fallback recreates the exact blind spot). `ci-green`'s existing behaviour is sound and must not regress — still-running maps to `pending` (`publish.yml:107`), absent is a refusal (`:143-148`), and one green must not mask one red (`:117-126`); `scripts/test_publish_gate.py` already pins all three. The ancestry check needs `origin/main` fetched in that job — a shallow checkout will fail it spuriously. **This phase makes the half-publish window measurably more likely, and that must be traded deliberately.** `npm` (`publish.yml:189-192`) and `python` (`:282-285`) run in parallel with no cross-gate; guard (b) adds a *new* way for the python job to fail after `npm publish` may already have succeeded, and a half-published version cannot be re-cut at that number. Two ways out, pick one and record it: put the floor-pinned install in a job that both `npm` and `python` `needs:` (strictly better, costs one job and a `needs:` edit that `scripts/test_ci_gate.py:79` will check), or keep it in-job and accept that a half-publish is the *safe* failure relative to shipping a false-metadata wheel. Do not leave it unstated. Also note but do not fix here: `ci-green` executes from `publish.yml` *as it exists on the tagged ref*, so it is only as strong as branch protection — the ancestry check materially narrows that.

**Acceptance criteria.**
1. `publish.yml`'s python job runs a floor re-derivation **after** its `make generate`, and fails the job on mismatch.
2. The pre-upload smoke installs the wheel with protobuf pinned to the wheel's own declared floor and imports `seam_sdk` successfully.
3. `version-check` (or an equivalent gated job) refuses a tag whose commit is not an ancestor of `origin/main`.
4. **Falsifiable negative:** a test drives the new logic red — a stub `pyproject.toml` floor lower than a stub gencode constant must fail the extracted publish step.
5. `scripts/test_publish_gate.py` passes, extended to cover the new steps; the pre-existing `ci-green` race/patience cases still pass unmodified.
6. No workflow calls `buf generate` directly (`python/tests/test_workflows_generate_through_the_makefile.py:43`), and `workflow-guards` stays free of `BUF_TOKEN`/`buf-setup-action`/`make generate` (`scripts/test_ci_gate.py:141`).

**Tests.** Extend `scripts/test_publish_gate.py` in its existing style — extract the new `run:` blocks and drive them against stubbed inputs, including the red case. This runs credential-free in the `workflow-guards` lane.

**Docs.** A `DECISIONS.md` entry: what the mechanism was, why `ci-green` alone did not close it, and why floor-pinned install beats plugin pinning. A line in `COMPATIBILITY.md`'s dependency-floors area noting the publish-time guard.

---

### Phase 7 — `COMPATIBILITY.md` pass: document 0.7.39-0.7.43, cross-link the upstream ask, answer #76

**Status:** DONE (2026-08-31)

> **Divergence 1 — the band is `0.7.39-0.7.43`, and both edges are PROVEN.** The phase as written
> assumed the lower bound was unrecoverable ("per-tag gencode is not recoverable from the repo")
> and told me to hedge it at `≥ 0.7.40` off the publication cluster. I did, and round 1 of the
> verify gate falsified the premise: the evidence is not in the tree but in **CI history**.
> `v0.7.38` is green; `v0.7.39` is the first red on
> `test_the_declared_floor_is_at_least_the_gencode_in_the_generated_stubs`; 0.7.40-0.7.43 are red
> the same way; `f68572f` is green for 0.7.47. The hedge is deleted rather than softened, and the
> plan's *"do not manufacture a start version"* instruction is satisfied in the stronger direction
> — the start is measured, not manufactured. **Five** releases published on red CI, not the one
> issue #52 names.
>
> **Divergence 2 — the plan's "27 tags" is 26** (0.7.22-0.7.25 and 0.7.33 were never tagged). Moot
> for the document, which no longer argues from the floor string's span now that both edges are
> measured, but recorded because the number was wrong in the plan body.
>
> **Divergence 3 — `crewAIInc/crewAI#7103` is a pull request, not an issue**, open since
> 2026-08-24. Linked as a PR, with what its merge would mean — that is the event the row turns on.
>
> **Divergence 4 — the §3 preamble needed amending, and the first amendment was wrong.** Resting
> the disposition on "fails loudly" made load-bearing the exact claim issue #52 disputes (*"the
> silent-skew shape, not a loud one"*, its argument **for** a yank). It now separates silent-at-
> installation from loud-at-use and adds the facts the yank argument lacked. This matters to
> Phase 10, which builds on it.
>
> **Divergence 5 — the phase's own AC2 guard was vacuous.** Adding `"0.7.43"` to the parametrize
> guards nothing (substring check; the string already appeared), so the row could be deleted with
> the suite fully green. Replaced with two guards that bind the row's shape and its contiguity
> with the table — the row as first committed was preceded by a blank line and rendered as literal
> pipes, which no prose review caught.
>
> **Divergence 6 — the issue replies are drafted, not posted.** AC3 and AC4 each have two halves;
> the `COMPATIBILITY.md` half is done. The replies on #48 and #76 are held until the PR exists, so
> they point at a merged paragraph instead of at nothing. Carried into ship, not dropped.

**Delivers:** the known-bad table tells the truth about the whole affected band; #48 points at the upstream PR that actually gates it; #76's asker gets an answer.

**Depends on:** Phase 6 (so the document can say the mechanism is closed, not just the instance).

**Files:** `COMPATIBILITY.md`, `python/tests/test_retracted_claims.py`.

**Approach.** Three edits to one file, batched because they touch adjacent sections and each alone is too small to ship.

*The known-bad band.* Add a §3 row (`COMPATIBILITY.md:130-133`) covering **more than 0.7.43 alone** — the issue names one version, but `protobuf>=7.35.1,<8` was declared continuously from v0.7.13 through v0.7.43 (27 tags), so the floor string does not bound the affected set on its own. What *is* established is the upper end: 0.7.43 demonstrably shipped 7.36.0 gencode under that floor, and the fix landed in `f68572f` for 0.7.47. The lower bound depends on when the emitted gencode first outran the floor, and **per-tag gencode is not recoverable from the repo** — the stubs are gitignored and each wheel's was produced by whatever the unpinned remote plugin emitted that day. What picks 0.7.40 out is not the floor string but the publication cluster: `v0.7.40` (2026-08-23T23:10:18Z) through `v0.7.43` (02:14:57Z) shipped inside about three hours off the same codegen, with a 41-hour gap back to `v0.7.39`. That makes 0.7.40 a defensible *"at least"*, never a proven start. So state the upper bound precisely, hedge the lower bound in `CHANGELOG.md:516-518`'s existing "may reach back further" style, and do not manufacture a start version. State the **narrow, true** condition: resolves cleanly, then raises `VersionError` at `import seam_sdk` only for a consumer whose closure caps protobuf below 7.36.0; a consumer resolving freely gets 7.36.0 and is fine. Root cause: a stale derived floor published past a CI gate that did not yet exist, closed by PR #51. Fixed release: 0.7.47. Add `"0.7.43"` to `python/tests/test_retracted_claims.py:172-176`'s parametrize so the row cannot be silently dropped.

Check — do not reflexively amend — the §3 preamble at `COMPATIBILITY.md:101-128` (written explicitly: alone in a paragraph, a bare `:N` inherits the previous paragraph's path and resolves against the wrong file in silence). Its "Nothing was yanked" disposition stays **true and consistent** under this plan (Phase 10 records a no-delete decision), and this band's defect fails loud at import with a `VersionError` naming both versions, which is the preamble's first rationale limb. Its second limb ("a floor already in wide use") does not literally describe this band; if the row cannot stand on the first limb alone as written, amend the paragraph to distinguish them rather than leaving it to imply an argument it never made.

*#48.* `crewAIInc/crewAI#7103` — the upstream ask that gates this — **is already filed and open**, and neither `COMPATIBILITY.md:227`'s Tracking cell nor issue #48 links it. Add the link and note its state. The §4a verdict itself is correct today and needs no change: a live resolution probe confirms crewai incompatible and langchain / strands-agents / claude-agent-sdk compatible, matching the committed table. Respect the `<!-- PROBE-TABLE: -->` marker at `:221-223` — columns and order are load-bearing and machine-read.

*#76.* The asker wants one thing: what does an adapters × SDK matrix cell *assert*, and what stable identifier should a floating `live-wire` cell record. Write that as a paragraph in §2 and reply on the issue. It is nearly free while the file is open and unblocks a real external waiter.

Rejected: three separate PRs (churn on one heavily-guarded file); or deferring the 0.7.43 row until the yank decision (the row is true and useful in the un-yanked state, which is the state today).

**Edge cases & failure modes.** Do not assert a yank happened — nothing was yanked and Phase 10 records that as the decision. Do not let this edit drift into implying 0.7.13-0.7.19 were yanked either; they were not, and issue #43 is a different question. Resist narrowing the row to 0.7.43 just because the issue title names it: the per-tag floor check (`git show vX:python/pyproject.toml`) covers 27 tags, not four, and it is the publication cluster — not the floor string — that makes 0.7.40 the defensible lower edge. Both facts belong in the row's hedge. Every backticked `file:line` added here is CI-checked (`python/tests/test_compatibility_citations_resolve.py:103`), and the `ANCHORED` needles at `:141-172` must still resolve exactly once within `CITATION_SLACK` — do not reflow paragraphs containing them.

**Acceptance criteria.**
1. ~~`COMPATIBILITY.md` §3 contains a row covering **at least** 0.7.40-0.7.43 … and the "may reach back further" hedge~~ — **superseded, see Divergence 1.** As shipped: §3 contains a row covering **0.7.39-0.7.43** stating the narrow condition, the root cause and 0.7.47 as the fixed release, with **both edges proven from CI history** and no hedge; the §3 preamble reads true alongside it. The original criterion required a hedge that the evidence made false, so meeting it as written would have been the wrong outcome.
2. `python/tests/test_retracted_claims.py` parametrize includes **`"0.7.39"`** (the lower edge — `"0.7.43"` was the original text, changed with the band) and passes. Additionally, because that parametrize is a substring check and cannot fail for a deleted row, two guards bind the row itself: its shape plus fixed release and symptom, and its contiguity with the table.
3. `COMPATIBILITY.md:227`'s crewai Tracking cell links `crewAIInc/crewAI#7103`; issue #48 has a comment doing the same.
4. §2 contains a paragraph defining what a compatibility-matrix cell asserts and what identifier a floating cell records; issue #76 has a reply pointing at it.
5. The `<!-- PROBE-TABLE: -->` block's columns and order are unchanged; `python/tests/test_compatibility_citations_resolve.py` passes.
6. Full Python suite green.

**Tests.** `python/tests/test_retracted_claims.py` (extended parametrize) and `test_compatibility_citations_resolve.py` (unchanged, must stay green). Optionally run `scripts/probe_framework_coinstall.py` to re-confirm §4a before touching the file.

**Docs.** `COMPATIBILITY.md` is the deliverable.

---

### Phase 8 — Issue #73: stop line-anchoring citations into vendored files

**Status:** DONE — the one existing anchor was **converted**, not grandfathered (the phase permitted either). Converting won because Phase 9's regeneration half refreshes that same vendored file again, so grandfathering would have carried a known-doomed anchor straight into the event that dooms it. The converted claim is not merely un-checked: a new line-number-free `QUOTED` mechanism asserts the needle is unique in the target, that `DECISIONS.md` quotes it verbatim, and that the attribution sits within two lines of the quote. That is a **trade, not a superset** — the line-position claim is genuinely dropped, and what is gained is that the document's own words are now checked against the source, which `ANCHORED` never did. Worth taking only because the dropped half is the half that cannot be kept true against a whole-file refresh.

**Delivers:** a recorded rule and a mechanical guard preventing `DECISIONS.md` citations from breaking every time the vendored spec is refreshed.

**Depends on:** Phase 1. **Should land before Phase 9** — but note the ordering claim is weaker than it first looks: under Open question 4's decision to *grandfather* the existing `ANCHORED` entry rather than convert it, Phase 9's spec refresh still drifts that one anchor and still needs a one-line bump. What Phase 8 buys before Phase 9 is that the refresh cannot *add* new anchors while repointing. If you want the ordering to actually prevent the drift, convert that single entry here (Phase 8 acceptance 2 already permits it) instead of grandfathering.

**Files:** `python/tests/test_compatibility_citations_resolve.py`, `DECISIONS.md`.

**Approach.** `verify/docs/seam-event.v1.md` is refreshed **whole-file and verbatim by policy**, so every line number below an upstream edit shifts; the drift has already fired twice (PRs #71 and #72 — pull requests, not issues), each fixed by a zero-information one-line bump. Record the rule — no new line-anchored citations into vendored files; cite the runtime source with a `seam-runtime/` prefix (which the citation test skips when the sibling is not checked out) or cite by a quoted needle — and enforce it with a `VENDORED` set in the citation test alongside the existing `SIBLING_PREFIXES` handling.

Scope deliberately to the *rule plus guard*, not the full mechanism swap. Converting every existing anchored citation to needle-based is a larger change with its own risk, issue #73 has not decided between the shapes, and the value here is stopping the bleeding before Phase 9. Widening `CITATION_SLACK` is explicitly ruled out by the issue and is not on the table.

**Edge cases & failure modes.** The guard must not break the existing `ANCHORED` entry that already points into that file (`test_compatibility_citations_resolve.py:166-170`) — grandfather it explicitly with a comment naming #73, or convert that one entry as part of this phase. The anti-vacuity floor of ≥10 citations per document (`:61-64,:92`) must still hold after any conversion. A needle must occur **exactly once**; the test's own error text says to lengthen the needle rather than relax the assertion, and that guidance must survive.

**Acceptance criteria.**
1. A new citation-test rule fails when a `DECISIONS.md` citation line-anchors into a vendored file, demonstrated by a red-first test.
2. The pre-existing `ANCHORED` entry into `verify/docs/seam-event.v1.md` is either grandfathered with an explicit `#73` comment or converted, and the suite is green either way.
3. `DECISIONS.md` records the rule, why line anchors into verbatim-refreshed files are structurally unstable, and what to do instead.
4. Both documents still carry ≥10 resolving citations.
5. Issue #73 has a comment recording the partial resolution and what remains open.

**Tests.** Extend `python/tests/test_compatibility_citations_resolve.py` with the new rule and a red-first case proving it fires.

**Docs.** `DECISIONS.md`.

---

### Phase 9 — Adopt ACDP P1a **[UNBLOCKED — spec half DONE, regeneration half TODO]**

**Status:** PARTIAL (2026-08-31). **The block is gone.** Both upstream triggers this phase waited on
have fired: `7c1d16d` merged the proto and `3b3d4ae` published the spec, both on runtime `main`, and
the BSR now serves `ContextBinding` tags 7–11.

- **Spec refresh — DONE**, shipped alone as [#80](https://github.com/zer07labs/seam-sdk/pull/80) per
  this phase's own "the two triggers are independent and each is separately shippable". It had become
  urgent rather than optional: `spec-pin` was red on `main` itself and on every open PR until it
  landed. Re-pinned `5d8c177` → `3b3d4ae`, whole-file and byte-verbatim; the `DECISIONS.md` citation
  into the copy was repointed in the same commit.
- **Regeneration — TODO**, and deliberately still gated behind Phase 5. Regenerating now would adopt
  five new fields silently: CI already regenerates from the BSR every run and every gate stayed green
  across #79 and #80 with all five present. That blindness *is* Phase 5's subject, so the manifest
  lands first and the contract gate then refuses and names them.

**Delivers:** the SDK regenerated against `ContextBinding` tags 7-10, with the vendored spec refreshed and citations repointed.

**Depends on:** Phase 5 (its manifest is the tripwire that fires here), Phase 8 (the citation rule), and the two upstream merges. Do **not** start it early — the fields are committed on `feat/acdp-p1a-receipt-slots` (`cda620a`), and so is the spec (`533f218`), but the branch is unpushed: neither exists on `origin/main` or the BSR, `make generate` reads the BSR, and `check_vendored_spec.py`'s currency check reads the tracked ref's tip.

**Files:** `verify/docs/seam-event.v1.md`, `DECISIONS.md`, `contract/field-manifest.txt`, `python/seam_sdk/_gen/**` and `ts/gen/**` (regenerated, gitignored), `CHANGELOG.md`, `COMPATIBILITY.md` if the surface note moves.

**Approach.** Two independent triggers, either of which may fire first; handle whichever arrives.

*Spec refresh (runtime Phase 6).* `spec-pin` announces it — `scripts/check_vendored_spec.py:22-38` asserts integrity, reachability and currency, and the currency check (`:34-38`) fails on staleness by design, so the job goes red on every PR until `verify/docs/seam-event.v1.md` is refreshed byte-verbatim. Refresh whole-file, re-pin the header commit, and repoint any `DECISIONS.md` citation into that file **in the same commit** or the Python suite goes red. An off-default-branch pin must be declared in the header or the checker refuses it.

*Regeneration (runtime Phase 4).* `make generate` from the BSR, then `STREAM=1 EVENTS=1 make check-contract` — which, thanks to Phase 5, now **refuses**, naming four fields that the manifest does not declare. That refusal is the deliverable working: decide the surface, then `--write-manifest` and commit the diff alongside. Re-run the floor tests, because regeneration can outrun the dependency floors; raise the floor if it moved, never relax the test. Then all five language builds.

No hand-written wrapper change is expected: `resolve_context` returns `pb.ContextBinding` directly, so the four fields appear on the generated type. If a wrapper turns out to be warranted, the two vocabulary traps are one-way in effect and must be carried **verbatim** — `key_status` is a closed PascalCase vocabulary, `resolved_status` is an open lowercase one, and both are byte-identical to the `context_digest` preimage, so any SDK-side re-spelling breaks third-party digest recomputation.

**Edge cases & failure modes.** If the proto merges *before* the spec publishes, the SDK can regenerate but must not transcribe any payload semantics — regenerate, wire nothing that depends on the encodings, and say so. Never normalise, case-fold or map either status vocabulary. Regeneration may raise the protobuf/grpcio floors as a side effect (unpinned remote plugins) — that is expected, and Phase 6's publish guard is what makes it safe. `make clean` is forbidden. If `spec-pin` reddens while the BSR is not yet pushed, do the spec half alone; the two triggers are independent and each is separately shippable.

**Acceptance criteria.**
1. `verify/docs/seam-event.v1.md` is byte-identical to the runtime spec at its declared pin, and `scripts/check_vendored_spec.py` passes all three of integrity, reachability and currency.
2. Every `DECISIONS.md` citation still resolves (`python/tests/test_compatibility_citations_resolve.py` green).
3. `STREAM=1 EVENTS=1 make check-contract` exits 0 after the manifest is updated — and the gate's **pre-update failing output**, naming the new fields, is pasted verbatim into `PROGRESS.md`'s phase log and the PR body. (A commit does not record an exit code; the pasted output is what a reviewer can actually check.)
4. `contract/field-manifest.txt`'s diff is additive only, contains the four `ContextBinding` fields, and every *other* added line is named and accounted for in the phase log — the BSR module may have moved for unrelated reasons between now and then, and an unexplained extra is the finding, not a failure.
5. Floor tests pass against the regenerated stubs; if a floor moved, `pyproject.toml` was raised, not the test relaxed.
6. Python, TS, Go, Java, Kotlin and `verify` suites all green.
7. `CHANGELOG.md` `## Unreleased` records the adoption.

**Tests.** No new digest tests — the SDK does not implement `context_digest`. Coverage is the existing conformance suites plus the contract gate's negative case.

**Docs.** `CHANGELOG.md`, `DECISIONS.md`, and `verify/docs/seam-event.v1.md` (refresh, not authored).

---

### Phase 10 — Record the 0.7.39-0.7.43 disposition and fix `yank.yml`'s token handling

**Status:** DONE (2026-08-31)

> **Divergence 1 — the band is the proven `0.7.39-0.7.43`, not "at least 0.7.40".** AC2 asked this
> entry to record the lower bound as unrecoverable because `_gen/` is gitignored. Phase 7's verify
> gate falsified that premise (the evidence is in CI history, not the tree), so the entry records
> five proven releases and no hedge. AC2 as written is superseded; the substance it wanted — the
> band, why the bound is what it is, and the lockfile check with its date — is all present.
>
> **Divergence 2 — the entry argues with #52 rather than around it.** The plan's four evidence
> lines all pointed one way, and one of them ("no consumer has it locked") is a fact #52 deploys
> in the *opposite* direction: with nothing locked, it argued, the blast radius of yanking is
> small. The entry now states #52's case in its own words — including its crux, that untrue
> metadata is worse than an honestly broken wheel — and answers both, rather than presenting a
> contested fact as settled.
>
> **Divergence 3 — a guard was added where the plan said "if cheap".** `scripts/test_yank_gate.py`
> (12 tests) *executes* the credential resolution rather than reading it, and pins the three
> filters that scope the deletion. It earned its place: the first draft of the fix copied
> `publish.yml`'s `&&` one-liner, which behaves differently under this workflow's
> `set -euo pipefail`. It runs in `workflow-guards` — an existing job, so `ci-ok`'s `needs:` is
> unchanged — and needs no credential.
>
> **Held to, exactly as instructed:** no workflow was dispatched and nothing was deleted from any
> registry. The scoping filters are byte-unchanged.

**Delivers:** the no-delete decision written down with its reasoning, so it stops being re-litigated; and a `yank.yml` that would actually authenticate if it is ever needed.

**Depends on:** Phase 7 (which writes the row this decision justifies).

**Files:** `DECISIONS.md`, `.github/workflows/yank.yml`.

**Approach.** This phase was scoped as a one-way door and analysed as one — deleting a published artifact is irreversible, and `yank.yml:91-92` is a hard `DELETE`, not a PyPI-style yank that leaves the version installable by exact pin. **The analysis settled it, so it drops to a decision to record rather than a gate to hold.** Four lines of evidence all point the same way:

- **The precedent covers a milder defect than the ones it already left installable.** `COMPATIBILITY.md:101-128` and `CHANGELOG.md:523-528` record "nothing was yanked" for versions that failed *harder*: 0.7.13-0.7.15 were unimportable for everyone, and 0.7.16-0.7.19 failed every `authorize()` with an actively misleading "admission ticket is not valid" when the ticket was fine. This band breaks only consumers who cap protobuf below 7.36.0, and fails with a `VersionError` that names both versions — self-diagnosing, not misleading. Documenting the worse defects while deleting the milder one inverts the precedent.
- **No consumer has it locked.** Verified across the workspace: no `uv.lock`, `package-lock.json` or constraint anywhere pins 0.7.43. The seam-adapters matches are prose about a roster claim, not a dependency.
- **Deletion would destroy a healthy artifact.** The defect is Python-only — 0.7.43's `ts/package.json` depends on `@bufbuild/protobuf ^2.12.1`, and protobuf-es has no analog of Python's gencode/runtime hard gate — but `yank.yml:73-76` deletes python **and** npm together with no format input. Running it as written breaks registry lockstep for nothing.
- **An unknown external consumer is harmed *more* by deletion than by documentation.** One with 0.7.43 locked and a free protobuf works today; deleting converts a working install into a hard resolution failure.

So: record the decision, do not delete, and leave `yank.yml` available. Rejected alternatives, with why: *a dry-run probe first* — it would tell us whether the artifact is still present, but the recommendation does not turn on the answer, so it buys nothing but a workflow dispatch. *Python-only deletion* — the workflow cannot express it. *Cloudsmith quarantine* (blocks download, retains the artifact, reversible) is the genuinely better middle path if blocking installs is ever wanted, and is the one thing worth asking about; see Open questions, default no.

Then fix the token line (`yank.yml:38` as this plan was written; `:55-60` after the fix), which resolved `${CLOUDSMITH_API_KEY:-$CARGO_REGISTRIES_ZER07LABS_TOKEN}` **without** stripping the `"Bearer "` prefix the cargo token carries — `publish.yml:369-371` strips it explicitly. This is worth doing precisely because it is latent: it fails closed today (Cloudsmith 401s, `curl -sf` under `set -euo pipefail` aborts before any DELETE), so it cannot cause a wrong deletion, but it would make even a dry run error out unless the dedicated `CLOUDSMITH_API_KEY` secret is set. A safety tool that silently does not work is worse than one that is known broken.

**Edge cases & failure modes.** The fix must preserve the fail-closed property — strip the prefix without making an empty or malformed token look valid. Do not "improve" `yank.yml` beyond the token line: its scoping is deliberate and correct (exact version equality, so `0.7.4` cannot match `0.7.43`; python and npm formats only; name must be exactly `seam-sdk` with the npm scope stripped, so the org's Cargo crates in the same repository are unreachable). Adding a format input would be a real improvement and is explicitly *not* in scope — it changes what a destructive tool can do, and belongs in its own reviewed change. The `DECISIONS.md` entry's citations are CI-checked and must resolve.

**Acceptance criteria.**
1. `DECISIONS.md` carries the disposition, the four evidence lines above, and the principle that distinguishes document-from-delete ("delete when a defect corrupts silently or is a security hazard; document when it fails loud") — stated so the next reader does not re-open it.
2. `DECISIONS.md` records that the defect band is **at least** 0.7.40-0.7.43 (with the reason the lower bound is not recoverable: `_gen/` is gitignored, so no per-tag gencode survives) and that no lockfile in the workspace pins it, with the date checked.
3. `yank.yml`'s token resolution strips a leading `"Bearer "` from either source, matching `publish.yml:369-371`.
4. `yank.yml`'s version-matching, format filter and name filter are unchanged.
5. Full Python suite green; `scripts/test_ci_gate.py` passes.

**Tests.** None beyond the existing doc-guards; the change is one workflow line plus a decision record. If a guard on the token handling is cheap in `scripts/test_ci_gate.py`'s executed-shell style, add it.

**Docs.** `DECISIONS.md`.

---

## Long-term posture

**The field manifest (Phase 5) is the one structural bet here, and it is the right one.** The alternative — a targeted probe for ACDP's four fields — is cheaper this week and wrong next quarter, because the defect is not "we forgot to watch ACDP," it is "the contract gate has never watched fields." That has now cost two unwired surfaces (`SubmitApprovalRequest`/`SubmitBallot` at the verb level, `collective_outcome` at the field level). Priced honestly: the manifest imposes a redden-on-every-additive-field tax, paid by one `--write-manifest` command and a reviewable diff. That tax is the feature; a gate nobody has to acknowledge is a gate that stops working.

**One-way doors in this plan: none remain.** The plan was scoped with one — deleting the published 0.7.40-0.7.43 artifacts — and it was analysed as a one-way door before being decided. The analysis chose the reversible branch: the artifacts stay, `yank.yml` remains available with its dry-run default, and the decision is recorded rather than executed. Three other things look like one-way doors and are not: adding sealed fields to `context_digest` is version-gated by design (`seam-runtime/plans/acdp-p1a-receipt-slots.md:402-404`, at `533f218` — `schema_version` stays 3, both old and new records recompute under one formula); the field manifest is a committed text file that can be deleted in a commit; and the vendored-spec refresh is a whole-file copy of a published document. The genuine irreversibility left in this area is *outside* the plan — anything already published cannot be unpublished without the deletion this plan declines to do, which is exactly why Phase 6's publish guard matters more than Phase 10's disposition.

**What the plan declines to foreclose.** It does not convert existing anchored citations wholesale (Phase 8 stops the bleeding and leaves #73's mechanism choice open), does not pin `buf.gen.yaml`'s remote plugins (that decision is recorded and its re-open trigger has not fired), and does not touch the protobuf floor. Each of those is a live option later; taking any of them now would settle a question on this plan's convenience rather than on its merits.

**The clean-room claim is an asset with a maintenance cost.** Four independent implementations agreeing on every committed vector is only evidence because none read the others. Phase 1's wording fix protects it from the opposite failure — a rule stated so broadly that it gets ignored, taking the real constraint with it.

## Enterprise concerns

**Release integrity** is the spine of Phases 6, 7 and 10. Today a green publish gate does not imply true wheel metadata, because the artifact is generated after the gate runs and nothing re-derives. Phase 6 makes the gate mean what a reader assumes it means. The residual risks are documented rather than fixed: `npm` and `python` publish in parallel with no cross-gate, so a half-published version is possible and cannot be re-cut at that number; and `ci-green` runs from the workflow as it exists on the tagged ref, so it is bounded by branch protection — Phase 6's ancestry check narrows that materially but does not eliminate it.

**Observability of the failure this plan is about.** The 0.7.43 class fails *silently at a consumer's import*, which is why `COMPATIBILITY.md` is load-bearing rather than decorative: with nothing yanked, the document is the only signal. That is also why Phase 7 amends the preamble rather than only adding a row — a document that overstates a decision is worse than one that admits a gap. The `framework-coinstall.yml` weekly probe is the right ongoing watcher for #48 and needs no change; it will go green on its own the day CrewAI's pin moves.

**Cross-repo failure domains.** The SDK's CI is coupled to `seam-runtime` in two places that will fire during this plan's life: `spec-pin` reddens on a spec change it does not control, and `check-contract` reddens on a BSR push it does not control. Both are deliberate freshness gates, and both are advisory-or-blocking by design decisions already recorded. Phase 2 exists so the second repo knows the first is watching.

**Scale and concurrency** are not materially at issue — this is a client SDK and a release pipeline, not a serving path. The one concurrency-shaped hazard is `ci-green`'s handling of multiple `ci-ok` runs for one commit and of still-running checks; that logic is already correct and pinned by executed tests, and Phase 6 must not regress it.

## Open questions

**Routed per the autonomy ladder. Nothing here blocks `/implement`; one optional question is surfaced with its default.**

1. **Delete the published 0.7.40-0.7.43 artifacts, or document them? — ANALYSED AS A ONE-WAY DOOR, THEN DECIDED: document, do not delete.** This was routed to a separate critical-decision analysis because deleting a published artifact is irreversible. The analysis settled it rather than escalating: the precedent already leaves *worse* defects installable, no lockfile in the workspace pins 0.7.43, deletion would also destroy a non-defective npm artifact, and an unknown external consumer is harmed more by deletion than by documentation. Reasoning and evidence go into `DECISIONS.md` in Phase 10. **The one thing worth the user's attention is optional and not blocking:** Cloudsmith has a package-quarantine facility that blocks download while retaining the artifact — reversible, unlike deletion — and whether this org's plan includes it could not be verified read-only. If blocking installs is ever wanted, that is the right instrument. **Default: no** — the §3 row is sufficient and matches standing policy.

2. **Field-manifest spelling for nested, `oneof` and `map` fields — RE-DECIDED after checking the stubs.** The earlier choice ("`oneof` members listed as ordinary fields with the containing `oneof` named in a trailing annotation") is **not producible on the Python side**: protobuf's `.pyi` emits no `oneof` grouping anywhere — the string does not occur in `seam_pb2.pyi` at all, and a member is indistinguishable from an ordinary field in both the `__slots__` and the `_FIELD_NUMBER` shapes (`seam_pb2.pyi:288-298`). Requiring the annotation would have made the two extractors permanently disagree — the exact failure the rationale claimed to avoid. It is also moot today: `seam.api.v1` has **zero** `oneof`s (verified in the proto, in the `.pyi`, and in the protobuf-es output) and **zero** real nested messages (the only nested classes are the two synthetic map entries; `AuditEntry` is top-level). Chosen instead: `Message/field`, mirroring `rpc-manifest.txt`'s `Service/Method`, with a genuinely nested message spelled by its full proto path (`Outer.Inner/field`, recoverable on both sides — Python from class nesting, TS from `Message<"seam.api.v1.Outer.Inner">`); `map` fields as one entry on the owner; *nested* synthetic map-entry messages excluded (by nesting, not by name — see Phase 5's second hazard). Oneof grouping is deliberately **not** represented; revisit if a `oneof` ever lands. Cheap to reverse — regenerate the manifest. `/implement` logs this to `ASSUMPTIONS.md` as UNCONFIRMED.

3. **Whether the field manifest covers `seam.event.v1` too — DECIDED (Opus).** No. Those fields already have two gates (probes 2 and 3, plus the vendored-spec pin) that fail for different reasons; a third would duplicate coverage while tripling the churn. Revisit only if an event field ever regenerates in unwired.

4. **Whether Phase 8 converts existing anchored citations or only guards new ones — DECIDED (Opus), with the cost now stated.** Guard new ones, grandfather the existing entry with an explicit `#73` comment. Issue #73 has not chosen between needle-based and heading-based anchoring, and settling it inside a plan that merely *encounters* the problem would be deciding someone else's open design question for convenience. **The cost of that choice:** grandfathering means Phase 9's spec refresh still drifts that one anchor, so Phase 8 does not actually spare Phase 9 the bump — it only stops new anchors being added. Converting the single entry (one citation, `test_compatibility_citations_resolve.py:166-170`) would, and is a smaller change than #73's full mechanism swap. Reversible either way; take it if Phase 8's implementer finds the conversion cheap.

5. **Live-runtime integration coverage for `submit_evaluation`/`submit_objection` — DECIDED (Opus): not in this plan.** The other verbs have it and these should eventually, but the gated `integration` job is advisory (`scripts/test_ci_gate.py:98`) and adding coverage there buys little against the risks this plan is about. Noted in `PROGRESS.md` as a follow-up, not a phase.

6. **Issues #40, #43, #44 — DECIDED (Opus): left alone.** #40 is an L-sized speculative build deliberately parked; #44 is blocked on information that was lost; #43 is operator action on a different axis. One correction is worth posting to #43 in passing: its premise that no yank workflow exists is false — `.github/workflows/yank.yml` is present, dispatch-only, `dry_run` defaulting true.

7. **`ASSUMPTIONS.md:177` (testing rather than only building `verify/` at its declared MSRV) — DECIDED (Opus): not inherited.** It is the one UNCONFIRMED assumption settleable in-repo, but it is unrelated to every strand here; folding it in would be scope drift. The other two UNCONFIRMED entries are blocked on `seam-runtime` answers and stay as they are. `/reconcile` at the end of this plan should see all three.

---

## Plan review

**Two independent Opus rounds ran against the code, both before any implementation. Round 1: REVISE (18 findings). Round 2: REVISE (12 findings). Both applied.**

**Round 1 — the six findings that changed the work.** (1) The commissioning premise ("the SDK must catch up on the contract") is false: over the SDK's 78-commit gap `seam.proto` moved +6 comment lines and `seam_event.proto` is byte-identical, so the plan carries **no** contract-adoption phase. (2) Phase 6 was resequenced to run first — the declared floor and the emitted gencode are both 7.36.0, so there is zero headroom and the 0.7.43 defect can recur on the next release. (3) The two "stale in-repo claims" were re-attributed from a `PROGRESS.md` that no longer exists to `plans/README.md:13` and `plans/archive/record-digest-v3.md:445-446`. (4) Phase 1's acceptance 1 was unachievable (`HEAD` is not an ancestor of `origin/main`) and its Files list omitted `ASSUMPTIONS.md`, which holds the over-broad clean-room wording. (5) Phase 3's TS union needs one body change — `client.ts:207`'s `decisionId` narrows to `string | undefined`. (6) The 0.7.40 lower bound is not established by the floor string, which dates to `v0.7.13`; and `COMPATIBILITY.md` §7 documents the *opposite* coupling direction from the one Phase 2 wanted to cite.

**Round 2 — what round 1 missed or what moved under it.** (a) **Phase 5's Python extractor was wrong.** `.pyi`'s `__slots__` omits keyword-named fields, so `ResumeRequest.raise` and `AdminResumeRequest.raise` are invisible to it: 221 vs protobuf-es's 223, a permanently red gate the documented escape cannot clear, and blindness to exactly the class of field the phase exists to watch. Rule changed to `*_FIELD_NUMBER` lowercased — measured 223 = 223, zero diff. (b) The `*Entry` exclusion must key on **nesting**, not the name; `AuditEntry` is a real top-level message a name filter drops from both sides, staying green while going blind. (c) **The runtime moved mid-review:** P1a Phase 6 was committed at `533f218` (10:17-07:00) and is marked DONE upstream, so Ask A is now *push and merge*, not *commit and publish*; all six anchors into `acdp-p1a-receipt-slots.md` and all four into `seam-event.v1.md` had drifted and were re-pinned with a commit stamp and a re-verify instruction. (d) Phase 1 AC1 required sha `3c37532` while its own Approach permits a rebase; made subject-matching. (e) Phase 7's "the evidence covers four" contradicted its own hedge — the per-tag floor check covers 27 tags; what bounds it at 0.7.40 is a three-hour publication cluster. Titles now say "at least". (f) One duplicated sentence trimmed.

**Confirmed sound across both rounds, and left alone.** The central bet — a whole-surface field manifest over a targeted ACDP probe — survived both attacks. Every `file:line` in this plan and `PROGRESS.md` now resolves and points at what it claims (checked mechanically, then spot-read). Held on re-check: the TS compile block (`TS2345`, reproduced), `check-contract.sh`'s field-blindness, the publish-time skew (no workflow pins protobuf anywhere), `crypto.py`'s opaque `context_digest` so P1a costs the digest layer nothing, `record-digest-v3.md` Phases 1-8 delivered, zero `oneof`s in `seam.api.v1`, and the baseline (545 passed / 17 skipped, `check-contract` exit 0).
