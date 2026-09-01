# PROGRESS — `plans/post-adoption-hardening-and-acdp-readiness.md`

Checkpoint trail and repo map for the post-adoption hardening / ACDP P1a readiness workstream.
`/implement` writes a block per phase; a resumed run reads this instead of re-scanning the repo.

**Plan:** [`plans/post-adoption-hardening-and-acdp-readiness.md`](plans/post-adoption-hardening-and-acdp-readiness.md)
— 10 phases (Phase 9 BLOCKED on `seam-runtime` ACDP P1a Phases 4 and 6).

**Execution order ≠ numbering:** 1 → 6 → 7 → 10 → 3 → 4 → 5 → 2 → 8. **Phase 6 runs immediately after
Phase 1** per its own Sequencing block: it depends on nothing and is the only phase guarding a hazard that
fires on every release — and releases follow the runtime, five in the three days to 2026-08-31, with zero
floor/gencode headroom. Phase 1 cannot yield to it because it syncs the checkout and establishes this file.
Phase 9 is not attempted.

**PR strategy — 3 PRs.** Chosen over one big PR because the phases have genuinely different review
audiences, and over one-PR-per-phase because several phases are too small to review alone.
1. **Phases 1, 6, 7, 10** — publish integrity + tracking state. Ships first: it carries the only
   actively-firing hazard.
2. **Phases 3, 4, 5** — the unwired field, closing #50, and the gate that missed it. One story;
   splitting the instance from the class would make each half look smaller than it is.
3. **Phases 2, 8** — the (deliberately unfiled) cross-repo asks and the vendored-citation guard.

**Scope restriction (user-set, 2026-08-31):** seam-sdk only. No writes and no issue actions in any
sibling repo. Phase 2 writes its asks and leaves them **UNFILED** — recorded again in that phase's log
entry so the gap stays visible.

**Hard constraint — clean-room, stated precisely.** This repo's digest implementations
(`python/seam_sdk/crypto.py`, `ts/src/crypto.ts`, `verify/src/verify.rs`) are transcribed from the
**published spec only, never from the runtime's Rust** — that is the claim at `verify/DECISIONS.md:113-117`,
and four independent implementations agreeing is only evidence because none read the others. So:
`../seam-runtime/crates/**` **Rust sources are never read**. `crates/seam-api/proto/**` is the *published
contract* and **is** read — `Makefile:29`'s `generate-local` target does exactly that via `buf`. Permitted
sibling reads: the protos via `buf`, `../seam-runtime/docs/**`, `../seam-runtime/plans/**`,
`../seam-runtime/scripts/**`, `../seam/docs/**`.
> The previous wording of this line ("`../seam-runtime/crates/**` is NEVER read") was over-broad and
> contradicted `Makefile:29`. Phase 1 corrects it wherever else it appears.

> The previous occupant of this file tracked `plans/record-digest-v3.md`, which is **delivered** —
> Phases 1-8 complete, the Phase 6 blocker explicitly cleared at `plans/archive/record-digest-v3.md:666-669`,
> and issue [#56](https://github.com/zer07labs/seam-sdk/issues/56) closed 2026-08-25. That file's own
> header here still said "Phase 6 BLOCKED", which was stale. **Phase 1 of this plan verifies that
> delivery against code — not against its status table — and completes the archive.** The previous
> checkpoint trail lives in git history (`git log -p -- PROGRESS.md`); nothing here carries over.
>
> **Done in Phase 1 (2026-08-31).** Delivery was verified against this tree — `record_digest_v3` at
> `python/seam_sdk/crypto.py:589`, `ts/src/crypto.ts:608`, `verify/src/verify.rs:448`; the 6a/6b
> streamed arms live at `python/seam_sdk/admin.py:129` and `ts/src/admin.ts:141`; KATs at
> `conformance/vectors.json:70` — and the plan is now `plans/archive/record-digest-v3.md`.
> `plans/authorize-single-canonicalization.md` turned out to be delivered too (issue #60, closed
> 2026-08-25) and had **no index row at all**, so it was archived in the same pass. Delivery PRs:
> [#58](https://github.com/zer07labs/seam-sdk/pull/58) and [#63](https://github.com/zer07labs/seam-sdk/pull/63)
> for record-digest-v3, [#68](https://github.com/zer07labs/seam-sdk/pull/68) for authorize.

## Repo map

| Path | Purpose / relevance |
|---|---|
| `python/seam_sdk/_collective.py:83` | `collective_outcome_of(resp: Union["pb.DecisionResponse", "pb.SessionStep"])` — fail-closed decode. **Phase 3 DONE**: widened to the union. `:1-30` documents why raw field access is unsafe (optional presence + `UNSPECIFIED` == 0 ⇒ a naive negative test allows on every unknown value). |
| `ts/src/client.ts:202` | `collectiveOutcomeOf(resp: DecisionResponse | SessionStep)` — the TS twin. **Phase 3 DONE.** It needed a real union: protobuf-es brands messages, so passing a `SessionStep` is a *compile error* today (reproduced: `TS2345`, `$typeName` mismatch). `:144-146` `UnknownCollectiveVerdictError(rawValue, decisionId: string)` — **required** `string`, so `:207`'s `resp.decisionId` became `resp.decisionId ?? ""`; a verifier mutation removing that coalesce reddens a test, so it is load-bearing, not decoration. |
| `ts/gen/seam/api/v1/seam_pb.ts:942` | Branded `SessionStep = Message<"seam.api.v1.SessionStep"> & {…}` — the reason Phase 3's TS half is a hard block, not a typing nicety. `:971` carries `collectiveOutcome?`. |
| `python/seam_sdk/_gen/seam/api/v1/seam_pb2.pyi:289,297` | `SessionStep.collective_outcome` in the Python stubs — generated, never surfaced. |
| `python/seam_sdk/client.py:541`, `ts/src/client.ts:654` | `submit_commit` / `submitCommit` return a `SessionStep` — the caller Phase 3 exists for. |
| `python/tests/test_collective_outcome.py`, `ts/tests/collective_outcome.test.ts` | `DecisionResponse` cases only. **Phase 3** adds the `SessionStep` cases (absent ⇒ none; `UNSPECIFIED` ⇒ raise; unknown ⇒ raise; non-commit step ⇒ none). Drive red first. |
| `python/seam_sdk/client.py:473,514` · `aio.py:371,412` · `ts/src/client.ts:601,637` | `submit_evaluation` / `submit_objection` — **already delivered** by `c49d005`. Do not re-plan. |
| `python/seam_sdk/client.py:506-507` · `aio.py:404-405` · `ts/src/client.ts:623` | `confidence` presence mapping — `None` ⇒ field-absent, never `0.0`. Correct in both languages; pinned by `python/tests/test_evaluation_confidence.py:55,64,87,100` and `ts/tests/evaluation.test.ts:59,70,85,93`. |
| `python/seam_sdk/_authorize.py:180,223` | `AuthorizeRequest.subjects` — one shared builder feeds sync + aio + TS. Delivered; tests at `python/tests/test_authorize.py:637,646`. |
| `scripts/check-contract.sh` | The contract-freshness gate. `:192` probe 1 (one named RPC) · `:196-210` probe 1b and `:212-226` probe 1c (hardcoded names; 1b includes **two `seam.api.v1` field names**, `call_sig` and `on_behalf_of`, at `:205-206`) · `:228-241` probe 2 (**exactly four hardcoded field names, all on `seam.event.v1`**; `STREAM=1` hardens) · `:242-247` probe 3 (`EVENTS=1`) · `:249-275` probe 4 (RPC set comparison, both directions). Every field probe names a *pre-existing* field, so **a new message field is invisible to all of them — that is the hole Phase 5 closes.** Extractors to mirror: `:158-161` `rpcs_python` (greps `_pb2_grpc.py`), `:163-166` `rpcs_ts` (greps `@generated from rpc`), `:173-188` `--write-manifest` (**writes from Python only**, preserves the header verbatim), `:88-97` the exit-3 no-stubs guard. |
| `contract/rpc-manifest.txt:60-61` | Declares `SubmitEvaluation`/`SubmitObjection`. The model Phase 5 mirrors one level down. |
| `contract/field-manifest.txt` | **Phase 5 creates.** Whole-surface `seam.api.v1` field declaration (measured: **223 fields over 65 messages** — both extractors agree exactly, given the `_FIELD_NUMBER` rule in the row below), set-compared per language both directions, `--write-manifest` escape. Also the ACDP tags-7-10 tripwire. |
| `python/seam_sdk/_gen/seam/api/v1/seam_pb2.pyi:106,163` | `AuthorizeRequest.FeaturesEntry` / `RunDecisionRequest.FeaturesEntry` — **synthetic map-entry messages Python emits and protobuf-es does not**. Phase 5's extractors must exclude them **by nesting, not by the `*Entry` name** — `AuditEntry` (`:716`) is a real top-level message. `.pyi` carries **no `oneof` grouping at all** (and `seam.api.v1` has zero `oneof`s). |
| `python/seam_sdk/_gen/seam/api/v1/seam_pb2.pyi:409,418` | **`__slots__` is NOT the field list.** `ResumeRequest`/`AdminResumeRequest` carry a proto field named `raise`; the `.pyi` generator cannot emit a Python keyword, so `__slots__` omits it and only `RAISE_FIELD_NUMBER` (`:412`, `:424`) survives. Measured: `__slots__` = 221 fields, protobuf-es = 223. **Phase 5 must extract from `<NAME>_FIELD_NUMBER: _ClassVar[int]` lowercased** — that reconciles both sides at 223 with zero diff. |
| `contract/wire-framing.json:31-33` | `_comment`: a bump is **NOT** for an additive proto field or a new RPC verb. Do not touch it for ACDP. |
| `.github/workflows/publish.yml:316` | `make generate` **again at publish time**, against unpinned plugins — the open half of #52. `:390-401` pre-upload smoke installs protobuf *unconstrained*, so the skew is invisible to it; `registry-smoke` (`:519`) likewise. Measured at planning: `grep -rn protobuf .github/workflows/` yielded **one** hit, a prose comment — no workflow pinned protobuf anywhere, so nothing caught the skew. **Phase 6 closed that** (DONE 2026-08-31): the same grep now yields 17, and `publish.yml:423` installs the built wheel with `protobuf==$FLOOR`. The declared floor and the emitted gencode are both **7.36.0** (`python/pyproject.toml:50`, `_gen/.../seam_pb2.py:12-18`) — zero headroom, which is why this phase ran first. |
| `.github/workflows/publish.yml:63-148` | `ci-green` — resolves every `ci-ok` conclusion for the tagged commit. Sound: `:107` still-running ⇒ `pending`, `:117-126` one-green-cannot-mask-one-red, `:143-148` timeout is a refusal. `:192`/`:285` gate both npm and python. **Must not regress.** |
| `.github/workflows/publish.yml:150-188` | `version-check` — tag vs in-tree versions. It had **no branch-ancestry check** (`ci.yml:19` runs on every branch push, so a tag at a green feature-branch commit published cleanly); **Phase 6 added one at `:176`**, which is inside this row's own range. Read the range as the job, not as evidence of the gap — it was widened in round 1 until it contained the very step it is cited for lacking. |
| `buf.gen.yaml:29,31,33` | Unpinned remote plugins — `protocolbuffers/python`, `pyi`, `grpc/python`. The reason the floors are *derived*. Pinning them is **rejected**: `DECISIONS.md:339-359`. |
| `python/tests/test_protobuf_floor.py:72,88` | The two pure-file-read assertions Phase 6 runs at publish time. `:29-31` reads only `_gen/seam/api/v1/seam_pb2.py`; `:47-51` **skips** when `_gen` is absent. `:88-99` forces `cap == gencode_major + 1` — this is why "widen the floor" is not a metadata edit. |
| `python/tests/test_grpcio_floor.py:38` | Module-level `import grpc` — matters if Phase 6 runs it in the publish job. |
| `.github/workflows/yank.yml` | `workflow_dispatch`, `dry_run` default `"true"`. A hard **DELETE** (`:91-92`), not a PyPI-style yank. Its token line did **not** strip the cargo token's `"Bearer "` prefix (`.github/workflows/publish.yml:369-371` does) — **Phase 10 fixed it** (DONE 2026-08-31) at `.github/workflows/yank.yml:55-60`, and left the version/format/name filters (`:73-76`) byte-unchanged. `scripts/test_yank_gate.py` now executes the resolution and pins those filters. |
| `COMPATIBILITY.md:99-136` | §3 known-bad table + the "Nothing was yanked" preamble. **Phase 7 added the `0.7.39 – 0.7.43` row** (DONE 2026-08-31) — *not* the hedged `≥ 0.7.40` this row first planned: both edges are proven from CI history, so the hedge was deleted rather than softened. `:181-188` dependency floors · `:203-262` §4a co-installability (`:221-223` machine-read `PROBE-TABLE` marker — columns and order load-bearing; `:227` crewai row, whose Tracking cell links **#48 and not crewAI#7103**) · `:328-364` §7 cross-repo coupling, incl. `:337-355` vector origination. **§7 documents `seam-sdk` main → `seam-runtime` CI, *not* a spec-side merge-order courtesy — do not cite it for one.** |
| `python/tests/test_retracted_claims.py:170-184` | Parametrized presence check over `COMPATIBILITY.md`. **Phase 7 added `"0.7.39"`** — the *lower* edge, which is the one a reader is most likely to assume they are outside of — plus two real row guards (`python/tests/test_retracted_claims.py:194-256`), because this parametrize is a substring check and could not fail for a deleted row. `python/tests/test_retracted_claims.py:27-30` globs **every `*.md` in the repo including `plans/` and this file**; `python/tests/test_retracted_claims.py:39-48` are the qualifier markers that make a paragraph "discussing, not claiming". |
| `python/tests/test_compatibility_citations_resolve.py` | Every backticked `file:line` in `COMPATIBILITY.md`/`DECISIONS.md` must resolve; `:61-64,:92` ≥10 each; `:76` sibling paths need a `seam-runtime/` prefix; `:141-172` `ANCHORED` needles must hit **exactly once** within `CITATION_SLACK` (`:176`). **Phase 8** adds the vendored-file rule. |
| `verify/docs/seam-event.v1.md` | Byte-verbatim vendored spec, pinned in its header. **Phase 9** refreshes it whole-file. Source of #73's citation drift. |
| `scripts/check_vendored_spec.py:22-38` | Integrity (`:24-26`) / reachability (`:28-32`) / **currency** (`:34-38`) — fails on staleness by explicit decision. This is what will announce runtime P1a Phase 6 by reddening `spec-pin` (`.github/workflows/ci.yml:517-543`) on every PR. |
| `python/seam_sdk/crypto.py:606-610` | `record_digest_v3` takes `context_digest` as an **opaque 32-byte sub-digest**, deliberately not reimplemented. **This is why ACDP P1a costs the digest layer nothing** — verified: `context_digest` appears only as an input (`:599,643,677`, `admin.py:141`), and no context-provenance formula exists in `python/`, `ts/` or `verify/`. `:386` `_frame` · `:390` `_opt` · `:584` `_opt_bytes` · `:394` `record_digest_v2`. |
| `verify/src/verify.rs:668-674` | `schema_version` dispatch (2 ⇒ v2, 3 ⇒ v3, else refuse); `:636-644` ceiling refusal. P1a keeps `schema_version = 3`, so **no new arm**. |
| `python/tests/test_errors_is_import_light.py:87-100` | `crypto.py` may import only `cryptography`; `errors.py` only `grpc`. seam-runtime's `sdk-digest-parity` gate loads `crypto.py` standalone. **No phase may add an import to either.** |
| `scripts/test_ci_gate.py:79,98,141` | `ci-ok`'s `needs:` must equal the full job set both ways; `ALLOWED_ADVISORY` (the literal is at `:52`, asserted by the test at `:98`) may hold only `{integration, spec-pin}`; `workflow-guards` must stay free of `BUF_TOKEN`/`buf-setup-action`/`make generate` (banned triple at `:191-195`). **Any new CI job must be added to `needs:`.** |
| `scripts/test_publish_gate.py` | Executes `publish.yml`'s extracted `run:` blocks against a stubbed `gh`. **Phase 6** extends it in the same style. |
| `python/tests/test_workflows_generate_through_the_makefile.py:43,72` | No workflow may call `buf generate` directly; the `generate:` target must keep both `buf generate` and `root_gen.py` (without which the wheel is unimportable). |
| `Makefile:24,29,57-58` | `generate` (BSR) · `generate-local RUNTIME=../seam-runtime` (reads `crates/seam-api/proto` via `buf`) · **`clean` `rm -rf`s all three stub trees — never run it; recovery needs a BSR login.** |
| `plans/README.md:1-6` | Archive convention: delivered plans move to `plans/archive/` with a dated verification note, verified **against code, never a status table**. `:13` **carried** the stale `record-digest-v3` Active row (*"Phases 1–5 delivered … Phase 6 remains BLOCKED"*) and the index was **missing a row entirely** for `plans/authorize-single-canonicalization.md` — both corrected in Phase 1, which archived each plan against code. `:13` now holds this plan's own Active row. The cross-repo *table* lives in `plans/cross-repo/README.md`, not here — **Phase 2** edits that file. |
| `CHANGELOG.md:3-7` | The SDK does not choose its own version; entries accumulate under `## Unreleased`. `:516-518` is the hedging style Phase 7 *was* to mirror — it did not, the band being provable, and the citation was removed as it sat within `CITATION_SLACK` of the `"No yank"` needle; `:521-526` the no-yank decision of record. **This advisory still names only 0.7.13-0.7.19** — see the Phase 7 checkpoint. |

### Sibling repos (read-only — referenced, never written)

| Path | Why it matters |
|---|---|
| `../seam-runtime/plans/acdp-p1a-receipt-slots.md` | The P1a plan. **Anchors below are stamped to `533f218`; this file moved twice on 2026-08-31 — re-verify before citing.** `:111-117` the four slots · `:276-301` Phase 4 = proto tags 7-10 · **`:289-291` "the seam-sdk regeneration … must be filed, not forgotten"** (Phase 2's mandate) · `:358-359` Phase 6 = the spec rewrite, now marked **`Status: DONE` (`533f218`)** · `:402-404` not a one-way door · `:103-109` bindings pinned all-`None` so `sdk-digest-parity` stays green (⇒ no populated-slot vector will ever reach `vectors.json`). |
| `../seam-runtime/docs/specs/seam-event.v1.md` | **Two sets of anchors, and they differ — re-verify before citing.** At the runtime's `origin/main`: `:568` still asserts the slots are reserved and absent, and `:581-587` still says the four payload encodings *"are D3's to pin, and one of them is a trap"* (describes what must be stated without stating it). At `533f218` on the unpushed branch, the rewrite has landed: `:534-544` the `context_digest` = `seam.audit.context-provenance.v3` formula the four slots enter · `:569-572` the slots are **filled**, populated on remote `acdp://`, absent on local `sha256:` · `:574-578` the `schema_version`-stays-3 rule · **`:586-593` all four payload encodings pinned in a table, naming the trap** — **this is the clean-room precondition, written but unpublished.** |
| `../seam-runtime/scripts/sdk-digest-parity.sh` | The cross-repo gate. Byte-diffs the whole `conformance/vectors.json` against the runtime's emitter, then loads `python/seam_sdk/crypto.py` **standalone** and resolves `record_digest_v*` by exact name. Renaming either function breaks merges upstream. |
| `../seam-runtime` branch `feat/acdp-p1a-receipt-slots` | Where P1a actually lives — **not `main`**. **All six phases are committed** (6 commits ahead of `origin/main` as of 2026-08-31T10:17-07:00): Phase 4 (proto tags 7-10 with real fields) at `cda620a`, and **Phase 6 (the spec rewrite) at `533f218`**, which also carried the `seam-store` edit that used to sit uncommitted beside it. The dirty working tree there is now unrelated Rust (serving-router, serving, integration). **The branch is not pushed** — `git ls-remote --heads origin feat/acdp-p1a-receipt-slots` is empty, so there is no PR, nothing on `origin/main`, and nothing on the BSR. The work is done; the publication is not. That is Phase 2's Ask A. |
| `../seam/docs/sdk/01-base-concepts-and-quickstart.md:110`, `04-requesting-access.md:14` | Tell partners `pip install seam-sdk` with no mention of the protobuf co-installability constraint. **Phase 2's Ask B.** |
| `../seam/docs/OPEN-TASKS.md:3-8` | Scopes itself to items with no clean repo home — so #48/#52 stay in this repo's tracker. |

### Baseline at plan time (2026-08-31)

- `cd python && .venv/bin/pytest -q` → **545 passed, 17 skipped**.
- `cd verify && cargo test` → **86 passed** across 8 binaries + 1 doc-test.
- `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` → **exit 0**, all 42 declared RPCs present in both python and ts.
- Generated stubs **present**: `gen/` 246 files · `python/seam_sdk/_gen/` 36 · `ts/gen/` 2. Suites run with **no BSR login**.
- Checkout is 5 releases behind and **diverged**: local `3c37532` ("docs: fill in repo-specific CLAUDE.md") is
  unpushed, `origin/main` = `ed9227e` = v0.7.68. `git log origin/main..HEAD` = 1, `HEAD..origin/main` = 5, and
  `HEAD` is **not** an ancestor of `origin/main` — so Phase 1's sync is a merge/rebase, not a fast-forward.
  `git diff --stat HEAD origin/main` is three files: `CLAUDE.md`, plus version stamps in `python/pyproject.toml`
  and `ts/package.json`. **The sync invalidates no line number cited anywhere in this file or the plan.**
- Untracked `python/uv.lock` — unreferenced by CI. Leave it; do not commit it.

### Follow-ups noted, deliberately not phases

- Live-runtime integration coverage for `submit_evaluation`/`submit_objection` (the `integration` job is advisory).
- `ASSUMPTIONS.md:177` (testing rather than only building `verify/` at its declared MSRV) — the one UNCONFIRMED
  assumption settleable in-repo; unrelated to this plan's strands. The other two are blocked on `seam-runtime`.
- Issue #43's premise that no yank workflow exists is false — worth a one-line correction on that issue.
- `publish.yml`'s npm and python jobs run in parallel with no cross-gate: a half-published version cannot be
  re-cut at that number. Pre-existing structural risk, documented in the plan's Enterprise concerns.

## Phase log

### Phase 1 — Reset the plan-tracking state to the truth · 2026-08-31

- **Verifier:** Opus, fresh agent each round. **Rounds: 3 → PASS.** All findings were
  documentation-precision; none was a correctness risk, and the commit is docs-only.
  - *R1 GAPS (4):* the repo-map cell asserted a staleness this very commit had just fixed;
    the Approach's "add the delivery PR numbers" instruction was silently skipped;
    `ts/src/admin.ts:109` was cited as the streamed v3 arm when it is the version-ceiling refusal
    (`:141` is the dispatch); and the archive move orphaned citations — two line-anchors plus seven
    `**Plan:**` paths in `ASSUMPTIONS.md`, which no guard covers.
  - *R2 GAPS (3):* the `:109`→`:141` fix reached `PROGRESS.md` but missed
    `plans/archive/record-digest-v3.md:12`; removing a duplicated execution-order block ate the
    blank line and merged two paragraphs; and the path repoint **over-replaced** four quoted
    `DECISIONS.md` section titles, which are lookup keys that must match `DECISIONS.md:222`
    verbatim, not paths.
  - *R3 PASS:* all three closed, both halves of the over-replacement checked (quoted titles reverted,
    `**Plan:**` paths still archive-pointed), no new breakage, 545/17 green.
- **Why three rounds on a docs-only phase:** this phase exists *because* two in-repo claims had gone
  stale, so citation accuracy is the deliverable rather than a nicety. Two of the three rounds were
  self-inflicted by the fix passes, not by an unclear spec — worth noting rather than hiding.
- **Sync:** `git pull --no-rebase` merged `origin/main` (`ed9227e`, v0.7.68) into the unpushed local
  `3c37532`. As predicted it was a **merge, not a fast-forward**, and it touched only
  `python/pyproject.toml` and `ts/package.json` (version stamps) — no line number cited anywhere in
  the plan moved. Merge commit `68e92c2`; branch `feat/publish-integrity-and-tracking-state`.
- **Delivery verified against code, not status tables** (the whole point of the phase):
  `record_digest_v3` at `python/seam_sdk/crypto.py:589`, `ts/src/crypto.ts:608`,
  `verify/src/verify.rs:448`; streamed v3 arms at `python/seam_sdk/admin.py:129` (with `:107`
  refusing `schema_version > 3`) and `ts/src/admin.ts:141` (with `:109` the matching ceiling
  refusal); KATs at `conformance/vectors.json:70`;
  issue #56 CLOSED 2026-08-25.
- **Divergence:** `plans/authorize-single-canonicalization.md` was also fully delivered (5/5 phases
  `DONE`, issue #60 closed 2026-08-25) and had **no index row at all**. Archived rather than given
  the planned Active row — an Active row would have been false. Logged inline in the plan's Phase 1.
- **Files:** `plans/record-digest-v3.md` → `plans/archive/` (+ delivery note),
  `plans/authorize-single-canonicalization.md` → `plans/archive/` (+ delivery note),
  `plans/README.md` (Active row replaced; two Archived rows added), `ASSUMPTIONS.md` (clean-room
  wording narrowed to Rust-only, proto explicitly excepted), `PROGRESS.md`,
  `plans/post-adoption-hardening-and-acdp-readiness.md`.
- **Not done here, deliberately:** `plans/README.md`'s cross-repo paragraph still says "six asks" —
  that is Phase 2's acceptance 5, not this phase's.
- **Tests:** `cd python && .venv/bin/pytest -q` → **545 passed, 17 skipped** (baseline held). The
  doc-guards that scan every `*.md` — `test_retracted_claims.py`, `test_compatibility_citations_resolve.py`
  — pass against the two new archive notes and the rewritten index.
- **Next:** Phase 6 (publish-time gencode/floor skew) — the actively-firing hazard.

### Phase 6 — Close the publish-time gencode/floor skew · 2026-08-31

- **Commit:** see below · branch `feat/publish-integrity-and-tracking-state`
- **Delivered:** the publish path now re-derives the dependency floors from the stubs *it* generated
  (`.github/workflows/publish.yml:340`), installs the built wheel with `protobuf` pinned at the floor
  the wheel itself declares and imports the generated module there (`:413`), and refuses a tag whose
  commit is not an ancestor of `origin/main` (`:176`). All three are executed — not merely
  asserted — by `scripts/test_publish_gate.py`.
- **The hazard was live, and this is the phase that was losing ground while it waited:** the declared
  floor (`python/pyproject.toml:50`, `protobuf>=7.36.0,<8`) and the emitted gencode are **equal**, so
  the next unpinned remote-plugin roll between a green CI run and a publish-time `make generate`
  reproduces the `0.7.43` defect exactly.
- **The falsifiable negative earned its keep twice, on this phase's own code:**
  - `git fetch --no-tags --depth=0` — git rejects it outright (*"depth 0 is not a positive
    number"*). It read fine; it would have failed **every** publish. Found on first execution.
  - The floor step's inner pytest went red and the **step still exited 0**. GitHub's implicit
    `bash -e {0}` would have hidden how fragile that was: a step's status is otherwise just its last
    command's, so a red protobuf-floor test followed by a green grpcio one publishes anyway. Both new
    steps now carry an explicit `set -euo pipefail`, and the harness runs them under a plain
    `bash -c` **on purpose**, so deleting that line goes red.
- **Half-publish trade-off, settled and recorded (not left unstated, as the plan required):** kept
  in-job rather than extracted to a shared gate both `npm` and `python` `needs:`. The `python` job
  already builds, smokes, and uploads the *same* `dist/*.whl` in one step, so extracting validation
  would mean rebuilding the wheel in the gate — a validated-vs-published skew of exactly the kind
  this phase removes. Reasoning in `DECISIONS.md` under "Accepted trade-off".
- **Rejected, consistent with `DECISIONS.md`:** pinning `buf.gen.yaml`'s remote plugins. It converts a
  self-correcting derivation into a number someone must remember to bump, and its failure mode is
  silent.
- **Citations this phase broke, and the guard's blind spot it exposed:** inserting into
  `publish.yml` shifted the needles COMPATIBILITY.md anchors for the npm and PyPI registry URLs —
  `test_compatibility_citations_resolve.py` caught those, twice (the second time after the
  skip-hole fix moved them again). It does **not** scan `PROGRESS.md` or the plan, and the 75-line
  `DECISIONS.md` prepend plus the 11-line `COMPATIBILITY.md` paragraph silently invalidated anchors
  throughout this file's repo map and the plan — among them the `COMPATIBILITY.md` ranges Phase 7
  navigates by, the Bearer-strip line Phase 10 navigates by, and one that had drifted onto a bare
  `fi`. **No count is recorded here, deliberately.** Three verify rounds each produced a different
  one, and for a round the two documents contradicted each other on it because a fix updated one
  copy and not the other — a number that has to be maintained in two places is one more thing that
  rots. **Repointing by hand missed six and re-broke one** (round 2), and round 3 then found four
  survivors of the *mechanical* sweep that replaced it: that sweep read only explicit `path:line`
  citations, not the bare `:line` form that inherits its path from earlier in the sentence, and
  every survivor lived in the form it did not read. It now reads both. Worth carrying forward: `PROGRESS.md` and the plan are the most-cited unguarded
  documents here, and adding them to that test's `DOCS` dict is a real candidate — deliberately not
  done in this phase, which is about the publish path, but the case is now evidence not tidiness.
- **Files:** `.github/workflows/publish.yml`, `scripts/test_publish_gate.py` (+11 tests),
  `COMPATIBILITY.md` (dependency-floors note + two citations), `DECISIONS.md` (new entry),
  `plans/post-adoption-hardening-and-acdp-readiness.md`, `PROGRESS.md`.
- **Tests:** `scripts/test_publish_gate.py` → **24 passed** (13 pre-existing `ci-green` race and
  patience cases, unmodified and byte-identical, plus this phase's 11); `cd python &&
  .venv/bin/pytest -q` → **555 passed, 17 skipped** (up from 545 — the doc guards parametrize per
  citation and this phase added ten); `scripts/test_ci_gate.py` + `scripts/test_release_gate.py` →
  17 passed; ruff clean. *(An earlier note here claimed the pre-existing patience cases take ~an
  hour locally because every exec of a freshly-written stub script cost ~14s. That was a symptom of
  the machine's disk being full, not a property of the tests — with space free the whole file runs
  in under 9 seconds. Recorded because the wrong explanation was the more flattering one.)*
- **Not done here, as the plan directed:** `ci-green` still executes from `publish.yml` *as it exists
  on the tagged ref*, so it stays only as strong as branch protection. The ancestry check narrows
  that materially without closing it.
- **Verify gate (fresh Opus), three rounds:** R1 **GAPS (5)**, R2 **GAPS (7)**, R3 **GAPS (8)** — all closed. The rounds converged on substance and diverged on records: R3 found **no code defect at all**, and every one of its eight findings was a document that no longer described the tree.
  - *G1/G2 (the same class, 13 sites):* citations broken by this phase's own insertions in
    `PROGRESS.md` and the plan — the two documents the citation guard does not scan.
  - *G3, the one that mattered:* `.github/workflows/publish.yml`'s floor step could **exit 0 having
    asserted nothing**. `test_protobuf_floor.py` skips when the generated tree is absent and pytest
    exits 0 when everything skips, so a `make generate` that wrote `_gen` somewhere unimportable —
    the exact defect this job shipped when it ran raw `buf generate` — would have left the guard
    green. The step's own comment claimed this *could not happen*, which made it an assumption
    wearing an assertion's clothes. Now `test -f` before pytest, plus
    `test_stubs_in_the_wrong_place_fail_rather_than_skip_the_guard`.
  - *G4:* the test count here said +9; it is +11.
  - *G5:* `test_compatibility_citations_resolve.py`'s docstring promised a 125-line masking margin
    between duplicate `publish.yml` citations; this phase's fourth citation cut it to 27. Still
    clear of `CITATION_SLACK` 3, but the note was false and is now accurate.
  - *R2's blocking finding — the G3 test was vacuous.* `test_stubs_in_the_wrong_place_…` passed
    **with the guard deleted**: `_stub_repo` created `_gen/` unconditionally and only skipped writing
    the files, so `test_grpcio_floor.py`'s `assert sources` hard-failed and the step exited non-zero
    for an unrelated reason. A test that green-lights the thing it protects being removed is worse
    than none. It now omits the tree entirely and asserts the guard's own `::error::` text; verified
    both ways — guard removed → red (exit 0, `1 skipped, 4 deselected`, the hole exactly), guard
    restored → green. The guard also gained that message, so the failure it catches is diagnosable.
  - *R2's other six:* the hand-repointing above missed six citations and re-broke one (its own +8
    lines moved the Bearer strip it had just fixed). Closed by mechanical sweep, not by eye.
  - *R3 proved the R2 fix rather than reading it.* It deleted `publish.yml`'s `test -f` line and
    confirmed `test_stubs_in_the_wrong_place_…` goes red **on the hole itself** (`1 skipped, 4
    deselected`), then restored it for 24 green. It also re-derived every citation independently
    rather than trusting this record. That is the standard a gate has to meet to be worth running.
  - *R3's eight, all records:* four citations the round-2 "mechanical" sweep had not covered — it
    read only explicit `path:line` and missed the bare `:line` form, which is where all four lived,
    one of them the `python` half of the very sentence whose `npm` half round 2 repointed. Two
    stale claims in the repo map that **this phase itself falsified** ("no workflow pins protobuf
    anywhere" — 17 hits now; and a `version-check` range widened until it contained the ancestry
    step it is cited for lacking). The anchor counts contradicting each other across the two
    records. One overstated docstring claim about the citation margin.
  - *Closing the phase here rather than running a round 4.* R3 found no code defect and confirmed
    the code by experiment; its findings were record hygiene, now fixed and re-verified
    mechanically against the files rather than by eye. Spending the next fresh-Opus gate on
    Phase 7 is worth more than a fourth pass over prose.
- **Next:** Phase 7 (`COMPATIBILITY.md` pass — known-bad band, CrewAI cross-link, #76).

### Phase 7 — `COMPATIBILITY.md` pass: the 0.7.39-0.7.43 band, the upstream link, #76 · 2026-08-31

- **Delivered:** §3 carries a third known-bad band (`COMPATIBILITY.md:134`) with the narrow
  condition, the root cause, 0.7.47 as the fixed release, and **both edges proven**; the crewai row
  (`COMPATIBILITY.md:227`) names the upstream PR that actually ends it; §2 gains a definition of
  what a compatibility-matrix cell asserts (`COMPATIBILITY.md:54-89`), which is #76's ask.
- **The band is 0.7.39-0.7.43, and round 1 of the gate is why.** I first wrote `≥ 0.7.40` with a
  paragraph arguing the lower edge was *unprovable* — "per-tag gencode is not recoverable from this
  repo", since the stubs are gitignored — and picked 0.7.40 from a publication cluster. **That
  premise was false.** The evidence is not in the tree, it is in CI: every tagged commit has a run,
  and `test_the_declared_floor_is_at_least_the_gencode_in_the_generated_stubs` *is* this defect.
  `v0.7.38` is **green**, `v0.7.39` is the first **red** (run `32557539171`, failing on that exact
  test with `protobuf-7.36.0` installed), 0.7.40-0.7.43 red the same way, `f68572f` green for
  0.7.47. Both edges proven; the hedge is deleted, not softened.
- **I searched the repo, found nothing, and concluded the evidence did not exist.** It did — one
  `gh run list` away. The error worth keeping is not the wrong version number; it is answering
  "can this be known?" from the working tree alone when the project's history is a queryable
  system of record.
- **The boundary is the buf *plugin* rolling, not the protobuf runtime.** v0.7.38's own green run
  installed protobuf 7.36.0 as its runtime and stayed green, because the gencode was still 7.35.x.
  Runtime and gencode move independently — which is the mechanism behind the whole defect class and
  is now stated in the document.
- **Five consecutive releases published on red CI** (0.7.39, .40, .41, .42, .43), over four days,
  each red on this test. Issue #52 names only the last. The gate existed and was failing the whole
  time; `publish.yml` never consulted it — which is exactly what Phase 6 closed.
- **The §3 preamble no longer rests on a claim the record contests.** My first amendment argued
  every band "fails loudly rather than quietly". Issue #52 says of this defect: *"the silent-skew
  shape, not a loud one: the install succeeds"* — and recommends a yank on that basis. Resting the
  disposition on loudness made load-bearing the one claim the cited issue disputes. It now
  distinguishes **silent at installation** (true, and why no consumer reported it) from **loud at
  use** (a `VersionError` on first import, so nothing runs against a mismatched gencode), and adds
  the two facts the yank argument did not have.
- **§2's definition was falsified by this document's own table.** It said a `compatible` cell means
  "a live gRPC call ran … in CI", but §4a's only `compatible` cells come from a **uv resolution
  probe** that opens no socket, and the live-gRPC job is *advisory* (`scripts/test_ci_gate.py:52`) —
  so a green pipeline is not evidence the lane ran. Publishing that to #76, to stop three repos
  contradicting each other, while contradicting a table 130 lines below, is the overstatement the
  same section condemns. Now scoped, with §4a explicitly asserting less.
- **The AC2 guard was vacuous, and the experiment is recorded.** Adding `"0.7.43"` to
  `test_retracted_claims.py`'s parametrize guards nothing: it is a substring check and 0.7.43
  already appeared in the file, so **the row could be deleted with all 557 tests still green**.
  Replaced with two real guards — one binding the row's shape plus the fixed release and the
  symptom, one asserting the row is contiguous with the table above it. Both proved falsifiable:
  delete the row → 2 red; insert a blank line before it → 1 red; restored byte-identically
  (`shasum` match) → 10 green.
- **That blank line was a real defect, not a hypothetical.** The row as first committed was
  preceded by an empty line, which terminates a GFM table — GitHub's own renderer (`gh api
  /markdown`) returned 3 `<tr>` and the band as a paragraph of literal pipes. It read fine in the
  diff. Now 4 `<tr>`, no leaked pipes.
- **Other round-1 corrections:** a `CHANGELOG.md:516-518` citation I added sat 3 lines from the
  `"No yank"` anchored needle, so it satisfied that guard on its own and would have masked the
  real citation rotting — removed with the hedge it belonged to. The "retracted one capability
  claim that arose exactly that way" line was `seam-adapters` describing *itself* in #76, quietly
  re-attributed to us; now attributed correctly. `README.md`'s ⚠️ block enumerated two bands and
  told readers "if you are pinned below 0.7.20, upgrade" — under-reporting for anyone on
  0.7.39-0.7.43; it now names the third band.
- **Citations, and the same mistake a third time.** The §2 and §3 rewrites moved everything below
  them, so both records were repointed by computed `difflib` map again. Round 1 of the gate still
  caught one bare `:64-68` the previous pass missed, and this round's remapper then missed a bare
  `:191` — because it scoped path-inheritance *per line* while the citations span a sentence that
  wraps. Explicit-vs-bare, then line-vs-paragraph: the same defect wearing a new hat each time. The
  verifying sweep scopes per paragraph and is what catches them; the remapper is now only trusted
  where the sweep confirms it.
- **Files:** `COMPATIBILITY.md`, `README.md`, `python/tests/test_retracted_claims.py` (+2 real
  guards), `PROGRESS.md`, `plans/post-adoption-hardening-and-acdp-readiness.md`.
- **Tests:** full python suite, `scripts/` gates, ruff — see the commit. The
  `<!-- PROBE-TABLE: -->` contract still parses 4 rows, columns and order unchanged.
- **Verify gate round 2 — GAPS(10), all closed. It confirmed round 1's ten by experiment** (five
  separate mutations of the row, each proving a guard fails for the reason it exists), **and found
  ten more.** Two mattered:
  - **`v0.7.43`'s CI was RED, and three places on this branch said it was green.** Phase 6's
    `DECISIONS.md` entry opened *"CI was green when it did… The green was honest"*, and
    `COMPATIBILITY.md` and `scripts/test_publish_gate.py` repeated it. All three runs at `ff0139a`
    are `failure`, on that exact floor test. `publish.yml:325-327` had it right the whole time
    ("a red CI at the tagged commit"), so the branch contradicted itself. **Phase 6's conclusion
    survives and its worked example does not:** there are *two* paths to shipping this defect —
    publish past a red gate (what actually happened, five times; `ci-green` closes it) and a
    genuinely green CI followed by a publish-time skew (**no release is known to have taken it**;
    that is what Phase 6's guards close). Conflating them made `ci-green` look insufficient for the
    wrong reason. All three passages now separate them.
  - **The rebuttal to #52 cited reasoning that does not exist.** `COMPATIBILITY.md` said
    "`DECISIONS.md` carries the full reasoning" — `DECISIONS.md` contains zero occurrences of
    "yank"; that is Phase 10's deliverable, still TODO. Present-tense assertion about content never
    checked: the same shape as round 1's critical finding, two commits later.
  - **I also inverted #52's own argument.** It cites "unlikely to be in anyone's lock yet" as a
    reason the blast radius of yanking is *small* — an argument **for** deleting. I presented the
    absence of locks as a no-yank fact. §3 now states #52's case in its own terms, including its
    crux ("untrue metadata is worse than honestly broken"), and answers it: the metadata is
    self-detecting, and the action #52 sized — one hours-old release — is not the action available,
    since the band is five.
  - **Smaller:** "that is how the defect survived five releases" attributed survival to install-time
    silence when the same section says a red gate nobody read is the cause; the probe was described
    as opening "no socket" when it is a live PyPI resolution (it makes no *gRPC* call); the plan's
    heading and AC1/AC2 still demanded the hedge and the `"0.7.43"` literal that round 1 replaced,
    making AC2 literally unsatisfiable; three repo-map rows still described the retracted Phase 7;
    `CHANGELOG.md`'s advisory named two bands while `README.md` now points there for three; and a
    row guard failed with a bare `StopIteration` carrying no message.
- **The bare-citation defect appeared twice more, making four distinct forms.** Round 2 found a
  `COMPATIBILITY.md:101-118` sitting alone in a paragraph, where paragraph-scoped inheritance
  resolves it against the *previous* paragraph's file — and it resolves there structurally, so
  nothing catches it. Then, fixing that, the remapper captured a `:194-256` that pointed at the test
  file, because a bare `COMPATIBILITY.md` appeared earlier in the row; and the parenthetical I wrote
  *explaining that hazard* named `COMPATIBILITY.md` again and re-captured the two citations after
  it. Explicit-vs-bare, line-vs-paragraph, subject-vs-target, and now the explanation capturing its
  own example. **The rule that actually holds: write the path explicitly and never rely on
  inheritance in a row that names another file.** Applied to row 81.
- **AC3/AC4 remain half-done on purpose.** The `COMPATIBILITY.md` half of each is complete; the
  replies on #48 and #76 are drafted and held until the PR exists, so they point at a landed
  paragraph. Carried into ship as an explicit step.
- **Next:** Phase 10 (`DECISIONS.md` yank disposition + the one-line `yank.yml` token-prefix fix),
  which closes PR 1.

### Phase 10 — The no-yank disposition, recorded; and `yank.yml` made to actually authenticate · 2026-08-31

- **Delivered:** a `DECISIONS.md` entry that makes the forward reference Phase 7 left dangling
  true; `yank.yml`'s credential resolution fixed (`.github/workflows/yank.yml:55-60`); and
  `scripts/test_yank_gate.py` (12 tests) wired into `workflow-guards`
  (`.github/workflows/ci.yml:585`).
- **Nothing was dispatched and nothing was deleted.** The scoping filters — exact version equality,
  the python+npm allowlist, the exact-name match keeping the org's Cargo crates unreachable — are
  byte-unchanged, and are now pinned by tests so that widening one is deliberate and visible.
- **The decision: document, don't delete.** The rule stated so it stops being re-litigated —
  *delete when a defect corrupts silently or is a security hazard; document when it fails loud* —
  turns on what a consumer can discover for themselves. This band raises `VersionError` at first
  import, naming both versions and the fix.
- **The entry argues with #52 instead of past it, which the plan did not ask for and needed.** The
  plan's four evidence lines all pointed one way, and one of them — "no consumer has it locked" —
  is a fact **#52 deploys in the opposite direction**: nothing locked meant, to it, that deletion
  was cheap. A week on the same fact inverts (anyone who installed it resolved `protobuf` freely
  and is working now), but presenting it as a settled no-yank point, as I first did in Phase 7,
  was wrong. The entry now states #52's case in its own words — including its crux, that untrue
  metadata is worse than an honestly broken wheel — and answers it: the metadata is
  **self-detecting**, caught by the very mechanism it is about, before any call reaches a runtime.
- **And the action #52 sized no longer exists.** It weighed deleting *one* hours-old release; the
  measured band is **five**. Its third option, re-release with a corrected floor, is already
  satisfied — 0.7.47 shipped the fix — so the only live question was whether to destroy the bad
  artifacts.
- **Evidence re-checked, not carried from the plan:** no lockfile anywhere in the workspace pins
  any version in the band (2026-08-31; the only `seam-sdk` entry in `seam-adapters/uv.lock` is
  0.7.9 via an editable path); v0.7.43's npm artifact is **healthy** (`@bufbuild/protobuf ^2.12.1`,
  a caret range with no analogue of Python's gencode gate), yet `yank.yml` deletes python and npm
  together with no format input — so running it as written would break registry lockstep for a
  defect only one language has.
- **The `yank.yml` bug was latent and fails closed, which is the argument for fixing it.** It
  resolved `${CLOUDSMITH_API_KEY:-$CARGO_REGISTRIES_ZER07LABS_TOKEN}` without stripping the
  `"Bearer "` the org Cargo token carries — a strip `.github/workflows/publish.yml:371` has always
  done. Cloudsmith 401s and `curl -sf` aborts before any DELETE, so no wrong deletion was possible;
  neither was the tool working *at all*, dry run included, unless the dedicated secret happened to
  be set. A safety tool that silently does not work is discovered during the incident.
- **The first draft of the fix was wrong, and executing it is what showed that.** Copying
  `publish.yml`'s `[ -z "$TOKEN" ] && TOKEN=…` one-liner into a step that runs under
  `set -euo pipefail` depends on the AND-OR exit-status rule — safe here, but by a rule most
  readers do not hold, and it becomes the step's status if ever moved last. Replaced with an
  explicit `if`, and tested across all eight credential shapes including "token is *only* the
  prefix" (strips to empty → refused, fail-closed preserved) and both variables unset (`set -u`).
- **The guards are falsifiable, proved three ways:** restoring the original one-liner → 5 red;
  widening the format filter → 1 red; flipping the `dry_run` default to `false` → 1 red. Each
  restored byte-identically (`shasum`) → 12 green.
- **Two stale citations found in my own Phase 6 entry while sweeping this one.**
  `scripts/test_publish_gate.py:322` and `:495` still resolved — to the wrong lines, after my
  later edits shifted that file. Resolution is not correctness; only reading the target catches it.
  Repointed to `:330` and `:510`.
- **`ASSUMPTIONS.md`:** Cloudsmith quarantine logged **UNCONFIRMED** — the one option the phase
  said was worth raising rather than settling unilaterally. It costs a working consumer exactly
  what deletion costs them and buys back only reversibility.
- **Files:** `DECISIONS.md` (new entry), `.github/workflows/yank.yml`, `.github/workflows/ci.yml`
  (one step in an existing job — `ci-ok`'s `needs:` unchanged), `scripts/test_yank_gate.py` (new),
  `CHANGELOG.md` + `COMPATIBILITY.md` + `python/tests/test_retracted_claims.py` (the "No yank"
  anchor shifted when Phase 7's advisory row landed), `ASSUMPTIONS.md`, `PROGRESS.md`, the plan. (*Not* `CHANGELOG.md` — an earlier draft of this line
  claimed it; the `"No yank"` anchor moved when Phase 7's advisory row landed in the preceding
  commit, and only the citations pointing *at* it were repaired here.)
- **Verify gate — GAPS(8), all closed. The blocking one was mine, and it is the third of its kind
  this run.** Two of `test_yank_gate.py`'s static assertions matched against the step's **raw**
  text, which includes comments — and the comment I added beside the token fix quotes
  `set -euo pipefail` verbatim. Deleting the real `set -euo pipefail` line left the file **12
  passed**. Deleting all three destructive-scoping filters from the jq chain and leaving them
  behind as comments also left it **12 passed**. The file already computed a comment-stripped
  list for one of its four static assertions and did not use it for the others.
  - Hoisted into `_code()`, with the reason recorded next to it so the next assertion added
    inherits it. The `set -e` check is now an exact **line** match, not a substring of the file.
    Proved both ways: delete the real line → 1 red naming it; comment out the filters → 1 red
    naming which filter moved; restored byte-identically → 12 green.
  - **The pattern across all three vacuous guards this run is one thing:** each matched a string
    against text that included the prose explaining the string. A guard a comment can satisfy is
    a search for a word someone wrote.
- **Second finding: this commit broke three of the plan's own citations** into `yank.yml`, in the
  section it was editing and marking DONE, because its `+19`-line divergence block shifted the file
  under them. Then, fixing those, I repointed them and *afterwards* expanded a `yank.yml` comment —
  shifting them again. Both passes are the same mistake: repoint before the target file is final.
  The rule now applied — **repoint once, last, with the cited file frozen.**
- **Third: a batched-write script silently discarded four fixes.** Three `DECISIONS.md` edits and
  one citation repoint printed `ok` and were never written, because the script wrote once at the
  end and a later match failed first. Re-applied with a write after *every* edit.
- **Fourth: nine literal `'\"'\"'` shell-quoting artifacts had leaked into `DECISIONS.md`** from
  the heredoc that wrote it. Repaired; the one remaining match in the repo (`ci.yml:297`) is
  legitimate quoting inside a `run:` block.
- **Substantive corrections from the gate, not just hygiene:**
  - *Fail-closed was overstated.* "A token that is only the prefix strips to empty and is refused"
    holds only when it is the **sole** credential; with a usable Cargo token it correctly falls
    through. Verified by executing the real step. Not a regression — the refused set is a strict
    superset of the pre-fix one — but the sentence was wrong, and the untested shape is now a
    parametrized case (13 tests).
  - *The rule's gloss contradicted the entry's own lead precedent.* I wrote that the distinction is
    "what a consumer can discover for themselves"; nineteen lines later the entry cites
    0.7.16-0.7.19, which failed with an *actively misleading* error and was still documented. The
    rule turns on **corruption and security, not diagnosability** — restated, with that precedent
    named as the reason diagnosability cannot be the line.
  - *#52's quote stopped one sentence before its rebuttal of my own lead argument.* It continues
    "That was the stated reason not to yank before, and it does not apply here." Restored in full
    and answered: it is **right** that "a floor already in wide use" does not describe this band —
    which is why `COMPATIBILITY.md:101-128` scopes that limb to the first two — and the precedent
    bullet turns on defect severity, which the objection leaves untouched.
- **What the gate confirmed:** all 12 original guards killed by 14 mutations except the two above;
  the destructive scoping byte-identical to HEAD~1 (it split both revisions at the token block and
  hashed the remainder); no credential shape proceeds with a malformed token where it previously
  refused; `ci-ok`'s `needs:` and `ADVISORY` unchanged; every factual claim in the entry
  independently re-derived, including the workspace-wide lockfile check over 23 lockfiles.
- **Next:** PR 1 (Phases 6, 7, 10) — then the #48/#76 replies, which have waited for it.

---

### PR 1 shipped, and the spec block cleared · 2026-08-31

- **[#79](https://github.com/zer07labs/seam-sdk/pull/79) merged** (Phases 1, 6, 7, 10) after
  [#80](https://github.com/zer07labs/seam-sdk/pull/80) unblocked it.
- **The `spec pin` red was not ours.** It was pre-existing on `main` — runs `33457207859`
  (`fbfff431`) and `33428449877` (`fa32409f`) both failed with exactly `spec pin` + `ci-ok`; the
  green runs on those SHAs are other workflows (Dependabot, release). The `python` failure on
  `33458058107` was a transient BSR outage at `buf generate` ("the server hosted at that remote is
  unavailable"), and the same job passed on `33458028677`; it cleared on re-run.
- **Merging past it was available and was not taken.** `main` is governed by a ruleset, so
  `gh pr merge` refused and offered `--admin`. Overriding a red gate is the precise failure this
  plan's Phase 6 exists to stop, so the gate was fixed instead — even though the red predated the PR.

### Phase 9 (spec half) — the vendored spec refreshed for ACDP P1a and P2 · 2026-08-31

- **The block is gone, and it went quietly.** Phase 9 was written as BLOCKED on runtime work
  "committed at `533f218` on an unpushed branch". That branch has since merged: `7c1d16d` (P1a
  receipt slots, #520, 0.7.69) and `3b3d4ae` (P2 `retraction`, #523, 0.7.70) are on runtime `main`,
  the spec is published, and the BSR serves `ContextBinding` tags 7–11 — verified by decoding the
  module's `FileDescriptorSet` rather than inferred from the commit titles.
- **Delivered:** `verify/docs/seam-event.v1.md` re-pinned `5d8c177` → `3b3d4ae` (+125/−28),
  whole-file and byte-verbatim; `check_vendored_spec.py` passes integrity, reachability and currency
  through **both** backends, including `--from gh`, the one CI uses.
- **Checked rather than assumed:** every `§section` that `verify/src/verify.rs` and `wire.rs` cite by
  name survived the refresh as a heading. `DECISION_SEALED` is not a heading — but it was not one at
  the old pin either, so that loose reference is pre-existing, not a regression.
- **Two citations repointed, one of them twice.** `DECISIONS.md` → the spec moved `:381-382` →
  `:388-389`. `COMPATIBILITY.md` → `CHANGELOG.md` moved `:521-526` → `:538-543` on #80, and the
  merge into #79 — which had independently moved it to `:523-528` — landed it at `:540-545`. Git
  merged the changelog cleanly and left the citation pointing at neither branch's answer; only
  re-deriving it from the merged file gets it right.
- **The regeneration half is deliberately NOT done.** CI regenerates from the BSR on every run, so
  #79 and #80 both went green with all five new fields already in the stubs and no gate noticing.
  That is Phase 5's subject exactly; regenerating before the manifest exists would adopt the fields
  silently and waste the tripwire.

### Phase 8 — Vendored files are quoted, never line-anchored (issue #73) · 2026-08-31

- **Converted, not grandfathered.** The plan allowed either and flagged that grandfathering leaves
  Phase 9's refresh free to drift the anchor again. Since Phase 9's regeneration half is still ahead
  and refreshes that exact file, converting is the only choice that actually makes the ordering mean
  something.
- **The guard fires on real content, not only on a fixture.** Before converting `DECISIONS.md`, the
  suite went red on the live document —
  `test_no_document_line_anchors_into_a_vendored_file[DECISIONS.md]` plus the new `QUOTED` check —
  so acceptance 1 is demonstrated against the repo's own prose, not just a synthetic string. The
  synthetic red-first test remains, with negative controls proving the rule leaves the two
  sanctioned alternatives (a `seam-runtime/`-prefixed citation, a bare quoted path) alone. A rule
  that rejected those too would leave vendored quotes with nowhere legal to go, which is how a
  check gets deleted under deadline.
- **Coverage is traded, not increased — the verify gate corrected me on this.** My first write-up
  said "strictly more than the line anchor checked", which is false: the line-position claim is
  genuinely dropped. `QUOTED` asserts the needle is unique in the target, that the document quotes
  it verbatim, and that the attribution sits within two lines of the quote. The gain is that the
  document's own words are now checked against the source — which `ANCHORED` never did, it only
  checked where the citation pointed. The trade is worth taking only because the dropped half is
  exactly the half a whole-file refresh makes unkeepable; against a file this repo edits itself,
  `ANCHORED` stays the right mechanism.
- **Citation floors after the conversion:** COMPATIBILITY.md 27, DECISIONS.md 55, floor 10 each.
  Acceptance 4 holds with wide margin. (DECISIONS.md gained four: the registry-consistency test,
  and the three rotted bare-shorthand references made visible — see below.)
- **The adjacent case is recorded, not fixed.** COMPATIBILITY.md's "No yank" citation into
  `CHANGELOG.md` has held **eleven distinct values since 2026-08-23**, the last six on 08-31 alone
  — identical zero-information churn, different cause: an append-only file rather than a refreshed
  one. It took three attempts to state that correctly: the first omitted `:523-528` while still
  calling the chain five repoints; the second said "twelve since 08-24", having counted a
  *different* CHANGELOG citation that a last-match grep swept in. Third measured properly, across
  `git rev-list --all`, matching the citation rather than taking the last one on the line. The plan scopes Phase 8 to vendored files and #73 has not decided whether
  the rule should widen, so it stays the open half rather than being silently converted.

- **Every count in this phase was remembered rather than measured, and every one was wrong** —
  including my corrections of them. Two verify rounds were needed to land the history:
  - "Three times in one session" → **five repoints over six days**, and the introduction was PR
    **#58**, not #63.
  - "One repoint per refresh" → **six refreshes, five repoints**. The missing one is the finding:
    **#63 refreshed the vendored copy, moved the sentence five lines, did not repoint the citation,
    and merged** — `DECISIONS.md` did not come under the citation test until #67. A citation sat on
    `main` pointing at a plausible wrong line, indistinguishable from a correct one. That is the
    actual failure; the churn was only its symptom, and three successive drafts undercounted the
    same evidence.
  - `ANCHORED` has **eight** entries, not nine. The CHANGELOG chain, three attempts, above.

  The lesson is the phase's subject applied to itself: walk `git log`, never recall. The measured
  table now lives in the `VENDORED` comment, with the merged-stale row called out.

- **A third route to "looks checked", found in the paragraph this phase rewrote.** `DECISIONS.md`
  carried three bare-shorthand references — `` `:878` ``, `` `:843-875` ``, `` `:841` `` —
  continuing a full path given earlier in the same sentence. `CITATION` requires a path, so a bare
  `:N` matches nothing: they were never resolved and never content-checked. **All three had rotted,
  by 5 to 66 lines** — `:878` was cited for an assertion that lives in a different test; `:843-875`
  was cited as a per-column parametrization and is a comment block. The substance was right and
  every pointer was wrong. Repointed with full paths (they are now checked, hence the count rising
  to 55), and the class — a citation opting out of checking by being written unusually — recorded
  on #73 alongside `COMPATIBILITY.md`'s comma-list form.

- **`VENDORED` names a file, not the `verify/docs/` directory** — the first draft used the directory
  prefix, which would have forbidden line anchors into `audit-anchor.md` and
  `erasure-certificate.v1.md`, both **authored here** and deliberately excluded from
  `scripts/check_vendored_spec.py`'s registry. That is the exact case the decision argues should
  stay line-anchored. A new test asserts this file's set equals that registry, on the repo's own
  stated principle that a value stored twice must not be able to disagree with itself.
- **The attribution assertion was too weak on the first pass, and the commit that made the claim
  is what weakened it.** `assert f"`{path}`" in doc_text` searched the whole document, and this
  phase's own decision record added a second backticked mention of the same path — so deleting the
  real attribution line left the test green with an orphaned quote. Now windowed to ±2 lines of the
  quote, and verified by deleting DECISIONS.md's attribution line ("quoted verbatim from
  `verify/docs/seam-event.v1.md`") and watching it go red before restoring the file.

- **Full python suite: 611 passed, 17 skipped** — 606 at first commit; the two verify rounds added
  a registry-consistency test and four newly-visible citations. Run whole, never a subset — the doc
  guards scan every `*.md` including this file.

### Phase 2 — The two cross-repo asks, written and **filed** · 2026-08-31

- **The "do not file" restriction was lifted mid-run** by the user. Both asks are now real issues:
  [seam-runtime#525](https://github.com/zer07labs/seam-runtime/issues/525) and
  [seam#26](https://github.com/zer07labs/seam/issues/26). No file outside `seam-sdk` was written —
  `git -C ../seam-runtime status --short` and `git -C ../seam status --short` are unchanged.
- **Ask A was re-scoped, not transcribed.** As drafted it asked the runtime to publish the encodings
  and push the contract — all of which had already shipped. Filing it verbatim would have asked for
  finished work. What is actually outstanding is three pieces of coordination: (1) the tracking issue
  their own plan says "must be filed, not forgotten" (`plans/acdp-p1a-receipt-slots.md:290-291`,
  repeated at `plans/acdp-p2-retraction.md:1009`) and which a search of all issue states shows was
  never filed; (2) sequencing the `sdk-digest-parity` un-pin, since `crates/seam-client/examples/*`
  are pinned all-`None` against **our** committed `conformance/vectors.json` and un-pinning turns a
  *required* job in their repo red, fixable only from here; (3) a heads-up when the spec changes.
- **Ask A's third point is evidenced, not hypothetical** — it fired during this run and cost the time
  documented above.
- **The plan's `COMPATIBILITY.md:203-262` anchor for Ask B was fine; my check of it was not.** I
  read it off a branch based on `main` *before* #79 merged, saw commitment-digest text at that line,
  and recorded the anchor as stale. At `20786dc` line 203 is exactly
  `### Agent-framework co-installability` (the section runs `:203-264`). The plan was right.
  Both asks cite the **heading** anyway — a file that moves should not be cited by a number, which is
  Phase 8's whole point, and this is a clean demonstration of why: the error was not in the anchor,
  it was in reading it against the wrong tree. The filed `seam#26` carries no line numbers at all,
  so nothing published needed amending.
- **Every runtime anchor was re-verified before filing**, against `f4e105f` / spec `3b3d4ae`:
  `p1a:103-107`, `:290-291`, `:439-441`, `p2:1009`, runtime `ci.yml:186` (`buf push`), `:299`
  (`sdk-digest-parity`), `sdk-digest-parity.sh:40,51,55`. Ask B's: `seam` `01-…:110`, `04-…:14`.
- **Next:** Phases 3, 4, 5 → PR 2; Phase 8 → PR 3; then Phase 9's regeneration half.

### Phase 3 — `collective_outcome` readable off a `SessionStep` · 2026-08-31

- **The plan's premise was verified, not assumed.** A probe file calling `collectiveOutcomeOf(step)`
  was compiled *before* any change and produced exactly the predicted
  `TS2345: Argument of type 'SessionStep' is not assignable to parameter of type 'DecisionResponse'`.
  The `resp.decisionId ?? ""` coalesce was also required exactly as predicted, because `decisionId`
  is required on `DecisionResponse` and `optional` on `SessionStep`.
- **Delivered:** a union signature in both languages — `Union["pb.DecisionResponse", "pb.SessionStep"]`
  and `DecisionResponse | SessionStep` — one decoder, not a per-message twin. 6 new Python cases,
  7 new TS cases.
- **The new tests were proven non-vacuous by mutation, not by passing.** Python already accepted a
  `SessionStep` by duck typing, so the new tests pass *without* the change and passing proves nothing.
  Two mutations were run: (a) unknown verdict returns `"APPROVED"` instead of raising → 6 red,
  including 2 of the new SessionStep cases; (b) the absent-field branch made unreachable → 4 red,
  including 2 new ones. In TS the fail-open mutation reddened 6, three of them new. Restored and
  re-verified green after each.
- **A finding for Phase 8.** `COMPATIBILITY.md`'s citation into `CHANGELOG.md` ("No yank") was
  repointed for the **third** time this session — `:521-526` → `:538-543` → `:540-545` → `:563-568`.
  Every changelog entry moves it, so the citation is structurally fragile in the way Phase 8 is about,
  even though the target is not a vendored file. Phase 8 should cover it.
- **Gates:** python 574 passed/17 skipped · ts typecheck + build OK, 112 passed/0 failed ·
  go ok · verify 9 suites ok · scripts 81 passed · `STREAM=1 EVENTS=1 check-contract` exit 0 ·
  ruff clean.

**Fresh-Opus verifier: PASS**, with seven advisories. Five were acted on in a follow-up commit; two
are recorded rather than fixed.

- **Acted: two brand-new cross-repo line anchors, in shipped source.** The same commit that logged
  anchor fragility as a Phase 8 finding introduced `seam.proto:461-465` citations into
  `_collective.py` and `client.ts` — a line range into a sibling repo's file that this repo neither
  tracks nor gates, which is a worse case than the one being logged. Both now cite
  `SessionStep.collective_outcome` **field 4** by name. A field number cannot rot; a line number can.
- **Acted: four docs under-described the widened surface.** Most materially, both error classes
  (`errors.py`, `client.ts`) still said "`DecisionResponse.collective_outcome` carried …" while the
  identical error now raises off a `SessionStep`. The plan scoped Phase 3's docs to `CHANGELOG.md`,
  so this was not a criterion miss — it was true drift, and it is fixed.
- **Acted:** the repo map's own rows still described Phase 3 in the future tense; the TS `step()`
  helper re-spread `state`, making its default dead whenever a caller passed one.
- **Recorded, not fixed — nothing type-checks Python.** There is no `mypy` or `pyright` config
  anywhere in this repo. So the Python half of this phase's contract, the `Union[...]` annotation, is
  enforced by **nothing**; only the runtime tests hold it. TypeScript is genuinely gated by `tsc`.
  The commit message's "the accident is now a declared contract" is therefore true of TS and
  aspirational of Python, and saying so is more useful than quietly leaving the asymmetry implied.
- **Recorded:** one new test per suite is structurally un-reddenable — the
  step-vs-response parity case survives every mutation, because both sides call the same code. That
  is correct for a guard against a *future* per-message branch, but it should not be counted among
  the load-bearing cases. The other five (Python) and six (TS) are proven load-bearing.
- **Correction to the Phase 3 commit message:** it reports the Python unknown-verdict mutation as
  "6 red (2 new)". The verifier measured 6 red with **3** new. Under-counted, not over-claimed.

### Phase 4 — #50 closed against evidence; README and CHANGELOG made true · 2026-08-31

- **The BSR probe was possible, so the fallback was not used.** The phase allowed for
  `buf registry login` being unavailable and for stamping a disclaimer instead. `buf` was
  authenticated: the module commit is re-probed at `4bf014bd5b194010b569ec6bbc006d60`, read
  immediately **before and after** the descriptor build and unchanged both times, so the stamp and
  the surface it describes come from one module state rather than two moments either side of a push.
  The descriptor was byte-identical to an independent pull made earlier in the session.
- **`buf breaking … --config FILE` against the previously recorded probe exits 0** — re-derived, not
  inherited from the line above it in the README.
- **#50's substantive item checked out.** `EvaluationRequest.confidence` is `proto3_optional=True` on
  the live descriptor, and all three client layers map an omitted value to field-absent with an
  explicit *"NEVER default it to 0.0"*. `rationale_ref` (field 7, also optional) is exposed too,
  though the issue never asked for it.
- **A correction recorded in the close comment:** #50 names `EvaluationPayload.confidence`. No
  `EvaluationPayload` message exists in `seam.api.v1`; the field is `EvaluationRequest.confidence`
  (field 5). The behaviour asked for was right, only the name was wrong — and the plan specifically
  warned not to restate that framing in a doc.
- **The `recommendation` vs `evaluation` divergence is recorded as deliberate**, so a future reader
  does not "correct" the SDK into disagreeing with the proto it is generated from.
- **The README now also states what the SDK has *not* adopted** — `ContextBinding` tags 7–11 are on
  the contract and absent from this repo's field-level expectations. Saying so in the surface
  blockquote is what keeps Phase 9's regeneration from looking like an oversight.
- **The `No yank` citation was repointed a fourth and fifth time** (`:563-568` → `:586-591`), and a
  `README.md` citation moved `:128` → `:147`. Every changelog or README edit moves them. Phase 8.
- **Gates:** python 574 passed/17 skipped · ruff clean.

### Phase 5 — the field manifest, and the tripwire firing for real · 2026-08-31

- **Both extractors agree at 223 on the local stubs — exactly as planned.** 65 top-level messages,
  zero diff in either direction, and all four canaries present: `ResumeRequest/raise`,
  `AdminResumeRequest/raise`, `AuditEntry/seq`, `AuditEntry/decision_id`. The plan's two hazards were
  confirmed live before being coded around: `RAISE_FIELD_NUMBER` appears twice in the `.pyi` while
  `"raise"` appears in **no** `__slots__`, and the synthetic `FeaturesEntry` classes are distinguishable
  from the real top-level `AuditEntry` by indentation alone.
- **The committed manifest is 228, not 223 — and that divergence is the phase's main finding.** The
  plan measured the surface before ACDP P1a/P2 reached the BSR. CI runs `make generate` from the BSR
  (`.github/workflows/ci.yml:108`) and *then* the gate (`:122`), so CI sees 228. Committing 223 would
  have meant knowingly-red CI on every job.
- **The tripwire was made to fire on the real fields before they were adopted**, against temporary
  stub copies carrying them. Verbatim, exit **6**:

```
ERROR: the generated FIELD surface disagrees with contract/field-manifest.txt:
  NOT IN THE MANIFEST, present in the python stubs (a new field landed):
    + ContextBinding/content_hash
    + ContextBinding/key_status
    + ContextBinding/receipt_hash
    + ContextBinding/resolved_status
    + ContextBinding/retraction
  NOT IN THE MANIFEST, present in the ts stubs (a new field landed):
    + ContextBinding/content_hash
    + ContextBinding/key_status
    + ContextBinding/receipt_hash
    + ContextBinding/resolved_status
    + ContextBinding/retraction
```

  Each language named it independently, which is the property that makes a stale `ts/gen` beside a
  fresh `python/_gen` visible. Only then were the five adopted, with the decision written into the
  manifest header: **declared, deliberately not interpreted** — carried on the generated type, never
  read, and neither status vocabulary re-spelled. Wiring them is Phase 9.
- **Known and stated: a bare local `check-contract` now exits 6 on this machine.** The local stub tree
  predates ACDP by exactly those five fields, so the gate reports them as MISSING and says
  "stale/partial generation" — which is **true**, and is the gate working. CI, which regenerates
  first, is the authoritative run. Running `make generate` locally would reconcile it; that was not
  done here because this session is under a standing instruction not to, and the instruction was not
  worth reasoning around when CI verifies the same thing in minutes.
- **The tests do not depend on any of that.** `python/tests/test_field_manifest_gate.py` (14 tests)
  drives the **real** script against manifests it writes itself into `tmp_path`, so it is correct
  whether a developer's stubs are fresh or stale. Four paths became env-overridable
  (`SEAM_PY_GEN`, `SEAM_TS_GEN`, `SEAM_FIELD_MANIFEST`, `SEAM_RPC_MANIFEST`) purely so a test can never
  write to the real manifests or corrupt the **gitignored** stub trees — which git could not restore.
  Verified: with both overridden, `--write-manifest` left both real manifests byte-identical.
- **`--write-manifest` writes both manifests**, so there is one escape command to document rather than
  two, and `contract/rpc-manifest.txt` came back byte-identical (42 RPCs, empty `git diff`).
- **No CI job was added**, so `ci-ok`'s `needs:` is untouched and `scripts/test_ci_gate.py` still
  passes (13 tests) — the gate rides inside the existing `check-contract` step in both language jobs.
- **Gates:** python 594 passed/17 skipped · scripts 81 passed · ts typecheck OK, 112 passed ·
  ruff clean · gate exit 0 against the BSR-shaped surface, exit 6 against the stale local one.

**Fresh-Opus verifier on Phase 5: GAPS** — all 8 acceptance criteria substantively met, both contested
claims independently confirmed (it decoded the BSR descriptor by a third path and got
`IDENTICAL — committed manifest == BSR surface exactly`, with the local tree exactly 5 fields stale).
Seven of eight findings are fixed here; one is informational.

- **G3 — the TS extractor had no nesting exclusion at all; it MISATTRIBUTED.** The header and the
  `DECISIONS.md` entry both claimed the exclusion was "structural". That was true of the Python awk
  only. `Message<"seam.api.v1.[A-Za-z0-9_]+">` cannot match a nested `...Outer.Inner` (the dot), so
  `cls` silently retained the **previous top-level message** and the nested type's fields were
  attributed to it. Python drops them, TS invents them on the wrong owner — red in both directions and
  unclearable by a Python-authoritative escape, which is the exact failure shape the header claims to
  have eliminated for `raise`. Latent only because protobuf-es emits no type for map entries, which is
  an accident of this contract, not an exclusion. Fixed with an explicit nested arm, pinned by a test
  that lifts the real `fields_ts` out of the shipped script rather than retyping it.
- **G4 — a non-snake_case proto field split the two extractors, unclearably.** Confirmed by the
  verifier with real `protoc --pyi_out`: `string myField = 1;` emits `MYFIELD_FIELD_NUMBER`, so the
  Python side can only ever produce `myfield` while protobuf-es yields `myField`. Both sides now fold
  case — a no-op for all 228 fields today. Note the two hazards have **opposite** fixes: `__slots__`
  would carry `myField` correctly and drops `raise` entirely.
- **G5 — `sort` was unpinned, so the "reviewable one-command diff" churned by locale.** Under
  `en_US.UTF-8` the escape reordered eight lines with zero contract change. The verdict was never
  affected (both sides re-sort at compare time), but that is not the reviewable diff the plan requires.
  `LC_ALL=C` pinned in both extractors and the manifest reader; re-verified under `en_US.UTF-8`, the
  regenerated body now differs by exactly the five expected lines and nothing else.
- **G1/G2 — four `DECISIONS.md` citations were wrong, and one pointed at a blank line.** Self-inflicted
  and instructive: I recorded them, then ran `ruff format`, which reformatted the test file and shifted
  every line under them. The repoint discipline exists precisely for this and I broke it. All are now
  repointed **once, last, against frozen files**, and each was checked for *content*, not just
  resolution — which caught a fifth landing inside a string literal. The citation guard cannot catch
  this class: for a non-anchored citation it only checks that the file exists and the line is in range,
  so a blank line passes.
- **G6** — the refusal printed both direction explanations regardless of which fired; now conditional.
- **G7** — `--write-manifest` preserves the header by grepping the file it overwrites, so a *deleted*
  manifest regenerated headerless with only four of criterion 1's items guarded. A new test pins all
  ten needles, and runs **without stubs** so a header regression cannot hide behind a missing
  `make generate`.
- **G8 — the file-level `skipif` meant all 14 tests could skip and pytest would exit 0** — the same
  "skip reads as green" shape this repo already had to fix once, and which I had flagged myself in the
  Phase 6 note. The skip moved into the fixture, so the three tests that need no stubs now always run.
- **Informational, not fixed:** a brand-new message with **zero** fields is invisible to both manifests
  (fields are the unit); `PY_GRPC` is not env-overridable, so `--write-manifest` still needs the real
  `_gen` tree even with both manifests redirected.

Post-fix: python **600 passed**/17 skipped · scripts 81 · ruff clean · gate exit 0 against the
BSR-shaped surface. No workflow sets any `SEAM_*` override (verifier checked independently).
