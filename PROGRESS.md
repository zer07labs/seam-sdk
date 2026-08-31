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
| `python/seam_sdk/_collective.py:83` | `collective_outcome_of(resp: "pb.DecisionResponse")` — fail-closed decode. **Phase 3** widens to accept `SessionStep`. `:1-30` documents why raw field access is unsafe (optional presence + `UNSPECIFIED` == 0 ⇒ a naive negative test allows on every unknown value). |
| `ts/src/client.ts:202` | `collectiveOutcomeOf(resp: DecisionResponse)` — the TS twin. **Phase 3.** Needs a real union: protobuf-es brands messages, so passing a `SessionStep` is a *compile error* today (reproduced: `TS2345`, `$typeName` mismatch). `:144-146` `UnknownCollectiveVerdictError(rawValue, decisionId: string)` — **required** `string`, so `:207`'s `resp.decisionId` must become `resp.decisionId ?? ""` once the parameter is a union. |
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
| `.github/workflows/yank.yml` | `workflow_dispatch`, `dry_run` default `"true"`. A hard **DELETE** (`:69-70`), not a PyPI-style yank. `:38` does **not** strip the cargo token's `"Bearer "` prefix (`publish.yml:369-371` does) — **Phase 10** fixes that one line and nothing else. |
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
