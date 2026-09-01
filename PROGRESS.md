# PROGRESS — `plans/post-adoption-hardening-and-acdp-readiness.md`

Checkpoint trail and repo map for the post-adoption hardening / ACDP P1a readiness workstream.
`/implement` writes a block per phase; a resumed run reads this instead of re-scanning the repo.

**Plan:** [`plans/post-adoption-hardening-and-acdp-readiness.md`](plans/post-adoption-hardening-and-acdp-readiness.md)
— 10 phases. (Phase 9 was BLOCKED on `seam-runtime` ACDP P1a Phases 4 and 6 when this plan was written; both merged 2026-08-31 and it is now DONE.)

**Execution order ≠ numbering:** 1 → 6 → 7 → 10 → 3 → 4 → 5 → 2 → 8. **Phase 6 runs immediately after
Phase 1** per its own Sequencing block: it depends on nothing and is the only phase guarding a hazard that
fires on every release — and releases follow the runtime, five in the three days to 2026-08-31, with zero
floor/gencode headroom. Phase 1 cannot yield to it because it syncs the checkout and establishes this file.
Phase 9 was not attemptable when this was written; the upstream merges on 2026-08-31 unblocked it and it is DONE.

**PR strategy — 3 PRs.** Chosen over one big PR because the phases have genuinely different review
audiences, and over one-PR-per-phase because several phases are too small to review alone.
1. **Phases 1, 6, 7, 10** — publish integrity + tracking state. Ships first: it carries the only
   actively-firing hazard.
2. **Phases 3, 4, 5** — the unwired field, closing #50, and the gate that missed it. One story;
   splitting the instance from the class would make each half look smaller than it is.
3. **Phases 2, 8** — the cross-repo asks (drafted unfiled, filed once the restriction below was
   lifted mid-run — see Phase 2's log entry) and the vendored-citation guard.

**Scope restriction (user-set, 2026-08-31):** seam-sdk only, at plan time. No writes and no issue
actions in any sibling repo. Under this restriction, Phase 2 wrote its asks and would have left them
**UNFILED** — recorded again in that phase's log entry so the gap would stay visible. **The
restriction was lifted mid-run by the user**, and both asks were filed:
[seam-runtime#525](https://github.com/zer07labs/seam-runtime/issues/525) and
[seam#26](https://github.com/zer07labs/seam/issues/26) — see Phase 2's log entry below for the full
filing record. This line is corrected, not deleted, because the disagreement already cost something
real: the audit brief that produced `plans/gate-blindness-hardening.md` asserted the asks were left
unfiled, reading it from this header rather than from Phase 2's log.

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
| `ts/src/client.ts:218` | `collectiveOutcomeOf(resp: DecisionResponse | SessionStep)` — the TS twin. **Phase 3 DONE.** It needed a real union: protobuf-es brands messages, so passing a `SessionStep` is a *compile error* today (reproduced: `TS2345`, `$typeName` mismatch). `:146-151` `UnknownCollectiveVerdictError(rawValue, decisionId: string)` — **required** `string`, so `:229`'s `resp.decisionId` became `resp.decisionId ?? ""`; a verifier mutation removing that coalesce reddens a test, so it is load-bearing, not decoration. |
| `ts/gen/seam/api/v1/seam_pb.ts` | Branded `SessionStep = Message<"seam.api.v1.SessionStep"> & {…}` — the reason Phase 3's TS half is a hard block, not a typing nicety. Also carries `collectiveOutcome?` on the same branded type. Cited by symbol, not by line: this is a generated, gitignored file, and a line number into it is correct only until the next `make generate`. |
| `python/seam_sdk/_gen/seam/api/v1/seam_pb2.pyi:289,297` | `SessionStep.collective_outcome` in the Python stubs — generated, never surfaced. |
| `python/seam_sdk/client.py:541`, `ts/src/client.ts:779` | `submit_commit` / `submitCommit` return a `SessionStep` — the caller Phase 3 exists for. |
| `python/tests/test_collective_outcome.py`, `ts/tests/collective_outcome.test.ts` | `DecisionResponse` cases only. **Phase 3** adds the `SessionStep` cases (absent ⇒ none; `UNSPECIFIED` ⇒ raise; unknown ⇒ raise; non-commit step ⇒ none). Drive red first. |
| `python/seam_sdk/client.py:473` + `python/seam_sdk/client.py:514` · `python/seam_sdk/aio.py:371` + `python/seam_sdk/aio.py:412` · `ts/src/client.ts:726` + `ts/src/client.ts:762` | `submit_evaluation` / `submit_objection` — **already delivered** by `c49d005`. Do not re-plan. Written as six separate citations rather than three comma-lists, because a comma-list matches `CITATION` **not at all**: `` `…:723,759` `` was wrong twice in a row — once before this phase and once *inside the commit whose message claims it shifted every citation below `:239`* — and nothing ever said so. |
| `python/seam_sdk/client.py:506-507` · `python/seam_sdk/aio.py:404-405` · `ts/src/client.ts:748` | `confidence` presence mapping — `None` ⇒ field-absent, never `0.0`. Correct in both languages; pinned by `python/tests/test_evaluation_confidence.py:55,64,87,100` and `ts/tests/evaluation.test.ts:59,70,85,93`. |
> **Read every row below as *as at plan time*, 2026-08-31, unless the row says otherwise.** Some
> were updated mid-run and some were not, which is worse than either — an unstamped map invites a
> reader to treat a stale row as current. The rows known to have moved since are corrected inline.

| `python/seam_sdk/_authorize.py:180,223` | `AuthorizeRequest.subjects` — one shared builder feeds sync + aio + TS. Delivered; tests at `python/tests/test_authorize.py:637,646`. |
| `scripts/check-contract.sh` | The contract-freshness gate. `:192` probe 1 (one named RPC) · `:196-210` probe 1b and `:212-226` probe 1c (hardcoded names; 1b includes **two `seam.api.v1` field names**, `call_sig` and `on_behalf_of`, at `:205-206`) · `:228-241` probe 2 (**exactly four hardcoded field names, all on `seam.event.v1`**; `STREAM=1` hardens) · `:242-247` probe 3 (`EVENTS=1`) · `:249-275` probe 4 (RPC set comparison, both directions). Every field probe names a *pre-existing* field, so **a new message field is invisible to all of them — that is the hole Phase 5 closes.** Extractors to mirror: `:158-161` `rpcs_python` (greps `_pb2_grpc.py`), `:163-166` `rpcs_ts` (greps `@generated from rpc`), `:173-188` `--write-manifest` (**writes from Python only**, preserves the header verbatim), `:88-97` the exit-3 no-stubs guard. |
| `contract/rpc-manifest.txt:60-61` | Declares `SubmitEvaluation`/`SubmitObjection`. The model Phase 5 mirrors one level down. |
| `contract/field-manifest.txt` | **Phase 5 creates.** Whole-surface `seam.api.v1` field declaration (measured: **223 fields over 65 messages** — both extractors agree exactly, given the `_FIELD_NUMBER` rule in the row below), set-compared per language both directions, `--write-manifest` escape. Also the ACDP tags-7-10 tripwire. **As shipped: 228, not 223** — the plan measured the surface before ACDP reached the BSR. |
| `python/seam_sdk/_gen/seam/api/v1/seam_pb2.pyi:106,163` | `AuthorizeRequest.FeaturesEntry` / `RunDecisionRequest.FeaturesEntry` — **synthetic map-entry messages Python emits and protobuf-es does not**. Phase 5's extractors must exclude them **by nesting, not by the `*Entry` name** — `AuditEntry` (`:716`) is a real top-level message. `.pyi` carries **no `oneof` grouping at all** (and `seam.api.v1` has zero `oneof`s). |
| `python/seam_sdk/_gen/seam/api/v1/seam_pb2.pyi:409,418` | **`__slots__` is NOT the field list.** `ResumeRequest`/`AdminResumeRequest` carry a proto field named `raise`; the `.pyi` generator cannot emit a Python keyword, so `__slots__` omits it and only `RAISE_FIELD_NUMBER` (`:412`, `:424`) survives. Measured: `__slots__` = 221 fields, protobuf-es = 223. **Phase 5 must extract from `<NAME>_FIELD_NUMBER: _ClassVar[int]` lowercased** — that reconciles both sides at 223 with zero diff. |
| `contract/wire-framing.json:31-33` | `_comment`: a bump is **NOT** for an additive proto field or a new RPC verb. Do not touch it for ACDP. |
| `.github/workflows/publish.yml:316` | `make generate` **again at publish time**, against unpinned plugins — the open half of #52. `:390-401` pre-upload smoke installs protobuf *unconstrained*, so the skew is invisible to it; `registry-smoke` (`:519`) likewise. Measured at planning: `grep -rn protobuf .github/workflows/` yielded **one** hit, a prose comment — no workflow pinned protobuf anywhere, so nothing caught the skew. **Phase 6 closed that** (DONE 2026-08-31): the same grep now yields 17, and `.github/workflows/publish.yml:423` installs the built wheel with `protobuf==$FLOOR`. The declared floor and the emitted gencode are both **7.36.0** (`python/pyproject.toml:50`, `python/seam_sdk/_gen/seam/api/v1/seam_pb2.py`'s `Protobuf Python Version` header — cited by symbol, not by line, since it is a generated, gitignored file) — zero headroom, which is why this phase ran first. |
| `.github/workflows/publish.yml:63-148` | `ci-green` — resolves every `ci-ok` conclusion for the tagged commit. Sound: `:107` still-running ⇒ `pending`, `:117-126` one-green-cannot-mask-one-red, `:143-148` timeout is a refusal. `:192`/`:285` gate both npm and python. **Must not regress.** |
| `.github/workflows/publish.yml:150-188` | `version-check` — tag vs in-tree versions. It had **no branch-ancestry check** (`.github/workflows/ci.yml:19` runs on every branch push, so a tag at a green feature-branch commit published cleanly); **Phase 6 added one at `:176`**, which is inside this row's own range. Read the range as the job, not as evidence of the gap — it was widened in round 1 until it contained the very step it is cited for lacking. |
| `buf.gen.yaml:29,31,33` | Unpinned remote plugins — `protocolbuffers/python`, `pyi`, `grpc/python`. The reason the floors are *derived*. Pinning them is **rejected**: `DECISIONS.md:476-489`. |
| `python/tests/test_protobuf_floor.py:72,88` | The two pure-file-read assertions Phase 6 runs at publish time. `:29-31` reads only `_gen/seam/api/v1/seam_pb2.py`; `:47-51` **skips** when `_gen` is absent. `:88-99` forces `cap == gencode_major + 1` — this is why "widen the floor" is not a metadata edit. |
| `python/tests/test_grpcio_floor.py:38` | Module-level `import grpc` — matters if Phase 6 runs it in the publish job. |
| `.github/workflows/yank.yml` | `workflow_dispatch`, `dry_run` default `"true"`. A hard **DELETE** (`:91-92`), not a PyPI-style yank. Its token line did **not** strip the cargo token's `"Bearer "` prefix (`.github/workflows/publish.yml:383-385` does) — **Phase 10 fixed it** (DONE 2026-08-31) at `.github/workflows/yank.yml:55-60`, and left the version/format/name filters (`:73-76`) byte-unchanged. `scripts/test_yank_gate.py` now executes the resolution and pins those filters. |
| `COMPATIBILITY.md:99-136` | §3 known-bad table + the "Nothing was yanked" preamble. **Phase 7 added the `0.7.39 – 0.7.43` row** (DONE 2026-08-31) — *not* the hedged `≥ 0.7.40` this row first planned: both edges are proven from CI history, so the hedge was deleted rather than softened. `:181-188` dependency floors · `:203-262` §4a co-installability (`:221-223` machine-read `PROBE-TABLE` marker — columns and order load-bearing; `:227` crewai row, whose Tracking cell linked **#48 and not crewAI#7103** — **Phase 7 fixed this; the cell now links the PR**) · `:328-364` §7 cross-repo coupling, incl. `:337-355` vector origination. **§7 documents `seam-sdk` main → `seam-runtime` CI, *not* a spec-side merge-order courtesy — do not cite it for one.** |
| `python/tests/test_retracted_claims.py:170-184` | Parametrized presence check over `COMPATIBILITY.md`. **Phase 7 added `"0.7.39"`** — the *lower* edge, which is the one a reader is most likely to assume they are outside of — plus two real row guards (`python/tests/test_retracted_claims.py:194-256`), because this parametrize is a substring check and could not fail for a deleted row. `python/tests/test_retracted_claims.py:27-30` globs **every `*.md` in the repo including `plans/` and this file**; `python/tests/test_retracted_claims.py:39-48` are the qualifier markers that make a paragraph "discussing, not claiming". |
| `python/tests/test_compatibility_citations_resolve.py` | Every backticked `file:line` in `COMPATIBILITY.md`/`DECISIONS.md` must resolve; `:61-64,:92` ≥10 each; `:76` sibling paths need a `seam-runtime/` prefix; `:141-172` `ANCHORED` needles must hit **exactly once** within `CITATION_SLACK` (`:176`). **Phase 8** adds the vendored-file rule. |
| `verify/docs/seam-event.v1.md` | Byte-verbatim vendored spec, pinned in its header. **Phase 9** refreshes it whole-file. Source of #73's citation drift. |
| `scripts/check_vendored_spec.py:22-38` | Integrity (`:24-26`) / reachability (`:28-32`) / **currency** (`:34-38`) — fails on staleness by explicit decision. This is what will announce runtime P1a Phase 6 by reddening `spec-pin` (`.github/workflows/ci.yml:588-589`) on every PR. |
| `python/seam_sdk/crypto.py:606-610` | `record_digest_v3` takes `context_digest` as an **opaque 32-byte sub-digest**, deliberately not reimplemented. **This is why ACDP P1a costs the digest layer nothing** — verified: `context_digest` appears only as an input (`:599,643,677`, `python/seam_sdk/admin.py:141`), and no context-provenance formula exists in `python/`, `ts/` or `verify/`. `:386` `_frame` · `:390` `_opt` · `:584` `_opt_bytes` · `:394` `record_digest_v2`. |
| `verify/src/verify.rs:668-674` | `schema_version` dispatch (2 ⇒ v2, 3 ⇒ v3, else refuse); `:636-644` ceiling refusal. P1a keeps `schema_version = 3`, so **no new arm**. |
| `python/tests/test_errors_is_import_light.py:87-100` | `crypto.py` may import only `cryptography`; `errors.py` only `grpc`. seam-runtime's `sdk-digest-parity` gate loads `crypto.py` standalone. **No phase may add an import to either.** |
| `scripts/test_ci_gate.py:79,98,141` | `ci-ok`'s `needs:` must equal the full job set both ways; `ALLOWED_ADVISORY` (the literal is at `:52`, asserted by the test at `:98`) may hold only `{integration, spec-pin}`; `workflow-guards` must stay free of `BUF_TOKEN`/`buf-setup-action`/`make generate` (banned triple at `:191-195`). **Any new CI job must be added to `needs:`.** |
| `scripts/test_publish_gate.py` | Executes `publish.yml`'s extracted `run:` blocks against a stubbed `gh`. **Phase 6** extends it in the same style. |
| `python/tests/test_workflows_generate_through_the_makefile.py:43,72` | No workflow may call `buf generate` directly; the `generate:` target must keep both `buf generate` and `root_gen.py` (without which the wheel is unimportable). |
| `Makefile:24,29,57-58` | `generate` (BSR) · `generate-local RUNTIME=../seam-runtime` (reads `crates/seam-api/proto` via `buf`) · **`clean` `rm -rf`s all three stub trees — never run it; recovery needs a BSR login.** |
| `plans/README.md:1-6` | Archive convention: delivered plans move to `plans/archive/` with a dated verification note, verified **against code, never a status table**. `:13` **carried** the stale `record-digest-v3` Active row (*"Phases 1–5 delivered … Phase 6 remains BLOCKED"*) and the index was **missing a row entirely** for `plans/authorize-single-canonicalization.md` — both corrected in Phase 1, which archived each plan against code. `:13` now holds this plan's own Active row. The cross-repo *table* lives in `plans/cross-repo/README.md`, not here — **Phase 2** edits that file. |
| `CHANGELOG.md:3-7` | The SDK does not choose its own version; entries accumulate under `## Unreleased`. `:631-636` is the hedging style Phase 7 *was* to mirror — it did not, the band being provable, and the citation was removed as it sat within `CITATION_SLACK` of the `"No yank"` needle; `:638-643` the no-yank decision of record. Both re-measured in Phase 4, which pushed them 28 lines down and found them already stale by ~115 before that. **This advisory still names only 0.7.13-0.7.19** — see the Phase 7 checkpoint. |

### Sibling repos (read-only — referenced, never written)

> **Superseded in one respect that matters:** the rows below describe the P1a work as committed
> on an unpushed branch, with nothing on `origin/main` and nothing on the BSR. Both merged on
> 2026-08-31 (`7c1d16d` proto, `3b3d4ae` spec), which is precisely what unblocked Phase 9 — see
> its checkpoint. Read the anchors below as historical.

| Path | Why it matters |
|---|---|
| `../seam-runtime/plans/acdp-p1a-receipt-slots.md` | The P1a plan. **Anchors below are stamped to `533f218`; this file moved twice on 2026-08-31 — re-verify before citing.** `:111-117` the four slots · `:276-301` Phase 4 = proto tags 7-10 · **`:289-291` "the seam-sdk regeneration … must be filed, not forgotten"** (Phase 2's mandate) · `:358-359` Phase 6 = the spec rewrite, now marked **`Status: DONE` (`533f218`)** · `:402-404` not a one-way door · `:103-109` bindings pinned all-`None` so `sdk-digest-parity` stays green (⇒ no populated-slot vector will ever reach `vectors.json`). |
| `../seam-runtime/docs/specs/seam-event.v1.md` | **Two sets of anchors, and they differ — re-verify before citing.** At the runtime's `origin/main`: `:568` still asserts the slots are reserved and absent, and `:581-587` still says the four payload encodings *"are D3's to pin, and one of them is a trap"* (describes what must be stated without stating it). At `533f218` on the unpushed branch, the rewrite has landed: `:534-544` the `context_digest` = `seam.audit.context-provenance.v3` formula the four slots enter · `:569-572` the slots are **filled**, populated on remote `acdp://`, absent on local `sha256:` · `:574-578` the `schema_version`-stays-3 rule · **`:586-593` all four payload encodings pinned in a table, naming the trap** — **this is the clean-room precondition, written but unpublished.** |
| `../seam-runtime/scripts/sdk-digest-parity.sh` | The cross-repo gate. Byte-diffs the whole `conformance/vectors.json` against the runtime's emitter, then loads `python/seam_sdk/crypto.py` **standalone** and resolves `record_digest_v*` by exact name. Renaming either function breaks merges upstream. |
| `../seam-runtime` branch `feat/acdp-p1a-receipt-slots` | Where P1a actually lives — **not `main`**. **All six phases are committed** (6 commits ahead of `origin/main` as of 2026-08-31T10:17-07:00): Phase 4 (proto tags 7-10 with real fields) at `cda620a`, and **Phase 6 (the spec rewrite) at `533f218`**, which also carried the `seam-store` edit that used to sit uncommitted beside it. The dirty working tree there is now unrelated Rust (serving-router, serving, integration). **The branch is not pushed** — `git ls-remote --heads origin feat/acdp-p1a-receipt-slots` is empty, so there is no PR, nothing on `origin/main`, and nothing on the BSR. The work is done; the publication is not. That is Phase 2's Ask A. |
| `../seam/docs/sdk/01-base-concepts-and-quickstart.md:110`, `../seam/docs/sdk/04-requesting-access.md:14` | Tell partners `pip install seam-sdk` with no mention of the protobuf co-installability constraint. **Phase 2's Ask B.** |
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
- **Other round-1 corrections:** a `CHANGELOG.md` citation I added, at what was then lines 516-518
  (written without backticks: it names a position in a past state of that file, not a current one),
  sat 3 lines from the `"No yank"` anchored needle, so it satisfied that guard on its own and would have masked the
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
    are `failure`, on that exact floor test. `.github/workflows/publish.yml:325-327` had it right the whole time
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
  (`.github/workflows/ci.yml:655-656`).
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
  `"Bearer "` the org Cargo token carries — a strip `.github/workflows/publish.yml:385` has always
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
  the heredoc that wrote it. Repaired; the one remaining match in the repo (`.github/workflows/ci.yml:311`) is
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

### Finalization + `/reconcile` — the record did not agree with itself · 2026-08-31

The final whole-feature verify found **no defect in code, gates or behaviour** — every phase's
substance shipped, no phase weakened an earlier phase's check, and every mechanical check holds.
What it found was record integrity, which in a plan whose thesis is *"a check that passes because it
never saw the thing"* is in scope rather than a nit.

- **The Phase 8 convert-vs-grandfather justification was counterfactual, and I had asserted it in
  four places.** It read *"Phase 9's regeneration half refreshes that same vendored file again."* It
  does not: the refresh (`c7331b6`, PR #80) landed at 18:26, about two hours **before** Phase 8 at
  20:14, and Phase 9's regeneration commit never touches the file. Worse, the reconcile pass then
  stamped the entry CONFIRMED citing *"the converted citation did not move"* — which is **vacuous**:
  it did not move because nothing refreshed the file, and a grandfathered anchor would equally not
  have moved. The comparison was against a `CHANGELOG.md` citation, a different file with a
  different cause that the rule explicitly does not reach. The decision stands on the durable reason
  (whole-file refresh on upstream's cadence drifts any anchor); the evidence offered for it is
  retracted, and the choice is recorded as **not yet exercised**.
- **The "No yank" chain in `DECISIONS.md` said eleven values and stopped one short** — Phase 9's own
  CHANGELOG entry had added the twelfth after that paragraph was written. So the paragraph had to be
  updated by the very drift it describes.
- **The same claim's thirteenth drift, in two files no guard watches.** `plans/…:524` and
  `python/tests/test_retracted_claims.py:180` both cited `CHANGELOG.md:523-528`, which is now
  unrelated prose. `DOCS` covers only COMPATIBILITY.md and DECISIONS.md, so neither resolved nor
  failed. Both repointed; the test's is now needle-based. Widening `DOCS` to the plan and this file
  stays deferred — Phase 6's Divergence 3 predicted this exact cost and declined it deliberately.
- **Two Phase 5 acceptance criteria were false at final state and unmarked**, while Phase 7's
  superseded criterion *was* struck. Both now struck the same way: the gate exits 6 (not 0) in a
  pre-ACDP checkout, and the manifest is 228 (not 223). The surviving invariant is *agreement
  between the extractors*, not a literal count — the count is a property of the contract on the day
  it is read.
- **A decision reversed in two of four places.** Phase 9 corrected "wiring them is Phase 9" in the
  manifest header and DECISIONS.md but left it in this file and in
  `python/tests/test_field_manifest_gate.py:361` — the docstring of the test asserting the slots are declared and
  *not* interpreted. Verbatim the "repaired in one document, left stale in the other" failure the
  same commit claimed to have caught elsewhere.
- **The repo map above is now stamped** *as at plan time*. Some rows were updated mid-run and some
  were not, which is worse than either: an unstamped map invites a reader to treat a stale row as
  current. Rows known to have moved are corrected inline.
- **"Both edges proven from CI history" now names its run ids.** It was asserted in four documents
  with one run id behind one of six data points — not false, but thinner than "proven" implies. The
  table is in `DECISIONS.md`: `v0.7.38` green (`32410597866`), `v0.7.39` red (`32557539171`),
  `v0.7.43` red (`32682442846`), `v0.7.47` green (`32805064452`).
- **The reconcile pass had itself skipped a directive** — the plan told it to look at the three
  pre-existing UNCONFIRMED entries and the first draft said nothing about them. A second instance of
  its own headline finding. All three are now stated and stay UNCONFIRMED, with reasons. The
  Cloudsmith deferral gained the re-open trigger and owner this file's own convention requires.
- **Final state:** python **618 passed / 17 skipped** · TS 112 passed · Go ok · `verify` 87 passed ·
  ruff and `tsc --noEmit` clean · `check-contract` exits **6**, and the verify confirmed the five
  ACDP fields are the *only* reason — every other probe present, all 42 RPCs matching in both
  languages. Citations: COMPATIBILITY.md 27, DECISIONS.md 57.

### Phase 9 — ACDP P1a/P2 adopted: declared, deliberately not interpreted · 2026-08-31

- **One divergence from the plan, stated first because it changes what the evidence is.**
  `make generate` was **not run locally** — the operator forbade it for this session. So the
  regenerated-stub evidence is **CI's, not this checkout's**. That is sound rather than a shortcut:
  the stub trees are gitignored, nothing committed depends on them, and CI runs `make generate` from
  the BSR (`.github/workflows/ci.yml:108`) and *then* the gate (`:122`) on every run — PR #82 was
  green at 228 = 228, which is the regeneration this phase asks for, executed by the machine that
  will execute it on every future PR.
- **AC3, the gate's failing output, in the direction this checkout can actually demonstrate.**
  Phase 5 captured the manifest-behind-stubs direction against temporary copies. Today the *live*
  local state gives the other direction — manifest at 228, this checkout's stubs at 223 — and the
  gate exits **6**, naming all five, independently per language:

```
ERROR: the generated FIELD surface disagrees with contract/field-manifest.txt:
  MISSING from the python stubs (stale/partial generation, or a REMOVED field):
    - ContextBinding/content_hash
    - ContextBinding/key_status
    - ContextBinding/receipt_hash
    - ContextBinding/resolved_status
    - ContextBinding/retraction
  MISSING from the ts stubs (stale/partial generation, or a REMOVED field):
    - ContextBinding/content_hash
    - ContextBinding/key_status
    - ContextBinding/receipt_hash
    - ContextBinding/resolved_status
    - ContextBinding/retraction

ERROR: A field MISSING from the stubs is either a stale generation — rerun 'make generate' (BSR) or
ERROR: 'make generate-local RUNTIME=../seam-runtime' — or a field REMOVED from the contract, which is
ERROR: a breaking change and must be handled, never silently rewritten away.
```

  A developer with pre-ACDP stubs meets exactly this, and it tells them what to do. The tripwire
  fires in both directions and neither is silent.
- **AC4, the manifest diff, was closed in Phase 5** and is recorded there: 228 entries, the 223→228
  divergence explained (the plan measured the surface before ACDP reached the BSR), and every
  `ContextBinding` field present — all eleven, `content_hash` / `receipt_hash` / `key_status` /
  `resolved_status` / `retraction` among them.
- **No wrapper change was needed, exactly as the plan predicted** — verified rather than assumed:
  `resolve_context` (`python/seam_sdk/client.py:718`) and `resolveContext` (`ts/src/client.ts:916`)
  return the generated `ContextBinding` straight through, so the five fields reach callers with no
  SDK work. What both *did* carry was a docstring enumerating four of the eleven fields as if that
  were the set; both now say what they actually return, and both carry the vocabulary warning.
- **`README.md`'s ACDP paragraph had gone stale in its second clause** — it said the five fields were
  "absent from this repo's field-level expectations, which is the gap the contract manifest closes".
  Phase 5 closed it. Corrected to what is true: declared in the manifest, present on the generated
  type, deliberately not interpreted, with the reason (`verify/` does not compute `context_digest`,
  so there is nothing here to check a receipt slot against).
- **The two vocabularies are carried verbatim and are now stated in four places** (README, CHANGELOG,
  both client docstrings). `key_status` closed/PascalCase, `resolved_status` open/lowercase, both
  byte-identical to the `context_digest` preimage. A consumer that normalises either breaks
  third-party digest recomputation with **no local symptom** — which is why it is written down
  rather than left to be inferred.
- **The "No yank" citation drifted a twelfth time, by my own hand, minutes after Phase 8 documented
  that it would.** Adding the CHANGELOG entry moved it `:586-591` → `:610-615`, and the README edit
  moved `README.md:147` → `:155`. Both were caught by the anchored check and repointed with content
  verified, not merely resolved. Unplanned, and the best available argument for #73's open half: the
  vendored rule that shipped in Phase 8 does not reach `CHANGELOG.md`, and this is what that costs.
- **Where the exit-0 half of AC3 actually comes from, precisely.** The "green at 228 = 228" run was
  **PR #82's**, on a different branch. This branch's own CI proves it again on push, but until then
  the exit-0 direction is inherited evidence, not this commit's — worth saying, because the exit-6
  output above *is* this checkout's and the two should not be read as the same kind of proof.
- **AC5's floor tests pass here but prove little here.** `python/seam_sdk/_gen/seam/api/v1/seam_pb2.py`'s
  `Protobuf Python Version` header (cited by symbol, not by line, since it is a generated, gitignored
  file) is gencode 7.36.0 and `python/pyproject.toml:50` declares `protobuf>=7.36.0,<8` — exact equality,
  zero headroom, and against *pre-ACDP* stubs. The assertion that matters runs in CI, after
  `make generate`. Recorded rather than reported as a local green.
- **A required gate is flaky, and that is filed rather than re-run away (#85).**
  `integration (live seam-grpc round-trip)` produced both outcomes twice on byte-identical code:
  push-run attempts 1 and 2 red, attempt 3 green, and the concurrent `pull_request` run green — same
  SHA, same `seamd:main` image, minutes apart, and the passing runs executed all 15 steps rather
  than skipping. The same three tests failed each time with `Connection reset by peer` on
  `127.0.0.1` port `8099`, *after* the workflow's smoke step had printed `seam-grpc is serving on 8099` —
  so the server listens and then dies on the session-seal and authorize paths. It cannot be this
  diff: nothing here changes behaviour, and none of the three tests touches `resolve_context`.
  I re-ran three times to establish the pattern, not to obtain a green. The reason it is worth an
  issue: a *required* gate that is red half the time on identical code teaches everyone to reach for
  "re-run" before "investigate", which is how a real failure gets waved through — the same class of
  habit that let #52 publish on red CI. #85 also notes that `/tmp/seam-grpc.log` is only printed
  when the *smoke* step fails, so every re-run destroys the one artifact that would name the crash.
- **Suites:** python 618 passed / 17 skipped (616 at the phase's own commit; the final
  whole-feature verify's fixes added two citations) · TypeScript 112 passed, 0 failed · Go ok ·
  `verify` 87 passed · ruff clean · `tsc --noEmit` clean. **Java and Kotlin were not run here** — no
  JDK in this environment; CI covers them, and this is flagged rather than implied green.
- **The verify gate caught the drift's second copy, which I had missed.** `DECISIONS.md` cites the
  same "No yank" claim as COMPATIBILITY.md. This commit's CHANGELOG entry moved the target; I
  repaired COMPATIBILITY.md's citation (the anchored one, which went red) and wrote a bullet about
  catching it — while DECISIONS.md's copy sat **87 lines stale**, 24 of them added by this very
  commit, passing because `ANCHORED` paired that needle with one document only. `ANCHORED`'s own
  docstring records exactly this for the `ci.yml` needle: *"cited from BOTH documents and drifted in
  both — repaired in COMPATIBILITY.md and left stale here."* The lesson had been written down and
  not wired. Now repointed **and** anchored for both documents.

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
  - `ANCHORED` had **eight** entries after the conversion, not nine. It now has **twelve**: the
    four repaired references below were added to it.

  The lesson is the phase's subject applied to itself: walk `git log`, never recall. The measured
  table now lives in the `VENDORED` comment, with the merged-stale row called out.

- **A third route to "looks checked", found in the paragraph this phase rewrote.** `DECISIONS.md`
  carried three bare-shorthand references — `` `:878` ``, `` `:843-875` ``, `` `:841` `` —
  continuing a full path given earlier in the same sentence. `CITATION` requires a path, so a bare
  `:N` matches nothing: they were never resolved and never content-checked. **All three had rotted,
  by 5 to 66 lines** — `:878` was cited for an assertion that lives in a different test; `:843-875`
  was cited as a per-column parametrization and is a comment block. The substance was right and
  every pointer was wrong. Repointed with full paths (they are now checked, hence the count rising
  to 55) **and added to `ANCHORED`**, so the content is checked and not merely the range —
  repointing alone would have repaired the instance and left the class. The class itself — a
  citation opting out of checking by being written unusually — is recorded on #73 alongside
  `COMPATIBILITY.md`'s comma-list form.

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

- **Full python suite: 615 passed, 17 skipped** — 606 at first commit; the two verify rounds added
  a registry-consistency test, four newly-visible citations, and four new `ANCHORED` content checks. Run whole, never a subset — the doc
  guards scan every `*.md` including this file.

### Phase 2 — The two cross-repo asks, written and **filed** · 2026-08-31

- **The "do not file" restriction was lifted mid-run** by the user. Both asks are now real issues:
  [seam-runtime#525](https://github.com/zer07labs/seam-runtime/issues/525) and
  [seam#26](https://github.com/zer07labs/seam/issues/26). No file outside `seam-sdk` was written —
  `git -C ../seam-runtime status --short` and `git -C ../seam status --short` are unchanged.
- **Ask A was re-scoped, not transcribed.** As drafted it asked the runtime to publish the encodings
  and push the contract — all of which had already shipped. Filing it verbatim would have asked for
  finished work. What is actually outstanding is three pieces of coordination: (1) the tracking issue
  their own plan says "must be filed, not forgotten" (`../seam-runtime/plans/acdp-p1a-receipt-slots.md:290-291`,
  repeated at `../seam-runtime/plans/acdp-p2-retraction.md:1010`) and which a search of all issue states shows was
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
  `p1a:103-107`, `:290-291`, `:439-441`, `p2:1009`, runtime `../seam-runtime/.github/workflows/ci.yml:186` (`buf push`), `:299`
  (`sdk-digest-parity`), `sdk-digest-parity.sh:40,51,55`. Ask B's: `seam` `01-…:110`, `04-…:14`.
- **Next:** all ten phases are DONE. Remaining: this phase's PR, the §4 finalization pass, and `/reconcile`.

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
  anchor fragility as a Phase 8 finding introduced `seam.proto` line-anchor citations (`:461-465`) into
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
  read, and neither status vocabulary re-spelled. Phase 9 then settled this rather than reversing
  it: the fields are carried and never wired.
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

---

# PROGRESS — `plans/consumer-decoders-and-event-surface.md`

Checkpoint trail for the consumer-decoders / event-surface workstream. Appended rather than
replacing the record above: the post-adoption and gate-blindness trails stay where they are.

**Plan:** [`plans/consumer-decoders-and-event-surface.md`](plans/consumer-decoders-and-event-surface.md)
— 5 phases across 3 issues:
[#85](https://github.com/zer07labs/seam-sdk/issues/85),
[#87](https://github.com/zer07labs/seam-sdk/issues/87),
[#88](https://github.com/zer07labs/seam-sdk/issues/88).

**Execution order = ranking:** 1 → 2 → 3 → 4 → 5. Phase 1 is a zero-diff issue comment. Phase 2
(#85) is next because a red `integration` reddens `ci-ok` and blocks merge, so it is the only phase
whose absence blocks a release. Phases 3-4 (#87 ask 2) close a fail-open decode gap a downstream repo
works around today. Phase 5 (#88) closes a blindness gap on a contract nobody is currently changing.

**PR strategy — 3 PRs, one per issue.** Chosen over one PR because the three share no file and no
mechanism — `python/tests/` + `ci.yml`, then `python/seam_sdk/` + `ts/src/`, then
`scripts/check-contract.sh` + `contract/` — and #85 must be mergeable without waiting on review of
the other two while a release is blocked. Chosen over one-PR-per-phase because Phases 3 and 4 are the
two halves of one decoder and must land together, and Phase 1 has no diff at all. The one place the
three interact is this file, which every PR appends to: a conflict surface, not a coupling, and
linear sequencing keeps it trivial.

1. **Phase 1 + Phase 2** — #85. The issue comment rides along because it is zero-diff.
2. **Phases 3 + 4** — #87 ask 2, both languages in one PR.
3. **Phase 5** — #88.

**Ground-truth corrections made while planning.** Recorded rather than smoothed over, because two of
them change what the phases do:
- `ts/src/client.ts:218` already carries `collectiveOutcomeOf` over a `DecisionResponse | SessionStep`
  union. TypeScript is not a judgement call — it gets the twin.
- The #85 failing set is the shared-8099 set **minus the first test**, not the whole set. Four tests
  use the `server` fixture (in `python/tests/test_integration.py` at `960cf81`, lines 69/93/108/306 —
  quoted rather than line-anchored, per #73, since Phase 2 rewrote the file out from under them); the three
  that failed are the last three in collection order. This also refutes the issue's own "seamd
  crashes on seal/authorize" hypothesis, since `test_full_round_trip` seals and passed.
- Port 8115 is **also** shared, by `data_port, mgmt_port = 8115, 8116` and `addr = "127.0.0.1:8115"`
  (`960cf81`, lines 143 and 226 of `python/tests/test_integration.py`), across three tests. A third
  instance of the same defect that did not fire in the observed runs.
- `python/tests/test_compatibility_citations_resolve.py:95-99` checks exactly three documents.
  `plans/*.md` is not under citation resolution; this file is.
- The `v0.7.71` publish run 33479578480 **skipped** `seam-verify → Cloudsmith`. The three jobs that
  carry ask 1 succeeded.

## Repo map — the files this plan touches

| Path | Purpose / relevance |
|---|---|
| `python/seam_sdk/_collective.py:84` | `collective_outcome_of` — the shape Phase 3 mirrors: `HasField` gate at `:116`, frozen dataclass at `:52`, union signature at `:84-86`. |
| `python/seam_sdk/_policy.py` | **Phase 3 created it.** `policy_enforcement_of(resp)` returning `None` iff absent. New module, not a `_collective.py` addition — that module's docstring is entirely about a growth policy this field does not have. |
| `python/seam_sdk/__init__.py:10` | Where `_collective`'s exports are imported; Phase 3 adds `_policy`'s alongside, plus two `__all__` entries. |
| `ts/src/client.ts:218` | `collectiveOutcomeOf` over the union. **Phase 4 inserted `policyEnforcementOf` immediately after it**, so this citation survived unchanged; the `submitCommit` citation did not, and was repointed by measurement in the same commit. |
| `ts/src/client.ts:328` | **Phase 4 created it.** `policyEnforcementOf(resp)` returning `undefined` iff absent — 103 lines inserted after `collectiveOutcomeOf` ends at `:239`. |
| `ts/src/index.ts:18` | The dual-declaration comment (called "shadowed-names" until Phase 4 retracted that word — see the record). It opened with "Two" and listed three names; Phase 4 rewrote it to name all **five** names declared on both sides (`CollectiveOutcome` was already missing before this phase) and made the count one-per-name. `python/tests/test_shadowed_names_comment.py` now enforces the list, the count, the namespace prefix, and that none of the five is on an explicit `../gen/` re-export list. |
| `python/tests/test_collective_outcome.py:208` | The `SessionStep` arm — the model for `test_policy_enforcement.py`. |
| `python/tests/test_integration.py` | At `960cf81`: `addr = "127.0.0.1:8099"` (line 48), hardcoded, four tests; `_wait` (26-34) proved only that *something* listens; a bare `terminate()` (66). **Phase 2's primary target** — all three are gone, so this row quotes rather than line-anchors. |
| `python/tests/test_integration.py` (cont.) | At `960cf81`: `dual_plane`, 8115/8116 (line 143) — collided with `governed_server` (216, addr at 226). |
| `python/tests/test_streamed_decode.py` | At `960cf81`: `dual_plane`, 8113/8114 hardcoded (line 259); bare `terminate()` (276). |
| `python/tests/test_admin.py` | At `960cf81`: `_free_port()` (line 175) — the ephemeral-port helper that already existed and that Phase 2 made the single copy. Its docstring already said fixed ports collide. |
| `python/tests/test_verify_attestation.py` | At `960cf81`: the second, verbatim copy of `_free_port()` (line 122). |
| `python/tests/live_server.py` | **Phase 2 creates.** One spawn/readiness/teardown/log-capture helper for all four live suites. |
| `ts/tests/integration.test.ts:51` | "Distinct ports avoid cross-test collisions" — the TS suite reached this conclusion and applied it everywhere. It has never shown this flake. |
| `.github/workflows/ci.yml` (cont.) | At `960cf81`: the smoke step's `kill "$pid"` (line 290), immediately followed by `exit 0` — it never waited for the process it started. Replaced by `reap()`. |
| `.github/workflows/ci.yml:336-347` | The python live step (the `pytest` line is `.github/workflows/ci.yml:346`). Phase 2 added an `if: failure()` log dump + artifact upload at the **end of the job**, after the TypeScript step at `.github/workflows/ci.yml:348` — a step is evaluated at its own position, so anything placed earlier cannot see a TypeScript failure. |
| `.github/workflows/ci.yml:704` | `ADVISORY: integration,spec-pin`. Advisory means *may skip*, not *may fail* — a red `integration` still reddens `ci-ok`, which lists it at `.github/workflows/ci.yml:689`. |
| `scripts/check-contract.sh:203` | `fields_python`; `:218` `fields_ts`. **Phase 5 parameterises both on stub path + package** — measured, they already yield 90/90 on the event stubs with zero one-sided entries. |
| `scripts/check-contract.sh:240` | `manifest_fields` — its stripper claims every `#`-free line, which is why the event surface cannot share `contract/field-manifest.txt`. |
| `scripts/check-contract.sh:472-476` | `--write-manifest` deletes `contract/expected-local-lag.txt` (the guard is `:472`, the `rm -f` is `:473`). The second reason the event surface needs its own file. |
| `scripts/check-contract.sh:583` | The corrected comment #88 was filed from. **Phase 5 must rewrite it** or it becomes false. |
| `contract/event-field-manifest.txt` | **Phase 5 creates.** 90 fields, 11 messages, zero enums, zero nested messages — all measured, not assumed. |
| `python/tests/test_field_manifest_gate.py:54` | `_run()` — the scratch-copy-plus-env-override pattern Phase 5's tests mirror. Nothing may mutate the real gitignored stub trees. |
| `python/tests/test_compatibility_citations_resolve.py:606` | The `ANCHORED` needle into `ts/src/client.ts`. The plan predicted the insertion would break the `submitCommit` anchor for any K of 4+ lines *except* a 125-131 window where it would go green against the unrelated `:804` citation. **Measured K = 101 at the time of that check, 103 as finally committed** — outside that window at every intermediate value, and the anchor failed red-first as required before `PROGRESS.md` was touched. |

## Phase log

### Phase 1 — record the evidence on #87 and re-scope it to ask 2 · **DONE**

Zero-diff. Commented on #87 with the measured evidence and left it **OPEN** for ask 2.

- `v0.7.70` carried `collective_outcome_of(resp: "pb.DecisionResponse")` and
  `collectiveOutcomeOf(resp: DecisionResponse)`; `v0.7.71` carries the union in **both** languages.
  Verified with `git show v0.7.70:...` / `git show v0.7.71:...` rather than from the changelog.
- Publish run 33479578480 succeeded on `python wheel → Cloudsmith`, `npm → Cloudsmith` and
  `install from Cloudsmith and run the vectors`; `seam-verify → Cloudsmith` was **skipped**, recorded
  explicitly rather than rounded up to "the run was green".
- Divergence from the plan, found while writing the comment: **`v0.7.69` and `v0.7.70` are tagged but
  were never published** — both publish runs failed at the `CI is green for this commit` gate because
  `spec pin` was red on those commits. The gate behaved correctly. It means `v0.7.71` is the first
  *installable* tag carrying the union, not merely the first tagged one, and the comment says so.
- Issue state after: `OPEN`, 1 comment. No file in the repo changed by this phase.

### Phase 2 — one live-server helper: ephemeral ports, waited teardown, captured logs · **DONE**

`python/tests/live_server.py` now owns spawning, readiness, teardown and log capture for all four
live suites. 9 teardown sites and 4 duplicate `_wait` copies collapsed to one.

**Red-first evidence, captured before the fix existed:**

- The defect itself, hermetically, against the real prior `_wait`:
  `_wait returned in 0.002s against a port the spawned process never bound; spawned proc exit code: 0`.
  A decoy listener stands in for a draining server; the "binary" exits before binding anything.
- `ci.yml` at `HEAD`: `reap` 0 occurrences, `if: failure()` 0, `upload-artifact` 0. After: 1 / 2 / 1.
- The structural guard, run at `HEAD`, named `test_admin.py` and `test_verify_attestation.py` as
  still holding duplicate `_free_port` definitions.

**Two plan corrections, both found by measuring rather than by review:**

- **Criterion 1's grep was wrong in both directions** and is replaced by an AST check. The pattern
  `:(80|81|82)[0-9][0-9]` can never return nothing — the citation guard holds `127.0.0.1:8099` and
  `192.168.1.10:8080` as *test data* for the "an IP is not a citation" rule — and it missed three of
  the four collision sites, which are written as bare integers (`data_port, mgmt_port = 8115, 8116`)
  with no colon. A criterion written to prove the ports were gone would have gone green with half of
  them still there.
- **The teardown count was nine, not seven.** The same count-over-list defect the plan flags for
  `ts/src/index.ts` one phase later, committed in the plan's own prose.

**A third correction, found when the guard first ran:** the `terminate`/`DEVNULL`/`Popen` detectors
were line-based and flagged the live suites' *module docstrings*, which deliberately say "do not
reintroduce a bare `proc.terminate()` here". A guard that punishes its own explanation is a guard
people delete. All detectors are AST-based, so they see attribute access and not prose.

**Citation drift, caught by the suite:** editing `ci.yml` moved the `must link NOTHING` anchor past
`CITATION_SLACK`, reddening the two `ANCHORED` cases. All four `ci.yml` citations in the two guarded
docs were re-measured with `grep -n` and repointed. Two of them still *resolved* and so were never
red, yet pointed at unrelated lines; resolving is not the same as being right, and
`test_each_citation_resolves` only ever asserted the former.

*Correction to an earlier version of this note,* which claimed those two had been fixed by
re-measuring: they had not. They were the old numbers shifted by the commit's own line delta —
mechanically translated, which is the very failure the sentence was written to disown. The
independent verifier caught it.

*And a correction to that correction.* This note used to quote the line numbers it had just
repointed to. Two of the three commits after it edited `ci.yml` again, so those numbers went stale,
and a third verifier found the note asserting a value that no longer matched any document. **Line
numbers have been removed from this paragraph entirely** — a record of
*what was done* does not need to restate the moving target, and restating it guarantees the record
goes wrong. The citations themselves are re-measured once, last, against a frozen `ci.yml`; the
resolved values are in the round-3 record below.

#### Verification round — verdict **GAP**, six findings, all closed

A fresh Opus verifier read the branch against the plan and #85. It confirmed the helper's four
properties by driving them with fake binaries, confirmed adoption was complete (all 9 teardown sites
and all 4 `_wait` copies gone), and confirmed the diff touches no shipped code. It then found six
defects, four of them in the halves that were never exercised locally:

- **G1 · the log dump could not reach the logs.** `find … -maxdepth 3` over `/tmp`, but every fixture
  passes pytest's `tmp_path` — `/tmp/pytest-of-runner/pytest-N/<test>0/seam-grpc-N.log`, four levels
  down. The `if: failure()` step would have run and printed nothing, which is the exact failure it
  exists to prevent. Now `-maxdepth 6`, with deduplicated roots (`find /tmp /tmp` printed everything
  twice) and an explicit `::warning::` when the glob matches nothing.
- **G2 · a TypeScript live failure produced no dump and no artifact.** Both `if: failure()` steps sat
  *before* `typescript live round-trip`; a step runs at its own position, so they were evaluated and
  skipped before the TS step ever failed. Both moved to the end of the job — the only position that
  covers both live lanes.
- **G3 · idiomatic Python evaded every detector.** The verifier wrote a replacement fixture that
  reintroduced all three #85 defects and passed all 19 guard tests: `from subprocess import Popen,
  DEVNULL` (bare names, not attributes), `from os import kill`, `proc.send_signal()`, and ports
  `9113/9114` outside the hardcoded `8000-8999` window. Detectors now match bare names and import
  aliases as well as attributes, cover `send_signal`/`killpg`/`posix_spawn`, and resolve dotted paths
  so `subprocess.run` is caught while `asyncio.run` — which `python/tests/test_integration.py:245` genuinely uses
  — is not. Ports are caught by three independent rules, the load-bearing one being *assignment to a
  port-named target from an int literal*, at any number. Deliberately **not** "any int in the
  registered-port range": `test_integration.py` legitimately holds `BudgetLimits(tokens=5000)`, and a
  guard that reddens on a token budget is a guard someone deletes. The verifier's whole evasion
  fixture is now a test.
- **G4 · two citations were mechanically translated, not re-measured** (above).
- **G5 · a child that died *during* a test was silent.** `_stop` short-circuits on an already-dead
  process, so the one path that most needs the server's log — "accepted the connection and then
  dropped it", #85's actual symptom — was the one path that never printed it. Teardown now writes the
  tail to stderr, and does not raise: the caller is usually already failing, and raising from a
  `finally` would replace that real failure with this one.
- **G6 · stale prose 30 lines from the edit**, still saying the suites send output to `/dev/null`.
  Rewritten to say what the smoke step is actually for now.

Two nits were taken as well: the dead `_ports` dataclass field is gone, and `free_ports(n)` now holds
every socket open until all the numbers are taken — allocating one at a time and closing each first
lets the kernel legitimately return the same number twice, which would put both planes on one port.
Both new tests were proved red-first against a reverted copy.

**Verification:** python **790 passed / 17 skipped** (from 754) · `scripts/` guards **100** ·
`ruff check` + `ruff format --check` clean · contract gate **exit 6** with the expected NOTE ·
independence gate **exit 0** · `ci-ok`'s `needs:` byte-identical to `HEAD` · the failure-dump step
executed under `bash -e` against a synthetic `pytest-of-runner` tree in all three of its paths
(TMPDIR unset, TMPDIR duplicating `/tmp`, no logs present).

**Not proven, and deliberately not claimed.** None of this proves the CI symptom is gone; N green
re-runs would not either. It proves the mechanism existed, is removed, that the realistic regression
is caught, and that the next occurrence leaves a log instead of destroying it. It does **not** prove
the shape cannot return: the guard is name- and AST-based, so a port computed by arithmetic or a
spawn helper imported under a new name still gets through, and the guard's own docstring says so
rather than implying a sandbox.

#### Verification round 2 — verdict **GAP** again, and the headline finding was this record

A second independent Opus verifier confirmed G2, G5, G6 and both nits sound, and confirmed G1's depth
arithmetic by executing the step. It then found that **the fix for G4 had scoped itself to two of the
three citation-enforced documents** — and the third is this file. `python/tests/test_compatibility_citations_resolve.py`
lists `COMPATIBILITY.md`, `DECISIONS.md` **and** `PROGRESS.md`. Phase 2's own edits to `ci.yml` and to
the four live suites invalidated **thirteen** citations here, four of them within sixty lines of the
paragraph above congratulating itself on re-measuring. The correction note was true and useless at the
same time.

All thirteen are fixed, but not all in the same way, and the difference is the point:

- **Nine described state Phase 2 deleted** — `addr = "127.0.0.1:8099"`, the two `_free_port()` copies,
  the smoke step's bare `kill "$pid"`. A line anchor cannot point at a line that no longer exists, so
  those rows now **quote the construct and name the commit** (`960cf81`) instead of line-anchoring it.
  That is the convention Phase 8 established for vendored files under #73, applied to the same problem
  one layer in: content that moves out from under a citation should not be cited by position.
- **Four described current state** and were simply re-measured.

The verifier also found the gate cannot see the worst class of these. `CITATION` at
`python/tests/test_compatibility_citations_resolve.py:109` requires a path with an extension, so the
bare companion form — `` `:306` `` following a full citation — is never extracted. There are **156** of
those across `DECISIONS.md` and `PROGRESS.md`, entirely unchecked, and one of them pointed past the end
of a 261-line file while the suite stayed green. Not fixed here: resolving a bare anchor needs its
antecedent, and the sweep would surface far more than this PR's scope. Filed as **#91**, along with the
**22 pre-existing citations** the verifier found that resolve while pointing at the wrong construct
and the four that point at outright wrong targets.

Five code findings, all closed:

- **H1 · the new registry check passed when its own scanner was blinded.** Pointing its glob at
  `*.NOPE` made it scan zero files and report success — the exact "asserts an absence, green when the
  detector broke" shape, committed *in the test written to close a blindness hole*, one function below
  a test whose entire purpose is pinning a denominator. It now asserts the denominator too.
- **H2 · the check caught only suites that volunteered.** It matched three substrings, so a fixture
  spawning its own server under a different env var was invisible. The verifier dropped exactly that
  file in and all 21 tests passed. The check is now AST-based with two independent signals: importing
  `live_server`, or spawning a process **and** opening a socket. The conjunction is load-bearing —
  four real files here (`test_conformance.py`, `test_packaging.py`, `test_field_manifest_gate.py`,
  `test_errors_is_import_light.py`) spawn subprocesses legitimately and none touches a socket.
- **H3 · it reddened on prose.** Being a substring scan, a file whose only content was
  `"""See live_server for the shared spawn helper."""` failed it — the "guard punishes its own
  explanation" failure that AST detection was chosen to avoid, reintroduced two functions away from
  the docstring saying so. Fixed by the same AST rewrite.
- **H4 · the port rule handled `ast.Assign` only.** `DATA_PORT: int = 9113` and a dataclass field both
  evaded — and `LiveServer` is itself a dataclass, so that is the idiom a copied fixture reaches for.
  `PORTS = [9113, 9114]` evaded while the tuple spelling did not. Both forms now covered.
- **H5 · the docstring exemption was a coincidence, not an exemption.** It rested on a
  `len(value) < 60` cutoff; `test_streamed_decode.py`'s docstring names 8113/8114 and sat **27
  characters** from reddening the build. Docstrings are now exempt by node identity, which also
  un-blinds the string rule to a fixed port buried in a long argv literal.

Three CI robustness holes, all closed: `find` had no `-type f` and `cat` no `|| true`, so one
unreadable match aborted the whole dump under `bash -e` (reproduced); the dedup was exact-match only;
and the artifact step's static glob could not follow `$TMPDIR` even though the dump step had just been
taught to. Every found log is now **staged into one fixed directory** that the upload points at, so
the artifact no longer depends on where pytest put `tmp_path`.

**And a fourth vacuous criterion, in this plan.** Phase 2's acceptance criterion 1 demanded
`grep -rnE '\b(80|81|82)[0-9][0-9]\b'` over the five live files return **nothing** — over files whose
docstrings deliberately name the old ports so the history stays with the code. It could not go green
without deleting the explanation. That is the third criterion in this plan satisfiable only by
damaging what it measures, and the paragraph immediately below it in `plans/consumer-decoders-and-event-surface.md`
is a warning box about the previous one. Rewritten: the AST guard is the gate, the grep is evidence a
human reads.

**Verification:** `scripts/` guards **100** · `ruff` clean · contract gate **exit 6** with the
expected NOTE · independence gate **exit 0** · shipped code untouched · H1 and H2 both proved
red-first on scratch copies · the hardened dump step executed under `bash -e` against a tree
containing a *directory* named `seam-grpc-*.log`, which aborted the previous version. (The python
count this paragraph used to quote was wrong by one and is superseded by the round-3 figure below;
it is not restated here, for the same reason the line numbers above are not.)

#### Verification round 3 — verdict **GAP**, and the finding that matters is the *pattern*

A third verifier was asked one question above all: has this converged, or is each repair producing
its own defects? The answer was flat, and the diagnosis is worth more than any individual finding:

> *Each round fixes the demonstrated instance and calibrates only against the negative set.* A
> reviewer exhibits input X; the fix is tuned until X is caught and the four known-innocent files
> stay green; **nobody re-runs the new detector against the true positives already in the
> repository.**

That is a fifth instance of the through-line in `plans/gate-blindness-hardening.md` — a check whose
result is decided by something other than the property it names — and it produced the round's
headline finding:

- **F1 · the registry check still caught only suites that volunteered.** Round 2 replaced three
  substrings with "spawns **and** imports `socket`/`grpc`". **Three of the four suites in
  `LIVE_SUITES` import neither.** The verifier took the real `test_integration.py`, removed its
  `live_server` import, inlined a raw `Popen` with `DEVNULL` and fixed ports 9113/9114 — all three
  #85 defects, in the shape of the file it was copied from — dropped it into `python/tests/`, and the
  whole guard reported **23 passed**. One line of measurement against the registered suites would
  have killed that signal before it shipped.

  The discriminator is now `connect` — chosen by measuring **both** sets: present in all four
  registered live suites, absent from all four files that spawn subprocesses for ordinary reasons. A
  live suite is one that spawns a server *and then connects a client to it*; that is a definition,
  not a correlation.

  **The durable half of the fix is `test_the_detector_is_calibrated_against_real_live_suites`.** It
  de-adopts each registered suite — tears out the helper import, puts a raw `Popen` back — and
  asserts the detector catches all four. A future narrowing cannot pass without being checked against
  the files it exists to protect. Proved by dropping the verifier's exact file in: the guard now goes
  red.

- **F2 · `mkdir -p "$stage"` was unguarded**, in the commit whose stated purpose was removing
  `bash -e` aborts from this step. With `$stage` present as a regular file the step exited 1 before
  printing a single log — and swallowed the `::warning::` that reports finding nothing. Guarded, and
  re-executed against that exact state.

- **F3 · round 2's own `ci.yml` edit re-broke two `DECISIONS.md` citations** that round 1 had
  correctly fixed, by shifting `workflow-guards` twelve lines and repointing only the two citations it
  happened to be looking at. `PROGRESS.md` already stated the right rule — *repoint once, last, with
  the cited file frozen* — and the commit did not follow it. All fifteen `ci.yml` citations across the
  three enforced documents have now been re-resolved in one pass against a frozen file, and each was
  read against its citing sentence rather than merely checked for range.

- **F4 · three false statements in this record**, including a python test count off by one and a
  quoted line number that had gone stale. Fixed above by removing the numbers, not by updating them.
  (A fourth round measured this claim too: of the values quoted, exactly one had actually gone stale —
  the others were still current at the time. The correction was itself slightly overstated, which is
  its own small instance of the thing being corrected.)

Also closed: `_assigned_pairs` missed port-named **keyword arguments**, **function defaults** and
**dict entries** — and the commit that added `AnnAssign` justified itself with "`LiveServer` is a
dataclass, so that is the idiom a copied fixture reaches for", while *constructing* that dataclass and
`field(default=...)` are both keyword arguments the same argument should have covered (F5).
`import subprocess as sp; sp.run(...)` evaded, because `ast.Import` aliases were never resolved (F6).
`live_server.py` was exempt from the **port** rule as well as the spawn rules, leaving a hardcoded
port in the one file where it would put every suite back on a single socket (F7). And
`test_the_helper_is_the_only_copy_of_free_port` was an unfloored substring scan — structurally
identical to the test round 2 had just fixed, in a file round 2 edited (F8).

Confirmed sound by this round and not touched: `_docstring_ids` is correct in both directions across
all eight docstring positions and exempts nothing that is not a docstring; all ten "At `960cf81`"
quote-plus-commit rows verify exactly against `git show`; the Phase 2 criterion-1 rewrite is real and
not a fifth vacuity (the grep returns exactly the six docstring lines the plan names).

**Verification:** `scripts/` guards **100** · `ruff` clean · contract gate **exit 6** with the
expected NOTE · independence gate **exit 0** · shipped code untouched · F1 proved red-first by
dropping a de-adopted `test_integration.py` into a scratch tests directory · F2 re-executed under
`bash -e` against a blocked staging path · **fourteen** of the fifteen `ci.yml` citations re-resolved
against the frozen file — see round 4 for the fifteenth.

#### Verification round 4 — **GAP, but a different shape**, and the lane that broke every round is closed

Round 3 said the rate was flat and the kind identical. Round 4 found that is no longer true, and the
difference is the useful signal:

- **The CI/shell lane is closed.** It produced a finding in all three prior rounds. The verifier
  executed the dump step under `bash -e` against eight adversarial states — `$stage` as a regular
  file, `$stage` unwritable, the root unwritable, an unreadable log, a *directory* named
  `seam-grpc-*.log`, zero matches, sixty matches, the smoke log as a directory — and got **exit 0 in
  all eight**, with the `::warning::` still printed in both no-match cases. `HEAD~1` exits **1** on the
  first of those, so the round-3 fix is real and no unguarded command remains.
- **The citation lane went 14/15 in outcome but the *claim* was still false.** `PROGRESS.md:405` cited
  `ci.yml` line 588 for "`scripts/test_yank_gate.py` wired into `workflow-guards`" — written without
  backticks here, because a *wrong* citation quoted inside a citation-enforced document is itself
  extracted and checked, and would have to be made right to be discussed. That line is `spec-pin:` — a
  different job's header. The value moved by roughly seventy lines and got the commit's own `+3`
  delta instead: the mechanical translation the same commit says it stopped doing, on the one citation
  of the eight that needed a real measurement. It resolves, so the gate stayed green. Now `655-656`.
- **And one new same-kind defect, in the commit that names the pattern.** `_import_aliases`, added to
  widen the detector, *narrowed* it: recording a mapping for unaliased imports made `import os.path`
  resolve `os.system` to `os.path.system`, losing four of the five `SPAWN_DOTTED` spellings. It
  survived because the red-first proof exercised **one** of the five — the proof was as narrow as the
  bug. Fixed to alias-only, and the proof now walks every entry, each also through an alias, plus the
  `import os.path` case directly. Reverting the one-line fix turns it red.

Two claims corrected rather than defended. **The calibration test's guarantee was overstated**: the
verifier swapped `CONNECT_NAMES` for a strictly worse discriminator and all 25 tests still passed,
because `_deadopt` *injects* the tokens (`Popen`, `DEVNULL`, `9113`) that a narrowing might key on —
the calibration corpus is generated by the guard it polices. It does catch the round-3 regression
exactly, which nothing before it did, and that is now what it claims. Calibrating against the real
pre-#85 fixtures would close the rest and cannot be done from git: CI checks out shallow, so `960cf81`
is unfetchable there. **And `connect` is a name list, not a definition** — `connect_ex` plus a locally
wrapped client evades it. The prose said "a definition, not a correlation"; it no longer does.

Also taken: `"port" in name` was a substring test, so `support=2000`, `report=5000`, `transport=1500`
and `{"reports": 4000}` all reddened — and round 3 had extended that test from assignments to every
keyword argument, default and dict key in the guarded files. It matches whole words now (`portfolio`
stays green). The `free_port` uniqueness scan missed `free_ports` — the plural the helper actually
exports, and therefore the name a re-implementation would copy — while its own docstring enumerated
three singular spellings.

Left as **#92**, per the verifier's own recommendation that a fifth round has negative marginal
return: the real-fixture calibration corpus, `connect_ex`, and the false-positive margin (eleven files
here already call a `CONNECT_NAME` with zero spawns; the sets are disjoint today and that is the whole
of the safety margin).

**Verification:** python **790 passed / 17 skipped** · `scripts/` guards **100** · `ruff` clean ·
contract gate **exit 6** with the expected NOTE · independence gate **exit 0** · shipped code
untouched · both new fixes proved red-first by reverting them on scratch copies.


### Phase 3 — `policy_enforcement_of`: absent and `enforced=False` stop being the same answer · **DONE**

**What shipped.** `python/seam_sdk/_policy.py` — a frozen `PolicyEnforcement` and
`policy_enforcement_of(resp)` over a `DecisionResponse` **or** a `SessionStep`, returning `None` iff
the field is absent. Exported from `python/seam_sdk/__init__.py` in both the import block and
`__all__`. `python/tests/test_policy_enforcement.py`: **17 test functions, 21 collected**.

**The hazard, measured rather than asserted.** Three states, two of them value-identical:

| state | `HasField` | `.policy_enforcement.enforced` |
|---|---|---|
| absent | `False` | `False` |
| present, `enforced=False` | `True` | `False` |
| present, `enforced=True` | `True` | `True` |

`absent.policy_enforcement == present.policy_enforcement` is **`True`** — verified against the
generated descriptors, and asserted in
`test_the_two_states_this_module_separates_are_value_identical` so that if it ever stops holding, the
module's reason for existing has changed and someone finds out from a red test rather than from a
docstring that quietly went stale. Only `HasField` separates them, so
`if resp.policy_enforcement.enforced:` reads "the runtime did not tell me" as "the runtime told me
no", which is the fail-open direction.

**The red-first sequence was run, not skipped.** The plan asks for the naive form to be built and
watched fail, and it was worth the two minutes: the version without the `HasField` gate fails every
absence assertion and passes every other criterion, including the frozen-type and export checks. One
line, one direction.

*An earlier version of this paragraph said "eight assertions … eight ways to see it".* A verifier
pointed out that four of those eight were a single `is None` check parametrized over four session
states — and `state` is a free-form string the decoder never reads, so `pb.SessionStep(state="Banana")`
behaves identically. The count was arithmetically true and rhetorically inflated. Those four
parameters are now one test that asserts the *irrelevance* directly, which is the true thing they were
gesturing at.

**Ground truth verified before writing anything**, against the descriptors rather than the proto text:
`policy_enforcement` has presence on **both** carriers at **different field numbers** (7 on
`DecisionResponse`, 3 on `SessionStep`), so one gate covers both and the two-message-type test is not
a tautology. `enforced` has **no** presence — `HasField("enforced")` raises
`ValueError: ... does not have presence` — so it is read directly, and the code carries that as a
comment rather than an unexplained asymmetry. `policy_id` **does** have presence, which is the same
three-state trap one level down: absent maps to `None`, explicitly-encoded-empty maps to `""`.

**The docstring enumerates the three presence sites and refuses to generalise** — the commit-terminal
step, the sealed-idempotent replay, and the pending-commitment seal retry — citing
**zer07labs/seam-runtime#526**, which publishes the measured matrix in its own body. That citation is
deliberate: `PROGRESS.md`'s clean-room constraint forbids reading `../seam-runtime/crates/**`, and the
issue is the readable source. Both of the proto comment's own general rules are false and the
docstring says so: it is *not* "only on a step that resolves the session via commit" (the
sealed-idempotent replay resolves nothing and carries it), and presence is *not* tied to `decision_id`
(the expiry seal carries a `decision_id` with no enforcement, so the comment's analogy points a reader
at the opposite of the truth). Even the issue's own first draft proposed a general rule that was
self-contradictory. Enumeration is the only thing that has survived contact.

**Deliberately not added.** No `allowed`/`unenforced` convenience boolean — `enforced` is already the
boolean and `None` is already the unsafe-to-guess case, so a twin would be a second truthiness that
can go the wrong way (the argument `_collective.py` makes for `approved` with no `declined`, asserted
here by `test_the_type_is_frozen_and_has_no_second_boolean`). Not folded into `_collective.py`, whose
docstring is entirely about a growth policy and fail-closed verdict decoding that this field does not
have — folding it in would make that module's own documentation false, which is the failure #88 exists
to prevent, one file over. No `errors.py` symbol: nothing to fail closed on, and
`test_errors_is_import_light.py` makes any addition there a deliberate act.

#### Verification round — verdict **GAP (minor)**, eleven findings, all closed

Every acceptance criterion passed on independent re-run, every descriptor and #526 claim checked out,
and **no mutation passed silently** — the verifier inverted the gate, dropped it, mapped absent
`policy_id` to `""`, unfroze the dataclass, returned the raw `pb.PolicyEnforcement`, hardcoded
`enforced=False`, and added a convenience property; all seven went red. The defects were in the prose
and in what the suite did not pin.

- **"Never raises." was false.** `policy_enforcement_of(pb.AuthorizeResponse())` raises
  `ValueError: Protocol message AuthorizeResponse has no "policy_enforcement" field` — Python does not
  enforce the `Union`. That is the right behaviour (a programming error surfacing as one) but it was
  the single unqualified absolute in a module whose whole thesis is that unqualified absolutes about
  this field have been wrong every time. Qualified, and now tested across all three carrier-less
  message types.
- **The new exports were filed under the wrong comment.** They landed beneath
  `# Collective outcome (C5) — fail-closed decoding of collective_outcome` in `__all__`, which is
  false about them on three counts. The commit argues at length that folding this into
  `_collective.py` "would make that module's documentation false, which is the failure #88 exists to
  prevent" — and then reproduced exactly that, one file over, in the export list. They have their own
  comment now.
- **The frozen-type test's exclusion set was entirely dead.** It filtered `dir()` against
  `{"enforced", "policy_id", "count", "index"}`; `dir(PolicyEnforcement)` returns **no** public names
  at all, because a frozen dataclass with no field defaults puts nothing on the class. `count`/`index`
  are namedtuple artifacts. The assertion still had signal, but it read as though it enumerated the
  type's real surface. Replaced with an empty-`dir()` assertion plus an explicit `dataclasses.fields`
  check, and `pytest.raises(Exception)` narrowed to `FrozenInstanceError`.
- **Nothing went through the wire.** Every message was built in-process, which the docstring framed as
  a virtue — and the consequence was that the most realistic production shape had no test: a runtime
  emitting `policy_enforcement { }`, an empty submessage (`1a00` on the wire), which must decode to an
  *instance*, not `None`. Now pinned, along with the explicitly-empty `policy_id` round-trip and an
  `isinstance` assertion (returning the raw generated type — the design the plan rejects — was
  previously caught only incidentally, by two field assertions that happened to still pass; it now
  fails five tests rather than two).
- **Two tests were decorative.** The expiry-seal test asserted `expired.decision_id == "d-expired"`,
  which tests the protobuf constructor, and its remaining assertion was indistinguishable from the
  plain absence case. It now pins what it actually can — that the combination is representable and the
  SDK has no `decision_id`-as-proxy shortcut — and says plainly that it cannot test the runtime claim,
  which lives in another repository.
- **The absence list borrowed the proto comment's own parenthetical.** "open, propose, vote, ballot"
  is not exhaustive: #526's matrix measures **both suspended shapes** as absent too. Corrected — and
  the suite had been parametrizing `"Suspended"`, a state the enumeration did not name.
- **Three descriptor claims, one test.** `test_the_two_states_this_module_separates_are_value_identical`
  was written precisely so a descriptor change goes red instead of leaving a docstring stale. The same
  reasoning was not applied to the field numbers (7/3) or to `enforced` having no presence — the
  latter being the stated reason another test "is not a tautology". All three are asserted now.
- Also: the plan's criterion 6 quoted a **754** baseline frozen at planning time (the branch point is
  791), the RST ruler in the test module's table was 26 chars against a 32-char header, and this file
  had lost its trailing newline.

**Verification:** python **812 passed / 17 skipped** (from 791 at the branch point; skips unchanged) ·
`ruff check` + `ruff format --check` clean · all five mutations re-run against the hardened suite and
caught more widely than before (drop-gate 8 → 9 failures, empty-`policy_id` 1 → 3, raw-`pb` 2 → 5).

### Phase 4 — `policyEnforcementOf` in TypeScript, and the citations it moved · **DONE**

`ts/src/client.ts:328`, inserted immediately after `collectiveOutcomeOf` ends at `:239`, so `:218`
survived unchanged. **K = 103 as finally committed** — 100 lines at first commit, +1 for a blank line
round 1 caught missing against the file's own convention (the only such gap in the file), +2 for a
TSDoc paragraph round 2 made retract a wrong claim. Every intermediate value is outside
`CITATION_SLACK`'s vacuous band and outside the 125-131 window the plan warned would go green against
the unrelated `resolveContext` citation, so the red-first result holds for the committed state and
not merely for the state it was measured in. The `submitCommit` anchor failed red-first, before
`PROGRESS.md` was touched, naming the exact new line.

**The TS hazard is not the Python one, and the docstring says which it is.** In `_policy.py` the first
two states are *value-identical* — `resp.policy_enforcement` compares equal whether the field is
absent or present-with-`enforced=False`, and only `HasField` separates them. protobuf-es models
presence natively, so in TypeScript they are already distinguishable *by value*: absent is
`undefined`, present is an object. Copying Python's claim across would have asserted a hazard this
language does not have. What does collapse them is the read a caller actually writes —
`if (!resp.policyEnforcement?.enforced)` is true for **both**, because `undefined` and `false` are
different values with the same falsiness. So the decoder is thinner here (one `=== undefined` check,
and `policyId` passes straight through where Python needs a second `HasField`) and the documentation
is the larger half of the deliverable. Both halves are stated in the TSDoc rather than implied.

**Four citations were repointed by measurement, and three of them were already wrong at `HEAD`** —
before this phase inserted a line. `submitEvaluation`/`submitObjection` were cited `:601,637` and were
actually at 623/659; `resolveContext` was cited `:804` and was at 813; the confidence-presence
mapping was cited `:623`, which is `submitEvaluation(`, not the mapping. None of that is drift this
phase caused: `:601,637` matches the `CITATION` regex not at all (a comma list has no closing
backtick after the number), and the other two are non-anchored, where the gate asserts only that the
line exists. This is issue #91's blindness measured on live data rather than argued. Final, measured
after the file was frozen — then re-measured once more when the blank-line fix moved everything below
`:239` by one: `collectiveOutcomeOf` `:218`, `policyEnforcementOf` `:326`, the confidence mapping
`:746`, `submitCommit` `:777`, `resolveContext` `:914`. The bare companions on the
`collectiveOutcomeOf` row moved too — `:144-146` → `:146-151` (the constructor, not the doc-comment
tail) and `:207` → `:229`, the latter also stale at `HEAD`.

**The margin moved, and this record needed two goes at saying why.** Open Question 6 predicted the
insertion would shrink the closest needle-to-foreign-citation distance from 53, and it did. The first
version of this paragraph called 53 "wrong rather than stale" — reasoning that the foreign citation
`:623` named the confidence mapping while the mapping truly sat at 645, so the real distance had been
31 all along. A verifier showed that misidentifies the metric. The distance that governs
foreign-citation masking, and the only one the assertion consults, is from the needle to a citation
**as written in the document**, never to the true location of what that citation names. By that
definition 53 was exactly right for the state it described. What moved it is that the citation was
*corrected* — 623 → 748, **+125**, of which +103 is the insertion and +22 the correction — while the
needle moved only +103; the insertion by itself would have left 779 − 726 = 53 untouched. The
prediction was right; neither the plan's stated cause nor this record's first correction of it was.
Kept in full rather than quietly amended, because "a stale citation makes a hand-measured margin
wrong" and "a corrected citation moves a margin" are different failures and only the second happened.

**Round 2 then narrowed it further, deliberately, and that is the more interesting number.** Splitting
`` `ts/src/client.ts:723,759` `` into two anchored citations put a citation at 762, seventeen lines
from `submitCommit(` at 779 — and `submitObjection(`'s own margin is **14**, now the tightest in that
table, displacing `publish.yml`'s 27. The trade was made knowingly: a comma-list matches `CITATION`
not at all, so those two positions were checked by nothing and had been wrong twice; splitting alone
would only have made them *resolve*, which would not have caught 723-versus-724. Anchoring is what
makes them falsifiable, and a citation that resolves but cannot be wrong is the vacuity this whole
plan is written against. 14 still clears `CITATION_SLACK` 3 by nearly five times, and the docstring
now says to revisit before inserting anything between `submitEvaluation` and `submitCommit`.
`CITATION_SLACK` itself was not widened (#73), and both margins are now derived from the same
`_citations()` the assertion uses, so the recorded number cannot disagree with the check again.

**`ts/src/index.ts:18` said "Two" and listed three; four names were dual-declared, and five are now.**
`CollectiveOutcome` had been in that state since Phase 3 of the previous plan and was never added, so
the comment was already false before this phase made it more so. The plan scoped that out and said to
record it; recording a known-false comment while editing the same five lines is the failure this
whole plan is about, so it was fixed instead, and the deviation is logged here. The count is now
one-per-**name**, not one-per-group: a count that must be decoded before it can be checked cannot go
stale loudly. The comment also distinguishes the two DTO entries (`CollectiveOutcome`,
`PolicyEnforcement` — decoded forms, reached only through a decoder) from the three parallel-spelling
ones, which is what a consumer reaching for `pb.` actually needs to know.

**The word "shadowed" was wrong and is gone.** The comment and the guard both claimed the root name
resolved to the hand-written export because `export * from "./client.js"` came *before*
`export * as pb`. That mechanism does not exist: `export * as pb` exports exactly one name — `pb` —
and contributes none of the module's inner names at the root, so there is no contest and ordering is
irrelevant; had two star exports genuinely collided, ESM would have **excluded** the ambiguous name
rather than resolving it to the first. These five are `pb.`-only because they are simply not on the
explicit named lists. The observable claim was right and the reason given for it was invented. Both
sites now say "declared on both sides", and both record the hazard that runs opposite to intuition:
adding one of these names to `export type { … }` would make the **generated** type win the root name
and displace the hand-written DTO.

**Beyond the plan: `python/tests/test_shadowed_names_comment.py` now enforces that comment** — and
its first version passed on the exact defect it was written to catch. The plan's criterion 6 asked
for both halves to be *asserted by reading them*, a one-time check on a comment that had already
rotted twice in the two ways such a comment can. The guard computes the dual-declared set from the
code (`ts/src/**/*.ts` against both `seam_pb.ts` and `seam_event_pb.ts`) and compares it to the list
as a **set, in both directions**, with floors on both inputs so a regex that stops matching reddens
rather than passing vacuously. Seven tests.

The first version substring-searched the whole comment block for `` `pb.X` `` — and the block's own
historical-rationale sentence contained `` `pb.BudgetLimits` `` and `` `pb.StepUsage` `` in prose. A
verifier deleted their entire list entry, leaving **"FIVE" above a list of three**, and all nine
tests passed. The sentence explaining the old bug is what blinded the new guard. List entries are now
matched by indentation and prose cannot satisfy them, with
`test_a_name_mentioned_only_in_prose_does_not_count_as_listed` pinning that distinction against a
synthetic block, and the offending sentence moved out of the comment into this record where it
belongs. Five mutations re-run against the fixed guard — delete a list entry, drop a name, FIVE →
FOUR, list a non-dual-declared name, demote a name from list entry to prose — each caught by two
tests. A missing generated tree now fails four tests instead of aborting collection (the
`parametrize` that evaluated at import time is gone), verified by running the whole suite with `GEN`
pointed at a nonexistent file: 4 failed, 818 passed.

**Open Question 1 answered, narrowly: `PolicyEnforcement` was NOT promoted to a named export.**
`ts/tests/policy_enforcement.test.ts` imports `PolicyEnforcementSchema` from the generated module
directly, exactly as `ts/tests/collective_outcome.test.ts` does for `CollectiveOutcomeSchema`, so
nothing in this phase needed it. `pb.PolicyEnforcementSchema` remains the consumer path and the
shadowed-names comment now documents it. The broader public-surface question — whether the two DTO
types should be named exports alongside the schemas — stays open and unchanged by this phase.

**Verification, re-measured after the gap fixes rather than carried forward.** `npm run typecheck`
and `npm run build` clean · `npm test` **136 tests, 126 pass, 10 skip, 0 fail**. The branch point was
**112 pass / 122 tests**, measured by checking out `978d05d` and running it, not inferred — the first
draft of this line said 120 and was wrong; `ts/` is byte-identical between the branch point and this
phase's parent, so the whole +14 is the new suite. Python **833 passed / 17 skipped**, decomposed
against 812 at the Phase 3 commit: **+10** from the dual-declaration guard, **+9** from citations
this phase added to the three enforced docs (which `test_each_citation_resolves` parametrizes over),
and **+2** from the two new `ANCHORED` entries. Every arm counted, because the first draft of this
line reported 821 with a `+9` that omitted the citation arm entirely — a number written before the
prose that changed it, and never re-measured; the second draft said 822 and was overtaken by round 2.
Skips unchanged throughout. `ruff check` + `ruff format --check` clean · `scripts/` 100 passed ·
contract gate exit 6 naming exactly the five recorded lag fields.

Six decoder mutations run against the TS suite — fail-open on absent, the `enforced === false`
inversion, `policyId ?? ""`, returning the generated message, hardcoding `enforced: true`, and
inverting the presence test — caught by 5, 4, 3, 2, 2 and 13 tests. One further mutation,
`if (!enforcement)`, passes silently and is an **equivalent mutant**: a protobuf-es message object is
always truthy, so the two spellings cannot differ. Recorded rather than papered over — an equivalent
mutant is not a gap, but calling it one, or quietly not mentioning it, is how a mutation score gets
inflated.

**A CHANGELOG entry was missing and nothing gates that.** Phases 3 and 4 shipped two new public
functions and two new exported types in two languages with no `Unreleased` entry, while their direct
sibling `collective_outcome_of` has a full one — and no later phase in this plan touches these APIs,
so it would have shipped absent. Added for both languages. Writing it moved the `No yank` block 28
lines down, which broke the `CHANGELOG.md` anchor cited from **both** COMPATIBILITY.md and
DECISIONS.md; both were repointed by measurement in the same edit. That break is the gate working:
unlike the four `ts/src/client.ts` citations this phase found already-wrong, this one was anchored,
so it reddened the moment it drifted.

#### Round 2 — verdict **GAP**, nine new findings, all closed

The thirteen round-1 findings all verified as closed, every measured number reproduced exactly, and
the guard's bypass was confirmed shut against twelve fresh attempts (prose at three indentations, a
split block, a Cyrillic lookalike, names inside the intro line, tab indentation). The pattern held
anyway: the fix pass introduced four more.

- **The commit that claimed to have shifted every citation below `:239` missed one.** `:71` still
  cited `ts/src/client.ts:723,759`; the true lines were 724 and 760, and both cited lines are the
  `*/` terminating the preceding doc comment. It was ungated for the reason this phase had already
  documented in the same file — a comma-list matches `CITATION` not at all — so the claim went into
  a commit message unchecked. Fixed by splitting the three comma-lists on that row into six ordinary
  citations and **anchoring** `  submitEvaluation(` and `  submitObjection(`, because splitting alone
  would only have made them resolve, which does not catch 723-versus-724. The margin cost is recorded
  above rather than absorbed.
- **The retracted word survived at two more sites.** The commit's own message says "the word
  'shadowed' was wrong and is gone", and `ts/src/client.ts` still said "Shadows the generated
  `pb.PolicyEnforcement` … see the shadowed-names note in `index.ts`" — pointing at a note that no
  longer carries that name — with the repo-map row above saying "all five actual shadows". Both now
  say "declared on both sides".
- **The paragraph written to state the mechanism correctly carried a false universal.** "Everything
  else from `../gen/` is re-exported by the explicit lists below": the lists carry **40** names and
  the two generated modules declare **167**. 127 reach the root only under `pb.`/`ev.`, which the
  same file says twelve lines further down. Corrected in both the comment and the guard's docstring,
  with the measured numbers.
- **The plan's own Phase 4 Status line, five lines from a block this commit edited**, still read
  "K measured at 100" and repeated the "wrong rather than stale" framing that the commit retracted.

Three more in the guard itself, each demonstrated rather than argued. `DECL` matched only
`interface|type|class|const|function|enum`, so `export abstract class ContextBinding` and
`export async function GrantView` — two genuine dual-declarations — left all seven tests green with
the comment still saying FIVE; the floors cannot fire on a detector that stopped matching one *form*.
`LIST_ENTRY` matched only `` `pb.X` `` while `GEN` had been widened to the event module, so an
`ev.`-namespaced name was **unlistable**: the only spelling that turned the guard green was
`` `pb.SeamEvent` ``, which does not resolve. And the comment's headline hazard — that adding one of
these names to `export type { … }` makes the generated type win the root name — was guarded by
nothing; a verifier proved it silently true (`tsc --noEmit` exit 0, the root `CollectiveOutcome`
becoming the wire message) and proved all seven tests stayed green while it was.

Also corrected: "4 failed, 819 passed" was 818; two `CHANGELOG.md` companions in the repo map
(`:516-518`, `:521-526`) that this phase pushed 28 lines further from targets they had already missed
by ~115; a COMPATIBILITY.md citation for `opts.canonical` that pointed at line 265 of
`ts/src/client.ts` (written without backticks here, since it names a position that was already wrong
before this phase widened it) and now lands inside the new `PolicyEnforcement` interface — repointed
to `ts/src/client.ts:521`; and a historical mention of a
long-removed citation that was written in backticks and so read as a live one.

**Round-2 verification:** python **833 passed / 17 skipped** · TS 136 / 126 pass / 0 fail ·
`tsc --noEmit` + `npm run build` clean · `ruff` clean · `scripts/` 100 · contract gate exit 6 naming
exactly the five recorded lag fields. Four new guard mutations, each caught: a dual-declared name
placed on the explicit re-export list, an `abstract`/`async` declaration pair, an event-module name
listed under the wrong namespace, and a blinded re-export detector. Ten tests in the guard now.
