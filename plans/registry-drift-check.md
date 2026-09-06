# Registry drift check — a scheduled comparison of what Cloudsmith serves against what `main` says

Issue [#100](https://github.com/zer07labs/seam-sdk/issues/100), second half. The first half shipped as
PR #101 (`release-outcome`, `.github/workflows/publish.yml:766-832`) and is **not touched by this plan
except for one comment**.

---

## Context

### What exists today, and what it structurally cannot see

The release path is: a `seam-runtime` release fires a `repository_dispatch` →
`.github/workflows/release-on-runtime.yml` (wire-framing gate at `:80-161` → `scripts/set_version.sh`
at `:168` → commit and push to `main` at `:179-180` → `git tag -a "v$VER"` at `:182`, `git tag -a
"go/v$VER"` at `:186`, `git push origin "v$VER" "go/v$VER"` at `:187`) → the `v*` tag push triggers
`.github/workflows/publish.yml` (`:24`) → `ci-green` (`:63`) + `version-check` (`:150`) → `npm`
(`:189`) ‖ `python` (`:282`) → `registry-smoke` (`:587`) → `release-outcome` (`:766`).

`release-outcome` files or updates an issue titled exactly `Release <tag> did not publish`
(`publish.yml:787-788`), matched against open issues by exact title equality over the first 100
(`:818-824`). It is a reporter, never a gate — `scripts/test_release_notice_gate.py` pins that.

Its blind spot is stated in the file (`publish.yml:761-765`): it is a **job inside `publish.yml`**, so
it reports a publish that *ran and failed*. A publish that **never ran at all** produces no job, no
run, and no report. That is the gap this plan closes.

**Verified against the tree at `f177cfb` — every claim below was re-opened, not inherited.** Three
corrections and two additions to the briefing findings are marked ⚠ / ➕.

### The three lag states, and why ONE comparison covers two of them

| state | remote tag | in-tree version on `main` | registry | drift? |
|---|---|---|---|---|
| A. release never dispatched, or refused before tagging (`release-on-runtime.yml:89-160`) | absent | old | old | **NO — consistent** |
| B. tag pushed, publish refused | present | == tag | lags | **YES** |
| C. tag push failed after the version commit landed | absent | bumped | lags | **YES** |

State C is real and I verified the ordering myself: `release-on-runtime.yml:180` is
`git push origin HEAD:main`, and `:182`, `:186`, `:187` (`git tag -a`, `git tag -a`, `git push origin
"v$VER" "go/v$VER"`) all come **after** it, in the same `run:` block. GitHub's default shell for a
Linux `run:` is `bash --noprofile --norc -eo pipefail {0}`, so a failure at `:180` aborts before any
tag exists — but a failure at `:182`/`:187` leaves `main` bumped with no tag. That is state C.

➕ **The `git push` at `:187` is not atomic** (no `--atomic`), and it pushes two refs. So `v$VER`
landing while `go/v$VER` does not is a distinct, previously-unnamed fourth state: everything green,
`go get github.com/zer07labs/seam-sdk/go@vX.Y.Z` unresolvable forever. ⚠ It is **real, verified, and
deliberately NOT in this plan** — it is tag-vs-tag, not registry-vs-source, and its fix is one word
(`--atomic`). Phase 8 records the drop and the issue to file instead.

**The comparison this plan makes:** *is the version `main` currently declares installable from
Cloudsmith, in both formats?*

That single question covers B and C, and correctly stays silent on A:

* In **B**, `release-on-runtime.yml:179-180` commits the bump to `main` before `:182` tags, so the
  in-tree version on `main` equals the tag. Registry lags → fires.
* In **C**, the bump is on `main` and there is no tag at all. Registry lags → fires. A tag-keyed
  check is blind here, which is exactly why the tag is not the key.
* In **A**, `main` still carries the old, already-published version → consistent → silent. Correct.

**What this comparison knowingly does not cover:** a version that was tagged, failed to publish, and
then *superseded* by a later successful release. `main` moves on, the check goes quiet, and the
intermediate version stays permanently unpublished. That is **correct and intended** — it is exactly
the `v0.7.8` / `v0.7.22-25` / `v0.7.33` / `v0.7.44-46` / `v0.7.62` / `v0.7.74` situation (confirmed
absent from both `git tag -l` and `git ls-remote --tags origin` at `f177cfb`), and `release-outcome`
already filed for any of those that reached the tag stage. The invariant worth defending is *"a
consumer can install what the source says the current version is"*, not *"every number ever minted
exists"*.

### The false-positive sources, each with its answer

1. **Version-number gaps.** ⚠ The check **never reasons about ordering or successorship at all**.
   It asks one membership question about one version string. `v0.7.74` (a runtime workspace-crate
   bump, never an SDK release) cannot be flagged because nothing ever asks about `0.7.74`. This is
   not a mitigation, it is an absence of the mechanism.
2. **Publish latency.** `ci-green` polls `ATTEMPTS=40`, `INTERVAL=30` (`publish.yml:82-83`) = 20 min
   before `npm`/`python` even start; `registry-smoke` retries `seq 1 10` × `sleep 30` per ecosystem
   (`publish.yml:625,633` python; `:721,724` npm) = up to 10 min in one job. Honest worst case ≈ 40 min
   of declared ceiling plus job/queue overhead. ➕ **Only `release-outcome` declares
   `timeout-minutes` (`publish.yml:771`); `ci-green` (`:63`), `version-check` (`:150`), `npm`
   (`:189`), `python` (`:282`), `publish-verify` (`:526`) and `registry-smoke` (`:587`) declare
   none** — verified by reading every job header — so their only hard bound is GitHub's default
   per-job limit of 360 minutes. ⚠ **That 360-minute bound does not by itself justify a 360-minute
   grace window.** A publish job that hangs to the default limit is *killed*, which makes the run
   fail, which `release-outcome` already reports (`if: always()`, `publish.yml:768`). The drift check
   does not have to stay silent for that case; it only has to avoid *double-filing* against it. So
   the window is **two-tier** — a soft tier sized on the declared ceilings and a hard tier sized on
   the job limit — see Phase 3.
3. **Yanked versions.** `.github/workflows/yank.yml` deliberately deletes published versions (issue
   #43 did). Suppression is a **label on the closed drift issue for that version**
   (`deliberately-unpublished`), not a curated file — Phase 6 argues it out.
4. **Half-publish.** `npm` (`publish.yml:192`) and `python` (`:285`) are ungated siblings, recorded
   as an accepted residual at `plans/post-adoption-hardening-and-acdp-readiness.md:316,560` and
   settled as "keep it in-job" at `:255-260`. Checking one ecosystem is a partial answer, so the
   check asks about **both formats in one query** and names which half is missing.
5. ➕ **A version bumped by a path other than `release-on-runtime.yml`.** `ci.yml:23-38` only holds
   py == ts; nothing stops a human PR from bumping both files without a dispatch or a tag. `main`
   then declares a version that was never tagged and never published, and the check fires — which is
   *correct by its own invariant* ("a consumer can install what the source says the current version
   is") but has a different remediation. State C's message ("the tag push failed, re-push it") would
   send someone to the wrong place. The remediation text must therefore branch on tag presence
   **and** say, in the no-tag case, that the two possibilities are a failed tag push and a bump that
   never had a release behind it.

### The mechanics that already exist and are reused verbatim

* **Registry read.** `yank.yml:69-76` queries the Cloudsmith **list API** and gets both formats back
  in one call: `curl -sf -H "X-Api-Key: $TOKEN"
  "https://api.cloudsmith.io/v1/packages/zer07labs/internal/?query=seam-sdk+version:$VERSION&page_size=50"`,
  filtered with `jq` on `select(.version == env.VERSION)`, `select(.format == "python" or .format ==
  "npm")`, `select((.name | sub("^@[^/]+/"; "")) == "seam-sdk")`.
* **Credential resolution.** `yank.yml:55-63`'s explicit `if` form, with `Bearer ` stripped from both
  sources — never `publish.yml:606-607`/`:710-711`'s `&&` one-liner, for the reasons written out at
  `yank.yml:38-54`. `CLOUDSMITH_API_KEY` first, `CARGO_REGISTRIES_ZER07LABS_TOKEN` (carries a literal
  `Bearer `) as fallback. Plus `::add-mask::`, which `yank.yml` omits and `publish.yml:612,712` do.
* **Workflow shape.** `.github/workflows/framework-coinstall.yml` (64 lines) is the template:
  `schedule` + `workflow_dispatch`, deliberately **not** a job in `ci.yml` (`:5-8`: *"The answer to
  this question changes when PyPI changes, not when this repository changes… `ci-ok` stays a
  statement about the diff"*), and exit-code discipline **0 clean / 1 verdict / 2 infrastructure,
  never a skip path** (`scripts/probe_framework_coinstall.py:36`, `:47-57`, `:80-82`, `:171-194` —
  positive infra markers checked *before* the verdict marker, and anything unrecognised is infra:
  *"Refusing to guess a verdict"*).
* **Package identity.** npm `@zer07labs/seam-sdk` (`ts/package.json:2`), registry
  `https://npm.cloudsmith.io/zer07labs/internal/` (`:14-17`); python `seam-sdk`
  (`python/pyproject.toml:2`). Both stamped by `scripts/set_version.sh` — only those two files, with
  a read-back postcondition at `:52-61` — and held equal by `ci.yml:23-38`.

### The known-unverifiable bit, stated up front

`yank.yml`'s query shape has **never been executed against the live API by any test**:
`scripts/test_yank_gate.py:36-48` deliberately truncates the workflow shell at `echo "querying` and
says so. So this plan inherits an unproven `?query=…` syntax. That is answered by a **canary query**
(Phase 4): every run also asks about versions that are known-published, and an empty canary response
is **exit 2, infrastructure** — never "no drift". A broken instrument cannot report a clean world.

⚠ There are **two** unproven things in that syntax, not one, and they fail differently:

* the `?query=` **endpoint and filter shape** — if wrong, `curl -sf` 4xx's or the body is not a list.
  Loud, and the canary catches it.
* the **`version:` qualifier** — if Cloudsmith silently *ignores* an unrecognised qualifier rather
  than erroring, the response is "all `seam-sdk` packages, first 50 by whatever the default order
  is", the client-side `.version == VERSION` filter finds nothing, and the run reports **drift** for
  a version that is published. A pinned-version canary does **not** catch this: the canary's own
  rows would be missing too, so it degrades to exit 2 rather than a false exit 1 — but only by luck,
  and only while the canary version is outside the first 50. Phase 4 therefore adds a **truncation
  check**: a response carrying exactly `page_size` rows is treated as evidence the qualifier was not
  applied, and is `InfraError`.

### Baseline measured at `f177cfb`

⚠ **The python-suite count is not a fixed number, and no acceptance criterion may treat it as one.**
`python/tests/test_compatibility_citations_resolve.py` parametrizes over every backticked `file:line`
in `PROGRESS.md`, so *any* phase that writes prose into `PROGRESS.md` — which is every phase — raises
the total. Three measurements make that concrete:

| tree | `cd python && .venv/bin/pytest -q` | `…test_compatibility_citations_resolve.py -q` |
|---|---|---|
| bare `f177cfb` | 1186 passed, 20 skipped | 434 passed |
| + the plan's `PROGRESS.md` repo map | 1229 passed, 20 skipped | 477 passed |
| + round-2's repo-map corrections (**current tip**) | **1245 passed, 20 skipped** | **493 passed** |

Each step moves both columns by the *same* delta (+43, then +16), which is the check that the growth
is citation parametrization and nothing else — confirmed by reverting `PROGRESS.md` alone and
re-measuring. **Every phase must state its own before/after pair and show the two deltas agree**,
rather than asserting equality against a number frozen when the plan was written.

* `python/.venv/bin/python -m pytest scripts -q` → **135 passed** (unchanged)
* `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` → **exit 6**, NOTE naming
  `contract/expected-local-lag.txt` and exactly seven `ContextBinding` fields
* `python -m pytest` (bare `python`) fails on this machine (Xcode shim) — use `python3` or
  `python/.venv/bin/python`
* Working tree carries the untracked `plans/aitp-timestamp-encoding.md`, which this plan never
  touches and which must stay untracked.

### Repo-wide constraints this plan operates under

* `.github/workflows/` declares **no `concurrency:` and no `continue-on-error:`** anywhere (verified
  by grep). This plan adds neither.
* Every new `scripts/test_*.py` must appear as its own named step in `ci.yml`'s `workflow-guards`
  job or `scripts/test_ci_gate.py:277-301` goes red — set equality both directions, tokens matched
  whitespace-delimited from `run:` strings.
* `workflow-guards` installs only `pyyaml pytest grpcio cryptography` (`ci.yml:642`), and
  `scripts/test_ci_gate.py:191-201` forbids adding `BUF_TOKEN`, `buf-setup-action` or `make generate`
  to that job. `scripts/` has no equivalent of `python/tests/test_test_dependencies_are_declared.py`,
  so an undeclared import there passes locally and fails on CI. ⚠ **Corrected from the briefing:
  the blast radius is one step, not the job's whole suite.** `workflow-guards` invokes pytest **once
  per file** (`ci.yml:644,649,654,660,665,671,677,682` — eight `python -m pytest <one file>` steps),
  so a collection error in a new file reddens *that* step; the steps above it have already run and
  reported, and the steps below it are skipped because a failed step ends the job. It is also
  **loud** — a named red check on the very PR that introduces it — not silent. Phase 2 is therefore
  a diagnostics improvement, not an outage prevention, and is re-scoped accordingly.
* ➕ **Exit code 1 is Python's own code for an uncaught exception, and 1 is this check's drift
  verdict.** Any crash — `ImportError`, `TypeError`, a `KeyError` on an unexpected JSON shape —
  therefore *reads as drift*. The precedent has this hole: `scripts/probe_framework_coinstall.py`
  catches only `InfraError` and lets everything else exit 1. This plan must not inherit it: the
  script wraps `main()` so that **any** unhandled exception becomes exit 2, and a test injects one.
* ➕ **`scripts/check_registry_drift.py` must import only the standard library.** The scheduled
  workflow (Phase 5) does a checkout plus `setup-python` and **no `pip install`** — deliberately, so
  the watcher needs no package index to run. A third-party import there is an `ImportError` on the
  scheduled run, which by the previous bullet would have been reported as drift. Both halves of that
  are asserted.
* `PROGRESS.md` is inside the citation guard (`python/tests/test_compatibility_citations_resolve.py:95-99`,
  floor 30, `CITATION_SLACK = 3` at `:802`). `plans/` is not scanned at all.
* ➕ **A second, sharper guard on the same documents, found by tripping it while writing this
  plan's `PROGRESS.md` section.** `test_unbound_bare_citations_do_not_grow` and
  `test_the_ceiling_is_not_slack` (`python/tests/test_compatibility_citations_resolve.py:1481-1500`)
  hold an **exact-equality ratchet** — `UNBOUND_BARE_CEILING` at `:1473-1477`, currently
  `PROGRESS.md: 68` — on backticked bare references of the form `` `:788` `` that bind to no file.
  A bare reference binds only to a full `` `path.ext:NNN` `` token **earlier on the same line**, or
  to a table row's subject cell. Adding a continuation line that carries `` `:788` `` with no full
  citation ahead of it on that line fails the suite, and *raising* the ceiling is explicitly the
  wrong fix. Phases 1 and 9 both write `PROGRESS.md`/`DECISIONS.md` prose and will meet this: keep
  every bare reference on the same line as its antecedent, or spell the path out in full.
* No writes outside `seam-sdk`. No `make generate` / `generate-local` / `clean`. No
  `check-contract.sh --write-manifest`. No dispatching workflows, publishing, re-pointing tags, or
  hitting a real registry from a test.

---

## Phase 1 — `publish.yml`'s blind-spot comment cites the issue it says it cites

**Status: DONE** (2026-09-06, commit on `feat/registry-drift-check`). Three divergences, all in the
guard rather than the edit:

* **Two tests, not one.** Criterion 3 said "one more test"; the Tests paragraph beside it names two,
  and criterion 4's red-first is unsatisfiable without the second. A plan defect — the verifier
  confirmed neither test is redundant. The file went 15 → 54 tests, because the guard needed a
  regression set (see below), not because the phase grew.
* **The pointer window is the promise LINE, not the paragraph.** The planned guard was defeated in
  three consecutive review rounds, each time by a decoy reference placed just inside a generously
  drawn boundary: first the whole 19-line comment block (`(see #69)` seventeen lines up satisfied
  it), then the paragraph (any comment line added below it), then the promise sentence with a
  one-line wrap extension (`.)`, `."`, `…`, `。` were misread as unfinished, so the verdict turned
  on the promise line's last character). The boundary is now the line, with no punctuation
  heuristic — it cannot be widened by editing the file it checks. **Cost accepted:** a citation
  that wraps onto a second line reads as absent and reddens the suite. Logged in `ASSUMPTIONS.md`.
* **The pattern accepts a workflow path as well as `#100`, and resolves it on disk.** Criterion 2
  asked for `#\s*100\b`. Phase 9 re-points this comment at the shipped workflow, so a path is a
  legitimate pointer — but it must exist (a regex cannot tell a live path from a dead one), it must
  not be `publish.yml` itself (a self-reference), and the existence check lists the directory
  rather than calling `is_file()`, because APFS resolves `Ci.yml` and `ubuntu-latest` does not.

Verification took three rounds and stopped at the cap; the user accepted the terminal fix. Evidence:
all 10 guard clauses caught by individual mutation, a 16-case sweep over promise-line endings, and
every defeat from all three rounds firing against the real file.

**Delivers.** `publish.yml:765` currently ends *"…it is deliberately NOT solved here (see the issue
this job cites)"* — and the job body (`:766-832`) cites **no issue number, no URL and no repo
reference anywhere**. The pointer to #100 was never written. This phase writes it.

**Depends on.** Nothing.

**Files.** `.github/workflows/publish.yml` (comment lines `761-765` only) ·
`scripts/test_release_notice_gate.py`.

**Approach, and why it is right.** Replace the five comment lines with five comment lines that name
`zer07labs/seam-sdk#100`. **Exactly five — the replacement must be line-count-neutral**, for two
reasons that are not cosmetic: `PROGRESS.md` and `DECISIONS.md` carry line-anchored citations into
`publish.yml` below this point (the citation guard resolves them structurally, and this plan's own
`PROGRESS.md` repo map cites `publish.yml:766-832`), and a line-neutral edit means the phase cannot
break them. If a five-line rewrite genuinely cannot say it, the phase must instead re-run
`python/.venv/bin/pytest python/tests/test_compatibility_citations_resolve.py -q` and repair every
citation that moved, in the same commit.

The comment stays *forward-looking* here and names only the issue. It is updated to name the shipped
workflow in Phase 9, when that file exists. Naming an unmerged path now would be a dead pointer —
which is the same defect this phase exists to fix, one indirection over.

*What I rejected:* putting the whole fix in Phase 9 as one edit. It leaves the repo carrying a
self-refuting comment for eight phases, and the defect is independent of everything else here.

**Edge cases & failure modes.**
* The guard added below is a **comment assertion**, which inverts `scripts/test_yank_gate.py:51-62`'s
  rule (*"strip comments before ANY static string assertion"*). That rule exists because a comment
  can satisfy a guard aimed at code. Here the comment **is** the subject, so the test must read raw
  YAML text and must say in its docstring why it is the one place that legitimately does.
* A future rewrite could satisfy an `"#100" in text` search from any part of the file. Scope the
  search to the contiguous comment block immediately above `release-outcome:`, located by parsing for
  the job key's line rather than by a hardcoded line number.

**Acceptance criteria.**
1. `git diff --stat` shows `publish.yml` with equal insertions and deletions confined to lines
   761-765, and no change inside `:766-832`.
2. The comment block above `release-outcome:` matches `#\s*100\b` or the full issue URL.
3. `python/.venv/bin/python -m pytest scripts/test_release_notice_gate.py -q` passes with **one more
   test than before**.
4. **Red-first:** with the pre-fix text restored into a temp copy, the new test fails; the phase's
   test output shows that run.
5. `python/.venv/bin/pytest python/tests/test_compatibility_citations_resolve.py -q` still passes.

**Tests.** `scripts/test_release_notice_gate.py` gains
`test_the_blind_spot_comment_points_at_a_real_issue`: locate the `release-outcome:` job key in the
raw file text, take the contiguous `#`-prefixed block directly above it, assert it is non-empty
(anti-vacuity: a block of zero lines would satisfy any "no bad pointer" phrasing), assert it still
contains the phrase `never ran at all` (a named sentinel, so a wholesale rewrite that drops the
subject fails rather than passes), and assert it carries an issue reference. A second test
`test_the_pointer_guard_fires_on_the_text_it_replaced` runs the same extraction over the literal
pre-fix five lines held as a fixture string and asserts it fails.

**Docs.** None beyond the comment itself. `CHANGELOG.md` is not touched — nothing consumer-visible
changed.

---

## Phase 2 — the `scripts/` twin of the declared-dependency guard

**Status: TODO**

**Delivers.** A test that every third-party top-level import in any `scripts/test_*.py` is installed
by `workflow-guards`' single `pip install` line (`ci.yml:642`).

**Depends on.** Nothing. Ships alone and is useful alone. ⚠ **Nothing depends on it either** — see
the honest scoping below. It is sequenced first because it is the cheapest thing in the plan, not
because Phase 3 needs it.

**Files.** `scripts/test_ci_gate.py`.

**Approach, and why it is right.** `python/tests/` is protected:
`python/tests/test_test_dependencies_are_declared.py` walks every test module's AST and fails when an
import is not in the `dev` extra. `scripts/` has no such guard.

⚠ **The blast-radius argument this phase was originally justified by does not survive reading
`ci.yml`.** `workflow-guards` invokes pytest **once per file** (`ci.yml:644,649,654,660,665,671,677,682`),
so a collection error in a new `scripts/` test reddens exactly its own step: the steps above it have
already run and reported, and the steps below are skipped only because a failed step ends the job.
And it is discovered **loudly, on the PR that introduces it**, by a named check. So this phase does
not prevent an outage; it converts a CI-only, moderately confusing failure ("collecting … ERROR")
into a local, named one. That is worth having — but it is worth having *at that size*, and this
plan should not pretend otherwise.

**Two consequences, both applied:** (i) Phase 3 no longer declares a dependency on this phase — its
imports (`json`, `subprocess`, `textwrap`, `pathlib`, `datetime`, `pytest`, `yaml`) are already
covered by `ci.yml:642`, so the ordering was invented, not real; (ii) this phase is **droppable**. If
the reviewer wants the PR narrowed to #100's second half, drop it and file it — it is a `scripts/`
hygiene guard, not registry-vs-source drift.

`scripts/test_ci_gate.py` is the right home if it is kept: it already owns the assertions about that install list
(`:170-201`, including the negative half that forbids `BUF_TOKEN` / `buf-setup-action` /
`make generate`). The new test reads the install line out of the same YAML rather than hardcoding
`{pyyaml, pytest, grpcio, cryptography}` — a hardcoded copy would go stale the day line 642 changes,
which is the failure this repo names most often.

*What I rejected:* switching `workflow-guards` to a single `pytest scripts/` invocation, which would
make the problem moot. `scripts/test_ci_gate.py:285-287` already rejected it and records why: the
per-file steps give a named check per gate in the PR's check list, which is worth keeping.

**Edge cases & failure modes.**
* `sys.stdlib_module_names` needs 3.10+; `workflow-guards` pins 3.11 (`ci.yml:635`). Fine, and the
  pin is itself asserted at `scripts/test_ci_gate.py:180-184`.
* First-party names: `scripts/` is not a package, and the sibling tests import their subjects by
  `importlib.util.spec_from_file_location` (`scripts/test_vendored_spec_gate.py:35-47`), not by
  `import`. So the first-party set should be empty; if a future file does `import check_registry_drift`
  the guard should fail and force the loader idiom. Say that in the assertion message.
* Import forms: `import x`, `import x.y`, `from x import y`, `from x.y import z`, and conditional
  imports inside functions. Walk the AST for `ast.Import` / `ast.ImportFrom` at any depth; take
  `module.split(".")[0]`; ignore relative imports (`node.level > 0`).
* Distribution-vs-module naming: `yaml` ← `pyyaml`. Reuse
  `python/tests/test_test_dependencies_are_declared.py`'s normalisation approach; do not import that
  module (it lives in a different directory and would drag its fixtures into a credential-free lane).

**Acceptance criteria.**
1. `python/.venv/bin/python -m pytest scripts/test_ci_gate.py -q` passes, count up by 2.
2. **Red-first:** a temporary `scripts/test_zz_synthetic.py` containing `import requests` makes the
   new test fail with a message naming `requests` and `ci.yml:642`; the file is deleted before
   commit. Test output shows both the red and the green.
3. **Anti-vacuity:** a companion test asserts the scan found `pytest` among the third-party imports
   (named sentinel) and that the scanned file count is ≥ 5 (numeric floor; measured 7 at `f177cfb`,
   so ⅓ ≈ 2 would be too slack — 5 is chosen because the set is a stable, slowly-growing roster and
   a drop below 5 means the glob broke).
4. `python/.venv/bin/python -m pytest scripts -q` → **137 passed**.

**Tests.** In `scripts/test_ci_gate.py`:
`test_every_scripts_test_import_is_installed_by_the_guards_lane` and
`test_the_scripts_import_scan_is_not_vacuous`.

**Docs.** A docstring on the new test naming the collection-error blast radius. No user-facing doc.

---

## Phase 3 — `scripts/check_registry_drift.py`: the decision core, offline

**Status: TODO**

**Delivers.** The script that answers the question, with the registry response **injected from a
file**. No network, no `gh`, no reporting. Exit **0** clean or within grace, **1** drift, **2**
infrastructure.

**Depends on.** ⚠ **Nothing.** (Was "Phase 2"; that dependency was invented. Every import this phase
needs — `json`, `subprocess`, `textwrap`, `pathlib`, `datetime`, `pytest`, `yaml` — is already
installed by `ci.yml:642`, so Phase 2's guard is not a precondition for anything here.)

**Files.** `scripts/check_registry_drift.py` (new) · `scripts/test_registry_drift_gate.py` (new) ·
`.github/workflows/ci.yml` (one new `workflow-guards` step).

**Approach, and why it is right.**

```
scripts/check_registry_drift.py           # stdlib imports ONLY — the scheduled workflow pip-installs nothing
  [--repo DIR]              default: the repo this script lives in
  [--packages-json FILE]    a saved Cloudsmith list response; Phase 4 makes it optional
  [--now ISO8601]           default: datetime.now(timezone.utc)
  [--soft-grace-minutes N]  default: SOFT_GRACE_MINUTES = 90
  [--hard-grace-minutes N]  default: HARD_GRACE_MINUTES = 360
Exit: 0 = the registry serves main's version, or the version is younger than the hard window
      1 = drift
      2 = infrastructure — never a verdict, INCLUDING every unhandled exception
```

**The exit-code contract has a hole in the precedent, and this phase closes it.** Python exits **1**
on an uncaught exception, and 1 is this script's drift verdict, so a crash reads as drift.
`scripts/probe_framework_coinstall.py` catches only `InfraError` and inherits exactly that. Here:

```python
if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException as exc:          # noqa: BLE001 — deliberate; see the module docstring
        print(f"::error::check_registry_drift crashed: {exc!r}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(2)
```

A test injects a crash (`--repo` pointed at a path whose `pyproject.toml` is a directory, or a
monkeypatched entry point) and asserts **2**, not 1.

Sequence:

1. **`source_version(repo)`** — the first `^version = "..."` in `python/pyproject.toml`, the same
   rule `scripts/set_version.sh:46-50` stamps by and `ci.yml:33` / `publish.yml:165` read by.
   Cross-check `ts/package.json`'s `version`. **A mismatch is `InfraError`, not drift**: `ci.yml:23-38`
   makes it impossible on a green `main`, so if it happens the world is not the world this script
   models, and guessing a verdict there is exactly what `probe_framework_coinstall.py:191-194`
   refuses to do.
2. **`version_landed_at(repo, version)`** — `git -C <repo> log -1 --format=%cI
   -S'version = "<version>"' -- python/pyproject.toml`. Content-derived, so it works identically in
   state B (tag exists) and state C (no tag), which is the whole reason it is not keyed on the tag.
   Empty output → `InfraError` ("cannot date this version on main"). A shallow clone lands here.
3. **`tag_present(repo, version)`** — `git -C <repo> tag -l "v<version>"`, non-empty. Diagnostic
   only: it never changes the verdict, it changes the **remediation text**, because B, C and the
   never-dispatched hand-bump need different instructions.
   **Denominator guard:** `git tag -l 'v*'` must return ≥ `TAG_FLOOR = 20` (⚠ **measured 67 at
   `f177cfb`** for that exact glob — the plan previously said 63, which is the count of `v0.7.*`, not
   of `v*`; the four `v0.3.0`/`v0.5.1`/`v0.6.0`/`v0.6.1` tags also match. ⅓ ≈ 22, rounded down to 20
   per the repo's floor convention). Below that, the checkout was fetched without tags and *every*
   release would be misdiagnosed as state C → `InfraError`.
   ➕ **`tag_created_at(repo, version)`** — `git -C <repo> for-each-ref
   --format='%(creatordate:iso-strict)' "refs/tags/v<version>"`, empty when there is no tag. These
   are annotated tags (`release-on-runtime.yml:182` uses `git tag -a`), so a creator date exists.
   This feeds the clock in step 5, not the verdict.
4. ➕ **`assert_query_safe(version)`** — the version is interpolated into a URL query string
   (`?query=seam-sdk+version:<version>`), where `+` means *space* and `#`, `&`, `%` and whitespace
   are all structural. `yank.yml:64-66` guards its own input with
   `case "$VERSION" in *[!0-9.]*|"") … exit 1`, and this plan had dropped that guard entirely. Any
   version not matching `^[0-9]+(\.[0-9]+)*$` → `InfraError`, naming the character. Note this is a
   *stronger* obligation than `yank.yml`'s: there the version is operator-typed and a refusal is
   free; here it is read from `main`, so a refusal must be exit 2 (the world is not the world this
   script models) and never exit 1.
5. **`registry_formats(...)`** — for this phase, parse `--packages-json` with the exact `jq`-equivalent
   filter `yank.yml:73-76` applies: `version == VERSION`, `format in {python, npm}`, and
   `name` with a leading `@scope/` stripped `== "seam-sdk"`. Implemented in Python over
   `json.loads`, not by shelling to `jq`, so the filter is unit-testable and its three clauses can
   each be driven red.
6. **Verdict** — `missing = {"python", "npm"} - found`, with the clock
   `age = now - max(version_landed_at, tag_created_at or version_landed_at)`.
   * `missing` empty → exit 0.
   * `missing` non-empty and `age < SOFT_GRACE_MINUTES` → exit 0, silent deferral, printing the age
     and when it will stop deferring.
   * `missing` non-empty and `SOFT ≤ age < HARD` → exit 0, **plus a `::warning::`** naming the age,
     both thresholds and the missing formats. Visible in the run summary; files nothing.
   * else → exit 1.

**Ordering that matters: the registry is consulted BEFORE the grace window is applied.** The cheap
implementation checks the age first and skips the query for a fresh version — and then a broken
instrument goes unnoticed on exactly the runs following a release, which is when it is needed. The
check must exercise its instrument on every run.

**The grace window is two-tier: `SOFT_GRACE_MINUTES = 90`, `HARD_GRACE_MINUTES = 360`.** ⚠ This
replaces a single 360-minute cliff, which was calibrated against the wrong bound.

*What the single cliff got wrong.* Its argument was: no publish job declares `timeout-minutes`
(`publish.yml:771` is the only one), so a job could run to GitHub's 360-minute default, so the check
must stay silent for 360 minutes. The premise is true and the conclusion does not follow. **A publish
job that runs to the default limit is killed, the run fails, and `release-outcome` reports it** — it
is `if: always()` (`publish.yml:768`) and `needs:` every publish job (`:769`). So the hung-job case
is already covered by the half that shipped. The drift check does not owe it silence; it owes it
*non-duplication*. Sizing the whole window on it bought nothing and cost 12 hours of blindness on the
case the check actually exists for.

*The two tiers, each sized on its own bound.*
* **90 minutes (soft).** The declared ceilings sum to ≈ 40 min: `ci-green` 40 × 30 s
  (`publish.yml:82-83`), then `npm`/`python` build+publish, then `registry-smoke` 10 × 30 s per
  ecosystem in one job (`:625,633` and `:721,724`). 90 is a bit over 2×, absorbing queue time, cold
  caches and a `setup-*` miss. Below it, silence: a publish is plausibly still running and there is
  nothing to say.
* **360 minutes (hard).** GitHub's default per-job limit, so above it *no publish job for this
  version can still be alive*. Only here does the check file an issue, which is what guarantees it
  can never duplicate `release-outcome` against a still-running publish.
* **Between them: a `::warning::` and exit 0.** The declared ceilings have been blown, so something
  is wrong; the hard ceiling has not, so it may still resolve itself. This is the state the single
  cliff represented as "clean", and representing it as clean is what a reader of a green run would
  have believed.

*What that buys against the cron.* With `cron: "17 */2 * * *"` (Phase 5, changed from every 6 h):
worst-case time to a **visible warning** ≈ 90 min + 120 min = **3.5 h**; worst-case time to a **filed
issue** ≈ 360 + 120 = **8 h**. The single 360-cliff on a 6-hour cron gave no warning at all and ≈ 12 h
to an issue. The failure historically went unnoticed for **five days** (`publish.yml:748-751`), so
either is a win — but 3.5 h/8 h is strictly better than 12 h at four extra runs a day of a ~1-minute
job, and it does not buy that by trading in false positives: the *issue-filing* threshold is
unchanged at 360, so nothing that was suppressed before is reported now.

**The clock is `max(commit date, tag date)`, not the commit date alone.** ⚠ A hole in the original:
`release-on-runtime.yml:176-181` has a branch where `git diff --quiet` is true and **no commit is
made at all** — "already at $VER — tagging only" (`:177`) — and `:182`/`:186`/`:187` tag and push
anyway. A re-dispatch of a version already on `main` therefore gets a `version_landed_at` from the
*original* bump, which is normally long past 360 minutes, so the retry gets **zero grace** and the
check can fire against a publish that started ninety seconds ago. Taking `max()` with the tag's
creator date makes the clock mean "when did the most recent attempt to publish this version begin",
which is what the window is actually for. In state C there is no tag and it degrades to the commit
date — correct, since no attempt was ever launched.

*What I rejected, and why:*
* **Keying on the tag** ("latest tag > latest published"). Blind to state C by construction, and
  state C is the half `release-outcome` cannot see either — the check would inherit the very blind
  spot it exists to close.
* **Reasoning about version successorship** ("0.7.78 should exist because 0.7.77 does"). Eleven
  numbers in the `v0.7.*` range have no tag at all; `v0.7.74` was a runtime workspace-crate bump with
  no SDK dispatch, and flagging it would be wrong. Membership-only makes the whole class impossible.
* **Suppressing while a `publish.yml` run for that tag is in progress** (query the Actions API
  instead of a window). Attractive — it replaces a guess with an observation — but it cannot see
  state C at all, because with no tag there is no run to observe. It would have to sit *in addition
  to* the window, and a second suppression path is a second way to be silently quiet. Recorded, not
  taken.
* **Reading `git tag` for the version instead of `git log -S`.** Same blindness as above.
* **Comparing against `seam-runtime`'s released version.** Out of scope by constraint, and wrong in
  principle: this check is about whether *this repo's own claim* is true.

**Edge cases & failure modes.**
* Version string with regex-special characters — `-S` takes a literal string by default (no
  `--pickaxe-regex`), so no escaping is needed; assert that with a test using a version containing a
  `.`.
* A version reverted and re-introduced: `-1` takes the most recent commit that changed the count,
  which is the moment `main` most recently started claiming it. Correct.
* Git not on `PATH`, or `--repo` not a git repo → `InfraError`.
* `--packages-json` missing/unreadable/not JSON/not a list → `InfraError`.
* A Cloudsmith row whose `name` is `@zer07labs/seam-sdk-extra` must not satisfy `seam-sdk` — the
  `sub("^@[^/]+/"; "")` equality is exact, and a test drives that.
* Clock skew: `--now` exists so tests are deterministic; production always uses real UTC.
* **Never a skip path.** There is no code path that prints "cannot determine" and exits 0.

**Acceptance criteria.** All hermetic — throwaway git repos in `tmp_path`, following
`scripts/test_vendored_spec_gate.py:8-11` (*"These build **real git repositories** in `tmp_path`
rather than mocking `git`"*), plus JSON fixtures written to disk.

1. **State A → 0.** Repo at `0.7.77`, commit dated 10 days ago, response contains `0.7.77` in both
   formats → exit 0, stdout contains `both formats`.
2. **State B → 1.** Repo at `0.7.78`, commit 10 days old, tag `v0.7.78` present, response lacks it →
   exit 1, stdout names the tag as **present** and gives the state-B remediation.
3. **State C → 1.** Same but no tag → exit 1, stdout names the tag as **absent** and cites
   `release-on-runtime.yml:180-187` in its remediation.
4. **Soft tier suppresses a fresh version, silently.** Same as (2) with the clock 30 minutes ago →
   exit 0, **no `::warning::` in stdout or stderr**, and stdout says how old it is and when it will
   stop deferring.
5. **The warn band warns without alarming.** Clock 200 minutes ago → exit 0 **and** a `::warning::`
   naming the age, both thresholds and the missing formats. Asserted as exit-0-with-warning, so a
   future change that promotes it to exit 1 goes red here rather than silently starting to file
   issues an hour and a half early.
6. **Hard tier stops suppressing.** Clock 361 minutes ago → exit 1. **All four boundaries are
   asserted, both directions:** 89 → 0 silent, 91 → 0 warned, 359 → 0 warned, 361 → 1.
7. ➕ **The clock takes the tag date when it is later.** A repo whose version commit is 10 days old
   but whose `v<version>` tag was created 30 minutes ago → exit 0 (soft tier), *not* exit 1. This is
   the `release-on-runtime.yml:176-181` re-dispatch path; without `max()` it exits 1. Its mirror: a
   10-day-old commit with a 10-day-old tag → exit 1.
8. **Half-publish → 1**, naming exactly the missing format, for both single-format cases.
9. **Broken instrument → 2, never 0.** An empty list, a list of unrelated packages, malformed JSON,
   a JSON object rather than a list, and a missing file each exit 2 and print an infrastructure
   message. **None of them may exit 0.** Asserted as a group with an explicit
   `assert proc.returncode == 2` per case.
10. **Lockstep mismatch → 2.** `ts/package.json` at `0.7.78`, `pyproject.toml` at `0.7.77` → exit 2.
11. **Tag-floor guard → 2.** A repo with 3 tags → exit 2 naming `TAG_FLOOR`.
12. **Undateable version → 2.** A repo whose `pyproject.toml` was never committed at that version.
13. ➕ **Query-unsafe version → 2.** Versions `0.7.78+local`, `0.7.78 rc1`, `0.7.78&x=1` and `""`
    each exit 2 naming the offending character — never 1, and never a request built from them.
14. ➕ **Any unhandled exception → 2, never 1.** Injected by pointing `--repo` at a tree whose
    `python/pyproject.toml` is a directory (so the read raises `IsADirectoryError`, a type no
    handler catches). Assert exit 2 and that stderr carries a traceback. This is the criterion that
    stops a future `ImportError` from being reported as drift.
15. ➕ **The script imports only the standard library.** Its own AST is walked and every top-level
    import asserted to be in `sys.stdlib_module_names`, with a message saying the scheduled workflow
    runs no `pip install`. Anti-vacuity: the same test asserts the scan found ≥ 4 imports.
16. `python/.venv/bin/python -m pytest scripts -q` passes; `scripts/test_ci_gate.py`'s
    `test_every_scripts_test_file_runs_in_ci` passes, proving the new `ci.yml` step is wired.
17. **Mutation round (required, output pasted into the phase record):** invert the `missing`
    emptiness test → (1) red; replace `max(commit, tag)` with the commit date alone → (7) red;
    collapse the two tiers into one → (4) *or* (5) red; delete the top-level exception handler →
    (14) red with an exit of 1; delete the query-safety guard → (13) red. A guard never observed
    failing is not evidence.

**Tests.** `scripts/test_registry_drift_gate.py`, wired into `ci.yml`'s `workflow-guards` as its own
step named *"the registry-drift check fires on a real lag and refuses to guess"*, with the run token
`scripts/test_registry_drift_gate.py` present whitespace-delimited so
`scripts/test_ci_gate.py:289-296` sees it. Imports: `json`, `subprocess`, `textwrap`, `pathlib`,
`datetime`, `pytest`, `yaml` — all covered by `ci.yml:642` and by Phase 2's new guard.

**Docs.** Module docstring in the style of `scripts/probe_framework_coinstall.py:1-37`: why it exists,
the three lag states, the two things easy to get wrong, and the exit-code contract on one line.

---

## Phase 4 — the live registry query, and the canary that proves the instrument works

**Status: TODO**

**Delivers.** The script learns to fetch the Cloudsmith response itself when `--packages-json` is
absent, and to refuse loudly when it cannot.

**Depends on.** Phase 3.

**Files.** `scripts/check_registry_drift.py` · `scripts/test_registry_drift_gate.py`.

**Approach, and why it is right.**

The script shells out to **`curl`**, not `urllib`. This is not stylistic: the repo's hermeticity
convention is *stub executables first on `PATH` in `tmp_path`* — `scripts/test_release_notice_gate.py:62-83`,
`scripts/test_publish_gate.py:52-77` — with the explicit rule *"no mocks, no cassettes"*. `urllib`
can only be controlled by monkeypatching, which would make this the one guard in the repo whose world
is a mock. `curl` also keeps the request shape byte-comparable to `yank.yml:69-71`, which is the
shape believed to work.

Token: read from the environment as `SEAM_REGISTRY_TOKEN`. The *resolution* of that value from the
two secrets lives in the workflow shell (Phase 5), so `yank.yml:55-63`'s executed-shell test pattern
applies to it directly. **Absent or empty → `InfraError`, exit 2.** This is a deliberate divergence
from `yank.yml:61-63`, which exits 1: there, 1 means "refused"; here, 1 means "the registry is behind
the source", and a missing secret must never be able to say that.

**⚠ The single pinned canary in the previous draft was broken, in the exact direction that matters.**
It was `CANARY_VERSION = "0.7.77"` — which is `python/pyproject.toml:3`'s current value, i.e. **the
target**. Whenever `main`'s version equals the canary (true today, and true for as long as no runtime
release lands), the two GETs are the same query, and a genuine drift on that version makes the canary
come back empty. The canary is checked first and raises `InfraError`, so the run exits **2** — the
check reports "my instrument is broken" for precisely the condition it exists to report as drift.
That is a structural mute on the live version, not a corner case. Separately, `yank.yml` can delete
any version, so a single pinned canary is one yank away from a permanent exit 2 that everyone learns
to scroll past.

**Canary, revised: a set, self-healing, and never overlapping the target.**

```python
#: Versions asserted to be published in BOTH formats. A set, not a single pin, so one yank does not
#: brick the instrument; three, so two would have to be yanked before this needs an edit. Any entry
#: equal to the target is dropped at runtime — a canary that IS the target proves nothing and would
#: convert that version's drift into an exit 2.
#:
#: Selection rule, and it is not "any tag": a tag proves a release was ATTEMPTED, not that it landed.
#: publish.yml:748-749 records v0.7.69, v0.7.70 and v0.7.72 as correctly REFUSED — tagged, never
#: published — so they and every never-tagged version (0.7.44-46, 0.7.62, 0.7.74, ...) are excluded.
#: Each entry below has both `vX` and `go/vX` tags and no recorded refusal.
CANARY_VERSIONS = ("0.7.50", "0.7.60", "0.7.65")
```

**These three must be confirmed against the live registry once, by hand, before Phase 4 merges** —
one `curl` with the real credential, output pasted into the phase record. A canary roster assumed
rather than observed is the same defect as the `?query=` shape this whole mechanism exists to
de-risk, one level up. If any of the three is not actually there, replace it; do not lower the "≥ 1
row of each format" bar.

Per run: `candidates = [v for v in CANARY_VERSIONS if v != source_version]`. If `candidates` is empty
→ `InfraError` naming the constant (only reachable if the roster is reduced to one). The instrument
is **healthy if any candidate returns ≥ 1 row of each format**; unhealthy only if *all* of them come
back empty — which is what makes it survive an individual yank. On unhealthy: `InfraError`, exit 2,
naming every candidate tried and the two possible causes (the query shape is wrong, or all the
canary versions have been yanked and the roster needs re-pointing).

Cost: 2 GETs on the common path (first candidate answers), at most 4 in the degraded one.

➕ **Truncation check, on every response including the canary's.** If a response carries exactly
`page_size` rows, treat it as evidence that Cloudsmith **ignored** the `version:` qualifier and
returned a first page of everything — in which case a target version outside that page reads as
"absent" and the run would report drift for a published version. `InfraError`, exit 2, saying to
raise `page_size` or stop trusting the qualifier. This is the one failure mode a pinned-version
canary could not catch (its rows would be missing for the same reason, so it degrades to 2 only by
luck and only while it sits outside the first page); the check makes it deterministic.

The canary is the runtime form of this repo's *"pin the denominator"* idiom
(`scripts/test_ci_gate.py:388-402`, `python/tests/test_test_dependencies_are_declared.py:164-181`:
one named sentinel plus one numeric floor). Without it, *every* failure of the query surface reads as
"drift", which is the single worst outcome available here: a confident wrong verdict.

Order: **canary first.** A failed instrument must abort before the target answer is even computed, so
there is no code path on which a target result is interpreted against an unproven instrument.

*What I rejected for the canary:* a version-less probe (`?query=seam-sdk&page_size=50`) as the
instrument check. It is genuinely self-healing and immune to every yank — but it exercises a
*different* query than the target, so it cannot prove the `version:` qualifier works, which is the
half of the syntax that is actually unproven. The truncation check covers that hole more directly and
at lower cost. Recorded because it is the obvious alternative and a later reader will think of it.

`curl` invocation mirrors `yank.yml:69-71`: `-sf` (so a 4xx/5xx is a non-zero exit rather than an
error body parsed as JSON), `-H "X-Api-Key: $TOKEN"`, output to a temp file. Add
`--max-time 60`; `yank.yml` has none, and a hung GET in a scheduled job is a silent 6-hour burn.
Non-zero `curl` → `InfraError` carrying the exit status.

*What I rejected:* querying without a version filter and paginating the whole package list to derive
"the latest published version". It needs pagination in an area where I cannot verify the API's
behaviour, it re-introduces version ordering (the thing Phase 3 removed on purpose), and it answers a
harder question than the one being asked.

**Edge cases & failure modes.**
* `curl` absent from `PATH` → `InfraError` (`FileNotFoundError`), the same shape as
  `probe_framework_coinstall.py:153-154`.
* HTTP 200 with a body that is not a JSON list → `InfraError`.
* HTTP 200 with `[]` for the **target** → that is the drift signal, and it is only trusted because
  the canary already returned rows on the same credential in the same run.
* HTTP 401/403 → `-sf` gives exit 22 → `InfraError`. A stripped-`Bearer ` bug (the one
  `yank.yml:38-54` documents) therefore surfaces as infrastructure, not as drift.
* **One** canary version is yanked → the run is unaffected; another candidate answers. **All three**
  yanked → exit 2 with a message naming every candidate tried. Loud, correct, and now requiring
  three deliberate acts rather than one.
* **A canary version becomes the target** (`main` regresses onto it, or the roster is edited to
  include the current version) → that entry is dropped from the candidate list at runtime, so it can
  never mask that version's own drift. If dropping empties the list → exit 2 naming the constant.
* Token leakage: the script must never print the token or the full URL with headers; it prints the
  URL path and the query only. A test greps stdout+stderr for the stub token value in every failure
  path.

**Acceptance criteria.**
1. **Happy path with stubbed `curl`:** first canary candidate and target both return rows → exit 0;
   the stub's call log shows exactly 2 invocations, and their argv contains the two expected
   `?query=` strings.
2. **All canaries empty → 2**, even when the target query would have returned rows. Asserted
   explicitly, because it is the case that proves the ordering.
3. ➕ **One canary empty, the next populated → the run proceeds normally** (exit 0 on a populated
   target, exit 1 on an empty one past the hard tier). This is the yank-resilience property; without
   it the roster is a single pin wearing a tuple.
4. ➕ **`source_version` equal to a roster entry → that entry is never queried** (asserted from the
   call log) **and the run still reaches a verdict.** With `main` at `0.7.50`, an empty target must
   exit **1**, not 2. This is the exact defect the previous draft shipped and is the criterion that
   keeps it fixed.
5. ➕ **Truncation → 2.** A response carrying exactly `page_size` rows exits 2, for the target and
   for a canary independently. Never 1.
6. **Target empty, canary populated → 1** (past the hard tier) — the real drift path, end to end,
   with no file injection.
7. **`curl` exits non-zero (401 simulated) → 2.** Never 1, never 0.
8. **`SEAM_REGISTRY_TOKEN` unset → 2**; **set to empty → 2.** Modelled as absent-from-env vs
   empty-string, distinctly, per `scripts/test_yank_gate.py:65-78`.
9. **`--packages-json` still works** and, when given, performs **zero** `curl` calls (the stub's call
   log is empty) — the offline path Phase 3 shipped must not silently start requiring a network.
10. **No token appears in any output**, asserted over every failing case.
11. **Mutation round:** delete the canary check → (2) red; change `-sf` to `-s` → (7) red (the error
    body parses as "no rows" and the run reports drift); swap the canary/target order → (2) red;
    remove the `v != source_version` filter → (4) red **with an exit of 2**; delete the truncation
    check → (5) red.

**Tests.** Extend `scripts/test_registry_drift_gate.py`. The `curl` stub is a heredoc `#!/usr/bin/env
bash` script, `chmod(0o755)`, first on `PATH` in `tmp_path`, appending every invocation to a call-log
file and emitting a pre-rendered response — the exact shape of
`scripts/test_release_notice_gate.py:62-83`.

**Docs.** Module docstring gains a *"why there is a canary, and why it is a set"* paragraph, and
`CANARY_VERSIONS` carries its own comment with the selection rule (published, not merely tagged) and
the re-point instruction.

---

## Phase 5 — `.github/workflows/registry-drift.yml`, read-only

**Status: TODO**

**Delivers.** The scheduled workflow. It runs the check and goes **red** on drift. It files nothing
yet.

**Depends on.** Phase 4.

**Files.** `.github/workflows/registry-drift.yml` (new) · `scripts/test_registry_drift_gate.py`.

**Approach, and why it is right.**

Shipping the read-only half first is a real phase boundary, not a slice for its own sake: **the first
live scheduled run happens with no write permission at all.** If the inherited `?query=` shape is
wrong, the failure is an exit-2 log entry, not a stream of issues.

```yaml
name: registry drift (does Cloudsmith serve what main says?)

on:
  schedule:
    - cron: "17 */2 * * *"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  drift:
    name: the registry must serve the version main declares
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          fetch-tags: true
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - name: compare Cloudsmith against main's declared version
        env:
          CLOUDSMITH_API_KEY: ${{ secrets.CLOUDSMITH_API_KEY }}
          CARGO_REGISTRIES_ZER07LABS_TOKEN: ${{ secrets.CARGO_REGISTRIES_ZER07LABS_TOKEN }}
        run: |
          set -euo pipefail
          TOKEN="${CLOUDSMITH_API_KEY:-}"
          TOKEN="${TOKEN#Bearer }"
          if [ -z "$TOKEN" ]; then
            TOKEN="${CARGO_REGISTRIES_ZER07LABS_TOKEN:-}"
            TOKEN="${TOKEN#Bearer }"
          fi
          if [ -z "$TOKEN" ]; then
            echo "::error::No Cloudsmith credential in scope — this is INFRASTRUCTURE, not drift."
            exit 2
          fi
          echo "::add-mask::$TOKEN"
          SEAM_REGISTRY_TOKEN="$TOKEN" python3 scripts/check_registry_drift.py
```

**Trigger set: `schedule` + `workflow_dispatch`, and deliberately NO `pull_request:`.**
`framework-coinstall.yml:32-37` has a `pull_request:` `paths:` filter and can afford it because it
*"needs no credentials anywhere in this job"* (`:62-64`). This job does need one, and **secrets are
not available to `pull_request` runs from a fork** — so a fork PR would fail this workflow for a
reason that has nothing to do with the PR, which is precisely the "red for the wrong reason" that
`framework-coinstall.yml:5-8` refuses. PR-time coverage comes instead from
`scripts/test_registry_drift_gate.py` in `workflow-guards`, which executes the same shell and the
same script hermetically and needs no credential — the arrangement `yank.yml` already uses (it has no
`pull_request` trigger at all, and `scripts/test_yank_gate.py` is its entire PR-time coverage).

**This workflow is NOT in `ci-ok`'s `needs:`, and cannot be.** The standing rule "a new CI job must be
in `ci-ok`'s `needs:`" applies to jobs in `ci.yml`; this is a separate workflow, and `needs:` only
orders jobs within a run (`publish.yml:42-44` spells that out — corrected from `:44-46`, which starts
one line past the sentence it cites). The deeper reason is
`framework-coinstall.yml:5-8`'s, inherited unchanged: **the answer changes when Cloudsmith changes,
not when this repository changes**, so gating merges on it would hold unrelated work hostage to a
third party's uptime. If a later reviewer concludes otherwise, that is a real fork and belongs in
Open questions, not in a quiet edit.

`cron: "17 */2 * * *"` — ⚠ **every two hours, changed from every six.** Offset off the hour because
GitHub delays schedules under top-of-hour load. The interval is what converts Phase 3's two tiers
into actual latency: worst-case time to a visible `::warning::` = `SOFT` 90 min + one interval =
**3.5 h**; worst-case time to a filed issue = `HARD` 360 min + one interval = **8 h**. At six hours
those were "no warning at all" and 12 h. The cost is 12 runs a day instead of 4, each ~1 minute with
two GETs and one `gh issue list` — negligible against Actions minutes, and it buys nothing in false
positives because the *issue-filing* threshold did not move.

`timeout-minutes: 10` is declared, unlike `publish.yml`'s publish jobs — a watcher that can hang for
six hours is a watcher that is not watching.

⚠ **`permissions:` here is `contents: read` only, and that is a Phase-5 statement, not a final one.**
Phase 6 adds `issues: write` and Phase 7 needs **`actions: read`** — `gh api
repos/…/actions/workflows/…/runs` reads the Actions API, and a declared `permissions:` block grants
*only* what it lists, so an undeclared `actions` scope is `none` and that query 403s.
`publish.yml:30-34` declares `actions: read` at top level for exactly this reason (`ci-green` reads
check runs). Whichever phase lands the staleness arm must add the scope in the same commit; a test
asserts the two travel together.

*What I rejected:* `concurrency:` to cancel overlapping runs. No workflow in this repo declares one,
the job is ~1 minute against a 6-hour period, and cancelling a run mid-flight is a way to produce a
missing answer that looks like a passing one.

**Edge cases & failure modes.**
* `fetch-tags: true` **and** `fetch-depth: 0` are both set explicitly. `fetch-depth: 0` alone is
  believed to bring tags, but that is `actions/checkout` behaviour, not a contract; if it ever
  changes, every release is misdiagnosed as state C. Phase 3's `TAG_FLOOR` catches it as exit 2 —
  belt and braces, and both are asserted.
* Scheduled runs execute on the **default branch** — which is exactly "what the source says". A
  scheduled run never sees a feature branch. Good.
* Exit 2 makes the job red, same as exit 1. The log distinguishes them, and Phase 6's issue body
  never appears for an exit 2 — an infrastructure failure must not file a drift issue.
* GitHub disables scheduled workflows in repositories with 60 days of no activity. Not a live risk
  here, but it is one of the ways this check can silently stop; Phase 7 addresses it.

**Acceptance criteria.**
1. The workflow file parses (`yaml.safe_load`), and its `on:` keys are exactly
   `{schedule, workflow_dispatch}` — asserted with the `wf[True] if True in wf else wf["on"]`
   handling YAML 1.1's `on:` → `True` (`scripts/test_yank_gate.py:222`).
2. **The credential resolution, executed.** The step's shell is extracted and truncated at the
   `python3 scripts/` line (`scripts/test_yank_gate.py:36-48`'s technique), then run under plain
   `bash -c` — not `bash -e` (`:79-80`) — across the same six credential shapes as
   `scripts/test_yank_gate.py:93-113`, plus the four refusal shapes at `:132-140`. Every refusal
   exits **2**, not 1.
3. `::add-mask::` is present in the comment-stripped step body (`scripts/test_yank_gate.py:51-62`'s
   `_code()` — a comment mentioning masking must not satisfy it).
4. The step body contains no `&&`-joined `TOKEN=` assignment (`scripts/test_yank_gate.py:162-174`'s
   assertion, re-pointed).
5. `set -euo pipefail` present as an **exact line match**, not a substring (`:175-181`).
6. The checkout step sets `fetch-depth: 0` and `fetch-tags: true`; asserted with a message saying
   what a tag-less checkout would misdiagnose.
7. `timeout-minutes` is declared on the job; `continue-on-error` appears nowhere in the file.
8. **`buf generate` is not invoked** — `python/tests/test_workflows_generate_through_the_makefile.py`
   scans every workflow, `.yml` and `.yaml` (`:37-46`), and must stay green (verify by running it).
9. ⚠ `python/.venv/bin/pytest python/tests -q` → **no new failures and no drop**, with the count
   recorded before and after the phase and the citation-suite delta shown to match it. (The original
   text pinned **1186**, which was already false when the plan was written and is now 1245 — see the
   baseline table in Context for why pinning this number at all is the mistake.)
10. ➕ **The job installs nothing.** The workflow contains no `pip install`, asserted over the
    comment-stripped step bodies, with a message pointing at Phase 3's stdlib-only obligation — the
    two are one claim seen from either end.
11. **Mutation round:** delete `::add-mask::` → (3) red; replace the `if` cascade with
    `publish.yml`'s `&&` one-liner (`:227`, `:385`, `:607`, `:711` — four sites, all AND-lists) →
    (4) red; drop `fetch-tags: true` → (6) red; change a refusal's `exit 2` to `exit 1` → (2) red;
    add a `pip install` step → (10) red.

**Tests.** Extend `scripts/test_registry_drift_gate.py`.

**Docs.** A header comment in the workflow in `framework-coinstall.yml:3-21`'s register: what the
question is, why it is not a job in `ci.yml`, why there is no `pull_request` trigger, and that exit 2
is infrastructure and never a verdict.

---

## Phase 6 — reporting: one issue per version, a suppression path, and provable non-collision

**Status: TODO**

**Delivers.** `--report` mode. The check files an issue, comments-and-reopens rather than
duplicating, suppresses a deliberately-unpublished version, and cross-links the `release-outcome`
issue when one exists.

**Depends on.** Phase 5.

**Files.** `scripts/check_registry_drift.py` · `.github/workflows/registry-drift.yml` ·
`scripts/test_registry_drift_gate.py`.

**Approach, and why it is right.**

**Title:** `Registry drift: seam-sdk <version> is not installable` — e.g. `Registry drift: seam-sdk
0.7.78 is not installable`. `release-outcome` uses `Release <tag> did not publish`
(`publish.yml:788`, where `GITHUB_REF_NAME` carries the `v`) and matches by **exact title equality**
over open issues (`:818-824`). Two exact-equality matchers over two title shapes that share no
prefix cannot collide in either direction. That is true by construction — which is exactly why it
gets a test rather than a paragraph.

**One `gh issue list` serves three purposes**, and the exact-title discipline is what makes that safe:

```
gh issue list --state all --limit 500 \
  --json number,state,title,labels \
  --jq '.[] | [.number, .state, ((.labels|map(.name))|join(",")), .title] | @tsv' > "$LISTING"
```

read with `awk -F'\t'` on field 4 for exact equality, mirroring `publish.yml:824`. From the one
listing the script resolves (a) this version's drift issue, (b) whether it is closed **and** carries
`deliberately-unpublished`, and (c) an open `Release v<version> did not publish` issue to cross-link.

Decision table once drift is established:

| existing drift issue | action | exit |
|---|---|---|
| none | `gh issue create` | 1 |
| open | nothing — already reported | 1 |
| closed, no suppression label | `gh issue reopen` + `gh issue comment` | 1 |
| closed, labelled `deliberately-unpublished` | print a NOTE naming the issue | **0** |

And when there is **no** drift but an open drift issue exists for the current version: print a
`::notice::` saying it can be closed. **The check never closes an issue itself.** A reporter that can
silence itself is a different and larger kind of authority than one that can only speak;
`release-outcome` is write-additive only, and this stays the same shape.

**The suppression path, argued out.** A yanked version that is *still* `main`'s declared version is
genuinely the state "the source claims a version consumers cannot install" — alarming is correct by
default. What must not happen is alarming *forever* when the org has decided to leave it that way.
Three candidates:

* *A curated file* (`contract/`-style, like `contract/expected-local-lag.txt`). Rejected — but ⚠ **on
  corrected grounds.** The original argument was that a stale file entry is "silent in the dangerous
  direction": an entry left for `0.7.78` suppresses real drift the day `0.7.78` is current again.
  **The label has exactly the same property** — a closed, labelled issue titled
  `Registry drift: seam-sdk 0.7.78 is not installable` suppresses just as permanently, and just as
  silently, if `main` ever returns to that version. The reasoning as written did not distinguish the
  options; it was an argument the chosen design also loses. The honest reasons to reject the file are
  narrower and still sufficient: it is a second place to keep in sync with a set of issues that
  already exists, it separates the suppression from the reasoning that justified it, and it makes
  suppressing a one-line diff rather than two deliberate acts.
* *Treat "a closed issue exists" as suppression.* Rejected. Closing a tab would then silently disarm
  the check, and "closed without fixing" is the exact culture this workstream fights.
* **A label on the closed issue.** Taken, on the reasons above rather than on a staleness asymmetry
  it does not have. It is scoped to one version, so it cannot over-suppress; it takes two deliberate
  acts (label *and* close); and the label does not need to pre-exist — the script only ever **reads**
  label names out of the listing and never filters by label server-side, so an absent label simply
  never matches.

**Because the staleness is symmetric, suppression must not be silent.** A suppressed run prints a
`::warning::` (not a bare `print`) naming the issue number, the version and the label, so a
suppression that has outlived its reason is visible in every run summary rather than only in stdout
nobody opens. Cost: one warning line on a green run. That is the mitigation the curated-file
rejection was originally claiming for free.

**How the label can be defeated, and in which direction** — checked, and every path fails toward
noise rather than silence, which is the property worth having:

| act | effect | direction |
|---|---|---|
| the suppressing issue is **reopened** (label kept) | state is `open`, so the "open → already reported" row wins; exit 1, red every run, no new issue | noise |
| the suppressing issue is **retitled** | exact-title match no longer finds it; a **new** issue is filed | noise |
| the **label is renamed** in repo settings (GitHub rewrites it on every issue) | nothing matches the constant; every suppression lifts at once | noise |
| a new issue is created with the exact title, closed, and labelled | suppression — but that is three deliberate acts and is the intended mechanism | n/a |

Only the last is a silence, and it is the feature. Worth stating because "reopened" is the one a
maintainer will actually hit: reopening to *discuss* a suppressed version re-arms the alarm.

**`--report` is off by default.** A local or manual invocation is read-only; the workflow passes
`--report`. Same instinct as `yank.yml:21-24`'s `dry_run: true` default: a tool with side effects
should need to be asked.

The workflow gains `permissions: { contents: read, issues: write, actions: read }` **at the job
level**, because job permissions *replace* top-level rather than extend them (`publish.yml:772-774`,
`scripts/test_release_notice_gate.py:222-229`), and `GH_TOKEN: ${{ github.token }}` plus
`REPO: ${{ github.repository }}`. ➕ **`actions: read` is included here, one phase early**, because
Phase 7's staleness arm reads `repos/…/actions/workflows/…/runs` and an undeclared scope in an
explicit `permissions:` block is `none`, not "inherit" — that query would 403. Granting it here
rather than in Phase 7 means Phase 7 adds no permission at all, which keeps the scope review in one
place. `publish.yml:30-34` declares the same scope for the same reason.

**Rollback.** This is the first phase that can write anything, so it is the first that needs a stated
way out. If the check misbehaves after merge, the revert is **comment out the two `schedule:` lines**
in `.github/workflows/registry-drift.yml` — a one-line-class diff that stops all scheduled writes
while leaving `workflow_dispatch` for debugging, and which Phase 7's structural guards will
deliberately turn red so it can never be done quietly or forgotten. Deleting `--report` from the
`run:` line is the narrower version: the check keeps reporting to the log and stops touching issues.
Neither needs a revert of the code.

*What I rejected:* commenting on every scheduled detection. At 4 runs/day an unresolved drift would
accrue ~28 comments a week, and volume is how a reporter gets muted. Re-detection of the same drift
is not new information; the open issue already says it.

**Edge cases & failure modes.**
* `gh` failing → `InfraError`, exit 2, **and the verdict is still printed to stdout first**, so a
  GitHub outage never erases the answer.
* `--limit 500` is a finite window (the repo is at issue ~#101). If the listing returns exactly the
  limit, emit a `::warning::` that the window may be truncated — pinning the denominator at runtime.
* Two runs racing (a scheduled run and a dispatch) could both create. Bounded by the 6-hour period
  and a ~1-minute job; a duplicate is cosmetic, and adding `concurrency:` to prevent it would
  contradict Phase 5's reasoning. Recorded, not fixed.
* `gh issue list` piped into a reader that exits early can SIGPIPE under `pipefail` — write to a file
  first, exactly as `publish.yml:818-823` explains.
* An issue whose title merely *contains* the drift title must not suppress
  (`scripts/test_release_notice_gate.py:185-200`'s case, re-pointed here).
* Exit 2 must **never** file an issue: assert the `gh` call log is empty on every infrastructure path.

**Acceptance criteria.** With `gh` stubbed as an executable that logs every argv and returns a
pre-rendered TSV (`scripts/test_release_notice_gate.py:62-83,104-109`):

1. Drift, no existing issue → exactly one `issue create`; its title equals the expected string
   exactly; body names the version, both package names, the missing format(s), the tag state, and
   the age.
2. Drift, open issue with that exact title → **no** `issue create`, **no** `issue comment`. Exit 1.
3. Drift, closed issue, no label → `issue reopen` **and** `issue comment`, no `issue create`. Exit 1.
4. Drift, closed issue labelled `deliberately-unpublished` → **zero** `gh` write calls; exit **0**;
   output carries a `::warning::` naming the issue number, the version and the label. Asserted as a
   `::warning::` specifically, not merely as text: a suppression that prints nothing the run summary
   surfaces is the silent staleness this design does not otherwise avoid.
4b. ➕ **Reopening does not suppress.** Same listing with `state = OPEN` and the label still attached
   → exit **1**, zero write calls (the "open → already reported" row). Asserted because reopening to
   discuss is the realistic way a maintainer re-arms this without meaning to, and because it pins
   that the label alone is never sufficient.
4c. ➕ **The warn band files nothing.** Drift with the clock in `[SOFT, HARD)` and `--report` given →
   exit 0, a `::warning::`, and an **empty** `gh` call log. This is the criterion that keeps
   Phase 3's middle tier from quietly becoming a reporting tier.
5. No drift, open drift issue present → zero write calls, exit 0, a `::notice::` suggesting closure.
6. An unrelated open issue whose title *contains* the drift title does not suppress.
7. Without `--report`: drift is reported to stdout, exit 1, and the `gh` call log is **empty**.
8. Every infrastructure path (canary empty, `curl` 401, missing token, tag floor) → exit 2 with an
   **empty** `gh` call log.
9. Cross-link: an open `Release v0.7.78 did not publish` issue in the listing appears as a link in
   the created body.
10. **Non-collision, pinned.** A test extracts the literal `TITLE="Release ${TAG} did not publish"`
    template from `publish.yml`'s `release-outcome` `run:` text, asserts the extraction is non-empty
    and contains `did not publish` (named sentinel — otherwise the test compares against `""` and
    passes for free), renders both templates for a list of ≥ 5 versions including `0.7.77`, and
    asserts pairwise inequality **and** that neither is a prefix or substring of the other. A second
    assertion pins that both mechanisms match by exact equality: `publish.yml` via
    `awk -F'\t' … '$2 == t'` (`:824`), this script via its own exact comparison.
11. `python/.venv/bin/python -m pytest scripts/test_release_notice_gate.py -q` still passes — the
    sibling reporter is untouched.
12. ➕ **The job's `permissions:` block is exactly `{contents: read, issues: write, actions: read}`,**
    asserted as a set, with a message saying which phase needs each and that an explicit block grants
    only what it lists. Dropping `actions` must go red here, not in a scheduled run six hours later.
13. **Mutation round:** change the drift title to `Release v<version> did not publish` → (10) red;
    remove the label check → (4) red; treat a labelled-but-open issue as suppressed → (4b) red; let
    the warn band call `gh` → (4c) red; make the `awk` match a substring instead of `==` → (6) red;
    make an `InfraError` path reach the reporting code → (8) red; drop `actions: read` → (12) red.

**Tests.** Extend `scripts/test_registry_drift_gate.py`.

**Docs.** The created issue body itself is documentation: it must state, in the body, that the issue
does **not** auto-close, that a scheduled re-detection will not comment while it is open, and that
closing it with the `deliberately-unpublished` label is the way to record an intentionally
unpublished version.

---

## Phase 7 — the watcher's own heartbeat

**Status: TODO**

**Delivers.** Guards that the check keeps its schedule and its shape, plus a runtime warning when the
schedule has evidently been skipping.

**Depends on.** Phase 6.

**Files.** `scripts/check_registry_drift.py` · `scripts/test_registry_drift_gate.py`.

**Approach, and why it is right.** A scheduled check is a thing that can stop existing without anyone
noticing — which is the same class of failure as the one it was built to catch, one level up. Three
layers, honestly ranked:

1. **PR-time structural guards** (strongest, and the only complete one for the cases it covers). The
   workflow must keep a `schedule` trigger; the cron must equal a constant declared in the test with
   its reasoning; `workflow_dispatch` must remain; `continue-on-error` must remain absent; the
   `checkout` inputs must remain. These make *deletion or detuning in a PR* impossible to land
   quietly. They do not see a schedule that stops firing for GitHub's own reasons.
2. **Runtime staleness warning** (partial). ⚠ **Requires `actions: read` on the job**, which Phase 6
   grants; without it the query 403s, because an explicit `permissions:` block grants only what it
   lists. On each run, ask
   `gh api "repos/$REPO/actions/workflows/registry-drift.yml/runs?event=schedule&status=success&per_page=5"`
   for `created_at` timestamps, and `::warning::` if the gap between the two most recent successful
   scheduled runs exceeds **3×** the cron period (3 × 2 h = 6 h). GitHub does drop scheduled runs under load; this
   catches the *resumed-after-a-gap* case, which is the observable one. **This arm can never change
   the exit code.** A failure of this query is a `::warning::` and nothing more — it is diagnostics
   about the watcher, not evidence about the subject, and letting it vote would be exactly the
   category error `probe_framework_coinstall.py:168-170` names. The workflow filename used in the
   query is a module constant, asserted equal to the real filename.
3. **The residual, stated plainly:** *permanent* cron silence is undetectable from inside the thing
   that went silent. The only real fix is an out-of-repo watcher, and writing into `zer07labs/seam`
   is out of scope for this plan by constraint. Recorded in Long-term posture as priced debt, with
   the mitigation that `workflow_dispatch` gives any human an on-demand answer in about a minute.

*What I rejected:* having the check write a heartbeat row somewhere (a file committed to `main`, an
issue comment) so its absence is visible. It makes a read-only watcher into a writer on every run,
adds commit noise to `main`, and still needs *something else* to notice the heartbeat stopped —
moving the problem rather than solving it.

**Edge cases & failure modes.**
* On the very first run there is no previous scheduled run → no warning, not a failure.
* `workflow_dispatch` runs have `event=workflow_dispatch` and are excluded from the gap computation,
  or a burst of manual runs would mask a dead schedule.
* Renaming the workflow file breaks the query → the constant-equals-filename test fails at PR time.

**Acceptance criteria.**
1. Removing `schedule:` from the workflow makes a named test fail with a message saying the check
   would silently stop running.
2. Changing the cron makes a named test fail and name both values, so a deliberate change is a
   one-line, reviewed edit. The pinned constant is `"17 */2 * * *"`, and the same test asserts the
   staleness threshold is derived from it (3× the period) rather than hardcoded in minutes — the two
   drifted apart is how a "6 h" threshold survives a move to a 12-hour cron.
2b. ➕ **Commenting out `schedule:` makes (1) fail**, which is the Phase 6 rollback path: the plan's
   own escape hatch must be one the guards notice, so it is never done quietly or left in place.
3. Adding `pull_request:` to the workflow makes a named test fail with the fork-secret reasoning in
   the message.
4. With `gh` stubbed to return two `created_at` values 40 hours apart, the run prints a `::warning::`
   naming the gap **and** the exit code is unchanged from the no-warning run (asserted by running the
   same scenario twice, with and without the gap, and comparing return codes).
5. With `gh api` stubbed to fail, the exit code is unchanged and a `::warning::` is printed.
6. The workflow-filename constant equals the actual filename on disk.
7. **Mutation round:** make the staleness arm raise `InfraError` → (4)/(5) red.

**Tests.** Extend `scripts/test_registry_drift_gate.py`.

**Docs.** A short *"how this check can itself fail"* section in the workflow header comment, naming
all three layers and the residual.

---

## Phase 8 — the Go module tag — **DROPPED FROM THIS PLAN. File as a separate issue.**

**Status: NOT IN SCOPE** *(round-2 review; kept here as the record of why, not as work)*

**The finding is real and was verified independently.** `release-on-runtime.yml:187` is
`git push origin "v$VER" "go/v$VER"` — two refspecs, **no `--atomic`** — so `v$VER` can land while
`go/v$VER` does not. The consequence is total for one language: the Go module path is
`github.com/zer07labs/seam-sdk/go`, Go resolves a nested module's versions **only** from `go/vX.Y.Z`
tags (`release-on-runtime.yml:183-185` says so), and `go get …@vX.Y.Z` would fail forever while every
other gate stayed green.

**It does not belong in this PR, for three reasons that compound.**

1. **It is not what #100's second half is.** This plan's subject is *registry vs source* — does
   Cloudsmith serve what `main` declares. A `v` tag without a `go/v` twin is *tag vs tag*: no
   registry is involved, the packages published perfectly, and the comparison shares no input with
   the rest of the check beyond `git tag -l`. It was in the phase list because it was found while
   reading `release-on-runtime.yml`, which is how scope arrives, not a reason to keep it.
2. **The plan builds a detector for a defect whose fix is one word.** Adding `--atomic` to
   `release-on-runtime.yml:187` makes the partial push impossible — GitHub supports atomic pushes,
   and the two refs are created from the same commit moments apart. The plan proposed instead:
   `GO_TAG_FLOOR`, dotted-tuple version ordering (which Phase 3 removed on purpose and this
   re-introduces), a second denominator guard, a distinct issue-body section, and six acceptance
   criteria — perhaps a hundred lines — to *notice* a failure that a one-word prevention removes.
   That is the wrong end of the problem, and worse, it would leave the one-word fix unwritten.
3. **It has never happened.** Measured at `f177cfb`: `git tag -l 'v*'` = **67**, `git tag -l 'go/v*'`
   = **45**; the `v` tags with no `go` twin are `0.7.4-0.7.7`, `0.7.9-0.7.21` and `0.7.26` — all
   *before* `go/` tagging began at `0.7.27` — and there is **no `go/v` tag without a `v` twin at
   all**. Every release from `0.7.27` on has both. So the phase's own evidence is that the failure it
   detects has occurred zero times, while consuming the plan's largest phase after the core.

**Recommendation, concretely.** File one issue against `zer07labs/seam-sdk`: *"`release-on-runtime.yml`
pushes `v` and `go/v` non-atomically"*, citing `release-on-runtime.yml:187`, proposing `--atomic` as
the fix and a `scripts/test_release_gate.py` assertion that the flag is present as the guard. That is
a small, self-contained PR with a real prevention in it. Detection can be argued there on its own
merits, against a prevention that already landed — which is the right order.

**If a reviewer disagrees and wants it here**, the phase text as drafted is recoverable from this
plan's history; but it must then also carry the `--atomic` fix, or it ships monitoring for a bug it
declined to fix.

**Numbering.** Phase 9 keeps its number. Renumbering would break every reference to "Phase 9" in
`PROGRESS.md`, `DECISIONS.md` and the phases above, to save one digit.

---

## Phase 9 — documentation closure

**Status: TODO**

**Delivers.** The repo tells the truth about the new mechanism, and `publish.yml`'s blind-spot
comment records that the gap is closed.

**Depends on.** Phases 1 and 6. (Phase 8 is dropped, so it is no longer conditional on anything.)

**Files.** `.github/workflows/publish.yml` (the same five comment lines) · `README.md` ·
`CLAUDE.md` (this repo's) · `plans/README.md` · `DECISIONS.md` · `ASSUMPTIONS.md` · `PROGRESS.md`.

**Approach, and why it is right.**
* `publish.yml:761-765`: update to say the gap **is** now covered, by
  `.github/workflows/registry-drift.yml`, and keep the structural explanation of *why* it could not
  be covered here. **Line-count-neutral again**, for Phase 1's reasons.
* `README.md`: in the *Internal distribution* section (around `:163-181`), a short paragraph — what
  the check compares, on what schedule, that exit 2 is infrastructure, and how to record a
  deliberately unpublished version.
* `CLAUDE.md` (seam-sdk): one Commands bullet — `python3 scripts/check_registry_drift.py` is
  read-only by default and needs `SEAM_REGISTRY_TOKEN`. Two lines at most; that file is loaded into
  every session.
* `plans/README.md`: an *Active / pending* row for this plan, following the existing row style.
* `DECISIONS.md`: the calls a later reader would otherwise re-litigate — the **two-tier** window
  (why `SOFT` is sized on the declared ceilings, why `HARD` is sized on the job limit, and that the
  job limit bounds *duplication* rather than *detection* because `release-outcome` already covers
  the hung-job case), the `max(commit, tag)` clock, no auto-close, the label suppression over a
  curated file **on the corrected grounds** (its staleness is symmetric; the reasons are locality
  and two-act deliberateness), the canary-as-a-set-excluding-the-target invariant, and no
  `pull_request` trigger.
* `ASSUMPTIONS.md`: **two** **UNCONFIRMED** entries — (i) *the Cloudsmith `?query=seam-sdk+version:X`
  shape returns matching rows*, and (ii) *Cloudsmith **errors on**, rather than silently ignoring, an
  unrecognised `version:` qualifier*. (ii) is the one that could produce a false exit 1 rather than a
  false exit 2, which is why Phase 4's truncation check exists; both are settled by the same first
  scheduled run. Inherited from `yank.yml:69-71` and never executed by any test
  (`scripts/test_yank_gate.py:36-48` truncates before it). The canary converts a wrong assumption
  into a loud exit 2 rather than a silent false verdict, and the first scheduled run after merge is
  the natural confirming observation — to be read out of the run log, not staged as an action.
* `PROGRESS.md`: the per-phase record `/implement` writes as it goes.

**Edge cases & failure modes.**
* Every backticked `file:line` added to `PROGRESS.md`, `DECISIONS.md` or `COMPATIBILITY.md` is
  checked (`python/tests/test_compatibility_citations_resolve.py`). No line-anchored citation may
  point into `gen/`, `ts/gen/`, `python/seam_sdk/_gen/` (`GENERATED`, `:241`) or
  `verify/docs/seam-event.v1.md` (`VENDORED`, `:186`). Sibling-repo paths need their repo prefix.
* The `publish.yml` comment edit shifts nothing if line-neutral; if it is not, re-run the citation
  test and repair in the same commit.

**Acceptance criteria.**
1. `python/.venv/bin/pytest python/tests/test_compatibility_citations_resolve.py -q` passes.
2. `git diff --stat` on `publish.yml` shows equal insertions and deletions within `761-765`.
3. `README.md` names the workflow file and the `deliberately-unpublished` label.
4. `plans/README.md` carries a row for this plan.
5. Full baseline re-measured and recorded in `PROGRESS.md`: `python` suite (with the
   citation-suite delta shown to account for the whole change), `scripts` suite,
   `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` still **exit 6** naming exactly the seven
   `ContextBinding` lag fields.

**Tests.** No new tests; the citation guard is the test.

**Docs.** This phase is the docs.

---

## Long-term posture

**Priced debt.**

* **The Cloudsmith query shape is inherited, not proven** (`yank.yml:69-71`; never executed by a
  test, by `scripts/test_yank_gate.py:36-48`'s own admission). The canary makes a wrong shape loud
  instead of silent, which is the affordable half. The unaffordable half — proving the shape — needs
  a live call, which no hermetic test may make. **Cost if wrong:** exit 2 on every run until someone
  fixes the query; zero false drift reports. **Trigger to revisit:** the first scheduled run's log.
* **"Listed" is weaker than "installable."** This check reads the package list API;
  `registry-smoke` (`publish.yml:587-745`) actually installs from `dl.cloudsmith.io` and runs the
  conformance vectors, and `publish.yml:790-794` is explicit that those are different claims. A
  version that is listed but not resolvable would pass this check. That case is covered on the
  publish path and is not the failure #100 is about. **Cost:** a narrow blind spot, already covered
  elsewhere. **Trigger:** an incident where a listed version was not installable outside a publish
  run.
* **Permanent cron silence is undetectable from inside the check.** Phase 7 covers deletion,
  detuning and skipping; it cannot cover "GitHub stopped running it and nothing asked". The real fix
  is an out-of-repo watcher, which this plan may not write. **Cost:** the watcher could die
  unnoticed, restoring the pre-#100 state without anyone knowing it had. **Trigger:** if
  `zer07labs/seam` ever grows a cross-repo scheduled health lane, this belongs in it.
* **`publish.yml`'s publishing jobs declare no `timeout-minutes`** (only `release-outcome` does, at
  `:771`). That is what forces `HARD_GRACE_MINUTES = 360` rather than something near the declared
  ceilings. ⚠ Note the corrected framing: 360 is not needed to avoid *missing* a hung publish —
  `release-outcome` reports that case itself (`if: always()`, `publish.yml:768`) — it is needed only
  to avoid *duplicating* it. Adding `timeout-minutes` to those jobs would let `HARD` drop to roughly
  `SOFT`, collapsing worst-case time-to-issue from ~8 h to ~3.5 h. It is a change to the publish
  path, out of scope here. **Trigger:** any future work in `publish.yml`.
* **A curated suppression list was rejected, and its absence is a small ongoing cost**: recording a
  deliberately unpublished version takes a label plus a close, in the UI, by a human. Cheaper than a
  file that rots, and the file's rot is silent while a forgotten label is merely a re-alarm.

**One-way doors, flagged.**

* **The issue title format.** Once it has filed issues, changing the string orphans every existing
  one — the matcher is exact equality, so old issues stop being found and duplicates appear. Treat
  the title as a wire format. `release-outcome` has the same property and the same constraint.
* **The `deliberately-unpublished` label name.** Same argument, smaller blast radius: renaming it
  silently un-suppresses every version it was suppressing. Pin it as a module constant, name it in
  the issue body, and never rename without sweeping the closed issues.
* Not one-way, and worth saying so: both grace tiers, the cron and `CANARY_VERSIONS` are constants
  with tests that fail on change, so each is a reviewed one-line edit.
* ➕ **`CANARY_VERSIONS` is closer to one-way than it looks.** Not the values — the *invariant* that
  no entry may equal the target. Lose it and the check goes structurally mute on whichever version
  it names, silently. That is why it is enforced at runtime rather than by comment, and why Phase 4
  acceptance (4) tests the collision case rather than the roster's contents.

---

## Enterprise concerns

**What we can observe when this breaks in production.** The check has exactly three observable
outcomes and they are kept disjoint on purpose: **0** (the registry serves `main`'s version, or the
version is younger than the window and the run says so), **1** (drift — a red job *and* an issue),
**2** (infrastructure — a red job and **no** issue). The 1/2 split is the whole reliability story: a
Cloudsmith outage, an expired token, a changed API shape or a tag-less checkout can each make the
check unable to answer, and none of them can make it answer *wrong*. That property is enforced in
three places — `InfraError` raised before any verdict is computed, the canary query ordered ahead of
the target query, and the assertion that every exit-2 path leaves the `gh` call log empty.

**Blast radius of the check itself.** It has `contents: read` and `issues: write`, no registry write
scope, no publish path, no ability to tag or dispatch. The worst it can do when wrong is file a
spurious issue. It is not on any decision path, not required by `ci-ok`, and no other job depends on
it — the same "reporter, never a gate" invariant `scripts/test_release_notice_gate.py:232-240` pins
for `release-outcome`.

**The watcher can stop watching.** Addressed at three levels in Phase 7, with the residual stated
rather than hidden: PR-time guards make deletion and detuning impossible to land quietly; the runtime
staleness warning catches a schedule that resumed after skipping; and permanent silence is
undetectable from inside, with `workflow_dispatch` as the human-triggered fallback and an out-of-repo
watcher named as the only real fix. That residual is written into the workflow header, so the next
person to read the file learns it there rather than by discovering it.

**Interaction with the existing reporter.** Two mechanisms can now file issues about the same
release. They cannot collide — different exact-equality titles over disjoint prefixes, pinned by
test — and they cover complementary halves: `release-outcome` sees *a publish that ran and failed*
(fast, once, with the job matrix); this check sees *a publish that never ran, or ran and left the
registry behind* (slow, repeatedly, from the outside). When both fire, the drift issue links to the
release-failure issue, so an operator lands on one thread with both facts.

**Cost.** Four runs a day, one checkout plus two GETs plus one `gh issue list`, ~1 minute each, with
a declared `timeout-minutes: 10`. Negligible against Actions minutes, and bounded — unlike
`publish.yml`'s untimed jobs.

**Security.** The token is resolved with `yank.yml:55-63`'s explicit form (never the `&&` one-liner
whose hazards `yank.yml:38-54` documents), `::add-mask::`-ed immediately, passed to the script only
through the environment, and never printed — asserted by a test that greps every failure path's
output for the stub token. Secrets are unavailable to fork PRs, which is precisely why there is no
`pull_request` trigger.

---

## Open questions

**Decided from the code; recorded here so they are not re-opened by accident.**

1. **Which comparison?** In-tree version on `main` vs the registry — *one* comparison, covering
   states B and C, silent on A. Settled by `release-on-runtime.yml:179-187`'s ordering: the bump
   reaches `main` before any tag exists, so `main` is the earlier and strictly more complete signal.
   The tag is read for diagnosis only. **Knowingly not covered:** a superseded intermediate version
   (correct — `release-outcome` already filed for it, and eleven such gaps exist today and are fine).
2. **Grace window = 360 minutes**, keyed on the age of the version-bump commit on `main` (not on tag
   age, which does not exist in state C). Calibrated against `publish.yml:82-83` and `:625,721`
   (≈ 40 min declared) and against GitHub's default 360-minute job limit, which is the only real
   bound because those jobs declare no `timeout-minutes` (`publish.yml:771` is the sole one).
3. **Cron = `17 */2 * * *`** (⚠ changed from `*/6` in round 2). Worst-case ≈ **3.5 h** to a visible
   warning and **8 h** to a filed issue, against ≈ 12 h with no warning at `*/6`, against a
   historical five days (`publish.yml:748-751`). Off-the-hour to dodge scheduled-run congestion.
   Cost: 12 runs/day of a ~1-minute job.
4. **Trigger set = `schedule` + `workflow_dispatch`, no `pull_request`.** Secrets are unavailable to
   fork PRs, so a PR trigger would fail for a reason unrelated to the PR — the exact objection
   `framework-coinstall.yml:5-8` raises. PR-time coverage is the hermetic gate suite instead, the
   arrangement `yank.yml` already uses.
5. **Not in `ci-ok`'s `needs:`, and the standing rule does not apply.** It is a separate workflow, and
   `needs:` orders jobs within a run only (`publish.yml:42-44`). The substantive reason is
   `framework-coinstall.yml:5-8`'s, inherited: the answer changes when Cloudsmith changes, not when
   the diff changes. **If a reviewer disagrees, that is a real fork and must be raised, not edited
   in.** The check's *tests* are in `ci-ok`, via `workflow-guards`.
6. **Exit codes 0/1/2, no skip path**, copying `scripts/probe_framework_coinstall.py:36,47-57,171-194`
   including *"anything unrecognised → infra"*. Divergence from `yank.yml:61-63`, which exits 1 on a
   missing credential: here 1 is a verdict, so a missing credential must be 2.
7. **Suppression = a `deliberately-unpublished` label on the closed drift issue**, not a curated
   file. Rejected alternatives and their failure modes are written out in Phase 6.
8. **No auto-close.** The reporter is write-additive only, like `release-outcome`. When drift clears
   it prints a `::notice::` suggesting closure and does nothing else.
9. **Both ecosystems, one query**, reusing `yank.yml:73-76`'s three filters verbatim. Half-publish
   (`plans/post-adoption-hardening-and-acdp-readiness.md:316,560`) is named per format in the report.
10. ⚠ **The Go module tag is OUT of scope** (Phase 8, reversed in round 2). The non-atomic push at
    `release-on-runtime.yml:187` is real and verified, but it is tag-vs-tag rather than
    registry-vs-source, its fix is `--atomic` rather than a detector, and it has occurred zero times
    in 45 paired releases. File it separately; do not carry it in this PR.
11. ➕ **Grace is two-tier and the clock is `max(commit, tag)`.** A single cliff calibrated on the
    360-minute job limit was calibrated against a case `release-outcome` already covers, and a
    commit-only clock gives zero grace to the `release-on-runtime.yml:176-181` re-dispatch path.
12. ➕ **The canary is a set that excludes the target.** A single pin equal to `main`'s version turns
    that version's drift into exit 2 — the failure mode the canary exists to prevent, pointed at the
    live release.
13. ➕ **Every unhandled exception exits 2.** Python's own uncaught-exception code is 1, which is this
    check's drift verdict; the precedent (`scripts/probe_framework_coinstall.py`) inherits that hole
    and this must not.

**Genuinely open — not decidable from this repo, and deliberately *not* escalated because nothing
downstream blocks on it.** Whether `zer07labs/seam` should host a cross-repo watcher that notices
*this* check going silent. It is out of scope by constraint, it is recorded in Long-term posture, and
the honest position is that the residual is small enough to carry until a second repo needs the same
thing.

**Nothing in this plan requires a decision from the user before implementation begins.**

---

## Plan review

### Round 2 — adversarial re-verification (independent reviewer, not the author) — **REVISE, applied**

Every file the plan cites was re-opened at `f177cfb`; the baseline was re-run. **Ten of the plan's
factual claims held**, including the ones the round was pointed at hardest: only `release-outcome`
declares `timeout-minutes` (`publish.yml:771` — verified by reading all seven job headers);
`release-on-runtime.yml:180` does precede `:182`/`:186`/`:187` under Actions' default `bash -e`, so
the single `main`-keyed comparison really does cover states B and C; `:187` really does push two
refspecs without `--atomic`; `yank.yml:55-76`, `framework-coinstall.yml:5-8,62-64`,
`scripts/test_yank_gate.py:36-48,51-62,65-80,93-113,132-140,162-181,222`,
`scripts/test_release_notice_gate.py:62-83,104-109,185-200,222-229,232-240`,
`scripts/test_ci_gate.py:180-184,191-201,277-301,285-287,388-402`,
`scripts/probe_framework_coinstall.py:36,47-57,80-82,153-154,168-194` and
`python/tests/test_compatibility_citations_resolve.py:95-99,802,1473-1500` all say what the plan says
they say.

**What changed, in descending order of severity.**

1. **The canary was pointed at the target.** `CANARY_VERSION = "0.7.77"` is `python/pyproject.toml:3`'s
   current value. Canary-first ordering then means a genuine drift on the live version returns an
   empty canary and exits **2** — the check reports a broken instrument for exactly the condition it
   exists to report as drift, on whichever version is current. Replaced with `CANARY_VERSIONS`, a
   three-entry set that drops any entry equal to the target at runtime and passes if *any* candidate
   answers, plus a selection rule (`publish.yml:748-749` records `v0.7.69/70/72` as tagged-but-refused,
   so a tag is not evidence of publication) and a one-time live confirmation before merge.
2. **Exit 1 is also Python's uncaught-exception code**, and 1 is the drift verdict — so any crash,
   including the `ImportError` that a non-stdlib import would cause on the pip-install-free scheduled
   job, reads as drift. Added a top-level handler mapping everything to 2, a stdlib-only obligation on
   the script, and tests for both.
3. **The 360-minute window was calibrated against a case `release-outcome` already covers.** A job
   killed at GitHub's default limit fails the run, and the shipped reporter files for it
   (`publish.yml:768`). The limit bounds *duplication*, not *detection*. Replaced with two tiers —
   `SOFT = 90` (silent, sized on the ≈40 min declared ceilings) / warn band / `HARD = 360` (files) —
   and the cron moved `*/6` → `*/2`. Worst case goes from "no warning, 12 h to an issue" to "3.5 h to
   a warning, 8 h to an issue", with the issue-filing threshold unmoved, so nothing trades detection
   for false positives.
4. **The grace clock gave a re-dispatch zero grace.** `release-on-runtime.yml:176-181` has a branch
   that makes **no commit** ("already at $VER — tagging only") and tags anyway, so a retry's
   `version_landed_at` is the original bump's date. Clock is now `max(commit, tag creator date)`.
5. **Phase 8 dropped.** The non-atomic push is real, but it is tag-vs-tag rather than
   registry-vs-source, its fix is `--atomic` rather than ~100 lines of detector, and it has occurred
   zero times (67 `v*` / 45 `go/v*` tags at `f177cfb`; every `v` without a `go/v` predates `0.7.27`,
   and there is no `go/v` without a `v`). File it separately, with the fix.
6. **Phase 3's dependency on Phase 2 was invented** — every import it needs is already in `ci.yml:642`.
   And **Phase 2's justification was factually wrong**: `workflow-guards` runs one pytest per file
   (`ci.yml:644,649,654,660,665,671,677,682`), so a collection error reddens one step loudly, not
   "all eight suites, dark". Phase 2 kept at its honest size and marked droppable; Phase 3 now
   depends on nothing.
7. **Phase 7's staleness query would have 403'd** — it reads the Actions API under an explicit
   `permissions:` block that never listed `actions: read`. Granted in Phase 6 and asserted as a set.
8. **The curated-file rejection was an argument the chosen design also loses.** A stale label
   suppresses exactly as silently as a stale file entry. Re-argued on locality and two-act
   deliberateness, and suppression now emits a `::warning::` so it is never fully silent. Added the
   reopened / retitled / label-renamed table (all three fail toward noise).
9. **Two dropped guards restored**: the version is interpolated into a URL query where `+` means
   space, and `yank.yml:64-66`'s `case` refusal had no counterpart here; and a response of exactly
   `page_size` rows now means "the `version:` qualifier was ignored" → exit 2, the one shape a
   version-pinned canary cannot catch.
10. **Falsifiability**: Phase 5 acceptance #9 pinned "1186 passed", which the plan's own `PROGRESS.md`
    repo map had already made false (1229, now 1245 — every delta matched by the citation suite,
    434 → 477 → 493). Exact counts replaced with a before/after pair plus the requirement that the
    two deltas agree. A fifth false-positive source (a hand-bumped version with no dispatch behind
    it) and a rollback path for Phase 6 were both missing and are now stated.

Minor citation repairs: `publish.yml:44-46` → `:42-44`; `git tag -l 'v*'` is 67, not 63 (63 is
`v0.7.*`); `publish-verify` (`:526`) added to the no-`timeout-minutes` list; the `&&` token form
exists at four sites (`:227`, `:385`, `:607`, `:711`).

**Constraints re-verified as still met:** `seam-sdk` only; no `make generate` / `generate-local` /
`clean` / `--write-manifest`; no workflow dispatch, publish, tag re-point or live registry call from
any test; every new `scripts/test_*.py` wired into `workflow-guards` as a named step; no import
outside stdlib + `pyyaml pytest grpcio cryptography`; mutation rounds required in every phase that
ships logic, now including the canary-collision, tier-boundary, clock, crash-to-2 and truncation
mutants.

**Baseline after this round** — `cd python && .venv/bin/pytest -q` **1245 passed / 20 skipped** ·
`python/.venv/bin/python -m pytest scripts -q` **135 passed** ·
`STREAM=1 EVENTS=1 ./scripts/check-contract.sh` **exit 6** · citation guard **493 passed**, with
`UNBOUND_BARE_CEILING["PROGRESS.md"]` still satisfied at exactly **68** (it was tripped once while
editing the repo map, and bound rather than raised).
