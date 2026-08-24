# Close out the loose ends left by the W1–W7 workstream

> **📦 ARCHIVED 2026-08-24 — DELIVERED, all four phases.** Shipped as PR
> [#53](https://github.com/zer07labs/seam-sdk/pull/53) (squashed to `cb87f30`), CI green.
> Written 2026-08-24 against `main` @ `f68572f` (v0.7.43).
>
> **Verified against this tree, not against the status table** (per `plans/README.md`'s archiving
> rule): Phase 1 — `verify-msrv` at `.github/workflows/ci.yml:326`, required via `ci-ok`'s `needs`
> at `:436`, with the floor derived in `verify/tests/msrv.rs` from `verify/Cargo.toml:31`. Phase 2 —
> the retirements are in place and dated in `plans/consolidation-2026-08-14.md`. Phase 3 — the
> finding is in `COMPATIBILITY.md` §4a and `DECISIONS.md`, and is re-derived weekly by
> `scripts/probe_framework_coinstall.py` via `.github/workflows/framework-coinstall.yml`. Phase 4 —
> six plan files plus an index under `plans/cross-repo/`.
>
> **What "delivered" does not mean.** Phase 4's deliverable was giving the six `seam-runtime` asks a
> version-controlled home here; the runtime-side work itself is **not** delivered and is not this
> plan's to deliver — `seam-runtime`
> [#418](https://github.com/zer07labs/seam-runtime/issues/418)–[#423](https://github.com/zer07labs/seam-runtime/issues/423)
> remain open. Phase 2 retired only the backlog entries that were actually done; §B (the MCP server,
> [#40](https://github.com/zer07labs/seam-sdk/issues/40)) and §D (the public-access DoD) survive in
> [`build-agent-ingress.md`](../build-agent-ingress.md).
>
> Each phase's own `Status:` field below is authoritative — this banner summarises them,
> never substitutes for them.
> **Source:** the three limits stated honestly at the end of
> [`plans/archive/sdk-exec-w1-w7.md`](archive/sdk-exec-w1-w7.md) and in PR #51's report, re-verified against this
> tree on 2026-08-24.
> **seam-sdk only.** No cross-repo *writes* — Phase 4 files plans locally and comments on existing
> issues, which the workspace convention treats as unrestricted. Nothing here needs a credential.

## Context

PR #51 (merged `f68572f`) delivered W1–W7 and closed the release-exposure gaps. It also left three
things open, two of which it stated plainly rather than hid. This plan closes them.

**The current state, honestly.** The repo is in good shape: `ASSUMPTIONS.md` carries **zero**
`UNCONFIRMED` entries, `main`'s CI is green, and the guards added in #51 (the RPC manifest, the
citation checker, the retracted-claims guard, the framing-rationale guard) are all live and were
each driven red before being kept. What remains is one real gap in CI and a documentation-accuracy
problem that has quietly spread across three plan files.

**What the resources got wrong, corrected here.** The brief described item (2) as "at least 2 of 5
backlog items are already done." Verification found it is worse than that: **four of the five are
done or materially misstated**, and the staleness is not confined to
`plans/consolidation-2026-08-14.md` — it has propagated into `plans/build-agent-ingress.md` and
`plans/README.md`, which repeat the same now-false claims. Two of the sub-items landed in
`seam-adapters` PR #42 on **2026-08-17**; the backlog has simply not been swept since it was written
on 2026-08-14, so nothing in this repo noticed. Phase 2 is therefore an accuracy sweep across three
files, not a two-line deletion.

*(An earlier draft of this paragraph said those items landed "yesterday (2026-08-23)". Both halves
were wrong — `9a05a04` was authored and merged on 2026-08-17 — and the recency was doing work in the
argument, so the correction matters rather than being cosmetic.)*

**Added 2026-08-24 (owner):** Phase 4 — the six `seam-runtime` asks filed during W1–W7 have no
local plan files, which deviates from the convention every other repo in this workspace follows.
That gap was introduced by this workstream and is closed here.

**Out of scope, by owner decision (2026-08-24):** anything touching 0.7.43 / issue
[#52](https://github.com/zer07labs/seam-sdk/issues/52) — no documentation change, left entirely for
now. Also out: the MCP server ([#40](https://github.com/zer07labs/seam-sdk/issues/40)), and anything
requiring Cloudsmith/PyPI credentials or a sibling-repo write.

### What was verified before planning

Everything below was executed or read at `f68572f`, not inferred:

| Claim | How it was checked | Result |
|---|---|---|
| `verify/` builds at its declared MSRV | `cargo +1.85 build --locked` | **passes** |
| …and its full suite passes there | `cargo +1.85 test --locked` | **passes** — 7 test binaries + doctest |
| …and the floor is *exact*, not conservative | `cargo +1.83 build --locked` | **fails** — `zeroize-1.9.0` requires `edition2024` |
| Dev-deps do not inflate the floor | `cargo metadata`, direct deps by kind | normal max **1.85** (`prost`); dev max **1.71** (`serde_json`) |
| MSRV is derivable from one source | `grep -m1 '^rust-version' verify/Cargo.toml` | yields `1.85` |
| A new CI job cannot be forgotten in the gate | `scripts/test_ci_gate.py::test_gate_needs_every_other_job` | asserts `ci-ok.needs` covers every job |

That third row is the important one: it means an MSRV job **discriminates** rather than passing
vacuously, and that 1.85 is the right number rather than a safe over-estimate.

---

## Phases

### Phase 1 — Compile `verify/` at its declared MSRV, deriving the version from the manifest

**Status:** DONE (2026-08-24, 1 round, Sonnet — CI config). Diverged from plan in one way: the
extraction is an **`awk` pass scoped to the `[package]` table**, not the line-anchored `grep` the
plan sketched. The verifier flagged that `verify/Cargo.toml` opens with an empty `[workspace]`, so a
future `[workspace.package]` carrying its own `rust-version` would sit *before* `[package]` and
`grep -m1` would silently read the wrong one — installing an undeclared toolchain while still
looking green. Proven fixed with a decoy `[workspace.package] rust-version = "1.60"`, which the
scoped extraction correctly ignores.

**Delivers.** A CI job that actually builds and tests `verify/` at Rust 1.85, so the published MSRV
is a checked promise rather than an asserted one — and it takes the version from
`verify/Cargo.toml` rather than a second hard-coded copy.

**Depends on.** Nothing.

**Files.** `.github/workflows/ci.yml`.

**Approach.**

`verify/Cargo.toml:26` declares `rust-version = "1.85"`, and `verify/tests/msrv.rs` asserts that
declaration covers every **declared** `rust-version` in the resolved graph. That closes one half of
the problem. The other half is open: **a dependency that requires more than it declares slips
through**, because `.github/workflows/ci.yml:278` builds `verify/` only on
`dtolnay/rust-toolchain@stable`. Nothing has ever compiled this crate at 1.85.

Add a separate `verify-msrv` job that:

1. **Derives the toolchain from the manifest**, rather than hard-coding `1.85` in the workflow:

   ```yaml
   - id: msrv
     run: echo "version=$(grep -m1 '^rust-version' verify/Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')" >> "$GITHUB_OUTPUT"
   - uses: dtolnay/rust-toolchain@master
     with:
       toolchain: ${{ steps.msrv.outputs.version }}
   ```

   This is the *right* approach here and not merely a working one, because it matches the
   convention this repo already enforces everywhere else: the protobuf floor, the grpcio floor and
   the MSRV itself are all **derived, not chosen**, each with a test that fails when the derivation
   outruns the declaration. Hard-coding `1.85` in `ci.yml` would create a second source of truth
   that can silently drift from `Cargo.toml` — the exact defect class this repo keeps closing.

   *Rejected:* `dtolnay/rust-toolchain@1.85`. It reads more simply and is what most repos do, but a
   version in `uses:` cannot be interpolated, so the number would have to be duplicated. A future
   MSRV bump would then need two edits, and forgetting the second leaves CI testing the wrong
   floor while every test still passes.

2. **Runs `cargo build --locked` and `cargo test --locked`** — not clippy, not fmt.

   `--locked` matters: without it cargo may resolve different dependency versions than the
   committed lockfile, and the job would be testing a graph nobody ships.

   Testing (not just building) is safe here and was checked rather than assumed: direct dev-deps
   max out at **1.71** (`serde_json`) against a normal-dep floor of **1.85** (`prost`), so the test
   profile does not inflate the consumer-facing promise. If that ever inverts, the honest fix is to
   split build-at-MSRV from test-at-MSRV — noted in Long-term posture, not pre-solved.

   *Rejected:* running clippy/fmt at MSRV. Lint sets and formatting differ between toolchain
   versions, so pinning them to the floor produces churn that has nothing to do with the MSRV
   promise. Those stay on `stable` in the existing `verify` job.

3. **Is added to `ci-ok`'s `needs:` list.** `ci-ok` is the single check branch protection requires,
   so a job absent from that list runs, goes red, and lets the PR merge anyway. This is not a
   judgement call to remember: `scripts/test_ci_gate.py::test_gate_needs_every_other_job` fails if
   the job is added to `ci.yml` and not to the gate — the guard already forces it.

*Rejected:* extending the existing `verify` job with a toolchain matrix. It would re-run the
`cargo tree` independence gate, fmt, clippy and the fixture check at both toolchains for no benefit,
and the two toolchains need genuinely different step lists. A separate job is clearer to read and
cheaper to run.

**Edge cases & failure modes.**
- **The job goes red when a dependency raises its MSRV.** That is the intended behaviour, not a
  bug — it forces `rust-version` to be raised deliberately, in a reviewed change, rather than
  discovered by a consumer. The failure message should say so, otherwise the next person "fixes" it
  by pinning the toolchain lower.
- **`grep`/`sed` extraction is brittle if `rust-version` moves or gains a comment on the same
  line.** Anchoring with `-m1 '^rust-version'` handles the realistic cases; if the extraction yields
  empty the step must **fail**, not silently install `stable` and produce a green job that checks
  nothing. This is the vacuous-gate failure mode this repo has hit twice, so guard it explicitly.
- **Older toolchains and newer lockfile formats.** Rust 1.85 reads lockfile v4; if the lockfile is
  ever regenerated to a newer version by a newer cargo, the MSRV job breaks first. That is a useful
  early warning, and worth a comment so it is recognised rather than worked around.
- **Network/toolchain-install flake** is the same exposure every other job has; no special handling.

**Acceptance criteria.**
1. `.github/workflows/ci.yml` contains a `verify-msrv` job that installs the toolchain **read from
   `verify/Cargo.toml`**, with no literal `1.85` anywhere in the workflow.
2. That job runs `cargo build --locked` **and** `cargo test --locked` in `verify/`.
3. `verify-msrv` appears in `ci-ok`'s `needs:` list, and
   `python -m pytest scripts/test_ci_gate.py -q` passes.
4. The extraction step **fails loudly** when `rust-version` cannot be parsed — demonstrated by
   running the extraction against a manifest with the key removed and showing a non-zero exit.
5. The job is green on this PR (proven by CI), and the local equivalent
   (`cargo +1.85 test --locked`) passes.
6. A comment in the job states what a red result means: raise `rust-version` deliberately; do not
   lower the toolchain.

**Tests.**
- `scripts/test_ci_gate.py` (existing) — proves the job is inside the required-check gate.
- `verify/tests/msrv.rs` (existing) — unchanged; it covers the *declared* half. The new job covers
  the *compiled* half. The plan should note in the job comment that the two are complementary and
  neither alone is sufficient.
- **Red-first evidence, recorded in the PR:** `cargo +1.83 build --locked` fails with
  `zeroize-1.9.0 ... feature 'edition2024' is required`, proving the job discriminates.

**Docs.** `COMPATIBILITY.md:103-112`'s dependency-floor table says the Rust MSRV is "asserted" by
`verify/tests/msrv.rs`. That becomes an understatement once it is also compiled — update that row to
say both, in the same commit.

---

### Phase 2 — Retire what is done from the residual backlog, precisely

**Status:** DONE (2026-08-24, 3 rounds, Opus — docs). Two divergences from plan, both found by the
gate and both worth recording:

1. **The sweep's scope was larger than planned.** `plans/sdk-exec-w1-w7.md` was listed as COMPLETE
   under *Active / pending*, contradicting `plans/README.md`'s own stated convention that delivered
   plans move to `plans/archive/` with a dated verification note. Archived it (`git mv`), and
   repointed every inbound reference — including three in `DECISIONS.md` and one in a test
   docstring — so the move left no dangling paths.
2. **The sweep introduced its own inaccuracies, twice, and that is the lesson.** Round 1 caught a
   date I had asserted rather than checked (PR #42 merged **2026-08-17**, not 08-23) and two
   citation ranges that overshot into the next symbol. Round 2 caught the *same* wrong date
   surviving in this plan file — which round 1's diff could not see, because the file was untracked
   — plus an ARCHIVED note of mine that overclaimed. Round 3 caught that same note asserting
   `plans/cross-repo/` existed when it is Phase 4's deliverable.

   Three rounds, each finding a defect one level up from the last, in a phase whose entire purpose
   is documentation accuracy. Recorded plainly rather than smoothed over: a sweep that introduces
   its own staleness is worse than the staleness it replaced, and the only reason none of it shipped
   is that the gate ran three times.

**Delivers.** `plans/consolidation-2026-08-14.md`, `plans/build-agent-ingress.md` and
`plans/README.md` describing the current tree rather than the tree of ten days ago — with each
retirement naming what was true, what changed, and what still stands.

**Depends on.** Nothing.

**Files.** `plans/consolidation-2026-08-14.md`, `plans/build-agent-ingress.md`, `plans/README.md`.

**Approach.**

The residual backlog is at `plans/consolidation-2026-08-14.md:71-83`, five bullets. Verified state:

| # | Bullet | Verdict | Evidence |
|---|---|---|---|
| 1 | `build-agent-ingress` §A–§D | **PARTIAL** — §A and §C **done**, §B and §D still real | `seam-adapters/examples/fraud_budget/`, `fraud_admission_denied/` exist; `seam-adapters/core/seam_agent_core/session_binder.py:43` defines `StepUsage` (both landed in seam-adapters PR #42, `9a05a04`, 2026-08-17). §B is issue #40, open. §D still needs a Cloudsmith entitlement (`seam-adapters/compose/README.md:12-30`). |
| 2 | No gradle wrapper; CI gradle unpinned | **DONE, both halves** | `java/gradle/wrapper/gradle-wrapper.jar` + `kotlin/…` tracked (`cf23722`); both `.properties` pin `gradle-8.7-bin.zip`; CI runs `./gradlew` (`ci.yml:254-257`, `:268-271`), so the wrapper pins CI too. |
| 3 | `now_millis` unexposed on both erasure wrappers | **DONE** | `python/seam_sdk/admin.py:250-269`, `:271-290`; `ts/src/admin.ts:183-194`, `:198-210`; shipped per `CHANGELOG.md:75`. |
| 4 | adapters lock resolves 0.7.9 | **FACT TRUE, framing wrong twice** | `seam-adapters/uv.lock:3920-3922` still resolves 0.7.9 — but "against an SDK at 0.7.21" is stale (now 0.7.43) and "documented as applying to partners/CI" is **retracted upstream** at `seam-adapters/pyproject.toml:17-29`. |
| 5 | Differential-harness rotation coverage | **DONE, and not ours** | `seam-runtime/crates/seam-verify/tests/differential.rs:177,453-468` has `rotation-both-issuers` and `rotation-new-issuer-only`. The harness is seam-runtime's; seam-sdk has no file to fix. |

**The editing discipline is the point, and it is the one #51 established.** Bullets 2, 3 and 5 are
wholly done and get retired outright. Bullets 1 and 4 are **half-true**, and a blanket retraction of
either would itself be a false claim — the exact failure mode `plans/build-agent-ingress.md:6-16`'s
own retraction was written to avoid. So:

- **Bullet 1** — retire the §A and §C clauses naming what closed them; keep §B and §D. Then fix the
  two places that repeat the stale version: `plans/build-agent-ingress.md:26-30` still says "Missing:
  the two scenes", and `plans/README.md:13` still says all four "remain".
- **Bullet 4** — rewrite rather than retire. Keep the true observation (the lock resolves 0.7.9),
  drop "0.7.21", drop the "partners/CI" framing that upstream has retracted, and point at
  `plans/build-agent-ingress.md`'s dated retraction block as the authoritative statement so there is
  one place to maintain instead of three.
- **Also fix `plans/consolidation-2026-08-14.md:58`** ("version lockstep py==ts==0.7.21 intact") —
  the lockstep claim is still true, the number is not. Correct the number, keep the claim.
- **And `:24`'s plan-triage row**, which lists all four `build-agent-ingress` gaps as missing.

*Rejected:* deleting the residual-backlog section wholesale now that most of it is done. The section
is a record as much as a queue — `plans/README.md:14` describes this file as **"RECORD + BACKLOG"** —
and deleting the record loses why each item existed. Retire in place, with dates.

*Rejected:* marking bullet 4 done because it is "not really our problem." It is still literally
true, and #51's whole discipline is that a true-but-misleading claim gets corrected, not deleted.

**Edge cases & failure modes.**
- **The retracted-claims guard will fire if this is done carelessly.**
  `python/tests/test_retracted_claims.py` fails when the string `seam-sdk >=0.7,<0.8` appears in any
  markdown paragraph lacking a retraction marker. Bullet 4's rewrite must not reintroduce it
  unqualified. Run that test as part of this phase, not at the end.
- **Dating matters.** Every retirement states *as of 2026-08-24* and cites what closed it. An
  undated "done" becomes the next stale claim — which is precisely how this backlog got here.
- **Cross-repo claims are cited, never asserted.** §A/§C/#5 closed in sibling repos; each retirement
  names the file and the commit so a reader can check without trusting this file.
- **`plans/README.md` and the plan files must agree.** Fixing one and not the other reproduces the
  problem one file over.

**Acceptance criteria.**
1. Bullets 2, 3 and 5 are marked retired, each naming the evidence that closed it and the date.
2. Bullet 1 retains §B and §D, and retires §A and §C with citations.
3. Bullet 4 is rewritten: the lock observation kept, `0.7.21` and the "partners/CI" framing gone,
   pointing at the authoritative retraction.
4. `plans/build-agent-ingress.md:26-30` no longer claims the two scenes are missing.
5. `plans/README.md`'s active table matches the plan files it describes.
6. `plans/consolidation-2026-08-14.md:58` no longer states a stale version number.
7. `python -m pytest python/tests/test_retracted_claims.py -q` passes.
8. No claim is retired without a `file:line` or commit citation — a reviewer can check every one.

**Tests.** `python/tests/test_retracted_claims.py` (existing) must stay green. No new test: these
are plan-file records, and the repo's existing guard already covers the one string that has a
history of reappearing.

**Docs.** This phase *is* the doc change. Nothing else goes stale as a result.

---

### Phase 3 — Record the CrewAI/protobuf finding where a reader will find it

**Status:** DONE (2026-08-24, 1 round, Fable — the phase grew executable code). **Scope widened
mid-phase by the owner**: "for this and other agent frameworks", with a design agent asked to find
the right solution. The plan text below is superseded by what shipped; kept for the reasoning.

**What changed against the plan.** The plan wrote this as prose in two files. It shipped as prose
**plus a resolving probe**, because the answer depends on PyPI rather than on this repo — a table of
versions is stale on arrival, which is the failure mode the rest of this plan is cleaning up. The
doc's table is the probe's *input*, so the two cannot disagree.

**Generalised past CrewAI, which was the point of the widening.** Scope is the four frameworks
`seam-adapters` ships shims for. Resolved live: `crewai` **incompatible**; `langchain`,
`strands-agents`, `claude-agent-sdk` **compatible**. The rule is not "OpenTelemetry is
incompatible" — OTel lifted its `protobuf<7` cap. It is: *a framework that exact-pins or `~=`-pins
the OTLP exporter below that lift is stuck; one that depends on it by range rides over it.* Same
ecosystem, opposite outcome, and pin style is the difference.

**Two corrections to the design agent's own proposal, both found by executing it:**
1. **Resolve with the shim's declared constraint, never the bare package name.** A bare `crewai`
   resolves *successfully* — by backtracking to **1.6.1**, a release predating the conflict — and
   would have reported a false `compatible`. Verified independently by the gate.
2. **Exit codes cannot classify the outcome.** `uv` exits non-zero for an unsatisfiable graph, a
   missing package **and** a disabled network, and all three print "unsatisfiable". The probe
   classifies on the message, checks infra markers *before* the unsatisfiable branch, and treats
   anything unrecognised as infrastructure (exit 2) — never a verdict.

*Gate findings closed:* the Python-version guard exited 1 (reserved for "a row disagrees") where an
infra condition must exit 2; and the `strands-agents` row said "depends on the exporter by range"
when the base install pulls no exporter at all and only the extras add it.

**Depends on.** Nothing. Sequenced last because it is the least urgent — the finding is correct and
written down in issue #48; it is simply not durable.

**Delivers.** The `#48` analysis recorded in the repo: the consumer-facing constraint in
`COMPATIBILITY.md`, and the decision not to widen the floor in `DECISIONS.md`.

**Files.** `COMPATIBILITY.md`, `DECISIONS.md`,
`python/tests/test_compatibility_citations_resolve.py` (only if new citations are added).

**Approach.**

The finding today lives only in a GitHub issue comment. Substance, re-verified:

- `opentelemetry-proto` capped `protobuf<7.0` through **1.42.1**, and lifted it to `<8.0` in
  **1.43.0**.
- `opentelemetry-exporter-otlp-proto-http` pins `opentelemetry-proto` **exactly** (`==1.42.0`,
  `==1.43.0`), so there is no resolving around it.
- `crewai` **1.15.17** (latest) requires `opentelemetry-exporter-otlp-proto-http~=1.42.0`, i.e.
  `<1.43.0` — so it cannot reach the release that lifted the cap.

**The blocker moved from OpenTelemetry to CrewAI**, and that is the durable, non-obvious part.

**Split by audience, because the two facts have different readers:**

- **`COMPATIBILITY.md` §4, after the dependency-floor table** — the consumer-facing constraint:
  `seam-sdk` and `crewai` cannot share one virtualenv today, why, and what will resolve it. A
  consumer hitting the resolver error needs this, and they will not read `DECISIONS.md`.
- **`DECISIONS.md`** — the *decision*: we will not widen our floor to accommodate it, and why that
  is not even available to us.

**Write the mechanism and a re-check command, not just today's version numbers.** This is the
critical design call. Every version number above will age, and a doc full of aged numbers is exactly
the stale-claim problem Phase 2 is cleaning up. So the record must state the *shape* — "the exporter
pins `opentelemetry-proto` exactly, so whichever version CrewAI's `~=` admits is the cap you get" —
and include the command that re-derives the current answer, so a future reader can check in thirty
seconds instead of trusting a number.

**Why widening our floor is not available**, and this is the part that belongs in `DECISIONS.md`:
the floor is **derived**, not chosen. `buf.gen.yaml` uses **unpinned** remote plugins, so buf emits
whatever gencode is current, and protobuf's runtime-version check rejects a runtime older than the
gencode that produced a file. #51 demonstrated this concretely — the floor moved `7.35.1 → 7.36.0`
with nobody editing `pyproject.toml`. Widening would mean pinning buf's remote plugins to emit older
gencode: freezing this repo's codegen, on the release source of record, indefinitely, to satisfy a
downstream pin — and it would not fix the root cause.

*Rejected:* putting it only in `DECISIONS.md`. That file is the reconcile ledger; a consumer
debugging a resolver error will not open it.

*Rejected:* pinning buf's remote plugins. Priced in Long-term posture.

**Edge cases & failure modes.**
- **The citation guard applies.** Any new `file:line` in `COMPATIBILITY.md` must resolve, and if a
  citation is load-bearing it belongs in `ANCHORED` in
  `python/tests/test_compatibility_citations_resolve.py`. Prefer citing **stable** anchors
  (`buf.gen.yaml`, `python/pyproject.toml`) over line numbers in files this plan is editing.
- **Version numbers age.** Mitigated by recording the mechanism plus a re-check command, and by
  dating the observation.
- **This is a third-party claim about CrewAI.** State it as observed-at-a-date with the command to
  re-verify, and do not imply CrewAI has agreed to anything.
- **Do not over-reach into `seam-adapters`' territory.** They own the two-venv workaround and have
  documented it; this repo records the constraint and the decision, and points at them.

**Acceptance criteria.**
1. `COMPATIBILITY.md` §4 carries the constraint, stating the **mechanism** (exporter pins
   `opentelemetry-proto` exactly; CrewAI's `~=1.42.0` cannot reach 1.43.0) and not only version
   numbers.
2. It includes a runnable re-check command and an as-of date.
3. `DECISIONS.md` records the decision not to widen the floor, with the derived-floor reasoning and
   the `7.35.1 → 7.36.0` evidence.
4. Neither claims CrewAI has committed to a fix; both name issue #48.
5. `python -m pytest python/tests/test_compatibility_citations_resolve.py -q` passes, with any new
   load-bearing citation added to `ANCHORED`.
6. `python -m pytest python/tests/test_retracted_claims.py -q` still passes.

**Tests.** Both existing doc guards must stay green. No new test: the citation guard already covers
the failure mode this change could introduce.

**Docs.** This phase is the doc change.

---

### Phase 4 — Give the six `seam-runtime` asks a version-controlled home

**Status:** DONE (2026-08-24). No divergence from plan. Six plan files plus an indexed README, each
carrying the workspace's `Owner` / `Filed by` / `Issue` / one-plan-one-home header; #419 records its
downgrade from blocker to hygiene. Issue comments linking to the blob URLs are posted **after merge**
so the links resolve rather than 404.

*Gate findings closed:* a quote attributed to the `seam-sdk` plan actually came from
`seam-aegis/plans/exec/seam-sdk.md` (the plan set's whole justification is being checkable, so a
misattribution there is worse than elsewhere); the anchor-feed plan inverted `SEAM_CHAIN_ANCHOR` —
it *overrides* rather than enables, and a durable deployment is **already emitting** the events, which
makes the ask smaller than the plan implied; and that plan asked for a `docs/specs/` document without
naming `docs/specs/audit-anchor.md`, which already exists, is **Normative**, and states the runtime
never anchors in-process — a tension the receiving team should reconcile rather than discover.

**Delivers.** `plans/cross-repo/` in this repo — the convention every other repo in the workspace
follows and this one does not — holding a plan file per outstanding `seam-runtime` ask, indexed, with
each issue pointing back at its plan.

**Depends on.** Nothing. Sequenced last because it is additive and touches no existing file except
`plans/README.md`.

**Files.** `plans/cross-repo/README.md` (new), six new plan files under `plans/cross-repo/`,
`plans/README.md`.

**Approach.**

The W1–W7 workstream filed six asks in `seam-runtime` — [#418](https://github.com/zer07labs/seam-runtime/issues/418)
(wire-framing handshake), [#419](https://github.com/zer07labs/seam-runtime/issues/419) (verifier
crate rename), [#420](https://github.com/zer07labs/seam-runtime/issues/420) (data-plane bind guard),
[#421](https://github.com/zer07labs/seam-runtime/issues/421) (evidence-bundle export),
[#422](https://github.com/zer07labs/seam-runtime/issues/422) (anchor feed),
[#423](https://github.com/zer07labs/seam-runtime/issues/423) (commitment-digest spec) — and put the
full detail **in the issue bodies**, writing no local plan file.

That is a deviation from the established workspace convention, and it is this plan that records it
rather than leaving it implicit. `seam-adapters`, `seam-learning`, `seam-connectors` and
`seam-runtime` all keep `plans/cross-repo/<target-repo>-<feature>.md` **in the repo that wrote it**,
paired with a tracking issue in the target repo that links back. `seam-sdk` has no such directory.

**Why the convention is worth conforming to, rather than declaring the issues sufficient.** Three
things are lost by living only in an issue: the reasoning is not version-controlled in this repo; it
is not discoverable from `plans/`, which is where someone looks for outstanding work; and an issue
that is edited, closed or transferred takes the record with it. The convention exists so that the
**plan** is the durable artifact and the **issue** is only the tracked ask. That is the same
distinction this repo already applies to `DECISIONS.md` versus a PR comment.

Follow the workspace's existing shape exactly — this is a case for conforming, not improving:

- **Header block** per file, matching `seam-learning/plans/cross-repo/seam-runtime-feature-schema-rule.md:1-8`:
  `**Owner:**` the target repo's team, `**Filed by:** seam-sdk, <date>`, `**Issue:**` the link, and
  the *"One plan, one home — if you copy this into `seam-runtime`, delete it here and leave a
  pointer"* instruction that keeps a plan from existing in two places.
- **Body**: Context / Delivers / Depends on / Files / Approach / Acceptance criteria / Tests, scoped
  to **only what that repo does**. `Files` lists paths inside `seam-runtime`, never this repo.
- **README index** modelled on `seam-adapters/plans/cross-repo/README.md`: a table of plan → target
  repo → headline → issue → state, plus the "staging area, not the execution home" framing and the
  standing instruction to **re-verify `file:line` anchors before editing**, since they were true when
  filed and these repos merge frequently.
- **Then comment on each issue** with a GitHub blob URL to its plan. The branch is not on `main` when
  written, so either link `main` and note it resolves once the PR merges, or post the comments after
  merge. Prefer **after merge** — a link that 404s is worse than a link that arrives a minute later.

**The content is a transcription, not a redesign.** The six issue bodies already carry the ask,
the evidence with `file:line`, and acceptance criteria; this phase moves that into the conventional
shape and adds the header/index. Where an issue has since been updated — #419 was downgraded from
blocker to hygiene when packages moved to Cloudsmith — the plan file records the **current** state,
not the state at filing.

*Rejected:* writing these files into `seam-runtime` directly. That is a cross-repo write, gated, and
the convention explicitly puts the plan in the authoring repo precisely so it need not be.

*Rejected:* one combined `seam-runtime.md` covering all six. They have independent owners, states and
lifetimes — #419 is now hygiene, #418 is blocking a latch in this repo, #423 is a docs deliverable.
A combined file cannot be archived per-item as each closes.

**Edge cases & failure modes.**
- **Anchors go stale.** Every `file:line` was true when filed (2026-08-23); `seam-runtime` merges
  often. The README carries the standing re-verify instruction, and each plan is dated, so a reader
  knows what to distrust.
- **Divergence between plan and issue.** Two homes for one ask invites drift. Mitigated by the
  "one plan, one home" header and by the issue linking to the plan rather than restating it.
- **#419's state already moved** — recording it as a blocker would reintroduce a claim this repo has
  already corrected. The plan file must reflect the Cloudsmith decision.
- **Do not re-file or duplicate issues.** All six exist; this phase adds a comment to each, nothing
  more.

**Acceptance criteria.**
1. `plans/cross-repo/` contains six plan files, one per issue #418–#423, each with the
   Owner / Filed-by / Issue / one-plan-one-home header block.
2. Each plan's `Files` section lists **only** `seam-runtime` paths — no `seam-sdk` path appears in
   any of them.
3. `plans/cross-repo/README.md` indexes all six with target repo, headline, issue link and current
   state, and carries the re-verify-anchors instruction.
4. #419's plan records it as **hygiene, not a blocker**, consistent with the Cloudsmith decision in
   `DECISIONS.md`.
5. `plans/README.md` references the new `cross-repo/` directory.
6. Each of the six GitHub issues carries a comment linking to its plan file, posted **after** the PR
   merges so the URL resolves.
7. No file is written into any sibling repo — verifiable with `git status` in `seam-runtime`.

**Tests.** No automated test: these are plan records. `python/tests/test_retracted_claims.py` must
stay green, since it scans every markdown file in the repo and these are new markdown files.

**Docs.** `plans/README.md` gains the `cross-repo/` pointer. Nothing else goes stale.

---

## Long-term posture

- **Pinning buf's remote plugins** would let the protobuf floor be widened deliberately, at the cost
  of freezing codegen on the release source of record. Not recommended, and the pricing is recorded
  in Phase 3 so a future reader sees a considered rejection rather than an unexamined default.
- **The MSRV job will go red on its own schedule**, when a dependency raises its floor. That is the
  design working. The cost is a small, recurring, deliberate bump — much cheaper than a consumer
  discovering an untrue `rust-version` from a compile error.
- **Dev-deps vs normal-deps MSRV** do not diverge today (1.71 vs 1.85). If they ever invert, testing
  at MSRV would overstate the consumer promise, and the fix is to split build-at-MSRV from
  test-at-MSRV. Not pre-solved, because solving it now would add a second job for a condition that
  does not exist.
- **No one-way doors in this plan.** No schema, no public API, no auth model, no migration. Every
  change is a CI job or a documentation edit, all trivially reversible.

## Enterprise concerns

Small plan; most of this section is genuinely N/A, and saying so is better than inventing scope.

- **Reliability.** Phase 1 adds a required check. If it flakes, it blocks merges — mitigated by
  `--locked` (deterministic resolution) and by a job that only builds and tests one small crate with
  six dependencies.
- **Observability.** The MSRV job's failure message must be self-explaining: a red result means
  raise `rust-version`, not lower the toolchain. A gate whose failure is misread gets weakened,
  which is how two of #51's own gates nearly shipped broken.
- **Security.** Untouched. Phase 1 pins a toolchain by version; no new dependency, no new
  credential, no new network surface beyond the toolchain download every Rust job already does.
- **Rollback.** Delete the job and its `ci-ok.needs` entry; revert the doc commits. No state.

## Open questions

None blocking. Two judgement calls, both taken with a defensible default and flagged here so
`/implement` logs them to `ASSUMPTIONS.md` as `UNCONFIRMED` if it wants confirmation:

1. **`cargo test` vs `cargo build` at MSRV.** Defaulting to **both**, because dev-deps demonstrably
   do not inflate the floor today (1.71 vs 1.85). Cheap to reverse.
2. **Where the CrewAI record lives.** Defaulting to **both** `COMPATIBILITY.md` (consumer-facing
   constraint) and `DECISIONS.md` (the decision), because the two facts have different readers.

## Repo map

| Path | Relevance |
|---|---|
| `.github/workflows/ci.yml` | Phase 1's only file. `verify` job at `:274-...`; `ci-ok` gate and its `needs:` list at the end. |
| `scripts/test_ci_gate.py` | Asserts `ci-ok.needs` covers every job — makes forgetting Phase 1's gate entry impossible. |
| `verify/Cargo.toml` | `rust-version = "1.85"`, the single source Phase 1 derives from. |
| `verify/tests/msrv.rs` | Existing guard for the *declared* half of the MSRV promise. |
| `plans/consolidation-2026-08-14.md` | Phase 2 primary. Residual backlog `:71-83`; stale version at `:58`; stale triage row at `:24`. |
| `plans/build-agent-ingress.md` | Phase 2. Stale "Missing: the two scenes" at `:26-30`; the model retraction block at `:6-16`. |
| `plans/README.md` | Phase 2. Active/pending table at `:13-14`. |
| `COMPATIBILITY.md` | Phase 1 (floor table `:103-112`) and Phase 3 (§4). |
| `DECISIONS.md` | Phase 3. |
| `python/tests/test_retracted_claims.py` | Guards the stale adapters pin; Phases 2 and 3 must keep it green. |
| `python/tests/test_compatibility_citations_resolve.py` | Every `COMPATIBILITY.md` citation must resolve; `ANCHORED` pins the load-bearing ones. |
