# PROGRESS — `plans/close-out-w1-w7-loose-ends.md`

Checkpoint trail and repo map for the close-out workstream. `/implement` writes a block per phase;
a resumed run reads this instead of re-scanning the repo.

**Plan:** [`plans/close-out-w1-w7-loose-ends.md`](plans/close-out-w1-w7-loose-ends.md) — 4 phases.
**Branch:** `feat/close-out-loose-ends`, cut from `origin/main` @ `f68572f` (v0.7.43).

## Repo map

| Path | Purpose / relevance |
|---|---|
| `.github/workflows/ci.yml` | Phase 1's only file. `verify` job builds on `stable` only; `ci-ok` is the single required check and its `needs:` list is the gate. |
| `scripts/test_ci_gate.py` | Asserts `ci-ok.needs` covers every job — makes forgetting Phase 1's gate entry impossible. REQUIRED vs ADVISORY split; `integration` is the only allowed advisory. |
| `verify/Cargo.toml` | `rust-version = "1.85"` — the single source Phase 1 derives the toolchain from. Also `publish = ["zer07labs"]` (Cloudsmith, not crates.io). |
| `verify/tests/msrv.rs` | Guards the *declared* half of the MSRV promise (derives from `cargo metadata`). Phase 1 adds the *compiled* half. |
| `verify/.cargo/config.toml` | Declares the private Cargo registry; publish-path only, does not affect a credential-less build. |
| `plans/consolidation-2026-08-14.md` | Phase 2 primary. Residual backlog `:71-83`; stale version at `:58`; stale plan-triage row at `:24`. |
| `plans/build-agent-ingress.md` | Phase 2. Stale "Missing: the two scenes" at `:26-30`; the model retraction block at `:6-16`. |
| `plans/README.md` | Phase 2 + 4. Active/pending table at `:13-14`. |
| `plans/cross-repo/` | Phase 4 creates it. Does not exist today — the deviation Phase 4 closes. |
| `COMPATIBILITY.md` | Phase 1 (floor table `:103-112`) and Phase 3 (§4). Every `file:line` citation in it is guarded. |
| `DECISIONS.md` | Phase 3. The durable decision ledger. |
| `python/tests/test_retracted_claims.py` | Scans every markdown file; guards the stale adapters pin and the truncation caveat. Phases 2/3/4 must keep it green. |
| `python/tests/test_compatibility_citations_resolve.py` | Every `COMPATIBILITY.md` citation must resolve; `ANCHORED` pins the load-bearing ones. Phase 3 may need to extend it. |

### Sibling repos (read-only — referenced, never written)

| Path | Why it matters |
|---|---|
| `../seam-adapters/plans/cross-repo/README.md` | The index format Phase 4 models its README on. |
| `../seam-learning/plans/cross-repo/seam-runtime-feature-schema-rule.md` | The header-block format Phase 4 copies (`Owner` / `Filed by` / `Issue` / one-plan-one-home). |
| `../seam-adapters/examples/fraud_budget/`, `fraud_admission_denied/` | Evidence that closes §A of Phase 2's bullet 1 (seam-adapters PR #42, `9a05a04`). |
| `../seam-adapters/core/seam_agent_core/session_binder.py:43` | Evidence that closes §C (`StepUsage`). |
| `../seam-runtime/crates/seam-verify/tests/differential.rs:177,453-468` | Evidence that closes Phase 2's bullet 5 (rotation coverage). |

## Phase log

_(appended per phase)_

### Phase 1 — MSRV compiled, not just asserted — **PASS**

- **When:** 2026-08-24. **Rounds:** 1. **Verifier:** Sonnet (CI/CD tier per `/implement` §2).
- **Files:** `.github/workflows/ci.yml` (new `verify-msrv` job + `ci-ok.needs` entry),
  `COMPATIBILITY.md` (floor row now says asserted **and** compiled).
- **Verdict:** PASS on all six acceptance criteria, each checked by execution.
- **Round-1 note (not a gap — a latent fragility the verifier raised and I closed):** the planned
  `grep -m1 '^rust-version'` would read a `[workspace.package]` `rust-version` if one were ever
  added, because this manifest opens with an empty `[workspace]`. Replaced with an `awk` pass scoped
  to `[package]`; verified with a decoy that the scoped form ignores.
- **Proven by execution, not inspection:**
  - builds + full suite pass at 1.85 (`cargo +1.85 test --locked`, 7 binaries + doctest);
  - **fails at 1.83** (`zeroize-1.9.0` needs `edition2024`) — so the job discriminates rather than
    passing vacuously, and 1.85 is exact rather than a safe over-estimate;
  - extraction fails **loudly** on a missing key, a garbage value and an unquoted value (all exit 1
    with an actionable `::error::`, not a silent `set -e` death);
  - removing `verify-msrv` from `ci-ok.needs` turns `scripts/test_ci_gate.py` red.
- **Suites:** Python 265 passed / 16 skipped; `scripts/test_ci_gate.py` 12 passed.
- **Assumptions logged:** 1 (`cargo test` as well as `cargo build` at MSRV).
- **Next:** Phase 2 — retire the stale residual-backlog entries across three plan files.

### Phase 2 — Residual-backlog sweep across three plan files — **PASS**

- **When:** 2026-08-24. **Rounds:** 3. **Verifier:** Opus (docs tier).
- **Files:** `plans/consolidation-2026-08-14.md`, `plans/build-agent-ingress.md`, `plans/README.md`,
  `plans/sdk-exec-w1-w7.md` → `plans/archive/` (git mv), `DECISIONS.md` (3 paths repointed),
  `python/tests/test_framing_rationale_is_documented.py` (1 docstring path).
- **Outcome:** of the five residual bullets, three retired outright (gradle wrapper, `now_millis`,
  differential-harness rotation), one narrowed (§A/§C done, §B/§D still open), one rewritten (the
  adapters lock — the observation is true, two of its clauses were not). Plus two stale claims that
  had spread into other files, and a plan archived per the repo's own convention.
- **Round 1 (6 gaps, 2 HIGH):** the "Remaining work" summary still listed §A/§C as remaining,
  contradicting the UPDATE block above it; the §C bullet asserted "no `StepUsage` reference anywhere
  in seam-adapters", false since PR #42; **a date I asserted without checking** (08-23 vs the real
  08-17); a COMPLETE plan sitting in the Active table; two citation ranges overshooting into the
  next symbol.
- **Round 2 (4 gaps):** the same wrong date surviving in this plan file — invisible to round 1,
  whose diff covered only tracked files; a dangling path left by the archive move; and an ARCHIVED
  note of mine claiming verification rounds were "recorded in the phase sections below" when they
  are not.
- **Round 3 (1 gap):** that same ARCHIVED note asserting `plans/cross-repo/` exists "as of
  2026-08-24" — it is Phase 4's deliverable and does not exist yet.
- **The honest read:** three rounds, each catching a defect one level up, in the phase *about*
  documentation accuracy. Nothing shipped wrong only because the gate ran three times.
- **Verified independently by the gate, not asserted by me:** PR #42 (`9a05a04`) really is
  2026-08-17; `fraud_budget` really drives SUSPENDED → `resume_session` → seal; `fraud_admission_denied`
  really refuses **at Admit** rather than at the tool gate; `StepUsage` really is at
  `session_binder.py:43`; the rotation cases really are at `differential.rs:453-468`.
- **Suites:** Python 265 passed / 16 skipped; `scripts/test_ci_gate.py` 12 passed.
- **Assumptions logged:** none new.
- **Next:** Phase 3 — the framework co-installability record (design returned by Fable; scope is
  wider than the plan's original Phase 3 — see that section).

### Phase 3 — Framework co-installability, recorded as a probe — **PASS**

- **When:** 2026-08-24. **Rounds:** 1. **Verifier:** Fable (the phase grew executable code + a
  network-dependent CI job — above the docs tier the plan assumed).
- **Scope widened mid-phase by the owner** from "record the #48 CrewAI finding" to "this and other
  agent frameworks", with a design agent asked to find the right solution.
- **Files:** `COMPATIBILITY.md` (§4a + machine-parsed table), `scripts/probe_framework_coinstall.py`
  (new), `Makefile` (`probe-frameworks`), `.github/workflows/framework-coinstall.yml` (new),
  `DECISIONS.md`.
- **The matrix, resolved live rather than asserted:** `crewai` **incompatible**; `langchain`,
  `strands-agents`, `claude-agent-sdk` **compatible**. Independently re-resolved by the gate.
- **Two corrections to the design, both found by executing it rather than reading it:**
  1. a bare `crewai` resolves by backtracking to **1.6.1** and would report a false `compatible` —
     the probe must use the shim's declared constraint;
  2. `uv` exits non-zero for unsatisfiable, not-found **and** offline, all saying "unsatisfiable",
     so exit-code classification is impossible; infra markers are checked first and anything
     unrecognised is infra, never a verdict.
- **Proven non-vacuous by execution:** both flip directions exit 1 with actionable messages; a
  missing table marker, a de-backticked table, a missing `uv`, `UV_OFFLINE=1` and a bogus index all
  exit **2**; and widening the floor in `pyproject.toml` flowed through to flip crewai's verdict,
  proving nothing is hardcoded.
- **Gate findings closed:** the Python-version guard exited 1 where infra must exit 2; the
  `strands-agents` row overstated where the exporter dependency lives.
- **Suites:** Python 270 passed / 16 skipped.
- **Assumptions logged:** none new (the design's open choices were settled by execution).
- **Next:** Phase 4 — `plans/cross-repo/` for the six seam-runtime asks.

### Phase 4 — `plans/cross-repo/` for the six seam-runtime asks — **PASS**

- **When:** 2026-08-24. **Rounds:** 1. **Verifier:** Opus (docs tier).
- **Files:** `plans/cross-repo/README.md` + six plan files (#418–#423), `plans/README.md`.
- **Why it existed:** the W1–W7 workstream put all six asks' detail in the GitHub issue bodies and
  wrote no local plans — a deviation from the convention `seam-adapters`, `seam-learning`,
  `seam-connectors` and `seam-runtime` all follow. Introduced by that workstream, closed here.
- **Gate findings closed (3, all content accuracy):** a quote attributed to the wrong source file;
  `SEAM_CHAIN_ANCHOR` described as an enable-flag when it is an *override* (a durable deployment
  already emits the events, so the ask is smaller than stated); and an ask for a `docs/specs/`
  document that omitted `docs/specs/audit-anchor.md` — which exists, is **Normative**, and states the
  runtime never anchors in-process.
- **Independently re-verified by the gate against seam-runtime source**, not taken from the issues:
  #420's derived-enforcement claims *and* the surviving Embedded+non-loopback gap; #422's zero-hit
  greps for `checkpoint`/`transparency`; #423's both-halves claim about which digest has a spec;
  #418/#419's seam-sdk-side state.
- **Repo scope held:** nothing written into any sibling. `seam-runtime`'s dirty worktree belongs to a
  **different concurrent session** (`.drive.lock` → `30a26ad5-…`, feature
  `a1-real-participation-and-deliberation`) doing AITP delegation-voucher work — confirmed unrelated.
- **Deferred by design:** the issue comments linking to each plan are posted **after merge**, so the
  blob URLs resolve instead of 404ing. Those comments should also correct each issue's footer, which
  points at `plans/sdk-exec-w1-w7.md` — a path this branch moves to `plans/archive/`.
- **Suites:** Python 270 passed / 16 skipped.
- **Next:** all four phases done — ship.
