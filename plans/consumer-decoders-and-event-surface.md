# Consumer decoders and the event surface

Three independent issues: a flaky required-lane gate that blocks releases (#85), a fail-open decode
gap a downstream repo is working around today (#87 ask 2), and a contract surface with no manifest
(#88). They share no files and no mechanism. They are planned together because they are the whole of
the current open queue, and separated into three PRs because nothing about them is coupled.

## Context

### Baseline, measured at `960cf81` on `main`, clean tree

| Command | Result |
|---|---|
| `cd python && .venv/bin/pytest -q` | **754 passed, 17 skipped** (771 collected) |
| `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` | **exit 6**, NOTE naming `contract/expected-local-lag.txt`, 5 `ContextBinding` fields |
| `./scripts/check-independence.sh` | exit 0 |

> **Corrected by the re-verification pass.** The first draft recorded **730 passed**. That number was
> measured *before* this plan's own `PROGRESS.md` section was appended.
> `python/tests/test_compatibility_citations_resolve.py` is parametrized over **every** citation in
> `PROGRESS.md` (`DOCS` at `:95-99`, `CITATION` at `:109`, `_all_citations()` driving
> `test_each_citation_resolves` at `:447-461`), and the appended section adds **24** matching
> citations — 730 + 24 = 754, re-measured at `960cf81`. Two consequences, both load-bearing:
>
> 1. Every "730 + N passed" criterion below is wrong and has been restated against **754**.
> 2. **`N` is not "the number of new test functions".** Each phase also edits `PROGRESS.md`, and each
>    new backticked `file.ext:NN` there adds a `test_each_citation_resolves` case. A phase that
>    predicts its own delta must count both. State the two numbers separately in the PR rather than
>    asserting one total, and never treat a mismatch as noise — a *lower* count than predicted is how
>    a silently-skipped or collection-error'd file looks.

Exit 6 locally is **correct**, not a defect: the committed manifest declares 228 fields, both
extractors read 223 from a pre-ACDP local stub tree, and the difference is exactly the five recorded
in `contract/expected-local-lag.txt`. CI regenerates fresh and is the authority. Do not "fix" it.

### #87 — ask 1 is already satisfied; ask 2 does not exist yet

`grep -rn policy_enforcement python/seam_sdk/ ts/src/` excluding `_gen/` returns nothing. There is no
hand-written decoder in either language.

**Ask 1 (cut a release carrying the `SessionStep` union) is DONE.** `v0.7.70` carried
`collective_outcome_of(resp: "pb.DecisionResponse")` and `collectiveOutcomeOf(resp: DecisionResponse)`.
`v0.7.71` carries the union in both languages, and its publish run (33479578480) succeeded on `python
wheel → Cloudsmith`, `npm → Cloudsmith` and `install from Cloudsmith and run the vectors`.

> **Correction to the briefing that produced this plan:** that run did **not** succeed on every job —
> `seam-verify → Cloudsmith` reported `skipped`. The three jobs that carry ask 1 all succeeded, so the
> conclusion holds, but "every job" was wrong and is corrected here rather than repeated.

`seam-adapters` pins `seam-sdk>=0.7.20,<0.8`, so `0.7.71` is inside its range and the debt retires
with no code change downstream. **#87 is not closed by this** — ask 2 is the work.

**Ask 2, and the trap, verified against the running protobuf runtime rather than read off a stub:**

```
SessionStep.policy_enforcement      has_presence=True
DecisionResponse.policy_enforcement has_presence=True
PolicyEnforcement.enforced          has_presence=False
PolicyEnforcement.policy_id         has_presence=True

absent  step: HasField=False | .policy_enforcement.enforced = False
genuine step: HasField=True  | .policy_enforcement.enforced = False
by value equal: True
```

Three states — absent / present+`enforced=False` / present+`enforced=True` — and the first two are
**value-identical**. Only `HasField` separates them. Returning `PolicyEnforcement(enforced=False)` for
an absent field is a fail-open bug: it converts "this response does not answer the question" into
"the runtime attests no policy gated this". That single property is the phase.

Unlike the verdict decode there is **no enum**, so no growth-policy fail-closed mapping is needed and
no new `errors.py` symbol is required. Smaller job than `_collective.py`.

**A second three-state field, one level down, that the issue does not mention.**
`PolicyEnforcement.policy_id` is `optional string` (`has_presence=True`): unset yields
`HasField("policy_id") == False` and `''`; explicitly-encoded empty yields `True` and `''`. The
dataclass must map absent to `None`, never to `""`, for exactly the reason the outer field does.

**The shape to mirror.** `python/seam_sdk/_collective.py`: `_VERDICT_NAMES` at `:43`,
`@dataclass(frozen=True) class CollectiveOutcome` at `:52`, `def collective_outcome_of` at `:84`,
`HasField` gate at `:116-117`.

**TypeScript gets a twin, and this is not a judgement call.** `ts/src/client.ts:218` already carries
`collectiveOutcomeOf(resp: DecisionResponse | SessionStep)`, with `UnknownCollectiveVerdictError` at
`:146` and `export interface CollectiveOutcome` at `:179`. The languages are already symmetric on the
sibling decoder; adding the Python half alone would create the asymmetry, not preserve one.

**The presence rule, and where to get it from.** seam-runtime#526 measures every `SessionStep`
construction site and reports: `policy_enforcement` is present on **three** — the commit-terminal
step, the sealed-idempotent replay, and the pending-commitment seal retry — where `collective_outcome`
is present on **one**. The expiry seal carries `decision_id` **without** `policy_enforcement`, so the
two do not track each other in either direction. The proto comment for field 3 states this
incorrectly in two ways, which is why #526 exists.

> **Source discipline.** `PROGRESS.md`'s clean-room constraint says `../seam-runtime/crates/**` Rust
> sources are never read. **Write the docstring from seam-runtime#526's own body**, which quotes the
> code and publishes the matrix — not from the Rust, and not from the proto comment #526 proves wrong.
> The generated comment in `ts/gen/.../seam_pb.ts` under `SessionStep.policyEnforcement` reproduces the
> wrong rule verbatim; a docstring copied from it would ship the defect into this repo.

> **Enumerate, never generalise.** #526 closes with: "Every short general rule anyone has tried here
> has been wrong, including in this issue" — an earlier draft proposed "populated on any step that
> reports a seal … absent on the expiry seal", which is self-contradictory, because the expiry seal
> *does* report a seal (it mints a durable record and returns a `decision_id`). The docstring must
> list the three sites by name. Any sentence of the form "populated whenever X" is a defect.

### #88 — the event surface has no manifest, and closing it is far cleaner than the issue implies

The load-bearing measurement, made by running the **real extractors** with only the stub path and the
package regex substituted (`seam.api.v1` → `seam.event.v1`):

| | Python | TypeScript |
|---|---|---|
| raw grep (`FIELD_NUMBER` / `@generated from field:`) | 90 | 90 |
| `fields_*` extractor output, sorted/deduped | **90** | **90** |
| Python-only entries | — | **0** |
| TS-only entries | **0** | — |
| nested messages | **0** | **0** |
| enums | **0** | **0** |
| messages | 11 | 11 |

**Both extractors already agree at 90/90 on the event surface with only a path and package change.**
No new extraction logic is needed — only parameterisation. That is the fact the whole phase rests on;
it was re-measured for this plan, not taken from the issue.

> **Independently re-run by the re-verification pass, against `960cf81`, and every cell holds.**
> `fields_python`'s awk was copied verbatim with `$PY_GEN` → the event `.pyi`; `fields_ts`'s awk was
> copied verbatim with `$TS_GEN` → the event `.ts` and all three `seam\.api\.v1` literals →
> `seam\.event\.v1`. Result: **90 / 90**, `comm -23` and `comm -13` both **empty**, 11 messages on each
> side (`AuditEntryEvent`, `AuthorizeEvaluated`, `BudgetBreach`, `ChainHeadAttestation`,
> `DecisionSealed`, `ErasureCertificate`, `LearningDecision`, `LearningOutcome`, `PolicyKey`,
> `SeamEvent`, `SessionLifecycle`), zero enums and zero nested types in both trees. Raw greps agree at
> 90 and 90. **The phase's central claim is sound as written.**

The machinery to extend, read end to end (`scripts/check-contract.sh`, 860 lines):

* `:84-94` the env-overridable paths (`SEAM_PY_GEN`, `SEAM_TS_GEN`, `SEAM_FIELD_MANIFEST`,
  `SEAM_RPC_MANIFEST`, `SEAM_EXPECTED_LOCAL_LAG`) — **note `PY_EV` (`:86`) and `TS_EV` (`:88`) are
  NOT overridable**, which the test pattern requires.
* `:203-213` `fields_python`, `:218-238` `fields_ts` — both hardcode `$PY_GEN`/`$TS_GEN` and the
  `seam\.api\.v1` package.
* `:240-242` `manifest_fields`, `:397-399` `manifest_enums`.
* `:297-314` `nested_messages_python`/`_ts`, `:324-352` `assert_known_nested_messages_only`,
  `:408-426` `assert_no_nested_enums` — all scoped to `seam.api.v1` on purpose (`:296` says so).
* `:428-478` `--write-manifest`, including `:472-476`, which **deletes `$EXPECTED_LOCAL_LAG`** on
  every field-manifest rewrite.
* `:583-594` the corrected comment #88 was filed from. (The issue and the briefing both cite
  `:580-591`; the seam.event.v1 paragraph actually begins at `:583` — `:577-582` is the api probe's
  own rationale. Minor, but this phase edits that comment, so get the range right.)

Existing partial coverage that must not regress: the `STREAM`/`EVENTS` probes (`:526-535`, `:541`)
assert **presence** of exactly four named fields. `scripts/check_vendored_spec.py` only catches drift
when the runtime also edits the spec doc.

`make check-contract` already runs with `STREAM=1 EVENTS=1` in both the `python` job
(`.github/workflows/ci.yml:118-122`) and the `typescript` job (`:181-185`). **No new CI job is needed
for #88**, so `ci-ok`'s `needs:` and `scripts/test_ci_gate.py` are untouched.

### #85 — the hypothesis was right, and the evidence is stronger than the briefing had

**Refuted first:** the issue's own guess is that `seamd` crashes on the seal/authorize RPC paths.
That cannot be it. `test_full_round_trip` (`python/tests/test_integration.py:69`) does a
`run_decision` + seal + `get_decision` + `replay_decision` and **passed**, while
`test_authorize_live_on_behalf_of_decision` (`:306`) does essentially the same work and **failed**.
The discriminator is not what the RPC does.

**What it is.** Confirmed against code, with the exact collection order:

1. `.github/workflows/ci.yml:284-291` — the smoke step starts `seam-grpc` on 8099, then
   `kill "$pid"` and `exit 0`. **It never waits for that process to exit.**
2. `python/tests/test_integration.py:37-66` — the `server` fixture is function-scoped, hardcodes
   `addr = "127.0.0.1:8099"` at `:48`, and tears down with a bare `proc.terminate()` at `:66` and no
   `proc.wait()`. Every test using it spawns a new server on the *same* port.
3. `:26-34` — `_wait(port)` proves only that *something* accepts a TCP connection there. It never
   proves it is the process just spawned.

`pytest --collect-only` on the four CI files gives **42 tests** (matching "3 failed, 39 passed") in
this order — re-measured, correct. The `server` users are #1 (`:69`), #2 (`:93`), #3 (`:108`) and
#7 (`:306`) — re-measured, correct. **The three that failed are #2, #3 and #7 — the shared-8099 set
minus the first.**

**The mechanism, stated as the hypothesis it is.** `_wait` returns against *something* listening on
8099; if that something is a previous spawn still draining, the new process's `bind` loses
(`EADDRINUSE`), the child exits, and the first real RPC hits a socket being torn down → **reset, not
refused**. That accounts for reset-not-refused and for the intermittency.

> **Re-verification pass — three corrections, because the first draft overclaimed.** The fix below is
> right under every reading; the *diagnosis* is not confirmed, and calling it confirmed is how the
> next occurrence gets theorised instead of measured.
>
> * **It does not explain the exact failing set.** 8115 is shared by tests #4 (`dual_plane`, `:143`),
>   #5 and #6 (`governed_server`, `:226`) — three consecutive tests on one fixed port, the same shape
>   as #2/#3 — and **all three passed** in the observed run. The same mechanism predicts #5 and #6
>   should have failed. It did not fire there, and the plan cannot say why.
> * **"the previous test's draining server" is wrong for #7.** #7's immediate predecessor is #6, a
>   `governed_server` on **8115**. The nearest 8099 predecessor is #3 — four tests earlier, and #3
>   itself *failed*. Whatever put #7 in the failing set, it is not the test that ran before it.
> * **The smoke step is a real defect but not the cause of #1 passing.** `ci.yml:284-291` does leave
>   an unwaited process on 8099, but `setup-python`/`setup-node`/`buf login`/`make generate`/`pip
>   install` run between it and `pytest` — minutes, not milliseconds. #1's `_wait` genuinely blocks
>   for a fresh bind. Fix the smoke step because a step that leaks a process it started is wrong on
>   its own terms, not because it explains the failure.
>
> **Unverifiable in this checkout, recorded rather than assumed:** `seam-grpc`'s listener socket
> options. The binary is not present here and `../seam-runtime/crates/**` is closed by `PROGRESS.md`'s
> clean-room constraint. Reasoning from tonic/tokio defaults — `tokio::net::TcpListener::bind` sets
> `SO_REUSEADDR` and does **not** set `SO_REUSEPORT` — two live listeners *cannot* coexist on
> `127.0.0.1:8099`, so the "second bind loses, `_wait` succeeds against the stranger" chain holds
> (`SO_REUSEADDR` affects `TIME_WAIT`, not an active `LISTEN`). If the runtime *did* opt into
> `SO_REUSEPORT`, both listeners would coexist and the kernel would load-balance between a healthy
> and a draining one — a different route to the same intermittent reset, closed by the same fix.
> Settle it from Phase 2's uploaded log, not from another round of theory.

**Proven deterministically, with no `seam-grpc` and no ambient dependency:**

```
_wait returned in 0.002s against a port the spawned process never bound
spawned proc exit code: 0
```

A decoy listener bound in-process; the "binary" a `python -c 'raise SystemExit(0)'` that binds
nothing and has already exited. Today's `_wait` calls that success. This is the red-first mechanism
for the whole phase.

**The defect is wider than the briefing said.** Corrections:

* **8115 is also shared.** `test_integration.py:143` (`dual_plane`, 8115/8116) and `:226`
  (`governed_server`, 8115) collide across three tests. It is a third instance that merely did not
  fire in the observed runs.
* `python/tests/test_streamed_decode.py:259` hardcodes 8113/8114.
* **All nine** teardowns across the four live files are bare `terminate()`:
  `test_integration.py:66,160,246`, `test_streamed_decode.py:276`,
  `test_verify_attestation.py:155`, `test_admin.py:265,277,326,345`.
  *(The first draft said "seven" over a list of nine, and repeated "7 teardown sites" in Phase 2's
  Approach. Re-measured with `grep -rn 'terminate()' python/tests/`: **nine**. Recorded because it is
  precisely the `ts/src/index.ts:18` "Two-over-three" defect this plan flags one phase later — a
  count word that contradicts its own list.)*
* There are **four** `_wait` copies, one per live file: `test_integration.py:26`,
  `test_streamed_decode.py:243`, `test_admin.py:164`, `test_verify_attestation.py:111`.
* `python/tests/test_integration.py`'s **module docstring is already false**: `:5` promises the test
  spawns the binary "on a free port", and `:48` hardcodes 8099. `:4` legitimately names
  `127.0.0.1:8090` as an example `SEAM_GRPC_ADDR` — prose, not a fixture port, and it must survive.
* All four files send server output to `subprocess.DEVNULL`, which is precisely why #85 says "every
  re-run destroys the only copy of the explanation".

**The fix pattern already exists in this repo and two files never adopted it.**
`python/tests/test_admin.py:175-181` and `python/tests/test_verify_attestation.py:122-128` define
`_free_port()`, whose own docstring says fixed ports "collide with whatever else is running (another
test worker, a leaked server) and fail with an unrelated-looking bind error". **The TypeScript suite
reached the same conclusion and applied it everywhere**: `ts/tests/integration.test.ts:51` states
"Distinct ports avoid cross-test collisions", and every live TS test gets a unique fixed pair (8095,
8097, 8098, 8201-8210, 8215-8218) with **zero** collisions across files that `node --test` runs in
parallel. The TS suite has never shown this flake. Python's has.

**Gate mechanics, stated precisely.** `integration` is in `ci-ok`'s `needs:`
(`.github/workflows/ci.yml:612`) and in `ADVISORY` (`:627`). Advisory means *may skip*, **not** *may
fail*: a job that runs and fails still reddens `ci-ok` and blocks the merge. So the practical
consequence — a flake blocks releases exactly as the spec-pin failure blocked v0.7.69 and v0.7.70 —
holds, and it is worth stating the mechanism correctly because "advisory" reads as "tolerated".

### What this plan does NOT do

* No `make clean` / `make generate` / `make generate-local`, in any phase. Those delete and replace
  three gitignored stub trees whose recovery needs a BSR login. CI runs `make generate` itself; that
  is why CI sees 228 api fields where this checkout sees 223.
* No mutation of the real stub trees. Every test that needs modified stubs copies them to `tmp_path`
  and drives the real script through the env overrides — the pattern already established in
  `python/tests/test_field_manifest_gate.py:54-92`.
* No `--write-manifest` without those overrides. A real write rewrites the manifest backwards from
  pre-ACDP local stubs and deletes `contract/expected-local-lag.txt` (`scripts/check-contract.sh:472-476`).
* No writes outside this repo, and no issue actions outside `zer07labs/seam-sdk`. seam-runtime#526 is
  read as the source for a docstring; it is neither commented on nor changed. If any phase turns out
  to need a change owned by another repo, it becomes a `plans/cross-repo/<repo>-<feature>.md` **in
  this repo** plus a note that an issue should be filed — never folded into a local phase's Files.
* No new CI job in any phase, so `ci-ok`'s `needs:` and `scripts/test_ci_gate.py` are untouched.
* No import added to `python/seam_sdk/crypto.py` or `python/seam_sdk/errors.py`
  (`python/tests/test_errors_is_import_light.py`).
* No workflow calls `buf generate` directly (`python/tests/test_workflows_generate_through_the_makefile.py`).
* Nothing is dispatched, published, or pushed to a registry.

### Two rules from this repo's own history, applied to every phase below

1. **Every acceptance criterion must be provable RED before the fix exists.**
   `plans/gate-blindness-hardening.md`'s `## Post-merge-gate record` records three
   vacuous artefacts that shipped: a criterion that passed by git's design, and two tests pointed at
   a file the fixture never created. Each phase below states *how* it is proven red first.
2. **A test must not be decided by the ambient environment.** The same plan then shipped tests that
   passed locally and failed in CI because they asserted on the ambient stub tree. Every test below
   **constructs** the state it asserts on — a scratch stub copy, a decoy listener, a fake binary.

### Ranking, and why

**Phase 2 (#85) → Phase 3-4 (#87) → Phase 5 (#88).** Phase 1 sits first only because it is a
two-minute comment and costs nothing.

* **#85 blocks releases.** A red `integration` reddens `ci-ok`, and `ci-ok` gates merge. Two of four
  runs on identical code were red. This repo has already published on red CI once (#52), and the
  standing hardening work exists to make a red gate mean something — a 50% flake trains everyone to
  reach for re-run before investigate, which is exactly how a real failure gets waved through.
* **#87 ask 2 is a live fail-open gap.** `seam-adapters` re-derives the three-state read today and
  documents its reasoning in its own repo, which is the same duplication argument that put
  `collective_outcome_of` here. A consumer that gets it wrong reads an unanswered question as an
  attestation.
* **#88 is blindness on a contract nobody is currently changing.** Real, but the failure mode is
  "a future additive field lands unseen", not "something is wrong now". Also the cheapest of the
  three, because both extractors already agree.

---

## Phases

---

### Phase 1 — Record the evidence on #87 and re-scope it to ask 2

**Status:** TODO

**Delivers:** #87's ask 1 is closed out with citable evidence and the issue is re-scoped to ask 2, so
the next reader is not re-deriving a released fact. **#87 stays OPEN.**

**Depends on:** nothing.

**Files:** none in the repo. One GitHub comment on `zer07labs/seam-sdk#87`.

**Approach:**

Comment on #87 with the measured evidence, then edit nothing else:

* `v0.7.70` carried `collective_outcome_of(resp: "pb.DecisionResponse")` and
  `collectiveOutcomeOf(resp: DecisionResponse)`; `v0.7.71` carries the `DecisionResponse | SessionStep`
  union in both languages. Reproduce with `git show v0.7.70:...` and `git show v0.7.71:...`.
* Publish run 33479578480 succeeded on `python wheel → Cloudsmith`, `npm → Cloudsmith`, and `install
  from Cloudsmith and run the vectors`. State plainly that `seam-verify → Cloudsmith` was **skipped**
  — the claim is about the jobs that carry the artefact, and overstating it is how the next reader
  gets misled.
* `0.7.71` is inside `seam-adapters`' `seam-sdk>=0.7.20,<0.8` range, so the documented debt retires
  with no downstream code change.
* Ask 2 remains open and is Phases 3-4.

Rejected: closing #87. Ask 2 is untouched and is the larger half.
Rejected: doing this inside a code PR. It is a bookkeeping act with no diff; folding it into a PR
makes both harder to review and delays the record behind CI.

**Edge cases & failure modes:**
* The comment must not assert that `seam-adapters` has retired the debt — that is their call to make
  in their repo, and this plan writes nothing there.
* Do not re-state the presence rule from the proto comment. seam-runtime#526 proves it wrong.

**Acceptance criteria:**
1. `gh issue view 87 --json comments` shows the comment; `state` is still `OPEN`.
2. The comment names `v0.7.70` and `v0.7.71` and run `33479578480`, and explicitly records the
   skipped `seam-verify` job.
3. No file in the repo changed **by this phase**: `git diff --stat` against the phase's start commit
   is empty.
   *Not* `git status --porcelain` is empty — the working tree already carries this plan file and the
   appended `PROGRESS.md` section, so that form is false before the phase starts and would be
   waved away rather than met.
   *Red-first:* criterion 1 is false before the comment exists — verified by running
   `gh issue view 87` at plan time and observing `comments: 0`.

**Tests:** none. There is no code.

**Docs:** none. The issue is the record.

---

### Phase 2 — One live-server helper, ephemeral ports, waited teardown, captured logs

**Status:** TODO

**Delivers:** the mechanism behind #85 is removed, not mitigated. A single helper owns port
allocation, readiness, teardown and log capture; all four Python live suites use it; and the shape
cannot return, because a guard test refuses a hardcoded port or a discarded log in a live fixture.
CI keeps the evidence when the suite fails, which is #85's explicit ask.

**Depends on:** nothing. Ranked first among code phases: it is the only one whose absence blocks a
release.

**Files:**
- `python/tests/live_server.py` — new. The helper.
- `python/tests/test_live_server_helper.py` — new. Hermetic red-first proofs, no `seam-grpc`.
- `python/tests/test_live_fixtures_are_isolated.py` — new. The structural guard.
- `python/tests/test_integration.py` — `server`, `dual_plane`, `governed_server` adopt the helper.
- `python/tests/test_streamed_decode.py` — `dual_plane` adopts the helper.
- `python/tests/test_admin.py` — `_spawn`/`_free_port`/`_wait` replaced by the helper.
- `python/tests/test_verify_attestation.py` — same.
- `.github/workflows/ci.yml` — smoke step waits; both live steps print and upload the logs on failure.
- `PROGRESS.md` — phase log entry.

**Approach:**

**The helper (`python/tests/live_server.py`).** `tests/` is already importable from tests
(`test_integration.py:221` does `from operator_token import sign_snapshot`), so a plain module needs
no packaging. It exposes one context manager:

```
spawn_server(*, mgmt=False, env_extra=None, log_dir=None) -> LiveServer
```

with four properties, each independently red today:

1. **Ephemeral ports, allocated per spawn.** Reuse the existing `_free_port()` body
   (`test_admin.py:175-181`) as the single copy. No fixed port survives anywhere in `python/tests/`.
2. **Readiness proves the port is *ours*.** Before spawning, assert the chosen port is **not**
   connectable; after spawning, poll `proc.poll() is None` on every iteration so a child that died
   fails immediately, naming the child's own captured log, instead of timing out on
   `"server never came up"`. Ephemeral allocation makes the pre-check nearly free.
   *Rejected:* resolving the listening socket's owning pid via `/proc/net/tcp` or `lsof`. It is
   platform-split between the Linux runner and macOS dev machines, and adds a second failure mode to
   a helper whose job is to remove one. The pre-check plus the liveness poll closes the observed hole;
   if a future failure needs pid attribution, add it then with a reproduction in hand.
3. **Teardown waits, with escalation.** `terminate()` → `wait(timeout=T)` → on `TimeoutExpired`,
   `kill()` → `wait()`. Both planes are served with tonic `serve_with_shutdown`, so SIGTERM starts a
   *graceful drain* rather than an immediate exit, and one of these very suites holds a
   `StreamEvents follow=true` tail open (`test_admin.py::test_stream_events_drains_decision_sealed`).
   A bare `wait()` can therefore block for the runtime's whole grace window.
   *Rejected:* an unbounded `wait()` — turns a leak into a hang.
   *Rejected:* `kill()` outright — it would work, but it discards the drain the runtime implements on
   purpose, and the escalating form costs three lines.
   **Do not encode the runtime's grace-window constant.** Pick `T` from this repo's own needs
   (a few seconds) and say in the comment that it is a bound, not a mirror of an upstream value.
4. **Server output is captured, never discarded.** Replace `stdout=DEVNULL, stderr=DEVNULL` with a
   per-spawn file under `log_dir` (default `tmp_path`), and print its tail from the helper's own
   failure paths. This is #85's "What would actually diagnose it", made structural rather than a CI
   afterthought.

**Adoption.** All three `test_integration.py` fixtures, `test_streamed_decode.py`'s `dual_plane`, and
`test_admin.py`/`test_verify_attestation.py` (which already allocate ephemeral ports but still bare-
`terminate()` and still `DEVNULL`) route through the helper. That is **9** teardown sites and 4
duplicate `_wait` copies collapsing to one.

**CI (`.github/workflows/ci.yml`).**
* Smoke step (`:281-299`): after `kill "$pid"`, wait for it, bounded, escalating to `kill -9`. Once
  the suites use ephemeral ports the smoke step's 8099 is harmless, but a step that leaves a process
  it started is wrong on its own terms.
* `python live round-trip + management plane` (`:322-333`) and `typescript live round-trip`
  (`:334-340`): `if: failure()` steps that `cat /tmp/seam-grpc.log` and any per-test logs, plus
  `actions/upload-artifact` so a flake that does not reproduce still leaves evidence. Neither changes
  what the job asserts.

*Rejected:* pointing the suites at one long-lived server over `SEAM_GRPC_ADDR`. `ci.yml:220-222`
already records why — the tests assume a fresh server per fixture and a shared one fails with
`duplicate SessionStart for an already-open session`, and `test_admin.py` needs its own management
listener.
*Rejected:* leaving `test_admin.py`/`test_verify_attestation.py` alone because they already use
`_free_port()`. They still bare-`terminate()` and still `DEVNULL`; fixing three files and calling the
class closed is how a fourth instance ships.
*Rejected:* a retry decorator on the flaky tests. That is the "re-run before investigate" reflex the
issue exists to stop, encoded in the suite.

**Edge cases & failure modes:**
* `_free_port()` has its own TOCTOU window: it binds ephemeral, closes, hands the number to a
  subprocess. Materially smaller than a fixed port shared by four tests, and the same trade
  `test_admin.py` already accepts. **Say so in the helper's docstring** rather than implying the race
  is gone. If it ever bites, the answer is passing a pre-bound fd, not a wider retry.
* `governed_server` needs `sign_snapshot` before spawn; the helper must accept `env_extra` rather
  than assuming a fixed env.
* `dual_plane` needs two ports; the helper must allocate both from one call so a caller cannot
  half-adopt it.
* `SEAM_GRPC_ADDR` short-circuits `test_integration.py`'s `server` fixture (`:39-42`). Keep that arm
  — it is the documented "point at a running server" path — but route the *spawning* arm through the
  helper.
* The guard test must have an anti-vacuity floor: assert it actually found four live files and at
  least one fixture in each, or a renamed file makes it pass by finding nothing.

**Acceptance criteria:**

1. Over the **four live files only** — `python/tests/test_integration.py`,
   `test_streamed_decode.py`, `test_admin.py`, `test_verify_attestation.py`, plus the new
   `live_server.py` —
   `python/.venv/bin/pytest -q python/tests/test_live_fixtures_are_isolated.py` is green, and every
   remaining match of `grep -rnE '\b(80|81|82)[0-9][0-9]\b' <those five files>` is inside a
   **docstring**. Paste both outputs into the PR.
   *Red-first, measured at `960cf81`:* the grep returned
   `test_integration.py:4` (8090, the docstring example — rewritten by this phase's Docs item),
   `:48` (8099), `:63` (`_wait(8099)`), `:143` (`= 8115, 8116`), `:226` (8115), `:243` (`_wait(8115)`),
   and `test_streamed_decode.py:259` (`= 8113, 8114`). At the phase's end it returns six matches, all
   prose: `test_integration.py:113`, `test_streamed_decode.py:243`, and `live_server.py:13`/`:14`/
   `:28`/`:29` — the records of what was fixed.

   > **This criterion was ALSO broken, and by its own argument.** As first written it demanded the
   > grep return **nothing** — over files whose module docstrings deliberately name the old ports so
   > the history stays with the code. It could not go green without deleting the explanation, which
   > is the third time in this plan a criterion has been satisfiable only by damaging what it
   > measures. Caught by an independent verifier *after* Phase 2 shipped, not before. The fix is to
   > let the machine-checkable half be the AST guard — which exempts docstrings by identity — and to
   > let the grep be evidence a human reads, not a gate.

   > **The first draft's version of this criterion was broken in both directions, and it is the kind
   > of break that ships.** It read `grep -rnE ':(80|81|82)[0-9][0-9]' python/tests/` returns
   > **nothing**, with a red-first list naming `:143` and `test_streamed_decode.py:259`.
   > * **It can never return nothing.** `python/tests/test_compatibility_citations_resolve.py`
   >   contains `127.0.0.1:8099` and `192.168.1.10:8080` at `:103`, `:386`, `:396`, `:397` — as
   >   *test data* for the "an IP and port is not a citation" rule. They must not be deleted, so the
   >   criterion is unsatisfiable and would have been "fixed" by relaxing it after the work was done.
   > * **It misses the actual defect.** The colon-anchored pattern does not match a bare integer, so
   >   `_wait(8099)`, `= 8115, 8116` and `= 8113, 8114` — three of the four things this phase exists
   >   to delete, including both of the ones the draft claimed it returned — never appear in its
   >   output. Verified by running it.
   >
   > A criterion that cannot go green and does not see the defect is worse than no criterion: it
   > trains the next reader to negotiate with the check rather than the code.
2. `test_live_server_helper.py::test_readiness_refuses_a_listener_the_spawned_process_never_bound`
   binds a decoy listener in-process, spawns a "binary" that exits 0 immediately, and asserts the
   helper **raises**. *Red-first, already reproduced at plan time against today's code:*
   `_wait returned in 0.002s ... spawned proc exit code: 0`. Paste that transcript into the PR.
3. `test_live_server_helper.py::test_teardown_leaves_no_process_and_frees_the_port` spawns a fake
   binary that installs a SIGTERM handler and keeps its listener open, exits the context, and asserts
   `proc.poll() is not None` **and** the port immediately re-binds. *Red-first:* today's
   `proc.terminate()` returns with the process alive and the port held; the fake binary makes that
   deterministic rather than timing-dependent.
4. `test_live_server_helper.py::test_two_consecutive_spawns_never_share_a_port` asserts distinct
   ports across two sequential spawns. *Red-first:* trivially false for any fixed-port fixture.
5. `test_live_fixtures_are_isolated.py` fails if any live fixture hardcodes a port or passes
   `DEVNULL`, and carries a floor asserting it inspected all four files.
   *Red-first:* run it against `HEAD` — it must report all four offending files by name.
6. `.github/workflows/ci.yml`'s smoke step waits for the process it started, and both live steps
   carry an `if: failure()` log dump plus an artifact upload.
   *Red-first:* `yq`/`grep` the workflow at `HEAD` and show the `wait` and the `if: failure()` steps
   are absent. **Do not** write a criterion of the shape "the log appears on failure" without also
   showing the step is absent beforehand — that is the vacuous-criterion failure recorded in
   `plans/gate-blindness-hardening.md`.
7. `cd python && .venv/bin/pytest -q` green from the **754 passed / 17 skipped** baseline, with
   **17 skipped unchanged** — a *rise* in the skip count is what this criterion really guards, since a
   live file that starts self-skipping reads as green. Report the delta as two numbers (new test
   functions, new `PROGRESS.md` citations), not one total. Full suite, never a subset.
8. `ci-ok`'s `needs:` is unchanged and `ADVISORY` is unchanged.
   `python -m pytest scripts/test_ci_gate.py -q` green.

**On what these criteria do and do not prove — stated plainly, because a flake invites overclaiming.**
None of them proves the CI symptom is gone; N green re-runs would not either, and a phase that offers
re-runs as acceptance is not acceptable. What they prove is: the mechanism exists (2, 3), it is
removed (1, 4), it cannot return (5), and the next occurrence names itself instead of being destroyed
(6). If #85 recurs after this, the uploaded log is the artefact that makes the *next* diagnosis real
rather than another guess — which is the honest end state for a flake.

**Tests:** the three helper tests and the guard test above. Every one constructs its own state — a
decoy socket it binds, a fake binary it writes into `tmp_path`, a port it allocated — and none reads
`SEAM_GRPC_BIN`, so all four run in the ordinary `python` job, not only in `integration`. That is
deliberate: the tests that prove the fix must not themselves be gated on the lane that was flaky.

**Docs:** `python/tests/live_server.py`'s module docstring records the failure this exists for — the
measured collection order, the shared-8099 set minus the first, and why `_wait` returning against a
stranger is the actual defect — so the next person reading it does not re-derive it from a closed
issue. Update `python/tests/test_integration.py`'s module docstring, which still describes a
per-file `_wait`/spawn convention that will no longer exist.

---

### Phase 3 — `policy_enforcement_of` in Python

**Status:** **DONE.** Implemented as designed. Two divergences from the text: criterion 6's baseline
was stale (754 at planning time, 791 at the branch point — corrected below), and the absence list in
the Approach borrowed the proto comment's four-verb parenthetical, which #526's matrix shows is not
exhaustive. The red-first sequence the criteria ask for was run in full: the naive
`return PolicyEnforcement(...)` form fails every absence assertion and passes every other criterion,
which is the one-line inversion made visible.

**Delivers:** `seam_sdk.policy_enforcement_of(resp) -> Optional[PolicyEnforcement]`, on a
`DecisionResponse` **or** a `SessionStep`, returning `None` **iff** the field is absent and never a
false-y instance. One documented place for the three-state read that consumers get wrong in the
fail-open direction.

**Depends on:** nothing. Independently mergeable; ordered after Phase 2 because Phase 2 is the one
blocking releases.

**Files:**
- `python/seam_sdk/_policy.py` — new.
- `python/seam_sdk/__init__.py` — import at `:10`'s block, two `__all__` entries near `:80-81`.
- `python/tests/test_policy_enforcement.py` — new.
- `PROGRESS.md` — repo-map rows + phase log.

**Approach:**

A **new module**, mirroring `_collective.py`'s structure exactly:

```
@dataclass(frozen=True)
class PolicyEnforcement:
    enforced: bool
    policy_id: Optional[str]        # None iff the field is absent, never "" for absent

def policy_enforcement_of(
    resp: Union["pb.DecisionResponse", "pb.SessionStep"],
) -> Optional[PolicyEnforcement]:
```

*Rejected:* adding it to `_collective.py`. That module's docstring (`:1-30`) is entirely about the
growth policy and fail-closed verdict decoding; `policy_enforcement` has no enum and no growth
policy. Folding it in would make the module's own documentation false — which is the failure #88
exists to prevent, one file over.

*Rejected:* returning `pb.PolicyEnforcement` directly. It is the very type whose default instance is
the trap; handing it back re-exposes the `enforced=False` ambiguity to the caller and gives the
docstring nowhere to live. `_collective.py:52` made the same call for the same reason.

*Rejected:* a new `errors.py` symbol. There is no enum and nothing to fail closed on, and
`python/tests/test_errors_is_import_light.py` makes any addition there a deliberate act.

**`policy_id` is `None` when absent.** `PolicyEnforcement.policy_id` has explicit presence: unset
gives `HasField == False` and `''`; explicitly-encoded empty gives `True` and `''`. Mapping both to
`""` reintroduces the outer bug one level down. Map absent to `None`.

**The docstring must state the presence rule from seam-runtime#526's measured matrix**, not from the
proto comment, and must say why: field 3's comment claims "populated only on a step that resolves the
session via commit", and #526 measures three sites. It must also say that `decision_id` present does
**not** imply `policy_enforcement` present — the expiry seal is the counterexample — since the proto
comment's `decision_id` analogy points a reader at the opposite of the truth. **Enumerate the three
sites; do not generalise** (see the Context section's source-discipline note). Cite the issue, not the
Rust: `PROGRESS.md`'s clean-room constraint forbids reading `../seam-runtime/crates/**`, and #526
publishes the matrix in its own body.

**Edge cases & failure modes:**
* `DecisionResponse` and `SessionStep` both have `has_presence=True` on this field, so one `HasField`
  gate covers both message types — verified against the descriptors, not assumed.
* `enforced` has **no** presence (plain `bool`), so it is read directly. Do not add a `HasField` on it.
* A `@property allowed`-style boolean must **not** be added. `_collective.py:73-81` deliberately
  exposes only a positive `approved` and no `declined` twin, "because `not approved` must stay the
  safe reading". Here `enforced` is already the boolean and `None` is already the unsafe-to-guess
  case; a second boolean is a truthiness that can go the wrong way.
* `python/seam_sdk/__init__.py:10`'s import block and `__all__` must both be updated. A module
  exported from one and not the other is the kind of half-adoption `test_packaging.py` exists over.

**Acceptance criteria:**
1. `policy_enforcement_of(pb.SessionStep(state="Proposed"))` is `None` — **identically `None`**, not
   an instance whose `enforced` happens to be `False`.
   *Red-first:* the function does not exist; `AttributeError` on import. Then, before wiring the
   `HasField` gate, implement the naive `return PolicyEnforcement(...)` form and watch this
   criterion fail while every other one passes. That is the one-line inversion this phase exists to
   prevent, and seeing it red is worth the two minutes.
2. `policy_enforcement_of(pb.SessionStep(state="Resolved",
   policy_enforcement=pb.PolicyEnforcement(enforced=False)))` is **not** `None` and has
   `enforced is False`. Criteria 1 and 2 together are the whole phase: the same `enforced=False`
   value, two different return values.
3. `policy_enforcement_of(pb.PolicyEnforcement(enforced=True, policy_id="p-1"))`-carrying responses
   round-trip `policy_id == "p-1"`; with `enforced=True` and no `policy_id`, `policy_id is None`;
   with an explicitly-encoded `policy_id=""`, `policy_id == ""`.
4. A `DecisionResponse` and a `SessionStep` carrying byte-identical `policy_enforcement` decode to
   equal `PolicyEnforcement` values — one decoder, two message types.
5. `from seam_sdk import PolicyEnforcement, policy_enforcement_of` works, and both are in `__all__`.
6. `cd python && .venv/bin/pytest -q` green from the branch-point baseline, skips still 17.
   *(That baseline was written as 754 when this plan was drafted. Phase 2 shipped first and moved it
   to **791 passed / 17 skipped** at `978d05d`; the criterion is against the branch point, not
   against a number frozen at planning time.)* Report new test functions and new `PROGRESS.md` citations as two numbers.

**Tests:** `python/tests/test_policy_enforcement.py`, modelled on
`python/tests/test_collective_outcome.py` (which runs the `SessionStep` arm at `:208-262`). Every
message is **constructed in the test** — no fixture reads a stub tree, no test depends on the ambient
generated surface beyond the two message classes it instantiates. Cases: absent → `None`;
present+`enforced=False` → an instance; the two are distinguishable while
`resp.policy_enforcement` compares equal across them; `policy_id` absent → `None`; `policy_id`
explicitly empty → `""`; `enforced=True` with an id; both message types agree; a non-commit
`SessionStep` behaves exactly like an absent field.

**Docs:** the module docstring is the deliverable — it is the "one place that documents the three
states" #87 asks for. Add the `python/seam_sdk/_policy.py` row to `PROGRESS.md`'s repo map.

---

### Phase 4 — `policyEnforcementOf` in TypeScript, and the citations it necessarily moves

**Status:** TODO

**Delivers:** the TS twin, keeping the two client layers symmetric on both consumer decoders.

**Depends on:** Phase 3 — same PR, so the two languages land together and neither can be the
odd one out. `collective_outcome_of` shipped Python-only once and the TS half had to follow later;
that is the asymmetry this ordering avoids.

**Files:**
- `ts/src/client.ts` — `interface PolicyEnforcement` + `export function policyEnforcementOf`,
  inserted **immediately after** `collectiveOutcomeOf` (which ends at `:239`).
- `ts/tests/policy_enforcement.test.ts` — new.
- `ts/src/index.ts` — the shadowed-generated-names comment.
- `PROGRESS.md` — **repointed** `ts/src/client.ts` citations.

**Approach:**

protobuf-es models a singular message field as `T | undefined`
(`policyEnforcement?: PolicyEnforcement | undefined`), so presence is native and the decoder is a
straight `if (pe === undefined) return undefined;`. That does **not** make the helper unnecessary:
the docstring is the deliverable, `policyId` is `string | undefined` with the same absent-vs-empty
distinction, and a consumer reading `resp.policyEnforcement?.enforced` gets `undefined` for both
"absent" and "no field", collapsing exactly the states this exists to keep apart.

**Placement is load-bearing, not stylistic.** `PROGRESS.md:66` cites `ts/src/client.ts:218` for
`collectiveOutcomeOf` and `:69` cites `:676` for `submitCommit`, and **both are `ANCHORED` needles**
(`python/tests/test_compatibility_citations_resolve.py:606-607`, `CITATION_SLACK = 3` at `:612`).
Verified at `HEAD`: `export function collectiveOutcomeOf` is at `ts/src/client.ts:218`, the function
ends at `:239`, and `  submitCommit(` occurs exactly once, at `:676`. Inserting after `:239` keeps
`:218` correct. It will not keep `:676` correct: a documented decoder is far more than 3 lines. So:

* Insert after `collectiveOutcomeOf`, never before it.
* In the **same commit**, repoint every `ts/src/client.ts` citation in `PROGRESS.md` —
  `:66` (`:218`, unchanged but re-verified), `:69` (`:676`), `:71` (`:601,637`), `:72` (`:623`) and
  `:637` (`:804`) — by re-measuring each with `grep -n`, never by adding the delta by hand.
  **Three of those five are not test-enforced, so the suite cannot catch a missed repoint:**
  `:71`'s `` `ts/src/client.ts:601,637` `` does not match `CITATION`
  (`test_compatibility_citations_resolve.py:109` requires the closing backtick immediately after the
  number, so a comma-list matches *nothing* — the same for `client.py:473,514` on that row), and
  `:72` (`:623`) / `:637` (`:804`) are non-anchored, where `test_each_citation_resolves`
  (`:447-461`) only asserts `end <= line_count`. Re-measure all five by hand; do not bank criterion 5's
  green as proof they are right.
* Run the **full** Python suite after the markdown edit, never a subset.

*Rejected:* widening `CITATION_SLACK`. Issue #73 ruled that out, and slack that survives an
insertion is slack that no longer checks anything.
*Rejected:* a separate `ts/src/_policy.ts`. TS keeps `collectiveOutcomeOf` in `client.ts` and
`ts/src/index.ts:7` re-exports the module wholesale; a new file would need its own export line and
would break the mirror with the Python module split for no gain. The languages are already
asymmetric in *file layout* and symmetric in *surface*; keep it that way.

**Edge cases & failure modes:**
* `export interface PolicyEnforcement` **shadows** the generated `pb.PolicyEnforcement`.
  `ts/src/index.ts:18-22` opens with the literal word **"Two"** and then lists three names
  (`pb.Commitment`, `pb.BudgetLimits`, `pb.StepUsage` — the last two counted as one group). Adding
  `PolicyEnforcement` means updating **the count word as well as the list**; appending a name and
  leaving "Two" in place turns a true comment into a false one, which is the failure mode this whole
  plan is about. Note in passing that `CollectiveOutcome` is
  *already* shadowed and already absent from that list; **do not fix that here** (it is out of
  scope), but record it in Open Questions so it is not lost.
* `policyId` maps absent → `undefined`, explicit-empty → `""`, mirroring Python's `None`/`""`.
* protobuf-es `create(SessionStepSchema, {})` leaves `policyEnforcement` `undefined`; a test must
  construct the present-but-`enforced:false` case with an explicit
  `create(PolicyEnforcementSchema, { enforced: false })` or it proves nothing.
* `ts/src/index.ts` does not currently export `PolicyEnforcementSchema`. If the test needs it, it is
  reachable via `pb.PolicyEnforcementSchema`; decide whether to promote it to a named export and say
  which, rather than adding it silently.

**Acceptance criteria:**
1. `policyEnforcementOf(create(SessionStepSchema, { state: "Proposed" }))` is `undefined`.
2. `policyEnforcementOf(create(SessionStepSchema, { state: "Resolved",
   policyEnforcement: create(PolicyEnforcementSchema, { enforced: false }) }))` is **defined** with
   `enforced === false`. As in Phase 3, 1 and 2 together are the phase.
   *Red-first for both:* the symbol does not exist — `tsc --noEmit` fails on the import.
3. `policyId` is `undefined` when absent and `""` when explicitly empty.
4. `npm run typecheck` and `npm test` are green in `ts/`.
5. **`cd python && .venv/bin/pytest -q` is green** — this is the criterion that catches the citation
   drift, and it is in the *TypeScript* phase on purpose.
   *Red-first:* make the `client.ts` insertion, run the full Python suite **before** touching
   `PROGRESS.md`, and confirm the `ANCHORED` case for
   `PROGRESS.md` → `ts/src/client.ts` → `  submitCommit(`
   **fails**.

   > **The re-verification pass worked the arithmetic out, and there are *two* ways this criterion
   > can be vacuous, not one.** `_citations("PROGRESS.md")` yields `ts/src/client.ts` at
   > **218, 623, 676, 804** (the `:601,637` row matches nothing — see Approach). The check is
   > `any(start - 3 <= true_line <= end + 3)` over *all* of them, so with `  submitCommit(` moving
   > from 676 to 676+K the case goes **red for 4 ≤ K ≤ 124 and for K ≥ 132**, and **green for
   > K ∈ [125,131]** — where 676+K lands inside the slack window of the unrelated `:804`
   > (`resolveContext`) citation and satisfies the assertion by accident.
   >
   > So: if it does not fail, measure `K` before concluding anything.
   > * `K ≤ 3` — the insertion really was smaller than `CITATION_SLACK`. The criterion is vacuous;
   >   say so and re-derive.
   > * `125 ≤ K ≤ 131` — the criterion is vacuous **and** something is quietly wrong: the anchor is
   >   being satisfied by a foreign citation, which is exactly the "path-only matching" limitation
   >   `test_the_load_bearing_citations_still_point_at_the_right_thing`'s own docstring
   >   (`:621-647`) warns about and calls "verified by hand, because that is the property the
   >   path-only matching cannot enforce". Repoint by measurement anyway, and record the near-miss —
   >   the docstring's margin table is now wrong for `PROGRESS.md` and should be re-measured.
   >
   > A 125-131-line insertion is not far-fetched for an interface plus a full three-state TSDoc table
   > plus the function, which is why this is written down rather than dismissed.
6. `ts/src/index.ts`'s shadowed-names comment names `PolicyEnforcement` **and its count word is no
   longer "Two"** — both halves asserted, by reading `:18-22` and quoting it in the PR.
   *Why both:* "names `PolicyEnforcement`" alone is satisfied by appending a name and leaving "Two"
   in place, which is the precise defect the Edge-cases item exists to prevent. A criterion that
   passes on the half-done version of the thing it names is the vacuity this plan is written against.
   Verified at `HEAD`: `:18` reads "**Two** generated names are shadowed" and then lists three
   (`pb.Commitment`, `pb.BudgetLimits`, `pb.StepUsage`), so the count is already generous-by-grouping
   before this phase touches it — say which reading you adopt rather than inheriting the ambiguity.

**Tests:** `ts/tests/policy_enforcement.test.ts`, modelled on `ts/tests/collective_outcome.test.ts`
(`SessionStep` arm at `:175-230`), constructing every message with `create(...)`. Include the
compile-level assertion the sibling suite uses at `:175` — that a `SessionStep` is accepted as an
argument at all — since protobuf-es brands message types and a union that compiles is itself the
contract.

**Docs:** the TSDoc block on `policyEnforcementOf` carries the same three-state table and the same
seam-runtime#526 sourcing as the Python docstring, so neither language is the authoritative copy.

---

### Phase 5 — A field-surface manifest for `seam.event.v1`

**Status:** TODO

**Delivers:** `contract/event-field-manifest.txt` declares all 90 `seam.event.v1` message fields, set-
compared per language in both directions by `scripts/check-contract.sh`, with a `--write-manifest`
escape and a structural tripwire for the preconditions the extractors assume. A field added, removed
or renamed anywhere on `seam.event.v1` reddens CI instead of landing silently.

**Depends on:** nothing. Last because it is the lowest-consequence of the three: nobody is currently
changing this contract.

**Files:**
- `scripts/check-contract.sh` — parameterise the extractors; add the event probe, the event
  precondition tripwire, the `--write-manifest` arm, three env overrides, one exit code; **update the
  `:583-594` comment**.
- `contract/event-field-manifest.txt` — new, with a full header.
- `python/tests/test_event_field_manifest_gate.py` — new.
- `python/tests/test_field_manifest_gate.py` — **added by the re-verification pass, and it is not
  optional.** Its `_run()` (`:54-95`) sets `SEAM_FIELD_MANIFEST` and `SEAM_RPC_MANIFEST` but nothing
  else, and the `manifests` (`:97-109`) and `enum_manifests` (`:126-136`) fixtures call the real
  script with `--write-manifest` — four call sites in all (`:106`, `:134`, `:220`, `:343`). The moment
  `--write-manifest` also writes the event manifest, **an ordinary `pytest` run rewrites the committed
  `contract/event-field-manifest.txt`**. That is verbatim the hazard the `manifests` docstring
  (`:101-102`) already names for the RPC manifest — "otherwise running this suite would rewrite the
  repo's real `contract/rpc-manifest.txt` as a side effect of testing fields". Teach `_run()`
  `SEAM_EVENT_FIELD_MANIFEST` (defaulting to a scratch path beside `field_manifest`, exactly as it
  already does for `SEAM_EXPECTED_LOCAL_LAG` at `:82-87`) **in the same commit that adds the write
  arm**, never after.
- `Makefile` — the exit-code comment under `check-contract`. Note it is **already stale**: `:36-38`
  lists 0-4 only, so 5, 6 and 7 must land alongside 8. Adding 8 to a list that stops at 4 would ship a
  comment that is more wrong than the one it replaced.
- `PROGRESS.md` — repo-map row + phase log.

**Approach:**

**Parameterise, do not duplicate.** `fields_python` (`:203-213`) and `fields_ts` (`:218-238`) hardcode
`$PY_GEN`/`$TS_GEN` and `seam\.api\.v1`. Take the stub path and the package as arguments; the api call
sites pass what they pass today. Verified for this plan: with only those two substitutions, the
extractors yield **90 and 90**, with **zero** one-sided entries. A second pair of extractors would be
a second place for the nesting and keyword-name bugs those two already solved
(`contract/field-manifest.txt`'s header records both at length).

**A SEPARATE file, `contract/event-field-manifest.txt`.** Three reasons drawn from the code, not
preference:

1. **The single-file option does not survive the existing strippers.** `manifest_fields` (`:241`) is
   `grep -vE '^\s*(#|$)' | grep -v '#'` — it claims **every** non-comment line without a `#`. An event
   line such as `SeamEvent/session_lifecycle` carries no `#`, so it would land in the api field set and
   be reported MISSING from `$PY_GEN`. `manifest_enums` (`:398`) claims the complement.
   The operative point is that `manifest_fields`' filter is **negative**: it is
   "everything that is not an enum line", not "everything that looks like a field line". So a third
   partition is unreachable *whatever* delimiter it picks — `%`, `@`, `!` are all free in a proto
   identifier, and all of them still land in `manifest_fields`' set. Sharing the file therefore means
   rewriting `manifest_fields` from a negative filter to a positive one, which is a change to the api
   gate made for the event gate's benefit.
   *(The first draft argued "there is no unambiguous character left". That premise is false — plenty
   of characters cannot occur in a proto identifier. The conclusion survives for the reason above, and
   is restated so nobody retires it by finding the counterexample to the premise.)*
2. **`--write-manifest` deletes the recorded lag.** `:472-476` removes `$EXPECTED_LOCAL_LAG` whenever
   `$FIELD_MANIFEST` is rewritten. The api surface has a real 228-vs-223 lag; the event surface has
   **none** (90/90/90, measured). One file means every event rewrite destroys the api lag recording
   and every api rewrite invalidates an event manifest that never lagged.
3. **#88 asks for it, and the comment at `:591-594` already says it.** "Closing it needs its own
   manifest ... not a widening of this one." A single file would blur which contract a failure reports
   against, which is the issue's stated objection.

*Rejected:* one file with a `seam.event.v1/` line prefix. Still `#`-free, so `manifest_fields` still
claims it; it trades an unambiguous file boundary for a convention the stripper cannot see.

**A new exit code 8** for an event-field-surface disagreement, added to the header table at `:58-64`
and to `Makefile`'s comment. Verified: nothing in the repo uses exit 8 today, and the only consumers
of this script's specific exit codes are `python/tests/test_field_manifest_gate.py` (which asserts
0, 6, 7 and `!= 7`) and `Makefile:39-40` (which only propagates). Reusing 6 would make the two
contracts indistinguishable at the exit code, and the whole point of that table is that the number
names the failure.
*Rejected:* reusing 6 — see above.

**Where the event probe sits in the flow — the thing the first draft left unsaid, and the one that
decides whether this phase gates anything locally.** `scripts/check-contract.sh` ends at `:857` with
`exit 6` inside the combined field/enum block, and `:860` is the last line of the file. On **every**
local checkout the api field surface disagrees (the recorded ACDP lag), so `exit 6` at `:857` always
fires. That gives two wrong placements and one right one:

* **After the field/enum block** — the event probe never executes locally. `make check-contract` on a
  dev machine would gate nothing on `seam.event.v1`, forever, while looking exactly like it does.
* **Before it, exiting 8 on the spot** — an event disagreement would preempt the api report, and a
  run with both problems would show one.
* **Correct: compute the event report in the same single pass**, alongside `field_surface_rc` /
  `enum_surface_rc`, print all three before any exit, and decide the code once at the end. The script
  already argues for exactly this at `:784-787` ("a script that exited on the field report first would
  never show the enum one"); the event surface is the third member of that set, not a new stage.

**Precedence, stated so it is a decision and not an accident:** when the api surface disagrees *and*
the event surface disagrees, print both and **exit 8**. Rationale: 6 is the code CI and
`CLAUDE.md`'s Gotchas already treat as "the known local lag, look at the NOTE", so an event failure
hidden behind a 6 is a failure hidden behind a message that says to ignore it. 8 is the code that
means "something here is not the known lag". Say this in the header table entry for 8, not only here.

*Rejected:* letting the recorded-lag downgrade at `:771-782` extend to the event surface. That file
(`contract/expected-local-lag.txt`) records an **api** gap; the event surface has none, and an event
manifest that acquires a lag needs its own recording (see Long-term posture), not a shared one.

**A structural tripwire, not an empty enum partition.** `seam.event.v1` has **zero** enums and **zero**
nested messages today, in both languages (re-measured for this pass: no
`EnumTypeWrapper` class and no indented `class …(_message.Message)` in the `.pyi`; no `export enum`
and no dotted `Message<"seam.event.v1.X.Y">` in the TS). An event enum partition would therefore be
empty and every comparison against it would pass vacuously — the exact defect
`plans/gate-blindness-hardening.md` records. Instead add `assert_event_surface_preconditions`
in the shape of `assert_no_nested_enums` (`:408-426`) and `assert_known_nested_messages_only`
(`:324-352`): assert **no** enums and **no** nested messages exist in either event tree, exit **7**
if one appears, with a message saying to extend the extractors deliberately before proceeding.

**Why 7 and not a ninth code — since the exit-8 argument above cuts the other way.** Exit 7's header
text (`:62-64`) names a *failure class*, "a structural precondition the extractors assume failed",
not a contract; two contracts sharing it is consistent, where two contracts sharing 6 (a
manifest disagreement) is not. Say that in the header entry, or the next reader reads the two choices
as inconsistent — the re-verification pass did. **Consequence to carry:**
`python/tests/test_field_manifest_gate.py:777-788` asserts `returncode != 7` against the real tree; it
now depends on the ambient **event** tree as well as the api one. That is acceptable only because both
preconditions are asserted, never assumed — but the test's docstring should say so, since a failure
there will now have two possible causes.

**Env overrides for the tests.** `PY_EV` (`:86`) and `TS_EV` (`:88`) are currently not overridable.
Add `SEAM_PY_EV`, `SEAM_TS_EV` and `SEAM_EVENT_FIELD_MANIFEST`, so
`python/tests/test_event_field_manifest_gate.py` can drive the **real script** against **scratch
copies** exactly as `python/tests/test_field_manifest_gate.py:54-92` does. Without these the tests
would have to mutate the gitignored event stub tree, which cannot be restored without `make generate`.

**Keep the four `STREAM`/`EVENTS` presence probes.** They now overlap the manifest but are not
redundant: they fire even when the manifest is absent or has just been rewritten, and they name the
four fields a consumer actually decodes rather than the surface as a whole. Say that in the comment
so a later reader does not delete them as duplication.

**Rewrite the `:583-594` comment.** It currently says the gap "is real, not merely undocumented" and
that closing it "needs its own manifest". Once this phase lands, that paragraph is false. Replace it
with what is now true: the event surface is manifested at `contract/event-field-manifest.txt`, the
four named probes remain as a narrower assertion, and `scripts/check_vendored_spec.py` still only
catches spec-doc drift.

**Edge cases & failure modes:**
* `--write-manifest` must write the event manifest from **Python**, as the other two do (`:433-437`),
  keeping exactly one escape and one authoritative side.
* The event manifest must **not** trigger the `$EXPECTED_LOCAL_LAG` deletion. That file records an
  *api* lag. Scope the delete to the api write.
* If Python and TS ever disagree on the event surface, that is a **generation skew**, not manifest
  drift — report it distinctly, as the enum probe already does at `:674-681`.
* The event manifest gate must not fire before the event stubs exist; the `:102-111` existence check
  already covers `$PY_EV`/`$TS_EV`, so route the overrides through the same loop.
* Every new test must construct its stubs. Asserting `exit 8` against the ambient event tree is the
  environment-dependence failure recorded in `plans/gate-blindness-hardening.md`, which
  passed locally and failed in CI.
* **The existing suite's `returncode == 0` assertions become event-sensitive.**
  `python/tests/test_field_manifest_gate.py` asserts exit 0 at `:107`, `:135`, `:211`, `:220`, `:343`,
  `:495`, `:1078`, `:1092` while overriding only the api manifests. Once an event probe runs in the
  same pass, all of those silently depend on the committed event manifest agreeing with the ambient
  event stubs. That is true today (90/90/90, no lag) and is *why* this is safe — but it is a new
  coupling between an api-gate test and the event tree, and it is exactly the "decided by the ambient
  environment" shape this plan's own rule 2 forbids. Point `SEAM_EVENT_FIELD_MANIFEST` at a scratch
  copy in `_run()` so those tests assert on state they constructed, not on the checkout they happen to
  be in.
* `PY_GRPC` (`:85`) is still not env-overridable, and `--write-manifest` refuses without it
  (`:429-431`). The event write arm inherits that; it is pre-existing and out of scope, but do not
  write a test that assumes the event arm can run without the real `_gen` tree.

**Acceptance criteria:**
1. `contract/event-field-manifest.txt` contains exactly **90** field lines spanning **11** messages,
   and **no field line contains `#`** (the file's header lines do, and must — `--write-manifest`
   preserves `^\s*(#|$)` at `:461`; the first draft's "zero `#`-bearing lines" would have forbidden
   the header this phase's own Docs item requires). Independently reproducible:
   `grep -c FIELD_NUMBER python/seam_sdk/_gen/seam/event/v1/seam_event_pb2.pyi` → 90, and
   `grep -c '@generated from field:' ts/gen/seam/event/v1/seam_event_pb.ts` → 90. Both re-measured at
   `960cf81` and both return 90.
2. Appending one field to **both** scratch event stub trees makes the script exit **8** and name
   `<Message>/<field>` for **both** languages.
   *Red-first:* before the probe exists, the same mutation exits 6 with only the api NOTE — i.e. the
   event addition is invisible. Capture that run.
3. Deleting one field from both scratch trees exits **8**, reporting it MISSING.
4. Adding a field to **one** scratch tree only produces a report that names generation skew, not
   manifest drift.
5. Adding a nested message, or any enum, to a scratch event tree exits **7** naming the precondition.
   *Red-first:* today such a mutation exits 6 with the api NOTE and the nested fields silently absent
   from both extractors — reproduce that first, as `:282-285` did for the api side.
6. **The api surface is bit-for-bit unaffected, and the event probe demonstrably ran.**
   `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` on the real tree still exits **6**, still NOTEs
   exactly the five `ContextBinding` fields, **and prints a positive event line** — e.g.
   `OK — the event field surface matches contract/event-field-manifest.txt in both languages` — so
   the criterion distinguishes "checked and clean" from "never executed".
   `git diff contract/field-manifest.txt contract/expected-local-lag.txt contract/event-field-manifest.txt`
   is empty at the end of the phase, **and after a full `pytest` run** (see the Files note on
   `test_field_manifest_gate.py`).

   > **This criterion was vacuous in the first draft and is the sharpest find of the re-verification
   > pass.** It read: still exits 6, still NOTEs the five fields, "and reports **no** event
   > discrepancy". Every clause of that is **already true at `HEAD`, verified by running it** — exit
   > 6, the five `ContextBinding` fields, no event discrepancy reported (because there is no event
   > probe), and a clean `git diff` on both contract files. It is a criterion that passes before the
   > fix exists. Worse, it is *satisfied by the failure mode*: an event probe placed after the
   > `exit 6` at `:857` never runs locally, reports nothing, and scores this criterion green. The
   > "prints a positive event line" clause is what makes it falsifiable.

7. `scripts/check-contract.sh`'s `:583-594` comment no longer claims the event surface has no
   manifest, **and names `contract/event-field-manifest.txt`**. *Red-first:*
   `grep -n 'has NO field-surface manifest' scripts/check-contract.sh` matches at `HEAD` (line 591)
   and must not match after; `grep -c 'contract/event-field-manifest.txt' scripts/check-contract.sh`
   is 0 at `HEAD` and non-zero after. The second half matters: the first is a case-sensitive grep for
   one phrase, which a rewrite to "has no field-surface manifest" would satisfy while leaving the
   claim false.

10. **Both surfaces disagreeing at once reports both.** Against scratch copies, break the api field
    surface *and* the event field surface in the same run; the output must name both and the exit code
    must be **8**. *Red-first:* trivially impossible before the probe exists. This is the criterion
    that pins the placement decision in the Approach — without it, a probe that exits 8 before the api
    report, or one that never runs because `exit 6` preceded it, both look fine.
8. `cd python && .venv/bin/pytest -q` green from the **754 passed / 17 skipped** baseline, skips
   still 17. Report new test functions and new `PROGRESS.md` citations as two numbers.
9. `ci-ok`'s `needs:` and `ADVISORY` unchanged; `python -m pytest scripts/test_ci_gate.py -q` green.

**Tests:** `python/tests/test_event_field_manifest_gate.py`, mirroring
`python/tests/test_field_manifest_gate.py` down to the `_run()`/`manifests` fixture shape
(`:54-110`). Every case copies the event stubs into `tmp_path`, mutates the copy, and points
`SEAM_PY_EV`/`SEAM_TS_EV`/`SEAM_EVENT_FIELD_MANIFEST` at it. Plus an anti-vacuity floor asserting the
committed manifest is non-empty and names all 11 messages — without it, a manifest emptied by a bad
write would make every comparison pass.

**Docs:** `contract/event-field-manifest.txt`'s header, in the shape of
`contract/field-manifest.txt`'s: what it covers, why `seam.event.v1` gets its own file rather than a
partition (the three reasons above), that `--write-manifest` writes from Python, that exit 8 is
distinct from 6 and why, and that zero enums / zero nested messages is asserted rather than assumed.
Update `Makefile`'s exit-code comment and `plans/README.md`'s Active table with a row for this plan
(which today has none — `gate-blindness-hardening.md` is also missing one; adding it is out of scope,
but note it).

---

## Long-term posture

* **The event manifest starts with no lag, and that is a state to protect.** `contract/expected-local-lag.txt`
  exists because the api manifest ran ahead of the BSR. If the event surface ever acquires the same
  gap, the answer is a *second* recorded-lag file scoped to it, never widening the api one — the two
  contracts have different owners and different publish cadences.
* **`policy_enforcement_of` and `collective_outcome_of` are now a pair, and they are not the last.**
  Anything the runtime adds with explicit presence over a message-typed field has this shape. Consider
  a short §"presence-decoding" note in `DECISIONS.md` recording the rule once — absent is `None`, a
  zero-valued instance is evidence, and the two are never normalised — so the third one is a lookup
  rather than a re-derivation.
* **The Python live suite converges on the TypeScript suite's discipline.** After Phase 2 both
  languages guarantee per-test port isolation. The remaining asymmetry is that TS hand-assigns fixed
  distinct ports while Python allocates ephemeral ones; TS's approach breaks the moment two files
  pick the same literal, which nothing currently checks. A future `ts/tests` guard mirroring
  `test_live_fixtures_are_isolated.py` would close it. Out of scope here; #85 is a Python failure.
* **`ADVISORY` should stay at two entries.** `scripts/test_ci_gate.py` asserts the list stays minimal.
  Nothing in this plan touches it, and the temptation to make a flaky lane advisory-and-tolerated is
  exactly what Phase 2 removes the need for.

## Enterprise concerns

* **Fail-open is the enterprise stake in Phase 3.** A consumer that cannot separate "no policy was
  bound" from "this response did not say" cannot answer, at audit time, whether a commitment was
  policy-gated. `seam-adapters` already carries absent as `None` and refuses to normalise; putting
  that in the shared decoder means one auditable implementation instead of one per consumer.
* **A gate red half the time is worse than no gate.** #85's own framing, and the reason Phase 2 is
  ranked first. This repo has published on red CI once (#52). The cost of a flake is not the lost
  minutes; it is that "re-run" becomes the first response to red.
* **Contract-surface blindness is a supply-chain property.** `seam.event.v1` is the outbox contract
  connectors and verifiers consume. A field added there today reaches consumers through this SDK with
  every gate green. Phase 5 makes that a refusal, which is the same argument that produced
  `contract/rpc-manifest.txt` and then `contract/field-manifest.txt` one level down.
* **Diagnostic retention.** Phase 2's artifact upload means an intermittent runtime failure leaves
  evidence that survives a re-run. Today the log exists only until the next attempt overwrites it —
  a self-erasing audit trail on the one lane that talks to a real server.

## Open questions

1. **Should `PolicyEnforcement` be re-exported from `ts/src/index.ts`'s named type list?**
   `CollectiveOutcome` is shadowed today and appears in neither the named export list (`:25-39`) nor
   the shadowed-names comment (`:18-22`). Phase 4 adds `PolicyEnforcement` to the comment; whether
   both should also be named exports is a public-surface call that should be made deliberately, not
   inherited from the existing inconsistency. **Not fixed in this plan.**
2. **Does the runtime intend to surface `freshly_sealed`?** seam-runtime#526 closes by noting that a
   client cannot tell whether *this* call performed the seal or re-reported one, and that the
   `policy_enforcement`/`collective_outcome` pair does not answer it in either direction. If it lands,
   `policy_enforcement_of`'s docstring is the first thing that goes stale. Watch #526; do not
   speculate in the docstring.
3. **Should the event manifest carry a DECISIONS-style header of declared-but-unconsumed fields?**
   #88 suggests it. 90 fields with 4 actively decoded means ~86 rows of "declared, not consumed",
   which is a large header of low information. Ship the manifest without it; revisit if a consumer
   ever needs to know which fields the SDK reads versus merely declares.
4. **When does `contract/expected-local-lag.txt` get re-opened?** `EXPECTED-FROM: 2026-08-31`, and
   `plans/gate-blindness-hardening.md`'s Open Questions set a 60-day trigger. Phase 5 must not delete
   or invalidate it; if the event `--write-manifest` arm ever touches it, that is a bug.
5. **Is `test_full_round_trip` passing while its three siblings fail a permanent property?**
   The diagnosis says yes — first-on-the-port always wins. If a future run shows #1 failing too, the
   port hypothesis is incomplete and the uploaded log from Phase 2 is what settles it. Recorded so
   the next occurrence is measured against a prediction rather than re-theorised. **The re-verification
   pass sharpened the prediction:** the same hypothesis also predicts #5/#6 (`governed_server`, 8115,
   run back-to-back after `dual_plane`'s 8115) should fail, and they did not. Either prediction being
   wrong on the next occurrence falsifies the port hypothesis; both being wrong means the cause is
   elsewhere entirely.

6. **Should the `PROGRESS.md` → `ts/src/client.ts` slack margin be re-measured after Phase 4?**
   `test_the_load_bearing_citations_still_point_at_the_right_thing`'s docstring
   (`python/tests/test_compatibility_citations_resolve.py:644-647`) records the closest
   needle-to-foreign-citation distance in `PROGRESS.md` as **53 lines** (needle 676, foreign citation
   623). Phase 4's insertion moves the needle away from 623 and toward 804, shrinking that margin by
   exactly the insertion size. The docstring is a hand-maintained measurement, not a computed one, so
   nothing reddens when it goes stale. Re-measure it in Phase 4's commit; do not widen
   `CITATION_SLACK` (issue #73 ruled that out).

---

## Re-verification pass — 2026-09-01, fresh agent, against `960cf81`

An independent pass re-ran every measured number in this plan against the code. Recorded here rather
than folded silently in, because "the plan was checked" is only useful if what failed is visible.

**Confirmed exactly as written** (no change needed): the Phase 5 extractor claim (90/90, zero
one-sided, 11 messages, zero enums, zero nested — re-run, not re-read); the separate-manifest
conclusion; `--write-manifest`'s `$EXPECTED_LOCAL_LAG` deletion at `:472-476`; exit 8 unused anywhere
in the repo and no consumer of specific exit codes beyond `test_field_manifest_gate.py` and the
`Makefile`; all four `PolicyEnforcement` presence facts, checked against the **descriptor**
(`SessionStep.policy_enforcement` field 3 `has_presence=True`; `DecisionResponse.policy_enforcement`
field **7**, also `has_presence=True`; `enforced` `has_presence=False`; `policy_id` in the synthetic
oneof `_policy_id`, `has_presence=True`, explicit-empty surviving a serialize/parse round trip as
`HasField=True`); the 42-test collection and the `server`-fixture users at `:69/:93/:108/:306`; the
`_wait` decoy reproduction, re-run verbatim (`_wait returned in 0.002s`, `exit code: 0`); every
`_collective.py`, `ts/src/client.ts`, `ts/src/index.ts`, `ci.yml` and `check-contract.sh` citation.

**Corrected in place** (each marked at its own site above): the 730 baseline (→ **754**, the delta
being this plan's own `PROGRESS.md` citations); Phase 2 criterion 1's grep (unsatisfiable **and**
blind to three of the four defects it targets); "seven" teardowns (→ **nine**); Phase 2's
"explains the exact failing set" (it does not explain the 8115 trio, and "the previous test" is wrong
for #7); Phase 4 criterion 5's single-cause vacuity diagnosis (there is a second, `K ∈ [125,131]`);
Phase 5's placement-in-the-flow gap and its criterion 6, which **passed verbatim at `HEAD`**; Phase
5's missing edit to `test_field_manifest_gate.py`, without which an ordinary `pytest` run rewrites the
new committed manifest; criterion 1's `#` clause; criterion 7's one-phrase grep; the "no unambiguous
character left" premise; the `Makefile` comment already being stale at 0-4.

**Left as known-unenforced, deliberately:** `PROGRESS.md`'s comma-list citations
(`` `ts/src/client.ts:601,637` ``) match `CITATION` (`:109`) not at all, so they are checked by
nobody. Widening the regex would pull `client.py:473,514` and others into scope and is a change to the
citation gate, not to this plan. Noted at the Phase 4 site so the implementer re-measures by hand.

---

## Plan review

**Round 1 — fresh Opus agent, verdict `REVISE`, applied.** The reviewer re-derived the plan's
measurements against the code rather than reading its prose. The two hardest technical claims held
exactly: Phase 5's extractor agreement (90/90, zero one-sided entries, 11 messages, 0 enums, 0 nested
in both languages) and Phase 4's `ANCHORED`-citation break. What it found instead was four broken
criteria — including one that **passes verbatim at `HEAD` today**.

| # | Finding | Severity |
|---|---|---|
| H1 | Baseline was stated as 730; it is **754**. The 24-test delta is *this plan's own `PROGRESS.md` section* — the citation test is parametrized per citation, so adding rows adds tests. `730 + N` was wrong twice. | HIGH |
| H2 | Phase 2 criterion 1's grep is **unsatisfiable and blind**: it can never return nothing (`test_compatibility_citations_resolve.py:103,386,396,397` hold IP:port strings as test data) and it misses three of four targets, which carry no colon. | HIGH |
| H3 | `exit 6` at `scripts/check-contract.sh:857` is the last statement before the OK-echoes. An event probe placed after it **never runs on a local checkout**; placed before it, it preempts the api report. The probe must compute in the same single pass. | HIGH |
| H4 | Phase 5 would make the **existing** suite rewrite the new committed manifest: `test_field_manifest_gate.py` calls `--write-manifest` at six sites while `_run()` redirects only the field and RPC manifests. | HIGH |
| M1 | "All seven" teardowns over a list of nine. Measured: **9**. This is the same count-over-list defect the plan flags for `ts/src/index.ts:18` one phase later. | MEDIUM |
| M2 | Phase 2 overclaimed "explains the exact failing set" — see the correction below. | MEDIUM |
| M3 | Phase 4's break is real but not *necessary*: for an insertion of 125-131 lines the citation drifts into an unrelated `:804` anchor's slack and goes green for the wrong reason. | MEDIUM |
| M4 | Reusing exit 7 for the event tripwire needs stating, since the plan argues exit 8 exists precisely so codes name their failure. | MEDIUM |

**The vacuity hunt, which is what this round was for.** Phase 5's criterion 6 — "still exits 6, still
NOTEs exactly the five `ContextBinding` fields, reports no event discrepancy, `git diff` empty" —
**was true at `HEAD` before any of Phase 5 existed**, verified by running it. Worse, it is *satisfied
by the failure mode*: a probe placed after `exit 6` never runs, reports nothing, and scores green.
That is the third time this repo has produced a criterion that passes before its fix
(`plans/gate-blindness-hardening.md`'s post-merge record holds the first two). Fixed by requiring a
positive "event surface matches" line and adding the new manifest to the diff check.

Phase 4's criterion 6 was vacuous in the same shape as the defect it guards: "the comment names
`PolicyEnforcement`" is satisfied by appending a name and leaving the word "Two" in place.

**The #85 mechanism is a hypothesis, not a confirmed cause — corrected here rather than left
standing.** The correlation is exact: all three failures are `server`-fixture users on the shared
8099, and the first 8099 user passed. But the collection order is 8099, 8099, 8099, 8115, 8115, 8115,
8099 — and tests #4/#5/#6 share **8115** back-to-back with **all three passing**, where the
"previous test's draining server" mechanism predicts #5 and #6 fail. Test #7's immediate predecessor
is on 8115, not 8099, and the nearest 8099 predecessor (#3) itself failed. The smoke step is also
separated from `pytest` by four intervening steps, so it is a hygiene defect rather than the reason
#1 passes.

**This does not weaken Phase 2.** The defect is independently proven: a readiness check that returns
in 0.002s against a port its own process never bound, with that process already dead. Shared ports,
unwaited teardown, and an unidentifiable readiness check are each wrong on their own terms, and the
fix is correct under every reading of the CI symptom. What changed is the claim: the phase now says
what it removes, not what it explains — and criterion 6's captured log is what will settle the causal
story if #85 recurs.

`SO_REUSEADDR` could not be verified here (the binary is absent and `../seam-runtime/crates/**` is
under the clean-room constraint). Reasoned from tokio defaults, `TcpListener::bind` sets
`SO_REUSEADDR` and not `SO_REUSEPORT`, so two live listeners cannot coexist and the diagnosis is
unaffected; were `SO_REUSEPORT` set, both would listen and the kernel would load-balance — same
symptom, same fix. Recorded as unverifiable locally rather than asserted.

**Round 2 was not run.** Round 1's findings were all mechanical to apply and none reopened the
approach: the reviewer confirmed the long-term shape of all three phases (Phase 3's new-module split,
Phase 5's separate manifest, Phase 2's convergence on the TypeScript suite's discipline) as correct
and argued from code. A second round would re-derive settled measurements.
