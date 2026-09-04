# Gate-blindness hardening

## Context

`plans/post-adoption-hardening-and-acdp-readiness.md` shipped ten phases whose subject was guards
that pass without seeing anything. A fresh adversarial audit (Fable, read-only, mutation-proofs in a
scratch copy) went looking for the same failure class in the machinery that plan *left behind*, and
found it in two places that matter and five that are worth closing.

The audit's own summary of the surface: the publish/CI gate machinery is genuinely strong — patience
without softening, one-green-cannot-mask-one-red, timeout-is-refusal, tag ancestry, the yank guards,
the vendored-spec pin, `ci-ok`'s two-directional job coverage all held under attack. The protobuf half
of the #52 defect class is closed end-to-end. What did not hold is listed below, and it is not a
style list: two findings permit a broken artifact or a silently-wrong SDK to reach a consumer.

The through-line is unchanged from the last plan: **a value stored twice can disagree with itself,
and the disagreement is the signal.** Every phase here either makes a second copy of a value exist so
it can disagree, or removes a copy that is already disagreeing.

### What this plan does NOT do

- It does not run `make clean` or `make generate`. Local stubs stay pre-ACDP (223 fields); the
  committed manifest stays at the BSR's 228. Every mutation proof happens in a scratch copy under
  the session scratchpad with `SEAM_PY_GEN`/`SEAM_TS_GEN` overrides, never in the real tree.
- It does not settle the deferred 0.7.39–0.7.43 Cloudsmith quarantine. That stays UNCONFIRMED with
  its recorded trigger and owner.
- It does not touch `java/` or `kotlin/` — no JDK in this environment; those stay CI-verified.
- It writes no file in any sibling repo. Closing `#77`/`#78` is issue hygiene in *this* repo.

## Phases

---

### Phase 1 — enum values enter the field manifest

**Status:** DONE — with one plan error corrected in flight: this section said "18 enum values", which
double-counted the three `UNSPECIFIED` zero values already inside the per-enum totals. 5 + 6 + 4 = **15**.
Both extractors independently agree at 15. The executor implemented against the measured stubs and
flagged the arithmetic rather than matching the number the plan asserted — which is the behaviour the
whole plan is about. Two further divergences, both improvements: the nested-enum tripwire uses a new
exit **7** (a structural precondition failure, like exit 3, not a surface disagreement), and field and
enum failures are now gathered and reported together before a single `exit 6`, so a simultaneous
field+enum failure cannot hide the second report behind the first exit.

**Delivers:** `contract/field-manifest.txt` declares the enum-value surface alongside the field
surface, and `scripts/check-contract.sh` compares it in both directions per language. A runtime that
adds, removes, or renames an enum value can no longer land with every gate green.

**Depends on:** nothing.

**Why this is first:** it is the highest-severity finding and it is the last plan's own failure class
repeating. `python/seam_sdk/_collective.py:19` and `python/seam_sdk/errors.py:104` are deliberately
fail-closed — they raise `UnknownCollectiveVerdictError` on any unrecognised value. So a new
`COLLECTIVE_VERDICT_VETOED` in the runtime does not degrade gracefully in consumers; it hard-errors
on a legitimate response. `buf breaking` in seam-runtime (`.github/workflows/ci.yml:168-176` there)
passes additive enum values by design, so nothing upstream catches it either. Proven by mutation:
appending two values to both scratch stub trees and rerunning the real script → exit 0.

**Files:**
- `scripts/check-contract.sh` — two new extractors, one new set-comparison, `--write-manifest` support.
- `contract/field-manifest.txt` — new enum-value section + a header paragraph on what it covers.
- `python/tests/test_field_manifest_gate.py` — new cases.

**Approach:**

Extend the existing dual-extractor design rather than inventing a second mechanism — the whole point
of that design is that two independently-derived spellings of the same surface must agree, and enum
values have exactly the same property. Spelling: `<Enum>#<VALUE>`, chosen because `#` cannot occur in
either a message or a field name, so a single flat manifest stays unambiguously partitioned and the
existing `MISSING`/`UNDECLARED` reporting works unchanged.

- **Python side:** parse `python/seam_sdk/_gen/seam/api/v1/seam_pb2.pyi`. Enum classes are declared
  `class <Name>(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):` and their values are the
  4-space-indented `<VALUE>: _ClassVar[<Name>]` lines beneath. Track the current enum by the most
  recent such `class` header; emit `<Name>#<VALUE>`.
- **TS side:** parse `ts/gen/seam/api/v1/seam_pb.ts`. protobuf-es emits `export enum <Name>` with
  `@generated from enum value: <VALUE> = <n>;` doc comments; extract from the doc comment, not the
  identifier, so the extractor keeps deriving from the generator's own record of the contract rather
  than from TypeScript syntax that could be reformatted.

Rejected: extracting from the runtime `.proto`. The whole gate's value is that it reads *generated
stubs* — what the SDK will actually compile against — not the source the stubs claim to come from.
Rejected: a separate `contract/enum-manifest.txt`. A second file is a second thing to forget to
update; the manifest is already the one declaration of "the surface this SDK expects."

**Edge cases & failure modes:**
- `UNSPECIFIED` zero values must be included, not filtered — a runtime removing one is a real change.
- The two extractors must agree with each other, not just each with the manifest. If Python sees a
  value TS does not, that is a *generation* skew and must be reported distinctly from manifest drift.
- Enums nested inside messages: none exist today. The extractor must not silently include them if one
  appears — same nesting trap as Phase 4. Assert none exist and fail loud if that changes.
- `--write-manifest` run against stale local stubs would rewrite the manifest backwards. Unchanged
  existing hazard; Phase 5 addresses it directly.

**Acceptance criteria:**
1. `contract/field-manifest.txt` contains exactly 15 `<Enum>#<VALUE>` lines covering
   `AuthorizeVerdict` (5), `CollectiveVerdict` (6) and `BallotChoice` (4) — each count already
   including that enum's `UNSPECIFIED` zero value — matching `python/seam_sdk/_gen/seam/api/v1/seam_pb2.pyi:11-33`.
2. Appending one enum value to *both* scratch stub trees makes `check-contract.sh` exit 6 and name
   `<Enum>#<VALUE>` for both languages.
3. Deleting one enum value from both scratch trees makes it exit 6 reporting it MISSING.
4. Adding a value to only ONE scratch tree produces a report distinguishing generation skew from
   manifest drift.
5. `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` on the real tree still exits 6 for exactly the
   five ACDP `ContextBinding` fields and reports **no** enum discrepancy.

**Tests:** `python/tests/test_field_manifest_gate.py` gains: added-value red, deleted-value red,
one-language-only skew red, and an anti-vacuity floor asserting the enum section is non-empty and
covers all three enums by name.

**Docs:** `contract/field-manifest.txt` header — say what the enum section covers and, explicitly,
that `buf breaking` upstream does *not* cover additive enum values, which is why this exists.

---

### Phase 2 — the grpcio half of the #52 defect class

**Status:** DONE — three divergences, all recorded rather than smoothed over:

1. **`COMPATIBILITY.md` and `DECISIONS.md` were edited, and they are not in this phase's Files list.**
   Rewriting the `publish.yml` comment block shifted line numbers and drifted six citations into it.
   That is self-inflicted and had to be repaired in the same commit, not deferred.
2. **That drift is live evidence for Phase 6, produced by accident here.** The guard caught the
   `COMPATIBILITY.md` citation because it is ANCHORED. The three `DECISIONS.md` citations still
   *resolved* — the lines existed — while pointing at the wrong content, and no check noticed. The
   distinction between "this citation resolves" and "this citation says what it claims" is exactly
   what Phase 6 is about, and it just failed in the direction Phase 6 predicts.
3. **`test_the_floor_pinned_install_has_no_unconstrained_fallback` had to be updated, not merely
   extended** — its literal-substring assertion necessarily breaks once grpcio is pinned in the same
   install line. What it guards (single install, no unconstrained fallback) is preserved and widened
   to cover grpcio.

Also worth knowing for future work: `scripts/test_publish_gate.py` needs `pyyaml`, which
`python/.venv` does not carry. CI builds a separate venv for it (`ci.yml`'s `workflow-guards` job);
running it from `python/.venv` fails for reasons that have nothing to do with the code under test.

**Delivers:** publish-time grpcio floor verification with the same two-part shape the protobuf half
already has: a derivation that cannot be fooled by an unrecognised calling convention, and an
end-to-end install-at-the-floor truth check.

**Depends on:** nothing.

**Files:** `.github/workflows/publish.yml`, `scripts/test_publish_gate.py`.

**Approach:**

`publish.yml:355-359` selects only `-k "covers_every_convention"`. That test
(`python/tests/test_grpcio_floor.py:108`) derives `required = max(version for _, version, _ in present)`
over `_MARKERS` (`:46-60`), a two-entry hardcoded list — so a grpc plugin roll emitting a *new*
convention alongside the old markers moves the derivation not at all and the floor silently understates
what the stubs need. The recognizer test at `:93` fires only when *none* of the known markers appear,
and is not selected by the publish `-k` in any case.

Two changes, mirroring exactly what closed the protobuf half:
1. Widen the `-k` selection to include the recognizer, so an unknown convention is a publish-time
   refusal rather than a silently-passing `max()` over stale markers.
2. In the floorcheck venv, parse the grpcio floor from `pyproject.toml` the same way `FLOOR` is
   parsed, install `grpcio==$GRPCIO_FLOOR` alongside `protobuf==$FLOOR`, and exercise the generated
   stub against a dead channel plus `add_*Servicer_to_server` on a real `grpc.server` — the two
   behavioural checks `test_grpcio_floor.py:133` and `:147` already model. Import alone is not
   enough: grpcio's convention mismatch surfaces at stub *construction*, not at import.

Rejected: raising the declared floor defensively. That trades a false floor for an unnecessarily high
one, and #48 is already open precisely because the floors are too high to co-install with CrewAI.
The fix is to make the derivation honest, not conservative.

**Edge cases & failure modes:**
- No grpcio floor declared at all → must be a refusal, not a skip.
- `grpcio==$FLOOR` unavailable as a wheel for the runner's Python → the step must fail loudly rather
  than silently resolving to something newer, which would restore exactly the hole being closed.
- The dead-channel stub construction must not attempt a network call or block.

**Acceptance criteria:**
1. A stub `_pb2_grpc.py` carrying only an unrecognised convention marker makes the extracted publish
   floor step exit non-zero.
2. The floorcheck venv provably has `grpcio` at the declared floor (asserted by
   `importlib.metadata.version`, printed to the log), not merely "some grpcio".
3. Constructing a stub and registering a servicer under the floor-pinned grpcio succeeds in the
   green case and fails the job in the mutated case.
4. `scripts/test_publish_gate.py` grows an unknown-marker case that is red before the fix and green
   after, and the whole gate suite still passes.

**Tests:** `scripts/test_publish_gate.py` — extend `_stub_repo` with an unknown-marker fixture;
assert the extracted step refuses. Keep the existing protobuf cases untouched and passing.

**Docs:** `publish.yml`'s own comment at `:338` already names this gap — rewrite it to describe the
closed state rather than the known hole.

---

### Phase 3 — invert the verifier-independence allowlist

**Status:** DONE. The six-crate list and the "`bandit` matches nothing" claim both checked out
exactly against the real `seam-runtime/crates` tree. Two things worth recording:

1. **The new test caught a real bug in the new script, in the acceptance criterion's own direction.**
   `grep -v` exits 1 when it filters out *every* line — which is exactly the root-only,
   zero-dependency case, acceptance criterion 2. Under `set -e` that aborted the script before it
   could print OK, so the GREEN case was failing closed for a reason that had nothing to do with
   independence. Fixed with an explicit `|| true` and a comment saying why. A gate that fails closed
   for the wrong reason is still wrong; it just fails in the direction nobody investigates.
2. **`verify`'s crate version is 0.3.0, not the 0.7.70 this section's acceptance criterion assumed.**
   The SDK's published version and the verifier crate's version are not the same number and were
   never meant to be. Criterion 2 below is corrected to say "the root line", which is what it always
   meant.

**Delivers:** the "must link NOTHING of Seam's" gate can see every Seam crate, present and future,
instead of a hardcoded list that has already drifted.

**Depends on:** nothing.

**Files:** `.github/workflows/ci.yml`, `.github/workflows/publish.yml`, and a new
`scripts/test_independence_gate.py`.

**Approach:**

The gate (`ci.yml:405`, duplicated verbatim at `publish.yml:478`) greps
`\bseam-(store|types|traits|trust|kernel|crypto|api|client|guard|coord|context|bandit)`. Measured
against `../seam-runtime/crates/` today, that misses `seam-acdp-testkit`, `seam-conformance`,
`seam-kms-vault`, `seam-serving`, `seam-serving-router`, and the `seamd` binary — six real crates —
while `bandit` matches nothing that exists. The gate whose comment reads "THE claim, asserted" cannot
currently see a third of what it is asserting about.

Invert it: refuse any `\bseam-[a-z0-9_-]+\b` or `\bseamd\b` in `cargo tree -e normal` other than the
root `seam-verify` line. An allowlist of what is forbidden must be maintained in lockstep with
another repo and silently rots; a denylist of what is permitted is complete by construction and its
failure mode is a loud false positive rather than a silent false negative.

A third-party crates.io package happening to be named `seam-*` would trip it. That is the correct
direction to fail, and the error message must say so: investigate, and if genuinely third-party,
verify its source registry with `cargo metadata` before adding a narrowly-scoped, commented
exemption. Never widen the pattern.

The duplication between the two workflows is itself a stored-twice value that can disagree. Extract
the check into a single script both call, so the two copies cannot drift.

**Edge cases & failure modes:**
- The root line `seam-verify v0.x.y` must pass; a *dependency* line naming `seam-verify` must not.
- `cargo tree` indentation/box-drawing prefixes must not defeat the root-line exclusion.
- Dev-dependencies are deliberately out of scope (`-e normal`) — keep that and say why.

**Acceptance criteria:**
1. A synthetic `cargo tree` containing `seam-serving v0.1.0` fails the extracted script.
2. The same synthetic containing only the root `seam-verify` line passes.
3. `seamd` in a synthetic tree fails.
4. `ci.yml` and `publish.yml` both invoke the one script; `grep -c 'seam-(store|types' .github/workflows/*.yml` returns 0.
5. `cd verify && cargo tree -e normal` on the real tree still passes the new script.

**Tests:** new `scripts/test_independence_gate.py`, run under the existing scripts-gate suite.

---

### Phase 4 — nested-message tripwire, and correct a scoping comment that is not true

**Status:** DONE. The blindness was reproduced by mutation before anything was built: the unmodified
script wrote a 224-field manifest (the top-level sibling only) and exited **0** with a nested
message's fields invisible to both extractors. The "two known `FeaturesEntry` synthetics" claim and
the 90-field event count both checked out exactly. Note for anyone re-running the proof:
`EscrowDirective` does not exist in this contract — it was a hypothetical in the audit, and injecting
into it is a silent no-op that looks like the tripwire failing. Inject into a message that is
actually there.

**Delivers:** the first real nested message on `seam.api.v1` fails loudly instead of being silently
excluded by both extractors symmetrically; and `check-contract.sh:368` stops claiming coverage that
does not exist.

**Depends on:** Phase 1 (touches the same extractor block; sequencing avoids a conflict).

**Files:** `scripts/check-contract.sh`, `python/tests/test_field_manifest_gate.py`.

**Approach:**

Map-entry types are excluded by *nesting* (`check-contract.sh:195-231`) — correctly, because the
`*Entry` name filter the manifest header warns about at `:50-55` would have dropped the real
top-level `AuditEntry`. But that exclusion is symmetric across both languages, so a real nested
message is invisible to both sides at once: the manifest header's own stated failure mode, "the gate
stays green while going blind," reproduced by the fix for the other one. Proven by mutation: with
`EscrowDirective.Hold{amount_cents, release_after_ms}` added to both scratch trees, the gate caught
only the top-level sibling field and then exited 0.

The contract has zero real nested messages today, so the cheap and correct move is a tripwire, not a
speculative extractor: assert that the only nested types in the Python `.pyi` are the two known
`FeaturesEntry` map synthetics, and that the TS tree contains no `Message<"seam.api.v1.X.Y">`. The
first real nested message then fails loudly and forces the extractor extension *with a concrete
example in hand*, which is a better design input than guessing at the shape now.

Separately, `:368` asserts "seam.event.v1 fields are covered by the STREAM/EVENTS probes and by the
vendored-spec gate." Measured: the probes assert presence of 4 named fields out of ~90
(`grep -c FIELD_NUMBER python/seam_sdk/_gen/seam/event/v1/seam_event_pb2.pyi` → 90) and never fail on
an additive field; the vendored-spec gate fires only if the runtime also edits its spec doc. The
comment is not true and must be corrected to state the real residual, with Phase 8 filing the issue
that tracks closing it.

**Edge cases & failure modes:**
- The known-synthetics allowlist must be exact — a third map field appearing must trip the wire, be
  investigated, and be added deliberately.
- The tripwire must not fire on `seam.event.v1` stubs, which are out of this gate's scope.

**Acceptance criteria:**
1. Adding a nested non-`*Entry` type to either scratch stub tree reddens the suite.
2. Removing one of the two known `FeaturesEntry` synthetics also reddens it (the allowlist is exact,
   not a floor).
3. `check-contract.sh:368`'s comment states what the event-field surface is and is not covered by,
   with no claim that is false.
4. The real tree passes the tripwire.

**Tests:** `python/tests/test_field_manifest_gate.py` — nested-type-added red, known-synthetic-removed
red, real-tree green.

---

### Phase 5 — make the expected local lag distinguishable from real drift

**Status:** DONE — with one addition the plan did not specify but which it needed. `--write-manifest`
deletes the lag file by design, so every pre-existing test that exercises `--write-manifest` would
have deleted the *real committed* `contract/expected-local-lag.txt` as a side effect. A
`SEAM_EXPECTED_LOCAL_LAG` override was added (same idiom as `SEAM_FIELD_MANIFEST`) and the test
harness auto-redirects to a scratch path unless a test explicitly opts into the real file. Verified:
the committed lag file is byte-identical after a full suite run.

The downgrade is correctly conjunctive, which is the part that could have gone wrong quietly. It
requires the MISSING sets to match in BOTH languages AND no NOT-IN-THE-MANIFEST entries AND a clean
enum surface AND no generation skew. A run where the five lag fields match but an enum value has
drifted produces the full un-downgraded error — verified directly, since that is exactly the case
where a downgrade would hide a real finding behind an expected one.

**Delivers:** a pre-ACDP local checkout can tell "the known five" from "the known five plus one" by
machine, not by a human reading five lines they have learned to skim.

**Depends on:** Phase 1 (both edit the gate's reporting path).

**Files:** `scripts/check-contract.sh`, `contract/expected-local-lag.txt` (new), `CLAUDE.md`,
`python/tests/test_field_manifest_gate.py`.

**Approach:**

`STREAM=1 EVENTS=1 make check-contract` exits 6 on every pre-ACDP checkout. `CLAUDE.md:9` lists the
command with no hint of that. The message a reader sees is *"stale generation ... or a field REMOVED
from the contract, which is a breaking change"* — the exact wording, exit code, and direction a real
removal produces. A gate that is red locally and green in CI trains everyone to ignore it, and the
documented escape for a red gate, `--write-manifest`, run against these stale stubs, rewrites the
committed manifest backwards to 223 — locally it looks like the fix, and CI catches it only later.

Two parts:
1. One `## Gotchas` line in `CLAUDE.md` — cheap, and it reaches the one file every session loads.
2. A `contract/expected-local-lag.txt` carrying the five lines and the date they were expected from.
   An exact match downgrades to a NOTE that names the file and says why; any superset, subset, or
   deviation stays a full exit 6. The gate must still exit 6 on exact match — the lag is real and CI
   is the authority — but the *output* must be unmistakably different.

Rejected: exit 0 on exact match. That would make a genuinely stale local tree look clean and is
strictly worse than the status quo.

**Edge cases & failure modes:**
- The file must not become a permanent excuse. It carries a date and the gate prints its age; once
  local stubs are regenerated the exact-match branch stops firing on its own.
- `--write-manifest` must delete or invalidate the file, since after a rewrite the recorded lag is
  meaningless.
- A `MISSING` set that matches the file but with an *extra* UNDECLARED entry is not an exact match.

**Acceptance criteria:**
1. On the real pre-ACDP tree the gate exits 6 and its output unmistakably identifies the five as the
   recorded expected lag, naming `contract/expected-local-lag.txt`.
2. A scratch tree missing those five *plus one more* field produces the full un-downgraded error.
3. A scratch tree missing only four of the five also produces the full error (subset ≠ match).
4. `--write-manifest` removes or invalidates the file.
5. `CLAUDE.md` states the expected local exit-6 and that anything beyond the five is real.

**Tests:** `python/tests/test_field_manifest_gate.py` — exact-match note, superset red, subset red,
write-manifest invalidation.

---

### Phase 6 — the citation guard reaches the record that misdirects the next run

**Status:** DONE. The rot was far worse than the three anchors this section named — **19 fixes in
`PROGRESS.md` and one in `CHANGELOG.md`**, and the extra sixteen are the interesting part because
they are mostly a *different* class than the one predicted:

* **Three citations RESOLVED while pointing at unrelated content.** `PROGRESS.md:80` cited
  `DECISIONS.md:419-439` for "pinning buf.gen.yaml plugins is rejected"; that range is the #52
  wheel-band decision. Two more cited the `Bearer`-prefix strip at a line holding something else.
  Structural resolution cannot see this class at all — only `ANCHORED` can, and it covered none of
  them.
* **Two more generated-tree anchors** beyond the one this section named, both converted to symbol
  references.
* **Nine basename-only citations** (`ci.yml:19`, `admin.py:141`, `aio.py:404-405`, …), repathed to
  carry a real directory. **Correction, made after `d968201` shipped:** that commit's message says
  the regex "declines these silently... never resolved, never counted, never failed." That is
  false — `CITATION`'s pattern is `[\w./-]+\.[A-Za-z]\w*`, and `.` is inside the character class, so
  a bare basename like `ci.yml` matches it exactly as a path (group 1 = `"ci.yml"`) just as readily
  as a directory-qualified one. Nothing declines it. Once `PROGRESS.md` entered `DOCS`, each of
  these nine would have been asserted against `REPO / "ci.yml"` (no such top-level file) and failed
  **LOUDLY** — a hard `AssertionError`, not a silent skip — which is *why* they had to be repathed
  before `PROGRESS.md` could be added to `DOCS` at all: a loud failure on nine citations at once
  would have been indistinguishable noise, not evidence of anything specific. `d968201`'s own commit
  message carries the wrong wording; it is not being rewritten (history stays history), so this
  correction lives here instead, precisely so the record does not silently disagree with itself —
  which is this whole plan's subject.
* One of those, `test_field_manifest_gate.py:240`, had **also** drifted 121 lines.
* This section's own estimate of the `CHANGELOG.md` rot — "~44 lines off" — was wrong. It is ~90
  lines, and the target had moved to `:636-645`.

**One divergence taken at the gate, not by the executor.** The executor found that `` `127.0.0.1:8099` ``
parses as a citation — `\w+` matches a purely numeric extension, so an IP and port reads as "file
`127.0.0.1`, line 8099" — and worked around it by rewording the prose. That closes the instance and
leaves the class. The guard was making writers edit around it, which teaches them to edit around it.
`CITATION` now requires the extension to begin with a letter. Measured before changing it: across all
four documents that drops **zero** real citations (27 / 57 / 81 / 3, unchanged in every file), and no
source file in this repo has a digit-initial extension. Narrowing a pattern is exactly how a guard
goes blind, so a test pins that it narrows by this class only — asserting both that IP:port shapes are
inert and that every real extension shape in the repo still parses.

Deliberately still out: `CHANGELOG.md` (append-at-top; the previous plan priced and declined it) and
`plans/` (historical records rot by design).

**Delivers:** `PROGRESS.md` under the citation guard; line anchors into gitignored generated trees
refused outright; the three live rotted anchors fixed.

**Depends on:** nothing (independent of the contract-gate phases).

**Files:** `python/tests/test_compatibility_citations_resolve.py`, `PROGRESS.md`, `CHANGELOG.md`.

**Approach:**

`DOCS` covers only `COMPATIBILITY.md` and `DECISIONS.md`
(`python/tests/test_compatibility_citations_resolve.py:72-75`). Phase 6 of the previous plan recorded
in its own divergence note that "`PROGRESS.md` and this plan are the most-cited unguarded documents
... the case for it is now evidence" — and no issue tracks that follow-up, so it has lived only in a
divergence note. Measured rot at HEAD, verified independently:

| Citation | Claims | Actually |
|---|---|---|
| `PROGRESS.md:59` → `ts/src/client.ts:202` | `collectiveOutcomeOf` | `:218` |
| `PROGRESS.md:62` → `ts/src/client.ts:654` | `submitCommit` | `:676` (`:654` is a `submitObjection` comment) |
| `CHANGELOG.md:437` → `verify/src/verify.rs:545` | "version refusal runs before it" | mid-doc-comment, ~44 lines off |

`PROGRESS.md:60` line-anchors into `ts/gen/seam/api/v1/seam_pb.ts:942` — a **gitignored generated
file**. That is worse than the vendored class `#73` just outlawed: it is correct only until the next
`make generate` inserts the five ACDP fields above it, and it cannot be verified on a fresh clone at
all. Add a `GENERATED` prefix rule refusing line anchors into `ts/gen/`, `python/seam_sdk/_gen/`, and
`gen/`, the same shape as the existing `VENDORED` refusal, and convert that citation to a symbol
reference.

Add `"PROGRESS.md": 10` to `DOCS`. Its citation volume qualifies, and it is the file a resumed run
reads *instead of re-scanning the repo* — a wrong anchor there misdirects execution, which is a
strictly worse consequence than a wrong anchor in a narrative document.

`CHANGELOG.md` is deliberately left out of `DOCS`: it is append-at-top, so every citation in it moves
on every release, and the previous plan already priced and declined that cost. Fix the one rotted
anchor; do not widen the guard there.

**Edge cases & failure modes:**
- Adding `PROGRESS.md` to `DOCS` will surface more rot than the three above. Every one found must be
  fixed or converted, not suppressed by lowering the floor.
- Structurally unresolvable basename-only citations (`publish.yml:316`, `admin.py:141`) exist in
  `plans/` and `PROGRESS.md`; the regex requires a path so it declines them silently. Within
  `PROGRESS.md` they must be given real paths. `plans/` history stays out of scope — those rot by
  design and are a record of what was true then.
- The anti-vacuity floor for `PROGRESS.md` must be set from the *actual* resolved count, not guessed.

**Acceptance criteria:**
1. `pytest python/tests/test_compatibility_citations_resolve.py` fails when a `PROGRESS.md` citation
   is pointed more than `CITATION_SLACK` lines past a moved target, and passes on the corrected file.
   (Corrected post-hoc: the guard tolerates drift up to `CITATION_SLACK` — 3 lines as of this
   writing — by design, per that constant's own comment; "one line past" understated the guard's
   actual, intentional tolerance and would itself fail against the shipped test.)
2. Any `` `ts/gen/...:N` ``, `` `python/seam_sdk/_gen/...:N` ``, or `` `gen/...:N` `` line anchor in a
   guarded doc is refused with a message naming the generated-tree rule.
3. The three rotted anchors above resolve to the symbols they claim.
4. No basename-only citations remain in `PROGRESS.md`.
5. The full python suite is green, and its count has grown, not shrunk.

**Tests:** existing file, extended: `GENERATED` refusal case, `PROGRESS.md` floor, a registry-consistency
check mirroring the `VENDORED` one so the two prefix rules cannot drift apart.

---

### Phase 7 — the record stops disagreeing with itself about what was filed

**Status:** DONE. The constraint is kept as history — "under this restriction, Phase 2 wrote its asks
and *would have* left them UNFILED" — followed by the lift and both issue links, so the log stays a
history rather than a tidied result. The propagated cost is stated in the file itself: the audit brief
that produced this plan asserted the asks were unfiled because it read this header instead of Phase
2's log. Burying that would have made the record tidier and less true.

**Delivers:** `PROGRESS.md`'s header agrees with its own Phase 2 log about whether the cross-repo
asks were filed.

**Depends on:** nothing.

**Files:** `PROGRESS.md`.

**Approach:**

`PROGRESS.md:21` says "the (deliberately unfiled) cross-repo asks"; `:24` says Phase 2 "leaves them
**UNFILED** — recorded again in that phase's log so the gap stays visible." `:762-767` says the asks
were "written and **filed**" as `seam-runtime#525` and `seam#26`. Both issues are real and open. The
scope restriction was lifted mid-run; the header was never updated, and `b064e07` — whose subject is
*"fix a record that did not agree with itself"* — shipped over it.

This has already propagated: the audit brief for this very plan asserted the asks were left unfiled,
because it was written from the header. That is the concrete cost of the disagreement, and it is worth
saying so in the edit rather than quietly correcting the lines.

Rewrite `:21` and `:24` to state that the restriction was lifted mid-run and both asks were filed,
pointing at the Phase 2 log and both issue numbers. Do not delete the original constraint — record
that it held at plan time and was lifted, so the log stays a history rather than a tidied result.

**Acceptance criteria:**
1. `grep -n 'UNFILED\|unfiled' PROGRESS.md` returns nothing outside a passage that also states the
   restriction was lifted and names both issues.
2. Header and Phase 2 log agree.
3. Full python suite green (doc-guard tests scan every `*.md`).

**Tests:** full python suite; no new test — this is a record correction, and the guard that would
have caught it is a semantic-consistency check no reasonable test can express.

---

### Phase 8 — hygiene: two stored-twice disagreements, and two issues that are done

**Status:** DONE — and this section's own acceptance criterion 2 was **vacuous**, which is worth more
than the phase it belonged to.

It read: "`git check-ignore CLAUDE.md` returns nothing." That is true whether or not the bug exists.
Git exempts *tracked* files from indexed `check-ignore` by design — its own docs say so — so the
command returns the passing result in both states. Proven directly: at the commit with
`.gitignore:22` still present, plain `check-ignore` exits 1 with no output; `--no-index` exits 0 and
prints `.gitignore:22:CLAUDE.md`. After the fix, `--no-index` exits 1.

So a plan about guards that pass without seeing anything shipped an acceptance criterion that passes
without seeing anything, and it survived my own plan-review pass. Criterion 2 below is corrected to
the `--no-index` form. The lesson generalises past this file: an acceptance criterion needs the same
red-first proof a test does — run it against the unfixed state and confirm it fails — and nothing in
this plan's own review process did that.

`.gitignore`'s `CLAUDE.md` entry was checked for other dependents before deletion (`find . -iname
CLAUDE.md` → exactly one, the tracked root file), so the straight deletion was right and no narrower
fix was needed.

**Delivers:** a clean `git status` on a fresh checkout; `.gitignore` that agrees with the index;
`#77` and `#78` closed with evidence; the event-field residual tracked as an issue instead of a
comment.

**Depends on:** Phase 4 (the event-field issue quotes the corrected comment).

**Files:** `.gitignore`; GitHub issues (this repo only).

**Approach:**

1. `python/uv.lock` is untracked *and not gitignored*. It was already swept into a commit once and
   had to be backed out (`a5d2c47` "untrack python/uv.lock — swept in by mistake"). Leaving it as
   permanent `??` noise re-arms exactly that sweep for the next `git add -A`. Add it to `.gitignore`.
2. `CLAUDE.md` is tracked **and** listed in `.gitignore:22`. The ignore file says "not repo content";
   the index says it is. A `git rm --cached` or a fresh re-add silently drops a committed file.
   It has been committed by design since `3c37532` — remove the `.gitignore` line.
3. Close `#77` and `#78` with a comment in the style Phase 4 of the last plan used for `#50`: what
   landed (`#80`, `#84`), what was deliberately *not* done (interpretation — per the manifest header
   decision), and one correction. `#77`'s body gives `key_status` as
   `Authorized · HistoricallyAuthorized · Unauthorized`; the authoritative spec
   (`verify/docs/seam-event.v1.md:619`) says
   `CurrentlyAuthorized · HistoricallyAuthorized · HistoricallyAuthorizedPreCompromise`. Closing
   without noting that leaves a wrong vocabulary as the issue's last word — and this is precisely a
   vocabulary that must stay byte-identical to what enters the `context_digest` preimage.
4. File one issue for the `seam.event.v1` field-surface residual Phase 4 exposes, so it stops living
   only in a source comment.

**Acceptance criteria:**
1. `git status --short` is empty on a clean checkout.
2. `git check-ignore --no-index CLAUDE.md` returns nothing (the plain form is vacuous on a
   tracked file — see Status); `git check-ignore python/uv.lock` returns it.
3. `#77` and `#78` are CLOSED, each with a comment naming the PR that satisfied it and, for `#77`,
   the corrected `key_status` vocabulary with its spec citation.
4. An open issue in this repo describes the event-field surface residual and cites the corrected
   comment location.

**Tests:** `git status --short` empty; full python suite green.

---

## Long-term posture

Phase 1 and Phase 4 together mark the point where the manifest stops being a *field* manifest and
becomes a *surface* manifest. That is the right direction, and the honest statement of where it ends:
the manifest can only ever see what the generated stubs spell out. Field numbers, wire types,
presence semantics, and oneof membership are covered upstream by `buf breaking` in seam-runtime, and
this repo depends on that being true. That dependency is worth stating in the manifest header rather
than being an unwritten assumption — if seam-runtime's `buf breaking` job were ever removed or made
advisory, several of this repo's gates would quietly weaken with no signal here.

Phase 5 is the one that admits a real design tension: the local/CI split exists because stubs are
deliberately not committed, and that is the right call (it forces the BSR to be the source of truth).
The cost is a gate that is structurally red for every local reader. The lag file manages the cost;
it does not remove it. If the split ever becomes permanent rather than a window, the better answer
is a committed surface snapshot regenerated in CI — noted here, not built now.

Phase 3's inversion is a small change with a durable property: it is complete by construction and
cannot rot as the sibling repo grows. Prefer that shape wherever a gate names things it must reject.

## Enterprise concerns

- **Reliability of the publish path** — Phase 2 closes the last known way a wheel with false
  dependency metadata reaches a consumer. After it, both floors have a derivation that refuses what
  it does not recognise *and* an install-at-the-floor truth check.
- **Observability of the gates themselves** — Phase 5 is really an observability fix: the gate was
  emitting a signal indistinguishable from a different, serious signal.
- **Security-adjacent** — Phase 3 guards the verifier's independence claim, which is the product
  property `verify/` exists to assert. A gate that cannot see a third of the crates it must exclude
  is a weak assertion of a strong claim.
- **Rollback** — every phase is a self-contained commit; none changes a published artifact, a
  registry, or a wire format. Phase 8's `.gitignore` edits are the only changes that alter what a
  fresh clone sees, and both are strictly corrective.

## Open questions

1. **Should the enum manifest carry numeric values as well as names?** Decided: no. The numeric value
   is what `buf breaking` protects upstream, and duplicating it here creates a second thing to update
   on every regeneration for a case already covered. **Corrected post-hoc:** this was NOT recorded as
   a scope line in the manifest header — `contract/field-manifest.txt` is generated from the stubs by
   `--write-manifest` and is off-limits to hand-edit, and no such line was ever added there. What
   actually carries the decision is an `UNCONFIRMED` `ASSUMPTIONS.md` entry ("The enum manifest
   carries names only, not numeric tags"), added after the fact — revisit it if an enum is ever
   renumbered without its name changing.
2. **Should `plans/` come under the citation guard?** Decided: no. Historical plan records document
   what was true when written; forcing them to resolve against current code would either freeze the
   code or falsify the record. `PROGRESS.md` is different — it is read as current state by the next
   run. Logged as an `ASSUMPTIONS.md` entry ("`plans/` stays outside the citation guard;
   `PROGRESS.md` does not"), added after the fact, so the distinction is explicit rather than
   incidental.
3. **Does `contract/expected-local-lag.txt` become a permanent excuse?** Open. Mitigated by the date
   stamp, the age print, and `--write-manifest` invalidation, but the honest answer is that it
   depends on the ACDP regeneration window actually closing. Logged `UNCONFIRMED` in `ASSUMPTIONS.md`
   ("`contract/expected-local-lag.txt` is a window, not a permanent excuse"), added after the fact,
   with a re-open trigger: if the file is still present and matching 60 days from now, the split is
   not a window.

## Post-merge-gate record: the plan reproduced its own defect three times

Worth stating plainly, because it is the plan's own subject turned on the plan:

1. **A vacuous acceptance criterion** (Phase 8). `git check-ignore CLAUDE.md` returns nothing for any
   *tracked* file by git's design, so the criterion read as passing before the fix existed.
2. **Two vacuous tests** (Phase 5). The superset and subset tests — the only evidence that a real
   field removal cannot hide behind the expected ACDP lag — pointed `SEAM_EXPECTED_LOCAL_LAG` at a
   file the fixture never created, so the downgrade's first conjunct was false by construction and
   they passed whatever the comparison did.
3. **Six citations green for an environmental reason** (Phase 6). `../seam-runtime/…` did not match
   the sibling-repo prefix tuple, so they resolved against this checkout — and passed only because
   the sibling repos happen to sit beside it. Reproduced red in the runner's layout.

And then, fixing (2) produced a fourth: the de-vacuumed tests became **environment-dependent in the
opposite direction**, asserting `exit 6` on an ambient pre-ACDP tree and failing in CI, which
regenerates to the post-ACDP surface first. Caught by CI on PR #89, not by any local run. The tests
now *construct* the lag scenario from stripped scratch stubs, so they assert the same property in
both environments.

The common thread across all four: **the check's result was determined by something other than the
property it names** — the file's tracked-ness, a fixture's omission, the machine's directory layout,
the ambient stub state. That is the same defect the eight phases were written to remove, and it was
found three times by adversarial verification and once by CI, never by a passing local suite.

The operational lesson, which is cheap and was not being applied: **an acceptance criterion needs the
same red-first proof a test does.** Run it against the unfixed state and confirm it fails. Nothing in
this plan's own review process did that, which is why all three shipped past it.

## Plan review

Drafted by Opus from a Fable adversarial audit (read-only, mutation-proofs in a scratch copy). Every
load-bearing claim in Phases 3, 6, 7 and 8 was independently re-verified against the working tree
before the plan was written — the two rotted `ts/src/client.ts` anchors, the generated-tree anchor,
the six missed runtime crates, the `UNFILED`/filed contradiction, and the `.gitignore`/index
disagreement were each reproduced directly rather than taken from the audit. Phase 1's enum blindness
was confirmed by inspecting `contract/field-manifest.txt` (zero `#` lines) against the three enums at
`python/seam_sdk/_gen/seam/api/v1/seam_pb2.pyi:11-33`.
