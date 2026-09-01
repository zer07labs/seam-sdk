# Decisions

The durable record of `/reconcile` passes over `ASSUMPTIONS.md`. Each entry: the original
assumption, the independent recommender's analysis, the human verdict, and the resulting status.
`/ship` and any later reconciliation read this file instead of replaying the conversation that
produced it.


## 2026-08-31 — `plans/post-adoption-hardening-and-acdp-readiness.md` Phase 8 (issue #73): citations into vendored files are quoted, never line-anchored

### Citations into vendored files are quoted, never line-anchored

- **Context.** `verify/docs/seam-event.v1.md` is a byte-verbatim copy of seam-runtime's
  `docs/specs/seam-event.v1.md`, refreshed **whole-file** by policy — `scripts/check_vendored_spec.py`
  asserts the copy is upstream's bytes under a header, so a refresh replaces the entire body rather
  than patching it. One `DECISIONS.md` citation pointed into that body at a line number.
- **The failure, three times over.** Every upstream insertion above the cited sentence shifts it, so
  the citation went stale on each refresh: PR #71, PR #72, and again on the ACDP P1a/P2 refresh in
  this run. Each repair was a one-line bump carrying no information — and each was an opportunity to
  "resolve" the citation onto a plausible wrong line, which is the failure the citation test exists
  to catch, not one it should be generating. This is structural, not carelessness: a line number is a
  claim about a file's *layout*, and a vendored copy has no stable layout by design. The rot rate is
  set by upstream's commit cadence, which this repo does not control and cannot slow down.
- **Decision.** No checked document may line-anchor into a vendored path. Enforced mechanically by
  `VENDORED` in `python/tests/test_compatibility_citations_resolve.py:101`, over every document in
  `DOCS`, with a red-first test proving the guard fires on a line anchor and leaves both sanctioned
  alternatives alone (`python/tests/test_compatibility_citations_resolve.py:145`).
- **What to do instead**, in preference order:
  1. **Cite the upstream file** with its `seam-runtime/` prefix. It is the actual source of the
     sentence, and `SIBLING_PREFIXES` already skips it when the sibling repo is not checked out. The
     line number still rots there, but it rots in the repo that owns the file and can see the edit.
  2. **Quote the sentence** and register it in `QUOTED`
     (`python/tests/test_compatibility_citations_resolve.py:318`). The check asserts the needle is
     unique in the target, that the document quotes it verbatim, and that the document still
     attributes it to that path — no line number on either side.
- **Widening `CITATION_SLACK` was considered and rejected.** Slack large enough to absorb a
  whole-file refresh is slack that no longer distinguishes a correct citation from a wrong one, and
  it would weaken every non-vendored anchor to buy tolerance for the one case that should not be
  line-anchored at all. Issue #73 rules it out for the same reason.
- **The one existing anchor was converted, not grandfathered.** The plan permitted either. Converting
  won because Phase 9's regeneration half refreshes that same vendored file again — grandfathering
  would have left a known-doomed anchor in place across the exact event it was doomed by. The quoted
  form is also strictly stronger than what it replaced: an anchor confirms the document points at the
  line holding the sentence, while the quote confirms the document and the file **say the same
  words**. A refresh that silently reworded the sentence would satisfy a dutifully-repointed anchor
  and fail the quote check, which is the right way round.
- **Scope, and what remains open in #73.** This covers `verify/docs/` — the only tree this repo
  vendors verbatim — and it stops new line anchors from being added there. It does **not** convert
  the nine remaining `ANCHORED` entries into non-vendored files; those point into files this repo
  edits itself, where a line number is a claim about our own layout and a drifting one is a real
  signal. The adjacent case is recorded here rather than fixed: `COMPATIBILITY.md`'s "No yank"
  citation into `CHANGELOG.md` was repointed **five times in this session** (`:521-526` → `:538-543`
  → `:540-545` → `:563-568` → `:586-591`) because a changelog grows at the top. That is the same
  zero-information churn with a different cause — an append-only file rather than a vendored one —
  and the same conversion would fix it. It is deliberately out of scope here: `CHANGELOG.md` is ours,
  the fix is a mechanism change to a check that is currently working, and #73 has not decided whether
  the rule should widen from "vendored" to "any file whose line numbers are structurally unstable".


## 2026-08-31 — `plans/post-adoption-hardening-and-acdp-readiness.md` Phase 10 (issue #52): the 0.7.39-0.7.43 band is documented, not deleted

### A whole-surface field manifest, not an ACDP-shaped probe

- **Context.** `contract/rpc-manifest.txt` closed "a new verb landed and nobody wired it". It is blind
  one level down. That blindness is not theoretical: `collective_outcome` regenerated in and sat
  unread on `DecisionResponse` and then on `SessionStep`, and the four ACDP D3 receipt slots plus P2
  `retraction` landed on `ContextBinding` with every gate green — CI regenerates from the BSR on every
  run, so the SDK had already *built* against all five and noticed nothing.
- **The narrower option, and why it lost.** An `ACDP=1` flag mirroring the `STREAM=1`/`EVENTS=1`
  pattern (`scripts/check-contract.sh:53`) would have caught these five fields and nothing else. It
  treats ACDP as special when the defect is general — the gate had never watched fields at all — and
  it has to be *remembered* at each change, which is the exact property `rpc-manifest.txt` was
  introduced to remove. A probe you must remember to add is a probe that will be missing on the change
  that matters.
- **Decision.** Mirror the RPC manifest exactly one level down: a committed declaration
  (`contract/field-manifest.txt`), set-compared per language in both directions
  (`scripts/check-contract.sh:383`), exiting 6 with the field named (`scripts/check-contract.sh:501`). `STREAM`/`EVENTS` stay as
  they are — they gate *event* fields for a different reason (BSR publication lag) and are not what
  this replaces. Scope is `seam.api.v1` only; `seam.event.v1` is already covered by those probes and
  by the vendored-spec gate, and duplicating it would mean two gates failing for different reasons on
  one cause.
- **Two extraction traps, both live in the stubs today rather than hypothetical.**
  1. **Do not read `__slots__`.** `ResumeRequest.raise` and `AdminResumeRequest.raise` are real
     fields, but `raise` is a Python keyword, so the `.pyi` generator emits neither an attribute nor a
     `__slots__` entry — only `RAISE_FIELD_NUMBER`. Measured: `__slots__` gives 221, protobuf-es gives
     223. A `__slots__`-derived manifest is permanently red on two fields the documented escape can
     never clear, and blind to any future field named `class`, `from`, `import`, `lambda`, `return`…
     Reading `*_FIELD_NUMBER` lowercased reconciles both sides at 223 = 223, zero diff.

     The lowercasing has a second edge, found in verification: protoc emits `MYFIELD_FIELD_NUMBER` for
     a `myField` proto field, so the Python side can only ever produce `myfield`. An un-folded TS side
     yields `myField`, and the two diverge permanently — again unclearable by the escape. Both sides
     now fold case. Two spellings cannot coexist in one message, so nothing is lost, and it is a no-op
     for every snake_case field, which today is all 228. Note the two hazards have OPPOSITE fixes:
     `__slots__` would have carried `myField` correctly and drops `raise` entirely.
  2. **Exclude synthetic map entries by *nesting*, never by the name `*Entry`.** Python emits
     `AuthorizeRequest.FeaturesEntry` and `RunDecisionRequest.FeaturesEntry`; protobuf-es emits no type
     for either. Filtering on the name looks equivalent and is not: **`AuditEntry` is a real top-level
     message** with `seq` and `decision_id`, and a name filter drops it from *both* sides — symmetric,
     so the gate stays green while going blind to a real message. That is this manifest's own failure
     mode, reintroduced by the fix for a different one. The exclusion is structural on BOTH sides:
     Python keys on indentation (top-level classes at column 0, their fields at four spaces, a nested
     class's at eight and never collected, `contract/field-manifest.txt:48-50`); TypeScript keys on the
     **dot** in protobuf-es's nested type name. Verification caught that the TS half was missing: the
     top-level pattern cannot match `seam.api.v1.Outer.Inner`, so `cls` silently retained the PREVIOUS
     message and a nested type's fields were attributed to it — not excluded, *misattributed*, which is
     worse, and unclearable by a Python-authoritative escape. It was latent only because protobuf-es
     emits no type for map entries, which is an accident of this contract rather than an exclusion.
     Pinned by `python/tests/test_field_manifest_gate.py:292`.
- **The escape names its authoritative side.** `--write-manifest` writes **both** manifests from
  **Python** (`scripts/check-contract.sh:262`), with TypeScript as the cross-check
  (`scripts/check-contract.sh:210`) — one command to document, not two. If it wrote from a side that cannot see every field, it
  would produce failures the documented escape could never clear, which is exactly what `raise` does
  under a `__slots__` extractor.
- **The refusal deliberately puts the escape second.** It says decide first, then run it
  (`scripts/check-contract.sh:495`). A failure message that leads with the fix trains the reader to
  run the fix, which turns the gate back into the silent pass it replaced.
- **What it does NOT check: names only, not tags or types.** A field retagged or retyped is
  wire-breaking and invisible here, exactly as the RPC manifest records names and not signatures.
  `buf breaking` covers that; a green gate here is not a wire-compatibility claim.
- **The cost, stated rather than discovered.** Every additive proto field now reddens CI until someone
  decides and runs the escape. That is the same trade already accepted for verbs. Measured churn is
  low — zero fields were added across the last 78 runtime commits before ACDP — and the first thing
  the gate did was refuse five real ones, which is the trade paying out immediately.
- **Both extractors and the manifest reader pin `LC_ALL=C`.** A bare `sort` follows the ambient locale,
  and under `en_US.UTF-8` the documented escape reordered eight lines with zero contract change. The
  gate's verdict was never affected (both sides re-sort at compare time), but a one-command escape
  whose diff is full of phantom moves is not the reviewable diff the plan requires it to be.
- **The five ACDP fields are declared and deliberately NOT interpreted.** The gate refused them (exit
  6, naming all five in both languages); that refusal forced a decision, and the decision is recorded
  in the manifest header itself rather than only here. They are carried — `resolve_context` returns
  `pb.ContextBinding` directly — but not read: this SDK does not compute `context_digest`, and
  `verify/src/verify.rs` does not read these slots. `key_status` is a closed PascalCase vocabulary and
  `resolved_status` an open lowercase one, both byte-identical to the digest preimage, so any SDK-side
  re-spelling silently breaks third-party recomputation. Declaring without interpreting is what stops
  that happening by accident. Wiring them is Phase 9.
- **Falsifiability.** Both directions are driven red in `python/tests/test_field_manifest_gate.py:158`
  and `python/tests/test_field_manifest_gate.py:183`, against temporary copies so no test can corrupt
  the gitignored stub trees.
- **Status:** ACCEPTED.

### The decision

**Do not yank 0.7.39 through 0.7.43. Document them.** `COMPATIBILITY.md:134` carries the row and
`COMPATIBILITY.md:101-128` the disposition; this entry is the reasoning behind it, and exists
because a decision that is only implied gets re-litigated by the next person to read the issue.

`yank.yml` stays available and has been repaired (below) so that it would work if this is ever
revisited. Nothing was deleted from any registry, and no workflow was dispatched to reach this
conclusion.

### The rule this follows

**Delete when a defect corrupts silently or is a security hazard. Document when it fails loud.**

The distinction is **corruption and security — not diagnosability.** A wheel that writes wrong
bytes, or accepts a signature it should reject, gives nobody anything to notice: the damage is done
before anyone knows to look, and the only remedy is to make the artifact unobtainable. A wheel that
fails, even confusingly, leaves untouched the thing you would have had to undo. Deleting the second
class buys no protection a document does not already provide, and costs the one thing deletion
always costs — it breaks whoever was working.

Diagnosability cannot be the line, and the precedent below is why: 0.7.16-0.7.19 failed with an
actively misleading error, and was documented rather than deleted. It corrupted nothing. That this
band is *also* self-diagnosing makes it an easier call, not a differently reasoned one.

### Issue #52 recommended the opposite, and it deserves the argument, not silence

#52 recommends yanking, on two grounds. Both are answered here rather than passed over.

**"Unlike the 0.7.13-0.7.19 window, 0.7.43 is hours old and unlikely to be in anyone's lock yet, so
the blast radius of yanking is much smaller than it was there. That was the stated reason not to
yank before, and it does not apply here."** The last sentence is aimed squarely at the precedent
this entry leads with, so it goes first: it is **right**. *"A floor already in wide use"* does not
describe this band, and that limb is not relied on — `COMPATIBILITY.md:101-128` scopes it to the
first two bands for exactly this reason. What the precedent bullet below turns on is **defect
severity**, which the objection leaves untouched: the milder defect would be deleted while worse
ones stay installable.

On the blast radius itself: that was true when written and has since inverted. A week on,
the absence of locks no longer means *nobody has it* — it means anyone who installed it resolved
`protobuf` freely, got 7.36.0, and **is working right now**. Deleting turns a working install into
a hard resolution failure at their next `pip install`. The fact that nothing pins the version is
what makes deletion cheap for us and expensive for them.

**"(1) alone leaves a wheel published whose metadata is untrue, which is a different and worse
thing than a wheel that is honestly broken."** This is the stronger point and it is conceded in
part: the metadata *is* untrue. What makes it survivable is that it is **self-detecting**.
protobuf's generated preamble calls `ValidateProtobufRuntimeVersion`, which raises on the first
`import seam_sdk`, naming both versions. The wheel cannot quietly do the wrong thing — the untrue
metadata is caught by the very mechanism the metadata is about, at the earliest possible moment,
before any call reaches a runtime. An honestly-broken wheel and a wheel whose lie fails closed on
first use are closer together than the framing suggests.

**And the action #52 sized no longer exists.** It weighed deleting *one* release, hours old. The
measured band is **five** — 0.7.39 through 0.7.43 — because the lower edge turned out to be
recoverable from CI history (see the divergence note below). Deleting five releases published over
four days is a materially different act from deleting one, and the case for it was never made.

Its third option — re-release with a corrected floor — is already satisfied: **0.7.47 shipped the
fix**. The remedy #52 wanted is available to every consumer today. What remains is only whether to
destroy the bad artifacts, which is the narrower question answered above.

### The evidence, each checked rather than assumed

- **The precedent already covers worse.** `CHANGELOG.md:523-528` records no-yank for 0.7.13-0.7.19,
  which failed *harder*: 0.7.13-0.7.15 were unimportable for everyone, and 0.7.16-0.7.19 failed
  every `authorize()` with an actively misleading "admission ticket is not valid" when the ticket
  was fine. This band breaks only consumers who cap `protobuf` below 7.36.0. Deleting the milder
  defect while documenting the worse ones inverts the precedent without saying so.
- **No lockfile in the workspace pins it.** Checked 2026-08-31 across every `uv.lock`,
  `package-lock.json` and requirements/constraints file in the sibling repos: no pin on any version
  in the band. The only `seam-sdk` entry in `seam-adapters/uv.lock` is `0.7.9` via an editable path
  source. The other workspace matches for "0.7.43" are prose in documents and tests, not
  dependencies. (Read alongside the inversion above — this fact cuts toward *not* deleting.)
- **Deletion would destroy a healthy artifact.** The defect is Python-only: v0.7.43's
  `ts/package.json` depends on `@bufbuild/protobuf` at `^2.12.1`, a caret range, and protobuf-es
  has no analogue of Python's gencode/runtime hard gate. But `yank.yml` deletes python **and** npm
  together — the format filter is a fixed allowlist with no input to narrow it. Running it as
  written would break registry lockstep between the two published languages for a defect only one
  of them has.
- **The harm is asymmetric.** A consumer with the band installed and `protobuf` unconstrained is
  unaffected today. Documentation costs them nothing and warns the ones who are affected; deletion
  costs the unaffected ones a broken build and gives the affected ones nothing they do not already
  get from a `VersionError` naming the fix.

### Rejected alternatives

- **A dry-run probe first, to see whether the artifacts are still there.** It would answer a
  question the recommendation does not turn on: present or absent, the reasoning above is
  unchanged. It buys a workflow dispatch and no information.
- **Python-only deletion.** `yank.yml` cannot express it — there is no format input, by design
  (`.github/workflows/yank.yml:74`), and adding one widens what a destructive tool can do. That is
  its own reviewed change, not a side effect of a decision record.
- **Cloudsmith quarantine** — blocks download, retains the artifact, reversible. This is the
  genuinely better middle path *if* blocking installs is ever wanted, and it is the one option
  worth raising rather than settling unilaterally. Not taken now: it has the same cost to a working
  consumer as deletion, without deletion's finality to justify it. Logged in `ASSUMPTIONS.md` as
  the open question.

### Divergence from the phase as planned

The plan asked this entry to record the band as **"at least" 0.7.40-0.7.43**, with the reason the
lower bound is unrecoverable: `_gen/` is gitignored, so no per-tag gencode survives. **That premise
was wrong and the phase before this one corrected it.** The evidence is not in the tree but in CI:
`v0.7.38` is green on the floor-vs-gencode test and `v0.7.39` is the first red, through 0.7.43,
returning to green at 0.7.47. Both edges are proven, the band is five releases rather than four,
and no hedge is recorded because none is warranted.

That correction strengthens the no-yank case in one direction and weakens it in another, which is
worth stating plainly: five artifacts is a larger footprint than four, but it also means #52's
"one hours-old release" framing no longer describes the choice.

### The `yank.yml` token fix, and why a latent bug in a safety tool matters

`yank.yml` resolved its credential as `${CLOUDSMITH_API_KEY:-$CARGO_REGISTRIES_ZER07LABS_TOKEN}`,
without stripping the `"Bearer "` prefix the org Cargo token carries — a strip `.github/workflows/publish.yml:371`
has always done. The effect: Cloudsmith receives `X-Api-Key: Bearer …`, returns 401, and `curl -sf`
under `set -euo pipefail` aborts before any DELETE.

**It fails closed, which is exactly why it is worth fixing.** No wrong deletion was ever possible.
What was not possible either was the tool working at all — including in dry run — unless the
dedicated secret happened to be set. A safety tool that silently does not work is worse than one
known to be broken: the defect is discovered during the incident, by the person who needed it.

The fix resolves both sources with the prefix stripped (`.github/workflows/yank.yml:55-60`), written
as an explicit `if` rather than `publish.yml`'s `&&` one-liner because this step runs under
`set -euo pipefail`, where an AND-list's exit status is a rule most readers do not hold. Fail-closed
is preserved, and precisely: a source that is *only* the prefix strips to empty and is skipped —
refused outright when it is the sole credential (`.github/workflows/yank.yml:62`), and otherwise
falling through to the other source. The inputs this refuses are a **superset** of what it refused
before the fix, so no shape that previously refused can now proceed.

The scoping was **not** touched. Exact version equality, the python+npm format allowlist, and the
exact-name match that keeps the org's Cargo crates unreachable are all unchanged — and are now
pinned by `scripts/test_yank_gate.py`, which executes the credential resolution rather than reading
it and asserts the three filters. It runs in `workflow-guards` (`.github/workflows/ci.yml:585`),
needs no credential, and was proved falsifiable three ways: restoring the original one-liner,
widening the format filter, and flipping the dry-run default each turn it red.

## 2026-08-31 — `plans/post-adoption-hardening-and-acdp-readiness.md` Phase 6 (issue #52): the publish path re-derives the floors it ships

### The mechanism, and why a green `ci-green` could never have closed it

`v0.7.43` declared `protobuf>=7.35.1,<8` in metadata while bundling gencode emitted by protoc
7.36.0. protobuf's generated preamble calls `ValidateProtobufRuntimeVersion`, which raises when the
*installed* runtime is older than the gencode — so the wheel's own stated minimum was a version at
which it could not be imported. It shipped anyway — and, correcting this entry's own first
telling, **CI was red when it did**: all three `ci` runs at `ff0139a` failed, on that exact
floor test. Which mechanism this phase closes turns on that, so it is worth being exact.

**There are two separate paths to shipping this defect, and `v0.7.43` took the first.**

*Path one — publish past a red gate.* The floor test was failing and `publish.yml` never consulted
the result. That is what happened, five times over four days: 0.7.39 through 0.7.43 each published
while `ci` was red on it. `ci-green`, added in #51, closes this path.

*Path two — a genuinely green CI, then a skew at publish time.* `ci.yml` runs
`python/tests/test_protobuf_floor.py`, which derives the required floor **from the stubs generated
in that run** and compares it to `python/pyproject.toml:50`. The publish job then regenerates the
stubs from scratch — against buf's *unpinned* remote plugins (`buf.gen.yaml:29`) — and nothing
re-checked the floor against **those** stubs. The two runs measure different artifacts, and only one
of them is the artifact that ships. **No release is known to have taken this path, and until this
phase nothing closed it** — which is why the phase exists.

This is why Phase 6 could not be discharged by strengthening the CI gate, and why `ci-green` is
necessary but **not sufficient**: it answers *did CI pass for this commit?*, which closes path one
completely, while path two lives entirely in the gap between what CI measured and what publish
built — where the honest answer to that question is *yes*. The headroom is currently **zero**: the declared floor and the emitted gencode
are both `7.36.0`, so the very next remote-plugin roll between a CI run and a publish reproduces it.

### Why a floor-pinned install, rather than pinning the buf plugins

Pinning `buf.gen.yaml` to fixed plugin versions is the obvious alternative and it is the wrong
trade. The floor is **derived** precisely because the codegen moves on its own schedule; pinning the
plugins converts a self-correcting derivation into a number someone must remember to bump, and the
failure mode of forgetting is silent — old gencode, indefinitely, with no signal. It also would not
answer the question that matters. Both existing smokes install `protobuf` unconstrained, so they
resolve the *newest* runtime, which by construction satisfies any gencode; neither could have caught
`0.7.43`, and neither could catch its successor.

So the publish job does two things instead. It re-runs the floor guards against the stubs it just
generated (`.github/workflows/publish.yml:340`), and it installs the built wheel into a clean venv
with `protobuf` pinned at the floor the wheel itself declares, then imports the generated module
there (`.github/workflows/publish.yml:413`). The second is the one that asks *is this metadata
true?* — it reproduces exactly the resolution a consumer gets when their dependency closure caps
protobuf at our stated minimum. The floor is parsed out of the wheel's own `pyproject.toml` rather
than hardcoded, and an unparseable pin **refuses to publish** rather than falling back to an
unconstrained install; a silent fallback would restore the blind spot the step exists to remove.

### Accepted trade-off: a failure here can half-publish, and that is the safer half

The floor check runs inside the `python` job, after `python -m build` and before `twine upload`, and
the `npm` job publishes independently. So a wheel that fails the floor check leaves npm published and
PyPI not — a version live in one registry and absent from the other.

The alternative was a shared validation job gating both uploads. It was rejected: the `python` job
already builds, smokes, and uploads the *same* `dist/*.whl` in one step, so extracting validation
would mean rebuilding the wheel in the gate — introducing a validated-vs-published skew of exactly
the kind this phase exists to remove. Between the two failure modes, a half-published version is
recoverable by a patch release and is visible immediately; a wheel whose declared floor is a lie is
neither, and it fails in the consumer's process rather than ours. The half-publish is accepted
deliberately, not overlooked.

### The guards are executed, not read — which caught a defect in this very change

`scripts/test_publish_gate.py` drives both new steps against stub trees rather than asserting on
their text: a stub `pyproject.toml` whose floor trails a stub gencode constant must fail the real
extracted step (`scripts/test_publish_gate.py:330`), and a matching floor must pass it, so the red
case is red for the floor rather than for a broken harness. The same file drives the tag-ancestry
guard against throwaway git repos (`scripts/test_publish_gate.py:510`).

That was not ceremony. The first draft of the ancestry step ran `git fetch --no-tags --depth=0`,
which git rejects outright — *"depth 0 is not a positive number"* — and would have failed every
publish. It survived a read-through and died the first time it was executed, which is the same
argument the `ci-green` tests in that file already make (`.github/workflows/ci.yml:573`).

A third defect was subtler and is worth stating as a rule. `test_protobuf_floor.py` **skips** when
the generated tree is absent, and pytest exits **0** when every selected test skips — only *zero
collected* is exit 5. So a `make generate` that succeeded while writing `_gen` somewhere the package
cannot import from would have left the re-derivation step green having measured nothing, which is
the same "green because it never ran" shape the step exists to remove. Writing `_gen` unimportably
is not a hypothetical failure here — it is what this job did when it ran raw `buf generate`. The
step now asserts the file is present before invoking pytest, and a test drives that case red. **The
rule: a guard that delegates to a suite which can skip must assert its own preconditions, because a
skip and a pass are the same exit code.**

### The tag-ancestry assertion, filed under the same phase

`publish.yml` triggers on a tag push, and a tag can be created from any local commit. `ci-green` then
resolves *that commit's* check runs, which a pushed branch happily has. Nothing asserted the tagged
commit was ever on `main`. `version-check` now refuses a tag whose commit is not an ancestor of
`origin/main` (`.github/workflows/publish.yml:176`), and its checkout takes full history because
`merge-base --is-ancestor` cannot answer in a depth-1 clone.

## 2026-08-25 — `plans/authorize-single-canonicalization.md` (issue #60): one derivation, and the integer rule that is not a magnitude test

### Widen the integer arm rather than narrow the float arm

The two arms disagreed about one number: `1e16` was accepted, `10**16` refused. Narrowing the float
arm would have made the Python SDK refuse `{"t": 1e16}` — a legal RFC 8785 value TypeScript accepts
and the runtime-owned vector's own `1e21` case shows the runtime handles — turning working calls into
failures. Wrong direction. The int arm was the one describing reality incorrectly.

### The predicate is "does JCS render this integer as itself", not "is it exactly representable"

This is the decision worth recording, because the obvious alternative is wrong in the expensive
direction and the first draft of this work shipped it.

`int(float(v)) == v` — exact representability — reads as equivalent and is not. `2**60` is exactly
representable, but ES6 `Number::toString` prints the **shortest round-tripping** digits, so JCS
renders it `1152921504606847000`, not `1152921504606846976`. Under that predicate the SDK would have
accepted `2**60` and signed a digest over a number the caller never supplied — silent corruption, in
a value `call_sig` signs, in the direction nothing downstream can detect.

The two predicates diverge from about `2**55`, not at the `10**21` decimal-to-exponential boundary
intuition suggests, and they **agree on every power of ten**. That last fact is why this nearly
shipped: the verification behind the first draft sampled powers of ten and boundary values, which is
exactly the sample on which the wrong rule looks right. A randomized corpus separates them
immediately — the wrong predicate breaks 1,996 of the committed corpus's 2,000 round trips. The test that proves the
property is therefore randomized on purpose (`python/tests/test_jcs_roundtrip_stability.py:120`), and
a companion test asserts the tidy corpus would *not* have caught it.

The chosen rule also carries its own safety argument for an irreversible widening: every byte string
the integer path can emit is one the float arm could already emit, so no new wire shape exists for a
conformant runtime to disagree with. The `10**21` cap falls out for free — a plain decimal form can
never match an exponential rendering — rather than being a separate rule anyone has to maintain.

### The `int.__repr__` hardening is the int arm only, and the other arms stay spoofable

Rendering the integer through unbound `int.__repr__` closes one real hole: on Python 3.10, this
package's floor, `str(SomeIntEnum.MEMBER)` is `"Color.RED"`, so the previous `str(v)` put invalid
JSON inside a signed digest. It must be `__repr__` and not `__str__` — `int` defines no `__str__`, so
the unbound `int.__str__` falls through to `object.__str__` and re-enters the subclass's `__repr__`,
which is strictly worse than the bug.

**It does not generalise, and saying so is the point of this entry.** JCS reads every value through
overridable methods, and the other arms are still spoofable by a subclass that *lies* rather than
raises: a `float` subclass overriding `__abs__` (`python/seam_sdk/crypto.py:203` renders
`repr(abs(v))`), a `str` subclass overriding `__iter__` (`python/seam_sdk/crypto.py:175`), a `dict`
subclass overriding `__iter__` to drop keys. `CanonicalizationError` covers subclasses that raise;
nothing covers ones that lie.

That is judged acceptable rather than overlooked. It is a caller attacking its own input, under its
own signature — the same trust model `canonical=` operates in, and the caller could simply pass
different values instead. The int arm was hardened because a *non-malicious, stdlib* type hits it by
accident; no stdlib type lies in the other arms. If that stops being true, the fix is the same shape
and belongs here.

### The SDK does not validate `canonical=`, and that is the design

Re-canonicalizing the caller's bytes to check them would reinstate the second derivation the
parameter exists to remove. Only what is checkable *without* re-deriving is checked — `bytes`,
non-empty (`python/seam_sdk/_authorize.py:140`). `bytearray` and `memoryview` are refused with the
rest: a mutable buffer could change between the digest being taken and the bytes being assembled onto
the request, which is the same two-derivations-disagree bug in a place nobody would look for it.

What this permits is bounded. A caller can only misrepresent its own input, which it already
controls, under its own signature, and the digest stays self-consistent — so the runtime sees nothing
different. Two consequences are real and are recorded in `COMPATIBILITY.md` rather than waved off:
with `digest_only` a signature can be bound to a digest of bytes never revealed, and non-canonical
bytes in an advisory audit row break third-party re-derivation. Whether the runtime validates
canonicality at all is filed upstream; it cannot be answered from this repo under the clean-room
constraint.

### `CanonicalizationError` lives in `errors.py` and is raised from `_authorize.py`, because it cannot be both

Ask 3 of #60 wanted canonicalization failures typed as `SeamError`. The obvious implementation —
raise it from `jcs_canonicalize` — is unavailable, and the reason is a genuine collision between two
existing cross-repo contracts rather than an oversight:

- the whole `SeamError` tree must be defined in `errors.py`, because `seam-adapters` loads that one
  file standalone and diffs its hierarchy against classification rosters
  (`python/tests/test_errors_is_import_light.py:513`);
- `crypto.py` may import `cryptography` and nothing else, with no relative imports, because
  seam-runtime's `sdk-digest-parity` gate loads *that* one file standalone
  (`python/tests/test_errors_is_import_light.py:86`). `errors.py` imports `grpc`.

So `crypto.py` cannot import the taxonomy. This is the same tension that already made
`RecordDigestStripError` a bare `ValueError` living in `crypto.py`; repeating that trick here would
have defeated the purpose, since a non-`SeamError` is invisible to the adapters roster and lands in
the transport bucket exactly as the builtins did. The typed error is therefore raised at the
`_authorize.py` boundary, through a new public `canonicalize_tool_input()`, and the residual — direct
`jcs_canonicalize` callers still get builtins — is stated in `COMPATIBILITY.md` and on seam-sdk#54,
where the import-light contract is owned.

The wrap catches `Exception`, not `BaseException`, and that breadth is the point rather than
defensiveness: the motivating failure, `RuntimeError: dictionary changed size during iteration`, is
raised by CPython's dict iterator, and a `str`/`int` subclass can raise anything from the dunders JCS
reads it through. It also means a genuine SDK bug — an `AttributeError` in our own code — now
surfaces as an input error; `__cause__` is what keeps that diagnosable, and is asserted.


## 2026-08-25 — `plans/record-digest-v3.md` (Phases 6a/6b/8): a tag-10 strip stays `False`; only tags 11/12 raise

**Confirmed.** `verify_streamed_record_digest` / `verifyStreamedRecordDigest` return `False` for a
`DECISION_SEALED` (v2 or v3) missing its `ciphertext_digest`, and raise the typed
`RecordDigestStripError` only for a v3 record missing `context_digest` (11) or `participation_digest`
(12).

**Why this is the right reading, not a convenience.** The spec's per-tag table (`seam-event.v1.md`
§"Presence on the wire") marks a tag-10 strip **refuse** and cites §Ordering & integrity Verification
(c) — which is written for the chain verifier, where REFUSE means the record *fails*. A helper whose
whole answer is "does this verify?" expresses a failure as `False`. The requirement that a refusal be
"reported distinctly from a digest mismatch" is attached in the spec to tags 11/12 and to nothing
else, and that distinctness is what the exception exists to carry.

**What was weighed against it.** Raising on a tag-10 strip too, for a richer diagnostic. Rejected: it
would change shipped v2 behaviour — which the standing "`record_digest_v2` must stay byte-identical
forever" constraint covers behaviourally as well as byte-wise — and would invent a distinction the
contract does not ask for. Inventing distinctions in a verifier is how two implementations stop
agreeing.

**Corroborated after the fact, in two ways this cycle.** Phase 8's gate walked the spec independently
and reached the same reading. And Phase 8's cross-language table now shows Rust, Python and TypeScript
returning the same verdict on identical spliced bytes for all six absence cases — so the choice is not
merely defensible, it is the one all three implementations actually make.

**Known consequence, accepted.** A v3 record stripped of tags 10 *and* 11/12 reports `False` rather
than the strip raise: an adversary who strips both gets the quieter diagnostic. The record fails
either way, so nothing verifies that should not; the cost is diagnostic richness, not integrity. It is
documented in both helpers' source rather than left to be rediscovered. Reversible in one line.

## 2026-08-24 — reconcile `plans/record-digest-v3.md`'s ASSUMPTIONS.md (4 entries)

Issue #56, Phases 3–4.5. The owner delegated the call on all four to a Fable reviewer rather than
taking it personally; it verified each against the code, the spec and the tests rather than against
the entries' own reasoning, which matters here because every entry was written by the person who
made the choice and is therefore an argument for itself. **All four CONFIRMED; none blocked the
merge.** One entry's stated reasoning was corrected in the process — recorded below as corrected,
not as written.

### v3 validates every input; v2 deliberately still does not
- **Reviewer (Fable):** CONFIRM, with the reasoning corrected. The alias argument is empirically
  true **in TypeScript** — verified by execution, not by reading: a 32-character string frames
  byte-identically to 32 zero bytes (`Uint8Array.set` coerces each char ToNumber→NaN→0), and
  `setBigUint64(2**64+5)` writes the same eight bytes as `5`. **In Python those same two inputs
  raise rather than alias**, so the entry's unscoped "three of these coercions produce an alias" was
  over-generalized. Python's validation still earns its place by a different route: v2 accepts a
  `memoryview(array("I", [0]*32))` and produces a digest whose length prefix claims 32 while 128
  bytes are hashed — the exact injectivity break framing exists to prevent — and v3 refuses it
  (`python/seam_sdk/crypto.py:378-408`).
- **Correction to the entry's blast-radius claim:** "every such digest was wrong, so no correct
  caller breaks" is too strong. A proto3-JSON int64-as-string (`sealedAt: "123"`) coerced
  *correctly* through `BigInt` under the old TS behavior and is now refused. The refusal is loud, at
  the first record, and names the fix (`ts/src/crypto.ts:509-522`) — and accepting strings reopens
  `BigInt("")→0n` and `BigInt([5])→5n`. The choice stands; the justification does not extend to
  "nothing that used to work stops working."
- **v2 freeze held:** `git diff main...HEAD` shows zero removed lines in `crypto.py` and a purely
  additive `vectors.json`.
- **Verdict:** Confirm. **Status:** CONFIRMED.

### The v1 skip is a downgrade hole, closed structurally rather than documented
- **Reviewer (Fable):** CONFIRM. Every load-bearing claim resolves. The guard keys on the four
  columns and never on the version alone (`verify/src/verify.rs:605-614`); a genuine v1 record falls
  through to `continue` and is tested twice — `verify/tests/authenticity.rs:238` and `:878`, the
  latter asserting skipped-not-recomputed. The per-column parametrization at `:843-875` exercises
  each column with the other three removed, and the comment at `:841` records the decoy that forced
  it. The spec sentence it rests on is quoted verbatim from `verify/docs/seam-event.v1.md`:
  `ciphertext_digest` "is absent (no wire bytes) only on `schema_version = 1` payloads." That
  quote is checked by content rather than by line number — see *Citations into vendored files are
  quoted, never line-anchored* in this file for why this one carries no `:N`.
- **Verdict:** Confirm. **Status:** CONFIRMED.

### `frame`'s `len() as u32` truncates above 4 GiB, in Rust only
- **Reviewer (Fable):** CONFIRM, and the three-way divergence (Python raises, TS wraps, Rust
  truncates) is moot because all three are **fail-closed**: a truncated prefix still appends the full
  bytes, so the preimage cannot equal the runtime's, the recompute mismatches, and the record FAILS.
  A false *pass* would need a SHA-256 second preimage. Reaching it at all needs a multi-gigabyte
  single field parsed out of one JSONL line, and a JS string cannot hold 2^32 characters.
- **Why not fix it here:** an asymmetric length guard inside v3's `frame` breaks the "v3 framing is
  v2's framing plus three slots" transcription property for zero security gain. A guard in **both**
  versions, as its own change, remains the right shape if anyone wants it — and does not need this
  entry held open to exist.
- **Verdict:** Confirm. **Status:** CONFIRMED.

### The v3 conformance cases live in a second file, not in `conformance/vectors.json`
- **Reviewer (Fable):** CONFIRM **now**, not pending seam-runtime's answer — overriding the
  suggestion that this wait on them. The factual core is verifiable today and independent of the
  outcome: `sdk-digest-parity.sh` byte-diffs the *entire* file against a fresh runtime emit, so
  SDK-authored cases in it redden runtime CI as fake drift, exactly as assumed. The extended file is
  loaded by all three suites (`python/tests/test_conformance.py:231`,
  `ts/tests/conformance.test.ts:187`, `verify/tests/conformance.rs:73`).
- **The deciding argument:** all three of seam-runtime#433's options leave the current arrangement
  correct — adopt means copy-and-delete at the same rendering, decline means the file stays. Nothing
  waits on their call, and deferring would leave `ASSUMPTIONS.md` shadowing a GitHub issue that
  already tracks the follow-up.
- **Verdict:** Confirm. **Status:** CONFIRMED. #433 owns the remainder.


## 2026-08-24 — `plans/archive/close-out-w1-w7-loose-ends.md` Phase 3: framework co-installability is a probe, not a table of versions

### Scope: the frameworks are the ones `seam-adapters` ships a shim for

Four, and no more: `crewai`, `langchain` (+`langgraph`), `strands-agents`, `claude-agent-sdk`
(`seam-adapters/crewai/pyproject.toml:13`, `seam-adapters/langchain/pyproject.toml:18`, `seam-adapters/strands/pyproject.toml:11`,
`seam-adapters/claude_agent/pyproject.toml:11`). `seam-aegis` adds nothing — it reaches frameworks only through
`seam-langchain`. A framework with no shim is out of scope; adding a shim is what adds a row.

### The mechanism, generalised past CrewAI

Issue [#48](https://github.com/zer07labs/seam-sdk/issues/48) is about CrewAI, but CrewAI is an
*instance*, not the rule. Our `protobuf` floor is **derived** from unpinned buf remote plugins, so it
moves on its own; protobuf then refuses a runtime older than the gencode. Any framework whose closure
caps `protobuf` below our floor is un-co-installable — in practice, **one that exact-pins or
`~=`-pins `opentelemetry-exporter-otlp-proto-http` below the release where `opentelemetry-proto`
lifted its own `protobuf<7` cap.**

The generalisation is worth stating because it is *not* "OpenTelemetry is incompatible": OTel lifted
the cap. `strands-agents` depends on the exporter by **range** and rides over the change; `crewai`
pins with `~=` and cannot. Same ecosystem, opposite outcome, and the difference is the pin style.

### The record is a probe, because a table of versions is stale on arrival

`COMPATIBILITY.md` §4a carries the table; `scripts/probe_framework_coinstall.py` **reads that table
as its input** and resolves each row against live PyPI, so doc and check cannot disagree. Run via
`make probe-frameworks`, weekly in `.github/workflows/framework-coinstall.yml`, and on any PR
touching the floors, the table, the probe or `buf.gen.yaml`.

It fails in both directions, and the second is the one that matters: **a row flipping to
`compatible` means the upstream fix landed**, and nothing else in this org watches for that —
`seam-adapters`' resolution-probe installs its shims *without* the `[sdk]` extra, so it stays green
either way.

**Two implementation facts, both learned by getting them wrong first:**
1. **Resolve with the shim's declared constraint, never the bare name.** Bare `crewai` resolves fine
   — by backtracking to **1.6.1**, a release predating the conflict — and reports a false
   `compatible`. With `crewai>=1.15.3,<2` the same resolver proves it unsatisfiable. A probe that
   confidently reports the wrong answer is worse than no probe.
2. **Exit codes cannot classify the outcome.** uv exits non-zero for an unsatisfiable graph, a
   missing package *and* a disabled network, and all three say "unsatisfiable". The probe classifies
   on the message and treats anything it cannot positively identify as **infrastructure (exit 2)**,
   never as a verdict.

*Rejected:* generating the table into the doc. The generator needs a staleness guard, the guard needs
the network to know what stale means, and that forces either network in the default suite or a
skip-when-offline path — both of which this repo rejects elsewhere. Doc-as-input gets the
no-disagreement property without either.

*Rejected:* a pytest in the default suite. Same skip-when-offline objection. The suite stays offline
and honest; the probe is a script with its own workflow.

### Widening our own protobuf floor: considered and rejected

It is not a metadata edit. The floor is derived, so widening means **pinning `buf.gen.yaml`'s remote
plugins** to emit older gencode — and protobuf's same-major rule (enforced by
`python/tests/test_protobuf_floor.py`) means the result is `>=6.x,<7`, not a wide `>=6,<8`.

- It **relocates** the incompatibility rather than removing it: `<7` co-installs with CrewAI and
  conflicts with everything on the current line.
- It freezes the codegen pipeline on the release source of record, indefinitely, with no owner for
  the "when do we unpin" decision.
- It does not fix the root cause — CrewAI's pin breaks it against *any* protobuf-7 neighbour.
- The 6.x line stops receiving fixes, and a `<7` cap forbids consumers from taking them.

The strongest counter — that a derived floor exports churn to consumers — is real and is stated
plainly in `COMPATIBILITY.md` §4. But the remedy for exported churn is the loud derived-floor
machinery that already exists, not a pin that converts churn into stagnation. **One upstream PR
against CrewAI's exporter pin is cheaper than a permanent pipeline pin**, and the probe is what
notices when it lands.

**Status:** RECORDED. Re-answer if a second framework becomes incompatible, or if the pin-style
generalisation above stops explaining the cases.

## 2026-08-23 — `plans/archive/sdk-exec-w1-w7.md` Phase 8 (W7): the digest dual-verify obligation

Written **before** v3 exists, because the failure this prevents is unrecoverable and the moment to
agree the rule is not the moment someone is mid-migration.

### W7.1 is DONE UPSTREAM — do not re-file it

The source plan's headline W7 defect was `compute_record_digest`'s catch-all: `1 => v1, _ => v2`,
meaning a record stamped `schema_version == 3` would be **silently hashed with the v2 framing**.

`seam-runtime` `d7f27c7` (#408, 2026-08-23) already fixed it. `seam-runtime/crates/seam-store/src/lib.rs:357-380`
now reads `1 => …`, `2 => …`, `_ => None`, with the comment *"No catch-all. An unknown stamp is
refused so it can never verify green under the wrong formula"*, and `recompute_sealed_digest` is
symmetric. **Verified directly, not taken from the plan.** Filing it would be filing a fixed bug.

### The rule, for when v3 lands

1. **Every verifier verifies v1, v2 and v3 simultaneously, selected by the record's own
   `schema_version`.** Never "latest wins", never a global flag. The version is in-band precisely so
   it can be dispatched per record.
2. **v2 code is never deleted.** A record sealed under v2 must verify in 2126. Removing a live path
   is the one irreversible mistake available here. The same applies to `compute_record_digest_v1`,
   which looks like dead code and is the only way a `schema_version == 1` record verifies.
3. **Both implementations move together** — `seam-sdk/verify/src/verify.rs` and
   `seam-runtime/crates/seam-verify` — and the differential harness must be extended to drive
   **mixed-version streams**, not just a homogeneous one. A harness that only ever sees one version
   cannot catch a dispatch bug.
4. **A KAT per version, generated from the Rust**, and the v2 vector stays forever.
5. **A mixed-version chain test** — one stream containing v1, v2 and v3 records verifying end to
   end — is the acceptance test for the whole item. A version bump that cannot produce a passing
   mixed stream is not ready.

### Two mechanics the source plan could not have known

- **Item 4 is already enforced from the runtime side.** `seam-runtime`'s `sdk-digest-parity`
  discovers vector blocks by **`record_digest_v*` prefix** (`seam-runtime/scripts/sdk-digest-parity.sh:90`), so
  the day a `record_digest_v3` block exists the gate covers it automatically rather than silently
  continuing to check only v2. Point at that rather than restating it.
- **The gate resolves the Python function by EXACT NAME** (`getattr(crypto, name)`), so
  `python/seam_sdk/crypto.py` must expose `record_digest_v3` under precisely that name. TypeScript
  (`recordDigestV2`, camelCase) and Rust (`verify/src/verify.rs`'s private `record_digest_v2`) are
  **not** checked by it — their parity rests only on this repo's own suites. **That asymmetry is
  where drift would hide**, and it is the reason item 3 says both implementations move together
  rather than trusting the cross-repo gate to notice.

### The commitment digest carries the same obligation and worse fan-out (W7.3)

`seam-commitment-digest:v1` is at v1 with no v2 planned, and is mirrored byte-for-byte in **all five**
SDK shims. Any change to what it binds costs **six coordinated edits** (five shims + the runtime), a
bumped domain label, and a permanent dual-verify obligation.

**When the need is additive, add a SEPARATE digest — do not extend v1's field tuple.** A second
digest costs one new thing; extending the tuple costs every past artifact a migration.

`verify/` is **not** a sixth mirror — it does not implement the commitment digest at all, and
`python/tests/test_framing_rationale_is_documented.py` now guards against a doc claiming otherwise.

**Status:** RECORDED. Java and Kotlin gained the length-prefix rationale they lacked (Go, Python and
TypeScript already had it), and a grep-guard keeps all five honest.

## 2026-08-23 — `plans/archive/sdk-exec-w1-w7.md` Phase 6 (W1): publishing `verify/` — to Cloudsmith, not crates.io

Three decisions, taken together because publishing is irreversible and they interact.

### `verify/` ships as a LIBRARY as well as a binary

- **The question.** `verify/` was bin-only — `[[bin]]` and no `src/lib.rs`. A published bin-only
  crate is installable but **not embeddable**: an auditor who wants
  verification inside their own pipeline must shell out and parse `--json`.
- **Verdict: lib + bin.** `src/lib.rs` holds the logic; `main.rs` is a shell over it, so the CLI and
  an embedding caller run **exactly the same code** and there is no second implementation to drift.
  A parse step between the answer and the decision is somewhere a wrong answer can be introduced,
  and embeddability is most of the reason to publish at all.
- **Accepted cost:** a public Rust API surface with its own semver obligations.
- **Consequence taken while doing it:** the CLI's certificate shape-sniffing moved into
  `Cert::parse_document`. While it was inline in the binary, an embedder had to reimplement it to
  accept the same files the CLI accepts — a second implementation of exactly the kind this crate
  exists to avoid.
- **Status:** DONE. A doctest verifies the shipped fixture **through the library API** (not the
  CLI), and asserts a wrong issuer fails closed.

### `verify/` keeps its own version, independent of the SDK's

- **The question.** `verify/` is `0.1.0` while the SDK is `0.7.42`. Publishing locks that in.
- **Verdict: deliberate — keep it independent.** `verify/` is its own cargo workspace with zero Seam
  dependencies, and an independent version lets it express **real semver**, which this SDK
  explicitly **cannot**: *"this SDK cannot express its own semver. A breaking change here ships under
  whatever number the runtime's history computes, which may be a patch"* (`CHANGELOG.md:9-12`).
  Binding the verifier to that would inherit a defect for the sake of a slogan.
- **Status:** CONFIRMED.

### The MSRV is derived, and the first number written down was wrong

- `rust-version` was **absent**, which a registry accepts silently — a published crate without one
  gives a consumer no signal and they find out from a compile error.
- It was first written as **1.74**, from recalling `ed25519-dalek`'s floor. **That was wrong.** The
  resolved graph requires **1.85** (`prost` 0.14.4, `base64ct` 1.8.3, `zeroize` 1.9.0). A floor that
  is too low is worse than none: absent is honestly silent, a wrong number reads as a checked
  promise.
- **Verdict:** declare 1.85, and **derive rather than pin it** — `verify/tests/msrv.rs` reads
  `cargo metadata` and fails when a dependency outruns the declared floor, the same discipline
  `python/tests/test_protobuf_floor.py` applies to the protobuf floor and for the same reason
  (third-party crates raise their MSRVs on their own schedule, with nobody editing this manifest).
- **Status:** DONE, and the guard was driven red (declaring 1.74 fails, naming `base64ct`).

### It goes to Cloudsmith, not crates.io — and that changes what publishing buys

**Decision (owner directive, 2026-08-23): binaries and packages for this org stay on Cloudsmith.**
`verify/Cargo.toml` therefore declares `publish = ["zer07labs"]`, the same private Cargo registry
(`sparse+https://cargo.cloudsmith.io/zer07labs/internal/`) the runtime crates use.

**The allow-list form is load-bearing, not stylistic.** A bare `publish = true` permits
`cargo publish` to default to crates.io, and this crate shares a package name with
`seam-runtime/crates/seam-verify`. Naming the registry makes an accidental public publish a *cargo
error* rather than an irreversible namespace claim — verified: `cargo publish --dry-run` now reports
*"found `zer07labs` as only allowed registry"*, and `--registry crates-io` is refused outright
(*"The registry `crates-io` is not listed in the `package.publish` value"*). Precisely: dependency
resolution still reads the crates.io **index** — that is where the six dependencies come from — but
nothing is ever *published* there.

**What this does NOT buy, said plainly so it is not overstated later.** Cloudsmith `internal` is
private, so **an external auditor cannot install the verifier from it.** Their path is what it always
was: clone this **public, Apache-2.0** repository and build. `verify/` is a standalone cargo
workspace with zero Seam dependencies precisely so that works anywhere, and the claim is a **CI
gate** (`.github/workflows/ci.yml:395-403` runs `cargo tree -e normal`), not a comment.

So publishing is **distribution convenience for internal and partner consumers** — *not* a
trust-anchoring improvement and *not* the thing that makes the verifier independently obtainable.
The earlier framing in this entry said "distribution and trust-anchoring"; against a private
registry only the first half survives, and §9's rule against overclaiming applies to our own ADRs
too.

**Consequence for the name collision.** With this crate on Cloudsmith and the runtime's copy at
`publish = false`, the two never meet in a shared namespace. The rename
([`seam-runtime#419`](https://github.com/zer07labs/seam-runtime/issues/419)) drops from **blocker to
hygiene** — worth doing so two crates in one org do not share a package name, but no longer gating
anything here.

A build-time check confirms the registry declaration does not compromise the standalone claim:
`cargo build` and `cargo test` pass with no registry access and no credentials, because every
dependency comes from crates.io. The private registry is reachable only on the publish path.

## 2026-08-23 — `plans/archive/sdk-exec-w1-w7.md` Phase 3 (W4.3): does a new field enter the record-digest preimage?

W4.3 requires an **explicit, written** answer per new field, because "an unanswered question here is
how v1→v2 happened." Answering it in a PR comment and moving on is what this entry exists to prevent.

### None of the four landed contract changes enters the record-digest preimage

- **The question.** The batched regeneration added `DecisionResponse.policy_enforcement` (7),
  `.participant_verdicts` (8), `.collective_outcome` (9), `SessionStep.policy_enforcement` (3), and
  the quorum verbs. Does any of them change what `verify/` must hash — which would make this a
  digest **version bump**, not an additive field, and pull in the whole of W7?
- **Answer: no, and the reason is structural rather than a judgment call.** Every one of those
  fields is on a `seam.api.v1` **response** message. The record digest is computed over
  `DECISION_SEALED`'s payload columns — specified byte-exactly at
  `seam-runtime/docs/specs/seam-event.v1.md` §"Record digest" (v2 and v3 both) — and
  `verify/src/wire.rs` mirrors the
  **event** wire only (`SeamEventPb`, `DecisionSealedPb`, `ErasureCertificatePb`, …). A response
  field is not a sealed column and never reaches the preimage.
- **The one event-wire addition in the same window** is `seam.event.v1 LearningOutcome.policy_key`
  (tag 3), found by the descriptor diff rather than by the PR list. `verify/` does not mirror
  `LearningOutcome` at all (grep: zero hits), so it does not reach the verifier either.
- **Consequence:** `verify/src/wire.rs` needs no change, `conformance/vectors.json` is untouched,
  and W7 does not apply to this regeneration.
- **The method, which outlives this answer:** the test is not "is the field new?" but **"is it a
  sealed column?"** Ask it against the event proto and `verify/src/wire.rs`, per field, every
  regeneration. `GetDecision`/`ReplayDecision` deliberately do **not** carry the three new response
  fields precisely because that *would* require a `DecisionRecord` schema + archive-format
  migration — the proto says so itself. The day a field lands on `DecisionSealed`, the answer flips
  and W7 engages.
- **Status:** RECORDED. Re-answer per regeneration; do not inherit this conclusion without redoing
  the check.

## 2026-08-16 — reconcile `plans/archive/adopt-runtime-2026-07.md`'s ASSUMPTIONS.md (8 entries)

Ranked by blast radius, highest first. The two dependency-floor entries are genuine one-way
doors (already-published breaking changes); the rest are low-stakes/reversible.

### The `protobuf` floor is derived from the generated stubs, not chosen
- **Recommender (Fable):** CONFIRM as-is. Verified `python/pyproject.toml`, `test_protobuf_floor.py`,
  and `CHANGELOG.md`'s 0.7.13 section directly: the floor (`protobuf>=7.35.1,<8`,
  `requires-python>=3.10`) shipped exactly as chosen, and the "confirm release framing before
  publishing" concern is moot — it published with an explicit breaking-change warning block
  already written up, since a minor bump was structurally impossible under "one version
  everywhere."
- **Verdict:** Confirm.
- **Status:** CONFIRMED.

### The `grpcio` floor is derived the same way, and needs the LATER of two versions
- **Recommender (Fable):** CONFIRM as-is. Same release-framing resolution as the protobuf floor;
  `grpcio>=1.64` and `test_grpcio_floor.py` still match, and the 1.64-not-1.63 reasoning (needs
  both halves of the registered-method convention) is empirically verified in the test itself.
- **Verdict:** Confirm.
- **Status:** CONFIRMED.

### `timeout` means per-RPC, not an overall call budget
- **Recommender (Opus):** CONFIRM as-is, plus a correction — the entry's own text said `authorize()`
  "can make up to four" wire calls, but its own enumeration (2 admit + 1 + 2 refresh + 1) sums to
  six, matching what `client.py`'s doc comment actually says. Verified TS carries the mirrored
  doc; no second consumer (checked `seam-aegis`) needs an overall budget yet — its production path
  already gets one via `seam-agent-core`.
- **Verdict:** Confirm + fix the "four" → "six" typo in the assumption record.
- **Status:** CONFIRMED. `ASSUMPTIONS.md` corrected.

### check-contract default mode is RPC-only; streamed-payload fields gate under STREAM=1
- **Recommender (Opus):** CONFIRM, but correct stale text. Verified `ci.yml` and `check-contract.sh`
  directly: CI already runs `STREAM=1 EVENTS=1` as permanent hard gates — the escalation this
  entry named as the eventual target already happened. The entry's "CI runs the default mode"
  clause is now false; the env-flag split design itself is unchanged and correct.
- **Verdict:** Confirm + correct the stale "CI runs default mode" text.
- **Status:** CONFIRMED. `ASSUMPTIONS.md` corrected.

### generate-local is the development baseline; the BSR is the release source
- **Recommender (Opus):** CONFIRM as-is. Verified `Makefile`, `ci.yml`, `publish.yml`, `README.md`,
  and `test_workflows_generate_through_the_makefile.py` — the dev/release split is intact and
  test-enforced (workflows can never silently fall back to raw `buf generate`).
- **Verdict:** Confirm.
- **Status:** CONFIRMED.

### The live attestation valid-case pins the runtime's chain_head_attestation KAT
- **Recommender (Opus):** CHANGE (mechanism only, not the underlying decision). Verified: Phase 5
  did add this KAT to `conformance/vectors.json` (byte-identical), but
  `python/tests/test_verify_attestation.py` and `ts/tests/verify_attestation.test.ts` were never
  rewired to load it — a runtime KAT regen would redden `test_conformance.py` while silently
  leaving the two hardcoded copies stale in any environment without the live-test binary. (A
  ship-gate verifier later noted `verify/src/verify.rs`'s Rust unit tests carry two more
  independent hardcoded copies of the same KAT — out of scope for this entry, which was
  specifically about the Python/TS live-attestation test; see the amended note in
  `ASSUMPTIONS.md`.)
- **Verdict:** Change now — rewire both attestation test files to load the KAT from
  `conformance/vectors.json`, matching the loader pattern `test_conformance.py`/`conformance.test.ts`
  already use, and delete the duplicated literals.
- **Status:** CONFIRMED (amended). Code changed: `python/tests/test_verify_attestation.py` and
  `ts/tests/verify_attestation.test.ts` now load `_VECTOR`/`VECTOR` from `conformance/vectors.json`
  instead of hand-copied literals. Verified: `pytest tests/test_verify_attestation.py` (2 passed, 1
  skipped — env-gated live test) and `tsc --noEmit` + `node --test tests/verify_attestation.test.ts`
  (2 passed, 1 skipped) both green after the rewire.

### The verify/ authenticity goldens are pinned to a runtime commit
- **Recommender (Opus):** CONFIRM as-is. Verified `verify/tests/goldens/` is populated and
  byte-for-byte identical (SHA-256) to seam-runtime commit `fd633c9`'s fixtures, that commit is
  real/reachable in the sibling checkout, and there's been no runtime-side drift since.
- **Verdict:** Confirm.
- **Status:** CONFIRMED.

### The streamed digest-recompute helper lives on the admin module, keyed to a single record
- **Recommender (Opus):** CONFIRM as-is. Verified `verify_streamed_record_digest`/
  `verifyStreamedRecordDigest` are behaviorally equivalent in both languages, both tested, and
  documented. No consumer has asked for the broader `verify_streamed_chain` since Phase 6 shipped.
- **Verdict:** Confirm.
- **Status:** CONFIRMED.

---

**Summary:** 7 confirmed as-is (2 corrected in text: timeout typo, check-contract stale claim), 1
confirmed-amended with a real code change (KAT pinning rewired to the shared conformance vector,
duplicated literals deleted). 0 changed in substance, 0 deferred. No follow-up code work needed
before the next `/ship` beyond what's already in this pass.
