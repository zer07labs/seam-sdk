# Digest correctness, gate repair, and ACDP P3 readiness

## Context

`seam-sdk` is in good shape: 1016 python tests pass, `scripts/` 100, `verify/` clean, ts and go green,
version lockstep holds at 0.7.71 against the runtime's own tag, and the contract gate exits 6 with
exactly the five recorded lag fields and nothing else. Five hardening passes have already run over
this repo, and the last three were all aimed at one failure class the repo named for itself: a check
whose result is decided by something other than the property it names.

This plan came out of a three-way audit commissioned on 2026-09-03: one pass over the hand-written
client layers, one over the guards and CI, one over the open issues and ACDP P3. What it found is
that the *guards* are now largely sound — the citation gate, the field/enum/event manifests, the
live-suite isolation guard and the CI wiring were all attacked with real mutations and held — but
that **the shipped crypto has four demonstrated cross-language divergences**, and **the one gate that
exists to stop a bad release is currently unable to refuse one**.

Four things are worth stating plainly before the phases, because each one changes what this plan does.

**1. The release handshake is latched open.** `contract/wire-framing.json` still carries
`"runtime_emits_version": false`. Its own comment says to flip it "in the PR that confirms the runtime
emits the field", and the runtime confirmed it: `seam-runtime#418` closed COMPLETED on 2026-08-26, and
every release dispatch since has carried `wire_framing_version` (the 2026-09-01 release logged
`runtime wire framing: 2   SDK supports: 2`). While the latch is false,
`release-on-runtime.yml`'s absent-field branch prints a warning and `exit 0`s — so if the dispatch ever
stops carrying the field, the SDK tags and publishes anyway. This is the gate whose file header names
0.7.17, which "published eleven minutes after the runtime change that broke it", as the reason it
exists. It is one line, it is live, and it goes first.

**2. Four demonstrated crypto divergences, all in TypeScript's direction.** Each was reproduced
against the built SDK, not read:

- `jcsCanonicalize({"\ud800": 1})` **digests in TS and is refused by Python.** The lone-surrogate
  guard is applied to string *values* and never to object *keys*, so a TS caller can sign a `callSig`
  over canonical bytes no other implementation in the system can produce or re-derive.
- `recordDigestV2` with `sealedAt = 2^64 + 5` produces a digest **byte-identical** to `sealedAt = 5`.
  `u64le` calls `setBigUint64`, which wraps mod 2^64 with no range check. The v3 path already refuses
  this exact class through `v3Uint` — whose docstring names it, "bytes as `5` — an alias, not an
  error" — but v2 and the chain-head attestation path were left on the raw helper. The sharp version
  is that a signature genuinely made over `attested_len = 5` verifies `true` against a claimed length
  of `2^64 + 5`.
- `verify_tct` decodes the `exp` claim three different ways in three languages, and Go's
  implementation contains a comment stating the reference semantics and warning that "a float-precise
  compare would accept it and drift from the shims". TypeScript performs exactly that float-precise
  compare, and additionally accepts a string `exp` via JS coercion; Python accepts a numeric-string
  `exp` that Go refuses.
- `jcsCanonicalize` in TS coerces `Date`, `Map` and `Set` to `{}`, aliasing onto the digest a genuine
  empty object produces, where Python raises `TypeError`.

None of these are reachable from in-range wire values — proto `uint64` is bounded, and the runtime
never sends a lone surrogate. They are reachable through the **public SDK surface**, which is exactly
the "verify a counterparty's artifact" surface the product exists to provide.

**3. One audit finding is refuted, and this plan deliberately does not act on it.** The code audit
reported that Node ≥24 silently corrupts canonical JSON after JIT warm-up, on the strength of a
20,000-input differential against Python. It does not reproduce. A fully in-process differential —
the SDK's own `jcsCanonicalize` against an independent reference canonicalizer in the same script, no
pipe and no second language — ran 180,000 inputs across three seeds on the exact Node v26.8.1 the
finding named, and produced zero mismatches. The reported corruption shapes (a key containing U+2029
emitted as `"\\"`, an entire key–value pair vanishing) are what Python's `str.splitlines()` does to a
JSON-lines record: it treats U+2028, U+2029, U+0085 and U+001C as line terminators, so a single record
carrying U+2029 splits into `'{"k":"'` and `'"}'`, and every later record's index shifts — which is how
a pair appears to "vanish". Of those four characters only U+2028, U+2029 and U+0085 are reachable in
canonical output; U+001C is a control character, which `JSON.stringify` escapes rather than emitting raw. The
corruption was in the differential's own transport. **No `engines` pin, no upstream bug report, and no CI leg on Node 24/26 is planned on that
basis.** The one genuine residue is unrelated and minor: `ts/package.json` declares no `engines` field
at all, which is worth fixing as packaging hygiene and is scoped as such in Phase 3.

**4. ACDP P3 (issue #96) is readiness work only, and cannot be adopted this cycle.** *(Corrected in
Phase 7 — the original reason below was true when written and is now false.)* The stated blocker was
that tags 12-13 lived on an unpushed branch, so there was nothing to regenerate against. The runtime
has since merged `feat/acdp-p3-key-revocation` as `ac325d7` (#531) and `buf push`ed it, so
`origin/main`'s `ContextBinding` now carries tags 12 and 13 and **the consequence is inverted**:
declaring the fields today would turn CI *green*, and not declaring them is what keeps `main` red —
the field-surface gate fails on a two-field surplus, blocking every merge including PR #97. The
remaining blocker is different and narrower: adopting the fields properly wants a regeneration this
workstation cannot run (`buf registry login` against a private BSR module), and the adoption is a
deliberate decision about whether this SDK carries the fields, which the gate's own refusal text says
must be made before the manifest moves. What *is* doable now is the guard that makes the adoption impossible to get
half-right, plus a set of corrections to the issue itself. Several of #96's vocabulary definitions are
superseded by the proto it describes: `unplaceable` has two producers, not one — the second is "the
acting revocation names a different controller than the producer", which fires *even with* a valid
pre-boundary receipt, and the proto comment says in as many words that this "is why this entry no
longer says 'no verified receipt'". And `unknown` is explicitly **not** "the negative answer is staler
than the bound": staleness triggers a synchronous re-source and yields `unknown` only if that fails.
A decoder built from the issue body would encode both errors. #96 also asks whether the vendored spec
will need a refresh; it will — the runtime's P3 plan changes `docs/specs/seam-event.v1.md`.

The digest-contamination risk #96 warns about was checked and **is not present**: nothing in this repo
computes a context digest, and none of the three `record_digest_v3` implementations iterate message
fields — every one takes explicitly named slots — so a regenerated stub gaining tags 12-13 cannot
sweep them into a preimage. That is recorded as an honest negative rather than turned into a guard
nobody needs.

---

## Phases

### Phase 1 — The release gate that cannot refuse

**Status:** DONE (2026-09-03). Two divergences from the plan as written, both found by the phase's
own verification rounds and both recorded in `DECISIONS.md`:

- The plan did not foresee that **arming the latch kills the manual release fallback**.
  `workflow_dispatch` has no `client_payload`, so `$DISPATCHED` is empty on every manual run and the
  new REGRESSION branch fires unconditionally — on precisely the path an operator reaches for *after*
  the automatic dispatch failed. Closed by adding an optional `wire_framing_version` input and
  diagnosing that case separately, ordered ahead of the latch checks.
- Consequently the stale-latch branch is **scoped to `repository_dispatch`** — see the amended
  criterion 3 and edge-case paragraph below, which the plan originally stated unqualified.

**Delivers:** a wire-framing handshake that actually refuses, plus a guard that stops the latch from
going stale silently again.

**Depends on:** nothing. Runs first: it is the only item here that is both live and load-bearing on
every release, and it is one line of content.

**Files:** `contract/wire-framing.json`, `.github/workflows/release-on-runtime.yml`,
`scripts/test_release_gate.py`, `DECISIONS.md`. *(As built, also `COMPATIBILITY.md`, `CHANGELOG.md`,
`README.md`, `plans/README.md`, `plans/cross-repo/` and `python/tests/test_compatibility_citations_resolve.py`
— de-staling the documents that described the pre-flip world, plus the citation repointing those edits forced.)*

**Approach.** Flip `runtime_emits_version` to `true` and rewrite `runtime_adoption_issue` to record
that seam-runtime#418 closed COMPLETED on 2026-08-26 rather than naming it as pending. That alone
restores the gate: with the latch true, an absent `wire_framing_version` becomes `exit 1` ("a field
that stopped being emitted is a REGRESSION in the handshake") instead of a warning and a tag.

The flip is necessary but not sufficient, and the second half is the point: the latch went stale for a
week because nothing watched it, and `scripts/test_release_gate.py` checks step ordering and file
existence only.

The guard must be one the staleness could not have survived. **Add the inverse branch to the framing
step in `release-on-runtime.yml`: when `$DISPATCHED` is non-empty and `$LATCHED` is `false`, refuse.**
A dispatch that carries `wire_framing_version` is itself proof that the runtime emits the field, so a
latch still reading `false` at that moment is provably stale — detected from live data, at exactly the
moment it matters, with nothing to keep up to date by hand. The 2026-08-31 and 2026-09-01 releases both
carried `wire_framing_version: 2` while the latch sat false, so this check would have fired on the
first release after adoption.

Rejected — and this was the plan's first draft, which the review round caught: a test asserting that
"if the latch is `false`, the issue named in `runtime_adoption_issue` must still be open", checked
against state recorded in the same file. That is circular. The staleness that actually happened left
*both* fields stale together, so the test would have stayed green indefinitely; it converts "someone
remembers to flip the latch" into "someone remembers to record the closure", which is the same
reliance moved one field sideways. Also rejected: asserting the latch is unconditionally `true`,
which would make the file's documented staged-adoption mode unusable the next time a framing lands
SDK-side first.

**Edge cases & failure modes.** The new branch must not break the legitimate staged-adoption window:
while the runtime genuinely does not emit the field, `$DISPATCHED` is empty and the branch never
fires — it keys on the presence of the field, not on the calendar. A framing bump and a latch flip in
one PR must both still be possible. If the runtime regresses and stops emitting the field, the
intended outcome is a **failed release**, which is correct and is the whole point.

*Amended as built:* two further cases the draft missed, both on the `workflow_dispatch` path.
(a) With the latch true and no manual input, the run must be told **its input is missing**, not that
the runtime regressed — the regression text sends someone to the wrong repo, on the recovery path.
(b) The stale-latch branch must **not** fire on a manual run: its entire claim is "the payload proves
the *runtime* emits the field", which is false of a value an operator typed into a form. Unscoped, a
manual release during a legitimate staged adoption would demand the latch be flipped on no evidence,
and flipping it would then send every subsequent automatic dispatch into the REGRESSION branch. So the
branch keys on `$EVENT = repository_dispatch`, and a manual run with an operator-asserted framing
version falls through to the version comparison, which is the right outcome.

**Acceptance criteria.**
1. `contract/wire-framing.json` has `"runtime_emits_version": true`.
2. `runtime_adoption_issue` records #418 as closed-completed with its date, not as pending work.
3. `release-on-runtime.yml`'s framing step refuses when `$DISPATCHED` is non-empty, `$LATCHED` is
   `false` **and the trigger is `repository_dispatch`**, with an error naming the latch as stale.
   *(The event scoping is the amendment above; the draft stated this criterion unqualified, which
   as built would have been wrong on the manual path.)*
4. `scripts/test_release_gate.py` pins the presence and direction of that branch, the same way it
   already pins step ordering — and the pin is demonstrated red against the pre-fix workflow.
5. The staged-adoption path still works: with `$DISPATCHED` empty and `$LATCHED` false, the step
   still warns and exits 0.
6. `python -m pytest scripts -q` stays green; `ci-ok`'s `needs:` is unchanged (no new job).
7. *(added as built)* A manual run with the latch true and no `wire_framing_version` input refuses
   with a message naming the **missing input**, and a manual run that supplies a matching one
   succeeds — so arming the gate does not close the documented recovery path.
8. *(added as built)* Deleting any of the four workflow cells the gate depends on but does not
   itself contain — the input declaration, the `||` fallback that reads it, the `EVENT` env line,
   the `repository_dispatch` trigger — turns a test red.

**Tests.** The new stale-latch branch pin, the staged-adoption negative control, plus the existing
`test_release_gate.py` ordering tests unchanged. *As built:* 4 tests became 19. The behavioural ones
execute the gate's real script, extracted from the YAML, against a synthetic `wire-framing.json` in a
tmpdir — the full 12-cell truth table over (dispatched × latched × trigger). Four structural ones read
the parsed workflow, covering criterion 8's plumbing cells, which no amount of executing the script can
reach. Every assertion was mutation-verified: the thing it names was deleted and the test watched to
fail.

**Docs.** A `DECISIONS.md` entry recording why the latch existed, why it went stale, and that the
guard now binds the latch to its tracking issue rather than to a date.

---

### Phase 2 — Digests that alias: the u64 wrap and the unguarded surrogate key

**Status:** DONE (2026-09-03). Three divergences from the plan, all found by the verification round:

- **The plan's own Approach item 3 was not quite enough.** Range-validating `attested_len`/
  `attested_at` closed the `struct.error` escape, but left `attested_len=True` digesting as `1`
  (`bool` subclasses `int`, so the comparison simply passes) while TypeScript refused `true` — so
  the fix **created** a cross-language divergence while closing three. And `5.0` passed the range
  check and then raised `struct.error` anyway, leaving the function with four possible answers.
  Closed by requiring `int` and excluding `bool` before the range check. Recorded in `DECISIONS.md`.
- **`v3Uint` was renamed to `uintSlot`**, rather than v2 getting its own copy of the rule. Not in
  the plan, but implied by it: the plan says to adopt v3's semantics, and two copies of a rule about
  which inputs have a digest is a divergence waiting for someone to fix only one of them.
- **One widening**, undocumented until the verifier found it: `schemaVersion: 3n` threw before and
  is accepted now, because the old `u32le` took `number` and fed a bigint straight to `setUint32`.
  Same integer, no alias; recorded in `COMPATIBILITY.md` §9 so the section is not purely a narrowing
  that quietly widens one cell.

A second verification round found the `bool` fix had been applied to only one of the two Python
functions that needed it — `record_digest_v2` still digested `sealed_at=True` as `1` — so the same
divergence survived in the sibling function while `COMPATIBILITY.md` asserted it closed. Both
languages now share **one** integer-slot validator per language (`uintSlot` / `_uint_slot`, both
renamed from their v3-only originals) across all three framings, which is the form that makes the
class unrepeatable rather than merely fixed.

**Delivers:** TS refuses out-of-range integers in the v2 and attestation framings, TS refuses lone
surrogates in object keys, and Python's attestation verifier keeps the contract its docstring states.

**Depends on:** nothing.

**Files:** `ts/src/crypto.ts`, `python/seam_sdk/crypto.py`, `ts/tests/`, `python/tests/`,
`COMPATIBILITY.md`.

**Approach.** Three narrow changes, each closing a demonstrated alias:

1. **`u64le`/`u32le` range-check.** Throw `RangeError` outside `[0, 2^64)` / `[0, 2^32)` instead of
   letting `setBigUint64` wrap. This is pure input validation: **no in-range value changes by a
   single byte**, so the frozen v2 formula is untouched. The precedent is already in the file —
   `v3Uint` refuses this exact class for v3 and its docstring explains why ("an alias, not an
   error"). This phase extends that reasoning to the two paths that predate it rather than inventing
   a rule.
2. **Lone-surrogate guard on object keys.** `jcsWrite`'s object arm calls `JSON.stringify(k)`
   directly; run the existing `hasLoneSurrogate` over each key first, mirroring the value arm one
   case above it. One line, and it makes the module's stated invariant — "keeps the three
   implementations agreeing on which inputs have a digest at all" — true for the first time.
3. **Python `verify_chain_head_attestation` keeps its `False` contract.** The digest recompute sits
   *outside* the `try`, so a `struct.error` on an out-of-range length escapes a function documented
   to return "``False`` on any tamper". **Do not simply move the recompute inside the existing
   `try`** — that block ends in a blanket `except Exception: return False`, which would also swallow
   the wrong-type `TypeError`s this phase's edge cases say must keep propagating, converting caller
   bugs into a silent "unverified". Instead range-validate `attested_len`/`attested_at` explicitly
   (or catch `struct.error` specifically) and return `False` for the out-of-range case, leaving
   `TypeError` to propagate.

4. **Decide v2's unsafe-`number` question explicitly.** A bare `[0, 2^64)` range check leaves
   `sealedAt: 2**60` — a JS `number`, already inexact — accepted by v2 while v3 refuses it. Adopt
   `v3Uint`'s full semantics for the v2 and attestation paths, which means a `number` above 2^53 is
   refused there too. That is a **narrowing of what is accepted**, not a change to any emitted byte,
   and it is the right call: above 2^53 the value hashed is the nearest double rather than the
   integer the caller meant, so Python (exact ints) would disagree — the same cross-language
   argument that motivates the whole phase. Record it as a deliberate narrowing rather than letting
   "no in-range value changes by a single byte" quietly cover it, because bytes and acceptance are
   different things.

Rejected: normalising or truncating out-of-range values. That would preserve the alias with extra
steps; the whole point is that two different inputs must not reach one digest.

**Edge cases & failure modes.** Range-checking must accept `number` and `bigint` alike and must not
regress the `number`-above-2^53 rejection v3 already performs. `-0`, `-1n`, and `2^64` exactly are
the boundary cases. Existing KATs and conformance vectors must be byte-unchanged — if any vector
moves, the change is wrong and the phase fails. The Python fix must not convert genuine
programming errors (wrong type) into a silent `False` that hides a caller bug.

**Acceptance criteria.**
1. `recordDigestV2({... sealedAt: (1n<<64n)+5n})` throws; `sealedAt: 5n` is byte-identical to its
   value before this phase.
2. `verifyChainHeadAttestation` with `attestedLen: (1n<<64n)+5n` against a signature made over
   `attestedLen: 5` returns `false` or throws — it does **not** return `true`.
3. `jcsCanonicalize({"\ud800": 1})` throws in TS, matching Python's refusal; a valid key with an
   astral-plane character (a correct surrogate *pair*) still canonicalizes unchanged.
4. `verify_chain_head_attestation(..., attested_len=(1<<64)+5, ...)` returns `False` rather than
   raising `struct.error`.
5. `verify_chain_head_attestation` with a **non-bytes** `attested_head` still raises — the blanket
   `except` was not widened to cover programmer error.
6. `recordDigestV2` refuses a `number` above 2^53 (the v3 rule, now applied to v2), and the
   `DECISIONS.md` entry names that as a deliberate narrowing.
7. Every existing conformance vector and KAT produces byte-identical output; `conformance/` is
   unmodified.
8. Full suites green: python, ts, go, `verify/`.

**Tests.** A red-first test per defect, each asserting the *alias* rather than only the throw: the
u64 test asserts the two digests were equal before and that the out-of-range one is now refused; the
surrogate test asserts key and value paths now agree; the attestation test uses a real Ed25519
signature over the in-range length and asserts the out-of-range claim is not accepted.

**Docs.** A `COMPATIBILITY.md` note that TS and Python now agree on which inputs have a digest at
all, in both the key and the value position.

---

### Phase 3 — Divergences that need a decision, not just a fix

**Status:** DONE. All four items landed as planned. Two divergences the plan did not name were found
by measuring rather than reasoning and closed in the same phase: `exp: true` was ACCEPTED by Python
and TypeScript at any clock below one second (invisible at a realistic `now`, so the shared vector
pins `now = 0` on every type case), and `signature` was the one argument Python's own type pass had
always skipped. Go's `exp` rule was adopted as normative; Java and Kotlin already implement it but do
not yet read the shared vector, since this workstation has no JDK — recorded in `ASSUMPTIONS.md`
rather than written blind.

**Delivers:** one normative rule for `exp` decoding implemented in all languages, a decision on
non-plain-object coercion in TS, a decision on whether `verifyChainHeadAttestation` swallows type
errors, and an `engines` declaration for the TS package.

**Depends on:** Phase 2 (same files; sequencing avoids a conflicting edit to `crypto.ts`).

**Files:** `ts/src/crypto.ts`, `python/seam_sdk/crypto.py`, `ts/package.json`, `DECISIONS.md`,
`ASSUMPTIONS.md`, tests in both languages.

**Approach.** Two of the four divergences cannot be fixed by picking the stricter side without
deciding *which* side is normative, so this phase records the decision and then implements it.

**`exp` decoding.** Go's implementation already carries the reference semantics in a comment —
`exp` must be a JSON number, truncated to whole seconds — and warns that a float-precise compare
"would accept it and drift from the shims". Adopt Go's rule as normative. Three reasons, in order of
weight: **Java and Kotlin already implement it** (`instanceof Number` + `longValue()`, and
`as? Number` + `toLong()` respectively), so it is the existing 3-of-5 majority and adopting it changes
two implementations rather than three; it is the only rule with a written rationale; and it is the
strictest of the three, which is the safe direction for a token verifier.

Concretely: TS requires `typeof payload.exp === "number"` and compares against `Math.trunc(exp)`;
Python requires `isinstance(exp, (int, float)) and not isinstance(exp, bool)` — the `bool` exclusion
is load-bearing, since `bool` subclasses `int` in Python and `exp: true` would otherwise be accepted
as `1`, which every other language refuses.

Rejected: adopting TS's float-precise behaviour, which would require changing four languages to match
the one that has no written rationale, and would accept tokens the other four currently reject.

**How a TypeScript caller learns they passed the wrong type.** Found during Phase 2's verification
and deliberately not fixed there, because it is a decision rather than a defect.
`verifyChainHeadAttestation` wraps its whole body in `catch { return false }`
(`ts/src/crypto.ts:730-735`), so every `TypeError` the new `uintSlot` guard raises is swallowed:
`attestedLen: "1000"`, `true`, `null` and `[1000]` all return `false`. Python's twin deliberately
lets `TypeError` propagate, on the argument that a caller bug reported as "did not verify" is a
program error disguised as a security verdict — so the two languages now disagree about *how* a
caller is told, though not about *which* inputs are refused.

Both positions are defensible: a boolean-returning verifier that never throws is easy to call
correctly, and it is the shape `verifyDecision` already has for `IssuerMismatchError` (which it
throws) versus an invalid TCT (which it returns `false` for) — so this repo has already decided,
once, that some failures are exceptional and others are verdicts. Decide which this is, apply it,
and record the consequence: narrowing the catch is a **behaviour change to a public API**, since a
caller who today gets `false` would get a thrown `TypeError`. Rejected in advance: leaving it
undecided and documenting the divergence, which is what `COMPATIBILITY.md` §9 does as a stopgap and
should not remain.

**Non-plain objects in TS JCS.** `Date`, `Map` and `Set` canonicalize to `{}`, aliasing onto a
legitimate empty-object digest. The module's stated rule is that it "refuses any input it cannot
faithfully represent, rather than coercing it", so the fix is to honour it: refuse objects whose
prototype is neither `Object.prototype` nor `null`. This is a **behaviour change to a public API** —
a caller passing a `Map` today gets a verdict for `{}` and will get an exception after — so it is
recorded in `DECISIONS.md` with that consequence stated, not slipped in.

**`engines`.** `ts/package.json` declares none. Add one reflecting what CI actually tests. This is
scoped as packaging hygiene and is explicitly **not** derived from the refuted Node-corruption
finding (see Context §3); the range must therefore not exclude current Node without a tested reason.

**Edge cases & failure modes.** A `null` prototype object must still work (it is a legitimate plain
map). Objects carrying a `toJSON` method are the ambiguous case — decide explicitly and record it.
For `exp`: a token with no `exp` at all currently defaults to `0` and is treated as expired; that
behaviour must not change. Boolean and `null` `exp` values must be refused in every language.

**Acceptance criteria.**
1. For each token shape in the shared vector — integer `exp`, numeric-string `exp`, `"1e10"`,
   fractional `exp`, **boolean `exp`, `null` `exp`, and absent `exp`** — Python, Go and TS return the
   **same verdict**. The last three are what falsify this phase's own edge-case bullet; without them
   the criteria cannot catch the `bool`-subclasses-`int` trap.
2. TS `jcsCanonicalize(new Map(...))` / `new Set(...)` / `new Date()` throws rather than returning
   the empty-object digest; a plain object and an `Object.create(null)` object both still work.
3. `ts/package.json` has an `engines.node` range consistent with the versions CI tests.
4. `DECISIONS.md` records **all three** decisions with their rationale and, for the JCS change and
   any narrowing of `verifyChainHeadAttestation`'s catch, the explicit statement that it is a
   breaking change to a public API.
4b. `verifyChainHeadAttestation`'s treatment of a wrong-typed argument is decided either way and
   asserted by a test; `COMPATIBILITY.md` §9's stopgap paragraph describing the divergence is
   replaced by a statement of the decision.
5. Both decisions are logged to `ASSUMPTIONS.md` as `UNCONFIRMED` if any part rests on an
   unverified reading of the other languages' intent.

**Tests.** A cross-language `exp` vector exercised from Python and TS (Go asserted by its existing
tests plus the shared vector); TS tests for each refused object type and each still-accepted one.

**Docs.** `COMPATIBILITY.md` gains a row for the JCS behaviour change, since it is caller-visible.

---

### Phase 4 — Guards that fire on the mutation they name

**Status:** DONE. All four repairs landed, each demonstrated green-before / red-after against the
mutation it names. Four things beyond the plan. (a) The `buf generate` scan found a fourth missed
spelling (`echo x | buf generate`) once it was written per-command rather than per-line. (b)
`test_packaging.py`'s new tests initially passed vacuously because `pytest.raises(Exception)` cannot
catch `Skipped`/`Failed` — both derive from `BaseException`. (c) Item 4's first repair split the two
causes by exception TYPE, which is not the discriminator: `python -m pip` without pip exits 1 rather
than raising `FileNotFoundError`, so a missing tool was reported as a package defect; both tests
missed it by forcing the `pip3` branch, where an absent executable really does raise. Replaced with a
`--version` presence probe. (d) That probe exposed a third class the plan did not have — a builder
that exits 0 and emits no `seam_sdk-*.whl` (this workstation's `/usr/bin/pip3` carries setuptools
58.0.4, which predates PEP 621 support, so it builds `UNKNOWN-0.0.0` and reports success). Three
classes, three messages, all three failing under `SEAM_REQUIRE_WHEEL_BUILD=1`. All four caught
locally, before the gate.

The verification round returned REVISE and found two more, both the phase's own subject: (e) the
suite could not have run in CI at all — `import yaml` was undeclared, and an undeclared import is a
collection error that aborts the whole run; and (f) the `buf generate` guard, the one with the most
history behind it, had no calibration, so blinding its walker left the file green. Both fixed, plus
a new `test_test_dependencies_are_declared.py` that closes (e)'s whole class rather than its
instance. Six further findings closed; one accepted and recorded (the shell split is
quoting-unaware). See PROGRESS.md's "Verification round" for the measurements.

**Delivers:** four guards that currently miss their own subject now catch it, each proven red-first.

**Depends on:** nothing.

**Files:** `python/tests/test_retracted_claims.py`,
`python/tests/test_workflows_generate_through_the_makefile.py`,
`python/tests/test_compatibility_citations_resolve.py`, `python/tests/test_packaging.py`,
`.github/workflows/ci.yml` (the `SEAM_REQUIRE_WHEEL_BUILD` env, per criterion 6 — omitted from this
list when the plan was written), and, added by the verification round,
`python/tests/test_test_dependencies_are_declared.py` + `python/pyproject.toml`.

**Approach.** Four narrow repairs, each demonstrated as currently-missed:

1. **Truncation-claim guard, substring matching.** A paragraph is excused if any of
   `("not", "cannot", "no ", "until", "never", "does not")` appears **as a substring**. So
   "notarised", "nothing" and "annotation" all contain `not`; `"until"` appears in ordinary prose;
   and `DISCUSSING_NOT_CLAIMING` contains the bare phrase `"the claim"`, which excuses a sentence
   that *makes* the claim while using it. Four mutations were demonstrated green. Fix: word-boundary
   matching, drop or narrow `"until"` and `"the claim"`, and add the red-first calibration case the
   module never had.
2. **`buf generate` guard, line-anchored regex.** `RAW_BUF_GENERATE` requires `buf generate` to open
   a line, so `- run: buf generate ...` (the ordinary compact spelling) and `make lint && buf
   generate ...` both slip past the guard that exists because "every wheel this repo ever published
   could not be imported". Fix: scan each step's `run` value split on `\n`, `&&`, `;` and `|`.
3. **Vendored-citation rule, missing comma-list form.** `_line_anchors_into_generated` iterates both
   `CITATION` and `COMMA_LIST_CITATION`; `_line_anchors_into_vendored` iterates only `CITATION`. The
   comma-list pattern was added precisely because "a comma separating two line numbers does not make
   them less line numbers" — and only one of the two rules got it, so
   `` `verify/docs/seam-event.v1.md:100,200` `` line-anchors into the whole-file-refreshed vendored
   spec invisibly. That is issue #73's exact class, re-opened in the sibling rule. Fix: iterate both,
   and add the mirror case.
4. **Packaging guards' over-broad `except`.** The skip catches `CalledProcessError` as well as
   `FileNotFoundError`, so *a failed wheel build* retires three packaging-contract guards (no global
   `seam` leak, `py.typed` ships, rooted `__init__.py` chain) as skips, and pytest exits 0.
   CI's separate wheel-import step checks imports only, not those three properties. Fix: an env flag
   (`SEAM_REQUIRE_WHEEL_BUILD=1`, set in CI) that turns the skip into a failure. The reasoning is
   the same one `ci-ok` already applies at the job level — a skipped required job counts as a
   failure, precisely so absence cannot read as success — applied here at the test level, where no
   equivalent currently exists.
   **Note for the implementer:** on this workstation the venv genuinely has no `pip` module, so the
   three local skips are correct and are *not* evidence of this defect. The defect is that the same
   `except` would swallow a real build failure. Do not cite the local skips as the demonstration.

**Edge cases & failure modes.** The truncation guard's word-boundary rewrite must not start failing
on the repo's existing prose — run the full suite, and if a real document trips it, that document is
the finding. The `buf generate` YAML scan must keep the existing prose-comment exemption. The
packaging env flag must be added to CI's python job or the guards stay skipped where it matters most.

**Acceptance criteria.**
1. Each of the four guards is shown red against a mutation that is green today, and green after —
   recorded in the phase log with the actual commands.
2. The four demonstrated truncation-guard mutations ("notarised", "Note:", "until you disable it",
   "The claim we make…") are all caught after the fix.
3. `- run: buf generate ...` and `make lint && buf generate ...` are both caught.
4. `_line_anchors_into_vendored` refuses the comma-list spelling, matching its sibling.
5. With `SEAM_REQUIRE_WHEEL_BUILD=1` and a deliberately broken build, the packaging tests **fail**
   rather than skip; without it, they skip as now.
6. CI's python job sets `SEAM_REQUIRE_WHEEL_BUILD=1`; no new CI job is added, so `ci-ok`'s `needs:`
   is unchanged.
7. Full python suite green.

**Tests.** The four red-first calibrations above, each committed as a permanent test so the
narrowing cannot return.

**Docs.** None — these are test-internal repairs. The `DECISIONS.md` vocabulary already covers the
class.

---

### Phase 5 — The verb surface nobody watches

**Status:** DONE. One divergence from the plan, in the direction the plan's own reasoning points:
rather than write a service-detection probe beside the existing verb extractors, the extractors were
parameterised by package so the event probe calls THE rule instead of a copy of it — the api side
verified byte-identical (42 verbs per language) before anything was added. Two findings beyond the
plan: exit 7 already preempted exit 2 before this phase (via the enum precondition), so `CLAUDE.md`
was documenting three reachable codes when there were four; and two planning-time notes in
PROGRESS.md's repo map claimed Phase 5 would parameterise the FIELD extractors, which were already
parameterised — corrected in place.

The verification round returned REVISE and found the Delivers line was false as written: the probe
watched two FILENAMES, so a verb arriving in a second `.proto` of the same package — buf's ordinary
layout, and the most likely way one would actually arrive — still exited 0. Now globbed over the
package directory. It also measured only RPCs while the refusal said "zero services", so a
zero-method service passed; service declarations are matched now in both languages. The "one rule,
not two" test was itself vacuous (green on a fully blinded probe, red on a byte-identical reformat)
and is now whitespace-tolerant and honestly scoped as structural-only. Six smaller items closed. One
operational incident is recorded in PROGRESS.md: a measurement run rewrote two committed manifests
because zsh does not word-split `env $VARS cmd`; both were restored byte-identical.

**Delivers:** a service landing on `seam.event.v1` can no longer arrive with every gate green.

**Depends on:** nothing.

**Files:** `scripts/check-contract.sh`, `python/tests/test_event_field_manifest_gate.py`,
`contract/event-field-manifest.txt` (header only), `CLAUDE.md`.

**Approach.** `check-contract.sh` claims "the whole verb surface is declared in
`contract/rpc-manifest.txt`", but both extractors are hard-pinned to `seam.api.v1` and read only the
api stub files. `python/seam_sdk/_gen/seam/event/v1/seam_event_pb2_grpc.py` exists as an empty
scaffold and **nothing in `scripts/` or `python/tests/` reads it**. So an RPC added to the event
package is invisible in both languages at once — this repo's own named failure class, and the same
story as the field-level gap #88 just closed, one level up at the verb level.

Ship the tripwire, not the full manifest: extend `assert_event_surface_preconditions` to assert that
`seam.event.v1` declares **zero services**, and exit 7 (structural precondition) when one appears.
This is the right shape because the event package having no services is a real current invariant, the
failure mode is "a verb arrived unnoticed", and a tripwire converts that from silent to loud without
committing to a manifest format for a surface that has no entries yet. Extending
`contract/rpc-manifest.txt` to cover a second package is the fuller fix and needs a format decision
(one file with package-qualified names, or a second file); that decision is deferred to the phase
where a verb actually lands, and recorded in Open questions rather than guessed at now.

**Edge cases & failure modes.** Exit 7 must not collide with the documented meanings of 6, 8 and 2 —
7 is already "structural precondition" and is the correct code. The probe must key on both languages
independently (python grpc stub and the TS generated file), because a one-language check is the
blindness it is meant to remove. The scaffold file existing but being empty is the current state and
must stay green.

**Acceptance criteria.**
1. With a service block grafted into a **scratch copy** of the python event grpc stub, the gate
   exits 7 and names it; likewise for the TS event file, independently.
2. On the unmodified tree, `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` still exits 6 with exactly
   the recorded five-field lag NOTE and nothing else.
3. A test drives the real script against scratch copies — never against the real stub trees. **The
   existing overrides are not sufficient for the Python half**: `PY_GRPC` is hardcoded to the api
   stub and services never appear in `$PY_EV` (the `.pyi` carries no RPCs), so this phase must add a
   new override (`SEAM_PY_EV_GRPC`) and thread it through the script and the fixtures. The TS half
   needs no new override — services annotate into the same `_pb.ts` that `SEAM_TS_EV` already
   points at.
4. `CLAUDE.md`'s exit-code documentation covers the new use of 7, and the test that pins that
   paragraph is extended rather than left describing the old set.

**Tests.** Both-language graft tests in `test_event_field_manifest_gate.py`, plus a negative control
proving the unmodified tree is unaffected.

**Docs.** `CLAUDE.md` Gotchas — the exit-code paragraph, which is machine-checked and must not drift.

---

### Phase 6 — ACDP P3: the guard that makes the adoption impossible to half-do

**Status:** DONE. One divergence found by mutation: every test was parametrized over `SOURCES`, so
DELETING a source silenced the guard while leaving it green — criterion 4's exact concern, and the
plan's own "quiet opt-out" failure mode arriving through the list rather than through a flag.
`SOURCES` is now derived from the tree and checked by exact equality. Two things beyond the plan: the
proto carries a fifth correction the plan did not name (registry-attested revocations stay scoped by
§6 to the serving or receipting registry), and the spec question is answered with a measurement — the
vendored copy is 93 lines stale today — rather than the predicted "it will need one".

**Delivers:** a tripwire binding the three pass-through docstrings to the contract manifest, and two
factual corrections posted to #96.

**Depends on:** nothing. Explicitly **does not** depend on the runtime merging P3 — that is Phase 8.

**Files:** new test in `python/tests/`, and a comment on issue #96 (this repo's own issue).

**Approach.** When tags 7-11 were adopted, both client docstrings "enumerated four of the eleven as
if that were the set" and the staleness was caught by hand, not by a gate. The same enumeration is
live today in three places — `python/seam_sdk/client.py`, `python/seam_sdk/aio.py` and
`ts/src/client.ts` — each naming exactly the current five pass-through fields, and nothing checks
them.

Add a test binding those enumerations to `contract/field-manifest.txt`'s `ContextBinding/*` entries
minus the frozen base six. It passes today, and it **reddens automatically** the moment tags 12-13
are declared — turning "remember to update the docstrings" into a gate, in the phase before the one
that will need it. That is the whole value: the guard must land *before* the adoption, or it is just
documentation of a mistake already made.

Separately, post a correction to #96. Four of its definitions are superseded by the proto it
describes: `unplaceable` has two producers, not one (the second fires even with a valid pre-boundary
receipt, and the proto comment says so explicitly); `unknown` contradicts the proto on staleness;
`not_revoked` says "registries" where the proto is deliberately singular; and `key_unidentified` is
scoped to this producer's revocations, where the proto scopes it to the **key fingerprint** — such a
key "cannot be cleared against ANY held producer-signed revocation, not merely this producer's". It
also asks whether the vendored spec will need a refresh: it will, because the runtime's P3 plan
changes `docs/specs/seam-event.v1.md`. Posting this now means the adoption phase builds from a
correct issue.

**Edge cases & failure modes.** The test must read the manifest, not a hardcoded list, or it is
self-calibrating and proves nothing. It must handle the TS camelCase spelling (`contentHash` vs
`content_hash`) without letting the mapping become a place where a field can hide. The base-six
exclusion must be derived and commented, not magic. If a future field is deliberately *not* named in
a docstring, the test must fail loudly rather than offer a quiet opt-out.

**Acceptance criteria.**
1. The test passes on the current tree.
2. With a scratch manifest copy declaring `ContextBinding/revocation`, the test **fails** and names
   all three files that need updating.
3. The base-six exclusion list carries its **own exact-equality assertion**, in a test named for
   being frozen. This is the honest version of the criterion: the expected set is derived from the
   manifest, but the exclusion list is hardcoded, so adding `revocation` to *it* would silence the
   tripwire. Nothing can make a hardcoded list mutation-proof — what the exact-equality pin buys is
   that widening it is a loud, reviewable edit rather than a one-word change nobody notices.
4. Both the Python and the TS docstrings are covered — a change to only one still fails.
5. A comment is posted to zer07labs/seam-sdk#96 carrying all four vocabulary corrections and the
   spec answer.

**Tests.** The tripwire itself, plus a scratch-manifest mutation test proving it fires.

**Docs.** None here; the docstrings themselves change in Phase 8.

---

### Phase 7 — Issue and assumption hygiene

**Status:** DONE. One divergence from the plan, and it is the plan being stale rather than the work
changing: **#43 needed no new comment.** Everything Phase 7 specifies for it — the yank-workflow
premise correction, the `dry_run=true`-lists-and-touches-nothing note, and the consolidation with
the 0.7.39–0.7.43 band — was already posted, across comments dated 2026-08-24 and 2026-09-02. The
plan was written without checking the thread. Rather than restate it, the posted evidence was
re-verified as still current and two things were checked that could have invalidated it:

- The 2026-08-24 comment's load-bearing claim that `python/tests/test_retracted_claims.py` keeps
  the advisory from eroding **was checked by reading the assertions, and reading was not enough.**
  Phase 4 had indeed left the version assertions untouched (`git diff 6d763c8 HEAD` on that file is
  empty), which is what the first check established — but the phase's verification round mutation-
  tested the guard instead and found it vacuous for two of the three things the comment names:
  deleting the `| **0.7.16 – 0.7.19**` row, or the `**Floor: 0.7.20.**` line, left the whole suite
  green. `"0.7.17"` never appears in the §3 table at all (the row is spelled `0.7.16 – 0.7.19`) and
  matched only unrelated prose; `"0.7.20"` appears five times elsewhere. So the comment's claim was
  true for one band and false for two, and this phase initially confirmed it on the wrong evidence
  — asserting that assertions *exist* is not asserting that they *fire*, which is this plan's own
  subject. Fixed in this phase: the row test is now parametrized over all three bands with per-band
  symptom needles, the floor is pinned as a whole line, and both were mutation-demonstrated. A
  correction was posted to #43, since the "documented, not yanked" disposition rests on that guard.
- The band the issue is deciding about was created by publishing on red CI, and `main` is red right
  now — so the obvious way for this issue to get worse is a sixth band appearing while it waits.
  It cannot: `publish.yml` resolves every `ci-ok` check run for the release SHA through the
  check-runs API and treats an absent conclusion as a refusal. A red `main` blocks publication.

A third comment repeating settled evidence would be exactly the issue noise this phase's own
Edge-cases section warns against, so none was posted. Recorded here instead, per criterion 2's rule.

**#44 was materially wrong and was corrected.** The thread's list of eight names to reserve was
derived from repo names plus judgement, and no comment stated its inclusion criterion — which is why
the error survived two sweeps. Sweeping `[project] name =` across the workspace gives **eleven**
branded distributions, all 404 on PyPI today. Two of the posted eight (`seam-verify`, a Rust
crate; `seam-adapters`, a repo name) build no Python distribution at all, and
five real ones were missing (`seam-claude-agent`, `seam-connector-sdk`, `seam-learning-batch`,
`seam-learning-keys`, `seam-aegis`). The comment leads with the criterion, not the list.

**#48 and #40 untouched, with reasons recorded here rather than posted:**

- **#48** is genuinely blocked upstream and nothing this repo does moves it. Re-verified 2026-09-04:
  `crewAIInc/crewAI#7103` is still OPEN, and `crewai` 1.15.20 on PyPI still pins
  `opentelemetry-exporter-otlp-proto-http~=1.42.0`. The weekly `framework-coinstall` probe already
  watches for the flip, so a comment saying "still blocked" adds a notification and no information.
- **#40** (an MCP server exposing the session lifecycle) is a feature request, not a defect. It is
  outside this plan's subject entirely — nothing in Phases 1–8 touches it, and triaging someone
  else's feature scope from inside a hardening run would be scope the user did not ask for.

**The enum-manifest assumption was promoted, but not on the evidence the plan proposed.** The plan
said to promote it by citing the runtime's `buf` config. Citing a config is the same "the check's
name implies its coverage" reasoning this whole plan exists to remove, so `buf` 1.66.0 was run
against a scratch module pair instead. Both forms were refused: a renumber (name kept, tag moved)
and — the case that actually matters — a **swap**, where two values exchange tags so that no name
and no number is deleted, and a delete-keyed rule would see nothing. The swap is caught by
`ENUM_VALUE_SAME_NAME`. The blast-radius clause's "or misses this case" half is now measured false;
its "if that upstream gate is ever bypassed" half survives and got *narrower*: the step carries
`if: github.ref != 'refs/heads/main'`, so it compares PR heads only, and the push that skips it is
the push that publishes the BSR module this SDK generates from. Recorded in DECISIONS.md; not filed
against `seam-runtime`, since it is a hypothesis about another repo's branch protection that this
repo cannot observe.

**Delivers:** two open issues corrected with evidence, one assumption promoted, and the remaining
open issues left honestly open.

**Depends on:** nothing.

**Files:** `ASSUMPTIONS.md`, `DECISIONS.md`; comments on issues #43 and #44.

**Approach.** Four items, none of which invents work:

- **#43** carries a premise that is now false: "No yank workflow currently exists."
  `.github/workflows/yank.yml` has existed since Phase 10 of the previous plan —
  `workflow_dispatch`-only, explicit version input, `dry_run` defaulting true, name-locked to
  `seam-sdk`. Post the correction, and note that verifying whether 0.7.7 is still present needs no
  local credential: a `dry_run=true` dispatch lists matches and touches nothing. Consolidate with the
  0.7.39–0.7.43 band so both Cloudsmith decisions are answered together rather than separately.
- **#44** needs a PyPI account, which this repo cannot supply — but the reconstruction half is
  doable and was done. The org ships **eleven** `seam-*` Python package names across the workspace:
  `seam-sdk`, `seam-agent-core`, `seam-claude-agent`, `seam-connector-sdk`, `seam-council`,
  `seam-crewai`, `seam-langchain`, `seam-learning-batch`, `seam-learning-keys`, `seam-strands`,
  `seam-aegis` — and **all eleven return 404 on PyPI**, i.e. unregistered and squattable, verified
  2026-09-03. The comment must state its inclusion criterion, because an earlier count of "seven"
  (`seam-sdk` plus the six adapters packages) would under-reserve by four. Two further non-branded
  names ship from the connectors repo, `compliance-report` and `ingest-history-iceberg`, also both
  404; whether generic names are worth reserving is a judgement call to put to the operator rather
  than to answer here.
- **#48** is genuinely blocked upstream and needs nothing: `crewAIInc/crewAI#7103` is still open,
  `crewai` still pins `opentelemetry-exporter-otlp-proto-http~=1.42.0`, and the weekly
  `framework-coinstall` probe already watches for the flip. Leave open, add nothing.
- **ASSUMPTIONS.md**: the enum-manifest entry's re-open trigger was "whoever next reviews `buf
  breaking` config for seam.api.v1's enums". That review is doable now — the runtime sets
  `breaking: use: [WIRE_JSON]` and runs `buf breaking --against` main in CI, and WIRE_JSON covers
  enum value name/number binding — so the entry's premise holds and it can be promoted with those
  citations. Everything else in the backlog needs a runtime answer or a future event and stays
  `UNCONFIRMED`, reviewed and dated.

**Edge cases & failure modes.** Issue comments are outward-facing and go only to this repo's issues
(#43, #44, #96) — no sibling-repo issue actions. Nothing is closed: #43 and #44 both still need a
credential and a human decision, and closing them to shrink the count would be dishonest.

**Acceptance criteria.**
1. Comments posted to #43 and #44 with the evidence above; neither issue closed.
2. #48 and #40 untouched, with the reasoning recorded in this plan rather than as issue noise.
3. The enum-manifest assumption is promoted with `buf` config citations, or explicitly left
   `UNCONFIRMED` with a reason if the review does not in fact settle it.
4. Every other `UNCONFIRMED` entry is re-dated with a one-line review note.
5. Full python suite green (ASSUMPTIONS.md and DECISIONS.md are scanned by the doc guards).

**Docs.** `ASSUMPTIONS.md`, `DECISIONS.md`.

---

### Phase 8 — The ACDP P3 adoption, specified and BLOCKED

**Status:** BLOCKED — not attemptable this cycle.

**Delivers:** the complete, reviewed specification of the adoption change, so that landing it once
the BSR republishes is mechanical rather than a fresh design exercise.

**Depends on:** *(satisfied 2026-09-04 — recorded here because the acceptance criteria name it as
the checkable blocking fact.)* This depended on the runtime merging `feat/acdp-p3-key-revocation`
to `main`, which is what `buf push`es the BSR. It merged as `ac325d7` (#531); `origin/main`'s
`ContextBinding` carries tags 12-13 and the BSR has republished — proved by this repo's own `main`
CI failing with `+ ContextBinding/revocation` and `+ ContextBinding/revocation_trust_class` in both
the python and typescript jobs. The phase stays **BLOCKED** on operator decision, not on upstream.

**Files (when unblocked):** `contract/field-manifest.txt`, `contract/expected-local-lag.txt`,
`python/tests/test_field_manifest_gate.py`, `python/seam_sdk/client.py`, `python/seam_sdk/aio.py`,
`ts/src/client.ts`, `verify/docs/seam-event.v1.md`, `CLAUDE.md`, `COMPATIBILITY.md`, `CHANGELOG.md`,
`DECISIONS.md`.

**Approach.** Do **not** attempt any of this now: declaring the fields before the BSR carries them
turns CI red on every PR, because CI regenerates fresh from the BSR and the fields would be missing.

The single design decision this phase turns on is `contract/expected-local-lag.txt`. That file is an
**exact-match** recording — "any SUPERSET, SUBSET, or other deviation is NOT a match and produces the
FULL, un-downgraded refusal". Declaring tags 12-13 makes the local gap seven fields, so leaving the
file at five would make every local run print the full refusal, whose wording, exit code and
direction are identical to a real field removal. That is precisely the gate-blindness the file exists
to prevent, so it is not an option.

The right answer is to **re-record the lag to seven fields with a bumped `EXPECTED-FROM`, in the same
commit as the manifest declaration**. The file's own header sanctions exactly this ("re-record
deliberately… if a new, real local/BSR gap is expected after the next regeneration"), and this is not
the case its warning targets: the warning is about reacting to unexplained new output, whereas here
the seven-field gap is predicted in advance from a named upstream change, dated, and recorded before
the gate ever reports it.

Two honesty riders travel with that. First, bumping `EXPECTED-FROM` resets the 60-day scenery
trigger, so the `DECISIONS.md` entry must carry the original 2026-08-31 date forward, keeping the
cumulative age visible. Second, count it correctly: `git log --follow contract/expected-local-lag.txt`
shows a single commit, its creation, so the seven-field change is the **first** re-record and the
second recording. The point at which the better trade becomes a one-time `buf registry login` on the
workstation and deleting the file outright is therefore the re-record *after* this one — flag it to
the operator then, and do not let the trigger fire a cycle early.

The commit must be atomic across: the two manifest lines, the lag re-record, `_KNOWN_LAG_FIELDS`,
both strip helpers, the exactly-N test (its name and its set), and `CLAUDE.md`'s "exactly those five
fields" prose. Splitting any of these produces either a red suite or documentation the gate
contradicts.

Also owed at adoption: the three docstrings (Phase 6's tripwire will be red and will name them), the
verbatim vendored-spec refresh with its `spec-pin` re-pin, and the W4.3 preimage re-answer — which is
`no` for tags 12-13, since they are `seam.api.v1` response fields rather than sealed columns, and
must be recorded rather than inherited, per that decision's own standing rule.

**Acceptance criteria (for the future run, not this one).**
1. This phase is marked BLOCKED in both the plan and `PROGRESS.md`, and is not attempted.
2. The specification above is complete enough that the adoption needs no new design decisions.
3. The blocking condition is stated as a checkable fact: tags 12-13 present on the BSR module.

**Docs.** All of the above, when unblocked.

---

## Long-term posture

The four crypto fixes are all **narrowing** — they refuse inputs that previously produced a digest.
That direction is deliberate and is the only safe one for a verifier: widening what is accepted can
never be undone without breaking callers who came to rely on it, whereas narrowing shows up
immediately and loudly. The one caller-visible break (TS refusing `Map`/`Set`/`Date`) is recorded as
such in `DECISIONS.md` rather than shipped quietly.

The `exp` decision is the closest thing here to a one-way door: adopting Go's truncating,
number-only rule as normative fixes the semantics for five languages at once, and reversing it later
would mean re-accepting tokens four languages currently reject. It is taken deliberately, on the
grounds that Go's is the only rule with a written rationale and that it is the strictest of the three.

Phase 5 deliberately ships a tripwire rather than a second RPC manifest. Choosing the manifest format
now, for a surface with zero entries, would be guessing at a shape; the tripwire makes the arrival of
the first entry loud, which is when the format question can be answered against something real.

## Enterprise concerns

**Release integrity** is Phase 1's whole subject, and it is the highest-blast-radius item in the
plan: while the latch sits false, a runtime dispatch that drops `wire_framing_version` publishes an
SDK that may not implement the runtime's framing. That is the 0.7.17 mechanism, and it is currently
un-gated.

**Verifier trustworthiness** is Phases 2 and 3. The product claim is that a counterparty can
independently recompute and verify a decision; a digest that aliases, or a token whose expiry is
read differently in two languages, undermines exactly that claim. None of these are reachable from
in-range wire traffic, which is why they are hardening rather than incidents — but they are all
reachable from the public API an integrator would use.

**Contract safety** is Phases 5, 6 and 8. The recurring lesson across this repo's history is that
additive contract changes arrive silently; every gate here exists because one already did.

**Observability of the gates themselves** is Phase 4. A guard that cannot fail is worse than no
guard, because it is counted as coverage.

## Open questions

1. **`toJSON` objects in TS JCS** (Phase 3). An object carrying a `toJSON` method is neither plainly
   a plain object nor plainly a foreign type. Default chosen: refuse it, consistent with "refuses any
   input it cannot faithfully represent". Cheap to reverse; log `UNCONFIRMED`.
2. **The `engines` range** (Phase 3). Default chosen: the versions CI actually tests, and no upper
   bound excluding current Node — because the finding that would have justified one is refuted.
3. **A second RPC manifest vs one package-qualified file** (Phase 5). Deferred deliberately until a
   `seam.event.v1` verb actually exists. Recorded, not guessed.
4. **The lag file's next re-record after Phase 8's** (Phase 8). Recommendation to the operator: at that
   re-record, do the one-time `buf registry login` and delete the file instead. This is a judgement
   call about workstation setup and belongs to the operator, not to this plan.
5. **The two Cloudsmith bands** (Phase 7). Still the operator's decision, now consolidated so both
   can be answered at once. The adjacent precedent — "documented, not deleted" — suggests the likely
   answer but must not be assumed.

6. **How `PROGRESS.md` transitions between workstreams.** Found while preparing this plan's own
   handoff, and deliberately not settled under that pressure. The documented convention is that the
   file is replaced per workstream and the old trail lives in git history — but the citation guard
   now binds 25 anchored/quoted claims and a 30-citation floor to its *content*, so a replacement
   turns 25 tests red and the only path to green is deleting guard entries. The file also cites
   itself by line in three places, at least two of them live and accurate, so prepending silently
   repoints them at different content while still resolving — no test fails and the citations are
   simply wrong. This cycle appends, which shifts nothing and retires nothing. That is correct but
   does not scale: the file grows without bound. The real options are (a) split the guard's anchors
   onto a stable per-workstream archive path, (b) scope the anchors to the active section only, or
   (c) accept unbounded growth and say so. Worth one deliberate decision, not a default.

## Plan review

**Round 1 — Fable, 2026-09-03. Verdict: REVISE. Applied in full.**

The reviewer re-ran every demonstrated behaviour against the built SDKs rather than trusting the
write-up, and independently re-tested the Context §3 refutation with a *stronger* method than this
plan used — a cross-process TS↔Python differential (the original harness's own comparison pair) with
hex-armored transport that the `splitlines()` bug cannot touch, 180,000 inputs after a 20k
JIT warm-up: zero mismatches, three seeds. It then reconstructed the original failure and confirmed
the transport explanation. The refutation stands.

Nine items were raised and all nine are applied:

1. **Phase 1's guard was circular** — the original draft proposed asserting that a `false` latch
   implies its tracking issue is recorded open, both fields living in the same committed file. The
   staleness that actually happened leaves both stale together, so the test would have stayed green
   forever. Replaced with the workflow-level check: a non-empty `$DISPATCHED` alongside a `false`
   latch is proof-of-staleness from live data. This is the most important finding in the round.
2. **Phase 2's Python fix contradicted its own edge case** — moving the recompute inside the existing
   blanket `except Exception` would swallow the `TypeError`s the same paragraph says must propagate.
   Now prescribes the disambiguated edit, with a criterion pinning it.
3. **`isinstance(exp, (int, float))` accepts `True`**, since `bool` subclasses `int` — violating
   Phase 3's own "booleans must be refused" bullet. Fixed, and the shared vector extended to boolean,
   `null` and absent `exp` so the criteria can actually falsify it.
4. **Phase 5's criterion 3 named a mechanism that does not exist** — there is no env override for the
   event grpc stub; `PY_GRPC` is api-only. The phase now specifies adding `SEAM_PY_EV_GRPC`.
5. **Phase 6's criterion 3 was not achievable** — a hardcoded base-six list can always be widened to
   silence the tripwire. Restated honestly around an exact-equality pin on the exclusion list.
   The reviewer also found a **fourth** superseded definition in #96 (`key_unidentified`'s scope is
   the key fingerprint, not the producer), now carried into the correction.
6. **"Seven Python package names" was wrong** — there are eleven `seam-*` names, all verified 404.
   Posting seven would have under-reserved by four.
7. **Phase 2 left v2's unsafe-`number` question undecided.** Decided: adopt `v3Uint`'s semantics,
   and record the resulting narrowing rather than letting "no in-range value changes by a single
   byte" paper over the difference between bytes and acceptance.
8. **Phase 8 miscounted the lag re-record.** `git log --follow` shows one commit, so the seven-field
   change is the first re-record, not the second; the "delete the file instead" trigger moves out a
   cycle accordingly.
9. **Precision fixes** — U+001C is escaped by `JSON.stringify` and so is not a reachable corruption
   vector; the Phase 4 env-flag "precedent" now names `ci-ok`'s skipped-required-job rule as an
   analogy rather than implying a test-level precedent that does not exist.

The reviewer also supplied evidence that **strengthens** Phase 3's normative choice: Java and Kotlin
already implement Go's truncating, number-only `exp` rule, so adopting it changes two implementations
rather than three and follows the existing 3-of-5 majority — not merely "the only written rationale".

Confirmed sound without change: the phase boundaries (including Phase 3's honestly-textual dependency
on Phase 2), Phase 8's BLOCKED status and lag-file reasoning, Phase 5's tripwire-over-second-manifest
deferral, the digest-contamination honest negative, and the byte-identity claim in Phase 2 (every
conformance `u64` is far below 2^53, and no existing test pins v2's wrap).
