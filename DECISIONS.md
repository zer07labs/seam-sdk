# Decisions

The durable record of `/reconcile` passes over `ASSUMPTIONS.md`. Each entry: the original
assumption, the independent recommender's analysis, the human verdict, and the resulting status.
`/ship` and any later reconciliation read this file instead of replaying the conversation that
produced it.


## 2026-09-05 — /reconcile over `plans/digest-correctness-and-gate-repair.md`

Closing pass for the whole plan. Most of the backlog was reviewed and re-dated during Phase 7, so
this records only what **moved** since, rather than restating fourteen unchanged entries.

### One assumption got its first real test, and it held

**"Phase 8 converts the vendored citation rather than grandfathering it"** was CONFIRMED on a
*prediction*, and the entry said so honestly: an earlier version claimed it was "vindicated within
the same run", which was vacuous — the converted citation had not moved because nothing had
refreshed the vendored file. The status was rewritten to rest on the durable reason instead: *"the
copy is refreshed whole-file on upstream's cadence, so the next refresh drifts any line anchor into
it, whenever that is."*

**This run performed that refresh.** Phase 8 re-pinned `verify/docs/seam-event.v1.md` to `ac325d7`,
whole-file and verbatim: **69 insertions, 5 deletions**. Every line number below the first insertion
moved. Nothing broke, because the citation had been converted to needle-based rather than
grandfathered — which is precisely the outcome the two alternatives differ on. Had it been
grandfathered with a `#73` comment, this refresh is the run that would have drifted it.

**Verdict: CONFIRM, and the evidence is upgraded** from "durable reason, not in-run evidence" to
measured. The prediction named an event that has now happened.

### One assumption changed shape rather than status

**"`contract/expected-local-lag.txt` is a window, not a permanent excuse"** stays `UNCONFIRMED`, but
what it is waiting on has changed. It was recorded against a five-field gap whose stated cause —
"the BSR has not caught up" — became false while nobody was looking. Phase 8 re-recorded it to seven
fields, corrected the cause (the BSR is *ahead*; the local stubs are old), and armed the trigger
explicitly: the **next** re-record, not this one, is the point at which curating the file stops being
the better trade and a one-time `buf registry login` on the workstation plus deleting the file
outright becomes it. That is now written in the file in capitals rather than inferred from
`git log`, which is what the entry's own honesty riders asked for.

### The rest

Fourteen entries stay `UNCONFIRMED`, each carrying a 2026-09-04 review note saying what the review
found. Three of them — the `tool_input` canonical-bytes entry, the JCS large-integer entry, and the
Cloudsmith quarantine entry — gained the **re-open trigger they had never had**, which is the
difference between an open question and scenery.

Nothing in the backlog is blocked on this repo. What remains needs a runtime answer, a consumer, a
credential, or a JDK this workstation does not have — and each entry names which.

### Plan status

All eight phases DONE. Phase 8 was written as BLOCKED and specified in advance; it landed on
operator go-ahead once the blocker dissolved upstream, and needed no design decisions because the
specification already existed. That is the argument for writing a blocked phase down rather than
deferring it, and it is worth carrying to the next plan.

---


## 2026-09-04 — ACDP P3 adoption: W4.3 re-answered, and the lag file re-recorded rather than left lying

Phase 8 was written as BLOCKED and specified in advance. Both halves of that turned out to matter:
the blocker dissolved (seam-runtime merged `ac325d7`, #531, and `buf push`ed it), and because the
specification was already written, the adoption needed no new design decisions — only execution.

### W4.3: do tags 12-13 enter the record-digest preimage? **No.**

W4.3's standing rule is that this must be **re-answered per regeneration and never inherited**, so
the previous "no" for the P1a/P2 fields does not carry. Re-answered by its own method — *not* "is
the field new?" but **"is it a sealed column?"** — and confirmed three independent ways:

1. **`seam.event.v1` never mentions `revocation`.** `grep` over the event proto: zero hits. The
   record digest is computed over `DECISION_SEALED`'s payload columns; a field absent from the
   event wire cannot be one.
2. **`verify/src/` does not mirror `ContextBinding` at all.** Zero hits across the crate. The
   verifier mirrors the event wire (`SeamEventPb`, `DecisionSealedPb`, …), and `ContextBinding` is
   not part of it.
3. **The runtime's own spec says so in a heading** — `docs/specs/seam-event.v1.md` §"`revocation`
   and `revocation_trust_class` — served only, never sealed", mirroring the wording it already used
   for P2 `retraction`.

Both fields are `seam.api.v1` **response** fields on `ResolveContext`. **Consequence:**
`verify/src/wire.rs` needs no change, `conformance/vectors.json` is untouched, and W7 does not
engage. Same structural answer as the P1a/P2 round, reached independently rather than assumed.

### The lag file: re-recorded to seven, with the trigger armed rather than reset

`contract/expected-local-lag.txt` is an **exact-match** recording — any superset, subset or other
deviation produces the full, un-downgraded refusal, whose wording, exit code and direction are
identical to a real field removal. Declaring tags 12-13 makes the local gap seven fields, so leaving
the file at five would have made every local run print that refusal. Training readers to scroll past
a refusal is the precise gate-blindness this file exists to prevent, so leaving it was not an option.

Re-recorded to seven in the same commit as the manifest declaration, which the file's own header
sanctions ("re-record deliberately… if a new, real local/BSR gap is expected after the next
regeneration"). This is not the case its warning targets: the warning is about *reacting to
unexplained new output*, whereas this gap was predicted in advance from a named upstream commit,
dated, and written down before the gate ever reported it.

**Two honesty riders travelled with it, both discharged:**

- **Bumping `EXPECTED-FROM` resets the 60-day scenery trigger**, which would hide how long this file
  has stood in for a regeneration nobody here can run. The file now carries an explicit
  **RE-RECORD HISTORY** block (2026-08-31 first recording, 2026-09-04 first re-record) so cumulative
  age survives the bump, and this entry carries the original date forward.
- **Counted correctly.** `git log --follow` on the file shows a single commit — its creation — so
  this is the **first** re-record and the **second** recording. The point at which the better trade
  becomes a one-time `buf registry login` on the workstation and deleting the file outright is the
  re-record *after* this one. The file says so in capitals, and deliberately does not fire it now.

### One thing the specification did not anticipate, and it was a defect in the file itself

The lag file's header explained the gap as "the BSR has not caught up". That was true when written
and is now **backwards**: the BSR is ahead — it republished P1a/P2 and then P3 — and it is the local
stubs that are old. The file was teaching a wrong cause on every local run, and the wrong cause
points at the wrong fix (wait for upstream, rather than regenerate). Corrected in the same commit,
with the correction called out in the file so the next reader knows the earlier framing was wrong
rather than merely differently worded.

### Not wired into the hand-written clients, and that is the recorded answer

The field-surface gate's refusal text requires a decision *before* the manifest moves: wire the
field into the hand-written clients, **or record why not**. Recording why not.

`revocation` and `revocation_trust_class` are pass-through `ContextBinding` slots, and the clients'
contract for that message is already pass-through — `resolve_context` returns the generated message
so every field the contract carries arrives without a per-field accessor. That is what the three
"ACDP receipt slots" docstrings promise, and Phase 6's guard enforces that they enumerate every
slot. Adding named accessors for these two would make them the only `ContextBinding` fields with a
bespoke surface, for no capability a caller does not already have.

The docstrings are updated to name both new slots — required, not optional: Phase 6's tripwire
derives its expected set from the manifest and goes red the moment the manifest declares a slot no
docstring names. That is the guard working as designed, on the first real field it ever saw.
---

## 2026-09-04 — promoting the enum-manifest assumption by executing `buf`, not by reading its config

`contract/field-manifest.txt` spells enum entries `<Enum>#<VALUE>` — names only, no tag numbers. The
recorded justification was that the tag is already protected upstream by `buf breaking`, so
duplicating it here would create a second copy to keep in sync. The assumption's re-open trigger was
"whoever next adds or reviews `buf breaking` config for `seam.api.v1`'s enums", and that review came
due this cycle.

**The config says what the plan said it says.** `../seam-runtime/buf.yaml:23-25` sets
`breaking: use: [WIRE_JSON]`, and `../seam-runtime/.github/workflows/ci.yml:173-181` runs
`buf breaking --against` a materialised `main` branch.

**That was not treated as sufficient.** "The config names a category that sounds like it covers
this" is the same reasoning this repo keeps finding defects in — a check whose result is assumed
from its name rather than observed. `buf` 1.66.0 is installed locally, so both forms of the gap were
run against a scratch module pair instead:

| mutation | what a delete-only rule would see | `buf breaking --against` (WIRE_JSON) |
|---|---|---|
| **renumber** — `FOO_A` keeps its name, tag `1` → `3` | number 1 deleted, number 3 added | **refused twice** — once for the deleted name, once for the deleted number |
| **swap** — `FOO_A`/`FOO_B` exchange tags `1`/`2` | *nothing*: no name and no number is deleted | **refused** — `Enum value "2" ... changed name from "FOO_B" to "FOO_A"` |

The swap is the case that matters. It is the only same-name renumber that survives a rule keyed on
deletion, and it is caught by a different rule (`ENUM_VALUE_SAME_NAME`) that binds number → name.
So `WIRE_JSON` protects the name↔number binding in **both** directions, and the assumption's
"if that upstream gate ... misses this case" clause is measured false rather than hoped against.

**Verdict: CONFIRM.** The name-only manifest spelling stays. Adding `=<tag>` would buy nothing the
upstream gate does not already provide, at the cost of a manifest line that churns on every
proto-side renumber.

**One thing changed, and it is a narrowing rather than a confirmation.** The entry's blast-radius
clause bundled two risks — "if that upstream gate is ever bypassed **or misses this case**". The
second half is now settled. The first is not, and is more specific than the entry implied: the
`buf breaking` step carries `if: github.ref != 'refs/heads/main'`, so it compares **PR heads only**,
and the same push to `main` that skips it is the push that publishes the BSR module this SDK
generates from. A change reaching `main` outside a PR is therefore never compared. That is a
question about the runtime's branch protection, not about `WIRE_JSON`'s coverage, and it is out of
this repo's reach — recorded here so the next reader inherits the narrowed risk rather than the
original bundled one.

**Not filed as an issue in `seam-runtime`.** It is a hypothesis about another repo's branch
protection that this repo cannot observe, and filing "your gate might be bypassable" without
evidence that it is would be noise. The record is here; if a same-name renumber ever does reach the
BSR, this entry is where the explanation already sits.

---

## 2026-09-04 — the remaining `UNCONFIRMED` backlog, reviewed and re-dated

Thirteen entries stay `UNCONFIRMED`. Each carries a one-line note dated 2026-09-04 saying what the
review found, so "unchanged" is a finding rather than an omission. Two moved in substance without
changing status:

- **`contract/expected-local-lag.txt` is a window, not a permanent excuse** — the window has begun
  closing on its own. seam-runtime merged its ACDP P3 key-revocation work and pushed the BSR, so a
  CI regeneration now emits two `ContextBinding` fields the manifest does not declare, so `main`
  fails on the gate's NOT-IN-THE-MANIFEST branch — a two-field **surplus**, which never consults
  the lag file at all. (Seven is the local-stub-vs-BSR delta; it becomes a recorded *gap* only
  once tags 12-13 are declared. An earlier wording here stated the direction backwards.) Local
  checkouts still show exactly the recorded five, so this checkout stays green while `main` does
  not. Resolving it needs BSR regeneration credentials this
  workstation lacks, which is the same blocker Phase 8 waits on.
- **Cloudsmith quarantine for the 0.7.39-0.7.43 band** — consolidated onto issue #43 on 2026-09-02
  so both known-bad bands get one answer. Re-verified that nothing can quietly create a third band
  while the decision waits: `.github/workflows/publish.yml:69-148` resolves every `ci-ok` check run
  for the release SHA through the check-runs API and treats an absent conclusion as a refusal, so
  today's red `main` blocks publication rather than repeating the pattern that produced the band.

The other eleven are unchanged for the reason each records: they need a runtime answer, a consumer,
a credential, or a JDK this workstation does not have.

---
## 2026-09-04 — adopting Go's `exp` rule as normative for all five SDKs

Five SDKs verified a TCT and five decoded its `exp` claim differently. That is not a style
difference: a capability token that verifies on two of five implementations and is refused by three
is a security boundary that depends on which language happens to be checking it. Something had to be
declared normative, and the candidates were the three rules actually in the tree:

| rule | implementations | accepts |
|---|---|---|
| `payload["exp"].(float64)` + `int64(exp)` | Go, Java, Kotlin | JSON numbers only, truncated toward zero |
| `int(payload.get("exp", 0))` | Python | the above, plus numeric strings and `true` |
| `now >= (payload.exp ?? 0)` | TypeScript | the above, plus `"1e10"`, fractions, objects, arrays |

**Go's rule was adopted.** Three reasons, in the order they carried weight:

1. **It was already the majority.** Java and Kotlin implement it independently (`instanceof Number`
   + `longValue()`, `as? Number` + `toLong()`). Adopting it moved two SDKs; adopting either other
   rule would have moved three, and would have loosened a verifier to do it.
2. **It is the strictest.** For a token verifier, the safe direction is to refuse what you do not
   understand. Both other rules reach their extra acceptances through *coercion* — `int("1e10")`,
   `ToNumber(true)` — and a coercion in a verifier is a value nobody supplied being treated as one
   that was.

**The rule had to be BOUNDED to be total, which verification caught and the first draft missed.**
Go's `int64(exp)` is implementation-defined when the value does not fit: measured, arm64 saturates
and `{"exp": 1e300}` verifies, while amd64 yields `INT64_MIN` and refuses the identical token. "Adopt
Go's rule" would therefore have meant different things on different machines, with CI's own
architecture as the accidental arbiter — a normative rule that is not one. All five now refuse `exp`
outside `[-2^63, 2^63)` explicitly. Python and TypeScript need no such bound alone; they carry Go's
constraint so the five agree, which is the same trade this whole decision is made of.
3. **It is the only one with a written rationale.** The type assertion that *is* the rule
   (`exp, ok := payload["exp"].(float64)`, `go/crypto/crypto.go:194`) and the truncation semantics
   below it (`go/crypto/crypto.go:198-203`) are both argued in comments at the code; the other two
   rules were the shortest expression that worked in that language.

The alternative considered and rejected was **union semantics** — accept anything any SDK accepts,
so nothing that verifies today stops verifying. It is the compatible choice and it is the wrong one:
it would have made `{"exp": {"seconds": 2000000000}}` a valid token in all five languages, because
`0 >= NaN` is false in JavaScript and a guard whose false branch is the permissive one fails open on
every input it cannot parse. Compatibility with a bug is not a property worth preserving in a
verifier.

**What made the decision checkable rather than declarative** is
`conformance/tct_exp_extended.json` — 18 signed tokens, machine-emitted, whose expected verdicts are
computed from the *rule* by `scripts/emit_tct_exp_vectors.py` rather than read out of any
implementation. Go, Python and TypeScript each read it from their own test suite. A vector whose
expectations are recorded from the code it checks cannot fail; it only writes down what the code
already did.

One case in it is worth naming because the first draft got it wrong. `exp: true` coerces to `1` in
both Python and JavaScript, so the token **verified** at any clock below one second — and at a
realistic timestamp it reads as long expired. A vector written with a plausible `now` would have
asserted cross-language agreement that was entirely accidental, and would have stayed green through
the exact bug it was named after. Most type cases pin `now = 0`; the three that do not —
`boolean_false`, `null` and `absent` — pin `now_s: -1` deliberately, because at `now = 0` the
coercing rule refuses them too and the case would assert nothing. Each says so in its own `why`.

Java and Kotlin do **not** yet read the vector. They already implement the rule — that is why it was
adopted — but this workstation has no JDK, so a consumer written for them could not be run before
being committed, and an unverified test is how a vacuous one lands. Tracked as follow-up rather than
shipped blind.

**Status:** DECIDED. Recorded here rather than in `ASSUMPTIONS.md` because it is settled, not
pending: the rule is implemented in five languages and pinned by a vector in three.


## 2026-09-04 — `jcsCanonicalize` refuses non-plain objects by a RULE, not a denylist


**This is a breaking change to a public API.** Stated in those words because the phase's own
acceptance criterion requires them, and because the SDK does not choose its own version — it ships
under whatever number the runtime's history computes, so a consumer who reads only the version has
no way to know. `Map`, `Set`, `Date` and class instances previously canonicalized to `{}` and now
raise; a caller relying on that silent empty digest will break at the call, which is the point.
`Date`, `Map`, `Set`, `RegExp`, typed arrays, boxed primitives and class instances all satisfy
`typeof v === "object"`, so JCS walked them with `Object.keys` and emitted whatever own enumerable
properties they happened to have. For `Date`, `Map`, `Set` and boxed numbers that is nothing, so they
became `{}` — and `{ deadline: new Date(...) }` had the same `tool_input_digest` for every possible
deadline, with `callSig` signing it.

The other half needs stating, because the tidy version of that sentence is false: a `Uint8Array`
canonicalized to `{"0":1,"1":2}`, a boxed string to `{"0":"x"}`, and a class instance to its own
fields. Those did **not** lose their contents. Refusing them is a genuine narrowing of working
behaviour, taken because Python refuses every one of them and the property being bought is that the
two agree on what has a digest — not because those digests were meaningless.

The obvious fix is a denylist — refuse `Date`, `Map`, `Set`, and so on. It was rejected. An
enumeration is correct only until someone passes the exotic type it forgot, and the failure mode it
leaves open is not "an error" but "silently digests an object with none of its contents". This repo
has now found the same defect in three places (`u64le`'s wrap, the surrogate object key, this), and
the shape has never varied: **a rule living in more than one place, with one of the copies
incomplete.** A denylist is that shape by construction.

The rule adopted instead: an object is canonicalizable iff its prototype is a **root** — `null`, or
something whose own prototype is `null`. A plain `{}` and `Object.create(null)` qualify; everything
with a constructor between it and `Object.prototype` does not. It mirrors Python's `isinstance(v,
dict)`, which is a nominal check and has never had this bug.

Testing the chain's **depth** rather than `proto === Object.prototype` is deliberate and
load-bearing. An object from a `vm` context or another frame has its own `Object.prototype`, so an
identity check would refuse a perfectly ordinary data bag; its prototype's prototype is still
`null`. A test pins this specifically, and reverting to the identity check reddens exactly that test.

Two behaviours were left as they are, and both are decisions rather than omissions:

- **`toJSON` is not honoured.** An object carrying one currently raises, because the walk reaches the
  function value. `JSON.stringify` would call it. Honouring it would mean the canonical bytes depend
  on a method the digest cannot see, and Python has no equivalent — so a `toJSON` that changed would
  silently change a signed digest in one language only. Refusing is the cross-language-safe answer.
  Logged UNCONFIRMED in `ASSUMPTIONS.md`, since it rests on no caller relying on it.
- **Symbol keys are still dropped silently.** `Object.keys` skips them, as `JSON.stringify` does, and
  Python cannot express a symbol key at all. This one is genuinely a JSON-standard behaviour rather
  than a hole in the guard, but it is worth writing down that it was looked at and not an oversight.

**Status:** DECIDED.


## 2026-09-04 — `verifyChainHeadAttestation` raises on a caller bug instead of returning `false`


**This is a breaking change to a public API.** Same wording, same reason as the entry above: a
wrong-typed `attested_head` that previously returned a clean `False` now raises, so a caller that
treated `False` as "did not verify" now sees an exception instead. That is the correction — the two
were never the same answer — but it is a break, and it ships under a number that cannot say so.
A verifier that throws is normally a bad verifier: a caller writing `if (!verify(...)) reject()`
crashes where it should have rejected. That is why the blanket `catch { return false }` was there,
and it is the strongest argument against this change.

It loses to a sharper one. **`false` is not a neutral answer here — it is a specific claim**, and the
claim is "this attestation did not verify". A caller who passed a string `attestedLen`, or the hex of
an `attestedHead`, was told the audit chain was bad. An operator handed that goes looking for a
compromise. Python's twin already documented this as "the one outcome worse than the crash", and had
implemented it for five of its six arguments; `signature` was the hole.

**`signature` is also the one place this is a narrowing rather than a repair**, and the first draft of
this entry got it backwards — worth recording, because the error was the easy kind to make. TypeScript
did not answer `false` to a hex-string signature: it answered `true`, correctly, because
`@noble/curves` types the parameter as `Hex = Uint8Array | string` and decodes it. So a JavaScript
caller passing hex had working verification and now gets a `TypeError`. Only Python's `False` there
was a lie.

Refusing it anyway is the deliberate call. The alternative is one language silently coercing a string
the other refuses — the divergence this phase exists to close — and closing it toward the stricter
side is the same choice made for `exp`. It is a real cost, disclosed as one in `COMPATIBILITY.md` §10
under "What this costs you", not counted as a bug fixed.

What makes raising safe is that **a wrong type cannot arrive from an attacker.** Attacker-controlled
bytes decode, through protobuf, into correctly-typed values with hostile *contents*. So this never
converts an attack into a crash; it converts a programming error into a visible programming error.
Everything genuinely untrusted — out-of-range integers, a malformed AID, a wrong-length or forged
signature, a tampered head — still returns `false`, in both languages, measured over 20,000
randomized well-typed inputs against `HEAD` with 0 verdict changes.

The boundary needed one non-obvious call. TypeScript's `uintSlot` refuses a `number` above 2^53
because its *neighbours* are not representable — but `2 ** 60` itself is exact, and Python holds it
as an ordinary integer, digests it, and answers `false`. Hoisting that check out with the type checks
would have made TypeScript throw where Python returns `false`: **closing one divergence by opening
another.** It stays inside the catch, so both reach the same `false`. The split is therefore not
"type checks out, value checks in" but "could this have arrived over the wire?" — a string, a
boolean, a `null` and a fractional number could not; a large integer could.

Error *classes* still differ across the two languages for one input: a fractional `attestedLen`
raises `RangeError` in TypeScript and `TypeError` in Python, because JavaScript has one number type
and "not a whole number" is a fact about the value there. Both refuse, which is the property that
matters. Identical exception classes across two languages is not a promise this SDK makes.

**Status:** DECIDED.

## 2026-09-03 — refusing a `number` above 2^53 in the v2 record digest: a narrowing, not a fix

Three of the four TypeScript changes in this phase close a demonstrated **alias** — two distinct
inputs reaching one digest — and need no justification beyond that. `recordDigestV2` with
`sealedAt: 2n**64n + 5n` produced the same 32 bytes as `sealedAt: 5n`, byte-for-byte, because
`DataView.setBigUint64` applies ToBigUint64 and wraps in silence. A digest that does that is not
doing the one thing a digest is for.

The fourth is different and is recorded here because it would otherwise pass as part of the same
sweep. **A `number` above 2^53 is now refused in the v2 and chain-head-attestation framings**, where
it was previously accepted. There is no collision *within* TypeScript: `2**60` is exactly
representable as a double and hashes deterministically. Nothing was broken for a caller who only
ever used TypeScript.

It is refused anyway, because the value the caller *meant* and the value that gets hashed have
already parted company by the time it reaches the digest. Above 2^53 a JS `number` is the nearest
double, so `2**60 + 1` silently is `2**60`; Python's exact integers and the `verify/` crate's `u64`
carry the value the caller wrote. A digest computed in TypeScript would disagree with the same
record digested anywhere else — the cross-language divergence this whole phase exists to close, in
the one arm where it does not present as a same-language collision. `bigint` is how TypeScript says
an integer it means, and the error message says so.

The rule was already written and already argued, for v3 only, in the function then called `v3Uint`.
Its reasoning is entirely about `DataView` and IEEE doubles, neither of which knows which framing it
is serving, so it always applied to v2 and the attestation preimage too. Renamed to `uintSlot` and
routed `u64le`/`u32le` through it, rather than writing a second copy of the rule: two copies of a
rule about which inputs have a digest is a divergence waiting for someone to fix only one of them,
and a function named `v3Uint` that v2 depends on is a lie a reader has to discover for themselves.

**Rejected: normalising or truncating out-of-range values.** That preserves the alias with extra
steps. The entire point is that two different inputs must not reach one digest; mapping them onto a
canonical representative is that failure, spelled deliberately.

**Rejected: leaving v2 alone because "no in-range value changes by a single byte" covers it.** That
sentence is true and it is about *bytes*. Acceptance and bytes are different things, and a phase
that quietly narrows what it accepts under a heading about what it emits is how a breaking change
ships as a patch. Hence this entry, `COMPATIBILITY.md` §9, and its own acceptance criterion.

**What it costs:** a caller passing `sealedAt` as a `number` above 2^53 gets a `RangeError` where
they previously got a digest. That digest was already wrong — it covered the nearest double, so any
record it sealed disagreed with the runtime's — which makes this a narrowing that reveals a bug
rather than one that creates work. Not reversible in the usual sense: widening back would re-admit
values whose digests we know to be wrong.

**Re-open trigger:** a caller who genuinely needs `number` above 2^53 and cannot use `bigint`.
Nothing in this repo or its known consumers does; the shims are the only callers and they were
written against `bigint`.

### The same argument, applied back to Python, after verification found the asymmetry

The first cut of this phase fixed Python by range comparison alone. A verification round pointed out
that this left `verify_chain_head_attestation(attested_len=True)` digesting as `1` — because `bool`
subclasses `int`, so `0 <= True < 1 << 64` is simply true — while TypeScript's `uintSlot` refused
`true` outright. The phase had **created** a cross-language divergence in the course of closing
three, and the draft of `COMPATIBILITY.md` §9 claimed TypeScript had "changed to match what Python
already did", which was not true of that row.

The same round found a second answer hiding in the same guard: `attested_len=5.0` passed the range
comparison and then hit `struct.pack`, which raised `struct.error`. A verifier that can return
`True`, return `False`, raise `TypeError` **or** raise `struct.error` has a contract no caller can
be written against.

Both closed by sharing `_uint_slot` — the validator `record_digest_v3` has used since it was
written, formerly `_v3_uint` — instead of a bespoke comparison. Recorded rather than done silently,
because it is a real narrowing of a public function: `True` used to reach a verdict (`False`, having
been digested as `1`) and now raises; `5.0` used to raise `struct.error` and now raises `TypeError`.
Nothing in this repo passed either — the only callers are the tests and the public export.

A second verification round then found the same defect one function over: `record_digest_v2` still
digested `sealed_at=True` as `1`. Both languages had agreed on that *before* this phase and would
have disagreed *after* — the phase would have closed three cross-language divergences by opening a
fourth, in the sibling function, with a `COMPATIBILITY.md` row asserting the opposite. Closed the
same way, by sharing the one validator across all three framings rather than writing a third copy.
That is the actual lesson of both rounds: the bug was never the missing check, it was the rule
existing in more places than one.

The asymmetry that remains is deliberate: Python refuses `5.0`, TypeScript accepts `sealedAt: 5.0`.
JavaScript has no separate float type, so `5.0` **is** `5` and there is nothing to refuse. Closing
that would mean inventing a distinction the language does not have.

## 2026-09-03 — the wire-framing latch: a gate may not be watched by a field that goes stale with it

`contract/wire-framing.json` carries `runtime_emits_version`, an adoption latch. While it is false,
a release dispatch that carries **no** `wire_framing_version` is downgraded to a `::warning::` and
the release tags anyway. That is correct only while the runtime genuinely does not emit the field.

seam-runtime#418 landed the field and closed COMPLETED on **2026-08-26**. The latch stayed `false`
until **2026-09-03**. For that week the one gate that *prevents* a 0.7.17 — rather than reporting
one afterwards — could not refuse anything, and every release dispatch in the window carried
`wire_framing_version: 2` while the file said the runtime had not adopted the handshake. The file's
own comment names the required action ("Flip it to true in the PR that confirms the runtime emits
the field"); nothing enforced it, and `scripts/test_release_gate.py` checked step ordering and file
existence only.

### The rejected design, recorded because it is the intuitive one

The first draft of the guard asserted a consistency property *inside* `contract/wire-framing.json`:
if `runtime_emits_version` is `false`, then the issue named in `runtime_adoption_issue` must still
be open. It is hermetic, needs no network, and is worthless. Both fields are hand-maintained and
they went stale **together** — on 2026-08-26 the latch became wrong and the recorded issue state
became wrong in the same instant, and neither was touched for a week. The test would have been green
throughout the exact failure it was named after. It converts "someone remembers to flip the latch"
into "someone remembers to record the closure": the same reliance, moved one field sideways.

This is the repo's own vacuity class — a check whose result is decided by something other than the
property it names — and it is worth recording that it was reached by drafting, not by carelessness.
A review round caught it.

### What was done instead

The check lives in the gate itself, keyed on the dispatch: **a payload that carries
`wire_framing_version` while the latch reads `false` is refused.** The dispatch is proof the runtime
emits the field, so the latch is provably stale at that moment — detected from live data that cannot
itself go stale, at the only point where the truth is available, with nothing to keep updated by
hand. Had it existed, it would have fired on the first release after 2026-08-26.

The latch is now `true`, and `scripts/test_release_gate.py` executes the gate's real script against a
synthetic contract file rather than pinning its text, so every *behavioural* branch is asserted by
running it and reading the exit code — not by text-matching the YAML. The load-bearing assertions were
demonstrated red against the pre-fix workflow before the fix landed.

### Assertions that do read the YAML, and why that is not the same thing

Executing the script proves what the script does. It cannot prove that the workflow still *hands it*
what it needs, because the harness supplies those values itself. Deleting the `wire_framing_version`
input declaration, or the `|| github.event.inputs.wire_framing_version` fallback that reads it, or the
`EVENT: ${{ github.event_name }}` line the trigger-type branches key on, left every behavioural test
green — each is a cell of plumbing outside the executed text, so the gate would have gone back to
refusing every manual release with the whole suite still passing. Four structural assertions now read
those cells out of the parsed workflow — the three above plus the `repository_dispatch` trigger the
stale-latch branch is scoped to — each verified by deleting the cell and watching exactly one
assertion fail. The distinction is deliberate: behaviour is asserted by execution, wiring by
structure, and neither substitutes for the other. Found by this phase's second verification round.

A fourth round found the fifth cell of that shape, and it is the one worth remembering: the gate's
refusal when `contract/wire-framing.json` **cannot be read** rests entirely on `set -e` aborting the
`python3` substitution. Drop the `-e` and `LATCHED` becomes the empty string, which is not `"true"`,
so the gate takes the staged-adoption branch and tags a release having compared nothing at all. That
cell was harmless until this phase: while the latch was false it warned and tagged anyway, so nothing
turned on `-e`. Arming the gate is what made a shell option load-bearing — a reminder that hardening
one path can silently promote an adjacent one into the trusted computing base. Pinned by behaviour
(run the gate with no contract file, assert non-zero) rather than by grepping for `set -e`, since
what matters is that it refuses, not which option makes it.

### The cost of flipping the latch, which the first cut of this phase missed

Arming the gate broke the recovery path. `workflow_dispatch` — the documented *"manual fallback: run
it yourself with an explicit version if the dispatch is ever missed"* — has no `client_payload`, so
the framing version is empty on every manual run. With the latch true and no special case, that lands
on the "a field that stopped being emitted is a REGRESSION" branch: **every manual release refuses,
unconditionally**, and the operator is sent to investigate the runtime when the real fix is a form
field. It fires on the path reached precisely *because* the automatic dispatch already failed, and
`test_release_gate.py`'s own header warns about this shape — "a gate that always refuses looks, from
the outside, like a gate that is working".

Fixed by giving `workflow_dispatch` an optional `wire_framing_version` input and diagnosing that case
separately, before the latch checks, so the message asks for the input instead of blaming the runtime.
The manual path still refuses a genuine mismatch, so it is not an escape hatch around the gate. Caught
by this phase's verification round, not by the author.

### A PR-time assertion that the latch is true was written, then dropped

It asserted `runtime_emits_version is True` in the committed file. That is the design this entry's
own rationale rejects one notch milder — it swaps "someone remembers to flip the latch" for "someone
remembers to revisit this guard" — and the phase spec had already rejected asserting the latch
unconditionally true, because it forecloses the staged-adoption mode the file documents. Dropped
rather than justified. The consequence of not having it is that setting the latch back to false lands
at release time instead of PR time, where it **blocks a release** rather than shipping a bad SDK:
failing closed, in the direction that costs minutes rather than a bad publish.

### Giving `$DISPATCHED` a second source broke the claim the branch rests on

The manual-fallback fix above introduced its own defect, caught by the second verification round.
Once `$DISPATCHED` could also come from a `workflow_dispatch` input, the stale-latch branch fired on
manual runs too — and there its message is a false premise. "The dispatch IS the proof that the
runtime emits the field" is true only when the *runtime* sent it; on a manual run the value came from
a form field an operator typed, which proves nothing. Worse, the refusal instructs them to flip the
latch, so following it during a legitimate staged-adoption window arms the gate on no evidence, and
every automatic dispatch for the rest of that window then hits the REGRESSION branch.

The branch is now scoped to `repository_dispatch`. A manual release during staged adoption falls
through to the ordinary comparison, which is what it should have done.

The lesson is narrow and worth keeping: widening a variable's provenance silently widens every
condition that reads it. The branch's correctness never depended on the value, only on *who sent it*,
and that distinction stopped being encoded the moment a second sender existed.

**Status:** DECIDED. The staged-adoption window is preserved on both trigger paths — the branch keys
on the presence of a *runtime-sent* field, not on a date, so the next framing that lands SDK-side
first still works the way the file documents. One residual, accepted: a manual run's framing version
is an operator assertion, so someone who simply types this SDK's own `supported` value bypasses the
comparison. That is inherent to any manual fallback — the same trust already placed in the
operator-supplied `version` — and the gate's purpose is to stop an *automatic* release from
outrunning the shims, which it does.


## 2026-09-01 — issues #91 and #92: how a bare `:NNN` binds, and what a guard's corpus may not be

Not a `/reconcile` pass — two standing issues closed directly, each of which forced one decision
worth recording because both were argued the wrong way in the issue that raised them.

### A bare `:NNN` binds same-line, and a table row's subject outranks any citation inside it

Issue #91 proposed that a bare line reference means "the file named in the previous full citation".
Measured against the real corpus, that rule is wrong twice, and both failures produce *confident*
wrong answers rather than misses:

- **In a table row the subject wins.** `PROGRESS.md`'s repo-map row for `python/seam_sdk/crypto.py`
  names `python/seam_sdk/admin.py:141` mid-sentence and then continues with four more bare
  references, all of which are crypto.py. Binding them to the nearer citation reports
  `python/seam_sdk/crypto.py:630` as past-EOF — it is `_opt_bytes`, and the claim is true.
- **Inheritance must not cross a line.** `PROGRESS.md` writes `p1a:103-107` followed by bare
  companions, where `p1a` is a shorthand alias for a sibling-repo spec and not a path at all. A
  paragraph-scoped resolver walks past it and binds those references to whatever file the previous
  line happened to mention.

So: same line only, subject cell first, and an alias with no extension binds nothing. The rule is in
`python/tests/test_compatibility_citations_resolve.py:1304`, and both failure modes are pinned by
mutation tests rather than described in prose.

**The 94 references that bind to nothing are not a backlog.** They are mostly two kinds that must
*not* be checked against HEAD: historical records (this file's own repoint table is a column of the
values one citation held at each PR) and the notation quoted as data. They are held under a ratchet
that may only be lowered, which is the part that actually answers #91 — the complaint was never that
some references are unchecked, it was that nothing knew how many.

**Rejected: forbidding the bare form.** It was the issue's own alternative and it is worse. It would
rewrite ~180 sites, and the repo-map rows it would make unreadable are exactly the ones the
same-line rule already checks for free.

### A guard may not calibrate itself against a corpus it wrote

Issue #92 said the live-suite detector's positive corpus is generated by `_deadopt`, which injects
the very tokens the detector keys on. Measuring it produced a sharper result than the issue claimed:
`_deadopt`'s output contains **zero** `terminate`/`kill` calls, so the detector for "teardown never
waited" — one of the three defects behind #85 — had no real positive at all.

The four pre-#85 fixtures are now vendored from `960cf81` as inert `.txt` data, AST-extracted and
unedited (`python/tests/fixtures/pre-85/test_integration.py.txt:1`). 389 lines, not the ~1000 the
issue priced, because only the imports and the defect-carrying functions are kept.

**A vendored corpus is necessary and not sufficient**, which is the part worth recording. Those
fixtures really did discard their server's output, so they satisfy the discard signal and the
connect signal equally — and the mutation #92 demonstrated (swap `CONNECT_NAMES` for
`DISCARD_NAMES`) still passes against them. What separates the two signals is a live suite that
*captures* output, which is what `python/tests/live_server.py:1` does today. That probe, not the
corpus, is what closes §2.


## 2026-09-01 — `/reconcile` over `plans/consumer-decoders-and-event-surface.md` (7 entries)

All five phases are DONE. Phases 1-2 shipped in #90, Phases 3-4 in #93, Phase 5 in #94. Seven
`ASSUMPTIONS.md` entries were open across this plan and the two before it: **two confirmed** — one on
evidence this cycle produced, one on re-measuring the condition it named — **three reviewed and left
unchanged** with the reasoning recorded, and **two deferred** to triggers that live outside this repo.
Those three numbers are the count of the seven sub-sections below, and they are stated once here so
they cannot disagree with the summary at the bottom, as an earlier draft of both did.

### `seam.event.v1` gets its own manifest file, not a partition of the api one — CONFIRMED

- **Recommender (Opus):** CONFIRM, and note that the decisive reason came back stronger than the
  entry claimed. The argument was mechanical: `manifest_fields`' stripper is a NEGATIVE filter
  ("everything that is not an enum line"), so no delimiter can carve out a third partition. Phase
  5's verification round tested the consequence rather than the argument, and found that
  `manifest_event_fields`' deliberately-absent second `grep -v '#'` makes the event side **strictly
  safer**: a `#`-bearing field line is reported MISSING and exits 8, where the shared api stripper
  would silently drop it. Measured, 90 against 91. A shared file would have inherited that drop.
- **Verdict:** Confirm.
- **Status:** CONFIRMED.

### Testing (not just building) `verify/` at its declared MSRV — CONFIRMED

- **Recommender (Opus):** CONFIRM on re-measurement, not on the original reasoning holding by
  default. `verify/Cargo.toml`'s dev-dependencies are `sha2`, `base64` and `serde_json` — still a
  strict subset of its normal dependencies — so the test profile resolves nothing a consumer does
  not already compile and cannot raise the floor. The declared `rust-version` still derives from
  normal dependencies only, and `verify/tests/msrv.rs` recomputes it from `cargo metadata` on every
  run, so the divergence this entry guards against fails a test rather than waiting to be noticed.
- **Verdict:** Confirm. One job, not two.
- **Status:** CONFIRMED.

### `plans/` stays outside the citation guard; `PROGRESS.md` does not — UNCHANGED

- **Recommender (Opus):** Leave the line where it is. Phase 5's verification round found three stale
  line references inside `PROGRESS.md` that the guard cannot see, which looks at first like evidence
  the guard cuts in the wrong place. It is not: all three were **bare** `:NNN` refs carrying no
  path, and the guard matches backticked `file:line`, so a pathless number is invisible in every
  guarded document — `PROGRESS.md` included. That is a different gap in the same guard, orthogonal
  to the `plans/` boundary, and one of the three had been wrong since the line it named moved.
- **Verdict:** No change to the guard. Closed at the source instead — those refs now name what they
  point at rather than where it sits, which is the form that cannot rot.
- **Status:** UNCONFIRMED (reviewed, unchanged).

### `contract/expected-local-lag.txt` is a window, not a permanent excuse — DEFERRED

- **Recommender (Opus):** Too early to settle — `EXPECTED-FROM` is 2026-08-31 and the re-open
  trigger is 60 days out. Worth recording that this cycle produced the first hard evidence for the
  **social** failure mode the entry names rather than the technical one. The NOTE this file drives
  ended "so this STILL exits 6 below" unconditionally, which is false whenever the event surface
  also disagrees — and it survived a full phase plus four verification rounds precisely because that
  block is the one every local run prints and nobody re-reads. The sentence is now conditional with
  both branches pinned by tests, but the mechanism is the one to watch at day 60.
- **Verdict:** Defer to the trigger. Not a blocker for `/ship`.
- **Status:** UNCONFIRMED (deferred deliberately).

### The enum manifest carries names only, not numeric tags — UNCHANGED

- **Recommender (Opus):** No new evidence either way. The event surface added in Phase 5 carries
  **zero enums** — asserted by `assert_event_surface_preconditions` rather than assumed — so it
  produced no second case to test the name-only rule against. The trigger still sits in
  `seam-runtime`'s `buf breaking` config.
- **Verdict:** No change.
- **Status:** UNCONFIRMED (reviewed, unchanged).

### `PolicyEnforcement` and `CollectiveOutcome` stay off `ts/src/index.ts`'s named export list — UNCHANGED

- **Recommender (Opus):** No change. Phase 4 shipped and merged without either type reaching the
  named export list and without a consumer needing it; the count of decoders of this shape is still
  two, not three. Nothing this cycle tested the assumption, which is the right outcome for one whose
  evidence can only come from a consumer.
- **Verdict:** No change. Widening a public surface later is additive; narrowing it is breaking.
- **Status:** UNCONFIRMED (reviewed, unchanged).

### `policy_enforcement_of`'s presence enumeration is orientation, not contract — DEFERRED

- **Recommender (Opus):** Not answerable from this repo. The enumeration is a claim about runtime
  behaviour and the only evidence that could settle it is seam-runtime#526's matrix, which is why
  the docstring cites the issue rather than a line of code. The docstring already says the list
  describes the runtime as measured rather than a guarantee to branch on, so the cost of being wrong
  stays bounded to trust — which is what the entry records.
- **Verdict:** Defer, open against seam-runtime#526.
- **Status:** UNCONFIRMED (deferred deliberately).

---

**Summary of the seven:** **2 confirmed** · **3 reviewed and unchanged** · **2 deferred** to
triggers outside this repo.

Three further entries are open and are deliberately **not** counted among those seven, because none
of them was settleable in this pass:

- **The Cloudsmith quarantine question** for the 0.7.39-0.7.43 band. The plan's only genuine one-way
  door in the harmful direction — quarantining breaks builds that work today and cannot be undone for
  anyone whose CI ran in the interim — so it stays with the human.
- **Whether the runtime validates caller-supplied canonical bytes**, and **how its JCS renders an
  integer at or above `10**21`.** Both need the runtime's Rust, which this repo's clean-room
  constraint does not read, so neither is answerable here by construction.

No code work is outstanding before the next `/ship`.


## 2026-08-31 — `/reconcile` over `plans/post-adoption-hardening-and-acdp-readiness.md` (3 entries)

All ten phases are DONE and merged (#79, #80, #81, #82, #83, #84). Three `ASSUMPTIONS.md` entries
carry this plan's tag. Two of them were **logged retroactively during this pass** rather than while
the phase ran, which is itself the finding worth recording first.

### `/implement` logged one of the three assumptions it was told to log

- **What happened.** The plan's Open questions named two entries `/implement` should write as
  `UNCONFIRMED` while implementing — the field-manifest spelling rule (Phase 5) and Phase 8's
  grandfathering choice. Neither was written. Only the Phase 10 quarantine entry made it in, and
  only because that phase's own text demanded it.
- **Why it matters more than it looks.** `ASSUMPTIONS.md` is the *input* to this pass. An entry that
  is never written is not reconciled, is not surfaced, and leaves no trace of having been skipped —
  so the reconcile reports complete coverage of a list that was silently short. That is the same
  shape as this plan's other findings: a check that passes because it never saw the thing.
- **Decision.** Both entries are written now and marked as retroactive rather than back-dated. The
  process gap is recorded here rather than quietly repaired, because the next run will have the same
  gap unless someone reads this.

### Field-manifest spelling: names only, `<Message>/<field_name>` — **CONFIRMED**

- Held in practice across the whole phase: both extractors agreed at 223 on local stubs and 228 in
  CI, zero diff in either direction, and the two keyword-named fields that break a `__slots__`
  reading are declared and matched. The lowercasing is forced by protoc's `MYFIELD_FIELD_NUMBER`
  emission, not chosen. The manifest header states what the spelling does *not* check, so the
  coverage limit is declared rather than inferred.
- **Verdict:** Confirm. **Status:** CONFIRMED.

### Phase 8 converts rather than grandfathers — **CONFIRMED on the reason, NOT on the evidence first given**

- **Both halves of the original write-up were wrong, and the final whole-feature verify caught them.**
  The stated reason — "Phase 9 refreshes that same vendored file" — is counterfactual: the refresh
  (`c7331b6`, PR #80) preceded Phase 8 by about two hours, and Phase 9's regeneration commit never
  touched the file. The stated vindication — "the converted citation did not move while the
  `CHANGELOG.md` one drifted" — is vacuous: it did not move because *nothing refreshed the file*, and
  a grandfathered anchor would equally not have moved. Comparing against `CHANGELOG.md` compares a
  different file with a different cause, one this rule explicitly does not reach.
- **What survives is the durable reason**, which needs no named trigger: the copy is refreshed
  whole-file on upstream's cadence, so the next refresh drifts any line anchor into it. That is
  sufficient on its own and was always the real argument.
- **The choice is not yet exercised.** The first upstream refresh after this is its actual test. A
  confirmation should say what it rests on, and this one rests on reasoning rather than on an
  observed event.
- **Verdict:** Confirm the decision; retract the evidence offered for it. **Status:** CONFIRMED.

### The three pre-existing UNCONFIRMED entries this pass was told to look at

- **The plan directed it and the first draft of this pass ignored it** — caught by the final verify,
  which is a second instance of this section's headline finding rather than a separate one.
  `ASSUMPTIONS.md` carries three UNCONFIRMED entries from *earlier* plans, and the plan's Open
  question 7 addressed one of them explicitly.
- **`ASSUMPTIONS.md:177` — testing rather than only building `verify/` at its declared MSRV.**
  Settleable in-repo but unrelated to anything this plan touched, and the plan already decided:
  **not inherited.** Left UNCONFIRMED, owned by whoever next changes `verify/`'s job matrix.
- **`ASSUMPTIONS.md:327`/`:352` — the runtime's caller-derived canonical bytes, and its JCS rendering
  of integers ≥ `10**21`.** Both were filed as questions upstream and neither is answerable from this
  repo. Both remain UNCONFIRMED, correctly: this plan changed nothing either depends on, and closing
  them would mean inventing an answer about another service's behaviour.
- **Decision.** All three stay UNCONFIRMED and stay tagged to their own plans. Recorded here so the
  next pass finds a statement rather than a silence — an entry nobody mentions is indistinguishable
  from an entry nobody read, which is the same defect this section opened with.

### Cloudsmith quarantine for the 0.7.39-0.7.43 band — **DEFERRED, and deliberately not settled here**

- **Why this one does not get settled unilaterally.** Every other entry in this pass is reversible in
  a commit. This one is not symmetric: choosing *not* to quarantine is fully reversible — the
  versions stay installable and quarantine remains available, and `yank.yml` now actually
  authenticates (Phase 10). Choosing *to* quarantine breaks builds that work today, and cannot be
  undone for anyone whose CI ran in the interim.
- **The current state is the safe one**, which is why this defers rather than blocks: the band is
  documented in `COMPATIBILITY.md`, nothing is removed, and no consumer's install changes. Issue #52
  recommended yanking; Phase 10 documented instead and recorded why.
- **What an owner would actually be deciding:** whether a consumer who is *currently fine* on one of
  those five versions should have their next install fail in order to stop a new consumer from
  arriving on them. The no-yank reasoning turns on harm to the working consumer, not on whether the
  act is reversible — so quarantine's reversibility does not answer the objection, it only softens
  the cleanup.
- **Re-open trigger and owner**, which the first draft of this entry omitted — a deferral without
  either is just a decision nobody made. **Trigger:** evidence that a consumer has newly *arrived*
  on one of the five versions (a lockfile pinning one, or a bug report against one) — that is the
  only harm documentation does not already address. **Owner:** the repo maintainer; this is a
  publishing-policy call about other people's builds, not an implementation detail, and it wants a
  human decision rather than an agent's default. **Standing default until then: no quarantine** —
  matching the plan's own Open question 1.
- **Verdict:** Defer, with the reversible option in force. **Status:** UNCONFIRMED — carried, not
  closed. Nothing in this plan depends on it.


## 2026-08-31 — `plans/post-adoption-hardening-and-acdp-readiness.md` Phase 8 (issue #73): citations into vendored files are quoted, never line-anchored

### Citations into vendored files are quoted, never line-anchored

- **Context.** `verify/docs/seam-event.v1.md` is a byte-verbatim copy of seam-runtime's
  `docs/specs/seam-event.v1.md`, refreshed **whole-file** by policy — `scripts/check_vendored_spec.py`
  asserts the copy is upstream's bytes under a header, so a refresh replaces the entire body rather
  than patching it. One `DECISIONS.md` citation pointed into that body at a line number.
- **The failure, five times over — measured, not recalled.** Every upstream insertion above the
  cited sentence shifts it, so the citation went stale on *every* refresh. Walking the history of
  `DECISIONS.md` against the history of the vendored copy gives the whole run:

  | PR | date | cited | needle really at | |
  |---|---|---|---|---|
  | #58 | 2026-08-24 | `:271-272` | 271 | introduced, correct |
  | #63 | 2026-08-25 | `:271-272` | **276** | **merged stale — never repointed** |
  | #66 | 2026-08-25 | `:295-296` | 295 | repoint 1 (silently absorbs #63's drift) |
  | #71 | 2026-08-26 | `:332-333` | 332 | repoint 2 |
  | #72 | 2026-08-27 | `:338-339` | 338 | repoint 3 |
  | #74 | 2026-08-27 | `:381-382` | 381 | repoint 4 |
  | #80 | 2026-08-31 | `:388-389` | 388 | repoint 5 |

  **Six refreshes, five repoints.** The gap is the finding. #63 refreshed the vendored copy, moved
  the sentence five lines, left the citation where it was — and merged, because `DECISIONS.md` did
  not come under the citation test until #67. So a citation sat on `main` pointing at a plausible
  wrong line, indistinguishable from a correct one to any reader. That is not the churn this entry
  set out to describe; it is the failure the churn was a symptom of, and nobody had it until the
  history was walked rather than recalled. **Issue #73 recorded two of these, the test file's own
  comments said "three, in one session", and this entry's first draft said five-one-per-refresh —
  three successive undercounts of the same evidence, in a record whose subject is claims that look
  checked.** The rest is structural, not carelessness: a line number is a claim about a file's
  *layout*, a vendored copy has no stable layout by design, and the rot rate is set by upstream's
  commit cadence, which this repo does not control and cannot slow down.
- **Decision.** No checked document may line-anchor into a vendored path. Enforced mechanically by
  `VENDORED` in `python/tests/test_compatibility_citations_resolve.py:128`, over every document in
  `DOCS`, with a red-first test proving the guard fires on a line anchor and leaves both sanctioned
  alternatives alone (`python/tests/test_compatibility_citations_resolve.py:202`).
- **What to do instead**, in preference order:
  1. **Cite the upstream file** with its `seam-runtime/` prefix. It is the actual source of the
     sentence, and `SIBLING_PREFIXES` already skips it when the sibling repo is not checked out. The
     line number still rots there, but it rots in the repo that owns the file and can see the edit.
  2. **Quote the sentence** and register it in `QUOTED`
     (`python/tests/test_compatibility_citations_resolve.py:411`). The check asserts the needle is
     unique in the target, that the document quotes it verbatim, and that the document still
     attributes it to that path — no line number on either side.
- **Widening `CITATION_SLACK` was considered and rejected.** Slack large enough to absorb a
  whole-file refresh is slack that no longer distinguishes a correct citation from a wrong one, and
  it would weaken every non-vendored anchor to buy tolerance for the one case that should not be
  line-anchored at all. Issue #73 rules it out for the same reason.
- **The one existing anchor was converted, not grandfathered — and the reason first given for it was
  wrong.** The plan permitted either. The justification written here, and repeated in the plan and
  `ASSUMPTIONS.md`, was *"Phase 9's regeneration half refreshes that same vendored file again."* It
  does not. `verify/docs/seam-event.v1.md` was last touched by `c7331b6` (18:26, PR #80 — Phase 9's
  **spec** half), roughly two hours **before** this phase landed at 20:14; Phase 9's regeneration
  commit `27dda87` does not touch it at all. The refresh being guarded against had already happened.

  Recording that rather than quietly restating it, because asserting an unchecked justification is
  the exact defect this entry is about, committed by the entry itself. The decision still stands on
  the durable reason, which needs no specific event: the file is refreshed **whole-file on upstream's
  cadence**, so the *next* refresh drifts any line anchor into it, and a rule that waits for a named
  trigger is a rule that arrives after the drift it was meant to prevent. The quoted
  form is a **trade, not a superset**, and calling it "strictly stronger" would be the same
  comfortable overstatement this entry is otherwise about. Dropped: the line-position claim. Gained:
  the document must quote the sentence verbatim, so a refresh that silently reworded it fails here
  while satisfying a dutifully-repointed anchor — and the anchor never checked the document's own
  text at all, only where it pointed. The trade is worth taking only because the dropped half is
  exactly the half a whole-file refresh makes unkeepable.
- **Scope, and what remains open in #73.** The rule names `verify/docs/seam-event.v1.md`
  file-by-file rather than the `verify/docs/` directory, and the distinction is load-bearing: that
  directory also holds `audit-anchor.md` and `erasure-certificate.v1.md`, which
  `scripts/check_vendored_spec.py` deliberately excludes from its registry because they were
  **authored here** and have no upstream to compare against. A directory prefix would have forbidden
  line-anchoring into two files this repo edits itself — the exact case argued below as one that
  *should* stay line-anchored. The two lists of what-is-vendored are now asserted equal against that
  registry (`python/tests/test_compatibility_citations_resolve.py:173`), on this repo's own stated
  principle that a value stored twice must not be able to disagree with itself. It does **not**
  convert the eight pre-existing `ANCHORED` entries into non-vendored files; those point into files
  this repo edits itself, where a line number is a claim about our own layout and a drifting one is
  a real signal. `ANCHORED` in fact *grew*, to twelve — the four references repaired below were
  added to it, because repointing them without content-checking them would have fixed the instance
  and left the class. The adjacent case is recorded here rather than fixed: `COMPATIBILITY.md`'s "No yank"
  citation into `CHANGELOG.md` drifts because a changelog grows at the top, so *every* new entry
  moves it. Measured across `git rev-list --all`, it has held **twelve distinct values since
  2026-08-23**: `:227-231` → `:277-281` → `:317-321` → `:419-424` → `:466-471` → `:521-526` →
  `:523-528` → `:538-543` → `:540-545` → `:563-568` → `:586-591` → `:610-615`, the last seven of
  them on 08-31 alone. The twelfth was added by Phase 9's own CHANGELOG entry, after this paragraph
  was written — so the paragraph had to be updated by the very drift it describes, which is the
  clearest statement of the problem available. (Two earlier drafts of this paragraph were wrong in two different ways — one omitted
  `:523-528` while still calling the chain five repoints, an enumeration disagreeing with its own
  count; the next said "twelve since 08-24", counting a *different* CHANGELOG citation that a
  last-match grep had swept in. Third time measured properly, by matching the citation rather than
  taking the last one on the line.) Same zero-information churn as the vendored case, with a
  different cause — an append-only file rather than a refreshed one — and the same conversion would
  fix it. It is deliberately out of scope here: `CHANGELOG.md` is ours,
  the fix is a mechanism change to a check that is currently working, and #73 has not decided whether
  the rule should widen from "vendored" to "any file whose line numbers are structurally unstable".

  A second open half, found while writing this entry: **a citation can opt out of being checked by
  being written unusually.** `CITATION` needs a path and a plain `:N`, so `` `:878` `` (bare
  shorthand continuing an earlier path) and
  `` `seam-runtime/docs/specs/seam-event.v1.md:372,379,399` `` (a comma list) match nothing at all.
  They are not skipped like a sibling path — they are never seen. Four such citations existed in
  these two documents; the three bare ones had all rotted, silently, inside a document whose every
  citation is supposedly verified. They are repointed above, but the class remains: the regex should
  arguably *reject* a citation-shaped string it cannot parse rather than ignore it, so that writing
  a reference unusually is a failure rather than an exemption. That is the second question on #73.


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
  (`scripts/check-contract.sh:830`), exiting 6 with the field named (`scripts/check-contract.sh:1200`). `STREAM`/`EVENTS` stay as
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
  **Python** (`scripts/check-contract.sh:644`), with TypeScript as the cross-check
  (`scripts/check-contract.sh:616`) — one command to document, not two. If it wrote from a side that cannot see every field, it
  would produce failures the documented escape could never clear, which is exactly what `raise` does
  under a `__slots__` extractor.
- **The refusal deliberately puts the escape second.** It says decide first, then run it
  (`scripts/check-contract.sh:1129`). A failure message that leads with the fix trains the reader to
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
  that happening by accident. **Phase 9 settled this rather than reversing it:** the fields are
  carried and never wired, because `verify/` does not compute `context_digest` and a projection
  would only add a second spelling of a wire commitment.
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

- **Both edges of the band, with the run ids so a reader can re-check rather than take it on
  trust.** This claim is asserted in several documents and until now named one run id behind one of
  its data points, which is thinner than "proven" implies. The `ci` runs on each tagged commit,
  failing or passing `test_the_declared_floor_is_at_least_the_gencode_in_the_generated_stubs`:

  | tag | commit | `ci` run | result |
  |---|---|---|---|
  | `v0.7.38` | `3b15b4ac1` | `32410597866` | **green** — last good |
  | `v0.7.39` | `8086a9842` | `32557539171` | **red** — first bad, the lower edge |
  | `v0.7.43` | `ff0139a26` | `32682442846` | **red** — last bad, the upper edge |
  | `v0.7.47` | `860db039a` | `32805064452` | **green** — the fix (`f68572f`, PR #51) |

  0.7.40-0.7.42 are red the same way. The lower edge was originally written as *unprovable* — "the
  stubs are gitignored, so per-tag gencode is not recoverable" — which was true of the working tree
  and false of the project: every tagged commit has a CI run, and that test *is* this defect. The
  hedge was deleted rather than softened because the evidence made it false.
- **The precedent already covers worse.** `CHANGELOG.md:682-687` records no-yank for 0.7.13-0.7.19,
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
without stripping the `"Bearer "` prefix the org Cargo token carries — a strip `.github/workflows/publish.yml:385`
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
it and asserts the three filters. It runs in `workflow-guards` (`.github/workflows/ci.yml:655-656`),
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
generated (`.github/workflows/publish.yml:354`), and it installs the built wheel into a clean venv
with `protobuf` pinned at the floor the wheel itself declares, then imports the generated module
there (`.github/workflows/publish.yml:428`). The second is the one that asks *is this metadata
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
argument the `ci-green` tests in that file already make (`.github/workflows/ci.yml:644-645`).

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
  the first record, and names the fix (`ts/src/crypto.ts:725-730`) — and accepting strings reopens
  `BigInt("")→0n` and `BigInt([5])→5n`. The choice stands; the justification does not extend to
  "nothing that used to work stops working."
  *(Citation corrected 2026-09-03. It named lines 509-522, which then held `v3Text` — the string slot
  validator — for a claim about a coerced integer. Wrong function even when written, and Phase 2's
  insertions then moved it onto an unrelated error message. It now names `uintSlot`, which is also
  where the fix genuinely lives for v2 as of that phase, since `u64le`/`u32le` route through it.)*
- **v2 freeze held:** `git diff main...HEAD` shows zero removed lines in `crypto.py` and a purely
  additive `vectors.json`.
- **Verdict:** Confirm. **Status:** CONFIRMED.

### The v1 skip is a downgrade hole, closed structurally rather than documented
- **Reviewer (Fable):** CONFIRM. Every load-bearing claim resolves. The guard keys on the four
  columns and never on the version alone (`verify/src/verify.rs:605-614`); a genuine v1 record falls
  through to `continue` and is tested twice — `verify/tests/authenticity.rs:238`
  (`a_v1_record_is_link_verified_but_not_recomputed`, whose skipped-not-recomputed assertion is at
  `verify/tests/authenticity.rs:254-257`) and `verify/tests/authenticity.rs:944`
  (`a_genuine_v1_record_is_still_skipped_not_refused`). The per-column parametrization at
  `verify/tests/authenticity.rs:906-909` exercises each column with the other three removed, and the
  comment immediately above it records the decoy that forced it: "a decoy that guarded only on tag
  10 passed an earlier version of this test, leaving the three v3 columns unchecked with a green
  suite."

  **Correction, found while writing the entry above.** Three of those references were written as
  bare `:N` shorthand — `` `:878` ``, `` `:843-875` ``, `` `:841` `` — continuing the full path in
  the same sentence. `CITATION` requires a path, so a bare `:N` matches nothing: those three were
  never resolved and never content-checked, in a document every citation of which is supposedly
  verified. All three had rotted, by 5 to 66 lines. `:878` was cited for skipped-not-recomputed and
  sat inside a different test entirely; `:843-875` was cited as the per-column parametrization and
  is a comment block plus record construction. The substance was right and every pointer was wrong,
  which is this entry's own subject arriving by a third route — not a stale anchor, not an unstable
  file, but a citation *format* the checker silently declines to see. Repointed above with full
  paths so they are checkable at all, and added to `ANCHORED` so the content is checked and not
  merely the range — repointing alone would have repaired the instance and left the class. The class
  itself is recorded on #73.

  The spec sentence the decision rests on is quoted verbatim from `verify/docs/seam-event.v1.md`:
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
gate** (`.github/workflows/ci.yml:488-489` runs `scripts/check-independence.sh`, which renders
`cargo tree -e normal`), not a comment.

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
