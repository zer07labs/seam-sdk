# Decisions

The durable record of `/reconcile` passes over `ASSUMPTIONS.md`. Each entry: the original
assumption, the independent recommender's analysis, the human verdict, and the resulting status.
`/ship` and any later reconciliation read this file instead of replaying the conversation that
produced it.


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
  columns and never on the version alone (`verify/src/verify.rs:518-523`); a genuine v1 record falls
  through to `continue` and is tested twice — `verify/tests/authenticity.rs:238` and `:878`, the
  latter asserting skipped-not-recomputed. The per-column parametrization at `:843-875` exercises
  each column with the other three removed, and the comment at `:841` records the decoy that forced
  it. The spec sentence it rests on is verbatim at `verify/docs/seam-event.v1.md:332-333`:
  `ciphertext_digest` "is absent (no wire bytes) only on `schema_version = 1` payloads."
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
