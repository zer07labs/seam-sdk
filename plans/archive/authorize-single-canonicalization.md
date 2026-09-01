# Close the double-canonicalization class in `Authorize` (issue #60)

> **📦 ARCHIVED 2026-08-31 — DELIVERED, all five phases.** Issue
> [#60](https://github.com/zer07labs/seam-sdk/issues/60) closed 2026-08-25. This plan was delivered
> on 2026-08-25 but was never given a row in `plans/README.md` at all — neither active nor archived —
> so it was invisible to anyone reading the index. Archived here while implementing
> `plans/post-adoption-hardening-and-acdp-readiness.md` Phase 1.
>
> **Verified against this tree, not against the status table** (per `plans/README.md`'s archiving
> rule): all five phases carry `Status: DONE` in this file, issue #60 is closed, and the delivered
> surface is present — `CanonicalizationError` in `python/seam_sdk/errors.py` raised from
> `python/seam_sdk/_authorize.py`, the `canonical=` parameter on the shared builder, and the
> integer-JCS predicate with its own committed vectors at `conformance/authorize_jcs_int_extended.json`.
> The suite covering it is green: `python/tests/test_authorize.py`,
> `test_authorize_single_derivation.py`, `test_canonicalization_errors.py`,
> `test_jcs_roundtrip_stability.py`.
>
> Its `../seam-runtime/crates/**` clean-room wording is preserved as-written for the same reason as
> its sibling archive entry: historical record, not a maintained document.

**Issue:** [zer07labs/seam-sdk#60](https://github.com/zer07labs/seam-sdk/issues/60)
**Refs:** `zer07labs/seam-adapters#59`, `zer07labs/seam-adapters#61`

> **Checkpoint trail lives at the bottom of this file, not in `PROGRESS.md`.** `PROGRESS.md` is
> single-occupant by convention and is currently held by `plans/record-digest-v3.md`, whose Phase 6
> verification gate is still open. Evicting it would destroy that trail, so this plan carries its own.

> **Revision 2.** A Fable design review of revision 1 found a blocker: revision 1's acceptance
> predicate for large integers (`int(float(v)) == v`) would have **silently signed a digest over a
> different number** — `2**60` is exactly representable, so revision 1 accepted it, but JCS renders it
> `1152921504606847000`, not `1152921504606846976`. Revision 1 also asserted, as "verified in
> advance", that a plain decimal rendering and the ES6 rendering are character-identical below
> `10**21`. That claim is **false**; they part company from about `2**55`. The original verification
> sampled only powers of ten, where the two happen to coincide — so the claim and the test corpus
> shared one blind spot, and the tests as specified would have passed while the delivered property
> was false. Phase 3 below carries the corrected predicate, empirically validated over 4,026 random
> values (revision 1's predicate fails 3,928 of them; the corrected one fails none). Revision 1 also
> sequenced a live, unrelated defect behind that irreversible change; it now ships first, as Phase 2.

## Context

`build_authorize_request` (`python/seam_sdk/_authorize.py:118`) JCS-canonicalizes `tool_input`
itself. Callers that need the digest *before* the call — every adapter that records it on a handle
row — canonicalize the same object first. Two derivations of one value, from a caller-supplied
mutable object, separated by an RTT. When they disagree the SDK raises a **builtin**
(`ValueError`/`TypeError`/`RuntimeError`/`RecursionError`), not a `SeamError`; a consumer that
classifies `SeamError` as policy and everything else as transport then treats it as an availability
failure, and a fail-open deployment runs the tool with zero RPCs sent. `seam-adapters` burned three
verification rounds closing exactly that, and its fix — rebuilding every container and normalizing
every scalar before handing the value over — is a workaround every other consumer would have to
rediscover.

Three things the issue did not know, found while reading the code:

1. **The SDK re-derives internally, on its own retry path.** `SeamClient.authorize`
   (`python/seam_sdk/client.py:276`, invoked at `:289` and again at `:293`) and
   `AsyncSeamClient.authorize` (`python/seam_sdk/aio.py:213`, invoked at `:229` and `:232`) build the
   request through a closure that is called **twice** when a stale ticket produces `UNAUTHENTICATED`.
   Each call re-canonicalizes `tool_input` from scratch. A dict mutated during the admit RTT gets a
   *different* digest on the retry than on the first attempt, and the SDK signs and sends it without
   noticing. The retried request is internally consistent, so the runtime accepts it — the SDK simply
   authorizes different input than it first asked about, and than whatever the adapter recorded.
   No caller discipline can prevent this; it is entirely inside the SDK.
2. **TypeScript already got this right.** `ts/src/client.ts:375` hoists
   `const canonical = jcsCanonicalize(toolInput ?? {})` out of its `request()` closure and reuses the
   bytes across the retry, re-signing only `callSig` (which must change — it binds the new ticket).
   Python's twin does not. A straight Python-vs-TS divergence in a signed-digest path.
3. **The int arm can already emit invalid JSON on the supported Python floor.** `pyproject.toml`
   requires `>=3.10`, and on 3.10 `str(SomeIntEnum.MEMBER)` is `"Color.RED"`, not `"1"` — the int arm
   at `crypto.py:232` calls `str(v)`, so an `IntEnum` (which frameworks ship freely) canonicalizes to
   `{"c":Color.RED}`: invalid JSON, digested and signed. Not in issue #60; found here.

On issue item 2 (the int/float asymmetry), the reported behaviour reproduces, and the underlying
defect is sharper than "the arms disagree": **canonicalization is not idempotent under a JSON
round-trip.** Verified against the working tree:

| value | `jcs_canonicalize` | note |
|---|---|---|
| `1e16` (float) | `10000000000000000` | accepted |
| `10**16` (int) | `ValueError: integer … exceeds 2^53` | rejected — *same numeric value* |
| `1e20` (float) | `100000000000000000000` | accepted; `json.loads` returns an **int** |
| `1e21` (float) | `1e+21` | accepted; `json.loads` returns a **float**; stable |

The hole opens just above `2^53` — `2**53` itself round-trips today, since `crypto.py:231` tests `>`
not `>=`, so the interval is open at the bottom and the first failing value is `2**53 + 2` — and
closes at `10**21`, where ES6 switches to exponential notation, `json.loads` yields a float again,
and the round-trip is stable on its own. `_MAX_SAFE_INT` is the wrong predicate even inside its own
rationale: the question is not "is this below 2^53" but "does JCS render this integer as itself".

## Long-term posture

**One-way doors in this plan.**

- **Widening what `jcs_canonicalize` accepts is irreversible.** Once `10**16` produces a digest a
  caller depends on it, and the digest is what `call_sig` signs and what the runtime re-derives.
  Phase 3's predicate is chosen so that this is nonetheless *provably* safe: an integer is accepted
  only if its plain decimal form **is** the ES6 rendering of its double, and the bytes emitted are
  the ES6 bytes. So **every byte string the widened int arm can produce was already producible by the
  float arm** — no new wire shape ever reaches the runtime, and there is nothing for a conformant
  runtime to disagree with. This is a much stronger guarantee than revision 1's `10**21` cap, which
  rested on a false premise; the cap now falls out of the predicate for free (a plain decimal form
  never contains an exponent, so nothing at or above `10**21` can satisfy it).
- **Narrowing the float arm instead was rejected.** It would make the Python SDK refuse `{"t": 1e16}`
  — a legal RFC 8785 value TS accepts and the conformance vector's own `1e21` case shows the runtime
  handles. Wrong direction.
- **`CanonicalizationError` changes the exception type callers see.** Phase 1 makes it inherit
  `ValueError` **and** `TypeError` alongside `SeamError` precisely so no existing `except` clause
  stops working. A widening, not a swap. Precedent in-repo: `RecordDigestStripError` subclasses
  `ValueError` for the same reason (`crypto.py:403`).
- **`canonical=` is a public API addition**, keyword-only and defaulted, so it is additive.

**Scope boundary.** Go, Java and Kotlin ship only generated protobuf stubs (`*/gen/`) with no
hand-written JCS, so they carry no obligation from any phase here. Stated so the next reader does
not re-check.

## Enterprise concerns

The failure this closes is a **fail-open**: a builtin escaping an SDK call, misclassified as
transport, executing a tool with no policy decision behind it. That is also why Phase 1 carries a
**cross-repo obligation, not just a code change**: `errors.py:15-22` records that `seam-adapters`
diffs this file's class hierarchy against its classification rosters, because an unclassified non-RPC
`SeamError` resolves there as a `TransportFailure` and under `FAIL_OPEN` runs a gated tool ungated —
the exact fail-open this plan exists to close. Adding `CanonicalizationError` without telling
adapters is *neutral* (it lands in the same bucket the builtins do today) but delivers none of the
benefit, so Phase 1 files the adapters issue in the same cycle rather than leaving it to be
discovered downstream.

Phases order **typed errors → stop re-deriving → correct acceptance set → let the caller own the
derivation**, so the irreversible change (Phase 3) is the last thing to land before the API that
depends on it, and the live defect (Phase 2) is not held hostage to it.

---

## Phase 1 — `CanonicalizationError`: canonicalization fails as a `SeamError`, always

**Status:** DONE
**Delivers:** a typed `seam_sdk.errors.CanonicalizationError`, and a public
`canonicalize_tool_input()` that raises it instead of a builtin — including for failures raised by
caller-supplied code (a mutating container, a scalar subclass, deep nesting) that the SDK never
raises itself. Every public `Authorize` path routes through it.
**Depends on:** nothing.
**Files:** `python/seam_sdk/errors.py`, `python/seam_sdk/_authorize.py`, `python/seam_sdk/__init__.py`,
new `python/tests/test_canonicalization_errors.py`. **`crypto.py` is deliberately not touched.**

**The structural constraint that shapes this phase.** The obvious implementation — raise the typed
error from `jcs_canonicalize` in `crypto.py` — is **not available**, and finding out why is what this
phase is actually about:

- `test_no_seam_error_subclass_is_defined_outside_errors_py`
  (`python/tests/test_errors_is_import_light.py:513`) requires every `SeamError` descendant to be
  defined in `errors.py`, because `seam-adapters` loads that one file standalone and diffs its
  hierarchy against its classification rosters.
- `crypto.py` is itself import-light under the same guard (`IMPORT_LIGHT`, `:86`), allowed
  `cryptography` and nothing else, with **no relative imports** — because `seam-runtime`'s
  `sdk-digest-parity` gate loads that one file standalone to call `record_digest_v*`. `errors.py`
  imports `grpc`, so `from .errors import …` in `crypto.py` breaks a *different repo's* CI.

This is the same tension that already made `RecordDigestStripError` a bare `ValueError` living in
`crypto.py` (`test_errors_is_import_light.py:76-81` records exactly that reasoning). Repeating that
trick here would defeat the point: a non-`SeamError` is invisible to the adapters roster, which is
the classification that ask 3 exists to enable.

**Approach.** Split definition from raising, along the boundary the guards already draw.

- `errors.py` gains `class CanonicalizationError(SeamError, ValueError, TypeError)`. Taxonomy-correct,
  stdlib-only, visible to the adapters roster. The triple base is what makes it additive: the
  existing arms raise `ValueError` (NaN, out-of-range int) and `TypeError` (non-string key,
  unserializable type), a caller cannot predict which a given input triggers, and anything catching
  either keeps working. MRO linearization and layout compatibility verified. In-repo precedent for
  the widening shape: `RecordDigestStripError` subclasses `ValueError` (`crypto.py:403`).
- `_authorize.py` — which already imports `.errors` and is under no import-light guard — gains
  `canonicalize_tool_input(tool_input) -> bytes`, exported from the package root. It calls
  `jcs_canonicalize` and converts any failure. `build_authorize_request` uses it, so both clients and
  every existing caller get typed errors with no change on their side.
- `crypto.py` keeps raising builtins for direct low-level callers. That residual is **stated in the
  docs, not hidden**, and the seam-sdk#54 issue gets a note asking whether the import-light contract
  should eventually widen — the errors.py docstring explicitly asks for that conversation to happen
  there rather than be discovered downstream.

Converting only our own `raise` statements would not be enough even if crypto could import errors:
the issue's motivating case — `RuntimeError: dictionary changed size during iteration` — is raised by
CPython's dict iterator, and a `str` subclass raising from `__iter__`/`encode` can raise anything. So
`canonicalize_tool_input` wraps the whole call, which also covers the final `.encode("utf-8")`
(`crypto.py:265`) where the lone-surrogate `UnicodeEncodeError` arises. `except Exception` (not
`BaseException`) is correct and load-bearing: `KeyboardInterrupt` and `SystemExit` must still
propagate, while `RecursionError` and `RuntimeError` must not. A `CanonicalizationError` already in
flight is re-raised unchanged, never re-wrapped.

Rejected: two error classes (value vs type) — the caller cannot tell in advance which arm a hostile
input hits, so it would catch both. Rejected: wrapping inside `seam_sdk/__init__.py` so that
`seam_sdk.jcs_canonicalize` differs from `seam_sdk.crypto.jcs_canonicalize` — two functions with one
name and different failure modes is worse than the problem.

**Edge cases & failure modes.** Exception from `__iter__` mid-traversal (`jcs_canonicalize` builds
into a local list, so there is no partial state to leak); `RecursionError` from deep nesting, caught
after the stack unwinds; `BaseException` from a subclass — must propagate untouched; `raise … from e`
must preserve `__cause__`, which is what keeps a genuine SDK bug diagnosable after being typed as an
input error.

**Acceptance criteria.**
1. `CanonicalizationError` is exported from `seam_sdk` and `seam_sdk.errors`, and is a subclass of
   all three of `SeamError`, `ValueError`, `TypeError`.
2. `canonicalize_tool_input` is exported from `seam_sdk`, returns bytes identical to
   `jcs_canonicalize` for every accepted input, and raises `CanonicalizationError` for every input
   `jcs_canonicalize` rejects — asserted over the existing rejection corpus.
3. A `dict` subclass whose `__iter__` raises `RuntimeError` surfaces `CanonicalizationError` with the
   `RuntimeError` as `__cause__`.
4. A `str` subclass that answers once and raises on the second read surfaces `CanonicalizationError`.
5. Nesting past the recursion limit surfaces `CanonicalizationError`.
6. `KeyboardInterrupt` from a container's `__iter__` propagates as `KeyboardInterrupt`.
7. A `CanonicalizationError` already in flight is not double-wrapped (`__cause__` is not itself a
   `CanonicalizationError`).
8. `build_authorize_request` raises `CanonicalizationError`, not a builtin, for a bad `tool_input`.
9. `python/tests/test_errors_is_import_light.py` passes **unchanged** — including the
   no-`SeamError`-outside-`errors.py` check and both standalone-load checks.
10. `python/tests/test_jcs_digest.py` passes **unchanged** — `crypto.py` is untouched, so this is
    trivially true and is the compatibility proof.

**Tests.** `python/tests/test_canonicalization_errors.py`, one test per criterion 1–8, each asserting
the new type *and* that the legacy builtin catch still works.

**Cross-repo (issues only, no sibling writes).**
- `zer07labs/seam-adapters`: `CanonicalizationError` is a new non-RPC `SeamError` and needs a
  classification-roster entry, or it resolves as `TransportFailure` and `FAIL_OPEN` runs the tool
  ungated. Also: the recommended consumer pattern is now
  `canonicalize_tool_input()` + Phase 4's `canonical=`, which replaces their normalization workaround.
- `zer07labs/seam-sdk#54`: note that ask 3 hit the crypto.py-cannot-import-errors boundary, and what
  the residual is, so the next person meets the reasoning instead of rediscovering it.

**Docs.** `CHANGELOG.md` (Unreleased/Added), `COMPATIBILITY.md` (new error type and helper, why
additive, and the stated residual that `seam_sdk.crypto.jcs_canonicalize` still raises builtins).

---

## Phase 2 — stop re-deriving on the SDK's own retry path

**Status:** DONE
**Delivers:** `SeamClient.authorize` and `AsyncSeamClient.authorize` canonicalize exactly once per
call, including across an `UNAUTHENTICATED` refresh-and-retry. No public API change.
**Depends on:** nothing. Deliberately **not** sequenced behind Phase 3 — this is a live defect in a
signed path and must not wait on an irreversible change.
**Files:** `python/seam_sdk/client.py`, `python/seam_sdk/aio.py`,
new `python/tests/test_authorize_single_derivation.py`.

**Approach.** Hoist the canonicalization out of each `build` closure: canonicalize once before the
closure, pass the bytes into `build_authorize_request` via the internal path Phase 4 makes public
(for this phase, an internal keyword is enough — Phase 4 promotes it). This is precisely what
`ts/src/client.ts:375` already does; the change makes Python match its own TS twin. `call_sig` is
still recomputed per attempt, because it binds the ticket bytes, which do change on refresh.

**Edge cases & failure modes.** The refresh path must still re-sign (a reused `call_sig` would be
rejected — assert it changes); a canonicalization failure now happens *before* the ticket is
acquired rather than after, changing which error a caller sees first when both would fail (an
improvement — no admit RTT is spent on uncanonicalizable input — but it is a behaviour change and is
recorded); `digest_only=True` unaffected.

**Acceptance criteria.**
1. On the `UNAUTHENTICATED` retry path, `jcs_canonicalize` is invoked **exactly once**, sync and
   async — asserted by call counting.
2. A `tool_input` dict that mutates between the two attempts yields the **same** `tool_input_digest`
   on both requests. This test fails on `main` and is the regression proof.
3. The two attempts carry **different** `call_sig` values (the ticket changed) but the same digest.
4. Every existing test in `python/tests/test_authorize.py` passes unchanged.

**Tests.** `python/tests/test_authorize_single_derivation.py`, driven through the existing fake-stub
harness in `test_authorize.py`. Criterion 2 is decoy-verified: it must be shown red on `main`.

**Docs.** `CHANGELOG.md` (Unreleased/Fixed).

---

## Phase 3 — align the int and float arms, by construction

**Status:** DONE
**Delivers:** `jcs_canonicalize` accepts an `int` iff JCS renders that integer as itself, rendering it
through the same ES6 path the float arm uses. Canonicalization becomes idempotent under a JSON
round-trip. The `IntEnum` invalid-JSON hole closes.
**Depends on:** Phase 1 (so the new rejection is already typed).
**Files:** `python/seam_sdk/crypto.py`, `ts/src/crypto.ts`,
new `conformance/authorize_jcs_int_extended.json`,
new `python/tests/test_jcs_roundtrip_stability.py`, `ts/tests/jcs_digest.test.ts`.

**Approach.** Replace the `abs(v) > _MAX_SAFE_INT` test at `crypto.py:231` with:

- `abs(v) <= _MAX_SAFE_INT` → render `int.__repr__(v)`. Byte-identical to today for every plain
  `int`; the pinned-vector path does not move.
- otherwise: `rendered = _jcs_number(float(v))`; accept iff `rendered == int.__repr__(v)`, and emit
  `rendered`.

**Why this predicate.** It says exactly the thing that matters — *JCS renders this integer as
itself* — and it is self-enforcing in both directions: the emitted bytes are the float arm's bytes
(so no new wire shape exists), and they parse back to the same `int` (so the round-trip is stable).
Revision 1's `int(float(v)) == v` looked equivalent and is not: it accepts `2**60`, whose ES6
rendering is `1152921504606847000` — a **different number**, silently signed. Empirically, over
4,026 random and boundary values, revision 1's predicate leaves 3,928 round-trips broken; this one
leaves none, and rejects `2**55` and `2**60` alongside `2**53 + 1`, all with the same honest reason:
canonicalization would rewrite the value.

`int.__repr__(v)` rather than `str(v)` closes the third finding above. It must be `__repr__`: `int`
defines no `__str__`, so the unbound `int.__str__` falls through to `object.__str__` and re-enters
the subclass's `__repr__` — for an `IntEnum` it yields `<Color.RED: 1>`, strictly worse than the bug
it was meant to fix. Verified both ways. This hardens the **int** arm only; a lying `str` subclass is
a wider surface that Phase 1 types when it *raises* but does not neutralize when it *lies*, and that
limit is recorded rather than papered over.

`float(v)` on a huge `int` raises `OverflowError`; Phase 1's wrapper types it, and it is caught
explicitly so the message names the real reason.

**TS mirror.** `ts/src/crypto.ts:172-173`'s `bigint` arm gets the same predicate and, critically, the
same **rendering**: `String(Number(v))`, accepted iff it equals `v.toString()`. Aligning acceptance
sets alone (revision 1) was not enough — a `bigint` accepted but rendered via `v.toString()` would
emit `…846976` where Python emits `…847000`, a live cross-language digest divergence in exactly the
newly-widened range.

**Durable pin.** A new SDK-owned `conformance/authorize_jcs_int_extended.json`, machine-emitted (no
digest typed by hand), consumed by **both** the Python and TS suites, following the
`record_digest_v3_extended.json` precedent. The runtime-owned vector is a byte-identity contract and
is not edited here.

**Edge cases & failure modes.** `2**53` (accepted, boundary, unchanged); `2**53 + 1` (still rejected,
rounds to `2**53`); `2**53 + 2` (newly accepted); `2**55`, `2**60` (**rejected** — the cases revision
1 got wrong); `10**16`, `10**20` (accepted — the issue's case); `10**21` and above (rejected by the
predicate for free); negatives at every boundary; `-0.0` unchanged; `bool` — `isinstance(True, int)`
is true but the `v is True`/`v is False` arms precede the int arm and still do; an `IntEnum` member.

**Acceptance criteria.**
1. `jcs_canonicalize(10**16) == jcs_canonicalize(1e16) == b"10000000000000000"`.
2. `jcs_canonicalize(2**53 + 1)`, `(2**55)`, `(2**60)`, `(10**21)` all raise `CanonicalizationError`
   (and are still `ValueError`).
3. Over a **randomized** corpus of ≥2,000 integral doubles spanning `(2**53, 10**21)` plus every
   boundary above, `jcs_canonicalize(json.loads(jcs_canonicalize(x))) == jcs_canonicalize(x)`. The
   corpus must be randomized: a boundary-only corpus passes under the *wrong* predicate too, which is
   how revision 1's tests would have certified a false property.
4. For every accepted `int n`, `jcs_canonicalize(n) == jcs_canonicalize(float(n))`.
5. Every byte string the int arm emits is producible by the float arm — asserted directly.
6. An `IntEnum` member canonicalizes to its numeric value on every supported Python, `>=3.10`.
7. The rejection message names value rewriting, not "exceeds 2^53" — which would now be false.
8. The runtime-owned conformance vector still passes byte-for-byte, Python **and** TS.
9. Python and TS agree on both the accepted set **and the emitted bytes** at every boundary, via the
   shared extended vector.

**Tests.** `python/tests/test_jcs_roundtrip_stability.py` (criteria 1–7); `ts/tests/jcs_digest.test.ts`
gains the shared-vector cases (criteria 8–9).

**Docs.** `CHANGELOG.md`, `COMPATIBILITY.md` (the accepted set widened — irreversible),
`DECISIONS.md` (why widen not narrow; why this predicate and not the obvious one).

---

## Phase 4 — one derivation: let the caller supply the canonical bytes

**Status:** DONE
**Delivers:** a caller can hand the SDK the canonical bytes it already produced, and the second
derivation disappears from the public path.
**Depends on:** Phases 1, 2, 3.
**Files:** `python/seam_sdk/_authorize.py`, `python/seam_sdk/client.py`, `python/seam_sdk/aio.py`,
`ts/src/client.ts`, `python/tests/test_authorize_single_derivation.py`, `ts/tests/*`.

**Approach.** `build_authorize_request(..., canonical: Optional[bytes] = None)`, keyword-only,
mutually exclusive with `tool_input`. Passing both raises `CanonicalizationError` rather than
silently preferring one — silently preferring is the exact fail-open shape this issue is about. The
SDK does **not** re-canonicalize `canonical` to check it: that reinstates the second derivation. It
validates only what is checkable without re-deriving — `bytes`, non-empty — and the docstring states
plainly that canonicality is the caller's assertion. Both public `authorize` methods gain the
pass-through kwarg, without which the parameter is unreachable and Ask 1 is not actually delivered.
TS gains `opts.canonical?: Uint8Array`; its hoist already exists.

**What accepting unvalidated bytes does and does not open.** The caller can only misrepresent *its
own* input, which it already fully controls, and the signature is its own key — the digest stays
self-consistent, so the runtime accepts it exactly as before. Two genuinely new things: with
`digest_only=True` a caller can bind a signature to a digest of bytes never revealed to anyone; and
non-canonical bytes in the audit row silently break third-party re-derivation. Neither is visible to
the runtime **unless the runtime validates the canonicality of `tool_input`** — which this repo
cannot determine without reading the runtime. Filed upstream in Phase 5, not guessed at.

**Edge cases & failure modes.** `canonical=b""` — rejected; the empty object is `b"{}"`, and empty
bytes would digest to something no re-derivation can reproduce. `canonical=` with `digest_only=True`
(digest sent, bytes withheld — must still work). `canonical=` as `str` — rejected, not silently
encoded. `canonical=` with `tool_input=None` explicitly passed — allowed; `None` is the default, not
a supplied input. `canonical=` plus the retry path — still one derivation, zero in the SDK.

**Acceptance criteria.**
1. `build_authorize_request(canonical=jcs_canonicalize(x), …)` produces a request **byte-identical**
   to `build_authorize_request(tool_input=x, …)` — same digest, same `tool_input`, same `call_sig`.
2. Both `tool_input` and `canonical` → `CanonicalizationError`; `str` or `b""` → `CanonicalizationError`.
3. `digest_only=True` with `canonical=` sets the digest and leaves `tool_input` empty.
4. `SeamClient.authorize` and `AsyncSeamClient.authorize` both accept and forward `canonical=`.
5. With `canonical=`, `jcs_canonicalize` is invoked **zero** times inside the SDK, across the retry.
6. Every existing `test_authorize.py` test passes unchanged.
7. TS `authorize` accepts `opts.canonical` and produces a byte-identical request.

**Docs.** `CHANGELOG.md`, `COMPATIBILITY.md` (additive kwarg), `DECISIONS.md` (why the SDK does not
verify `canonical`).

---

## Phase 5 — record it where the next consumer will find it, and close the loop

**Status:** DONE
**Delivers:** the reasoning is durable in-repo, `#60` is answered against shipped code, and both
open questions are filed upstream.
**Depends on:** Phases 1–4.
**Files:** `DECISIONS.md`, `COMPATIBILITY.md`, `CHANGELOG.md`, `ASSUMPTIONS.md`,
`python/tests/test_compatibility_citations_resolve.py`.

**Approach.** Fold the per-phase doc edits into coherent final form; add anchored citations (the
existing guard requires them to find a needle, not pin a line); log any residual assumption in
`ASSUMPTIONS.md` tagged to this plan; file the two upstream questions; answer `#60` point by point
with `file:line` into merged code, including the three things it did not know.

**Cross-repo (issues only, no sibling writes).**
- `seam-runtime`: does its JCS validate that `AuthorizeRequest.tool_input` is canonical, or does it
  trust the digest? Determines whether Phase 4's unvalidated-bytes path is observable server-side.
- `seam-runtime`: how does its JCS render an integer ≥ `10**21`? Blocks nothing — Phase 3's predicate
  refuses that range for independent reasons — but it is the last gap between the predicate and the
  fully general one.
- `seam-adapters`: the Phase 1 roster entry (filed in Phase 1, confirmed closed here).

**Acceptance criteria.**
1. `python -m pytest python/tests/test_compatibility_citations_resolve.py` passes — every new
   citation resolves, anchored rather than line-pinned.
2. `ASSUMPTIONS.md` carries this plan's entries, tagged.
3. `#60` has a reply naming what shipped for each of its three asks, what deliberately did not, and
   the three findings it did not contain.

## Open questions

Both are filed in Phase 5 rather than guessed at, and neither blocks any phase.
`../seam-runtime/crates/**` is unreadable under the standing clean-room constraint, so neither can be
answered from here.

1. Does the runtime validate canonicality of `AuthorizeRequest.tool_input`? (Phase 4's blast radius.)
2. How does the runtime's JCS render an integer ≥ `10**21`? (The residual gap in Phase 3's predicate.)

## Checkpoint trail

| Phase | Status | Verifier | Rounds | Notes |
|---|---|---|---|---|
| 1 | DONE | Fable | 2 | `GAPS` → the wrap leaked through its own handler (an exception whose `__str__` raises), the residual statement omitted the root re-export, and a docstring named a kwarg that did not exist yet. All closed in `beaa80b`; the leak has a decoy-verified regression test. |
| 2 | DONE | — | 1 | Decoy-verified directly instead: reverting the hoist reddens exactly five tests. Split out of the plan's original Phase 3 on the reviewer's advice, so a live defect did not wait behind an irreversible change. |
| 3 | DONE | Fable | 1 | The one-way door. Predicate rewritten before any code, after review found revision 1's `int(float(v)) == v` would silently sign a rewritten value. |
| 4 | DONE | — | 1 | Rides on Phase 2's `_resolve_canonical`; the public surface and the TS mirror. |
| 5 | DONE | — | 1 | Docs, assumptions, upstream issues. The citation guard caught one drift caused by this phase's own CHANGELOG edit. |

**Divergences from the plan as written, recorded rather than silently absorbed:**

* **Phase 1 could not be implemented as specified.** `crypto.py` cannot import `errors.py` — two
  separate standalone-load contracts collide (see `DECISIONS.md`). The plan was revised mid-phase and
  the typed error is raised at the `_authorize.py` boundary through a new public
  `canonicalize_tool_input()`, with the residual disclosed rather than hidden.
* **Phase 3's predicate is not the one revision 1 specified.** See the Revision 2 note at the top.
* **`PROGRESS.md` was not used**, deliberately — it is single-occupant and still held by
  `plans/record-digest-v3.md`, whose Phase 6 gate is open.
