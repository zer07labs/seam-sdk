# `record_digest_v3` in Rust/Python/TS + v3 conformance vectors — issue #56 (B3 Phase 2)

> **📦 ARCHIVED 2026-08-31 — DELIVERED, all phases including 6a/6b/7/8.** Issue
> [#56](https://github.com/zer07labs/seam-sdk/issues/56) closed 2026-08-25. Archived while
> implementing `plans/post-adoption-hardening-and-acdp-readiness.md` Phase 1, whose whole
> premise was that this plan's tracking state had gone stale in two places.
>
> **Verified against this tree, not against the status table** (per `plans/README.md`'s archiving
> rule): `record_digest_v3` exists in all three languages — `python/seam_sdk/crypto.py:589`,
> `ts/src/crypto.ts:608`, `verify/src/verify.rs:448`. The Phase 6a/6b streamed arms are live and
> version-bounded in both helpers: `python/seam_sdk/admin.py:129` takes the v3 branch and `:107`
> refuses `schema_version > 3`; `ts/src/admin.ts:141` mirrors the branch and `:109` the refusal.
> The committed KATs are at
> `conformance/vectors.json:70`. The Phase 6 blocker cleared explicitly in this file's own log —
> `seam.event.v1` carrying `DecisionSealed` tags 11/12/13 reached the BSR.
>
> **One claim in this file did not survive and is left uncorrected on purpose**, because an archived
> plan is a historical record rather than a maintained document: its §"what this makes stale" says
> version-block origination became SDK-first per issue #56. That inversion **did not survive contact**
> — the runtime's emitter landed with its own blocks and its bytes were taken verbatim.
> `COMPATIBILITY.md` §7 is the settled text, and it says new vectors originate in the runtime, with a
> separate file — never a new block — as the sanctioned escape.
>
> Its `../seam-runtime/crates/**` clean-room wording is likewise preserved as-written: it was that
> plan's own operating constraint, and the corrected, narrower form now lives in `PROGRESS.md`.

**Status:** phases TODO. **Issue:** [seam-sdk#56](https://github.com/zer07labs/seam-sdk/issues/56).
**Spec (the ONLY normative input):** `../seam-runtime/docs/specs/seam-event.v1.md` §"Record digest"
(`:372`), §"Record digest (v3)" (`:379`), strip semantics (`:594`), `None`/`Some("")`/empty-list
(`:570`), outer-count rationale (`:586`), slot indices (`:401`), raw-UTF-8 rule (`:410`).
**Sequencing:** this repo merges FIRST; seam-runtime's B3 Phase 1 (`../seam-runtime/plans/b3-digest-v3.md`
Phase 2 = this work) does not merge until this turns its `sdk-digest-parity` green.

## Clean-room constraint — restated because it is the product claim

The three implementations here are transcribed **from the spec text alone**. Nobody implementing this
plan reads `../seam-runtime/crates/**` — not source, not tests, not fixtures. Four independent
implementations agreeing is evidence only if they are independent. If the spec is ambiguous, that is a
**spec bug to file at seam-runtime** (record it under Open questions), never a reason to consult their
Rust. Reading `../seam-runtime/docs/specs/**` and `../seam-runtime/plans/b3-digest-v3.md` is allowed;
reading `../seam-runtime/scripts/sdk-digest-parity.sh` (gate mechanics, zero digest code) was done for
the vector-shape decision and is allowed for the same reason.

## Scope

**The OUTER `digest_v3` only.** `context_digest` / `participation_digest` / `policy_rules_digest`
arrive as opaque 32-byte inputs on the wire (`DecisionSealed` tags 11/12/13). The spec's two
sub-digest formulas (`seam.audit.context-provenance.v3`, `seam.audit.participation.v3`) are for the
runtime and auditors — **no sub-digest code lands in this repo**. This is a wire-input
reimplementation with the same shape as `record_digest_v2`. Go/Java/Kotlin are crypto shims with no
record digests today (verified: zero hits for `record_digest`/`RecordDigest` outside `go/README.md`)
and stay out of scope — the issue names three languages.

## The formula (transcribed from spec `:385-399`; re-verify against the spec, not against this plan)

```
frame(x) = le32(len(x)) ‖ x
opt(x)   = 0x00 absent; 0x01 ‖ frame(x) present          # None ≠ Some(""): 1 byte vs 5
digest_v3 = SHA256(
    frame("seam.audit.record-digest.v3")
  ‖ frame(decision_id) ‖ frame(tenant) ‖ frame(namespace)
  ‖ frame(SHA256(ciphertext))        # wire ciphertext_digest, tag 10
  ‖ frame(le64(sealed_at))
  ‖ frame(outcome) ‖ opt(mode) ‖ opt(policy_version) ‖ opt(supersedes)
  ‖ frame(context_digest)            # 32 bytes, wire tag 11 — MANDATORY, framed (slot 10)
  ‖ frame(participation_digest)      # 32 bytes, wire tag 12 — MANDATORY, framed (slot 11)
  ‖ opt(policy_rules_digest)         # 32 bytes when present, wire tag 13 — genuinely optional (slot 12)
  ‖ frame(le32(schema_version))      # == 3 (slot 13, stays last)
)
```

Slots 1–9 are byte-identical to v2; the three new slots are **inserted before `schema_version`**, not
appended after it (spec `:406-408`). Strings hash as raw UTF-8, no normalization (spec `:410`).

## Non-negotiables (each is a falsifiable acceptance criterion somewhere below)

1. `record_digest_v2` stays byte-identical forever; the v2/admission/tct/attestation vector blocks are
   untouched in the diff (sole allowed diff line outside the new block: the closing `}` of the
   `record_digest_v2` object gains a trailing comma — JSON syntax, no value changes).
2. A v3 payload missing tag 11 or 12 is REFUSED, never defaulted, never fallen back to v2 — and the
   refusal is reported **distinctly** from a digest mismatch. Tag 13 absent is legitimate.
3. A verifier is never silently green on a `schema_version` it cannot recompute (spec `:648-650`).
4. Vectors are never transcribed by hand: outputs are emitted by executing one of our implementations
   and independently recomputed by the other two.
5. ~~Absent ≠ empty for tags 11/12 on the wire: the Rust mirror must use explicit presence
   (`optional bytes`), because `wire.rs:153`'s tag-10 pattern (non-optional `Vec<u8>`) collapses
   absent/empty — acceptable for tag 10's non-empty check, NOT for strip detection on 11/12.~~
   **RETRACTED — see the Phase 6 approach-correction below, and Phase 8.** The conclusion (absent
   must be distinguishable, and a strip must be refused) was right; the mechanism was wrong. Tags
   10–13 are SINGULAR, and absence is carried by LENGTH: seam-runtime#435 pinned `len == 0` as a
   total absence mapping, because a singular field makes the out-of-domain empty digest
   *unrepresentable by a conforming encoder*, which `optional` would not. Implementing this rule as
   written is what shipped the Phase 8 bug — a verifier that refused records the contract calls
   valid. Everything below that asserts explicit presence for 11/12/13 inherits this retraction;
   it is left in place rather than rewritten, because the plan is also the record of what we
   believed when.

---

## Design decisions (argued once here; phases reference them)

### D1 — Python is the vector emitter; TS and Rust are independent reproducers

The standing rule (no hand-transcribed vectors) plus "this repo merges first" (so no runtime KAT
exists yet) means one of OUR implementations must emit the v3 `digest_hex` values. **Python**,
because: (a) the runtime's parity gate already executes `python/seam_sdk/crypto.py` standalone via
`spec_from_file_location`, so Python is the implementation the cross-repo gate exercises directly;
(b) a Python emitter can splice JSON while byte-preserving the rest of the file, which criterion 1
requires; (c) the emitter is committed (`scripts/emit_record_digest_v3_vectors.py`) and a pytest
re-runs it and byte-compares its output against the committed block — so a hand-edited digest reddens
CI, which is what makes "not hand-transcribed" a checked property rather than a habit.

TS and Rust then **recompute every case from the inputs** and compare to `digest_hex` — reproduction,
not file-reading-as-oracle: a consumer that read a cached answer would pass vacuously, so each
language also carries a binds-every-field mutation test (perturb one input ⇒ digest must change),
which is the decoy that drives the guard red. Honest residual: all three transcriptions share one
author, so the truly independent cross-check is the runtime's own emitter byte-diffing this file in
its Phase 1 — that is the fourth implementation, and it is exactly what the lockstep gate exists for.

*Rejected:* Rust as emitter (verify/ deliberately has no JSON-writing role and splicing from Rust
risks reformatting the file); waiting for the runtime to emit first (inverts the decided merge order
and would have the SDK transcribe from runtime output — a copy, not a clean room).

### D2 — vector block shape: a `cases` list of v2-shaped objects

```jsonc
"record_digest_v3": {
  "cases": [
    { "name": "all_optionals_present", "inputs": { ... }, "digest_hex": "..." },
    ...
  ]
}
```

Each `inputs` object mirrors the v2 key style exactly (`domain`, `decision_id`, `tenant`,
`namespace`, `ciphertext_hex`, `ciphertext_digest_hex`, `sealed_at`, `outcome`, `mode`,
`policy_version`, `supersedes`, plus `context_digest_hex`, `participation_digest_hex`,
`policy_rules_digest_hex` (JSON `null` = tag 13 absent), `schema_version: 3`). Rendering matches the
existing file byte-conventions: 2-space indent, lowercase hex, `null` for absent, `\uXXXX` escapes,
trailing newline.

Why this shape given the runtime's script: today the script does `v = vectors[name]; i = v["inputs"]`
and calls with the fixed v2 ten-tuple — a v3 block of ANY multi-case shape makes it fail loud
(`KeyError`/`TypeError`), which the issue documents as the runtime's known Phase 1 gap. The `cases`
wrapper helps their fix: the discovery loop stays (`record_digest_v*` prefix), and per-version
handling becomes "if `cases` in block: iterate, else: legacy single object" — with `name` giving them
a printable failure label per case. Their emitter must reproduce our block byte-for-byte (the drift
step diffs the whole file), so the exact rendering above is part of the contract; Phase 5 communicates
it to seam-runtime explicitly.

*Rejected:* a bare JSON list (works, but `isinstance` branching is uglier for them and leaves no room
for per-case names); one flat object per case as separate top-level keys (`record_digest_v3_case1`…)
— pollutes discovery-by-prefix and makes "how many cases" invisible.

Cases (inputs hand-CHOSEN, outputs machine-EMITTED — choosing inputs is allowed, computing outputs by
hand is not). All share `decision_id "dec:conformance-v3"`, `tenant "acme"`, `namespace "fraud"`,
`sealed_at 1700000000000`, `outcome "Resolved"`, `schema_version 3`, one fixed ciphertext (emitter
computes `ciphertext_digest_hex = SHA256(ciphertext_hex)`), `context_digest =
SHA256("seam-conformance-context-v3")`, `participation_digest =
SHA256("seam-conformance-participation-v3")` (distinct by construction — required so a tag-11/12
slot-swap cannot cancel out):

1. `all_optionals_present` — `mode "decision.v1"`, `policy_version "policy-7"`,
   `supersedes "dec:prior"`, `policy_rules_digest = SHA256("seam-conformance-policy-rules-v3")`.
   Exercises every `opt` present branch including tag 13.
2. `policy_rules_absent` — as (1) but `policy_rules_digest: null`, `supersedes: null`. Today's
   common case; pins the deliberate frame-vs-opt asymmetry (slots 10/11 framed even when 12 absent).
3. `optionals_none` — `mode`/`policy_version`/`supersedes`/`policy_rules_digest` all `null`. Pins the
   four 0x00 presence bytes.
4. `mode_empty_string` — identical to (3) except `mode: ""`. Pins `opt(None)` (1 byte) ≠
   `opt(Some(""))` (5 bytes) as a cross-language vector, not just a unit test; every consumer asserts
   case 3's and case 4's digests differ.

### D3 — Python/TS API shape: extend the v2 shape, three parameters inserted before `schema_version`

Python (mirrors `crypto.py:351`'s positional style; insertion position mirrors the preimage order):

```python
def record_digest_v3(decision_id, tenant, namespace, ciphertext_digest, sealed_at, outcome,
                     mode, policy_version, supersedes,
                     context_digest: bytes, participation_digest: bytes,
                     policy_rules_digest: bytes | None,
                     schema_version: int = 3) -> bytes
```

TS (mirrors `crypto.ts:299`'s single-object style):

```ts
export function recordDigestV3(d: { decisionId; tenant; namespace; ciphertextDigest; sealedAt;
  outcome; mode: string | null; policyVersion: string | null; supersedes: string | null;
  contextDigest: Uint8Array; participationDigest: Uint8Array;
  policyRulesDigest: Uint8Array | null; schemaVersion?: number }): Uint8Array
```

Rationale: the runtime's parity script builds a per-version argument mapping in its Phase 1; a shape
that is "v2's tuple + three args in preimage order" is the cheapest possible mapping to write and to
review. A struct/dict Python API would be the only non-positional digest function in `crypto.py` and
would buy nothing (the input set is closed and versioned by name). Name must be exactly
`record_digest_v3` at module top level of `crypto.py` — the runtime resolves functions by exact name
(`COMPATIBILITY.md:243`). Export from `python/seam_sdk/__init__.py` (both import and `__all__`);
TS exports automatically via `export *` in `ts/src/index.ts`.

### D4 — strip refusal in Python/TS lives in BOTH layers, differently

- **Pure functions** (`crypto.py`/`crypto.ts`): `context_digest`/`participation_digest` are
  non-optional parameters, and the function **raises/throws a typed error** (`ValueError` /
  `Error`) on `None`/`undefined` or on a length ≠ 32, with a message naming the strip semantics
  ("a v3 record without context_digest (tag 11) is a strip attack — refuse, do not default").
  This makes "distinct from mismatch" true **by construction** for any consumer: a strip is an
  exception, a mismatch is a `False`/unequal comparison — they cannot be confused. Passing `None`
  into `_frame` would otherwise die as an incidental `TypeError` naming `len()` — fail-loud but
  unactionable, and an operator cannot tell it from a caller bug.
- **Wire-level helpers** (`admin.py:70` / `admin.ts:79` `verify[_s]treamedRecordDigest`): the layer
  that can actually SEE absence (`HasField`) — but it is **blocked** on the regenerated contract
  carrying tags 11/12/13 (Phase 6, cross-repo dependency). Until then those helpers already refuse
  v3 loudly (`ValueError: v3 record is not stream-recomputable (only v2)`), pinned by
  `python/tests/test_streamed_decode.py:85` — correct interim behavior; **do not touch it in
  Phases 1–5**.

32-byte length validation (also for a present `policy_rules_digest`) is a deliberate choice: the spec
fixes these values at 32 bytes; framing a wrong-length value would produce a garbage digest reported
as a "rewrite", which mislabels the failure. `record_digest_v2` stays exactly as it is — retrofitting
validation onto it would violate non-negotiable 1's spirit (its observable behavior is frozen).

### D5 — Rust verifier dispatch and reporting

`verify/src/verify.rs` `verify_authenticity` currently does: `schema_version < 2 ⇒ skip; else
recompute v2` — which routes a v3 record into a **misleading "does NOT match its own digest"** error
(the same defect the runtime found in its own verifier). Replace with an explicit match:

- `0 | 1` ⇒ skip (historical, not stream-recomputable — unchanged, disclosed via the existing
  `records_recomputed` count staying below the sealed-record count).
- `2` ⇒ existing v2 path, byte-identical behavior (tag-10 non-empty check, recompute, compare).
- `3` ⇒ tag-10 non-empty check (same strip/downgrade rationale, spec `:265-274` scopes it to
  `schema_version >= 2`); then **tag 11/12 presence + 32-byte checks** — absence or wrong length is
  an `Err` whose text names the field, the tag, and the word "strip", and states what an operator
  should conclude ("someone removed a field — this is NOT a digest mismatch"); then recompute v3
  (an `opt`-bytes arm added beside the existing `opt` string closure) and compare — mismatch keeps
  the v2 arm's "payload rewrite" wording. `policy_rules_digest` absent ⇒ `opt(None)`, no refusal;
  present ⇒ 32-byte check then `opt(Some)`.
- `n >= 4` ⇒ `Err` refusing outright: "schema_version {n} is newer than this verifier knows (v2/v3)
  — refusing rather than reporting green on a formula it cannot recompute; upgrade seam-verify".
  Mirrors the Python/TS streamed helpers' existing "upgrade the SDK" refusal and the spec's
  never-silently-green rule. *Rejected:* skip-and-disclose like v1 — v1 is a closed historical class;
  an unknown FUTURE version reaching an old verifier is indistinguishable from a downgrade-mask and
  must fail closed.

**Reporting shape: no third shape is invented.** Precedent examined: `--strict` refusal uses
`fail(msg, json, "REFUSED (--strict)")`, tag-10 strip and mismatch both surface as
`AUTHENTICITY VERIFICATION FAILED` with distinct message text, all exit 2; `--json` always emits
`{"verified":false,"error":<text>}` (`main.rs`). v3 strip and unknown-version refusals follow exactly
that channel: **exit 2, same banner, distinct and unambiguous message text** (the message is the
operator's discriminator, as it already is for tag-10 strip vs rewrite). No new exit code (0/1/2 is a
published contract; a new code would break every harness parsing it), no new JSON field (additive
stability for the runtime's differential harness, which parses this output).

Wire structs: `DecisionSealedPb` (`wire.rs:132`) gains
`#[prost(bytes = "vec", tag = "11")] context_digest: Vec<u8>` and the same for
12/13 — **as planned this said `optional`/`Option<Vec<u8>>` per the now-retracted non-negotiable 5;
corrected in Phase 8 to singular, absence by length**; `DecisionSealedJson` (`wire.rs:261`)
gains three `Option<String>` base64 fields (`#[serde(default)]`, absent ⇒ `None`); `Decision`
(`wire.rs:330`) gains three `Option<Vec<u8>>`; both `Event::parse` arms map them through. Field
names transcribed from the spec's column names (`context_digest`, `participation_digest`,
`policy_rules_digest`) — see Open question 2.

### D6 — Rust consumes `conformance/vectors.json` directly (new), instead of inlined KATs

The v2 KAT is inlined in `verify.rs` unit tests because a runtime-committed KAT existed to copy. For
v3 no runtime KAT exists (we merge first), and inlining Python-emitted hex would be hand-copying
outputs into a second location — drift surface. A new integration test
`verify/tests/conformance.rs` reads `../conformance/vectors.json` via `CARGO_MANIFEST_DIR` and
**fails (never skips) if the file or the `record_digest_v3` block is missing** — a skipping guard is
vacuous. Packaging: the file lives outside the crate; add the test file to `Cargo.toml`'s package
`exclude` with a comment (the published crate's consumers cannot run a repo-relative test; CI runs it
from the repo, which is where it means something). The runtime's differential job checks out the
whole SDK repo, so the relative path holds there too.

### D7 — the vendored spec copy must be refreshed

`verify/docs/seam-event.v1.md` has **no v3 section** (its "Record digest" is at `:356` with only
v2/v1) — but the crate's README claims it is "written from the two specs in docs/". Shipping a v3
recompute whose normative text is absent from the vendored spec makes that claim false, which this
repo treats as a defect. Refresh the copy verbatim from
`../seam-runtime/docs/specs/seam-event.v1.md` (spec text is an allowed read; it is the input).
Likewise `verify/proto/seam/event/v1/seam_event.proto:186-201` (`DecisionSealed`, tags 1–10) gains
`bytes context_digest = 11; … = 12; … = 13;` transcribed from the spec's tag assignments, with a
comment noting the transcription source. (Planned as `optional bytes`; retracted — see rule 5.)

---

## Phases

### Phase 1 — Python `record_digest_v3` (the emitter-to-be)

**Status:** DONE (2026-08-24, 1 verify round, Fable — a crypto formula on a cross-repo contract).
The transcription was independently re-derived by the verifier and compared on 51 cases, including
unicode NFD/NFC, embedded NUL, `sealed_at` at both u64 bounds, and every optional-presence
combination: zero mismatches. `record_digest_v2` is byte-identical (zero removed lines in the
crypto.py diff, function body diffed against HEAD).

**Three divergences from the plan, all disclosed and verified:**

1. **`RecordDigestStripError` lives in `crypto.py` as a `ValueError`, not in `errors.py`.** D4 did not
   say where it goes. It cannot come from `.errors`: seam-runtime's `sdk-digest-parity` gate loads
   `crypto.py` **standalone** via `spec_from_file_location`, so a package-relative import breaks the
   gate outright (`ImportError: attempted relative import with no known parent package`, confirmed
   by running their loader against a counterfactual). The obvious taxonomy placement was the wrong
   one, and only the cross-repo constraint says so.
2. **The seam-sdk#54 import-light guard now covers `crypto.py` too.** That module had exactly the
   same out-of-repo, load-one-file dependency as `errors.py` and no guard at all. Per-module
   allow-lists and required imports; `.github/workflows/ci.yml`'s credential-free lane installs
   `cryptography` accordingly and `scripts/test_ci_gate.py` asserts it (a missing dep does not
   redden the guard — it makes it *skip*, which is the silent degradation worth asserting against).
3. **That guard's `__all__` cross-check fired falsely on this phase's own new error** and was fixed:
   it filtered by the `*Error` name suffix, which assumes every exported `*Error` is a `SeamError`.
   It now intersects with the real closure via a shared `_seam_error_closure`.

**Verifier findings, all closed:** the spec's raw-UTF-8/no-normalization rule (`:410`) was
untestable — every fixture was ASCII, and both an `.encode("ascii")` and an NFC-normalizing mutant
survived all 38 tests; an NFD/NFC fixture pair now kills both (re-proven by mutating inside
`record_digest_v3` specifically — the first mutation run patched `record_digest_v2` and gave a false
negative). The standalone fixture's skip/fail messages hardcoded "errors.py" and "grpcio" and so
misnamed both module and package once `crypto.py` was in the table. This plan said `opt(present)` was
38 bytes; it is 37. The `None`-vs-`b""` rationale credited the erasure-certificate v1 collision,
which was actually an omitted outer list count — same lesson, wrong incident.

**Depends on:** nothing.

**Delivers.** `record_digest_v3` in `python/seam_sdk/crypto.py` per D3/D4 (plus a private
`_opt_bytes` helper — the existing `_opt` at `crypto.py:347` takes `str`), exported from
`python/seam_sdk/__init__.py`.

**Files.** `python/seam_sdk/crypto.py`, `python/seam_sdk/__init__.py`,
`python/tests/test_record_digest_v3.py` (new).

**Approach.** Transcribe the preimage from spec `:385-399` in the same style as
`record_digest_v2` (`crypto.py:351`) — a flat `_frame`/`_opt` concatenation, no abstraction shared
with v2 beyond the existing helpers (a shared "builder" would couple v2's frozen bytes to v3
edits — rejected). Docstring states the slot/tag offset (slot 10 = wire tag 11), the frame-vs-opt
asymmetry and why, and the strip-refusal contract. Do NOT touch `admin.py` (D4; the
`test_streamed_decode.py:85` pin must stay green).

**Edge cases & failure modes.** `None` vs `""` for each of mode/policy_version/supersedes;
`policy_rules_digest=None` (1 byte) vs present (37 bytes: 0x01+le32(32)+32); `context_digest=None`
⇒ `ValueError` naming tag 11 and "strip", not an incidental `TypeError`; wrong length (31/33 bytes)
⇒ `ValueError`; `schema_version` framed as given (vector carries 3).

**Tests** (`test_record_digest_v3.py`, style modeled on `test_conformance.py`'s
binds-every-field pattern): (a) binds-every-field — perturb each of the 13 inputs in turn, digest
must change; includes **swapping** context/participation values (slot-order decoy) and toggling
`policy_rules_digest` present↔absent; (b) `None` ≠ `Some("")` for `mode`; (c) strip refusals raise
`ValueError` with messages matched by `pytest.raises(..., match=...)` — and a decoy proving the
guard is real: assert the error type is NOT what a bare `_frame(None)` would raise; (d) v2
regression pin: `record_digest_v2` on the existing vector inputs still equals
`3817863521537d347c112bb95d7960d3d9f3007ee041f59c87bcaaf88ac40785`.

**Acceptance criteria.** `pytest python/tests/test_record_digest_v3.py -q` green;
`pytest python -q` green (proves `test_streamed_decode.py:85` untouched); `ruff check`/`format`
clean; a reviewer can map every preimage line to a spec line using only the diff and the spec.

**Docs.** None yet (Phase 5 batches them). Makes stale: nothing.

### Phase 2 — v3 conformance vectors, machine-emitted

**SUPERSEDED IN PART (2026-08-24, during Phase 5).** The digests this phase produced were right —
seam-runtime's independent emitter reproduces them exactly. The *file shape* was wrong, and the
reasoning that produced it was the wrong reasoning. D2 chose a `cases` array on the premise that this
repo merges first, so it gets to define the new block. That premise ignored what §7 of
`COMPATIBILITY.md` already said: the parity job byte-diffs the whole file, and byte-identity does not
converge — it settles wholesale, in one direction. seam-runtime landed
`record_digest_v3` + `record_digest_v3_absent_policy`, one `{inputs, digest_hex}` each, matching the
shape every other block in that file already used; those bytes are now taken verbatim, and the five
cases from this phase live in `conformance/record_digest_v3_extended.json`, loaded alongside by all
three SDK suites. See Phase 4.5. Nothing about the formula changed.

**Status:** DONE (2026-08-24, 1 verify round, Fable — a cross-repo byte-diffed artifact). The
committed block is 109 added lines and **zero** removed: v2/admission/tct/attestation are byte-
untouched, and the structural comma landed inside the added region rather than as an edit. The
strongest attack the verifier could build — change an input *and* splice in the correctly recomputed
digest — is caught, because the emitter regenerates inputs from its own constants rather than from
the file.

**Three divergences from D2, each with a reason found during verification:**

1. **A fifth case, `non_ascii_nfd`.** Carried over from Phase 1's finding: the spec names
   normalization as the step "three of four implementations would implement differently, or skip",
   and an all-ASCII vector set cannot falsify a normalizing implementation. Genuinely decomposed
   (`e` + U+0301), and now pinned as such on both sides — the emitter refuses to run if its source
   literal is ever NFC-normalized, and a test asserts the *committed bytes* are still decomposed.
   Without that pin, an editor's normalize-on-save would leave every test green while the case
   silently lost its only purpose.
2. **`why` is NOT emitted into the JSON.** D2 put it there. Every byte of that file is a cross-repo
   contract, so five paragraphs of English would have to be reproduced character-for-character,
   em-dashes included, by the runtime's Rust emitter — a maintenance tax with no machine consumer.
   The prose lives in the emitter source, where the person changing a case will read it.
3. **`ensure_ascii=True` is a decision with a disclosed cost, not an inherited convention.** The
   plan implied the existing file established it. It did not — that file has no non-ASCII at all
   (its one `\u0000` is a control char every JSON writer emits). Both settings round-trip the old
   bytes; only the new case differs. Escaping was kept because this artifact's *bytes* are the
   contract and ASCII-only bytes survive editors and transfer encodings unchanged — but serde_json
   has no `ensure_ascii`, so the runtime needs a custom `Formatter`. **Phase 5 must put this in
   front of them explicitly rather than let them meet it as a red gate.**

**Also fixed in verification:** the emitter reported infrastructure failures (malformed JSON, a
renamed `record_digest_v3`, an import error) as exit 1 — i.e. as *drift* — violating the
never-report-infra-as-a-verdict rule the repo already follows in
`scripts/probe_framework_coinstall.py`. All four exit paths are now proven: infra 2, drift 1, healthy
0. That included one subtle case: internal refusals originally raised `SystemExit`, which derives
from `BaseException` and so sailed straight past the handler meant to catch them.

**Depends on:** Phase 1.

**Delivers.** `scripts/emit_record_digest_v3_vectors.py` (committed emitter, loads `crypto.py`
standalone via `spec_from_file_location` exactly as the runtime's parity gate does — no `_gen`
import, no BUF token); `conformance/vectors.json` gains the D2 block; python conformance tests.

**Files.** `scripts/emit_record_digest_v3_vectors.py` (new), `conformance/vectors.json`,
`python/tests/test_conformance.py`.

**Approach.** The emitter holds the D2 case inputs, computes `ciphertext_digest_hex`,
`context/participation/policy_rules` digests from their documented label strings, calls
`record_digest_v3` per case, and splices the block after `record_digest_v2`. **Byte-preservation is
verified by execution, not assumed:** first check whether
`json.dumps(json.loads(file), indent=2) + "\n"` round-trips the current file byte-identically (the
`\x00` escape in the admission block suggests `ensure_ascii=True` matches); if yes, splice via
dict insertion + dump; if not, splice textually before the final `}` — whichever survives the
byte-diff test below. Idempotent: re-running on a file already carrying the block rewrites only the
block.

**Edge cases.** Case 4 vs case 3 digests must differ (None≠"" on the wire); context ≠ participation
values (slot-swap detectability); `null` rendering for absent tag 13.

**Acceptance criteria.** (1) `git diff conformance/vectors.json` shows ONLY added lines inside the
new block plus exactly one line where `record_digest_v2`'s closing `}` gains a comma — checkable by
a reviewer holding only the diff; (2) `python3 scripts/emit_record_digest_v3_vectors.py --check`
exits 0 (emitted block == committed block, byte-compare) and a pytest wraps that check so CI runs
it; (3) all four `digest_hex` values were produced by executing Phase 1's function (the emitter is
the proof — no hex literal in the diff originates outside it).

**Tests** (in `test_conformance.py`): `test_record_digest_v3_matches_reference_all_cases` (loop,
recompute, compare); `test_record_digest_v3_vector_none_and_empty_mode_differ` (cases 3 vs 4);
`test_v3_vectors_regenerate_byte_identically` (runs the emitter in-process, byte-compares the
block — the guard that makes hand-editing impossible); decoy: corrupt one input in-memory and
assert the recompute mismatches (proves the comparison is not vacuous).

**Docs.** Makes stale: `COMPATIBILITY.md` §7 ("New vectors must originate in the runtime" — now
version-block-origination is SDK-first per issue #56; Phase 5 rewrites it). Note: from the moment
this merges, seam-runtime's `sdk-digest-parity` on THEIR main is red until their Phase 1 lands
(their emitter lacks the block) — that is the documented lockstep design (issue #56 "Sequencing"),
but merge timing should be coordinated (Open question 3).

### Phase 3 — TypeScript `recordDigestV3`

**Status:** IMPLEMENTED — verification gate NOT closed (round cap fired; see `PROGRESS.md`) ·
**Depends on:** Phase 2 (consumes the committed vectors).

**Divergence from the plan, recorded.** The plan said "throw `Error`"; the delivered refusal is a
typed `RecordDigestStripError` carrying `field` and `wireTag`, mirroring Phase 1's Python twin (which
gained the same two attributes this phase, closing a parity gap the gate found). The plan also did
not anticipate input validation at all — it scoped Phase 3 as a transcription. Four verification
rounds turned that into the phase's largest sub-problem; see the Long-term posture note below and
`ASSUMPTIONS.md`'s entry "v3 validates every input; v2 deliberately still does not".

**Delivers.** `recordDigestV3` in `ts/src/crypto.ts` per D3/D4 (plus a bytes-opt helper beside
`optLE`, which takes `string`), reproduction + mutation tests.

**Files.** `ts/src/crypto.ts`, `ts/tests/conformance.test.ts`,
`ts/tests/record_digest_v3.test.ts` (new).

**Approach.** Transcribe from the spec in `recordDigestV2`'s style (`crypto.ts:299`): same
`frameLE`/`optLE`/`u32le`/`u64le` helpers, object parameter, `schemaVersion ?? 3`. Throw `Error`
with a strip-naming message on missing/wrong-length `contextDigest`/`participationDigest` and on a
present wrong-length `policyRulesDigest` — the TS type system requires the fields, but JS callers
are unchecked, so the runtime guard is load-bearing, not decorative. `export *` in `index.ts`
already surfaces it.

**Edge cases.** Same as Phase 1; additionally `sealedAt` as `number | bigint` (mirror v2's
handling); `undefined` vs `null` both mean absent for the three string optionals (mirror `optLE`).

**Acceptance criteria.** `npm test` green in `ts/`; every vector case reproduced; the mutation
suite would fail a formula with any one slot wrong (demonstrated by the swap/perturb assertions);
v2 tests untouched and green.

**Tests.** Conformance loop over `cases`; cases-3-vs-4 inequality; binds-every-field mutations
(including context/participation swap and tag-13 toggle); strip throws with distinct messages
(`assert.throws` with message regex); v2 KAT regression untouched.

**Docs.** None yet (Phase 5). Makes stale: nothing.

### Phase 4 — Rust: wire fields, `record_digest_v3`, version dispatch, distinct strip refusal

**Status:** DONE (verifier `PASS`, 1 round) · **Depends on:** Phase 2 (vectors); independent of Phase 3.

**Divergences from the plan, recorded.**

1. **Added a guard the plan did not anticipate: a covered record relabelled as v1.** The plan kept
   `schema_version < 2 ⇒ skip` unchanged, and that skip is a hole — rewrite a column, set
   `schema_version` to 1, and the record is exempted from the recompute entirely. It is the ONE
   downgrade direction the recompute cannot catch by construction (every other version is dispatched
   to a formula and fails the comparison; a downgrade *into* the skip means no comparison happens).
   Closed structurally: a payload declaring v1 while carrying `ciphertext_digest` or tags 11/12/13 is
   not a v1 record, because a genuine v1 payload has none of them. Each of the four columns is
   decoy-proven independently. Logged in `ASSUMPTIONS.md`.
2. **Added in-package unit tests for v3 in `verify.rs`** (`None` vs `Some("")`, tag-13 absent vs
   zeroed, the tag-11/12 slot binding, strip-vs-mismatch). The plan put the vector coverage in
   `tests/conformance.rs`, which is package-`exclude`d — so without these the *published* tarball
   would ship a v3 implementation whose distinguishing behaviour nothing in the package tests.
3. **Acceptance criterion (4) — "v2 KAT tests untouched in the diff" — could not hold literally.**
   `Decision` gained three fields, so both v2 test constructors had to name them. No v2 input or
   expectation changed, and `record_digest_v2` itself is byte-identical.
4. **The tag-10 strip message was reworded** ("A v2 record is required" → "Every covered record
   (schema_version >= 2)"). The plan said unchanged wording; that wording became false once the
   message became reachable from a v3 record.

**Delivers.** D5 in full: `wire.rs` tags 11/12/13 on both PB and JSON paths (planned with explicit
presence; **retracted in Phase 8** — singular, absence by length, on both paths);
`Decision` carrying the three `Option<Vec<u8>>`; `record_digest_v3(d: &Decision) -> Result<[u8;32],
String>` (or an enum-error equivalent — the `Err` carries the strip/malformed text) beside
`record_digest_v2` at `verify.rs:273`; the schema-version match in `verify_authenticity`
(`verify.rs:~343-393`); CLI usage text and the human report line updated
(`records recomputed: … (v2/v3 digest recompute)`); D6's `verify/tests/conformance.rs`; D7's
vendored spec + proto refresh.

**Files.** `verify/src/wire.rs`, `verify/src/verify.rs`, `verify/src/main.rs`,
`verify/tests/conformance.rs` (new), `verify/tests/authenticity.rs`, `verify/Cargo.toml`
(dev-dep already has `serde_json`; add package `exclude` per D6), `verify/docs/seam-event.v1.md`,
`verify/proto/seam/event/v1/seam_event.proto`.

**Approach.** Per D5. `record_digest_v2` is not modified in any way — the v3 function is a sibling
with its own `frame`/`opt`/`opt_bytes` closures (duplication is the safety property here; shared
helpers would put v2's frozen bytes behind a refactor surface). The strip/malformed/unknown-version
refusals return through the same `Err(String)` channel the tag-10 strip already uses, so the CLI
and `--json` shapes are untouched (exit 2, distinct text).

**Edge cases & failure modes.** `wire.rs`'s `with_identity()` (`:583-605`) re-encodes every event
through `DecisionSealedPb` to give it a canonical byte identity — deliberately, so the same event
arriving as JSON on a webhook and as protobuf on a relay collapses to one link instead of looking
like a forgery. **The three new fields must be carried there too.** If they are added to `Decision`
and to both parse arms but missed in `with_identity`, identity is computed over a payload with tags
11/12/13 stripped: two v3 records differing ONLY in `participation_digest` become the same event,
and the dedup that exists to prevent a false forgery alarm starts erasing evidence instead. This is
the one place in Phase 4 where an omission fails *silently* rather than loudly, so it gets its own
test (two v3 events differing only in tag 12 must have distinct identities). Beyond that: JSON
~~`context_digest: ""` (present-but-empty base64 ⇒
`Some(vec![])` ⇒ malformed-length refusal, NOT treated as absent, NOT a mismatch); PB absent vs
present-empty distinguished by `optional`;~~ **retracted (rule 5): `""` and missing are ONE state,
absent, on the JSON path exactly as on the wire — a strip refusal, not a malformed one;** v3 record with tag 10 missing ⇒ tag-10 strip error
(unchanged wording, now reachable from the v3 arm); mixed v2+v3 chain; v3 with tag 13 absent ⇒
green; `schema_version = 4` ⇒ unknown-version refusal (today it would mis-report as a rewrite —
this phase FIXES that misreport, and a test pins the fix); a v3 event lacking tag 19 `digest` ⇒
already `UNVERIFIABLE` at integrity, no invented pass (mirror the v2 comment at
`verify.rs:~372-377`).

**Acceptance criteria.** All falsifiable from diff + `cargo test` output: (1) every vector case
recomputed from `../conformance/vectors.json` inputs matches `digest_hex`; (2) the strip tests
assert the error text contains the field name + "strip" AND does NOT contain the mismatch wording
("does NOT match its own digest") — the distinctness requirement as a string-level assertion, both
directions; (3) the unknown-version test asserts the pre-fix misreport is gone (message contains
"newer than this verifier", not the rewrite text); (4) `record_digest_v2` KAT tests byte-identical
and untouched in the diff; (5) `cargo fmt --check`, `clippy -D warnings`, zero-Seam-crates gate all
green (no new dependencies at all); (6) `verify/docs/seam-event.v1.md` diff is exactly
runtime-spec-verbatim (reviewer can `diff` against the sibling).

**Tests.** `tests/conformance.rs` per D6 (fails, never skips, when the block is absent — proven by
running it against a doctored file in-test); unit tests in `verify.rs` mirroring v2's
(none-vs-empty for `mode`; tag-13 present-vs-absent); `tests/authenticity.rs` extensions built with
the existing `mutate_first_sealed` helper over synthesized v3 streams (constructed in-test as the
existing ones are — the runtime's v3 goldens do not exist yet and their arrival is their Phase 1):
green v3 chain under `--issuer`; strip tag 11 ⇒ exit 2 distinct text; strip tag 12 likewise;
rewrite `outcome` on v3 ⇒ mismatch text; `schema_version: 4` ⇒ refusal text; mixed v2/v3 green;
integrity-only (no `--issuer`) still passes a stripped stream (the refusal is design-a work, scoped
to `--issuer`, exactly as tag-10 strip is today). The wire-slot decoy: the vector-driven test
builds the JSON event from case inputs where context ≠ participation, so a tag-11/12 swap in
`wire.rs` mapping cannot cancel.

**Docs.** `main.rs` usage text; `verify/README.md` "what it verifies" (v2 → v2/v3, strip refusal
sentence). Makes stale: `COMPATIBILITY.md:183` ("every v2 `DECISION_SEALED` digest is recomputed")
— Phase 5.

### Phase 4.5 — take seam-runtime's vector bytes (unplanned; added 2026-08-24)

**Status:** DONE (2026-08-24). **Depends on:** Phases 1–4. **Not in the original plan** — it exists
because seam-runtime landed its side while Phases 3–4 were running here.

**Delivers.** `conformance/vectors.json` byte-identical to what
`cargo run -p seam-client --example conformance_vectors` emits in seam-runtime, so
`sdk-digest-parity` goes green and seam-runtime PR #432 can merge. Plus
`conformance/record_digest_v3_extended.json`, carrying the five cases Phase 2 designed, loaded by all
three SDK conformance suites alongside the shared file.

**Why not push this repo's shape upstream instead.** Three reasons, in order of weight. The gate is a
whole-file `diff -u`, so exactly one side can define the bytes; the runtime's two-block shape matches
what every other block in that file already does, where the `cases` array was the outlier; and their
emitter has already merged, so re-shaping it means reopening a landed PR to make a file cosmetically
different and no more correct. The digests were never in question — this repo's Python reproduces
both runtime blocks exactly, which is what four independent transcriptions agreeing actually means.

**What was checked before adopting, not after.** Every pre-existing block (`admission`, `tct`,
`chain_head_attestation`, `record_digest_v2`) compared structurally against `origin/main` and found
untouched — `record_digest_v2` byte-identity is the standing promise in issue #56, and "the diff
looks clean" is not how you keep it.

**Acceptance criteria.** `bash seam-runtime/scripts/sdk-digest-parity.sh <this checkout>` exits 0 with
both steps green (drift byte-identical; the Python implementation reproducing `record_digest_v2`,
`record_digest_v3` and `record_digest_v3_absent_policy`). All three SDK suites reproduce the union of
both files. A missing runtime block fails loudly in each language rather than silently shrinking the
case set.

**Tests.** Each language's loader gained a hard failure for a missing runtime block, each driven red
with a doctored document — the Rust one parametrized per block after a single-block guard would have
let the second disappear silently.

### Phase 5 — docs, decision record, and the cross-repo handshake

**Status:** DONE (2026-08-24). **Depends on:** Phases 1–4.

**Divergence from the plan, and it is the interesting one.** This phase was written expecting to
*tell* seam-runtime what the vectors are. By the time it ran, seam-runtime had already landed its
side (PR #432) and pinned the `record_digest_v3` signature on issue #56 — so the handshake inverted:
this repo verified it matched (it did, positionally, exactly) and adopted the runtime's vector bytes,
rather than publishing its own for them to converge on. The `ensure_ascii` ask survives, but as a
*proposal* attached to an extended vector file rather than as a cost imposed by a red gate.

**Coordination artifact delivered** in two parts, because a comment thread is where a durable ask
goes to die: the confirmation and timing note on
[seam-sdk#56](https://github.com/zer07labs/seam-sdk/issues/56#issuecomment-5403239868) (signature
match, both blocks reproduced, and an explicit "your gate stays red until this merges, don't re-run
it"), and the extended-cases proposal as a tracked issue,
[seam-runtime#433](https://github.com/zer07labs/seam-runtime/issues/433), carrying the `ensure_ascii`
cost and three options including declining.

`COMPATIBILITY.md` §7 was updated to record that the rule this plan proposed inverting held instead —
including the resolution (a separate file, never a block) so the next person who needs vector coverage
the shared file cannot carry does not re-derive it.

**Delivers.** All prose brought true in the same change-set that made it stale, plus the runtime
coordination artifact.

**Files.** `CHANGELOG.md` (Unreleased → Added: `record_digest_v3` ×3 languages + v3 vectors +
verifier v3 arm with distinct strip refusal; note the unknown-version behavior change in the
verifier — previously a misleading mismatch report); `COMPATIBILITY.md` (§5 covered list:
"every v2/v3 … recomputed; a v3 record stripped of tags 11/12 is refused distinctly"; §7 rewritten:
for a NEW `record_digest_vN` block the SDK commits first and the runtime's emitter converges — cite
issue #56; keep the old rule for all existing blocks); `verify/README.md` + `verify/DECISIONS.md`
(new D-0xx entry, earned per the existing protocol: the strip repro watched to fail — integrity
passes the stripped stream, `--issuer` refuses with the strip text, both transcripts in the entry);
`plans/README.md` (active table row).

**Cross-repo (sibling repos are READ-ONLY — this is an issue/comment, not an edit):** post a comment
on seam-runtime's B3 tracking (or file a small runtime issue if none is open for Phase 1) carrying:
(a) the exact committed v3 block bytes, (b) the D2 shape description + the per-version input mapping
their parity script needs (their Phase 1 owns the fix — the issue says so), (c) the note that our
verifier's report line/`--json` fields are unchanged so their differential harness needs no output
reshaping, only v3 stream coverage. This phase **blocks nothing here** but their Phase 1 **depends
on it**.

**Acceptance criteria.** `pytest python -q` green including `test_retracted_claims.py`,
`test_compatibility_citations_resolve.py`, `test_framing_rationale_is_documented.py` (the
doc-guard suite is the falsifier for this phase); every new `file:line` citation in
`COMPATIBILITY.md` resolves; CHANGELOG entry names the verifier behavior change explicitly.

**Docs.** This phase IS docs. `seam/docs` and `seam/CLAUDE.md`: **not affected** (no repo/edge/deploy
change; the cross-repo coupling doc lives in `COMPATIBILITY.md` §7 by precedent).

### Phase 6 — streamed-helper v3 arms (UNBLOCKED 2026-08-24)

**Status:** superseded by Phases 6a/6b below — split so Python and TypeScript each get their own
verification gate rather than sharing one. The blocker is cleared: seam-runtime B3 Phase 1 is merged
and `seam.event.v1` carrying `DecisionSealed` tags 11/12/13 is published to the BSR (module
`fb1a5dce9d044933a36c3c8cde959ff8`); `make generate` off the BSR now emits all three fields, verified
against the descriptor rather than assumed.

**Approach correction — the planned `HasField` check is not implementable, and was never right.**
This section originally specified "`HasField`/presence checks on tags 11/12". That is wrong, and the
generated stubs prove it: tags 10–13 are **singular** `bytes` (`has_presence=False`), so `HasField`
raises `ValueError` on them rather than answering. seam-runtime#435 — filed from this repo during
Phase 5 and closed 2026-08-25 — pinned the real rule in `docs/specs/seam-event.v1.md`
§"Presence on the wire — why tags 10–13 are not `optional`":

> A `DecisionSealed` scalar is `optional` **iff** its preimage slot is `opt(...)` **and** the empty
> value is inside its value domain. […] the digest slots (tags 10–13) exclude the empty value by
> domain, whether their slot is `opt`ed (13) or not (10–12).

and states the consumer rule as a **total** mapping: `len == 0` means absent on all four tags,
*however the bytes arose* — including an explicitly-encoded `0x6a 0x00` from a hostile producer,
which proto3 requires a decoder to accept. The spec names our exact situation:

> A consumer decoding through generated stubs therefore cannot ask a presence question of these four
> fields […] and does not need to: `len == 0` **is** the presence answer, by this rule.

So the v3 arms test `len == 0`, not presence. This is not a workaround for a stub limitation — it is
the contract, and the singular declaration is what makes a present-but-empty digest unrepresentable
by a conforming encoder in the first place. Recorded here rather than silently implemented, because
the plan said something false and a reader would otherwise trust it.

**Consequence for tag 13, which is the one that can bite.** Absent tag 13 is a *legitimate* state
(`opt(None)` — no policy bound, today's common case), so the arms must map `len == 0` → `None`/`null`
before calling the digest function. Passing the decoded `b""`/empty `Uint8Array` straight through
would frame `opt(Some(b""))` — five bytes where the sealer wrote one — and report a spurious mismatch
on a genuine record. Tags 11/12 need no such mapping: passing the empty value through is exactly what
makes `record_digest_v3` raise the typed strip error the spec demands.

---

### Phase 6a — Python streamed v3 arm

**Status:** DONE (2026-08-24, 1 verify round + 3 observations closed, Fable — the authenticity path
on a published contract). **Divergence, recorded:** the plan's `HasField` approach was replaced by the
spec's `len == 0` rule before any code was written — see the Phase 6 approach-correction above; that
is the phase's substantive divergence and it originated in a stale plan, not in implementation drift.

**Delivers.** `verify_streamed_record_digest` (`python/seam_sdk/admin.py:70`) dispatches on
`schema_version`: v2 keeps its current path byte-for-byte, v3 recomputes through `record_digest_v3`,
and the "newer than this SDK" refusal moves from `>= 3` to `>= 4`. Tags 11/12 pass through so the
crypto layer raises `RecordDigestStripError`; tag 13 maps `len == 0` → `None`. The docstring's
"only v2" claims are corrected in the same diff.

**Files.** `python/seam_sdk/admin.py`, `python/tests/test_streamed_decode.py`.

**Approach.** Keep the strip rule in exactly one place — `record_digest_v3` already refuses an absent
or wrong-length tag 11/12 with a typed error carrying `field`/`wire_tag`. The streamed helper adapts
the wire to that function; it does not re-implement the check. Rejected: duplicating the length
checks in the helper for an earlier error — it would be a second copy of a security rule that can
drift from the first, and the phase's whole point is that a strip is reported distinctly.

**Edge cases & failure modes.** A v3 record with tag 10 stripped (must stay `False`, the v2 rule,
not a v3 strip raise); an explicitly-encoded zero-length tag 13 (must verify green as `opt(None)`,
not raise, not mismatch); a wrong-length (31/33-byte) tag 11 (raises, per Open question 1); v4+
(refuses loudly); a v3 record whose payload was rewritten (plain `False`).

**Acceptance criteria.** A v3 streamed event built from the conformance vector verifies `True`; a
stripped tag 11 and a stripped tag 12 each raise `RecordDigestStripError` with the matching
`wire_tag`; a zero-length tag 13 verifies `True` and is byte-distinct from a 32-zero-byte tag 13; the
v4 refusal test is red before the dispatch change and green after; `pytest -q` green.

**Tests.** `python/tests/test_streamed_decode.py` — flip the existing v3-refused test to v4-refused,
plus green-v3, strip-11, strip-12, absent-13-green, explicit-empty-13-green, wrong-length-11, and a
rewritten-payload mismatch.

**Docs.** Deferred to Phase 7 (one CHANGELOG entry covering both languages).

---

### Phase 6b — TypeScript streamed v3 arm

**Status:** DONE (2026-08-24, 1 verify round + 2 observations closed, Fable — parity against the
6a reference was the gate's main task). **No divergence from the corrected plan.** The `?? null`
hazard the plan named was real and is the reason the tag-13 line is a length test; the verifier's
parity audit walked 16 input classes across both languages and found no behavioural asymmetry, only
two cosmetic diagnostic-wording differences forced by the two protobuf runtimes.

**Delivers.** The `verifyStreamedRecordDigest` twin (`ts/src/admin.ts:79`), same dispatch, same
`len === 0` rule, throwing the typed `RecordDigestStripError`. Docstring corrected likewise.

**Files.** `ts/src/admin.ts`, `ts/tests/streamed_decode.test.ts`.

**Approach.** Mirror 6a exactly, including which layer owns the refusal. Divergence between the two
helpers is the failure mode worth designing against — they answer the same authenticity question for
the same bytes, so a rule enforced in the Python helper and the TS crypto layer (or vice versa) would
be a parity gap no single-language test could see.

**Edge cases & failure modes.** As 6a, plus: `p.policyRulesDigest` is a `Uint8Array` that is empty
rather than `undefined` when absent, so the `?? null` idiom used for `mode`/`policyVersion` does
**not** work here and would silently frame `opt(Some(empty))`.

**Acceptance criteria.** The 6a test matrix, case for case, green in `ts/`; `npm test` and
`tsc --noEmit` green.

**Tests.** `ts/tests/streamed_decode.test.ts`, mirroring 6a's matrix one-for-one.

**Docs.** Deferred to Phase 7.

---

### Phase 7 — docs for the v3 arms, and two guard cleanups riding along

**Status:** DONE (2026-08-24, 2 verify rounds, Opus — docs + test logic, no boundary).
**Divergences, recorded.** (a) The citations rewrite found a **real pre-existing stale citation** the
old design was structurally unable to see: `COMPATIBILITY.md` cited `release-on-runtime.yml:120`
(`git push origin HEAD:main`) for a claim about the `go/vX.Y.Z` tag, six lines off, while the test's
own pin of 126 passed green — the test was validating its copy of the number, not the document.
(b) Four of the six needles were not unique (`npm.cloudsmith.io` occurs on four lines of
`publish.yml`), so they were lengthened; a whole-file search would have passed vacuously.
(c) Round 1 caught a heading this phase corrupted in `CHANGELOG.md` and one overstated claim.
(d) The verifier surfaced `verify/proto`'s tags 11/12/13 declared `optional`, contradicting the
contract — corrected here; the matching decoder bug it exposed became **Phase 8**, because it is a
behavioural fix and did not belong in a docs phase.

**Delivers.** (1) One CHANGELOG entry covering both v3 arms. (2) `release-on-runtime.yml:62` names
`scripts/test_release_gate_order.sh`, which does not exist — the guard is `scripts/test_release_gate.py`.
A comment pointing at a nonexistent guard is worse than no comment: it tells the next reader the
ordering is protected and gives them a filename that returns nothing when they check.
(3) `python/tests/test_compatibility_citations_resolve.py`'s `ANCHORED` table pins line numbers and
has needed repointing four times in one session — every repoint a chance to "fix" it by pointing at
the wrong line. It already searches a ±3-line window for a needle, so the line number carries no
information the needle does not; make it find the needle and drop the pin.

**Files.** `CHANGELOG.md`, `.github/workflows/release-on-runtime.yml`,
`python/tests/test_compatibility_citations_resolve.py`, `COMPATIBILITY.md` (only if the citation
format changes).

**Approach.** For (3), the check must stay a real check: searching the whole file for a needle that
appears many times would pass vacuously. Require the needle to be **unique** in the target file and
fail if it is absent *or* ambiguous — that is strictly stronger than the current window, since today
a needle occurring twice passes as long as one copy is near the pinned line.

**Edge cases & failure modes.** A needle that is genuinely non-unique (then it is a bad needle and
the test must say so, not silently pick the first); a citation whose target file was renamed;
`COMPATIBILITY.md` citing a line number in prose that a reader will still check by hand.

**Acceptance criteria.** The cleanup in (3) is demonstrated by deleting a cited line and watching the
test go red, and by duplicating a needle and watching it go red for ambiguity; `test_release_gate.py`
is named correctly and the file it names exists (already asserted by that suite's own
`test_every_repo_file_the_gate_reads_actually_exists` sibling logic); full `pytest -q` green.

**Tests.** The citations suite itself, driven red both ways before being trusted.

**Docs.** `CHANGELOG.md` as above.
---

## Cross-repo dependencies and blocks (explicit)

- **Nothing in Phases 1–5 requires any seam-runtime change.** Phase 5 files the informational
  comment their Phase 1 consumes.
- **seam-runtime B3 Phase 1** (their emitter + parity-script per-version inputs + their verifier's
  v3 arm) depends on our merged vectors; their main's `sdk-digest-parity` is red from our merge
  until theirs lands — by design, but see Open question 3.
- **Phase 6 here** is blocked on their Phase 1 + BSR push, and is deliberately severed from the
  issue-#56 deliverable so the lockstep never waits on codegen.

## Open questions (honest — the spec does not pin these for the OUTER digest)

1. **Present-but-wrong-length tags 11/12/13.** The spec fixes the values at 32 bytes but does not
   say what a verifier does with a present 31/33-byte value. This plan refuses as malformed
   (distinct text, exit 2) rather than framing-and-mismatching. If the runtime's Phase 1 chooses
   differently, the differential harness will surface it; candidate one-sentence spec clarification
   — file at seam-runtime if the reviewer agrees. NOT resolved by reading their code.
2. **JSON-projection field names for tags 11/12/13.** Inferred from the spec's column names
   (`context_digest`, `participation_digest`, `policy_rules_digest`) under the "field-for-field
   mapping" rule; the spec's `DECISION_SEALED` payload paragraph (`:253-262`) was not extended with
   the new columns' names. If the runtime's proto names differ, our JSON path silently reads absent
   ⇒ spurious strip refusals. Low risk, but it is a **spec gap worth a one-line fix** (add the three
   columns to the payload enumeration) — file at seam-runtime.
3. **Merge-timing of the runtime-main red window.** Our merge reddens `sdk-digest-parity` for every
   runtime PR until their Phase 1 merges. The issue accepts this; the courteous execution is to
   merge here when their Phase 1 PR is up and ready to take the diff. Coordination, not design.
4. **`records_recomputed` semantics widen** (v2-only → v2+v3) in the CLI report and `--json`. Field
   name kept for additive stability; if their differential harness asserts the v2-only meaning,
   their Phase 1 updates it (flagged in the Phase 5 comment).
5. **Emitter byte-splice fallback.** If `json.dumps(indent=2)` does not round-trip the current file
   byte-identically, the textual-splice fallback is used; either way the acceptance criterion is the
   byte-diff, so this is an implementation detail with an executable arbiter, not a risk.


---

### Phase 8 — the Rust verifier's tag-13 zero-length divergence

**Status:** DONE (2026-08-25, 2 verify rounds, Fable — a verdict change on the authenticity path).
**Divergences, recorded.** (a) The same wrong rule was found in the **JSON projection** too, asserted
by a test (`""` stays present-but-empty) that contradicted the spec's "missing/`\"\"` ⇔ absent
there too" — flipped, so wire and JSON consumers cannot disagree about absence on one record.
(b) The change turned out to have **three** consumer-visible effects, not one: the tag-13 fix, a
diagnostic move on tags 11/12 from MALFORMED to STRIP (same verdict; spec-sanctioned), and a
FAILED→VERIFIED flip in the v1-smuggling check for a zero-length column. All three are in the
CHANGELOG. (c) The vendored spec copy `verify/docs/seam-event.v1.md` was stale — missing the very
section every new comment cites — and was refreshed verbatim; its header now names the fact that
nothing enforces the verbatim claim.

**Why this exists.** Phase 7's re-verification found that `verify/src/wire.rs` declares tags 11/12/13
as prost `optional`, and still carries — as fact, in a doc comment — the "`optional` is load-bearing"
argument that seam-runtime#435 considered and rejected. That is not merely stale prose. prost decodes
an explicitly-encoded zero-length field as `Some(b"")`, so `v3_optional` refuses a zero-length **tag
13** as MALFORMED, where the spec's total mapping makes `len == 0` on tag 13 *absent and legitimate* —
the record must verify green. Python and TypeScript both implement the mapping as of Phases 6a/6b;
Rust does not, and `verify/` has no test for the case at all.

**Delivers.** Tags 11/12/13 declared singular in `verify/src/wire.rs`, the decoder mapping `len == 0`
to absent for all three, and the doc comment replaced with the rule the spec actually pins. A
zero-length tag 13 verifies green; a zero-length tag 11/12 still refuses as a strip.

**Files.** `verify/src/wire.rs`, `verify/src/verify.rs`, `verify/tests/` (a new case), `CHANGELOG.md`.

**Approach.** Make the Rust decoder agree with the other two implementations rather than making the
other two agree with it — the spec is explicit and the other two already match it. Rejected: leaving
Rust strict and documenting the divergence. A verifier that refuses a record the contract says is
valid is a false positive on the authenticity path, and "it refuses in the safe direction" is the
argument that keeps a wrong verifier alive.

**Edge cases & failure modes.** Zero-length tag 13 (must go from refused to green — the whole point);
zero-length tags 11/12 (must stay refused, and the refusal should read as a strip); omitted tag 13
(already green, must not regress); wrong-length tag 13 (must stay malformed); the v2 path (untouched).

**Acceptance criteria.** A crafted `0x6a 0x00` payload verifies green in Rust and produces the same
verdict as the Python and TS twins on identical bytes; the new test is red against the current
decoder and green after; `cargo test` and `cargo clippy -- -D warnings` clean; the three
implementations agree on every case in the v3 conformance corpus.

**Tests.** A wire-level test crafting an explicitly-encoded zero-length tag 13 (and 11/12), driven red
before the fix. This is the case the spec says a hostile producer can send, so it is exactly the case
a verifier must not get wrong.

**Docs.** The Phase 7 CHANGELOG bullet currently says the proto correction carries "no behavioural
change"; that becomes true only once this lands, so the bullet is corrected here.
