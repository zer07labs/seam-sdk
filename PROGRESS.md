# PROGRESS — `plans/record-digest-v3.md`

Checkpoint trail and repo map for the `record_digest_v3` workstream (issue #56, B3 Phase 2).
`/implement` writes a block per phase; a resumed run reads this instead of re-scanning the repo.

**Plan:** [`plans/record-digest-v3.md`](plans/record-digest-v3.md) — 6 phases (Phase 6 BLOCKED on
seam-runtime B3 Phase 1 + BSR push).
**Hard constraint:** clean-room — `../seam-runtime/crates/**` is NEVER read. Spec + runtime plan +
runtime gate script are the only permitted sibling reads.

> The previous occupant of this file tracked `plans/close-out-w1-w7-loose-ends.md`, which was
> delivered (PR #53) and archived on 2026-08-24 (PR #57). Its checkpoint trail lives in that PR's
> history; nothing here carries over.

## Repo map

| Path | Purpose / relevance |
|---|---|
| `python/seam_sdk/crypto.py:343-384` | `_frame`/`_opt` helpers and `record_digest_v2` (`:351`). Phase 1 adds `record_digest_v3` + `_opt_bytes` beside them. Function name is resolved EXACTLY by the runtime's parity gate. |
| `python/seam_sdk/__init__.py:35,86` | `record_digest_v2` export points; Phase 1 mirrors for v3. |
| `python/seam_sdk/admin.py:70` | `verify_streamed_record_digest` — refuses `schema_version != 2` with `ValueError`. Phase 6 ONLY; untouched in Phases 1–5. |
| `python/tests/test_streamed_decode.py:85` | Pins v3 ⇒ `ValueError` on the streamed helper. Must stay green through Phase 5; flips to v4 in Phase 6. |
| `python/tests/test_conformance.py` | Vector consumption + the binds-every-field test pattern Phases 1–3 copy. Phase 2 extends. |
| `scripts/emit_record_digest_v3_vectors.py` | Phase 2 creates — the committed emitter; a pytest byte-compares its output against the committed block. |
| `conformance/vectors.json` | Keys: `_comment`, `admission`, `tct`, `chain_head_attestation`, `record_digest_v2` (single `{inputs, digest_hex}` object). Phase 2 appends `record_digest_v3: {cases:[…4 cases…]}`; ONLY allowed foreign diff line: the v2 block's closing `}` gains a comma. |
| `ts/src/crypto.ts:272-330` | `frameLE`/`optLE`/`u32le`/`u64le` and `recordDigestV2` (`:299`, object param). Phase 3 adds `recordDigestV3` + bytes-opt helper. `export *` via `ts/src/index.ts`. |
| `ts/tests/conformance.test.ts` | Reads `../../conformance/vectors.json`. Phase 3 extends. |
| `ts/src/admin.ts:79-94` | `verifyStreamedRecordDigest` — distinct `<2` / `>2` refusals already. Phase 6 only. |
| `verify/src/verify.rs:273-299` | `record_digest_v2` (private, local `frame`/`opt` closures). Phase 4 adds the v3 sibling. |
| `verify/src/verify.rs:~343-393` | `verify_authenticity`'s recompute loop: `schema_version < 2 ⇒ skip; else v2` — TODAY misreports a v3 record as a payload rewrite. Phase 4 replaces with the 1/2/3/≥4 match; tag-10 strip and mismatch error texts live here and are the wording precedents. |
| `verify/src/wire.rs:132-155` | `DecisionSealedPb` tags 1–10; tag 10 is NON-optional (absent==empty — fine for tag 10's non-empty check, NOT for 11/12). Phase 4 adds tags 11/12/13 as `optional bytes`. |
| `verify/src/wire.rs:261-283` | `DecisionSealedJson` (base64/`Option`); Phase 4 adds three `Option<String>` fields. `Decision` struct at `:330`; both `Event::parse` arms map payloads. |
| `verify/src/main.rs` | CLI. Exit contract 0/1/2; `fail()` banners; `--json` = `{"verified":false,"error":…}`. Phase 4 updates usage text + report line only — NO new exit code, NO new JSON field. |
| `verify/tests/authenticity.rs` | `mutate_first_sealed` helper + synthesized-stream pattern for the Phase 4 strip/rewrite/unknown-version/mixed-chain tests. Goldens in `verify/tests/goldens/` are v2-era; v3 streams are synthesized in-test. |
| `verify/tests/conformance.rs` | Phase 4 creates — reads `../conformance/vectors.json` via `CARGO_MANIFEST_DIR`; FAILS (never skips) when block missing; listed in Cargo.toml package `exclude`. |
| `verify/docs/seam-event.v1.md` | STALE vendored spec — no v3 section (its §Record digest at `:356` has v2/v1 only). Phase 4 refreshes verbatim from the runtime spec. |
| `verify/proto/seam/event/v1/seam_event.proto:186-201` | Vendored `DecisionSealed`, tags 1–10. Phase 4 adds `optional bytes` 11/12/13 transcribed from the spec. |
| `verify/Cargo.toml` | Empty `[workspace]` (standalone build — keep); `publish = ["zer07labs"]`; MSRV 1.85 derived. No new dependencies allowed (CI gates zero Seam crates). |
| `CHANGELOG.md`, `COMPATIBILITY.md` (§5, §7), `verify/README.md`, `verify/DECISIONS.md`, `plans/README.md` | Phase 5. §7's "new vectors must originate in the runtime" is inverted for NEW version blocks by issue #56 — rewrite with citation. Doc-guard tests: `test_retracted_claims.py`, `test_compatibility_citations_resolve.py`, `test_framing_rationale_is_documented.py`. |
| `.github/workflows/ci.yml` | No new **jobs** needed — `python`/`typescript`/`verify` already run the suites Phases 1–4 extend. Phase 1 did touch the credential-free `workflow-guards` lane (it installs `cryptography` now, because the seam-sdk#54 import-light guard was widened to cover `crypto.py`), and `scripts/test_ci_gate.py` asserts that install list. |

### Sibling repos (read-only — referenced, never written; `crates/**` NEVER read)

| Path | Why it matters |
|---|---|
| `../seam-runtime/docs/specs/seam-event.v1.md:372-660` | THE input. v3 formula `:385-399`; slots `:401`; raw-UTF-8 `:410`; None≠""≠[] `:570`; strip semantics `:594`; v2 `:621`; v1 `:641`; never-silently-green `:648`. |
| `../seam-runtime/plans/b3-digest-v3.md` | Phase 2 = this work; merge-order contract; "do not share code with Phase 1". |
| `../seam-runtime/scripts/sdk-digest-parity.sh` | Gate mechanics (no digest code): byte-diffs the WHOLE `vectors.json` vs their emitter, then loads `crypto.py` standalone and calls discovered `record_digest_v*` functions — currently with the fixed v2 ten-tuple (their Phase 1 fixes; our `cases` shape is designed for that fix). |

## Phase log

### Phase 1 — Python `record_digest_v3` · **PASS** · 2026-08-24

- **Verifier:** Fable, 1 round (crypto formula on a cross-repo contract). 6 findings, all minor,
  all closed; the transcription itself was independently re-derived and matched on 51 cases.
- **Files:** `python/seam_sdk/crypto.py` (+`record_digest_v3`, `RecordDigestStripError`,
  `_v3_required`, `_opt_bytes` — additions only, zero removed lines), `python/seam_sdk/__init__.py`,
  `python/tests/test_record_digest_v3.py` (new, 45 tests),
  `python/tests/test_errors_is_import_light.py` (widened to cover `crypto.py`),
  `scripts/test_ci_gate.py`, `.github/workflows/ci.yml` (credential-free lane installs
  `cryptography`).
- **Decoys driven red:** slot 10/11 swap · frame↔opt both directions · append-after-`schema_version`
  · default-a-missing-digest · big-endian length prefix · le32 `sealed_at` · opted `schema_version`
  · v2-suffixed domain · dropped `opt(supersedes)` · UTF-16 codec · `.encode("ascii")` ·
  NFC-normalize · plain `ValueError` for a strip · unchecked lengths · swapped tag in the message.
  Plus, on the widened #54 guard: `from .errors import` in `crypto.py`, absolute package import,
  new third-party dep, renamed `record_digest_v*`.
- **Watch out:** stale `__pycache__` gave two false negatives during mutation testing (the `.pyc`
  records source mtime at second granularity, so an edit inside the same second is not seen). Clear
  `__pycache__` BEFORE each mutant run, not after.
- **Suite:** 328 passed / 17 skipped · ruff clean · ci-gate 13 · credential-free lane 26 passed.
- **Next:** Phase 2 — the machine-emitted v3 vectors. Add a non-ASCII case per Phase 1's finding.

### Phase 3 — TypeScript `recordDigestV3` · **GATE NOT CLOSED (round cap fired)** · 2026-08-24

- **Verifier:** Fable, **4 rounds** — one more than `/implement`'s cap allows, which is why this phase
  stops here for a human call rather than continuing. Round 1 `PASS` (5 advisories), rounds 2/3/4
  `GAPS`. **No gap item ever survived two consecutive rounds** — each was confirmed closed by the next
  round — so this is convergence, not oscillation. But four rounds is itself the signal the cap
  exists to surface.
- **What each round found** (all confirmed by execution, not argued):
  1. Five silent-coercion paths in `recordDigestV3`; transcription itself independently re-derived
     from the spec and correct on all 5 vector cases.
  2. The tag-11/12 coercion fix left **tag 13** with the identical hole, and the test parametrized
     only 11/12. Junk as `policyRulesDigest` produced a digest byte-identical to a legitimate
     all-zeros one. Plus: Python measured `memoryview` with `len()` (elements), not `nbytes`.
  3. `v3Uint` fell through to `BigInt(value)`, which coerces `"5"`, `""`→`0n`, `true`, `[5]`.
     Sharpest: **proto3 JSON renders int64 as a string**, so `sealedAt: "1700000000000"` produced the
     legitimate baseline digest exactly.
  4. A **genuine `Uint8Array` with a shadowed `length`**: `frameLE` wrote a prefix of 32 from the
     property while `concat`'s `set` copied the internal `[[ArrayLength]]` of 0 — a length prefix
     that lies about its own content, from inside a right-typed object. No type check could catch it.
- **The through-line.** Every one of these is the same defect: not a mismatch (which the caller's
  comparison catches) but an **alias** onto a digest a legitimate caller also produces (which nothing
  catches). Rounds 2–4 each closed one instance; round 4's response closed the class instead —
  `asBytes` now reads byte views through `%TypedArray%.prototype`'s internal-slot accessors, and both
  languages carry a **wrong-kind corpus test** driving every parameter with values of every other
  kind, with a completeness guard so a new parameter cannot be silently exempt.
- **Files:** `ts/src/crypto.ts` (`recordDigestV3`, `RecordDigestStripError`, `asBytes`,
  `v3SubDigest`, `v3Text`, `v3Uint`, `optBytesLE`, `hasLoneSurrogate` extracted from the JCS path),
  `ts/tests/record_digest_v3.test.ts` (new), `ts/tests/conformance.test.ts`,
  `python/seam_sdk/crypto.py` (`_as_bytes`, `_v3_sub_digest`, `_v3_text`, `_v3_uint`, `_v3_enc`,
  `_v3_opt_text`; `RecordDigestStripError` gained `field`/`wire_tag`),
  `python/tests/test_record_digest_v3.py`, `ASSUMPTIONS.md`, `plans/record-digest-v3.md`.
- **v2 is provably untouched:** `record_digest_v2` and `recordDigestV2` extract byte-identical to
  `HEAD` in both languages (asserted mechanically, not by reading the diff). `conformance/vectors.json`
  unmodified this phase.
- **Decoys driven red:** 19 in TS (slot 10/11 swap · tag-13 `opt`→`frame` · slots appended after
  `schema_version` · v2 domain suffix · dropped `opt(supersedes)` · mode `opt`→`frame` ·
  `schemaVersion` default 2 · NFC normalize · tags 11/12 made optional · tag 13 made mandatory ·
  dropping each of the byte-ness, length, surrogate, string-type, uint-range, safe-integer and
  element-size checks · plain `Error` for a strip · mismatch vocabulary in a strip message ·
  restoring the `instanceof` fast path that caused round 4's hole); 6 in Python. The corpus test was
  separately shown to catch three historical holes on its own.
- **Suite:** Python 392 passed / 17 skipped · ruff check + format clean · TS `tsc --noEmit` clean,
  96 tests / 86 pass / 0 fail / 10 skipped.
- **Open, and why it needs a human:** the round-4 fix (internal-slot reads in TS; `str.encode`
  bypassing subclass overrides in Python) went in AFTER the last independent review. I drove both red
  by decoy, but no fresh agent has reviewed them. The real question underneath is scope, not
  correctness — see the report.
- **Next:** Phase 4 (Rust), NOT started. One hazard already recorded in its plan section:
  `wire.rs`'s `with_identity()` must carry tags 11/12/13, or two v3 records differing only in tag 12
  collapse to one event identity — the single Phase 4 omission that fails silently.

### Phase 4 — Rust: wire fields, `record_digest_v3`, version dispatch, strip refusal · **PASS** · 2026-08-24

- **Verifier:** Fable, 1 round, `PASS` with 5 non-blocking observations (4 acted on, 1 recorded).
  Fable tier because this is the riskiest phase in the plan: it parses UNTRUSTED wire bytes, changes a
  published wire contract, and its output is what an auditor acts on.
- **Files:** `verify/src/wire.rs` (tags 11/12/13 on `DecisionSealedPb` as `optional bytes`, on
  `DecisionSealedJson` as base64 `Option<String>`, on `Decision` as `Option<Vec<u8>>`; both parse arms;
  `with_identity`), `verify/src/verify.rs` (`V3_DIGEST_LEN`, `v3_required`, `v3_optional`,
  `record_digest_v3`, the schema-version dispatch, the v1-downgrade guard, 5 new unit tests),
  `verify/src/main.rs`, `verify/src/lib.rs`, `verify/README.md`, `verify/Cargo.toml`,
  `verify/tests/conformance.rs` (new), `verify/tests/authenticity.rs` (+8 tests),
  `verify/proto/seam/event/v1/seam_event.proto`, `verify/docs/seam-event.v1.md` (verbatim refresh).
- **`record_digest_v2` untouched.** Its two unit-test constructors gained three `None` fields because
  the struct did; no v2 input or expectation changed. Existing goldens still verify, which is also the
  proof that a v2 record's wire IDENTITY is unchanged (prost emits nothing for an absent `optional`).
- **Decoys driven red: 20.** slot 10/11 swap · tag-13 `opt`→`frame` · slots appended after
  `schema_version` · v2 domain suffix · dropped `opt(supersedes)` · mode `opt`→`frame` · big-endian
  length · defaulting a stripped sub-digest to empty · falling back to v2 for a v3 record · skipping
  unknown versions · dropping the 32-byte length check · mismatch vocabulary in a strip message ·
  tag 11/12 swap on the JSON arm · tag 11/12 swap on the PROTOBUF arm · dropping the columns from
  `with_identity` · collapsing absent-into-empty on the JSON arm · re-opening the v1 downgrade hole ·
  and the downgrade guard for each of tags 10/11/12/13 independently.
- **Three of my own tests were caught being vacuous, by decoys rather than by reading:**
  1. The protobuf parse arm had **no test at all** — every stream-level test synthesizes the JSON
     projection, so a swapped PB mapping would have shipped. Fixed with a `wire.rs` unit test asserting
     each tag lands in the slot its number names, on both transports.
  2. The `with_identity` test was vacuous **twice**: first the two events differed in `seq`/
     `prev_checksum`; then, after a fix, in `digest`/`checksum` — which are themselves part of the
     identity projection. Neither version could ever have failed. Now the two lines are identical in
     every identity-bearing field, so the payload column is the only discriminator.
  3. The v1-downgrade test passed with a decoy that guarded only on tag 10, because it kept all four
     columns present at once. Now parametrized per column, each with the other three removed.
- **Verifier observations acted on:** a literal NUL byte in `plans/record-digest-v3.md` (the file read
  as binary to `file` and `grep`); missing in-package v3 unit tests, which mattered because
  `tests/conformance.rs` is package-`exclude`d; the tag-10 strip message still saying "v2" under a v3
  header; and the v1-downgrade shape, which the verifier suggested documenting and which I closed
  instead. Recorded, not fixed: `frame`'s `len() as u32` truncation above 4 GiB, which mirrors v2.
- **Suite:** `cargo test` 62 passing, 0 failing · `cargo fmt --check` clean · `cargo clippy
  --all-targets -- -D warnings` clean · `cargo tree -e normal | grep seam` shows only `seam-verify`
  itself (the zero-Seam-dependency claim holds). Python 393 passed / 17 skipped; TS 96 tests / 86 pass.
- **Vendored spec refreshed VERBATIM** from `seam-runtime@0b62cb7`: `diff <(tail -n +12
  verify/docs/seam-event.v1.md) ../seam-runtime/docs/specs/seam-event.v1.md` is empty, which is a
  checkable claim a reviewer can re-run. It was stale in a way that mattered — it carried no
  §Record digest (v3) at all while `verify.rs` implements it.
- **Next:** Phase 5 — see below; overtaken by seam-runtime landing its side first.

## 2026-08-24 — Phase 4.5 (unplanned) + Phase 5 · verifier tier: Fable (cross-repo contract file)

**What forced Phase 4.5.** seam-runtime landed PR #432 while Phases 3–4 ran here, and posted the
exact `record_digest_v3` signature its parity gate calls on issue #56. Two facts had to be
established before anything else, and both were, by execution rather than by reading:

1. **The signature matches**, positionally and exactly — `python/seam_sdk/crypto.py`'s
   `record_digest_v3` takes their thirteen arguments in their order. No adaptation needed on either
   side.
2. **The formulas agree.** This repo's Python reproduces *their* two emitted vector blocks
   byte-for-byte, including the `opt(None)` vs `opt(Some(b""))` case that is the whole reason they
   ship two blocks. Four independent transcriptions from the same spec, agreeing.

**What did not match: the file shape.** Phase 2 emitted one `record_digest_v3` block holding a
`cases` array; seam-runtime emits `record_digest_v3` and `record_digest_v3_absent_policy`, one
`{inputs, digest_hex}` each. The gate is a whole-file `diff -u`, so exactly one side defines the
bytes. Took theirs verbatim — their shape is what every other block in that file already uses, and
the `cases` array was the outlier. Phase 2's premise (this repo merges first, so it defines the new
block) was wrong, and `COMPATIBILITY.md` §7 already said so; §7 now records that it was tested and
held.

**Coverage kept rather than dropped.** Phase 2's five cases moved to
`conformance/record_digest_v3_extended.json` — they pin `mode: ""` vs `mode: null` and decomposed
non-ASCII, which two fixtures cannot express. All three SDK suites now load the union of both files,
so the runtime's own vectors get the same scrutiny as this repo's. The extended file is invisible to
the parity gate by construction.

- **Verified against the real gate, not a simulation:** `bash ../seam-runtime/scripts/
  sdk-digest-parity.sh <this checkout>` exits 0 — drift byte-identical, and all three digest blocks
  reproduced by this repo's Python.
- **v2 byte-identity re-proven mechanically** after the reshape: every pre-existing block compared
  against `origin/main` structurally, all unchanged; the only delta is the two added blocks.
- **New guards, each driven red with a decoy:** a missing runtime block now fails loudly in Python,
  TypeScript and Rust rather than silently shrinking the case set. The Rust guard is parametrized per
  block — a single-block version would have let the second disappear unnoticed, the same hole the
  Phase 4 downgrade test had.

**Phase 5 (docs).** `CHANGELOG.md` (themed Added/Changed sections, including the two verifier
behavior changes — the unimplemented-`schema_version` refusal and the v1 downgrade guard — stated so
a reader can tell no previously-green stream turns red); `COMPATIBILITY.md` §5 (v3 recompute + the
three distinct refusals, citation resolving to `verify/src/verify.rs:579`) and §7 (the rule held;
the separate-file resolution recorded); `verify/DECISIONS.md` **D-035**, earned per the existing
protocol — the strip repro watched to fail through the shipped binary against a stream built outside
the Rust harness, with the transcript in the entry; `plans/README.md` active row; `plans/record-
digest-v3.md` Phase 2 marked superseded-in-part, Phase 4.5 added, Phase 5 DONE.

- **Suite:** Rust 62 passing / 0 failing, fmt + clippy clean, `cargo tree` still zero Seam crates ·
  Python 396 passed / 17 skipped, ruff clean · TS 97 tests / 87 pass / 0 fail / 10 skipped ·
  `tsc --noEmit` clean.
- **Handshake delivered** (it was the one Phase 5 deliverable the verifier caught still outstanding
  while the phase was marked DONE): seam-sdk#56 comment 5403239868 confirms the signature match, both
  blocks reproduced, and states plainly that their gate stays red until this merges; seam-runtime#433
  carries the extended-cases proposal with the `ensure_ascii` / custom-`Formatter` cost and three
  options, one of them declining.
**Verify round 1 — Fable — GAPS (2 items), both closed:** (1) this entry claimed 393 Python tests
where the real figure is 394; (2) Phase 5 was marked DONE while its own listed cross-repo deliverable
was undelivered — closed by delivering it, not by relabelling the status. Two observations were also
acted on rather than filed: the CHANGELOG's "no previously-green stream turns red" had one
constructible counterexample (`schema_version > 3` carrying no event digest — the version refusal now
runs before the digest-presence check), and the missing-block guards were only test-pinned in Rust.
Python and TypeScript now carry committed guard-the-guard tests too, each driven red by softening the
guard, so all three languages hold the same standard rather than two of them resting on a dev-time
check nobody can re-run. The verifier reproduced every test claim, the parity gate, and the v2
byte-identity comparison independently. (Round 1 was interrupted by a model quota after it had read
the diff; resumed from transcript rather than restarted.)

**Verify round 2 — Fable — GAPS (1 item), closed:** the suite figures on this very line were stale
again, because the three guard tests round 1 asked for moved them after the line was written. Third
occurrence of one class of error — a hand-maintained count that goes stale the moment the thing it
counts changes — so the numbers here are now written first and re-run afterwards, which is the only
ordering that can catch it. Everything else round 2 checked came back closed, and it re-derived
rather than trusted: it softened each new Python and TypeScript guard itself and watched them go red,
confirmed `loadV3Cases()`'s defaulted parameters leave the real module-load path armed, read both
cross-repo artifacts and matched every claim the plan makes about them against what they actually
say, resolved `verify/src/verify.rs:545` to the character, and confirmed against `origin/main` that a
v4 record which ALSO stripped tag 10 was already red — so the CHANGELOG's "one previously-green
shape" survives that subset exactly.

- **Next:** `/reconcile` the `ASSUMPTIONS.md` entries tagged to this plan, then `/ship` with the
  pre-merge pause (cumulative diff is well past the >500-line / >15-file threshold and touches a
  public contract).
- pushed feat/record-digest-v3 32292d8
- PR #58 opened: https://github.com/zer07labs/seam-sdk/pull/58

## 2026-08-24 — /reconcile (delegated to Fable by the owner) + ship

All four `ASSUMPTIONS.md` entries tagged to this plan came back **CONFIRMED**; none blocked the
merge. Recorded in `DECISIONS.md`. The reviewer verified each against code, spec and tests rather
than against the entries' own reasoning — which mattered, because it caught two overstatements in
the Phase 3 entry that I had written and would otherwise have been recorded as settled fact:

1. **The alias argument was over-generalized.** It is TypeScript-specific — a 32-character string
   frames as 32 zero bytes there, but the same input *raises* in Python. Python's validation still
   earns its place, by a different route: v2 accepts a `memoryview(array("I", [0]*32))` and frames a
   prefix claiming 32 while hashing 128 bytes.
2. **"Every such digest was wrong, so no correct caller breaks" was too strong.** A proto3-JSON
   int64-as-string coerced correctly through `BigInt` before and is now refused. The trade is still
   right — accepting strings reopens `BigInt("")→0n` — but the justification does not extend that
   far.

Both corrected in `ASSUMPTIONS.md` in place, and `DECISIONS.md` records the corrected reasoning
rather than the entry's. The reviewer also overrode my own recommendation on entry 4: I proposed
deferring the extended-vector-file split until seam-runtime answers #433, and it confirmed instead,
on the grounds that all three of #433's options leave the current arrangement correct, so nothing
actually waits on their call.

- **Ship:** commit `32292d8`, pushed `feat/record-digest-v3`, PR
  [#58](https://github.com/zer07labs/seam-sdk/pull/58). CI fully green — every language suite, both
  `verify` jobs including the MSRV build, guards, preflight, version lockstep, the framework probe,
  and all five CodeQL analyzers. The live `seam-grpc` integration job SKIPPED (no credentials in
  CI) — a genuine skip, not a pass. `mergeable=MERGEABLE state=CLEAN`.
- **Untracked `python/uv.lock`** deliberately left unstaged, as throughout this plan.

