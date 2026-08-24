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
