# Authorize D2 — `commit.policy_deny` in the verifier preimage table, seam-verify 0.8.0

Wave 2 of `seam-runtime/plans/scale-retention-authorize-waves.md`; ask in
`seam-runtime/plans/cross-repo/seam-sdk-authorize-records-and-chained-denials.md` (§ Sequencing, round 1);
issue seam-sdk#453 (the D2 bullet only — D3 and R5 are later waves). Runtime D2: seam-runtime#2105 @ `08503f90e`
(0.128.0).

## Why this must ship now

Runtime D3 switches commit-time refusals to a chained `AUDIT_ENTRY` with action `commit.policy_deny`. A
verifier that does not know the action reads it as uncovered and, under `--issuer`, refuses the whole stream
(runtime `crates/seam-verify/src/main.rs:1599-1610`). So the row must be **published** before D3 deploys.

## Scope: "all languages" is one lane

Only `verify/` (Rust) carries a (b′) preimage table. Python, TS, Go, Java and Kotlin recompute no audit entry
digest (`grep -r "seam.audit.denial" --exclude-dir=verify` is empty). The D3 items (drop `POLICY_DENIED` from
`ADVISORY_KINDS`/`KNOWN_KINDS`, codec removal) and R5 (`call_sig` v4, `RefusalUnrecorded`) are **not** in this
wave.

## Phase 1 — row, vector, spec re-pin, release (one PR)  · Status: DONE

- `verify/src/entry.rs`: `commit.policy_deny` in the `seam.audit.denial.v1` domain; `Confidential` in
  `audit_classification`; unit assert. Mirrors runtime `crates/seam-verify/src/entry.rs` @ `08503f90e`.
- `verify/docs/seam-event.v1.md`: re-vendor @ `08503f90e` (adds the (b′) row + reason-form paragraph). The
  `the_tables_are_the_vendored_spec_tables` tripwire then requires the code row.
- `verify/docs/evidence-bundle.v1.md`: re-vendor @ `08503f90e` (runtime E0 #2101 wording; the currency gate
  is red on main without it — a blocker for this PR's CI).
- Vector: re-capture runtime `entry_recompute.rs` `stream()` @ `08503f90e` (a clean `git archive` export, a
  throw-away capture test never committed; never re-derived) as a SECOND pinned golden,
  `verify/tests/goldens/entry_domains.d2.jsonl`. `entry_domains.jsonl` stays byte-for-byte: the runtime stream no
  longer writes `ciphertext_evicted` (E0), and that still-accepted domain keeps its vector (DECISIONS
  2026-11-26). New tests mirror runtime `a_tampered_or_stripped_policy_denial_fails`: the pinned reason form, a
  rewritten staged `policy_version` or `mode` or a relabelled classification is `ENTRY REWRITE`, and a
  stripped checksum is `UNCHAINED EVENT`. Plus `--issuer` green over the whole D2 stream, with 0 uncovered.
- Release: `verify/Cargo.toml` 0.7.1 → **0.8.0**. Main also carries unpublished breaking verifier changes
  since 0.7.1 (#438 S9-O7, #441 S10-O1, #445 S-4, #448 S-3), so a minor, not a patch. CHANGELOG +
  COMPATIBILITY note. After merge, dispatch `publish.yml` (`publish-verify` → Cloudsmith internal; the
  verifier is internal-only — `scripts/promote-to-partner.sh` allowlist).

Acceptance: `cargo test` / `clippy -D warnings` / `fmt --check` in `verify/`; `check_vendored_spec.py` OK;
full Python suite (citation tests); `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` exit 0; `cargo publish
--dry-run` clean; `seam-verify` 0.8.0 visible on Cloudsmith internal after dispatch.
