# Plan — seam-sdk#399: runtime 0.105.0 option-selection surface (wave 2026-11-21 W5)

Branch `feat/399-option-selection-0105` off `c43a8cd` (v0.104.0), worktree `seam-sdk-w5-399`. One PR.

## Analysis (anchors at c43a8cd; runtime origin/main 8034af2d)

- Runtime #1834 (5728621a) changes `seam.api.v1` by exactly two things: `optional SelectionView selection = 8`
  on `SessionStep`, and `message SelectionView { bool has_winner = 1; string winner_proposal_id = 2; }`
  (seam.proto:1127-1139). `seam.event.v1` is untouched. 0.106.0 adds no api/event proto change.
- The PROPOSAL kind, `Commitment.selection = 12`, the selection digest, the `0x04` trailer and the
  `selection_rule_v1` vectors landed at 0.90.0 (S1) and are byte-identical to the runtime fixtures
  (`conformance/selection_rule_v1_vectors.json`, `commitment_digest_v5_*`). #1834 changed no fixture.
- All six ports already implement the framing, `decide`, `verifySelection`, the content-digest link,
  principal binding and the named tamper results (`selection_winner_mismatch`,
  `selection_content_link_mismatch`), and test every vector: Rust `verify/src/selection.rs`,
  `verify/tests/selection_vectors.rs`; Python `crypto.py` + `tests/test_selection_rule_v1.py`;
  TS `ts/tests/selection_v1.test.ts`; Go `go/crypto/selection*.go`; Java/Kotlin `SelectionV1Test`.
  So #399's verifier asks are met on main; this PR records that and closes the issue.
- Contract gate (`STREAM=1 EVENTS=1 ./scripts/check-contract.sh`) exits 6 on fresh BSR stubs:
  `SelectionView/has_winner`, `SelectionView/winner_proposal_id`, `SessionStep/selection` not in
  `contract/field-manifest.txt`. That is why the 0.105.0 / 0.106.0 dispatches were refused (#400, #401).
- Hand-written clients return the generated `SessionStep` unchanged (Python `client.py`/`aio.py`
  `-> pb.SessionStep`; TS `client.ts`). Go/Java/Kotlin have no session client. Precedent:
  DECISIONS 2026-11-19 `decided_value` — carried through the stubs, no wrapper.
- Release: `scripts/release_pending.py:111-120` refuses #400 (0.106.0 superseded it); #401 fires on
  green main (`:151-165`). The SDK release this ships in is **0.106.0**; 0.105.0 is never published.

## Phase 1 — carry the live selection view (simple)  Status: TODO
- Decision (DECISIONS.md): carry `SessionStep.selection` through the stubs, no wrapper; presence
  means "selection session", never "threshold met"; not sealed, not verifier input.
- Tests: Python (sync + aio) and TS pin that a step's `selection` presence, `has_winner` and
  `winner_proposal_id` survive the hand-written wrappers, and absence stays distinct.
- `scripts/check-contract.sh --write-manifest` after the decision; gate exits 0.

## Phase 2 — docs (simple)  Status: TODO
- CHANGELOG Unreleased: the field; no digest/vector change at 0.105.0; v0.105.0 not published.
- COMPATIBILITY: pairing note — SDK 0.106.0 pairs with runtime 0.106.0; 0.105.0 skipped; the 0.104.0
  verifier already verifies 0.105.0 selection records.
- plans/README row. Citation tests (`test_compatibility_citations_resolve.py`) via the full Python suite.

## Gates
py pytest + ruff · ts typecheck/build/test · go test · cargo test/clippy/fmt · java/kotlin gradle · contract exit 0.
