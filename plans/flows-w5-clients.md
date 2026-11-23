# Flows W5 — clients (seam-sdk)

Wave 5, unit `clients`, [QB]. Sources: replan `seam-console-ui/plans/cross-repo/flows-w4plus-replan.md`
§9.7 (row `5|clients|drive|Multi-chain verify; v6 voter-vector step 3 with runtime`), issues #420 and #421
(CK1 blockers on partner), and #419's re-pin TODO. One PR. Decisions: DECISIONS.md 2026-11-23.

| Phase | What | Status |
|---|---|---|
| P1 | #420: served v6 commitment verifies — rebuild trailers from `gate`/`governing_doc_sha256`/`env` in py, TS, Go, Java, Kotlin (wired) and Rust (helper); `commitment_view` carries `gate_body`/`env` | DONE |
| P2 | Multi-chain: `seam-verify chain --chain <SELECTOR>`; Live + Sandbox version chains of one flow each verify alone (`tests/chain_vectors.rs`) | DONE |
| P3 | #421: `verify/` 0.6.0; spec header re-pinned to runtime main `ddbfa6ff`; publish via `publish.yml` `publish-verify` after merge | DONE (publish after merge) |
| P4 | v6 voter-vector step 3: already landed in seam-runtime #1859; confirmed byte identity, nothing to change here | DONE (no-op) |

Out of scope: attestation v3 under `--issuer` (not cheap; carried, not verified).
