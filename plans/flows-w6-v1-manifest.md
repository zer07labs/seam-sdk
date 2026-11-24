# Flows W6 — seam-sdk follow-up to seam-runtime 0.118.0 (#1921, `253f4995`)

Wave 6 (board `.waves/flows`), unit seam-sdk. Source: the runtime W6 done report, "Pins to route / seam-sdk".
One PR. Lean run (owner brief): the plan was written directly from the code read below, not through a
separate planner pass.

| Phase | What | Status |
|---|---|---|
| P1 | Re-vendor `verify/docs/seam-event.v1.md` at `253f4995` (two `LEARNING_*` `flow_ref` lines). This is what refused the 0.118.0 release dispatch (issue #427, `CURRENCY: … STALE`) | DONE |
| P2 | `verify/`: chain-manifest v1 dispatch, matching runtime `crates/seam-verify/src/chains.rs` @ `253f4995`: `is_v1` (`tenant_len == 0 && tenant_head` empty), the v1 preimage (fields 1-8 under `seam.audit.chain-manifest.v1`) for the entry digest and the signature, no tenant-head check for v1, `MANIFEST_DOWNGRADE` for a v1 after a v2 on the same `(stream_id, tenant)`; V7 still runs over a v1 manifest's listed chains. Regression tests: the runtime's real v1 event fixture, and a mixed v1→v2 stream plus a downgrade. seam-verify 0.7.1 | DONE |
| P3 | `make generate` from the BSR (0.118.0 push confirmed: runtime CI run 45360225384 `buf push` success, BSR commit `bd7ce692` at 08:54Z); contract gate; COMPATIBILITY re-quote check against agent-core 0.37.0; CHANGELOG/README | DONE |

Facts the plan rests on:
- `253f4995` is the only `seam.proto` change since 0.117 and the runtime's main proto equals it.
- agent-core 0.37.0 pins `seam-sdk>=0.117.0,<0.118` (`seam-adapters/core/pyproject.toml:159`); the
  COMPATIBILITY row already quotes that, so it is not stale.
- The SDK 0.118.0 release is re-fired by `release-refire.yml` once main's CI is green after this merge.
