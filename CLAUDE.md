# seam-sdk

Client SDKs for the Seam runtime — Go / Java / Kotlin / Python / TS generated from `seam.api.v1`, with
hand-written clients layered on the stubs, plus `verify/`: an independent Rust decision verifier that
deliberately links nothing of Seam's.

## Commands
- Codegen (**run first** — see Gotchas): `make generate` · against a runtime checkout: `make generate-local RUNTIME=../seam-runtime`
- Contract surface gate: `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` — **call the script, not
  `make check-contract`.** The exit code IS the result here (see Gotchas), and `make` replaces a
  failed recipe's status with its own **2** — which is itself a real, differently-meaning code in
  this gate's vocabulary (the `STREAM=1` mirror-field refusal), so every distinct outcome arrives
  wearing one that means something else. The `make` target still exists and is fine for CI, where
  only pass/fail is read.
- Registry drift (read-only by default; needs `SEAM_REGISTRY_TOKEN`, and `REPO` + `GH_TOKEN` only
  for `--report`): `python3 scripts/check_registry_drift.py` — **exit 2 is infrastructure, never a
  verdict**; 1 is drift, 0 is clean-or-still-in-grace.
- Python (use the venv — a system `pytest`/`ruff` fails to resolve the package): setup `pip install -e "./python[dev]"` ·
  lint `python/.venv/bin/ruff check python && python/.venv/bin/ruff format --check python` · test `cd python && .venv/bin/pytest -q`
- TypeScript (in `ts/`): `npm run typecheck` · `npm run build` · `npm test`
- Go (in `go/`): `go test ./...`
- Rust verifier (in `verify/`): `cargo test` · `cargo clippy --all-targets -- -D warnings` · `cargo fmt --check`
- Java / Kotlin (in `java/`, `kotlin/`): `./gradlew test --no-daemon` *(needs JDK 17)*

## Gotchas
- **Generated stubs are never committed** — `gen/`, `python/seam_sdk/_gen/`, `ts/gen/` are gitignored. A fresh
  clone cannot `import seam_sdk` or typecheck `ts/` until `make generate` runs, and that needs a one-time
  `buf registry login` (the BSR module `buf.build/zer07labs/seam` is private). Never vendor a local `.proto`;
  to iterate against an unpublished runtime change use `make generate-local`, then regenerate from the BSR
  before releasing.
- **One version everywhere** — `python/pyproject.toml` and `ts/package.json` must carry the *same* version
  (stamped by `scripts/set_version.sh`; it follows the runtime). CI's `version-lockstep` job fails on drift.
- **Regenerating can outrun the dependency floors** — the `protobuf` / `grpcio` minimums in
  `python/pyproject.toml` are *derived* from the emitted stubs, and `python/tests/test_protobuf_floor.py` /
  `test_grpcio_floor.py` go red after a `make generate` that bumps gencode. Raise the floor; don't relax the test.
- Python CI installs editable **and** builds the wheel to import it in a clean venv — an editable install
  cannot see a packaging defect. Don't trust a green suite alone before a release.
- **`STREAM=1 EVENTS=1 ./scripts/check-contract.sh` exits **0** on a checkout whose stubs are current** —
  and that is new. It used to exit **6** on every local run, because the stubs here lagged the
  committed manifest by seven `ContextBinding` fields and no one could regenerate; the gate carried a
  recorded-lag file (`contract/expected-local-lag.txt`) whose whole job was to downgrade that standing
  refusal to a NOTE. Both are gone. `buf registry login` is done on this workstation, `make generate`
  pulls the BSR module clean, and the recorded lag closed with it — so a local run and a CI run now
  compare the same two things and agree. If the gate is red here, it is red in CI too. **Regenerate
  before believing a field-surface refusal**: stale stubs are the one cause this checkout can fix by
  itself, and it now can.
  **Read the exit code, not just this bullet** — which is why the command above is the script and
  not `make`. Several codes are reachable from the same command: 6 (api field or enum-value surface
  disagrees with `contract/field-manifest.txt`), 5 (RPC-manifest drift), 3 (stubs absent), 1
  (RPC/Authorize/admin surface stale). Three more matter. If `seam.event.v1`'s field surface
  disagrees with `contract/event-field-manifest.txt`, the run exits **8** — 8 is deliberately not 6,
  so an event regression cannot arrive wearing the api code. But if the disagreement is one of the
  **four streamed-payload mirror fields** (`session_lifecycle`, `chain_head_attestation`,
  `ciphertext_digest`, `AuditEntryEvent.actor`), `STREAM=1` refuses earlier with exit **2**.
  Earlier still — ahead of all three — is exit **7**, a structural precondition of the event gate:
  `seam.event.v1` is asserted to have zero enums, zero nested messages, and **zero services**. The
  verb clause is the newest: `contract/rpc-manifest.txt` covers `seam.api.v1` only, so a service
  landing in the event package would be declared nowhere and named by no probe in either language,
  and would ship unwired with every gate green. It is probed over the package **directory**, not two
  filenames — a service usually arrives in its own `.proto`, hence its own generated file — and it
  matches service declarations as well as RPCs, since a service with no methods emits no RPC literal
  at all. 7 preempting 2 is not new — the enum clause always did — and it is the right order, because
  a failed precondition means the surface being compared is not the surface the gate knows how to
  read. Those four codes — 6, 8, 2, 7 — are pinned against the gate's real behaviour by
  `python/tests/test_event_field_manifest_gate.py`, so this paragraph cannot drift from it silently.
- **A field the stubs carry and the manifest does not is a DECISION, not a chore.** The gate refuses
  and names it; the remedy is to decide whether this SDK carries it — wire it into the hand-written
  clients or record in the PR why not — and only then write the manifest. Running
  `--write-manifest` first turns the refusal back into the silent pass it exists to remove, and a
  bare run additionally rewrites the api manifest from whatever the local stubs happen to be.

<!-- Shared cross-repo context (zer07labs/seam, cloned as a sibling). -->
@../seam/CLAUDE.md
