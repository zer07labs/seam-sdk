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
- **`STREAM=1 EVENTS=1 ./scripts/check-contract.sh` exits **6** on every pre-ACDP local checkout** — local stubs
  lag the committed manifest by five `ContextBinding` fields (`content_hash`, `receipt_hash`,
  `key_status`, `resolved_status`, `retraction`) until a regeneration pulls a BSR module that carries
  them. The gate recognises exactly that case and downgrades its output to a NOTE naming
  `contract/expected-local-lag.txt` — it still exits **6**, since CI is the authority, not this checkout.
  Anything the gate names beyond exactly those five fields is real drift, not this known lag.
  **Read the exit code, not just this bullet** — which is why the command above is the script and
  not `make`. Several other codes are reachable from the same command — 5 (RPC-manifest drift),
  3 (stubs absent) and 1 among them — and none is the recorded lag.
  Three matter here. If `seam.event.v1`'s field surface disagrees with
  `contract/event-field-manifest.txt`, the run exits **8** — 8 exists precisely so an event
  regression cannot arrive wearing the code this bullet tells you to read past — and the NOTE then
  says so instead of claiming 6. But if the disagreement is one of the **four streamed-payload mirror
  fields** (`session_lifecycle`, `chain_head_attestation`, `ciphertext_digest`,
  `AuditEntryEvent.actor`), `STREAM=1` refuses earlier with exit **2** and no NOTE is printed at all.
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

<!-- Shared cross-repo context (zer07labs/seam, cloned as a sibling). -->
@../seam/CLAUDE.md
