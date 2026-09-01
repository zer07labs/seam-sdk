# seam-sdk

Client SDKs for the Seam runtime — Go / Java / Kotlin / Python / TS generated from `seam.api.v1`, with
hand-written clients layered on the stubs, plus `verify/`: an independent Rust decision verifier that
deliberately links nothing of Seam's.

## Commands
- Codegen (**run first** — see Gotchas): `make generate` · against a runtime checkout: `make generate-local RUNTIME=../seam-runtime`
- Contract surface gate: `STREAM=1 EVENTS=1 make check-contract`
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

<!-- Shared cross-repo context (zer07labs/seam, cloned as a sibling). -->
@../seam/CLAUDE.md
