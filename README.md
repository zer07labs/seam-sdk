# Seam SDKs

Open-source client SDKs for the [Seam](https://github.com/zer07labs) decision-boundary runtime, generated
from the **`seam.api.v1`** protobuf contract. Languages: **Go, Java, Kotlin, Python, TypeScript**.

Licensed Apache-2.0. The Seam runtime itself is a separate, private repository — these SDKs depend only on
the public contract, never on the runtime internals.

## Architecture

The single source of truth is the `seam.api.v1` protobuf contract, published as the buf module
**`buf.build/zer07labs/seam`**. Each SDK has two layers:

1. **Generated transport** — gRPC client stubs + message types, produced by `buf generate` (see
   `buf.gen.yaml`). Never hand-edited.
2. **A small crypto shim** (hand-written, per language) — the client-side crypto the server can't own:
   - **Pinned-key proof-of-possession** — answer the admission challenge by signing the issued nonce with
     the agent's Ed25519 key (the seed never leaves the client).
   - **AID derivation** — derive the `aid:pubkey:ed25519:` identity from the agent's public key.
   - **Independent TCT/JWS verification** — verify a sealed decision's rooted commitment offline, with
     zero server trust, from the issuer AID + the signed artifact.

   The Rust reference implementation of this shim lives in the runtime repo (`seam-client`); each language
   mirrors its small surface (`Agent`, `SeamClient`, `verify_sealed_commitment`).

## Generate

Requires [`buf`](https://buf.build/docs/installation) and a one-time `buf registry login` (remote plugins
run codegen on the BSR — no local `protoc-gen-*` toolchains needed).

```sh
buf registry login
make generate          # all languages, from the published contract module
# or, against a local runtime checkout:
make generate-local RUNTIME=../seam-runtime
```

Generated stubs are git-ignored (regenerated on release). They land per language where each package
consumes them: **Python → `python/seam_sdk/_gen/`** (so the wheel ships the transport), **TypeScript →
`ts/gen/`** (so it resolves the package's `node_modules`), and **Go/Java/Kotlin → `gen/<language>/`**.

## Build & test

Each package wraps the generated stubs with its crypto shim and is published on its own cadence (PyPI,
npm, pkg.go.dev, Maven Central). Generate first (above), then:

```sh
# Python — an installable wheel that ships the generated transport.
pip install ./python              # or: pip install -e "./python[dev]" && (cd python && pytest)

# TypeScript — compiles to dist/ (JS + d.ts); `npm pack`/publish runs the build via prepack.
cd ts && npm ci && npm run build  # npm test runs the conformance + (gated) live round-trip
```

CI (`.github/workflows/ci.yml`) regenerates from the contract and runs both: Python (`ruff` + `pytest`)
and TypeScript (`tsc` typecheck + build + `node --test`). A gated job builds `seam-grpc` and runs the live
round-trip end-to-end (it needs a runtime-checkout token, so it self-skips when unset).

## Layout

```
buf.gen.yaml         # codegen for all five languages (remote plugins)
Makefile             # generate / generate-local / clean / lint
.github/workflows/   # CI: ruff+pytest, tsc+build+test, gated live integration
gen/{go,java,kotlin}/             # generated stubs without an in-package home (git-ignored)
python/seam_sdk/_gen/, ts/gen/    # generated transport, inside each package (git-ignored)
<lang>/              # per-language package: the crypto shim + ergonomic client + packaging
```

## Contract changes

The contract is versioned and **backward-compatibility-checked** in the runtime repo's CI (`buf breaking`),
so a change there can never silently break a generated client. Regenerate after a contract release.

## Status

| Language | Transport (generated) | Crypto shim + ergonomic client |
|---|---|---|
| **Python** | ✅ | ✅ **complete** — round-trips live (admit → decide → seal → read → verify) |
| **TypeScript** | ✅ | ✅ **complete** — round-trips live (`@noble/curves` + `@noble/hashes`, `@connectrpc/connect`) |
| Go | ✅ | ⏳ |
| Java | ✅ | ⏳ |
| Kotlin | ✅ | ⏳ |

The crypto shim is identical across languages — pure stock Ed25519/SHA-256/JOSE, conformance-tested against
`conformance/vectors.json`. Python (`python/`) is the reference each other language mirrors.
