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
     zero server trust, from the issuer AID + the signed artifact. `verify_decision`/`verifyDecision`
     returns `false` for an ordinary invalid decision, but raises a **distinct** `IssuerMismatchError`
     when the server's proof carries a different issuer AID than the one the caller pinned — a
     key-substitution signal that is never downgraded to a bland `false` (matching the Rust reference's
     distinct `ClientError::Crypto`).

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
round-trip **and the management-plane (erasure/auth) suite** end-to-end (it needs a runtime-checkout token,
so it self-skips when unset).

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

## Session lifecycle & budgets (enterprise 6.2)

Python and TypeScript expose the **incremental session** path — `open_session` → `submit_proposal`/
`submit_vote` → `submit_commit`, with `resume_session`/`cancel_session`/`expire_session`/`session_status`
— alongside the one-shot `run_decision`. The multi-dimension budget surface is first-class; all three
clients (Py/TS + the Rust `seam-client`) document **identical** semantics:

| Rule | Behavior |
|---|---|
| Legacy `budget` (int) | The message-count limit. `0` ⇒ the server default (32). |
| `limits.messages` | Overrides the legacy `budget` when set. |
| Absent `limits` dimension | Unlimited on that dimension (`tokens`/`cost_micros`/`wall_ms`). |
| `soft_pct` | Soft-warning threshold as % of any limit (server default 80). |
| Per-step `usage` | Absent ⇒ zero; the orchestrator reports what the agent runtime spent. |
| **Suspended** | A hard breach returns a step with `state == "Suspended"` — an **ok step, not an error**. |
| `resume` with a raise | The R9 approver raises any dimension; the session then continues. |
| Scope-floor denial | Surfaces as gRPC **`PERMISSION_DENIED`** (distinct from `INVALID_ARGUMENT`). |

`uint64` budget dimensions are `bigint` in TypeScript and `int` in Python. The live 6.2 suspend→raise→resume
loop is covered by `test_budget_suspend_resume_loop` (Python) and the "6.2 budget loop" test (TS).

## Request features (advisory serving)

`run_decision`/`runDecision` take an optional `features` map (`dict[str, str]` / `Record<string, string>`).
The runtime's advisory learning classifier keys `context_class` on them; they **never** affect the sealed
record — a decision seals identically with or without features (mirrors the Rust reference's
`run_decision_with_features`). Default absent ⇒ no features (non-breaking). Covered by the
"features never affect the sealed record" test in both Py + TS.

## Management plane — GDPR erasure & governance (`SeamAdminClient`)

The governance surface (`SeamAdmin`) is served on a **separate management listener**
(`SEAM_GRPC_MGMT_LISTEN`), never the data plane, and is gated by a bearer token (`SEAM_MGMT_TOKEN`). The Py +
TS SDKs expose it as a **distinct `SeamAdminClient`** you point at the management endpoint:

```python
admin = SeamAdminClient.connect("mgmt.host:8443", token="…")   # omit token only against a dev server
preview = admin.preview_erasure("tenant", subject)             # non-destructive
cert = admin.erase_subject("tenant", subject, len(preview.would_erase))   # or: erase_subject_confirmed(...)
```

**Erasure is preview → confirm → erase** (runtime audit P0.1): `preview_erasure`/`previewErasure` is
non-destructive (returns `would_erase` / `held` / `already_erased`); `erase_subject`/`eraseSubject` requires
a **non-empty `tenant`** scope (erasure never crosses tenants) and a `confirm_count` that must **equal the
preview's `would_erase` count**, and returns a signed, chain-anchored `ErasureCertificate`.
`erase_subject_confirmed`/`eraseSubjectConfirmed` does both in one call. The client also wraps the governance
RPCs (`enroll_tenant`, `list_tenants`, `register_party`, `place`/`release_legal_hold`, `enforce_retention`,
`audit_trail`). The live preview→confirm→erase flow (+ empty-tenant / wrong-count rejections + bearer-auth)
is covered by `test_admin.py` (Python) and `admin.test.ts` (TS).

## Data-plane surface

Beyond decisions & sessions, `SeamClient` wraps the rest of the data plane: independent proof retrieval +
local verification (`get_commitment_proof`, `verify_decision`), server-side trust
(`verify_commitment`, `verify_party_anchor`), context binding (`register_context`, `resolve_context`),
and advisory outcome reporting (`report_outcome`, Plan R — emits a `LEARNING_OUTCOME`, never mutates the
sealed record).

## Errors & transport security

- **`IssuerMismatchError`** (Py + TS) is the one semantic typed error — a key-substitution signal raised by
  `verify_decision`/`verifyDecision`, never downgraded to `false`. Everything else surfaces as the idiomatic
  transport error carrying a typed status code: `grpc.RpcError` with `.code()` (Python) / `ConnectError`
  with `.code` (TS) — e.g. `UNAUTHENTICATED` (bad/missing management token), `PERMISSION_DENIED` (scope-floor
  denial), `INVALID_ARGUMENT` (empty tenant / wrong `confirm_count`).
- **TLS.** Both clients are plaintext by default (the dev/loopback path). Python: pass
  `credentials=grpc.ssl_channel_credentials()` to `connect(...)`. TypeScript: use an `https://` base URL.
  Prefer TLS whenever a real management bearer token is in play, so it isn't sent over cleartext.

## Status

| Language | Transport (generated) | Crypto shim + ergonomic client |
|---|---|---|
| **Python** | ✅ | ✅ **complete** — one-shot + **sessions & budgets** + **features** + **management plane** (`SeamAdminClient`: erasure/governance) + context/trust/outcome; round-trips live |
| **TypeScript** | ✅ | ✅ **complete** — one-shot + **sessions & budgets** + **features** + **management plane** (`SeamAdminClient`: erasure/governance) + context/trust/outcome; round-trips live |
| Go | ✅ | ✅ **shim** — conformance-tested (Ed25519 PoP, AID, TCT verify); ergonomic client over gen transport is a follow-up |
| Java | ✅ | ✅ **shim** — conformance-tested (Bouncy Castle); client is a follow-up |
| Kotlin | ✅ | ✅ **shim** — conformance-tested (Bouncy Castle); client is a follow-up |

The crypto shim is identical across languages — pure stock Ed25519/SHA-256/JOSE, conformance-tested against
`conformance/vectors.json`. Python (`python/`) is the reference each other language mirrors.
