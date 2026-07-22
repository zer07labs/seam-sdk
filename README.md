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

**BSR vs. local — which contract to build against.** `make generate` pulls the **published BSR module**
(`buf.build/zer07labs/seam`) — the immutable release of record that shipped packages are built from.
`make generate-local` pulls a **runtime checkout's working tree** — always current with the runtime, so SDK
development is never blocked waiting on a BSR push. The BSR is updated on a runtime **main-merge**, and only
when that CI has `BUF_TOKEN` set; publishing to the BSR is immutable per label, so it is a **runtime-side,
user-gated** step this repo never performs. Rule of thumb: **`generate-local` for iteration, `generate`
(BSR) for release**. When a contract change has landed in the runtime but not yet been pushed to the BSR,
only `generate-local` sees it.

**`make check-contract`** turns "what surface does the active contract expose?" into a verifiable fact
(the SDK's analogue of the runtime's published-surface gate). It runs after a `generate`/`generate-local`
and probes the emitted stubs:
- **`SeamTrust.VerifyPartyAttestation`** (the A4 RPC the attestation client calls) — a **hard gate**;
  a stale contract missing it exits non-zero.
- the **streamed-payload mirror fields** (`session_lifecycle` tag 21, `chain_head_attestation` tag 22,
  `DecisionSealed.ciphertext_digest` tag 10, `AuditEntryEvent.actor` tag 4) — **reported** by default,
  and a **hard gate under `STREAM=1`** (the mode for live-event decoding). These reach the BSR only after
  the runtime's proto-mirror push; `generate-local` carries them today.

> **BSR state (probed 2026-07-21, `buf build buf.build/zer07labs/seam -o /tmp/x.binpb && strings /tmp/x.binpb | grep -E 'VerifyPartyAttestation|session_lifecycle'`):** carries `VerifyPartyAttestation`
> (A4 is live on the BSR), but **not yet** the four streamed-payload mirror fields — those are pending the
> runtime proto-mirror's main-merge push. Until then, `make generate-local RUNTIME=../seam-runtime` is the
> baseline for any streamed-event work.

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

## Internal distribution (private — Cloudsmith `zer07labs/internal`)

The SDK is **not** published to public npmjs / PyPI. It ships to the org's **private Cloudsmith** repo
`zer07labs/internal` — the *same* registry the Rust crates use ([seam-runtime
`docs/deployment.md` § Publishing](https://github.com/zer07labs/seam-runtime)). One registry hosts all
formats: Cargo, **npm**, **Python**.

**Cutting a release.** Bump the versions (`ts/package.json`, `python/pyproject.toml` — keep them equal) and
push a matching tag; [`.github/workflows/publish.yml`](.github/workflows/publish.yml) generates the
transport from the BSR and pushes both packages. Immutable per version — a re-cut needs a bump.

```sh
# versions bumped to X.Y.Z in ts/package.json + python/pyproject.toml, then:
git tag vX.Y.Z && git push origin vX.Y.Z     # → npm + wheel land on Cloudsmith
```

*Requires two repo secrets:* `BUF_TOKEN` (read the contract from the BSR) and `CLOUDSMITH_API_KEY` (a raw
Cloudsmith key with push to `zer07labs/internal`, npm + python formats enabled). The npm/python formats may
need enabling once on the Cloudsmith repo (they're format-agnostic; the Cargo one is already live).

**Consuming it** — point the consumer at Cloudsmith and add the dependency:

```sh
# npm (e.g. the control plane): .npmrc
@zer07labs:registry=https://npm.cloudsmith.io/zer07labs/internal/
//npm.cloudsmith.io/zer07labs/internal/:_authToken=${CLOUDSMITH_API_KEY}
#   package.json → "dependencies": { "@zer07labs/seam-sdk": "^0.3.0" }

# Python: pip
pip install seam-sdk --extra-index-url \
  https://token:${CLOUDSMITH_API_KEY}@python.cloudsmith.io/zer07labs/internal/simple/
```

> Endpoint hosts follow the per-format Cloudsmith convention (`cargo.cloudsmith.io/…` → `npm.`/`python.`).
> If a call 4xx's on a URL, confirm it against Cloudsmith → the repo → **Set Me Up**.

## Contract changes

The contract is versioned and **backward-compatibility-checked** in the runtime repo's CI (`buf breaking`),
so a change there can never silently break a generated client. Regenerate after a contract release.

## Session lifecycle & budgets (enterprise 6.2)

Python and TypeScript expose the **incremental session** path — `open_session` → `submit_proposal`/
`submit_vote` → `submit_commit`, with `cancel_session`/`expire_session`/`session_status` — alongside the
one-shot `run_decision`. The R9 **resume** is the exception: it moved to the **management** plane (rt-D),
so it is `SeamAdminClient.resume_session(session_id, approver, …)`, not a data-plane call (the data-plane
`resume_session` is now a tombstone). The multi-dimension budget surface is first-class; all three clients
(Py/TS + the Rust `seam-client`) document **identical** semantics:

| Rule | Behavior |
|---|---|
| Legacy `budget` (int) | The message-count limit. `0` ⇒ the server default (32). |
| `limits.messages` | Overrides the legacy `budget` when set. |
| Absent `limits` dimension | Unlimited on that dimension (`tokens`/`cost_micros`/`wall_ms`). |
| `soft_pct` | Soft-warning threshold as % of any limit (server default 80). |
| Per-step `usage` | Absent ⇒ zero; the orchestrator reports what the agent runtime spent. |
| **Suspended** | A hard breach returns a step with `state == "Suspended"` — an **ok step, not an error**. |
| `resume` with a raise | The R9 approver (on the **management** plane: `SeamAdminClient.resume_session`) raises any dimension; the session then continues. |
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
(`SEAM_GRPC_MGMT_LISTEN`), never the data plane, and is gated by an **operator token** — a compact-JWS
credential the control plane mints against the runtime's `operator_keys` trust root, enforcing a per-verb
scope (the deprecated shared `SEAM_MGMT_TOKEN` bearer was removed in seam-runtime #175). The Py + TS SDKs
expose it as a **distinct `SeamAdminClient`** you point at the management endpoint:

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

`SeamAdminClient` also **streams the governance outbox** (`seam-event.v1`) via `stream_events` /
`streamEvents`: **drain** mode (`follow=False`) yields the current backlog and closes (`ack=True` marks
those rows published); **live-tail** mode (`follow=True`) yields the backlog from a cursor then keeps
yielding new events (never acks; resume from `seq + 1`, dedup by `event_id`; ends cleanly on server
shutdown). Sealing a decision emits a `DECISION_SEALED` event — asserted live in both SDKs.

## Data-plane surface

Beyond decisions & sessions, `SeamClient` wraps the rest of the data plane: independent proof retrieval +
local verification (`get_commitment_proof`, `verify_decision`), server-side trust
(`verify_commitment`, `verify_party_anchor`), context binding (`register_context`, `resolve_context`),
and advisory outcome reporting (`report_outcome`, Plan R — emits a `LEARNING_OUTCOME`, never mutates the
sealed record).

## Errors & transport security

- **`IssuerMismatchError`** (Py + TS) is the one client-side semantic error — a key-substitution signal
  raised by `verify_decision`/`verifyDecision`, never downgraded to `false`.
- **Typed server errors.** Server failures are mapped to a status-code taxonomy under `SeamError`:
  `SeamRpcError` and subclasses `InvalidArgumentError` (empty tenant / wrong `confirm_count`),
  `PermissionDeniedError` (scope-floor denial), `UnauthenticatedError` (bad/missing management token),
  `NotFoundError`, `ResourceExhaustedError`, `UnavailableError`, … The mapping is **non-breaking**: in
  Python each is *also* a `grpc.RpcError` (so `except grpc.RpcError` and `.code()` still work); in TypeScript
  each *extends* `ConnectError` (so `instanceof ConnectError` and `.code` still work). Catch a specific
  subclass, or keep catching the raw transport error — both work.
- **TLS.** Both clients are plaintext by default (the dev/loopback path). Python: pass
  `credentials=grpc.ssl_channel_credentials()` to `connect(...)`. TypeScript: use an `https://` base URL.
  Prefer TLS whenever a real operator token is in play, so it isn't sent over cleartext.

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
