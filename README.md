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

   The Rust reference implementation of this shim lives in the runtime repo (`seam-client`). **Python and
   TypeScript** mirror its full surface (`Agent`, `SeamClient`, verification) and add the ergonomic
   clients documented below; **Go, Java, and Kotlin** ship the crypto shim only
   (`BuildPresentation`/`VerifyTCT`/AID derivation — see the Status table), by ADR.

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
  `DecisionSealed.ciphertext_digest` tag 10, `AuditEntryEvent.actor` tag 4) and
  **`SeamEvents.ReportEventsConsumed`** — **permanent hard gates** (`STREAM=1` / `EVENTS=1`, set in CI).
  Each probe checks the Python and TypeScript stubs **independently**, so a partial regen that leaves one
  language stale fails loudly.

> **BSR state (probed 2026-08-14, `buf export buf.build/zer07labs/seam` + grep):** the BSR carries the
> full surface — `VerifyPartyAttestation`, all four streamed-payload mirror fields, and
> `ReportEventsConsumed`. Their absence is now a regression, which is why the gates above are permanent.

## Build & test

Python and TypeScript wrap the generated stubs with their crypto shims and are the two published
packages (private Cloudsmith — see *Internal distribution*). Go/Java/Kotlin are standalone crypto shims
(no generated transport in-package); Go resolves by module path + `go/vX.Y.Z` tags, Java/Kotlin build
from source. Generate first (above), then:

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
python/, ts/         # first-class SDKs: crypto shim + ergonomic clients + packaging
go/, java/, kotlin/  # crypto shims + conformance tests only (ADR; ergonomic clients are demand-driven)
```

## Internal distribution (private — Cloudsmith `zer07labs/internal`)

The SDK is **not** published to public npmjs / PyPI. It ships to the org's **private Cloudsmith** repo
`zer07labs/internal` — the *same* registry the Rust crates use ([seam-runtime
`docs/deployment.md` § Publishing](https://github.com/zer07labs/seam-runtime)). One registry hosts all
formats: Cargo, **npm**, **Python**.

**Cutting a release — one version everywhere.** The SDK version tracks the **seam-runtime** version: a
runtime release fires a `repository_dispatch` here ([`release-on-runtime.yml`](.github/workflows/release-on-runtime.yml)),
which bumps `ts/package.json` + `python/pyproject.toml` to match, commits, and tags `vX.Y.Z` — that tag
triggers [`publish.yml`](.github/workflows/publish.yml) (transport regenerated from the BSR, both packages
pushed to Cloudsmith). So you don't cut the SDK release by hand; releasing the runtime releases the SDK at
the same version. A `workflow_dispatch` fallback (with an explicit version) exists if a dispatch is missed.
Immutable per version — a re-cut needs a bump. The `version-lockstep` CI guard keeps py == ts.

*Credentials.* `BUF_TOKEN` (read the contract from the BSR — already set) plus a Cloudsmith push token. The
workflow **reuses the org-level `CARGO_REGISTRIES_ZER07LABS_TOKEN`** (the same Cloudsmith key the Rust crates
publish with) — it just strips that value's literal `Bearer ` prefix, which npm/twine must not carry. So if
that org secret is in scope for this repo, **there is no new secret to set**. (A dedicated `CLOUDSMITH_API_KEY`
is honored first if you ever prefer a separate key.) **No per-format setup is needed** either — Cloudsmith
repos are format-agnostic; the same repo that holds the Cargo crates accepts an npm package or a wheel on
first push (verified: `npm.cloudsmith.io/zer07labs/internal/` already answers, like the Cargo endpoint).

**Consuming it** — point the consumer at Cloudsmith and add the dependency:

```sh
# npm (e.g. the control plane): .npmrc
@zer07labs:registry=https://npm.cloudsmith.io/zer07labs/internal/
//npm.cloudsmith.io/zer07labs/internal/:_authToken=${CLOUDSMITH_API_KEY}
#   package.json → "dependencies": { "@zer07labs/seam-sdk": "^0.7" }  # version follows the runtime release

# Python: pip. NOTE the pip index host (dl.cloudsmith.io/basic/…/python/simple/) is DIFFERENT from the
# twine upload host (python.cloudsmith.io/…/) — Cloudsmith serves install and upload from separate hosts.
pip install seam-sdk --extra-index-url \
  https://token:${CLOUDSMITH_API_KEY}@dl.cloudsmith.io/basic/zer07labs/internal/python/simple/
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
| Legacy `budget` (int) | The message-count limit. `0` ⇒ the server default (32). The SDK entry points default to `0` — they never bake the server's default client-side. |
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

Party/grant lifecycle is symmetric: `register_party` has its inverse `remove_party`, and cross-namespace
grants are managed with `place_grant` / `revoke_grant` / `list_grants` (same wrappers in TS).

`SeamAdminClient` also **streams the governance outbox** (`seam-event.v1`) via `stream_events` /
`streamEvents`: **drain** mode (`follow=False`) yields the current backlog and closes (`ack=True` marks
those rows published — `ack` is drain-only and rejected with `follow=True`); **live-tail** mode
(`follow=True`) yields the backlog from a cursor then keeps yielding new events (never acks; resume from
`seq + 1`, dedup by `event_id`; ends cleanly on server shutdown, or deliberately — Python returns an
`EventStream` handle with `.cancel()`, TS takes an `AbortSignal`). A relay reports its durably-consumed
cursor with `report_events_consumed` / `reportEventsConsumed` (destructive: advances the runtime's GC
watermark; needs the `events:consume` scope). For streamed `DECISION_SEALED` events,
`verify_streamed_record_digest` / `verifyStreamedRecordDigest` recomputes the v2 record digest
client-side; `KNOWN_KINDS` lists the event kinds the SDK types (unknown kinds always pass through
opaque). Sealing a decision emits a `DECISION_SEALED` event — asserted live in both SDKs.

## Data-plane surface

Beyond decisions & sessions, `SeamClient` wraps the rest of the data plane: independent proof retrieval +
local verification (`get_commitment_proof`, `verify_decision`), server-side trust
(`verify_commitment`, `verify_party_anchor`, `verify_party_attestation` — the A4 signed chain-head
check, boolean verdict, tamper/unknown ⇒ `False` never an exception), context binding
(`register_context`, `resolve_context`), and advisory outcome reporting (`report_outcome`, Plan R —
emits a `LEARNING_OUTCOME`, never mutates the sealed record).

**`authorize` — the 1-RTT advisory tool-call gate.** Both clients expose the pre-tool-call
`Authorize` verb: a ticketed call (admission handshake amortized across calls, refreshed at 80% TTL,
revocation-stampede-safe) returning a typed `AuthorizeResult` with the closed verdict set
ALLOW / DENY / TRANSFORM / ESCALATE; an unrecognized verdict raises `UnknownVerdictError` (never an
implicit allow), and a TRANSFORM without a transformed input raises `ProtocolViolationError`. The
offline helpers `record_digest_v2` and `verify_chain_head_attestation` are exported at top level for
consumers verifying exported streams without the `verify/` binary.

**Async (Python).** `seam_sdk.aio` mirrors the full data-plane `SeamClient` for `asyncio` (same
signatures, shared ticket core). The management plane is **sync-only by design** — an async operator
runs `SeamAdminClient` in a thread.

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
- **Deadlines.** Every unary call is bounded in both SDKs: ~2 s on the data plane, 30 s on the
  management plane (destructive calls must not hang forever), streams unbounded. Override per call
  (`timeout=` in Python, `timeoutMs` in TS); a breach maps to the typed `DeadlineExceeded` error.
- **Lifecycle.** Both clients expose idempotent `close()` (Python also context-manages); the deprecated
  data-plane `resume_session` tombstone emits a `DeprecationWarning` pointing at the management-plane
  resume.

## Status

| Language | Transport (generated) | Crypto shim + ergonomic client |
|---|---|---|
| **Python** | ✅ | ✅ **complete** — one-shot + **sessions & budgets** + **features** + **management plane** (`SeamAdminClient`: erasure/governance) + context/trust/outcome; round-trips live |
| **TypeScript** | ✅ | ✅ **complete** — one-shot + **sessions & budgets** + **features** + **management plane** (`SeamAdminClient`: erasure/governance) + context/trust/outcome; round-trips live |
| Go | ✅ | ✅ **shim** — conformance-tested (Ed25519 PoP, AID, TCT verify); ergonomic client over gen transport is a follow-up |
| Java | ✅ | ✅ **shim** — conformance-tested (Bouncy Castle); client is a follow-up |
| Kotlin | ✅ | ✅ **shim** — conformance-tested (Bouncy Castle); client is a follow-up |

The admission/TCT crypto is byte-identical across all five languages — pure stock Ed25519/SHA-256/JOSE,
conformance-tested against `conformance/vectors.json` (`admission` + `tct` sections). The wider crypto
surface (JCS/call-sig framing for `authorize`, `record_digest_v2`, chain-head attestation verify) exists
in **Python and TypeScript only** — its "every SDK MUST" vectors are scoped to languages with an
authorize surface, and wiring them is a named precondition of any future Go/Java/Kotlin ergonomic
client. Python (`python/`) is the reference each other language mirrors.
