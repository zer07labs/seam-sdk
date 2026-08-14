# seam-sdk — hardening & completion (P1.10 · H3 · H4 + solid-SDK surface)

> **📦 ARCHIVED 2026-08-14 — DELIVERED (re-verified against code).** P1.10 typed
> `IssuerMismatchError`, H4 `features`, H3 `SeamAdminClient` (erasure preview→confirm→erase +
> governance wrappers + bearer interceptor on both unary and stream calls), H5 data-plane parity,
> `SeamEvents.StreamEvents`, the typed-error taxonomy, and optional TLS are all present and tested
> in both first-class SDKs (Py: `admin.py`/`errors.py`; TS: `admin.ts`/`errors.ts`). The bearer
> model described in H3.0 was later replaced runtime-side (#175: shared `SEAM_MGMT_TOKEN` →
> compact-JWS operator tokens); SDK PR #16 migrated the auth suites — no drift remains.
> **Residuals found in the 2026-08-14 review and fixed in the same pass:** the four
> grants/RemoveParty `SeamAdmin` RPCs were still unwrapped in both SDKs; TS TLS remained
> scheme-only (`https://` baseUrl) vs Python's `credentials=` param. See
> `plans/consolidation-2026-08-14.md` for the full review + fix record.

> **✅ IMPLEMENTED 2026-07-09** (branch `feat/sdk-hardening-h3-h4-h5`). Landed: H4 `features`; a new
> `SeamAdminClient` (Py `admin.py` + TS `admin.ts`) with the preview→confirm→erase flow, bearer-token auth,
> and the governance wrappers; H5 data-plane parity (`report_outcome`, `register_context`/`resolve_context`,
> `verify_commitment`/`verify_party_anchor`); a two-port (data + `SEAM_GRPC_MGMT_LISTEN`) live test harness;
> optional TLS; versions bumped `0.1.0`→`0.2.0`; README + CI updated. Verified live against a built
> `seam-grpc` (both planes): **Python 18 passed, TypeScript 12 passed**, ruff + tsc clean. The narrative
> below is the design of record.
>
> **✅ DEFERRED ITEMS ALSO DONE 2026-07-09** (branch `feat/sdk-events-and-typed-errors`, versions
> `0.2.0`→`0.3.0`): (1) **`SeamEvents.StreamEvents`** — `stream_events`/`streamEvents` on `SeamAdminClient`
> (drain + live-tail), live-tested against the outbox's `DECISION_SEALED`. (2) **Typed-error taxonomy** — a
> `SeamRpcError` hierarchy keyed by status code, mapped centrally (Python stub proxy / TS Connect
> interceptor), **non-breaking** (Python subclasses `grpc.RpcError`; TS extends `ConnectError`, lossless
> in-place retype). Verified live: **Python 19 passed, TypeScript 13 passed**, ruff + tsc clean.


> **Scope:** the **`../seam-sdk`** repo. Python (`python/seam_sdk/`) and TypeScript (`ts/src/`) are the two
> first-class SDKs; Go/Java/Kotlin stay crypto shims (ADR). Generated proto stubs live in
> `python/seam_sdk/_gen/` and `ts/gen/seam/api/v1/` — **git-ignored, never committed**, produced by
> `make generate` (BSR module `buf.build/zer07labs/seam`) or `make generate-local RUNTIME=../seam-runtime`.
>
> **Re-grounded 2026-07-09 against the actual code** (seam-sdk `main`, seam-runtime `d544ea8` — i.e. through
> runtime PR #91 + the C1 shutdown fix, well past the PR #85 baseline the previous draft assumed). Every
> claim below was verified in-tree; the corrections vs the previous draft are called out inline as **⟲**.

---

## 0. State of the world (verified, not assumed)

| Item | Status | Evidence |
|---|---|---|
| **P1.10** typed `IssuerMismatchError` | ✅ **DONE + tested** | `client.py::verify_decision` / `client.ts::verifyDecision` throw it; `python/tests/test_verify_decision.py` + `ts/tests/verify_decision.test.ts` pass. Merged (PR #5). |
| **Session lifecycle + 6.2 budgets** | ✅ **DONE + tested** | `open_session`…`resume_session` in both clients; suspend→raise→resume loop tests pass. Merged (PR #4). |
| **H4** `features` on `run_decision` | ❌ **not in clients** | Wire field **confirmed present**: `RunDecisionRequest.features` = `map<string,string>` field 5. Neither `run_decision` nor `runDecision` accepts/sets it. |
| **H3** erasure / admin surface | ❌ **not started** | `SeamClient` wires only Admission/Coordination/Trust stubs. **No admin stub, no `SeamAdmin` client code at all** — `SeamAdmin`/`Erasure` appear only in generated stubs. |
| Generated stubs (local) | ⚠️ **STALE** | Local `_gen`/`ts/gen` (dated Jul 5) carry the *old* single-arg `EraseSubject` + `features`, but are **missing** `PreviewErasure`, `confirm_count`, `would_erase`, `ReportOutcome`. |
| BSR published contract | ✅ **current** | `buf build buf.build/zer07labs/seam` shows `PreviewErasure`, `confirm_count`, `would_erase`, `ReportOutcome`, `features` all present. |

**⟲ Correction 1 — no runtime work is required.** The previous draft treated the contract republish as a
prerequisite. It's already done: BSR carries the full surface, and the runtime side (erasure preview/confirm,
features, ReportOutcome) is all merged. **This plan is SDK-only.**

**⟲ Correction 2 — stubs are ephemeral, not committed.** `.gitignore` excludes `python/seam_sdk/_gen/` and
`ts/gen/`. CI runs `buf generate buf.build/zer07labs/seam` fresh on every job. So "commit the regenerated
stubs as their own commit" (previous draft) is **wrong** — there is nothing to commit. Regeneration is a
local-dev / CI-time step only.

**⟲ Correction 3 — H3 is net-new, not a mirror.** The Rust reference `seam-client` (`crates/seam-client/src/lib.rs`,
the whole crate) has **no** erasure, no `report_outcome`, no management-token/admin surface — one channel,
one endpoint, PoP-only auth. So H3 cannot be "mirrored from the reference client"; it is original SDK design
against the proto + the runtime's management-plane semantics (documented in H3 below).

**Guarantee to preserve (runtime G3/G4):** the issuer AID stays the **untagged** `aid:pubkey:<base64url>`
form (distinct from a tagged `aid:pubkey:ed25519:…`), golden-pinned and TCT-embedded. The SDK's issuer
pinning + `IssuerMismatchError` oracle depends on this; do not "normalize" AID strings in the client.

---

## Step 0 (prerequisite) — regenerate the local stubs

Local dev only (CI regenerates itself). H3/H4 need the fresh symbols (`PreviewErasure`, `confirm_count`,
`features` on `RunDecisionRequest`).

1. `cd ../seam-sdk && make generate` (BSR; needs a one-time `buf registry login` — already configured on this
   machine) **or** `make generate-local RUNTIME=../seam-runtime`.
2. Verify the new surface landed:
   - Python: `grep -rE "PreviewErasure|would_erase|confirm_count" python/seam_sdk/_gen/seam/api/v1/seam_pb2.pyi`
   - TS: `grep -rE "PreviewErasure|wouldErase|confirmCount" ts/gen/seam/api/v1/seam_pb.ts`
3. **Do NOT commit `_gen`/`ts/gen`** (git-ignored by design).

---

## P1.10 — typed issuer-substitution error  →  ✅ CLOSED

Already implemented + tested in both first-class SDKs (see §0). No code change. One doc task remains:

- **README:** state that the typed `IssuerMismatchError` is a **Py/TS guarantee** (Go/Java/Kotlin shims
  don't verify), and that it is *stronger* than the Rust reference (which returns a generic
  `ClientError::Crypto` string, not a typed error).
- **DoD:** none beyond the existing green tests + the README note.

---

## H4 — `features` on `run_decision` (Py + TS)  ·  small, additive, non-breaking

Attach optional pre-decision request features (`{key: value}`) that the advisory learning classifier keys
`context_class` on. Features **never** touch the sealed record. Mirrors `seam-client::run_decision_with_features`
(`crates/seam-client/src/lib.rs:142`), which sets `RunDecisionRequest.features`.

- **Python** (`client.py::run_decision`): add `features: dict[str, str] | None = None` (keyword). When set,
  populate `req.features` (proto `ScalarMap`). Default `None` ⇒ omit ⇒ non-breaking.
- **TypeScript** (`client.ts::runDecision`): add optional `features?: Record<string, string>`; map onto
  `runDecision({ …, features })`. Default omit.
- **Tests (unit, server-free):** assert the request-building maps features correctly (construct the request
  and check the field) — no server needed. **Plus** an integration assertion (server-gated): a decision run
  *with* features seals a record **byte-identical** to one *without* (same `decided_value`/`outcome`, and a
  populated `policy_version`) — proving features are accepted and don't corrupt the record.
- **DoD:** optional `features` on `run_decision`/`runDecision` in Py + TS, non-breaking, with the
  record-unaffected assertion.

---

## H3 — the management / erasure surface (Py + TS)  ·  net-new, largest item

The GDPR-erasure surface is a **preview → confirm → erase** flow with a REQUIRED tenant scope and a per-call
`confirm_count` (runtime audit P0.1). It lives on the **`SeamAdmin`** service, which the runtime serves on a
**separate management listener** — NOT the data plane.

### H3.0 — connection & auth model (the part the previous draft under-specified)

Verified in `crates/seamd/src/bin/seam-grpc.rs` + `crates/seamd/src/grpc.rs`:

- **Separate port.** `seam-grpc` serves the data plane on `SEAM_GRPC_LISTEN` (default `127.0.0.1:8090`) and
  the management plane on **`SEAM_GRPC_MGMT_LISTEN`**. If `SEAM_GRPC_MGMT_LISTEN` is **unset, the management
  plane is not served** (the gRPC binary has no co-serve mode — only the HTTP `seam-server` binary does).
- **Bearer auth.** Every `SeamAdmin`/`SeamEvents` call passes through a `management_interceptor` that reads
  metadata key **`authorization`** = **`Bearer <token>`** and compares (constant-time) to `SEAM_MGMT_TOKEN`.
  - Token **set** ⇒ client MUST send `authorization: Bearer <token>` or the RPC is `UNAUTHENTICATED`.
  - Token **unset + `SEAM_DEV_INSECURE=1`** ⇒ the plane is **unauthenticated** (no bearer needed — the dev
    test path). Token unset + not dev-insecure ⇒ the binary refuses to bind the mgmt plane (`exit(1)`).

**Design decision:** because the admin surface targets a *different endpoint* and needs *different creds*,
implement it as a **separate `SeamAdminClient`**, not methods on `SeamClient`. (The previous draft's "add an
admin client or methods on the existing client" — the separate-port reality forces the separate client.)

**Python** — `python/seam_sdk/admin.py` (new), `class SeamAdminClient`:
- `SeamAdminClient.connect(target: str, *, token: str | None = None) -> SeamAdminClient` — plaintext channel
  to the **management** endpoint; when `token` is set, attach it via a `grpc` call-credentials / metadata
  interceptor emitting `authorization: Bearer <token>` on every call.
- `preview_erasure(tenant: str, subject: str) -> pb.ErasurePreview` → `SeamAdmin.PreviewErasure` (non-destructive;
  returns `would_erase` / `held` / `already_erased`).
- `erase_subject(tenant: str, subject: str, confirm_count: int) -> pb.ErasureCertificate` → `SeamAdmin.EraseSubject`
  with `ErasureRequest(subject=…, tenant=…, confirm_count=…)`. **`tenant` required** (empty ⇒ server rejects);
  `confirm_count` MUST equal the preview's `len(would_erase)`.
- `erase_subject_confirmed(tenant: str, subject: str) -> pb.ErasureCertificate` — previews, then erases with
  `len(preview.would_erase)` (the common, safe path).

**TypeScript** — `ts/src/admin.ts` (new), `class SeamAdminClient` mirroring: `connect(baseUrl, { token })`
(attach the bearer via a Connect interceptor), `previewErasure`, `eraseSubject`, `eraseSubjectConfirmed`.

**Governance sibling RPCs (same `SeamAdminClient`, cheap to add while we're here — recommended for parity):**
`enroll_tenant`, `list_tenants`, `place_legal_hold`, `release_legal_hold`, `enforce_retention`, `audit_trail`,
`register_party`. All are on `SeamAdmin`; each is a thin wrapper. Legal-hold interplay is directly testable
against erasure (a held record shows in `preview.held`, never in `would_erase`).

**Optional nice-to-have:** `verify_erasure_certificate(cert)` — the cert is signed by the issuer key; re-verify
its signature locally like `verify_decision`. Not required for DoD.

### H3.1 — extend the test harness for the management plane

The current harness (`test_integration.py` fixture / `integration.test.ts::withServer`) spawns `seam-grpc`
with only `SEAM_GRPC_LISTEN` + `SEAM_DEV_INSECURE=1` → **data plane only**. Add a management-plane harness that
also sets **`SEAM_GRPC_MGMT_LISTEN=127.0.0.1:<mgmt_port>`** (a second free port) so `SeamAdmin` is reachable,
unauthenticated under the existing `SEAM_DEV_INSECURE=1`. Keep the data + mgmt ports distinct per test.

### H3.2 — live test (server-gated, mirrors the existing integration harness)

Against a real `seam-grpc` with both planes up: seal a decision for the `[42;32]` demo agent (tenant
`design-partner`) → `preview_erasure("design-partner", subject)` returns it in `would_erase` →
`erase_subject` with the **wrong** count is REJECTED → with the **right** count returns a populated, signed
`ErasureCertificate` → a second `preview_erasure` shows it in `already_erased`. Assert **empty `tenant` is
refused**. (Bearer-token path: also add a variant that boots with `SEAM_MGMT_TOKEN` set and asserts a
missing/wrong token → `UNAUTHENTICATED`, right token → success. Optional but proves the auth wiring.)

- **DoD:** `SeamAdminClient` (Py + TS) with preview/confirm/erase (+ the governance wrappers); the
  preview→confirm→erase live test; empty-tenant and wrong-`confirm_count` rejections asserted; bearer-token
  path exercised at least once.

---

## H5 (new) — round out the data-plane surface for "solid" SDKs

Small, additive parity items the contract exposes that neither SDK wraps. Recommended for a client users can
rely on end-to-end; each is a thin wrapper + a small test.

1. **`ReportOutcome`** (`SeamCoordination.ReportOutcome`) — advisory delayed-correctness report (Plan R).
   `report_outcome(decision_id, correct: bool, verified_by: str | None = None) -> bool`. Data plane; trivial.
2. **`SeamContext`** — `register_context(content, fidelity, derived_from=[]) -> ContextRef` and
   `resolve_context(refs) -> [ContextBinding]`. The context-binding path; data plane.
3. **`SeamTrust` extras** — `verify_commitment(commitment, signed_artifact) -> bool` and
   `verify_party_anchor(party_id, anchor) -> bool` (network-mode counterparty anchor). Data plane.
4. **`SeamEvents.StreamEvents`** — a server-stream consumer (`stream_events(from_seq, follow, ack)`), management
   plane (same `SeamAdminClient` endpoint/creds). Heavier (streaming + the C1 shutdown interaction); make it a
   **separate opt-in step**, not a blocker for H3/H4. Note the runtime's C1 fix: a `follow=true` tail ends on
   server shutdown, so a spawned test server tears down cleanly.

- **DoD:** wrappers + a unit/integration test for items 1–3; item 4 tracked separately.

---

## Cross-cutting solidity (do alongside, not a separate phase)

- **Bearer/credentials mechanism** — required by H3; implement once (Python `grpc.metadata_call_credentials` /
  a `UnaryUnaryClientInterceptor`; TS a Connect interceptor) and reuse for `SeamEvents`.
- **Typed error taxonomy** — today only `IssuerMismatchError` is typed; everything else is a raw
  `grpc.RpcError` / Connect error. For a solid SDK, map common gRPC status codes to named errors (e.g.
  `PermissionDeniedError` for the scope-floor denial the session docs already mention, `NotFoundError`,
  `UnauthenticatedError`) — additive, keep the raw error as `.cause`. Keep `SeamError` as the base.
- **Secure transport** — both clients hard-use plaintext (`grpc.insecure_channel` / `createGrpcTransport`
  baseUrl). Add an optional TLS path (`connect(target, *, tls=...)`) for non-dev use; the runtime supports
  `SEAM_TLS_*`. Non-breaking (default plaintext for the dev/loopback path).
- **`admit` as public API?** — the Rust reference exposes `admit`; the SDKs keep it private. Leave private
  unless a user needs the raw presentation (out of scope unless asked).
- **Versioning & release** — bump `python/pyproject.toml` + `ts/package.json` from `0.1.0` → `0.2.0` once H3/H4
  land (new surface, non-breaking). Update the README status table + the two READMEs' method lists.
- **CI** — the existing `integration` job self-skips without secrets. Extend it (or add a job) to boot the
  **management plane** (`SEAM_GRPC_MGMT_LISTEN`) so the H3 erasure test runs live in CI, not just locally.

---

## Sequencing & guardrails

1. **Step 0** — `make generate` locally (stubs only; nothing to commit).
2. **P1.10** — already closed; just the README note.
3. **H4** — smallest new surface (one optional param each). Land first; unit test + record-unaffected assertion.
4. **Bearer/credentials + `SeamAdminClient` scaffold** — the shared plumbing H3 needs.
5. **H3** — preview/confirm/erase + governance wrappers + the extended (two-port) test harness + live test.
6. **H5 items 1–3** — thin data-plane wrappers (ReportOutcome, Context, Trust extras).
7. **H5 item 4 (Events)** + TLS + typed-error taxonomy — opt-in follow-ups.
8. **Release** — bump versions, README, run the full SDK CI green.
9. **Keep everything additive + non-breaking** (default-None/omitted params); do **not** touch the Go/Java/Kotlin
   crypto shims or the existing data-plane happy path. Do **not** normalize/tag issuer-AID strings (G3/G4).

## Explicitly out of scope
- Go/Java/Kotlin ergonomic clients (crypto shims by ADR).
- The runtime side — all merged (BSR carries tenant/confirm_count/PreviewErasure/features/ReportOutcome).
- Any runtime contract push or regeneration commit (stubs are git-ignored + CI-regenerated).
