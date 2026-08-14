# Build Plan — SDK session + budget surface (Python/TS; `seam-sdk` repo)

> **📦 ARCHIVED 2026-08-14 — DELIVERED (verified against code, not memory).** All eight lifecycle
> methods + `BudgetLimits`/`StepUsage` exist in both SDKs (`python/seam_sdk/client.py:364-486`,
> `ts/src/client.ts:286-349`); the suspend→raise→resume loop is live-tested in both
> (`python/tests/test_integration.py:163-192`, `ts/tests/integration.test.ts:121-146`); the README
> budget-semantics table exists (README §budget semantics). **Post-plan runtime change absorbed:**
> the runtime moved resume to `SeamAdmin.ResumeSession` (rt-D), so the data-plane `resume_session`
> is a documented deprecated tombstone and the live raise path is `SeamAdminClient.resume_session`.
> **Deviations from the letter of the plan:** (1) lifecycle methods return raw generated pb messages
> (`SessionStep`/`TerminalResponse`/`SessionStatusResponse`), not the promised DTO wrappers — kept
> deliberately at v0.7.x: the surface is shipped, tested, and identical across Py/TS, and a DTO
> retrofit is now a breaking change with no behavioral payoff; inputs *are* DTO-typed. (2) TS tests
> run under `node:test`, not vitest. Neither deviation affects the wire contract or the DoD loop.

> **Scope:** the sibling `../seam-sdk` repo (Python + TypeScript SDKs). **Status: ready to
> build** once runtime PR #51 (`feat/budget-transport`) is merged and the updated
> `seam.api.v1` contract is published to the BSR.
> **Ground truth (verified 2026-07-04):** the Py/TS SDKs today expose only the **one-shot**
> path (`run_decision`, `get_decision`, `replay_decision`, `verify_decision`,
> `get_commitment_proof`, `issuer_aid`) over gRPC with generated stubs (`buf.gen.yaml` →
> `gen/`, `python/seam_sdk/_gen/`, `ts` gen). **There is no session API in any SDK.**
> Go/Java/Kotlin are crypto shims + conformance vectors only — they stay that way here.

**Goal:** bring the **incremental session lifecycle** to the Python and TS SDKs — open →
propose/vote → commit, cancel/expire/resume, status — with the enterprise-6.2 budget surface
first-class from day one: multi-dimension `BudgetLimits` at open, per-step `StepUsage`
reporting, and the dimension-raising resume (the R9 approver action). Since the session API
is greenfield in the SDKs, budgets are part of its **initial** shape, not a retrofit.

**Wire contract (already merged runtime-side, additive):** `BudgetLimits{messages?, tokens?,
cost_micros?, wall_ms?, soft_pct?}` + `StepUsage{tokens, cost_micros}`;
`OpenSessionRequest.limits` (6), `Proposal/VoteRequest.usage` (5), `CommitRequest.usage` (4),
`ResumeRequest.raise` (3). Legacy `budget: u32` = message count (0 ⇒ server default 32);
absent limits dimensions = unlimited; absent usage = zero. Suspension surfaces as
`SessionStep.state == "Suspended"` (an `Ok` step, not an error); scope denials surface as
gRPC `PERMISSION_DENIED`.

**Execute in order; each step gates on a test.**

---

## §0 — Contract refresh (gate for everything)

- **0a.** Merge runtime PR #51; confirm the runtime CI `contract` job (buf lint + breaking)
  is green and the `seam.api.v1` module is published to the BSR at the new revision.
- **0b.** In `seam-sdk`: `buf generate` (per the Makefile) to refresh `gen/`,
  `python/seam_sdk/_gen/`, and the TS generated client. **Assert additive:** the refreshed
  stubs still compile the existing one-shot clients untouched.
- *Gate:* existing Py + TS test suites green on the regenerated stubs, zero source changes.

## §A — Python session API (`python/seam_sdk/client.py`)

- **A1 — Budget/usage types.** Thin dataclasses `BudgetLimits(messages=None, tokens=None,
  cost_micros=None, wall_ms=None, soft_pct=None)` and `StepUsage(tokens=0, cost_micros=0)`
  with `to_pb()` mappers — SDK users never touch generated protos directly (matches the
  existing DTO discipline).
- **A2 — Lifecycle methods.** On `SeamClient`:
  `open_session(agent, session_id, participants, *, budget=32, limits=None, mode="")`
  (admit → `OpenSession`, mirroring `run_decision`'s handshake);
  `submit_proposal(..., usage=None)`, `submit_vote(..., usage=None)`,
  `submit_commit(..., usage=None)`; `resume_session(session_id, *, budget=32, raise_=None)`;
  `cancel_session`, `expire_session`, `session_status`. Every method returns a typed
  `SessionStep`/terminal DTO, never raw pb.
- **A3 — Semantics tests (against a live seamd, env-gated like the existing e2e):**
  1. full open→propose→vote→commit seals (`decision_id` present);
  2. the 6.2 loop: open with `limits=BudgetLimits(tokens=1000)` → proposal reporting
     `StepUsage(tokens=1000, cost_micros=40)` → next step returns `state == "Suspended"` →
     `resume_session(raise_=BudgetLimits(tokens=5000))` → continues → seals;
  3. a scope denial surfaces as `PERMISSION_DENIED` (grpc `RpcError`), distinguishable from
     `INVALID_ARGUMENT`.
- *Gate:* `pytest` unit (DTO↔pb mapping, absent-field semantics) + the env-gated live suite.

## §B — TypeScript session API (`ts/src/client.ts`)

- **B1/B2 —** Same shape as §A: `BudgetLimits`/`StepUsage` interfaces (all-optional fields),
  `openSession({sessionId, participants, budget?, limits?, mode?})`,
  `submitProposal/submitVote/submitCommit(..., usage?)`,
  `resumeSession(sessionId, {budget?, raise?})`, `cancelSession`, `expireSession`,
  `sessionStatus`. Camel-case per the existing client; DTOs over generated types.
- **B3 —** Mirror §A3's three semantics tests (vitest; live suite env-gated).
- *Gate:* `vitest` green; the live 6.2 loop test passes against a local seamd.

## §C — Cross-SDK consistency + docs

- **C1 —** A shared table in the SDK README pinning the budget semantics (legacy `budget` =
  messages; `limits.messages` overrides; absent = unlimited; absent usage = zero; Suspended
  is a state, not an error; `PERMISSION_DENIED` = scope floor) so Py/TS/Rust
  (`seam-client`) all document identical behavior.
- **C2 —** Runtime repo follow-up (1 line): note in `build-api-grpc-http-sdks.md` that the
  session surface reached the SDKs.

## Out of scope (explicit)

- **Go/Java/Kotlin session clients** — those SDKs are crypto shims + conformance vectors by
  design; a session client there is demand-driven, not part of this plan.
- **HTTP-transport SDK variants** — the SDKs are gRPC-first; the HTTP surface is for curl/
  gateway users.
- **Streaming events (`StreamEvents`) in Py/TS** — separate follow-up if the learning/ops
  tooling wants it; not needed for the session loop.

### Definition of Done
- [ ] Regenerated stubs, additive (existing one-shot suites untouched + green)
- [ ] Py + TS: full session lifecycle with `limits`/`usage`/`raise`, DTO-typed, no raw pb in
      the public surface
- [ ] The 6.2 loop proven live from BOTH SDKs (token breach → Suspended → raise → sealed)
- [ ] Scope denial distinguishable (`PERMISSION_DENIED`) in both
- [ ] README semantics table; CI green in `seam-sdk`
