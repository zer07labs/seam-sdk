# Post-onboarding SDK asks: ticket refresh beyond `authorize`, and a seed-free identity-facts loader

> **Issues:** [#275](https://github.com/zer07labs/seam-sdk/issues/275) (B-SDK-REFRESH) and
> [#274](https://github.com/zer07labs/seam-sdk/issues/274) (B-CORE-FACTS, SDK half). Both are
> **non-blocking** for seam-mcp.
> **Spec (the ask, by seam-mcp):** `seam-mcp/plans/cross-repo/seam-sdk-post-onboarding.md`, sections
> B-SDK-REFRESH and B-CORE-FACTS. The consumer is seam-mcp P4c (`seam-mcp/plans/post-onboarding.md`
> §P4c, plus the Blocker register rows B-CORE-FACTS and B-SDK-REFRESH).
> **Epic:** zer07labs/seam-mcp#50. **Core counterpart:** zer07labs/seam-adapters#262 (B-CORE-FACTS).
> **Anchors:**
> - seam-sdk anchors are true at `f1d112d` (`main`).
> - seam-runtime anchors are at `origin/main` `358edca7`, read with `git show`. The local runtime
>   checkout is on `plan/aws-deployment`.
> - Re-check every anchor before editing.

## Status

PLANNED 2026-10-19. Revised after review round 1 (see **Plan review**). All four phases are TODO.
- Every decision is settled, including D-SUBMIT-RETRY and D-AID-RECORD (see **Decisions** and
  **Open questions**).
- No phase is held.

## Context

### What the code does today

**Refresh.** `authorize` is the only verb that recovers from a rejected ticket.
- Python sync, `python/seam_sdk/client.py:389-392`: on `UnauthenticatedError` it calls
  `_refresh_ticket(agent, ticket, timeout)` and sends `Authorize` once more. A second failure
  propagates typed.
- Python aio does the same at `python/seam_sdk/aio.py:273-276`. TS does it at
  `ts/src/client.ts:770-776`.

Refresh is coalesced per AID by **adopt-if-different**. If the cache holds a live ticket that is not
the failed one, the client adopts it. Otherwise it invalidates the cache and re-admits.
- Python sync, `client.py:416-448`: under the per-AID `threading.Lock`.
- Python aio, `aio.py:297-316`: under an `asyncio.Lock`.
- TS, `ts/src/client.ts:817-828`: through the same rule plus the in-flight `admitting` map.

**Credentialed verbs.** Every other credentialed verb takes its ticket from `_credential_md`
(`client.py:458-478`, aio `:326-345`) or `credentialHeaders` (`ts/src/client.ts:841-862`). These attach
`x-seam-ticket-bin` and `x-seam-call-sig-bin` (`seam-request-call-v1`) from the cached ticket.

**No credentialed verb retries.** That is 16 verbs in each client.

| Kind | Python verb (`client.py` line) |
|---|---|
| Bodyless read | `get_escalation` :396 |
| Bodyless read | `session_status` :892 |
| Bodyless read | `get_decision` :909 |
| Bodyless read | `replay_decision` :931 |
| Bodyless read | `get_commitment_proof` :1093 (called by `verify_decision` :1110) |
| Bodied write | `open_session` :530 |
| Bodied write | `submit_proposal` :567 |
| Bodied write | `submit_vote` :595 |
| Bodied write | `submit_evaluation` :629 |
| Bodied write | `submit_objection` :680 |
| Bodied write | `submit_commit` :715 |
| Bodied write | `submit_approval_request` :761 |
| Bodied write | `submit_ballot` :796 |
| Bodied write | `cancel_session` :858 |
| Bodied write | `expire_session` :875 |
| Bodied write | `report_outcome` :948 |

TS has the same 16 verbs at `ts/src/client.ts:869-1282`.

**Identity.** `load_identity_file` (`python/seam_sdk/identity.py:57-105`) works in this order:
1. Resolve the path or env pointer, then parse the JSON object (:59-75).
2. Check `version` (:77-80).
3. Check that `seed_hex` is a string of length 64 (:81-85). Decode it with `bytes.fromhex` (:86-89).
   Require 32 bytes (:90-93).
4. Check the required fields (:95-99).
5. Return `LoadedIdentity(agent=Agent(seed), ...)`. The AID is a property of the held `Agent`
   (:46-48).

The file stores **no public key and no AID**: `create_identity_file` writes five keys (:132-144). An AID
is `"aid:pubkey:ed25519:" + b64url(pubkey)` (`python/seam_sdk/crypto.py:36-38`), which is the public
half itself.

Every parser ignores unknown keys:

| Language | Parser | Ignore-unknown-keys promise |
|---|---|---|
| Python | `identity.py:77-95` | :10 |
| TS | `ts/src/identity.ts:109-141` | :8 |
| Go | `go/identity/identity.go:84-110` | :6 |
| Java | `java/.../IdentityFile.java:112-148` | — |
| Kotlin | `kotlin/.../IdentityFile.kt:85-110` | — |

The schema exists in all five languages (`COMPATIBILITY.md:212-219`).

### Which languages are in scope

| Surface | Python | TS | Go / Java / Kotlin |
|---|---|---|---|
| `authorize` refresh-once | yes | yes | **No client, so nothing to extend.** See `go/crypto/agent.go:105-107`, `java/.../RequestCredentials.java:25-26`, and `DECISIONS.md:2660` ("Go, Java and Kotlin have no admission or retry logic"). |
| Bootstrap-file loader | yes | yes | yes, so the facts loader and the `aid` key go in all five |

B-SDK-REFRESH covers Python (sync and aio) and TS. Go, Java and Kotlin only sign: their
`RequestCredentials` takes a ticket the caller supplies, and the caller's own transport owns
admission and refresh. Adding a refresh there would be a new feature, not parity.

### What the runtime guarantees (the retry-safety evidence)

This section is a behavioural read of runtime handler ordering, not a transcription of a digest
construction. The clean-room rule (`PROGRESS.md`, previous plan's header) is not implicated. Where a
published spec says the same thing, it is cited first. All runtime paths are relative to the
seam-runtime root at `origin/main`.

1. **A refused credential has no effect.**
   - The credential is resolved in a tower layer in front of every data-plane service. Its
     `resolve()` runs before `inner.call`, and on refusal it returns without calling the handler
     (`crates/seamd/src/grpc_credential.rs:260-264`, wired at `crates/seamd/src/grpc.rs:146-149`).
   - So session lookup, the engine step, the audit append, the outbox and the budget debit are all
     unreachable on a refused ticket.
2. **The replay digest is burned in that same layer, before the handler runs.**
   - Path: `prove_request_subject` (`crates/seamd/src/grpc_credential.rs:370`) calls the
     `replay_guarded` block (`crates/seamd/src/authorize.rs:1589-1629`).
   - Consequence: a credentialed write whose handler then fails (for example `FAILED_PRECONDITION`)
     has still spent its signed bytes. Any resend must be re-signed under a different ticket.
3. **Every ticket failure is `UNAUTHENTICATED` with one byte-identical message**
   (`docs/specs/authorize.v1.md:412-414`). The SDK cannot tell which reason caused it, and must not
   try.
4. **Some `UNAUTHENTICATED` causes cannot be fixed by a new ticket:**
   - `missing_subject` (`crates/seamd/src/facade.rs:37`, used at :992).
   - "not authorized for this decision" for an out-of-scope or absent decision
     (`crates/seamd/src/facade.rs:998,1038,1133`). No equivalent "…for this session" message exists.
   - `GetEscalation` out of scope or with no subject (`docs/specs/authorize.v1.md:360`).
   - `OpenSession`'s own presentation failure (`crates/seamd/src/grpc.rs:1404-1409`). Its challenge
     is single-use (`crates/seam-trust-aitp/src/lib.rs:935-954`).
5. **A ticket can be refused before its own expiry.**
   - There is no revocation list (`docs/specs/authorize.v1.md:74-78`).
   - Early refusal comes from an issuer-key change, or a malformed or corrupted ticket.
   - The clock grace is **one-sided**: it only extends past expiry, `now - 30s >= expires_at_ms`
     (`crates/seamd/src/authorize.rs:100,479`). The spec's "±30s" wording overstates it.
   - The early-refusal case is the one this ask exists for.
6. **Credentialed writes are single-use** (#1204, #1218; `docs/specs/authorize.v1.md:669-685`).
   - Covered: `OpenSession`, the `Submit*` verbs, `CancelSession` and `ExpireSession`.
   - `ReportOutcome` is exempt (:682-685). It is idempotent on its signed `idempotency_key`, durably
     deduped (#1154). The reads are also exempt.
   - The client consequence is stated at :687-691: *"A client that retries a credentialed write after
     a lost response must `Admit` a new ticket and re-sign."*
   - A re-sign under a new ticket passes the guard, because the ticket bytes are framed inside the
     signed `request_sig_payload` (`crates/seamd/src/authorize.rs:572`).
7. **Submit envelopes are content-addressed and deduped by the engine** (runtime behaviour, not
   published contract).
   - The id is `message_id = SHA-256(session_id ‖ sender ‖ message_type ‖ payload)`, truncated to 16
     bytes (`crates/seam-coord-macp/src/lib.rs:317-327`).
   - The vote payload is `VotePayload {proposal_id, vote, reason}` (:744-757).
   - The envelope `timestamp_unix_ms` is a constant `0` (:344).
   - The live step maps `Precheck::Duplicate` to `StepDisposition::Duplicate` (:1781). The
     precondition internals live in the external `macp_modes` crate and are **unverified at
     source**; they are pinned instead by the runtime test `duplicate_vote_reports_duplicate`
     (lib.rs ~:6200).
   - `crates/seamd/src/session.rs:1787-1806` (#1351) handles a `Duplicate`. It records no budget
     debit, no tally bump and no explanation entry, and it returns
     `SessionStep {state, decision_id: None, policy_enforcement: None, collective_outcome: None}`.
     This is pinned by `duplicate_vote_does_not_debit_or_tally` (~:9447).
   - `SessionStep` has no disposition field (`crates/seam-api/proto/seam/api/v1/seam.proto:861`).
   - Its comment names "a byte-identical retry" of a client as the case it exists for.
   - **The duplicate → none path applies only while the session is unsealed.** Once a step has sealed
     the session (resolved, cancelled or expired by a client call), every later submit takes the
     sealed early return before the engine runs (`crates/seamd/src/session.rs:1563-1580`). That
     return gives:
     - `Ok(SessionStep {decision_id: Some(sealed id), collective_outcome: None, ...})`;
     - `policy_enforcement` only if `s.sealed_attestable`.
   - **Two terminal cases are errors instead** (`session.rs:1541-1561`), both `FAILED_PRECONDITION`
     (`session_not_open`):
     - a session sealed by the sweeper (`s.swept`);
     - a session whose Expire or Cancel terminal seal is still pending.
8. **A vote reason is scanned before the engine runs.**
   - A non-empty `reason` goes through `boundary_dispatch` before the engine
     (`crates/seamd/src/session.rs:2808-2817`).
   - A guard finding appends one `boundary.data_flagged` audit entry per call
     (`crates/seamd/src/boundary.rs:158-290`), even on a resend that the engine later dedupes.

### Why `submit_*` retry is safe, and what it changes

**Within one SDK call.**
- A retry after `UNAUTHENTICATED` cannot double-apply that call's own attempt, because a refusal has
  no effect (fact 1).

**Across calls.**
1. An application's write lands, but the response is lost.
2. The application resends the same verb with the same body while the SDK still caches the same
   ticket.
3. The runtime refuses the resend as `request_replayed` (fact 6, which surfaces as
   `UNAUTHENTICATED`).
4. With this plan, the SDK re-admits, re-signs and resends.
5. The engine dedupes the resend (fact 7) and returns success with no second effect.

That is the same path the spec prescribes for the application itself (`authorize.v1.md:687-691`). So
invalidate-then-raise is not materially safer. The caller's own retry would cross identical bytes and
reach the identical dedupe.

**Two observable differences belong in the docs:**
- **A resend of a resolving step loses `collective_outcome`, and possibly `policy_enforcement`.**
  The first attempt sealed the session, so the resend takes the sealed early return (fact 7). It
  returns:
  - `decision_id`: the sealed id;
  - `collective_outcome`: unset;
  - `policy_enforcement`: present only if `sealed_attestable`.

  The caller must read `get_decision` for the outcome. A duplicate of a **non-resolving** step, in a
  session that is still unsealed, returns `decision_id`, `collective_outcome` and
  `policy_enforcement` all unset (that is expected, since no decision exists yet).
- **A deduped resend whose `reason` trips the boundary guard adds one more `boundary.data_flagged`
  audit row** (fact 8). The same is already true of a resend issued by the application.

## Decisions

All of the following are **DECIDED**. The Phase work logs each one to `DECISIONS.md` (Chose,
Alternatives, Blast radius, Status) in the phase that implements it.

| ID | Decision | Reversibility |
|---|---|---|
| D-READ-RETRY | Refresh once and retry once on `UNAUTHENTICATED` for the five bodyless reads (`get_escalation`, `session_status`, `get_decision`, `replay_decision`, `get_commitment_proof`, and so `verify_decision`) **and `report_outcome`** (idempotent by published contract and exempt from the replay guard, fact 6). | Reversible |
| D-NO-CRED-NO-RETRY | Without a resolved credential (no `credential=` and no bound agent) there is no ticket, so there is **no refresh**. | Reversible |
| D-SUBMIT-RETRY | **YES.** The seven `submit_*` verbs get the same refresh-once (reasoning: facts 1, 2, 6, 7 and the section above). The helper keeps a `retry` flag, so the behaviour can be flipped back to "invalidate then raise" without an API change. | Reversible (observable, so a flip back is a CHANGELOG "Changed") |
| D-WRITES-EXCLUDED | `open_session`, `cancel_session` and `expire_session` get **no** retry. None was asked for. `open_session`'s `UNAUTHENTICATED` may be its single-use presentation (fact 4), which a ticket refresh does not fix. A repeated terminal transition has no dedupe evidence. | Reversible (adding later is additive) |
| D-AID-RECORD | **YES.** `create_identity_file` also writes `"aid"` (the derived AID, last key), and the schema `version` stays 1. Readers verify `aid` **only when it is present**. Every existing parser ignores unknown keys (see Context, Identity), so new files load in every old release. | On-disk one-way door, but additive and ignorable |
| D-FACTS-API | New public names. The fields are `agent_id`, `tenant`, `endpoint` and `aid`, with **`aid` a required string**. | One-way door (public API) |
| D-LEGACY-AID | The facts loader **always** returns `aid` as a string. It is the recorded `aid` when present (Phase 3 is landed and the key exists). That value is an **unverified file claim**, and the full loader is the verifier. Otherwise the facts loader derives the AID transiently from the seed: it computes the public key, discards the signing key, and returns no `Agent` or signing capability. | Reversible |
| D-FACTS-CHECKS | The facts loader and the full loader share one validator, so both run the same checks **in the same order** with the same messages (Phase 4 Approach). | Reversible |

The D-FACTS-API names by language:

| Language | Loader | Return type |
|---|---|---|
| Python | `load_identity_facts` | `IdentityFacts` |
| TS | `loadIdentityFacts` | `IdentityFacts` |
| Go | `identity.LoadIdentityFacts` | `*IdentityFacts` |
| Java / Kotlin | `IdentityFile.loadFacts` | `IdentityFacts` |

**Why D-LEGACY-AID derives.** seam-adapters' in-progress `bootstrap_facts` (branch
`feat/mcp-post-onboarding`, `core/seam_agent_core/identity.py:209-256`) returns a required `aid: str`,
and it promises to delegate to #274 with the same signature. The ask's acceptance criterion is "agrees
with `load_identity_file` on every field". Returning none for every pre-Phase-3 file would fail both.

**What "seed-free" honestly means.**
- It does not mean "the seed is never read": `json.load` already materialises `seed_hex` as a string.
- What it guarantees:
  - **No signing capability is returned**, in any form.
  - **On a file that records `aid`, the seed is never hex-decoded.**
- Phase 3 is therefore the fast, seed-decode-free path. Phase 4 no longer strictly needs it.

## Phases

The phases ship in order 1 → 2 → 3 → 4, and each one can also ship alone. PR grouping:
- Phases 1 and 2 are either one PR (#275) or two.
- Phases 3 and 4 are one PR (#274), or Phase 4 can ship alone.

Python and TS change together within a phase. Both are published clients version-locked by
`version-lockstep`, and per-language phases would ship a release in which "the SDK" retries in one
language but not the other.

---

### Phase 1: Refresh-once on credentialed reads and `report_outcome` (Python sync and aio, TS)

- **Status:** DONE (2026-10-19). Matches the plan. `retry=False` is implemented as invalidate-then-raise, ready for the Phase 2 flip-back path. Moving the CHANGELOG entry shifted `CHANGELOG.md:N` citations, including inside old DECISIONS entries; this is the release tooling's own shift.
- **Risk:** complex
- **Delivers:** the read half of #275. These verbs each recover from one rejected ticket through the
  existing coalesced `_refresh_ticket` / `refreshTicket`, retrying exactly once:
  - `session_status`
  - `get_decision`
  - `replay_decision`
  - `get_commitment_proof` (so `verify_decision` too)
  - `get_escalation`
  - `report_outcome`

  A second rejection propagates as `UnauthenticatedError`.
- **Depends on:** nothing.
- **Files:**
  - `python/seam_sdk/client.py`
  - `python/seam_sdk/aio.py`
  - `python/seam_sdk/errors.py`
  - `ts/src/client.ts`
  - `ts/src/errors.ts`
  - `python/tests/test_credential_refresh.py` (new)
  - `python/tests/test_authorize.py` (the `FakeSeam` coordination handlers)
  - `python/tests/test_ticket_lifecycle.py` (the `busy_server` coordination handlers)
  - `ts/tests/unit_plumbing.test.ts`
  - `README.md`, `COMPATIBILITY.md`, `CHANGELOG.md`, `DECISIONS.md`, `ASSUMPTIONS.md`
- **Approach:**
  - **Python helper.** Add one private helper per client:
    `_credentialed_call(credential, rpc_full_name, resource_id, body, send, *, timeout, retry=True)`,
    plus an `async` twin.
    1. Resolve the credential (the explicit one, else `self._agent`). With neither, return
       `send(None)` and never retry (D-NO-CRED-NO-RETRY).
    2. Get the ticket from `_ticket_for`, build the metadata with `credential_metadata`, then
       `send(md)`.
    3. On `UnauthenticatedError` with `retry`, refresh: `ticket = self._refresh_ticket(cred, ticket, timeout)`.
    4. Rebuild the metadata **over the same `body` object** and `send(md)` once more.
  - **`_credential_md`.** It stays for the verbs that do not retry. Refactor it so both paths share
    one resolve-and-sign step.
  - **TS helper.** `credentialedCall(...)` has the same shape over `credentialHeaders`. Ticket
    acquisition must be split out of header building, so that `refreshTicket(agent, failed, opts)`
    receives the ticket that actually failed.
  - **Why one helper.** It puts the retry rule in one place per client, and Phase 2 becomes a
    call-site switch.
  - **Rejected alternatives:**
    - Retrying inside `_MappedStub`: it cannot see the agent, the ticket or the body, and it would
      silently extend retry to every verb.
    - A gRPC interceptor: it has the same blindness and would re-sign nothing.
- **Edge cases and failure modes:**
  - **A handler-level `UNAUTHENTICATED` that refresh cannot fix** (fact 4).
    - The call pays one admit (challenge plus `Admit`, 2 RPCs) and one retry, then raises typed.
      That is at most 6 wire calls, the same as `authorize`.
    - A caller polling an out-of-scope id re-admits on every call. Document this.
    - Do not add a negative cache. The runtime makes scope refusals and ticket refusals
      indistinguishable on purpose.
  - **Concurrent mass rejection.** N in-flight calls trigger **one** re-admit (adopt-if-different).
    This includes an `authorize` and a read refreshing the same AID at once, because both go through
    the same per-AID lock and cache.
  - **Explicit `credential=` on a bound client.** The retry refreshes the ticket of the signer, never
    the ticket of `self._agent`.
  - **aio cancellation mid-refresh.** No new state is held across the retry await, and the cache is
    mutated only synchronously (`aio.py:5-7`). A task cancelled during the re-admit therefore leaves
    the cache **empty** (it was invalidated before the await), and the next call re-admits.
  - **`report_outcome`.** The same `req` and `idempotency_key` are re-signed. If the first attempt
    had landed, the resend is a runtime no-op.
  - **Deadline.** `timeout` stays per-RPC, so the worst case per credentialed read becomes 6×.
  - **A non-`UNAUTHENTICATED` error** (`NOT_FOUND`, `PERMISSION_DENIED`, `DEADLINE_EXCEEDED`)
    propagates without a refresh.
  - **The refresh's own `Admit` fails** (for example `UNAVAILABLE` / `CHALLENGE_REFUSED`). That error
    propagates typed, never looped (`DECISIONS.md` 2026-10-18, "A load-shed is surfaced, never
    retried").
- **Acceptance criteria (falsifiable).** The baseline for every criterion: the client starts with a
  **pre-seeded, live ticket** for the AID, so the first call makes no admission. "One extra admit"
  means exactly **two** admission RPCs (challenge plus `Admit`).
  1. **Recovery.** The ticket is rejected once, then the server accepts. For each of the six verbs, in
     Python sync, Python aio and TS:
     - the call returns the server's response;
     - the server saw exactly **two** calls of that RPC;
     - it saw exactly one extra admit (2 admission RPCs).
  2. **Second rejection.** `UnauthenticatedError` is raised. The RPC was called exactly twice, with
     one extra admit.
  3. **No credential.** An unbound client with no `credential=` raises on `UNAUTHENTICATED` after
     **one** call and **zero** admission RPCs.
  4. **Coalescing.** With N=32 concurrent reads rejected at once, the client makes exactly one extra
     admit, in sync, aio and TS.
  5. **Mixed coalescing.** A concurrent `authorize` and `session_status` on the same AID, both
     rejected, produce exactly one extra admit.
  6. **Re-signing.** The retried call's `x-seam-ticket-bin` is the new ticket. Its
     `x-seam-call-sig-bin` verifies under the new ticket via `request_sig_payload` and does **not**
     verify under the old one.
  7. **`report_outcome` body.** Both attempts carry byte-identical serialized bodies.
  8. **Cancellation (aio).** Cancelling the task during the refresh `Admit` leaves `_tickets[aid]`
     empty, and the next call admits afresh and succeeds.
  9. **Public surface.** `python/tests/test_client_parity.py` stays green (no public verb added).
  10. **Writes unchanged.** All 10 write verbs still make exactly **one** call on `UNAUTHENTICATED`.
      Phase 2 narrows this guard.
- **Tests:**
  - **Unit, Python.** Extend the `_Recorder` / `_AioRecorder` pattern
    (`python/tests/test_credential_wiring.py:47,65`) with a scripted first `UNAUTHENTICATED`.
    Pre-seed `_tickets`, and count admission calls.
  - **Real-gRPC fakes need work.** `FakeSeam` (`python/tests/test_authorize.py:46`) and `busy_server`
    (`python/tests/test_ticket_lifecycle.py:46-47`) implement **only** Admission and Authorization,
    so this phase adds coordination handlers:
    - `SessionStatus`, `GetDecision` and `ReportOutcome` get a `fail_next_unauthenticated` switch.
    - They are registered with `add_SeamCoordinationServicer_to_server`.
    - The typed-error mapping is then exercised end to end, and criteria 4, 5 and 8 run on real
      gRPC.
  - **Failure paths:**
    - a double rejection;
    - an unbound call with no retry;
    - `NOT_FOUND` not retried;
    - a failure of the refresh `Admit`;
    - aio cancellation mid-refresh;
    - the guard that writes are not retried.
  - **Unit, TS.** Extend `ts/tests/unit_plumbing.test.ts`: the fake throws
    `new UnauthenticatedError(...)` (:244), and `deferRejections` (:248) drives the concurrent and
    mixed `authorize` cases.
  - **Live.** `python/tests/test_integration.py:326` (the deny-plane credentialed read) corrupts the
    cached ticket's last byte and asserts that the read still succeeds.
- **Docs** (the "never retries" claims become stale):
  - `python/seam_sdk/client.py:85-107` (`DEFAULT_TIMEOUT_S` note; :106 "never retries beyond that
    single ticket refresh"): extend the six-call bound to credentialed reads.
  - `python/seam_sdk/aio.py:3-4`.
  - `python/seam_sdk/errors.py:467` ("The SDK itself never retries"): say "never retries a load-shed".
  - `ts/src/client.ts:60-75`.
  - `ts/src/errors.ts:282`.
  - `README.md:502-504` describes `authorize`'s refresh, which is not a "never retries" claim. Extend
    it to name the newly covered verbs.
  - `DECISIONS.md:2660` and `ASSUMPTIONS.md:1423` ("never retries at all") get **new superseding
    entries** that cite these lines. The old entries are not edited.
  - `COMPATIBILITY.md`: a new behaviour row (Python and TS yes; Go, Java and Kotlin N/A, no client).
  - `CHANGELOG.md` `## Unreleased`, "### Changed": credentialed reads and `report_outcome` refresh a
    rejected ticket once (#275).

---

### Phase 2: Refresh-once on the seven `submit_*` verbs (Python sync and aio, TS)

- **Status:** TODO
- **Risk:** complex
- **Delivers:** the rest of #275.
  - These seven verbs route through `_credentialed_call` with `retry=True`: `submit_proposal`,
    `submit_vote`, `submit_evaluation`, `submit_objection`, `submit_commit`,
    `submit_approval_request` and `submit_ballot`.
  - `open_session`, `cancel_session` and `expire_session` stay on the no-retry path
    (D-WRITES-EXCLUDED).
- **Depends on:** Phase 1 (the helper).
- **Files:**
  - `python/seam_sdk/client.py`
  - `python/seam_sdk/aio.py`
  - `ts/src/client.ts`
  - `python/tests/test_credential_refresh.py`
  - `python/tests/test_integration.py`
  - `ts/tests/unit_plumbing.test.ts`
  - the TS live suite
  - `README.md`, `COMPATIBILITY.md`, `CHANGELOG.md`, `DECISIONS.md`
- **Approach:**
  - Switch the seven call sites to the helper, passing the already-built `req`. The retry re-signs
    **the same message object**.
  - Safety rests on facts 1, 2, 6 and 7, and on the cross-call analysis in Context.
  - Log D-SUBMIT-RETRY to `DECISIONS.md` with that reasoning.
  - **Rejected alternatives:**
    - **"Invalidate then raise".** Not materially safer: the caller's retry crosses the identical
      path. It remains reachable as `retry=False`.
    - **No retry and no invalidate.** The dead ticket stays cached until 80% of its TTL, up to about
      240 s on the 300 s default, so every write fails for that long while reads self-heal.
    - **Detecting `request_replayed` in the client.** The uniform message removes that oracle
      (fact 3).
- **Edge cases and failure modes:**
  - **The laundering path.** The app resends after a lost response; the runtime answers
    `request_replayed`; the SDK refreshes and resends; the engine dedupes the resend. The caller gets
    success with no second effect.
  - **A resend after a resolving step returns `collective_outcome` unset.**
    - Once the first attempt sealed the session, the resend hits the sealed early return
      (`session.rs:1563-1580`). It returns `decision_id` = the sealed id, `collective_outcome` unset,
      and `policy_enforcement` only if `sealed_attestable`.
    - The duplicate → all-none path applies only while the session is unsealed (a non-resolving
      step).
    - `SessionStep` has no disposition field (fact 7), so the response cannot tell "deduped" from
      "applied".
    - Document on every `submit_*`: after a retried write, read `get_decision` for the outcome.
  - **`usage` is not in the hashed payload.**
    - `VotePayload` is `{proposal_id, vote, reason}`, and `timestamp_unix_ms` is `0` (fact 7).
    - So a resend that differs **only in `usage`** is still a duplicate. It is deduped and **not
      debited**, and the second `usage` is silently dropped.
    - A changed `reason` (or a changed `proposal_id` / `vote`) is a new message.
    - Document both.
  - **An extra audit row from the boundary guard.** A deduped resend whose `reason` trips the guard
    appends one more `boundary.data_flagged` audit entry (fact 8). This is already true of resends
    from the application. Document it; it is not a correctness issue.
  - **A failed handler has still burned its digest** (fact 2). This is harmless here, because the
    retry is always under a new ticket.
  - **The session becomes terminal before the retry.** The outcome depends on how it became
    terminal (`session.rs:1541-1580`):
    - **Sealed by a client call** (resolved, cancelled or expired): the retry returns `Ok`, with the
      sealed `decision_id` and `collective_outcome` unset. It is not an error.
    - **Swept** (`s.swept`), or with an Expire/Cancel **terminal seal pending**: `FAILED_PRECONDITION`
      (`session_not_open`) propagates typed. Nothing is applied.
  - **Serialization drift between the two attempts.** None of the seven requests has a map field.
    Tests assert byte-equality of `SerializeToString()` / `toBinary`, so a future map field fails
    loudly.
- **Acceptance criteria:**
  1. **Phase 1 criteria.** Criteria 1, 2 and 4 hold for each of the seven verbs in all three clients,
     with the same baseline (a pre-seeded ticket; one extra admit = 2 RPCs).
  2. **Body and signature.** The serialized bodies of the two attempts are byte-identical, and their
     `x-seam-call-sig-bin` values differ.
  3. **Excluded verbs.** `open_session`, `cancel_session` and `expire_session` still make exactly one
     call on `UNAUTHENTICATED`.
  4. **Live, against `seamd` in the credential-only posture** (`python/tests/test_integration.py`
     and the TS live suite):
     - **(a)** A `submit_vote` sent with a corrupted cached ticket lands exactly once:
       `session_status` shows the tally +1, and the budget is debited once.
     - **(b)** An app-level resend of the **same** vote under the same ticket returns success. The
       tally and budget are unchanged.
     - **(c)** The same as (b), but with a **different `usage`**: still deduped, and the budget is
       unchanged.
     - **(d)** A **resolving** vote is resent the same way. The first call returns a `decision_id`
       and a `collective_outcome`. The resend returns the **same** `decision_id` with
       `collective_outcome` unset. `policy_enforcement` is asserted present iff the first response
       carried it **and** the session is `sealed_attestable`; otherwise unset. `get_decision` still
       returns the sealed record.
- **Tests:**
  - **Unit.** Mirror Phase 1 for the seven verbs, and narrow the Phase 1 guard to the three excluded
    verbs.
  - **Live.** Criterion 4 (a) to (d).
  - **Failure paths:**
    - a double rejection;
    - a failure of the refresh `Admit`;
    - an excluded verb is not retried.
    - `test_submit_retry_after_client_seal_returns_sealed_id`: the session is cancelled between the
      rejection and the retry. Assert `Ok`, the sealed `decision_id`, and `collective_outcome` unset.
    - `test_submit_retry_after_sweeper_expiry_raises_failed_precondition`: the session is swept
      between the rejection and the retry. Assert `FailedPreconditionError` (the SDK's
      `FAILED_PRECONDITION` type) with the "sealed by the session sweeper" message.

      This case is live-only. If the harness cannot force a sweep in time, this test is skipped with
      that reason; it is not dropped silently.
- **Docs:**
  - The `submit_*` docstrings (Python and TS) get one shared paragraph covering:
    - a retry-safe identical body;
    - `usage` is not part of identity;
    - a resend after a resolving step returns the sealed `decision_id` but **no
      `collective_outcome`** (and `policy_enforcement` only if attestable), so read `get_decision`;
    - a duplicate of a non-resolving step returns all three fields unset;
    - the possible extra `boundary.data_flagged` row.
  - The README retry paragraph.
  - A `COMPATIBILITY.md` row.
  - `CHANGELOG.md` `## Unreleased`.
  - A `DECISIONS.md` D-SUBMIT-RETRY entry.

---

### Phase 3: Record the AID in the bootstrap file and verify it on load (all five languages)

- **Status:** TODO
- **Risk:** complex
- **Delivers:**
  - A bootstrap file that carries its own public identity, so Phase 4 can return the AID without
    decoding the seed.
  - Full loaders that refuse a file whose recorded `aid` disagrees with its seed.
- **Depends on:** nothing.
- **Files:**
  - Python: `python/seam_sdk/identity.py`, `python/tests/test_identity_file.py`.
  - TS: `ts/src/identity.ts`, `ts/tests/identity_file.test.ts`, and a new fixture
    `ts/tests/fixtures/identity_v1_aid_python.json`. The existing `identity_v1_python.json` stays as
    the legacy case.
  - Go: `go/identity/identity.go`, `go/identity/identity_test.go`.
  - Java: `java/src/main/java/com/zer07labs/seam/IdentityFile.java`,
    `java/src/test/java/com/zer07labs/seam/IdentityFileTest.java`.
  - Kotlin: `kotlin/src/main/kotlin/com/zer07labs/seam/IdentityFile.kt`,
    `kotlin/src/test/kotlin/com/zer07labs/seam/IdentityFileTest.kt`.
  - Docs: `COMPATIBILITY.md`, `CHANGELOG.md`, `DECISIONS.md`.
- **Approach:**
  - **Writers.** Every `create` appends `"aid"` after `endpoint`. Key order is preserved, because TS
    pins Python's exact bytes.
  - **Readers, when `aid` is present.** It must match `^aid:pubkey:ed25519:[A-Za-z0-9_-]{43}$` and
    equal the seed-derived AID. Otherwise raise `IdentityFileError`:
    - a wrong shape gives `"aid is malformed"`;
    - a mismatch gives `"recorded aid does not match seed_hex"`.
  - **Readers, when `aid` is absent.** Behaviour is unchanged.
  - **The schema version stays 1.** Every parser ignores unknown keys (Context, Identity), so a new
    file loads in every release since #201.
  - **Why `aid` and not `public_key_hex`.** An AID *is* the encoded public key
    (`crypto.py:36-38`). It is the value consumers display, and reading it back needs no crypto.
  - **Rejected alternatives:**
    - **A version-2 schema.** It breaks every older loader for an additive fact.
    - **A sidecar `.pub` file.** That is a second custody artefact.
    - **A backfill rewrite.** See Open question 3.
- **Edge cases and failure modes:**
  - **A hand-edited `aid`.** The full loader refuses it. The Phase 4 facts loader returns it as the
    file's (unverified) claim.
  - **A non-string or empty `aid`.** Refused as malformed.
  - **A legacy file.** It loads unchanged and is never rewritten.
  - **Python's looser field typing** (`not data.get(k)`, then `str(...)`) is not changed here. It is
    recorded as an observed divergence (Open question 4).
- **Acceptance criteria:**
  1. **Created files.** In each language, a newly created file contains `aid` equal to the returned
     AID.
     - **Byte-equality with `identity_v1_aid_python.json` applies to Python and TS only.**
       - Python writes the fixture.
       - TS reproduces it from a fixed seed via `identityFileBody` (`ts/src/identity.ts:142`).
     - `ts/tests/identity_file.test.ts:103` (the exact key list) becomes `[..., "endpoint", "aid"]`,
       and `:226` (the byte layout) is updated.
     - **Go, Java and Kotlin assert key order** (`version, seed_hex, agent_id, tenant, endpoint, aid`)
       **and the `aid` value**, not bytes. Their serializers differ in escaping and whitespace:
       - Go uses `json.MarshalIndent` (`go/identity/identity.go:140`).
       - Java and Kotlin use Gson `setPrettyPrinting().disableHtmlEscaping()`
         (`IdentityFile.java:191`, `IdentityFile.kt:150`).
  2. **Mismatch.** All five full loaders refuse a file whose `aid` does not match its seed, with the
     message above.
  3. **Legacy files.** `identity_v1_python.json` still loads, with an unchanged AID.
  4. **Backward compatibility, checkable.**
     - The test extracts `python/seam_sdk/identity.py` from `f1d112d` with
       `git show f1d112d:python/seam_sdk/identity.py`.
     - At `f1d112d`, `identity.py:25` is `from .client import Agent`, a relative import. So the test
       loads the extracted file with `importlib.util.spec_from_file_location("seam_sdk._identity_f1d112d", tmp_path)`.
       That makes it a submodule of the installed `seam_sdk` package, and `.client` resolves to the
       current `seam_sdk.client`.
     - It `exec_module`s it, then removes the name from `sys.modules` on teardown.
     - It loads `identity_v1_aid_python.json` through it.
     - It asserts the agent's AID equals the fixture's `aid`.
     - If `git` history is unavailable (shallow CI clone), the test skips, and CI fetches depth ≥ the
       tag.
     - The alternative is a pinned 0.48.1 wheel in a throwaway venv. The `git show` route is preferred
       because it needs no network.
- **Tests:**
  - Extend all five identity-file suites.
  - Keep the existing `0600`, symlink, no-clobber and `umask(0)` cases green and unchanged.
  - **Failure paths:**
    - a mismatched `aid`;
    - a malformed `aid`;
    - an empty `aid`;
    - a non-string `aid`.
- **Docs:**
  - The schema line in `python/seam_sdk/identity.py:8` and its four twins.
  - `COMPATIBILITY.md:212-219`.
  - `CHANGELOG.md` `## Unreleased` ("### Changed": new files record `aid`).
  - A `DECISIONS.md` D-AID-RECORD entry.
  - Tell seam-adapters (#262) that the schema gained an optional key.

---

### Phase 4: A seed-free identity-facts loader (all five languages)

- **Status:** TODO
- **Risk:** complex
- **Delivers:** #274.
  - A new loader in each language, `load_identity_facts(path=None) -> IdentityFacts` and its four
    twins (D-FACTS-API).
  - It returns `agent_id`, `tenant`, `endpoint` and `aid: str` after the same checks as the full
    loader.
  - It never returns, or constructs, an `Agent` or any signing key.
- **Depends on:** nothing.
  - With Phase 3, files that record `aid` are served without hex-decoding the seed.
  - Without Phase 3, the loader derives `aid` from the seed for every file (D-LEGACY-AID).
- **Files:**
  - Python: `python/seam_sdk/identity.py`, `python/seam_sdk/__init__.py` (exports and `__all__`),
    `python/tests/test_identity_file.py`.
  - TS: `ts/src/identity.ts`, `ts/src/index.ts`, `ts/tests/identity_file.test.ts`.
  - Go: `go/identity/identity.go`, `go/identity/identity_test.go`.
  - Java: `java/.../IdentityFile.java`, `java/.../IdentityFileTest.java`.
  - Kotlin: `kotlin/.../IdentityFile.kt`, `kotlin/.../IdentityFileTest.kt`.
  - Docs: `COMPATIBILITY.md`, `README.md`, `CHANGELOG.md`, `DECISIONS.md`.
- **Approach.** Each language splits a shared validator out of the full loader:
  `_read_and_validate(resolved)`. Its order is **the full loader's order** (`identity.py:57-99`), so
  both loaders report the same error for the same bad file:
  1. Resolve the path or env pointer, read the file, parse the JSON, and require an object.
  2. Check `version == 1`.
  3. **Check `seed_hex` before the fields.**
     - It must be a string with `len == 64`. Otherwise raise
       `"seed_hex must be exactly 64 hex chars (a 32-byte Ed25519 seed)"`.
     - It must match `^[0-9a-fA-F]{64}$`. Otherwise raise `"seed_hex is not valid hex"`.
     - No bytes are produced.
  4. Check the required fields `agent_id`, `tenant` and `endpoint`. The message is unchanged.
  5. **Only if Phase 3 has landed:** validate the shape of a present `aid` (Phase 3's regex and
     message).
     - Before Phase 3, this step does not exist, and both loaders keep ignoring an `aid` key.
     - Otherwise, a Phase-4-only release would start refusing files that carry an unrelated `aid`
       key, which loaders ignore today.

  The validator returns the dict with `seed_hex` as an opaque string. Then:
  - **The full loader** decodes the seed through one module-level `_decode_seed(seed_hex)`, builds
    the `Agent`, and (with Phase 3) cross-checks a present `aid`.
  - **The facts loader** returns:
    - the recorded `aid` if it is present (with Phase 3), as an **unverified claim**;
    - otherwise `_derive_aid(seed_hex)`. That calls `_decode_seed`, derives the public key, encodes
      the AID, and returns only the string; the private key goes out of scope.

  The return type differs per language:
  - Python: a frozen dataclass.
  - TS: a readonly class with `toJSON`.
  - Go: a struct.
  - Java: a record.
  - Kotlin: a data class.

  None has a seed field, and its `repr` / `toString` names only the four fields.

  **Message change (stated).** Today a 64-character `seed_hex` containing whitespace (for example
  `"00 " * 21 + "0"`) passes the length check. `bytes.fromhex` then accepts it, and the 32-byte check
  fails with `"seed_hex must be exactly 64 hex chars…"` (`identity.py:90-93`). Under the shared regex
  it fails earlier with `"seed_hex is not valid hex"`. It is still an `IdentityFileError`, and only
  the text changes, in both loaders. Python is the only language affected: TS already uses the regex,
  and Go's `hex.DecodeString` refuses whitespace. Record this in CHANGELOG.

  **Rejected alternatives:**
  - **A `facts` property on `LoadedIdentity`.** It still builds an `Agent`.
  - **Returning `aid=None` for legacy files.** This breaks adapters' `aid: str` and the ask's "agrees
    on every field" (D-LEGACY-AID).
  - **Skipping the `seed_hex` checks.** The facts loader would then bless a file the full loader
    refuses.
  - **Verifying the recorded `aid` in the facts loader.** That needs the seed decode the fast path
    exists to avoid. The full loader is the verifier.
- **Edge cases and failure modes:**
  - **No path and no env.** Same error as the full loader.
  - **Symlinks and modes.** Follow and do not check, the same as the full loader (Open question 5).
  - **A recorded `aid` that does not match its seed.** The facts loader returns the claim, and the
    full loader refuses the file. Document the claim-versus-verifier split in the docstring.
  - **seam-adapters core alignment.** The core's `bootstrap_facts` currently checks the fields before
    `seed_hex`. Aligning it to this order is seam-adapters' change on #262, not a write in this repo.
    Note it on #262.
- **Acceptance criteria:**
  1. **No signing capability.**
     - The returned object has no `seed`, `agent`, private-key or signing attribute in any language.
     - Its `repr` / `toString` contains no 64-hex run.
     - In Python, `Agent` is patched to raise, and `load_identity_facts` still succeeds on the legacy
       file. **When Phase 3 has landed**, it also succeeds on a Phase-3 file. When Phase 4 ships
       alone, only the legacy file is used.
  2. **No decode on Phase-3 files (when Phase 3 has landed).**
     - With `_decode_seed` patched to raise, `load_identity_facts` succeeds on a file that records
       `aid`, and `load_identity_file` fails on it.
     - The patched-decoder assertion applies **only** to Phase-3 files. A legacy file necessarily
       decodes the seed to derive `aid`.
     - When Phase 4 ships alone, this criterion is replaced by AC1's legacy-file case. TS uses
     `vi.spyOn`. Go, Java and Kotlin use a test-visible decoder hook.
  3. **Same refusals.** Parametrized over the existing malformed cases
     (`python/tests/test_identity_file.py:155`), **plus** these:
     - the 64-char whitespace seed, which both loaders refuse with exactly `"seed_hex is not valid hex"`;
     - a file with a bad seed **and** missing fields, which both loaders refuse with the **seed**
       message;
     - before Phase 3, a file with a junk `aid` key, which both loaders accept.

     In every case, both loaders raise `IdentityFileError` with an identical message.
  4. **Agreement.** On the legacy fixture, the Phase-3 fixture (if landed) and freshly created files,
     `load_identity_facts` equals `load_identity_file` on **all four** fields, including `aid`.
  5. **Python exports.** `seam_sdk.load_identity_facts` and `seam_sdk.IdentityFacts` are in
     `__all__`.
- **Tests:**
  - The criteria above, in all five suites.
  - **Failure paths:**
    - a missing file;
    - invalid JSON;
    - a wrong version;
    - a short `seed_hex`;
    - a non-hex `seed_hex`;
    - a whitespace `seed_hex`;
    - missing fields;
    - a malformed `aid` (with Phase 3).
- **Docs:**
  - A `COMPATIBILITY.md` identity-table row: "Read bootstrap facts without a signing key (#274)".
  - A line in the `README.md` identity section.
  - `CHANGELOG.md` `## Unreleased`: "### Added" for the loader, "### Changed" for the whitespace
    message.
  - A `DECISIONS.md` D-LEGACY-AID entry.
  - The docstring states that the facts are the file's **claims** and that `load_identity_file` is
    the verifier.

## Long-term posture

**One-way doors:**
- **New public names (D-FACTS-API).** Five languages plus seam-adapters core will depend on them.
  - The field set is part of that contract, including `aid` as a **required** string.
  - Adding a field later is additive. Removing one, or making `aid` optional, is breaking.
- **The on-disk `aid` key (D-AID-RECORD).** Every file created after Phase 3 carries it permanently.
  Every future loader must keep tolerating it, and should keep verifying it.

**Reversible, but observable:**
- **D-SUBMIT-RETRY.** Callers may come to rely on self-healing writes. A flip back through the
  internal `retry` flag is a CHANGELOG "Changed" entry and a minor bump.

**Reversible:**
- the private helper shape;
- the excluded write verbs (adding them later is additive);
- deriving the AID for legacy files;
- the absence of a backfill helper.

**Runtime behaviour relied on.**
- Phase 2 relies on the engine's content-addressed dedupe (fact 7). It is pinned by runtime tests and
  by Phase 2's live criterion 4, so a runtime change that breaks it fails seam-sdk's `integration`
  job first.
- A seam-runtime ask to make the dedupe normative in a spec is optional: file it only if a bug or
  blocker appears.

## Enterprise concerns

- **Security.**
  - No new oracle: the SDK never inspects refusal text.
  - Refresh uses the same admission path as `authorize`.
  - The facts loader returns no signing capability, which shrinks seed exposure for read-only
    consumers (seam-mcp `whoami_agent`).
  - The recorded `aid` is public information.
- **Load and abuse.**
  - Refresh is coalesced per AID, and the worst case per credentialed call is 6 RPCs.
  - A caller polling an out-of-scope id costs one admit per call; this is documented, not cached.
  - Admission load-shed (`CHALLENGE_REFUSED`, `RESOURCE_EXHAUSTED`) surfaces typed from the refresh,
    with no loop.
- **Audit.**
  - A refresh shows server-side as one ticket reject (or `request_replayed`) plus one `Admit`.
  - A deduped submit resend adds no decision-record entry. It may add one `boundary.data_flagged`
    row (Phase 2).
  - The SDK adds no logging of its own.
- **Compatibility.**
  - No runtime change is needed. Phases 1 and 2 work against runtime 0.48.x.
  - Phase 3 files load in every SDK since #201 (0.43.3).
  - `seam.api.v1` is unchanged, so `check-contract` is unaffected.
- **Release.**
  - The version follows the runtime (`scripts/set_version.sh`). Changes land under
    `## Unreleased`.
  - Python and TS stay version-locked.

## Open questions

1. **D-SUBMIT-RETRY: DECIDED, YES** (review round 1). Retrying after a refusal cannot double-apply,
   because the refusal comes before any effect. The re-sign carries the new ticket bytes, so it
   passes the replay guard. An identical body is deduped with no debit or tally. "Invalidate then
   raise" is not materially safer. The decision is flippable behind the `retry` flag. Phase 2 logs it
   to `DECISIONS.md`.
2. **D-AID-RECORD: DECIDED, YES** (review round 1). The key is optional in schema v1, readers verify
   it only when present, and every parser already ignores unknown keys. Phase 3 logs it.
3. **D-LEGACY-AID: DECIDED.** `aid` is always a string, derived transiently when it is not recorded.
   This matches seam-adapters' `bootstrap_facts` signature and the ask's agreement criterion.
   Phase 4 logs it.
4. **Backfill for existing files** (`record_identity_aid(path)`)? **Default: no**, not in this plan.
   Rewriting a secret file is a custody operation that deserves its own issue. Legacy files still get
   a correct `aid` via derivation.
5. **Should the Python full loader's looser field typing** (`str()` coercion) be aligned with TS and
   Go? **Default: out of scope.** Recorded as an observed divergence.
6. **Should either loader check file mode on read?** **Default: no.** Neither loader does today.
7. **Delegation, seam-adapters#261.** Will B-CORE-READS route reads through `seam_sdk.SeamClient` so
   that seam-mcp inherits Phase 1? Not decidable here. Raise it on #261 when Phase 1 merges.
8. **A retry for `open_session`, `cancel_session` or `expire_session`?** **Default: no**
   (D-WRITES-EXCLUDED). Re-open when there is a concrete consumer and dedupe evidence for terminal
   transitions.

## Plan review

**Round 1: REVISE.** The reviewer settled two decisions and found anchor and completeness defects.

- **Decisions settled.**
  - D-SUBMIT-RETRY = YES.
  - D-AID-RECORD = YES.
  - D-LEGACY-AID changed from "`aid` none for legacy files" to "always a string, derived transiently
    when not recorded". The reasons: adapters' `bootstrap_facts` requires `aid: str`, and the ask
    requires agreement on every field.
  - "Seed-free" is restated honestly. It means no signing capability returned, and no hex-decode on
    Phase-3 files.
- **Runtime anchors corrected.**
  - `facade.rs` and `session.rs` are in `crates/seamd/src/`.
  - The only "not authorized" message is "…for this decision" (`facade.rs:998,1038,1133`).
  - `authorize.v1.md` line numbers are re-anchored.
  - The clock grace is one-sided (`authorize.rs:100,479`).
  - Live dedupe is at `lib.rs:1781`, not the log-replay path at :1946. The `macp_modes` internals are
    marked unverified at source.
- **Phase 2 gaps closed.**
  - `usage` is outside the hashed payload, so a resend with a different `usage` is deduped and not
    debited.
  - A deduped resolving step returns no `decision_id` / `collective_outcome`, so a resolving-vote live
    criterion is added.
  - A resend can add one more `boundary.data_flagged` audit row.
  - The replay digest is burned before the handler runs.
- **Docs list corrected.**
  - `README.md:502-504` is not a "never retries" claim.
  - Added `errors.py:467` and `ts/src/errors.ts:282`.
  - `DECISIONS.md:2660` and `ASSUMPTIONS.md:1423` get superseding entries, not edits.
- **Phase 1.**
  - Adding coordination handlers to `FakeSeam` and `busy_server` is listed as work.
  - Tests added: aio cancellation mid-refresh, and a concurrent `authorize` plus read coalescing into
    one refresh.
  - The criterion baseline is stated: a pre-seeded ticket, and one extra admit = 2 RPCs.
- **Phase 3.**
  - Criterion 1 names the `identity_file.test.ts:103` and `:226` updates.
  - Criterion 4 is checkable: the `f1d112d` loader is extracted via `git show`.
- **Phase 4.**
  - The check order matches the full loader (seed before fields), and the adapters core misalignment
    is noted as theirs to fix.
  - `aid` validation applies only once Phase 3 has landed.
  - The whitespace-seed message change is stated and added to criterion 3.
  - The dependency on Phase 3 is removed.

**Changes applied:** all of the above, in this revision. Phase order is unchanged: 1 → 2 → 3 → 4.

**Round 2: REVISE.** Five defects, each verified against code and fixed:

1. **A resend after a resolving vote takes the sealed early return** (`session.rs:1563-1580`).
   - `decision_id` = the sealed id, `collective_outcome` unset, and `policy_enforcement` only if
     `sealed_attestable`.
   - The duplicate → all-none path applies only while the session is unsealed.
   - Fixed in Context fact 7, "Two observable differences", the Phase 2 edge case, the docstring
     paragraph, and criterion 4(d).
2. **A terminal session before the retry is `Ok` with the sealed id when a client call sealed it.**
   - It is `FAILED_PRECONDITION` only when the sweeper sealed it or an Expire/Cancel seal is pending
     (`session.rs:1541-1561`).
   - The edge case is fixed, and each failure-path test names the case it asserts.
3. **Phase 3 criterion 4.**
   - The `f1d112d` `identity.py` uses a relative `from .client import Agent`.
   - So the test loads it via `spec_from_file_location` as `seam_sdk._identity_f1d112d`.
4. **Phase 3 criterion 1.**
   - Byte-equality is required for Python and TS only.
   - Go, Java and Kotlin assert key order plus the `aid` value.
5. **Phase 4 criteria 1 and 2.**
   - The Phase-3-file clauses are qualified "when Phase 3 has landed".
   - When Phase 4 ships alone, the legacy file is used only.

**Changes applied. Plan final.** Phase order is unchanged: 1 → 2 → 3 → 4.
