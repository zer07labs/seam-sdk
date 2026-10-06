# Wire `VerifyAnchorRequest.tenant` into both hand-written clients

> **📦 ARCHIVED 2026-10-06 — DELIVERED, merged as PR #183 (`4469ce4`).** Archived after a delivery
> verification against this tree, during `/sweep`. All three phases verified DONE and merged:
> `python/seam_sdk/client.py`/`aio.py` and `ts/src/client.ts` all carry the optional `tenant`
> parameter on `verify_party_anchor`/`verifyPartyAnchor`, forwarded to `VerifyAnchorRequest.tenant`.
> Tracking issue [seam-sdk#172](https://github.com/zer07labs/seam-sdk/issues/172) is **CLOSED**.
> Full suites green on the merged commit: Python 1916 passed/0 failed, TypeScript 185 passed/0
> failed, `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` exits 0.
>
> **The stale re-open trigger this plan's Context corrected holds up**: `DECISIONS.md`'s
> 2026-10-04 entry was amended in place (not re-litigated) to record that the write side arrived
> via the operator-token tenant claim, not a new `RegisterPartyRequest` field — confirmed still
> true against current code (`register_party`'s tenant binding is still
> `seam-runtime/crates/seamd/src/planes.rs:1124`'s scoped-operator derivation, no new request field).
>
> **One pre-existing index gap this plan's own Context flagged is now fixed**: `revoke-tenant.md`
> was missing from `plans/README.md`'s index entirely (active or archived) — found separately
> during this same `/sweep` pass and archived as `plans/archive/revoke-tenant.md`.

## Context

`VerifyAnchorRequest` (`seam-runtime/crates/seam-api/proto/seam/api/v1/seam.proto:1114-1121`) carries
a `tenant` field (wire tag 3, additive) that neither hand-written client exposes: `verify_party_anchor`
(`python/seam_sdk/client.py:928-934`, duplicated verbatim in `python/seam_sdk/aio.py:822-830`) and
`verifyPartyAnchor` (`ts/src/client.ts:1218-1225`) all construct the request with only `party_id`/
`anchor`. `contract/field-manifest.txt:399` already records `VerifyAnchorRequest/tenant`, so
`check-contract.sh` is clean today — this is a deliberate, already-decided gap, not contract drift.

**Why now, and why the record this plan corrects.** The gap was deferred on 2026-10-04
(`DECISIONS.md:2294-2327`), whose entry names the re-open trigger as `check-contract.sh` exit 6 on
`+ RegisterPartyRequest/tenant` (`DECISIONS.md:2313-2314`) — i.e. it expected the write side to arrive
as a **new `RegisterPartyRequest.tenant` field**. `seam-sdk#172`'s own title carries a related but
distinct framing — "once party registration carries a tenant on the write side" — which is the issue's
title verbatim, not a `DECISIONS.md` quote; the two sources agree on the shape of what was being waited
for but neither anticipated how it actually arrived, and the issue title is itself stale for the same
reason. **Both predictions were wrong, and the `DECISIONS.md` trigger as written will never fire.**
Confirmed today, directly, against seam-runtime's current `main` (`243f51b0`): `RegisterPartyRequest`
still carries only `party_id`/`pubkey`
(`seam-runtime/crates/seam-api/proto/seam/api/v1/seam.proto:1362-1365`, unchanged). Instead,
`register_party`'s write side already binds a tenant a completely different way: the GRPC auth layer
derives it from the **authenticated operator's token claim**, never the request body —
`seam-runtime/crates/seamd/src/planes.rs:1124` (`let tenant = self.binding.require_scoped("register_party")?`)
dispatching to `seam-runtime/crates/seamd/src/planes.rs:720` (`("register_party", "grant:create")`).
This session verified that mechanism live, twice, fixing PR zer07labs/seam-sdk#174's CI: `register_party`/
`remove_party` now outright **refuse** a fleet-wide (no-tenant-claim) operator (seam-runtime#903 Phase 1 /
#922, confirmed intentional by seam-runtime, not a regression), so every party registered through the SDK
today already carries a real tenant — just not one spelled on the wire request, and not one any
`check-contract.sh` run will ever surface as a manifest gap, because no new field is coming.

So the write side the 2026-10-04 entry was waiting on **already exists**, in a form its own trigger
can't detect. The read side it paired it with — `VerifyAnchorRequest.tenant` — is also already live:
`seam-runtime/crates/seamd/src/facade.rs:351-360`'s doc comment states plainly "**#903 Phase 3** closes
the gap this used to document: the gRPC/REST `VerifyAnchorRequest` now carries a `tenant` field
... so a party registered under a real tenant ... can finally be anchor-verified through this path."
Both halves are live on `main` today. Nothing is blocked. This plan wires the read side the SDK was
always going to need to expose, and corrects the stale trigger in the same change.

**Scope boundary — no write-side SDK *signature* changes, but the write-side docstrings must catch up.**
Because the write-side tenant comes from the *authenticated operator's token*, not a request parameter,
there is nothing to add to `register_party`/`registerParty`'s signatures: `SeamAdminClient.connect(addr,
token=<bearer>)` (`python/seam_sdk/admin.py`, `ts/src/admin.ts`) already accepts any pre-minted bearer
string, tenant-bound or not — minting one is the control plane's job in production, and this SDK's
test-only `operator_token.py`/`operator_token.ts` already grew a `tenant` kwarg in PR #174 for exactly
this. But `register_party`'s own docstring (`python/seam_sdk/admin.py:388-394`, `ts/src/admin.ts:281-288`)
says nothing about `grant:create`, nothing about the fleet-wide refusal (#903 Phase 1 / #922), and
nothing about which tenant a registered party ends up bound to — the one piece of information a caller
needs in order to know what to pass to this plan's new `verify_party_anchor(..., tenant=...)` parameter.
`plans/revoke-tenant.md:354-356` named exactly this failure mode ("settable but never populatable from
this SDK"); Phase 1/2 close that loop for THIS plan's own new parameter by adding one doc-only sentence
to each `register_party` docstring (no signature change, so the scope boundary above still holds) — see
each phase's Files list.

**A structural asymmetry worth stating up front, because it is exactly the mistake this session already
made once this week (PR #174/#176, `test_verify_attestation.py`'s second CI round).**
`verify_party_attestation`'s tenant lives **inside** the message being verified
(`ChainHeadAttestation.tenant`, unsigned, wire tag 7) — the caller never passes tenant separately.
`verify_party_anchor`'s tenant lives on the **request wrapper**, a sibling of `party_id`/`anchor`, because
`Anchor` itself is deliberately tenant-agnostic bytes-in/bytes-out
(`seam-runtime/docs/specs/audit-anchor.md:105-110`: "Nothing in the wire `Anchor` format above carries a
tenant identifier ... a consumer holding only a bare `Anchor` object still attributes it to a tenant via
... the enclosing `SeamEvent` envelope ... never from the `Anchor` payload itself"). Both wrappers'
docstrings get an explicit cross-reference so a reader of one doesn't assume the other's shape.

## Phases

### Phase 1 — Python: `verify_party_anchor` (sync + async) carries `tenant`

**Status:** DONE — verified PASS (fresh Opus subagent, 1 round), committed as `07c9d42`.
**Risk:** complex — a public SDK method signature, on both the sync and async clients.

**Divergences from plan, all advisory/additive, none changing the spec:**
- `python/tests/test_live_fixtures_are_isolated.py` needed registering the new live test file in
  `LIVE_SUITES` and bumping its anti-vacuity count — not in the original Files list because this
  structural guard wasn't surfaced during planning; confirmed mandatory (the guard's own detector
  flags any unregistered file that imports `live_server`), not scope creep. In practice this was 8
  hunks, not one line: the registration itself plus correcting 5 now-stale "four suites"
  prose/assertion-message references and rewording the frozen pre-85-corpus assertion's failure
  message (confirmed message-only — its subject list, the 4 pre-85 fixture files, is unchanged) so
  it no longer reads as if it should track `LIVE_SUITES`'s current size.
- The async unit test uses an explicitly-named `_AioRecordingTrust.VerifyPartyAnchor` stub rather than
  the plan's cited `__getattr__`-based `_AioRecorder` pattern — a method-name typo fails loudly
  instead of silently recording under the wrong key; verifier confirmed this still satisfies "no new
  `AsyncMock` harness" and judged it an improvement.
- The live test (`test_verify_anchor.py`) has 6 cases, not the plan's 5 — a tampered `timestamp_millis`
  case added alongside the plan's tampered-signature case, since both are part of the signed preimage.
- Added one clarifying sentence to `verify_party_attestation`'s docstring in both `client.py` and
  `aio.py` (the latter previously had none) distinguishing its message-level `tenant` from
  `verify_party_anchor`'s request-level `tenant` — closes the "both wrappers get a cross-reference"
  intent from Context, which the original Files/Docs bullets under-scoped to one direction only.

- **Delivers:** `SeamClient.verify_party_anchor` (`python/seam_sdk/client.py:928-934`) and
  `aio.SeamClient.verify_party_anchor` (`python/seam_sdk/aio.py:822-830`) both grow a keyword-only
  `tenant: str = ""` parameter (inserted before `timeout`, matching
  `SeamAdminClient.resume_session`'s own `tenant: str = ""` precedent at
  `python/seam_sdk/admin.py:462,472-473`), forwarded as `pb.VerifyAnchorRequest(party_id=party_id,
  anchor=anchor, tenant=tenant)`. Omitted, it sends `""` — byte-identical to every existing caller's
  wire bytes.
- **Depends on:** none.
- **Files:**
  - `python/seam_sdk/client.py` — `verify_party_anchor`'s signature, body, and docstring.
  - `python/seam_sdk/aio.py` — the same, on the async twin (no docstring exists there today; add one
    rather than leaving the async copy undocumented while the sync one is). The sync and async edits are
    one atomic unit within this phase, not two independent commits: `test_client_parity.py`'s
    `test_the_two_clients_agree_on_each_verbs_signature` (`:64-79`) compares parameter **lists in
    order**, so `tenant` must land in the identical position in both files or that test reddens.
  - `python/seam_sdk/admin.py` — `register_party`'s docstring only (no signature change): add the one
    sentence named in Context's Scope-boundary paragraph (which tenant a registered party binds to, and
    that a fleet-wide token is refused).
  - `python/tests/test_verify_anchor.py` (new) — see Tests below.
- **Approach:** Mirror `resume_session`'s exact convention (keyword-only, empty-string default, no
  client-side validation — the server already treats `""` as the untenanted partition and anything else
  as a plain partition key; see `seam-runtime/crates/seam-trust-aitp/src/lib.rs:1499`'s
  `verify_party_anchor_in`, an exact-string `(tenant, party_id)` map lookup with no normalization).
  Rejected: validating `tenant` client-side (e.g. rejecting colons, the way `register_party`'s server
  side does via `require_clean_id_segment`) — that would be the SDK second-guessing a server that
  already has its own validation on the write side and performs none on this read side; adding it here
  would diverge from the contract instead of exposing it.
- **Edge cases & failure modes:**
  - Caller omits `tenant` entirely → `""` on the wire, identical to today — the whole point of the
    default, proven by a unit test, not left to protobuf's goodwill alone.
  - Caller passes a tenant that was never registered, or that doesn't match the party's actual
    registration tenant → the server returns `valid: false` (never an error); the SDK surfaces this the
    same boolean way it already does for an unknown party or a tampered signature. No new exception
    type, no new code path — `verify_party_anchor`'s contract ("boolean verdict, never an exception")
    is unchanged, just one more input that can legitimately produce `False`.
  - A caller who built `pb.VerifyAnchorRequest(...)` directly instead of going through the wrapper is
    unaffected either way — this phase only changes the wrapper, not the generated stub.
- **Acceptance criteria:**
  1. `inspect.signature(client.SeamClient.verify_party_anchor).parameters["tenant"].default == ""` and
     the same for `aio.SeamClient.verify_party_anchor`.
  2. A stub-recorded call to `verify_party_anchor("p", anchor)` with no `tenant` shows
     `tenant == ""` on the captured `VerifyAnchorRequest`, for both the sync and async clients.
  3. A stub-recorded call to `verify_party_anchor("p", anchor, tenant="acme")` shows `tenant == "acme"`
     on the captured request, for both clients.
  4. Against a live `seam-grpc` (`SEAM_GRPC_BIN` set): a party registered under a tenant-bound
     `grant:create` operator token (tenant `T`) verifies `True` when the caller passes `tenant=T`;
     verifies `False` when the caller omits `tenant` (defaults to `""`, the wrong partition) or passes
     a different tenant; a tampered signature under the correct `T` still verifies `False`; an unknown
     `party_id` under `T` still verifies `False`.
  5. Both `python/tests/test_client_parity.py::test_sync_and_async_clients_expose_the_same_verbs` AND
     `::test_the_two_clients_agree_on_each_verbs_signature` (`:64-79` — the one that actually reddens if
     only one of sync/async grows the parameter) pass, and the full existing suite (including
     `test_authorize.py`'s two deadline tables at lines 400 and 501, which call `verify_party_anchor`
     positionally with no `tenant` — must keep passing unmodified) stays green.
  6. `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` exits `0` (confirms the manifest-vs-stub surface
     stays unaffected, since this phase only touches hand-written wrapper code).
- **Tests:**
  - New `python/tests/test_verify_anchor.py`:
    - Server-free unit tests mirroring `test_verify_attestation.py:78-93`'s `_RecordingTrust`/
      `_client_with_trust` pattern for the sync client, and the `_Recorder`/`_AioRecorder` pattern
      already established at `python/tests/test_commit_supersedes.py:31-40` (used at
      `test_credential_wiring.py:62-71,232-233`) for the async client — a `__getattr__`-based async
      recorder returning `SimpleNamespace(valid=...)`, not a new `AsyncMock` harness. Proves the two
      default/explicit-tenant cases in acceptance criteria 2-3 for both clients.
    - A live round-trip test, gated on `SEAM_GRPC_BIN` exactly like `test_verify_attestation.py`'s
      `dual_plane` fixture (same pattern: `spawn_server(mgmt=True, ...)` with the `operator_keys`
      snapshot installed via `sign_snapshot`/`REGISTRY_SNAPSHOT_PATH`). A **self-signed** `Anchor` is
      sufficient and correct here — no conformance vector exists for `Anchor` (checked:
      `conformance/vectors.json` has no `anchor` key) and none is needed, because
      `anchor_payload = SHA256(chain_head || little_endian_u64(timestamp_millis))`
      (`seam-runtime/docs/specs/audit-anchor.md:70-79`,
      `seam-runtime/crates/seam-trust-aitp/src/lib.rs:611-617`) has no domain separator or framing
      ambiguity to get wrong, unlike `ChainHeadAttestation`'s richer preimage (which is why *that* test
      pins a KAT and this one doesn't need to). Register under a tenant-bound operator
      (`mint_operator_token(["grant:create"], tenant=T)`, reusing the `tenant` kwarg PR #174 already
      added to `python/tests/operator_token.py`), then exercise acceptance criterion 4's five cases.
- **Docs:** `verify_party_anchor`'s docstring (both clients) gets the cross-reference to
  `verify_party_attestation` described in Context (tenant lives on the request here, inside the message
  there) — this repo's own code, updated in the same commit.

### Phase 2 — TypeScript: `verifyPartyAnchor` carries `tenant`

**Status:** DONE — verified PASS (fresh Opus subagent, 1 round), committed as `a4ef019`.
**Risk:** complex — same reasoning as Phase 1, on the TS public contract.

**Divergences from plan, both additive, for symmetry with Phase 1:**
- The live test (`verify_anchor.test.ts`) has 6 cases, not the plan's 5 — a tampered
  `timestampMillis` case alongside the tampered-signature case, matching Phase 1's Python test
  case-for-case (same order, same reasoning: both fields are part of the signed preimage).
- `verifyPartyAttestation`'s doc comment also got a one-sentence addition distinguishing its
  message-level `tenant` from `verifyPartyAnchor`'s request-level `tenant` — the TS mirror of
  Phase 1's bidirectional cross-reference fix, closing the same "both wrappers" gap in Context
  that Phase 1 found under-scoped to one direction in the original Docs bullets.

- **Delivers:** `SeamClient.verifyPartyAnchor` (`ts/src/client.ts:1218-1225`) grows an inline options
  field `tenant?: string`, matching the established "method-specific extra option" convention this
  codebase already uses for `resumeSession`'s inline `{ tenant?: string; ... }` bag
  (`ts/src/admin.ts:338-344`) and `authorize`'s inline `{ ...; timeoutMs?: number }` bag
  (`ts/src/client.ts:650-672`) — **not** a new named interface the way `SubmitCommitOptions`
  (`ts/src/client.ts:89-95`) is. The real split in this codebase isn't "shared vs. single-method" —
  `SubmitCommitOptions` is itself a named, exported interface carrying a field (`supersedes`) used by
  exactly one method (`submitCommit`) — it's *base-plus-extra* (a method that already needs the shared
  `CredentialedCallOptions` base gets a named interface layering one field on top) vs.
  *timeout-plus-extra* (a method that only ever needed bare `UnaryCallOptions` gets an inline bag when it
  grows a method-specific field, as `authorize` and `resumeSession` both did). `verifyPartyAnchor` takes
  `UnaryCallOptions` today, so it falls in the second group — inline is the consistent choice, just not
  for the "shared vs. many" reason. `CredentialedCallOptions`'s own doc comment
  (`ts/src/client.ts:75-78`) still establishes the deliberate non-folding-into-the-base principle this
  phase also relies on for the Rejected call below.
- **Depends on:** none (independently shippable from Phase 1 — different language, same contract
  field).
- **Files:**
  - `ts/src/client.ts` — `verifyPartyAnchor`'s signature, body, and doc comment.
  - `ts/src/admin.ts` — `registerParty`'s doc comment only (no signature change): the same one-sentence
    addition as Phase 1's `admin.py`, mirrored (Context's Scope-boundary paragraph).
  - `ts/tests/verify_anchor.test.ts` (new) — see Tests below.
- **Approach:** `opts?: { tenant?: string; timeoutMs?: number }`, request built as
  `{ partyId, anchor, tenant: opts?.tenant ?? "" }`, call options via the existing `call(opts)` helper
  (`ts/src/client.ts:97-99`) — structurally compatible with `UnaryCallOptions` (the helper only reads
  `timeoutMs`), identical to how `authorize`'s wider inline bag already calls `call(opts)` today.
  Rejected: extending `UnaryCallOptions` directly to add `tenant` there — that would make `tenant` a
  compile-time-legal (if silently ignored) option on every *other* unary method too, exactly the failure
  mode `CredentialedCallOptions`'s own doc comment says this codebase avoids on purpose.
- **Edge cases & failure modes:** Identical to Phase 1's (same RPC, same server), plus one TS-specific
  check: passing a plain `UnaryCallOptions`-typed value (just `{ timeoutMs }`, no `tenant`) must still
  typecheck against the new inline type — true by structural typing (the target type's `tenant` is
  optional), verified by `npm run typecheck` rather than asserted by hand.
- **Acceptance criteria:**
  1. `verifyPartyAnchor(partyId, anchor)` with no `opts.tenant` sends `tenant: ""` on the captured
     request (a stub `trust.verifyPartyAnchor` recording its input, mirroring
     `verify_attestation.test.ts:61-80`'s `clientWithTrust` pattern — the first dedicated test
     `verifyPartyAnchor` gets in this repo; today it has **zero** test coverage, not even in the
     3-example "unary data-plane wrappers" timeout spot-check at `unit_plumbing.test.ts:267-278`).
  2. `verifyPartyAnchor(partyId, anchor, { tenant: "acme" })` sends `tenant: "acme"`.
  3. Against a live `seam-grpc`: the same five live scenarios as Phase 1's acceptance criterion 4,
     built with `withPlanes`'s existing operator-keys-snapshot pattern
     (`verify_attestation.test.ts:116-146`) and a self-signed `Anchor` via `@noble/curves/ed25519`
     (same payload formula, no vector needed, same reasoning as Phase 1).
  4. `npm run typecheck && npm run build && npm test` all green.
  5. `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` exits `0` (same reasoning as Phase 1 AC6).
- **Tests:** New `ts/tests/verify_anchor.test.ts`, structured like `verify_attestation.test.ts`:
  unit tests via a `clientWithTrust`-style stub (party/anchor/tenant captured, boolean returned), then a
  `withPlanes`-gated live round trip covering the same five scenarios as Phase 1.
- **Docs:** `verifyPartyAnchor`'s doc comment gets the same `verifyPartyAttestation` cross-reference as
  Phase 1's Python docstrings.

### Phase 3 — Docs, decision record, and closing the loop

**Status:** DONE — verified PASS (fresh Opus subagent, 1 round), committed as `c887d77`. AC4 (issue #172 shows CLOSED)
is necessarily N/A until the PR merges — tracked as a `/ship`-time outcome, not a gap.
**Risk:** simple — no code; last phase, nothing to batch it with (same situation
`plans/revoke-tenant.md`'s Phase 4 was in), so it still gates solo per `/implement`'s own rule.

**Divergence from plan:** `CHANGELOG.md`'s placement instruction ("after the existing
`revoke_tenant` entry") assumed `## Unreleased` still held that entry. It didn't by the time this
phase executed: a `v0.33.2` release commit, pulled onto this branch before Phase 1 started (see
`PROGRESS.md`'s pre-phase note), had already moved `revoke_tenant` and everything else under a new
`## 0.33.2 — 2026-10-05` header, leaving `## Unreleased` empty. The new entry became the Unreleased
section's first (and only) entry instead — verified by the Phase 3 reviewer as satisfying AC1's
actual intent (discoverable, correctly placed, correct dual citation) despite the literal mismatch.

- **Delivers:** The written record catches up with what Phases 1-2 shipped and corrects the stale
  prediction in the existing deferral entry; `seam-sdk#172` closes; this plan is indexed.
- **Depends on:** Phase 1, Phase 2 (describes what they shipped).
- **Files:**
  - `CHANGELOG.md` — one `### Added` entry under `## Unreleased`, placed immediately after the existing
    `revoke_tenant`/`revokeTenant` entry (`CHANGELOG.md:109-121`) — matching where the three most recent
    landings actually went (confirmed: `8f311cd` and `837b4e3` both top-inserted right after
    `## Unreleased`, which is why the pinned-key entry at `:19` sits *above* `:51`'s `supersedes` today;
    only the three most recent entries were appended at the tail, and `DECISIONS.md:1028-1029` itself
    says "a changelog grows at the top" — so this is matching recent precedent, not a settled
    file-wide convention). Header cites both issues this entry closes:
    `(seam-sdk #172, seam-runtime #922)`, mirroring `CHANGELOG.md:109`'s own dual-citation style.
  - `DECISIONS.md` — **a new dated entry, plus an in-place amendment to the 2026-10-04 entry's stale
    trigger bullet** (`:2313-2314`). This file is NOT append-only — `:1220-1221` ("This bullet is
    amended rather than deleted, because the reversal removes its support without touching its
    conclusion"), `:1551` ("Citation corrected 2026-09-03 ... It now names `uintSlot`"), and `:1952`
    ("**Status:** CONFIRMED (amended)") are all established in-place-amendment precedent — only
    `CHANGELOG.md` is described as append-only (`:1040`). Amend `:2313-2314` in that same style: keep
    the bullet's original text, append a dated amendment note stating the exit-6/`RegisterPartyRequest`
    trigger will never fire and pointing at the new entry below for what actually happened. The new
    entry states plainly that the write side arrived via the operator-token's own `tenant` claim, not a
    new request field (confirmed via PR #174/#176's own live-fixture fix this week), records that both
    halves are now wired by this plan, and cross-references the amended bullet above. The 2026-10-04
    entry's original *conclusion* (deferred, re-open on write-side tenant support) is preserved, not
    rewritten — only the trigger mechanism gets the dated correction.
  - `COMPATIBILITY.md:102` and `DECISIONS.md:1222` — repoint only: both carry a `CHANGELOG.md:1035-1052`
    citation to the "No yank" clause, and this phase's new `CHANGELOG.md` entry shifts that line range
    (see Acceptance criteria below — this is mandatory, not conditional).
  - `plans/README.md` — add this plan to the **Active/pending** table (status `TODO` at write time;
    `/implement` doesn't flip this table itself, but it's the one doc this plan creates that the index
    doesn't yet know about).
  - `seam-sdk#172` — close via the PR (`Closes #172` in the PR body), with a comment naming the two
    PR'd commits, the corrected trigger story, and noting the issue's own title ("once party
    registration carries a tenant on the write side") was itself part of the stale prediction.
- **Approach:** Treat the stale trigger as a finding to record honestly (this plan's own Context
  section already does the hard part), not as something to quietly paper over — a reader of
  `DECISIONS.md` six months from now should be able to tell *why* the original trigger never fired
  without re-deriving it from a proto diff. That means the stale bullet itself needs the dated
  amendment note, not just a fresh entry elsewhere that a reader might never cross-reference.
- **Edge cases & failure modes:** None — this phase is pure bookkeeping; its only failure mode is
  drifting from what Phases 1-2 actually shipped, which the verify gate checks against the real diff,
  not against this plan's prose.
- **Acceptance criteria:**
  1. `CHANGELOG.md`'s new entry appears after the `revoke_tenant` entry and before `## 0.22.0`, with a
     header citing `(seam-sdk #172, seam-runtime #922)`.
  2. `DECISIONS.md` has a new 2026-10-05-or-later dated entry, AND the 2026-10-04 entry's trigger bullet
     (`:2313-2314`) carries a dated amendment note pointing at it — the bullet's original text and the
     entry's original conclusion are preserved (not deleted/rewritten), matching the `:1220-1221`/`:1551`
     amendment style.
  3. `plans/README.md`'s Active/pending table lists `verify-anchor-tenant.md`.
  4. `gh issue view 172` shows `CLOSED` after the PR merges, with a closing comment.
  5. `COMPATIBILITY.md:102` and `DECISIONS.md:1222` are repointed to the new line number of the "No
     yank" clause in `CHANGELOG.md` (diff old-vs-new line content for byte-identity before repointing,
     never assume — the same discipline PR #174 already exercised twice). This is required, not
     conditional: `test_compatibility_citations_resolve.py`'s `ANCHORED` list + `CITATION_SLACK = 3`
     (`:575,802`) means any Unreleased insertion this far from the target line WILL break
     `test_the_load_bearing_citations_still_point_at_the_right_thing` (`:1154`) without it.
  6. `python/tests/test_compatibility_citations_resolve.py`'s full suite passes (covers `COMPATIBILITY.md`,
     `DECISIONS.md`, and `PROGRESS.md` citations alike — any of the three can hold a stale
     `CHANGELOG.md:NNN` pointer after this phase's edit).
- **Tests:** `python/.venv/bin/pytest -q python/tests/test_compatibility_citations_resolve.py` after
  every doc edit in this phase, not just once at the end — this is the mechanical check this repo
  already trusts for exactly this failure mode.
- **Docs:** This phase *is* the docs sweep for this plan. One addition: `README.md:479-483`'s
  "Data-plane surface" trust clause documents `verify_party_anchor` as "boolean verdict, tamper/unknown
  ⇒ `False`, never an exception" — a tenant mismatch is a new way to reach that same `False`, so add one
  clause there rather than leaving a reader to infer it.

## Long-term posture

This is additive, not a one-way door: the new parameter defaults to the exact pre-existing wire shape,
and nothing about `VerifyAnchorRequest`'s schema changes (the field already exists; this plan only
stops leaving it unreachable from the two hand-written clients). The actual one-way-door-shaped thing
already happened — on seam-runtime's side, when `register_party`/`remove_party` started refusing
fleet-wide operators (#903 Phase 1) — and it already shipped, confirmed by this session fixing CI
against it twice. This plan does not revisit that; it only finishes exposing the read-side half that
decision made meaningful.

The one thing worth pricing explicitly: **Go, Java, and Kotlin get this field for free, today, with no
code change**, because those languages have no hand-written wrapper layer at all — callers already set
`VerifyAnchorRequest.tenant` directly on the generated stub. The asymmetry this plan leaves standing
(three languages wired via a convenience method, three via the raw generated type) is the same
asymmetry the `RevokeTenant` CHANGELOG entry already named out loud ("Go, Java and Kotlin have no
admin-surface client to wire this into") — consistent with this repo's existing posture, not a new gap
introduced here.

## Enterprise concerns

- **Observability:** no new failure mode to observe — `verify_party_anchor` already returns a plain
  boolean, and a tenant mismatch surfaces exactly like an unknown party or a tampered signature (a
  `False`, with no distinguishing signal on the wire or in the SDK). A caller who needs to tell "wrong
  tenant" apart from "no such party" has never been able to from this RPC's shape, on any language
  binding, including Go/Java/Kotlin's raw stub access — not a regression this plan introduces, and not
  in scope to change here (it would be a server-side RPC-shape decision, not a client-wiring one).
- **Reliability / migration:** zero migration story needed — proto3 scalar default (`""`) is
  byte-identical to today's hand-written requests, so every existing caller on every currently-shipped
  SDK version is unaffected whether or not they ever upgrade to pick this parameter up.
- **Security:** no new trust boundary. The read side still performs no authentication (data plane,
  dev-insecure or ticket-based, unrelated to the management plane's `operator_keys` root) and no new
  authorization check — a caller could already (before this plan) attempt to verify any `party_id`
  string blind; now they can additionally attempt any `tenant` string blind. Both still only ever
  produce a boolean no-information-leak verdict (never "party exists in a different tenant," just
  `False`), matching the server's own designed behavior, not something this plan changes.

## Open questions

- **`revoke-tenant.md` is not indexed in `plans/README.md`'s Active/pending table either**, discovered
  while checking the convention for this plan. Out of scope here — a different plan's housekeeping gap,
  not something this plan's diff should quietly absorb. Decided (Opus, consequential-but-decidable):
  leave it for whoever next runs a `plans/` housekeeping pass or archives `revoke-tenant.md` with its
  own delivery-verification note; flagged here rather than silently fixed or silently ignored.
  **Pending confirmation** only in the sense that if the maintainer wants it fixed now instead, that's a
  one-line addition to this plan's Phase 3 rather than a reason to hold the plan.
  <!-- /implement: if addressed, log the resolution to ASSUMPTIONS.md as this isn't a code assumption but
  a scope call worth recording the same way. -->
- **Whether `plans/README.md`'s Active/pending table should be flipped to "done"/archived by this same
  plan's Phase 3, or left for a later dated audit.** Decided (Opus): left for later — the table's own
  stated convention requires a dated, code-verified delivery note, which belongs to a `/reconcile`-style
  pass looking at the shipped code fresh, not to the plan that just wrote the code and would be grading
  its own homework. Phase 3 only *adds* the row; it does not claim delivery.
- No critical/one-way-door decision in this plan rose to the Fable tier — the write-side mechanism
  (operator-token tenant claim) was already shipped and tested by seam-runtime and by this session's own
  prior PR, not a decision this plan is making; the read-side wiring is a small, fully-reversible,
  additive SDK change with direct in-repo precedent (`resume_session`) on both the Python and TS side.

## Repo map

Scoped to this plan — see `PROGRESS.md`'s existing repo-map entries from `plans/revoke-tenant.md` for
the wider SDK layout, unchanged by this plan.

- `python/seam_sdk/client.py:928-934` — sync `verify_party_anchor`, the primary wrapper to change.
- `python/seam_sdk/aio.py:822-830` — its async twin, duplicated by hand (no shared base class); must
  change in lockstep — `test_client_parity.py:64-79`'s
  `test_the_two_clients_agree_on_each_verbs_signature` compares parameter lists in order, so this is
  not just a names-equality check and a half-done change will redden it.
- `python/tests/test_verify_attestation.py` — the sibling test file to model Phase 1's new test file
  after: `_RecordingTrust`/`_client_with_trust` (unit), `dual_plane` fixture + `operator_token`'s
  `sign_snapshot`/`mint_operator_token(..., tenant=...)` (live).
- `python/tests/operator_token.py` — already carries the `tenant` kwarg (added in PR #174); reused
  as-is, not modified.
- `python/tests/test_authorize.py:380-407,470-508` — the two mechanical deadline tables that call
  `verify_party_anchor` positionally; confirmed unaffected by a keyword-only addition, not touched.
- `ts/src/client.ts:71-99` (`UnaryCallOptions`/`CredentialedCallOptions`/`call()`), `:646-700`
  (`authorize`'s inline-opts precedent), `:1218-1225` (`verifyPartyAnchor` itself) — the TS surface to
  change and the conventions it must match.
- `ts/src/admin.ts:335-358` — `resumeSession`'s inline `tenant?: string` precedent (admin plane, same
  pattern applied here to the data plane).
- `ts/tests/verify_attestation.test.ts` — the sibling test file to model Phase 2's new test file after.
- `ts/tests/operator_token.ts` — already carries the `tenant` opt (added in PR #174); reused as-is.
- `contract/field-manifest.txt:399` — already has `VerifyAnchorRequest/tenant`; nothing to change.
- `DECISIONS.md:2294-2327` — the entry whose stale trigger bullet (`:2313-2314`) Phase 3 amends in
  place, alongside a new dated entry; `:1222` also needs a "No yank" citation repoint (see below).
- `CHANGELOG.md:17-121` — `## Unreleased`'s entries; the most recent three (`0a48c6e`/`f23a9e1`/
  `faa654e`) were tail-appended, the two before them top-inserted. Phase 3's entry goes immediately
  after line 121 (`revoke_tenant`), before `## 0.22.0` at line 123, matching the three most recent
  landings.
- `COMPATIBILITY.md:102` — carries the same "No yank" `CHANGELOG.md:1035-1052` citation as
  `DECISIONS.md:1222`; both need repointing once Phase 3's new entry shifts that line range.
- `plans/README.md` — the plan index Phase 3 adds a row to.
- `README.md:479-483` — the "Data-plane surface" trust clause Phase 3's Docs step adds one sentence to.
- `seam-sdk#172` — the issue this plan closes; its own title is part of the stale prediction (see
  Context).
- `seam-runtime/crates/seam-api/proto/seam/api/v1/seam.proto:1106-1121` — `Anchor`/`VerifyAnchorRequest`
  wire shapes, read-only reference (sibling repo).
- `seam-runtime/crates/seamd/src/planes.rs:720,1124`, `facade.rs:351-360`, `grpc.rs:1542-1559` — the
  write-side auth binding and read-side gRPC handler, read-only reference.
- `seam-runtime/crates/seam-trust-aitp/src/lib.rs:605-617,1077-1085,1491-1499` — `Anchor`'s signing
  payload and `PartyRegistry`'s `(tenant, party_id)` lookup, read-only reference.
- `seam-runtime/docs/specs/audit-anchor.md:70-120` — the normative signing-payload formula and the
  "`Anchor` is tenant-agnostic" clause this plan's docstring cross-reference cites.

## Plan review

**Round 1 (fresh Opus agent, against the code in `seam-sdk` and the sibling `seam-runtime` checkout):**
Verdict **REVISE** — 10 items, all addressed in this revision:
1. `test_client_parity.py`'s signature-equality test (`:64-79`), not just the names-only test, is now
   named in Phase 1 AC5, and the sync/async edit is called out as one atomic unit within the phase.
2. Phase 1's async unit test now mirrors the existing `_Recorder`/`_AioRecorder` pattern
   (`test_commit_supersedes.py:31-40`) instead of inventing a new `AsyncMock` harness.
3. `register_party`'s docstring (both languages) is added to Phase 1/2's Files, doc-only, to state
   which tenant a registered party binds to — closing the "populatable from this SDK?" gap
   `plans/revoke-tenant.md` already named.
4. Phase 2's named-interface-vs-inline rationale is corrected (`SubmitCommitOptions` IS a named
   interface for a single-method field; the real split is base-plus-extra vs. timeout-plus-extra) —
   same decision, correct reasoning.
5. Seven stale citations corrected throughout (client.py's actual line range, the audit-anchor.md quote
   location, both test-pattern line ranges in Python and TS, authorize's actual bag range, facade.rs's
   doc-comment start, and the runtime commit hash).
6. `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` exits `0` added as an acceptance criterion to both
   Phase 1 and Phase 2.
7. `COMPATIBILITY.md` and `README.md` added to Phase 3's scope (repoint-only; one trust-clause sentence,
   respectively); `PROGRESS.md` noted as also covered by the citation-resolution test.
8. Phase 3's `DECISIONS.md` approach rewritten: this file is NOT append-only (direct counter-evidence
   at `:1220-1221`, `:1551`, `:1952`) — the stale trigger bullet now gets an in-place dated amendment,
   not just a new entry elsewhere a reader might never find.
9. The "No yank" citation repoint (`COMPATIBILITY.md:102`/`DECISIONS.md:1222`) is now a required Phase 3
   acceptance criterion, not a conditional parenthetical.
10. The CHANGELOG "append-at-the-end" claim is corrected to "matches the three most recent landings"
    (not a file-wide convention); the Context section now attributes the "write side" framing to
    `seam-sdk#172`'s title specifically, separate from `DECISIONS.md:2313-2314`'s actual exit-6
    trigger — and notes the issue's own title was itself stale.

**Round 2 (fresh Opus agent, closure check against the Round-1 gap list):** Confirmed all 10 Round-1
items genuinely closed against the real code (each re-verified independently: parity test, `_Recorder`
pattern, admin docstring gaps, named-interface rationale, all seven citations, both gate ACs, the three
added doc files, the `DECISIONS.md` amendment approach and its counter-evidence, the mandatory repoint,
and the CHANGELOG-convention/trigger-quote split — including a git-log check confirming which of the
five most recent `CHANGELOG.md` landings were tail-appended vs. top-inserted). It surfaced two new,
purely mechanical citation slips introduced by the Round-1 edit itself (`ts/src/client.ts:79-85` should
have read `:75-78`; the Repo map's CHANGELOG bullet said "most recently top-inserted" when the opposite
is true and `## 0.22.0` is at line 123, not 122) — both fixed directly in this pass without a third
review round, since they were citation-only and the fix was unambiguous from the same evidence Round 2
already gathered. **Final verdict: SOUND**, two rounds run, cap not exceeded.
