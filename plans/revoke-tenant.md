# Add `SeamAdmin.RevokeTenant` to the Python and TypeScript clients

## Context

`SeamAdmin.RevokeTenant(RevokeTenantRequest{subject_aid: string}) -> Empty` shipped in
`seam-runtime` 0.32.0 and landed on the published BSR module (`buf.build/zer07labs/seam`) via a
`buf push` on 2026-10-04. It is **not yet wired into any seam-sdk client**, and `contract/rpc-manifest.txt`
does not list it — confirmed directly, twice (once while drafting, once independently in review):
`make generate` regenerates clean against the live BSR module, and the generated stubs
(`python/seam_sdk/_gen/seam/api/v1/seam_pb2.pyi:694-698`, `seam_pb2_grpc.py:1493-1495,1574-1582`;
`ts/gen/seam/api/v1/seam_pb.ts:2546-2561,3546-3561`) carry `RevokeTenant` while
`contract/rpc-manifest.txt` (71 lines: a 27-line header + 44 RPC entries) does not.
`scripts/check-contract.sh`'s RPC-manifest comparison fails on this today — verified empirically:
`STREAM=1 EVENTS=1 ./scripts/check-contract.sh` exits **5**, printing `+ SeamAdmin/RevokeTenant`.

**Baseline, as of this session (verify before trusting it's unchanged):** `python/.venv/bin/pytest -q`
is currently **RED** — `1 failed, 1325 passed, 22 skipped` (pristine `main`, confirmed in Phase 1's
verify round by running the suite against a detached worktree at `main`; this plan's own earlier
draft said 1324 — off by one, corrected here). The one failure is
`tests/test_field_manifest_gate.py::test_an_exact_match_of_the_known_lag_downgrades_to_a_note_naming_the_lag_file`,
caused by the same two undeclared-field gaps this plan closes (see below) — confirmed by the review
round: inserting both missing manifest lines turns a pristine-`main` run of this into
`1326 passed, 22 skipped` (pristine baseline + the fix, before Phases 1-2 add their own tests — see
Phase 3's acceptance criteria for the actual expected count once all phases are applied in order).
TypeScript
is green today (`npm test` in `ts/`: 182 pass / 10 skip). `ci.yml`'s last run on `main` was
**success** (2026-10-03, `f23a9e1`), before the 2026-10-04 BSR push that introduced the gap — so the
gate is *latently* red (it will fail the next push or PR that regenerates), not currently showing
red in the Actions tab. Separately and unrelated: `release-on-runtime.yml` **is** actively failing
today, but at a different step entirely — *"The runtime's wire framing must be one this SDK
implements"*, the `contract/wire-framing.json` `supported: 3` hold. **This plan does not touch that
gate and will not unblock releases** — it only fixes `check-contract.sh`.

This work was requested via a cross-session message from a `seam-runtime` session, relaying an
instruction attributed to the repo owner. Two of that message's claims needed correction before
scoping this plan, and both were checked against the code rather than taken on trust:

1. **"Wire it into the five hand-written clients" is wrong for Go/Java/Kotlin.** Those three
   language directories contain *only* a crypto-primitives module and a conformance test each
   (`go/crypto/crypto.go`, `java/src/main/java/com/zer07labs/seam/SeamCrypto.java`,
   `kotlin/src/main/kotlin/com/zer07labs/seam/SeamCrypto.kt` — confirmed by listing every source
   file in all three trees, independently re-confirmed in review). `scripts/check-contract.sh:27-28`
   states this is by design, verbatim: *"Only Python and TS carry an admin surface; Go/Java/Kotlin
   are crypto + conformance by design and are not probed here."* There is nothing to wire
   RevokeTenant into in those three languages. Scope is **Python and TypeScript only**.

2. **Fixing RevokeTenant alone will not turn `check-contract.sh` green.** `VerifyAnchorRequest`
   gained a `tenant` field (`python/seam_sdk/_gen/seam/api/v1/seam_pb2.pyi:588-596`) that is also
   absent from `contract/field-manifest.txt` (which lists only `VerifyAnchorRequest/anchor` and
   `VerifyAnchorRequest/party_id`, lines 396-397). This is unrelated to RevokeTenant and currently
   *masked*: the RPC-manifest check (exit 5) fires before the field-manifest check (exit 6) in the
   gate's ordering — verified empirically in review by pointing the gate's
   `SEAM_RPC_MANIFEST`/`SEAM_FIELD_MANIFEST` env overrides at scratch copies: with only the
   `VerifyAnchorRequest.tenant` line added (RPC manifest untouched), the gate still exits **5** and
   the field check **never runs**; with the RPC + `subject_aid` lines added too, it exits **6** on
   `+ VerifyAnchorRequest/tenant` alone; with all three lines present, it exits **0**. Neither
   `python/seam_sdk/client.py:928-933` nor `python/seam_sdk/aio.py:822-827` nor
   `ts/src/client.ts:1219-1224` (`verify_party_anchor` / `verifyPartyAnchor`) passes this field
   today. This plan resolves it (Phase 3) so the gate can actually reach green — see Open Questions
   for why "record, don't wire" is the right call here, on different grounds than first drafted.

The semantics of `RevokeTenant` are pinned from **one** authority: the generated gRPC servicer
docstring, sourced from the runtime's own proto comment
(`python/seam_sdk/_gen/seam/api/v1/seam_pb2_grpc.py:1574-1582`, mirrored in
`ts/gen/seam/api/v1/seam_pb.ts:3546-3554`):

> Revoke (soft-delete) a subject AID's enrollment — the inverse of EnrollTenant; parity with the
> HTTP `DELETE /v1/tenants/{subject_aid}`. The durable row is tombstoned (never deleted), the
> in-memory binding is evicted with no restart, and a `tenant_revoked` entry is chained. Idempotent:
> a retry of an already-revoked AID is OK; an AID with no enrollment row at all is NOT_FOUND (#951;
> a tenant-scoped operator gets OK instead, so it cannot probe other tenants' AIDs). `tenant:revoke`
> scope (a tenant-scoped operator may revoke only its own tenant's AIDs). Returns `Empty` by design;
> an outcome-bearing variant would be a new RPC, not a response-type change (buf
> `RPC_SAME_RESPONSE_TYPE`).

`zer07labs/seam-runtime#951` (fetched and read this session, **CLOSED**, title: *"revoke_tenant:
return NOT_FOUND instead of a silent 204 for an AID with no enrollment row (decide before
RevokeTenant ships in an SDK)"*) is the record that this decision was **made**, not an independent
statement of what it is — its body only poses the question ("...would catch it, but it changes the
HTTP/gRPC contract, so decide before an SDK release picks up `RevokeTenant`") and carries no
comments. The proto comment above is the single source of truth for behavior; #951 is cited in docs
as the decision's paper trail. The default on "no enrollment row at all" is **NOT_FOUND**; a
tenant-scoped operator gets **OK instead** (not the reverse). The HTTP-layer detail from the
originating cross-session message (`DELETE /v1/tenants/{subject_aid}` → 204) is a runtime/REST-gateway
concern outside this SDK's gRPC surface and needs no SDK-side test.

The closest precedent for *how* to land a plain (non-crypto-framing) RPC addition is PR #154
(merged 2026-09-30), which wired `SeamAuthorization.GetEscalation` into Python + TypeScript only,
as one bullet in a larger PR, with no dedicated `plans/<feature>.md` of its own — confirmed by
reading `plans/README.md` and `plans/archive/`, where no single-RPC addition has ever gotten its
own plan file. This plan exists only because `/plan` was invoked explicitly; **the repo's own
convention is that a change this size does not normally warrant a plan file**, called out again in
Open Questions rather than silently overridden.

Not in scope: `contract/wire-framing.json` and the `release-on-runtime` release gate — the
cross-session message explicitly asked that these not be touched, and nothing here needs them
(`RevokeTenant` is not a crypto framing change; see the Baseline paragraph above on why this PR
will not turn that gate green). Not in scope: any change to `go/`, `java/`, `kotlin/`, or `verify/`.

## Phases

Ordered to satisfy `contract/rpc-manifest.txt`'s own header rule (≈lines 16-19): *"a stub has an
RPC/field NOT listed here -> wire it into the hand-written clients (or record why not), then add
the line here."* Wiring comes first; the manifest commit comes last, so no committed state ever
declares a verb the clients don't yet carry.

### Phase 1 — Python: `SeamAdminClient.revoke_tenant`

**Status:** DONE — implemented exactly as planned, no approach divergence. Verify round found the
plan's own baseline test count was off by one (corrected in Context/Phase 3 above); no code gap.
**Risk:** complex — new public-SDK-surface method crossing a network/another-service boundary
(a gRPC call to `SeamAdmin`), even though it mirrors four existing siblings exactly. Solo gate.

**Delivers:** A working, tested `revoke_tenant(subject_aid)` method on the Python admin client.

**Depends on:** nothing (the generated stubs already carry the symbol from BSR; this phase needs
no manifest change to compile or test — `check-contract.sh` is a separate CI gate, already
latently red before this phase and unaffected by it either way).

**Files:**
- `python/seam_sdk/admin.py`
- `python/tests/test_admin.py`
- `python/tests/test_lifecycle_and_timeouts.py`

**Approach:** Add `revoke_tenant` to `SeamAdminClient` (`python/seam_sdk/admin.py`), in the
`# ── Governance / tenancy` section, immediately after `list_tenants` (ends line 370) and before
`register_party` (starts line 372) — grouping the enroll/list/revoke tenant trio together,
matching the runtime's own framing of `RevokeTenant` as "the inverse of EnrollTenant":

```python
def revoke_tenant(
    self, subject_aid: str, *, timeout: float = DEFAULT_ADMIN_TIMEOUT_S
) -> None:
    """Revoke (soft-delete) a subject AID's enrollment — the inverse of ``enroll_tenant``. The
    durable row is tombstoned (never deleted) and the in-memory binding is evicted with no
    restart. Idempotent: revoking an already-revoked AID succeeds. An AID with no enrollment row
    at all gets ``NotFoundError``; a tenant-scoped operator gets the same success as an idempotent
    re-revoke instead, so it cannot use this to probe another tenant's AIDs (seam-runtime #951).
    Requires the ``tenant:revoke`` operator scope."""
    self._admin.RevokeTenant(pb.RevokeTenantRequest(subject_aid=subject_aid), timeout=timeout)
```

This matches `remove_party`/`revoke_grant`'s exact shape: single positional arg mirroring the
proto's one field, inline request construction, `timeout=` kwarg, `-> None` return (the RPC returns
`Empty`, discarded). No new error handling is added — `self._admin` is a `_MappedStub`
(`python/seam_sdk/errors.py:351-370`, used at `admin.py:257`), which already converts any
`grpc.StatusCode.NOT_FOUND` into the typed `NotFoundError` (`errors.py:266-267`, dispatch table at
`errors.py:294-306`) for every call made through it, with zero per-method special-casing anywhere
else in the file — adding bespoke NOT_FOUND handling here would be inconsistent with every sibling
method and is explicitly rejected (see Edge cases). The generic timeout tests
(`test_lifecycle_and_timeouts.py`) use `HangingSeam` (`test_authorize.py:134-151`), whose
`__getattribute__` hangs *any* CamelCase-named RPC generically — no new servicer/fixture code is
needed for `RevokeTenant` to participate; only the `ADMIN_CALLS` table entry below is required.

**Edge cases & failure modes:**
- *NOT_FOUND from an operator with no scoping to the AID's tenant* — already handled for free by
  `_MappedStub`; surfaces as `NotFoundError`, a `SeamRpcError`, a `grpc.RpcError`. No code needed;
  **tested** (see below) to prove the wiring, not to test the mapping machinery itself (that's
  `test_status_mapping.py`'s job, already generic).
- *Repeat revoke of an already-revoked AID* — server-side idempotency behavior
  (`seam-runtime#951`'s resolution, stated in the proto comment); the SDK has no client-side state
  to get this wrong and needs no special-casing. Not independently testable from seam-sdk without a
  live runtime, and the closest SDK-level precedent (`remove_party`/`revoke_grant`) carries no
  idempotency test of its own either (confirmed: zero `pytest.raises` tests for either method in
  `test_admin.py`; the only `pytest.raises` tests there cover the erasure flow and operator-token
  auth) — see Open Questions for why this is not added here.
- *Empty `subject_aid`* — not validated client-side, matching every other admin method's
  convention (`remove_party("")`, `revoke_grant("", ...)` are not guarded either); the server is the
  source of truth for validation.

**Acceptance criteria:**
- `SeamAdminClient.revoke_tenant("aid:x")` sends a `RevokeTenantRequest(subject_aid="aid:x")` over
  the wire and returns `None` on success.
- `revoke_tenant` accepts a `timeout` keyword and enforces it, verified by the existing generic
  `test_every_admin_method_accepts_a_timeout_argument` / `test_every_admin_method_enforces_its_timeout`
  introspection tests in `test_lifecycle_and_timeouts.py` (lines 162-189) — which only happens once
  it's added to the `ADMIN_CALLS` dict there.
- `python/.venv/bin/pytest -q python/tests/test_admin.py python/tests/test_lifecycle_and_timeouts.py`
  passes. The repo-wide pre-existing failure
  (`test_field_manifest_gate.py::test_an_exact_match_of_the_known_lag_downgrades_to_a_note_naming_the_lag_file`,
  see Context's Baseline paragraph) is **not** this phase's responsibility — Phase 3 resolves it.

**Tests:**
- `python/tests/test_admin.py`: add a `RevokeTenant` handler to `RecordingAdmin`
  (`self.revoked_tenant: pb.RevokeTenantRequest | None = None`, returning `pb.Empty()`, mirroring
  `RemoveParty` at lines 45-47) and a new
  `test_revoke_tenant_sends_the_subject_aid_and_returns_none`, mirroring
  `test_remove_party_sends_the_party_id_and_returns_none` (lines 79-83) exactly:
  ```python
  def test_revoke_tenant_sends_the_subject_aid_and_returns_none(recording_admin):
      servicer, addr = recording_admin
      with SeamAdminClient.connect(addr) as admin:
          assert admin.revoke_tenant("aid:x") is None
      assert servicer.revoked_tenant.subject_aid == "aid:x"
  ```
- `python/tests/test_lifecycle_and_timeouts.py`: add `"revoke_tenant": lambda a:
  a.revoke_tenant("aid:x", timeout=0.1)` to the `ADMIN_CALLS` dict (lines 125-146), picking up both
  generic timeout tests automatically.
- **Deliberately not added**, matching sibling coverage exactly (see Open Questions): a dedicated
  NOT_FOUND-mapping test for this method, and an idempotency ("call it twice") test. Neither exists
  for `remove_party`/`revoke_grant`, and adding one here only would be inconsistent gold-plating,
  not matching an established pattern.

**Docs:** None in this phase (Phase 4).

---

### Phase 2 — TypeScript: `SeamAdminClient.revokeTenant`

**Status:** DONE — implemented exactly as planned, no approach divergence. Solo Opus verify PASS
on round 1: implementation matches spec verbatim at `ts/src/admin.ts:269-277`; interceptor-based
NotFoundError mapping confirmed and empirically exercised via `errors_taxonomy.test.ts:121-128`;
both new assertions survived mutation testing (deadline override, wire-shape payload). No gaps.
**Risk:** complex — same reasoning as Phase 1 (new public-SDK-surface method, network/service
boundary). Solo gate.

**Delivers:** A working, tested `revokeTenant(subjectAid)` method on the TypeScript admin client.

**Depends on:** nothing (same reasoning as Phase 1 — the generated stub already carries the
symbol). Independent of Phase 1 — the two language clients share no code.

**Files:**
- `ts/src/admin.ts`
- `ts/tests/unit_plumbing.test.ts`

**Approach:** Add `revokeTenant` to `SeamAdminClient` (`ts/src/admin.ts`), in the
`// ── Governance / tenancy ──` section, after `listTenants` (ends line 267) and before
`registerParty` (starts line 270), matching `removeParty`'s exact shape (`admin.ts:278-283`:
`async`, `void`-returning, doc comment with purpose + required scope):

```ts
/** Revoke (soft-delete) a subject AID's enrollment — the inverse of `enrollTenant`. The durable
 * row is tombstoned (never deleted) and the in-memory binding is evicted with no restart.
 * Idempotent: revoking an already-revoked AID succeeds. An AID with no enrollment row at all gets
 * a `NotFoundError`; a tenant-scoped operator gets the same success as an idempotent re-revoke
 * instead, so it cannot use this to probe another tenant's AIDs (seam-runtime #951). Requires the
 * `tenant:revoke` operator scope. */
async revokeTenant(subjectAid: string, opts?: UnaryCallOptions): Promise<void> {
  await this.admin.revokeTenant({ subjectAid }, call(opts));
}
```

No explicit `try/catch` — the `errorMappingInterceptor()` installed in `SeamAdminClient.connect`
(`admin.ts:186-194`, defined `errors.ts:108-116`) already retypes every unary call's error, exactly
as it does for `removeParty`/`revokeGrant`. The `streamEvents`/`reportEventsConsumed` exception to
this (explicit `try/catch { throw toSeamError(e) }`, `admin.ts:405-435,446-455`) exists only because
streaming errors surface after the interceptor's `next(req)` resolves — irrelevant to this plain
unary call. The `ADMIN_CALLS` deadline-plumbing table drives against a generic `fakeTransport`
(`unit_plumbing.test.ts:69-126`) — no new fixture code is needed for `RevokeTenant`, same as Python.

**Edge cases & failure modes:** Same as Phase 1 (NOT_FOUND via the interceptor for free;
idempotency and validation are server-side, untested here, matching sibling methods).

**Acceptance criteria:**
- `admin.revokeTenant("aid:x")` sends `{ subjectAid: "aid:x" }` as `RevokeTenant` over the
  transport and resolves to `undefined` on success.
- `revokeTenant` honors both the default admin timeout and an explicit override, verified by the
  existing generic deadline-plumbing loop in `unit_plumbing.test.ts` (lines 155-169) — which only
  happens once it's added to the `ADMIN_CALLS` table there.
- `npm test` (in `ts/`) passes, remaining at 0 failed (currently 182 pass / 10 skip, plus whatever
  this phase adds).

**Tests:**
- `ts/tests/unit_plumbing.test.ts`: add `revokeTenant: (a, o) => a.revokeTenant("aid:x", o),` to the
  `ADMIN_CALLS` table (lines 133-153) — covers default + override deadline plumbing automatically.
- Add a wire-shape assertion inside the existing test at line 180,
  **`"placeGrant / revokeGrant / listGrants / removeParty wrap SeamAdmin verbatim"`** — rename it
  to include `revokeTenant` (e.g. `"placeGrant / revokeGrant / listGrants / removeParty /
  revokeTenant wrap SeamAdmin verbatim"`) and add: call `admin.revokeTenant("aid:x")` against
  `fakeTransport`, assert `calls[n].method === "RevokeTenant"` and `calls[n].input` deep-equals
  `{ subjectAid: "aid:x" }`, mirroring the `removeParty` assertion shape
  (`assert.deepEqual(calls[3]!.input, { partyId: "party-1" })`, lines 204-206).
- **Deliberately not added** (same reasoning as Phase 1): a dedicated NOT_FOUND or idempotency
  test. `errors_taxonomy.test.ts:25-36` already pins `NotFoundError ⇄ Code.NotFound` generically.

**Docs:** None in this phase (Phase 4).

---

### Phase 3 — Contract manifests, and the `VerifyAnchorRequest.tenant` decision

**Status:** DONE — implemented with one deliberate deviation from the Approach's literal text (see
below); verify round found the deviation already correctly applied, no code gap.
**Risk:** complex — gates CI for the whole SDK (`check-contract.sh`) and carries a real judgment
call (the `VerifyAnchorRequest.tenant` deferral, recorded in `DECISIONS.md`). Solo gate.

**Divergence from plan:** step 5's literal citation text below (`` `python/seam_sdk/_gen/.../seam_pb2.pyi:706-712` ``,
`` `ts/gen/.../seam_pb.ts:2584-2596` ``) would have put a line-numbered anchor into a gitignored,
regenerated file **inside `DECISIONS.md`**, which `test_no_document_line_anchors_into_a_generated_tree`
forbids for every doc in `DOCS` (`DECISIONS.md` included) — running it verbatim turns the suite red.
The actual `DECISIONS.md` entry cites those stubs by symbol name (`seam_pb2.pyi` / `seam_pb.ts`)
instead, per that same test's own sanctioned alternative. Same substitution applies everywhere
below that names a generated-stub line number for use inside `DECISIONS.md` prose.

**Delivers:** `check-contract.sh` reaches exit 0; the pre-existing
`test_field_manifest_gate.py::test_an_exact_match_of_the_known_lag_downgrades_to_a_note_naming_the_lag_file`
failure (Context's Baseline) is resolved; the deliberate non-wiring of `VerifyAnchorRequest.tenant`
is recorded as an actual decision, not a silent gap.

**Depends on:** Phase 1 and Phase 2 (the manifest commit must land *after* the clients that wire
`RevokeTenant` exist, per `contract/rpc-manifest.txt`'s own ordering rule quoted above — otherwise
a committed manifest would describe a verb the clients don't yet carry, the exact state the gate
exists to prevent).

**Files:**
- `contract/rpc-manifest.txt`
- `contract/field-manifest.txt`
- `DECISIONS.md`

**Approach:**
1. Add `SeamAdmin/RevokeTenant` to `contract/rpc-manifest.txt`, sorted between
   `SeamAdmin/RevokeGrant` (line 41) and `SeamAdmission/Admit` (line 42) — confirmed
   `"SeamAdmin/" < "SeamAdmission/"` lexically. (45 RPC entries after, was 44.)
2. Add `RevokeTenantRequest/subject_aid` to `contract/field-manifest.txt`, sorted between
   `RevokeGrantRequest/to_ns` (line 368) and `RunDecisionRequest/context_refs` (line 369).
3. Add `VerifyAnchorRequest/tenant` to `contract/field-manifest.txt`, sorted immediately after
   `VerifyAnchorRequest/party_id` (line 397).
4. Do **not** run `scripts/check-contract.sh --write-manifest` for any of the above. Confirmed in
   review: that flag rewrites **three** files from whatever the live stubs currently expose
   (`scripts/check-contract.sh:612-681` — `contract/rpc-manifest.txt:635-643`,
   `contract/field-manifest.txt:645-652`, **and** `contract/event-field-manifest.txt:658-664`),
   then deletes `contract/expected-local-lag.txt:675-679`. Using it here would silently absorb
   `VerifyAnchorRequest.tenant` as a "decided" surface with no individual record of the decision,
   and would risk sweeping in any other BSR drift present at write time. Three hand-edited lines,
   each reviewable in the diff, is the right-sized action.
5. Add a `DECISIONS.md` entry for the `VerifyAnchorRequest.tenant` non-wiring, following the
   existing `GetEscalationDelivery` entry's template (`DECISIONS.md:2244-2284` — a field/verb that
   "lands on the contract; the SDK does not carry it yet — manifest records it, hand-written
   clients do not wire it", with a `Decided by`, a `Re-open trigger and owner`, and a `Status`):
   - **Decision:** `VerifyAnchorRequest.tenant` lands on the contract; the SDK does not carry it yet
     — the field-manifest records it, `verify_party_anchor`/`verifyPartyAnchor` do not wire it.
   - **Decided by:** Opus, alongside wiring `RevokeTenant` (same PR).
   - **Why:** the write side is not on the contract — `RegisterPartyRequest` carries only
     `party_id`/`pubkey` (`python/seam_sdk/_gen/seam/api/v1/seam_pb2.pyi:706-712`,
     `ts/gen/seam/api/v1/seam_pb.ts:2584-2596`), so no SDK caller can create a tenanted party today.
     Wiring the read-side filter alone would expose a parameter nothing can populate.
   - **Re-open trigger and owner:** `seam-runtime#903` ("seam-event.v1: refuse tenant-less events
     at the producer...", confirmed **OPEN**) Phase 3 — the party-registration write-side —
     landing. Re-open and wire both halves together when it does.
   - **Status:** CONFIRMED-DEFERRED.
6. File a seam-sdk tracking issue (`gh issue create -R zer07labs/seam-sdk`) for this specific
   deferral, citing `seam-runtime#903`, so it's discoverable without reading `DECISIONS.md`
   end-to-end.

**Edge cases & failure modes:** If `VerifyAnchorRequest.tenant` is wired later without the write
side existing, it would be dead client code (settable but never populatable from this SDK) — the
DECISIONS.md entry exists precisely to keep that sequencing visible. Proto3 scalar fields default
to `""` when unset, so leaving it unwired changes no existing caller's behavior in the meantime.

**Acceptance criteria:**
- `contract/rpc-manifest.txt` contains `SeamAdmin/RevokeTenant` in sorted position (45 entries, was
  44).
- `contract/field-manifest.txt` contains both `RevokeTenantRequest/subject_aid` and
  `VerifyAnchorRequest/tenant` in sorted position.
- `make generate && STREAM=1 EVENTS=1 ./scripts/check-contract.sh` exits 0 — the first point in the
  plan where the full gate is green, and the deliverable the cross-session request actually asked
  for.
- `python/.venv/bin/pytest -q` is fully green (no `failed`) — specifically confirms
  `test_field_manifest_gate.py::test_an_exact_match_of_the_known_lag_downgrades_to_a_note_naming_the_lag_file`
  now passes, closing the Baseline failure from Context. This is a stronger, independent signal
  than the gate script alone. **Exact count depends on what Phases 1-2 already added** — don't gate
  on a number restated here going stale; gate on `failed` being absent. As of Phase 1's own verify
  round, pristine `main` is `1 failed, 1325 passed, 22 skipped` and Phase 1 alone brings it to
  `1 failed, 1327 passed, 22 skipped` — so after Phase 2 adds its own (TypeScript-side, not
  Python-test-count-affecting) work and this phase's fix lands, expect `1328 passed, 22 skipped, 0
  failed` in this same environment, but re-run rather than trust the arithmetic.
- `DECISIONS.md` contains the `VerifyAnchorRequest.tenant` entry in the format above.
- A seam-sdk issue exists, citing `seam-runtime#903`.

**Tests:** No new test files — this phase's acceptance criteria are the gate script and the
existing `test_field_manifest_gate.py` suite, both already written.

**Docs:** `DECISIONS.md`, as above. This is the one judgment call in this plan worth a durable
record — plain RPC wiring (Phases 1-2, 4) does not get one, matching how `RemoveParty`/`RevokeGrant`
and `GetEscalation` itself (as opposed to the deferred `GetEscalationDelivery`) never did.

---

### Phase 4 — Docs, a tracking issue, and finalization

**Status:** DONE — implemented with two deviations from the plan's literal text, both required by
the test suite, neither a scope change the verifier flagged as a problem:
1. The CHANGELOG header cites both issues (`seam-sdk #173, seam-runtime #951`), not just the
   runtime one as step 2's literal text showed — matching every sibling Unreleased header's
   convention of citing the local issue, which the plan's own stated precedent (`GetEscalation`)
   actually followed too (its runtime cite sits in the bullet body, not the header — the plan
   misread that precedent).
2. `COMPATIBILITY.md` and `DECISIONS.md` were touched despite not being in this phase's `Files`
   list and despite step 2's "do not add a `COMPATIBILITY.md` entry" instruction — this is not a
   new entry, it's repointing one pre-existing `CHANGELOG.md:NNN` citation in each file that the
   new CHANGELOG entry's 11 lines pushed stale (`1022-1039` → `1033-1050`, content byte-identical,
   confirmed required by reverting it and watching the citation-anchor tests go red).
**Risk:** simple — docs-only (`CHANGELOG.md`, `README.md`) plus issue filing; fully contained,
cheap to redo. No neighbor to batch with (last phase), so it still gets its own solo gate.

**Delivers:** The `RevokeTenant` addition is discoverable the way every other SDK method is: a
CHANGELOG entry, a README mention, and a seam-sdk issue a reader can find from the runtime side.

**Depends on:** Phase 3 (the CHANGELOG/README entries describe a shipped, gate-clean addition; and
this phase's finalization check needs Phase 3's green gate).

**Files:**
- `CHANGELOG.md`
- `README.md`

**Approach:**
1. File a seam-sdk tracking issue (`gh issue create -R zer07labs/seam-sdk`) for `RevokeTenant`
   itself, summarizing the ask and linking `zer07labs/seam-runtime#951` for the semantics —
   mirroring the dual-citation convention `GetEscalation` used (seam-sdk#157 locally,
   `(seam-runtime #517)` in the changelog).
2. Add one new entry to `CHANGELOG.md`'s `## Unreleased` section, appended after the current last
   entry (`### Added — \`verify/\`: a truncation check...`, ending just before `## 0.22.0 —
   2026-10-02` at line 109), following the single-change-per-header convention every other
   Unreleased entry uses (`### Added — <title> (#issue)`, e.g. line 51's `### Added —
   \`supersedes\` on the commit path (#141)`):
   ```markdown
   ### Added — `revoke_tenant` / `revokeTenant` (seam-runtime #951)

   - **`revoke_tenant`/`revokeTenant`** — soft-delete a subject AID's enrollment, the inverse of
     `enroll_tenant`/`enrollTenant`: `SeamAdmin.RevokeTenant` on the wire, taking just
     `subject_aid` and returning nothing. The durable row is tombstoned (never deleted); the
     in-memory binding is evicted with no restart. Idempotent: revoking an already-revoked AID
     succeeds. An AID with no enrollment row at all gets `NotFoundError`; a tenant-scoped operator
     gets the same success as a re-revoke instead, so the error can't be used to probe another
     tenant's AIDs. Requires the `tenant:revoke` operator scope. Go, Java and Kotlin have no
     admin-surface client to wire this into (crypto shims only, by design).
   ```
3. Update `README.md`: add `revoke_tenant`/`revokeTenant` to the governance-RPC list at line 455,
   and extend the symmetry sentence at line 459 (*"Party/grant lifecycle is symmetric:
   `register_party` has its inverse `remove_party`..."*) to also name the enroll/revoke tenant
   pair.

Do **not** add a `COMPATIBILITY.md` entry — confirmed (and reconfirmed in review) that individual
admin RPCs (`RemoveParty`, `RevokeGrant`, `GetEscalation`) have never gotten one; that file's stated
scope is version/semver-lockstep caveats, not a verb changelog. `RevokeTenant` itself does not get a
`DECISIONS.md` entry — mechanical wiring with zero ambiguity, unlike the Phase 3 deferral.

**Edge cases & failure modes:** None — documentation-only phase.

**Acceptance criteria:**
- A seam-sdk issue exists for `RevokeTenant`, references `zer07labs/seam-runtime#951`, and is
  linked from the PR.
- `CHANGELOG.md`'s `## Unreleased` section contains the new entry, correctly formatted and citing
  `seam-runtime #951`.
- `README.md` lines 455 and 459 (or their shifted equivalents after edits) mention
  `revoke_tenant`/`revokeTenant`.
- Full test suites green: `python/.venv/bin/pytest -q` (Python, 0 failed), `npm test` (TypeScript,
  in `ts/`, 0 failed), plus `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` exiting 0 — this is the
  finalization gate for the whole plan, not just this phase.

**Tests:** No new tests — this phase verifies the whole plan's test suites are green together.

**Docs:** `CHANGELOG.md` and `README.md`, as above. No `seam/docs/` or `seam/CLAUDE.md` change —
this adds no repo, no dependency edge, no deploy/topology change, and resolves no `⟨confirm …⟩`
placeholder.

## Long-term posture

This is purely additive and non-breaking: a new method on an existing client class, wrapping an
RPC that already exists on the wire. Nothing here is a one-way door — `revoke_tenant`/`revokeTenant`
could be renamed, deprecated, or have its signature extended (e.g. an optional reason string, if the
runtime ever adds one) without affecting any existing caller, since this plan introduces the only
caller. The one deferred decision (`VerifyAnchorRequest.tenant`, Phase 3) is explicitly recorded
rather than silently absorbed, and is cheap to reverse in the direction that matters: wiring it in
later, once `seam-runtime#903` Phase 3 exists, is additive.

No debt is being taken on. The alternative that was rejected — folding both unrelated field gaps
straight into the manifest via `--write-manifest` — would have been the fast path, and was rejected
specifically because it trades a visible, reviewable decision for a silent one, which is the exact
failure class `contract/rpc-manifest.txt`'s own header was written to prevent.

## Enterprise concerns

- **Security:** `tenant:revoke` scope enforcement is entirely server-side (confirmed: no
  client-side scope registry exists anywhere in `python/seam_sdk/` or `ts/src/` — scope strings are
  documentation-only prose in every sibling method's docstring, and this plan matches that
  convention rather than inventing enforcement the rest of the SDK doesn't have).
- **Reliability / idempotency:** Retry-safety is a server-side property (`seam-runtime#951`,
  confirmed by the proto comment); the SDK adds no retry logic and needs none — a caller that
  retries a timed-out `revoke_tenant` is already safe by the runtime's own design.
- **Observability:** No SDK-side logging/metrics are added, matching every sibling admin method —
  the audit trail (`tenant_revoked` entry) is server-side.
- **Rollback:** Reverting this PR is a pure code revert with zero data-migration exposure — no
  schema, no persisted state, no migration anywhere in this plan.
- **Scale:** No scale concerns — a single unary RPC wrapper, identical cost profile to its four
  siblings.
- **Release-gate interaction:** explicitly verified this does NOT touch or unblock
  `release-on-runtime.yml`'s wire-framing hold (Context's Baseline paragraph) — stated so nobody
  downstream mistakes a merged PR here for a signal that releases have resumed.

## Open questions

1. **`VerifyAnchorRequest.tenant` (Phase 3): decided, not escalated — on corrected grounds.** The
   first draft of this plan claimed the field "carries no proto doc comment" and that "no runtime
   issue or plan was found" — both wrong, caught in review: the field does carry a doc comment
   (`ts/gen/seam/api/v1/seam_pb.ts:2139-2147`, naming `seam-runtime#903` Phase 3) naming the
   partition to verify `party_id` in. The real, correct basis for deferring is that the *write*
   side isn't on the contract yet (`RegisterPartyRequest` has no `tenant` field), so wiring the read
   filter alone would be dead client code. Recorded in `DECISIONS.md` (Phase 3) with an explicit
   re-open trigger (`seam-runtime#903` Phase 3 landing) rather than left as an `ASSUMPTIONS.md`
   `UNCONFIRMED` — this is exactly the class of judgment call `DECISIONS.md` exists for, per the
   `GetEscalationDelivery` precedent.
2. **PR strategy — recommend one PR.** All four phases are one coherent story (wire the RPC that
   was asked for, then close the contract gap it depends on, including the one other gap found
   blocking the same gate) — matching PR #154's own precedent of bundling multiple small, related
   changes into a single PR rather than fragmenting review. `/implement` decides for real, per its
   own phase-shippability judgment.
3. **No Fable escalation.** This is an additive, fully-precedented change (four existing sibling
   methods in each language establish the exact pattern) with no public-contract ambiguity, no
   schema shape decision, no auth-model change, and no cross-repo write — it does not meet the
   Autonomy ladder's "critical" bar, so Opus proceeds directly rather than manufacturing a gate.
4. **Closing the loop with the originating cross-session request.** Once this ships, the reply to
   the `seam-runtime` session (per its own ask: "reply here with the PR link and merge state... and
   say whether your CI for it went green") should also carry: the two corrections from Context
   (Go/Java/Kotlin out of scope by design; the unrelated `VerifyAnchorRequest.tenant` gap it didn't
   know about, now recorded in `DECISIONS.md` and tracked against `seam-runtime#903`); and the fact
   that `check-contract.sh` going green here does **not** unblock `release-on-runtime.yml` (separate
   wire-framing hold) — not just a bare "done."

## Repo map

- `contract/rpc-manifest.txt`, `contract/field-manifest.txt` — the two-directional contract-surface
  declarations `check-contract.sh` diffs against the generated stubs.
- `python/seam_sdk/admin.py` — `SeamAdminClient`; all `SeamAdmin.*` RPCs are hand-wired here,
  sync-only, grouped into `# ──`-delimited sections (Governance/tenancy, cross-namespace grants,
  erasure, etc.).
- `python/seam_sdk/errors.py` — the typed exception hierarchy (`SeamError`/`SeamRpcError`/
  `NotFoundError`/...) and `_MappedStub`, which auto-converts every `SeamAdminClient` RPC's
  `grpc.RpcError` to its typed subclass.
- `python/tests/test_admin.py` — `RecordingAdmin` (fake in-process servicer) + unit tests for every
  `SeamAdminClient` method's wire shape; also the live erasure-flow + operator-token-auth tests.
- `python/tests/test_lifecycle_and_timeouts.py` — the `ADMIN_CALLS` table + two generic
  introspection tests that enforce every admin method accepts/honors a `timeout` kwarg.
- `ts/src/admin.ts` — the TypeScript mirror of `admin.py`; same section grouping, all `async`,
  `errorMappingInterceptor` installed once in `SeamAdminClient.connect` instead of per-method.
- `ts/src/errors.ts` — the TS typed error hierarchy + `errorMappingInterceptor`/`toSeamError`.
- `ts/tests/unit_plumbing.test.ts` — `fakeTransport` (fake Connect transport) + the `ADMIN_CALLS`
  deadline-plumbing table + per-verb wire-shape assertions.
- `scripts/check-contract.sh` — the contract-freshness gate; probes generated stubs against
  `contract/*-manifest.txt`, per language, with `--write-manifest` as an escape hatch this plan
  deliberately does not use (see Phase 3).
- `python/tests/test_field_manifest_gate.py` — exercises `check-contract.sh`'s field-manifest logic
  directly against scratch stub copies; currently has one failing test due to the two gaps this
  plan closes.
- `CHANGELOG.md` — `## Unreleased` section, one `### <Type> — <title> (#issue)` header per change.
- `README.md` lines ~455-459 — the governance-RPC list and the party/grant symmetry sentence.
- `DECISIONS.md` — durable judgment-call record; `GetEscalationDelivery`'s entry
  (`DECISIONS.md:2244-2284`) is this plan's template for the `VerifyAnchorRequest.tenant` entry.
- `go/crypto/`, `java/src/main/java/com/zer07labs/seam/SeamCrypto.java`,
  `kotlin/src/main/kotlin/com/zer07labs/seam/SeamCrypto.kt` — confirmed out of scope: crypto +
  conformance only, no RPC-wrapping client code exists in any of the three.

## Plan review

**Round 1 — verdict REVISE.** Run by a fresh Opus agent (no prior context on this plan), against
the live code — not this plan's prose. It re-ran `make generate`, independently re-derived the
exit-5-then-6 gate-ordering claim by manipulating the gate's env-var manifest overrides, read every
cited file:line in `admin.py`/`admin.ts`/`errors.py`/`errors.ts`/the two test files, fetched
`seam-runtime#951`, and ran the full Python suite to check the baseline. Findings applied in this
revision:
- **Factual correction:** the semantics citation wrongly pointed at `seam_pb2.py` and
  over-attributed content to `#951`; corrected to cite `seam_pb2_grpc.py`/`seam_pb.ts` as the sole
  authority and demote `#951` to the decision's paper trail (Context).
- **Phase merge:** the original Phase 1 (field-manifest-only) was not independently verifiable in
  isolation (the field check never runs while the RPC check fails first) — merged into the new
  Phase 3.
- **Phase reorder:** client wiring now precedes the manifest write, matching
  `contract/rpc-manifest.txt`'s own stated rule, which the original draft had backwards.
  (Renumbered 5 phases down to 4.)
- **Open Question 1 rewritten:** the original factual basis ("no doc comment, no runtime issue") was
  wrong; replaced with the real basis (write side not on the contract yet) and a concrete re-open
  trigger (`seam-runtime#903` Phase 3).
- **`DECISIONS.md` routing change:** the `VerifyAnchorRequest.tenant` deferral now gets a
  `DECISIONS.md` entry (Phase 3), following the `GetEscalationDelivery` precedent, rather than
  being left as an `ASSUMPTIONS.md`-only note.
- **New baseline fact added:** the repo-wide Python suite is currently red
  (`test_field_manifest_gate.py`) from exactly the two gaps this plan closes — added to Context and
  used as Phase 3's independent acceptance signal.
- **New doc surface added:** `README.md`'s governance-RPC list and symmetry sentence, missed in the
  original draft — added to Phase 4.
- Several line-number and quote-attribution corrections applied throughout (admin.py section
  boundaries, `_MappedStub`'s real line range, the RPC-manifest entry count, the `--write-manifest`
  blast radius, the TS test-rename requirement, the TS insertion point).

No full second round was run: the reviewer's findings were concrete and directly actionable (each
named the exact section and the exact fix), applied here in full, and none of them contested the
remaining structure (scope, test-deferral reasoning, no-Fable call, one-PR recommendation, skipping
`plans/cross-repo/`/`seam/docs/`) — re-reviewing content that passed verification unchanged would
not find anything new. Instead, the three new claims this revision introduced on top of the
reviewer's own citations — ones the reviewer named but this revision had to transcribe into new
prose (the `DECISIONS.md` template, the `README.md` lines, `seam-runtime#903`) — were independently
spot-checked directly against the repo before treating this plan as final: `README.md:450-462`
confirmed the governance-RPC list and the symmetry sentence read exactly as described;
`DECISIONS.md:2244-2284` confirmed the `GetEscalationDelivery` entry's exact shape (Decided
by/What it is/Why not/Nothing regresses/Re-open trigger and owner/Verdict+Status), which Phase 3's
new entry follows; `gh issue view 903 -R zer07labs/seam-runtime` confirmed it is real, OPEN, titled
"seam-event.v1: refuse tenant-less events at the producer, and publish the legacy cutoff seq" — the
broader initiative `ts/gen/seam/api/v1/seam_pb.ts:2139-2147`'s "#903 Phase 3" doc comment names as a
sub-phase (the issue's own top-level body covers the event-tagging half; Phase 3's party-registration
extension is this plan's actual citation, visible in the generated doc comment rather than the
issue's top-level text — consistent, not contradictory). If `/implement` finds any further factual
drift while executing (e.g. BSR main having moved again), treat this file's citations as of this
session and re-verify before trusting them.
