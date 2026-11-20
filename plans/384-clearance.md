# #384 — opt-in `x-seam-clearance` on the decision reads (+ #391 flaky release-gate test)

Wave 2026-11-21 W1, seam-sdk unit. Brief: `seam-runtime/plans/wave-2026-11-21/seam-sdk.md` items 1–2.
Item 3 (#368) is out of scope. One PR, branch `feat/384-clearance-391-flake`.

## Context

seam-runtime applies the namespace's §2.3 decrypt-clearance floor on reads, taking the caller's
clearance from `x-seam-clearance` metadata or the header (`grpc_clearance`, seam-runtime
`crates/seamd/src/grpc.rs` ~1243 on origin/main; HTTP `http_clearance`, `server.rs` ~2859). On
origin/main it is read by **GetDecision** (:2272), **ReplayDecision** (:2294, since runtime 0.101.0,
#1812) and **GetCommitmentProof** (:2319). If the value is absent **or unrecognised**, the runtime uses
`Public`, so a governed-namespace replay or proof is now `PERMISSION_DENIED` for every SDK caller.
That is because no SDK can send the header today (`DEFERRED.md:2`, #273 Q2).

Parse is exact and case-sensitive: `Public|Internal|Confidential|Financial|Pii|Phi`
(`crates/seam-types/src/classification.rs:48-58`). Issue #384's text lists `Restricted`, which is stale
and does not exist. The brief's list is correct.

**Where the runtime honours the header.** It honours it only on a data plane in `allow` subject-header
posture, i.e. behind a trusted gateway. A `deny` plane (`SEAM_GRPC_SUBJECT_HEADERS=deny`, the
credential-only posture, e.g. partner) strips it (`grpc.rs:238-241`), and so does a peer-cert plane
(`:249`). On those planes the read is at Public. The header is not covered by the #508 call signature.
The SDK can only send it; the docs must say this.

**Shape today.** Python (`client.py`, `aio.py`) and TS (`ts/src/client.ts`) have hand-written clients
whose RPCs go through `_credentialed_call` / `credentialedCall`. Those call `send(md)` once, plus once more on the
#275 refresh. Go, Java and Kotlin are crypto shims with no coordination client: callers use generated
stubs, and the SDK ships metadata helpers (`go/routing`, `TenantRouting.java/.kt`).

**Release.** The SDK version always equals a runtime version (`release-on-runtime.yml` input:
"must match the runtime's"). Runtime 0.102.0 is already published as SDK 0.102.0. This change goes
under `## Unreleased` and is published by the release that the next runtime publish dispatches (0.103.0,
the wave leader's train). There is no SDK-only version.

## Decisions (Opus, reversible, logged to DECISIONS.md at implement time)

- **D1: GetDecision is included** in Python and TS (`get_decision`/`getDecision`).
  - The runtime reads clearance there too.
  - The DEFERRED entry the brief tells us to update (#273 Q2) is about exactly that read: a record
    reads `CLEARANCE_DENIED` because no clearance is sent.
  - Leaving it out would leave the SDK able to replay a record it cannot explain.
  - In Go, Java and Kotlin the helper is per-call, so it applies to whatever call the caller attaches it to.
- **D2: values are a closed set, validated client-side, before any RPC (admission included).** An
  unknown value would silently downgrade to Public at the runtime. That fails closed, but it is
  undiagnosable. Per-language error idiom:
  - Python `ValueError` (precedent `admin.py:574-577`)
  - TS `InvalidArgumentError` (precedent `admin.ts:433-437`)
  - Go sentinel `ErrClearance`
  - Java `IllegalArgumentException`
  - Kotlin `require`
- **D3: default `None`/`undefined` leaves the wire byte-identical.** Python metadata stays `None` when
  there is no credential and no clearance; TS headers stay `undefined`. The existing pins
  (`_assert_no_credential_sent`, TS "omitted sends no headers") must still pass unmodified.
- **D4: no "Public" special case.** Sending `Public` explicitly is allowed and goes on the wire. It is
  the caller's choice and equals the default at the runtime. We do not elide it, so the wire matches
  what the caller asked for.
- **D5: Java/Kotlin shape.** An enum `Clearance` with a wire value, `parse(String)` and
  `interceptor()`, which returns a `ClientInterceptor`. The interceptor **sets** the key, replacing
  any earlier value, so a caller cannot end up with two values. It does not use `MetadataUtils`, which
  is in `grpc-stub`, and that is test-only today. It does not use `CallCredentials`, which is for auth.
  Usage: `stub.withInterceptors(Clearance.CONFIDENTIAL.interceptor()).replayDecision(req)`.
- **D6: Go shape.** A new package `go/clearance` with:
  - `type Clearance string` and its six consts
  - `Parse(string) (Clearance, error)`
  - `NewContext(ctx, Clearance) (context.Context, error)`, which validates and *replaces* any existing
    `x-seam-clearance` in the outgoing metadata (copy then `Set`, never append)
  This is per-call, which matches a two-verb option. A channel-wide interceptor (the routing style) is
  rejected for that reason.

## Phases

### P1 — #391: fix the flaky `test_a_red_release_commit_ci_leaves_main_untouched_and_no_tag`
- **Risk:** simple
- **Status:** DONE (Opus verify PASS, 1 round; the deterministic repro is `{ sleep 0.05; printf dummy; } | stub` under pipefail: old stub 141, new stub 0)
- **Delivers:** the root cause of the flake is removed, and a failure prints the full captured issue body.
- **Depends on:** none.
- **Files:** `scripts/test_release_refire_gate.py`, and the script/harness it exercises if the root
  cause is there.
- **Approach:** diagnose from the failing CI run 44625461026 log, plus a local repro under CI-like
  env and looping. Fix the nondeterminism, not with a retry.
- **Edge cases:** env leaking from the CI runner (`GITHUB_*`, `BASE_SHA`); ordering between tests.
- **Acceptance:**
  - The root cause is stated with `file:line` and evidence.
  - Evidence comes from the attempt-1 log (`gh run view 44625461026 --attempt 1 --log-failed`) AND a
    deterministic repro that fails before the fix and passes after; looping alone proves nothing for a
    test that already passed locally.
  - The whole file is green.
  - An assertion failure message contains the full issue body.
- **Tests:** the test itself, looped; full `scripts/test_release_refire_gate.py`.
- **Diagnosis (pre-implement):** the fake `buf` stub (`_dry_run`, old :410-411) exits without reading
  stdin, while the fresh step runs `printf "$BUF_TOKEN" | buf registry login --token-stdin`
  (`release-on-runtime.yml:253`) under `pipefail`. When the stub wins the race, printf takes SIGPIPE
  (141), the fresh gate reads red, and the body records release-commit CI as "skipped". Linux container
  repro: 6/5000 with the old stub, 0/5000 fixed; `sleep 0.05` before printf fails 100% with the old
  stub. Fix: the stub drains stdin on `--token-stdin`; the step subprocess gets `stdin=DEVNULL`;
  `_why(r)` is attached to the body assertions.

### P2 — Python: `clearance=` on get_decision / replay_decision / get_commitment_proof / verify_decision (sync + aio)
- **Risk:** complex
- **Status:** DONE (Opus verify PASS, 1 round; also exports `CLEARANCE_HEADER`, one more name than planned)
- **Delivers:**
  - Exported constants `CLEARANCE_PUBLIC … CLEARANCE_PHI` and a frozenset `CLEARANCES`, following the
    `ENROLMENT_KIND_*` precedent (`admin.py:81-92`, `__init__.py` exports + `__all__`).
  - A keyword-only `clearance: Optional[str] = None` on the 4 methods × 2 clients.
- **Depends on:** none.
- **Files:**
  - `python/seam_sdk/_clearance.py` (new: constants, `_check_clearance`, `_with_clearance`)
  - `python/seam_sdk/client.py`, `python/seam_sdk/aio.py`, `python/seam_sdk/__init__.py`
  - `python/seam_sdk/_seal.py`, `python/seam_sdk/_allocation.py` (docstrings)
  - `python/tests/test_clearance.py` (new)
- **Approach:**
  - Validate at the top of each public method, before `_credentialed_call`, so a bad value makes zero
    RPCs (no admission either).
  - Inside each `send` lambda, use `metadata=_with_clearance(md, clearance)`:
    - `None` returns `md` unchanged
    - otherwise it returns `list(md or ()) + [("x-seam-clearance", clearance)]`
  - Because the lambda runs on the first send and on the #275 retry, both carry the header, and
    `_credentialed_call` does not change.
  - `verify_decision` forwards `clearance` to `get_commitment_proof`.
  - The type check rejects non-`str` (e.g. bytes) with `ValueError` as well.
  - The `_seal.py:46-49,111-112` and `_allocation.py:45-48,131-132` docstrings change from "this SDK
    sends no x-seam-clearance" to "pass `clearance=` on get_decision; honoured only where the runtime
    trusts it".
- **Edge cases:**
  - A wrong-case value (`"public"`) is rejected.
  - `""` is rejected.
  - Credential and clearance together: the header set is exactly {ticket, sig, clearance}.
  - Clearance without a credential: metadata is exactly `[("x-seam-clearance", v)]`.
- **Acceptance:**
  - The default wire is unchanged: existing `test_credential_wiring.py` / `test_credential_refresh.py`
    pass unmodified.
  - With `clearance=X`, each of the 4 verbs, sync and aio, sends `x-seam-clearance: X`, with and
    without a credential.
  - It is present on both attempts of a #275 refresh.
  - An invalid value raises `ValueError` naming the allowed set, and no RPC is recorded.
  - `CLEARANCES` is exactly the six runtime strings and is exported from `seam_sdk`.
  - `test_client_parity.py` (sync/aio signature parity) is green.
  - `ruff check` and `ruff format --check` are clean.
  - `test_compatibility_citations_resolve.py` is green, and any unanchored `client.py:N`/`aio.py:N`
    citation shifted by the edit is re-pointed.
  - Validation checks `isinstance(clearance, str)` before the set lookup, so `["Phi"]` is a `ValueError`.
  - The full Python suite is green.
- **Tests:** `python/tests/test_clearance.py`, reusing the `_Recorder`/`_AioRecorder` pattern
  (`test_credential_wiring.py:60-86`) and the `_Wire`/`h` fixture (`test_credential_refresh.py:114,192-230`).

### P3 — TypeScript: `clearance` on getDecision / replayDecision / getCommitmentProof / verifyDecision
- **Risk:** complex
- **Status:** DONE (Opus verify PASS, 1 round). Divergence: the labels and helpers live in a new `ts/src/clearance.ts`, mirroring Python's `_clearance.py`, to keep `client.ts` citation shifts small. `CLEARANCE_HEADER` is exported too. The tests use their own `wire()` fake rather than `fakeTransport`. Verifier nits closed: an unprintable value (BigInt, circular) still throws InvalidArgumentError, and a `@ts-expect-error` test pins clearance as decision-reads-only.
- **Delivers:**
  - `export type Clearance = "Public"|…|"Phi"`, `CLEARANCE_*` consts and `CLEARANCES: ReadonlySet<Clearance>`.
  - `export interface DecisionReadOptions extends CredentialedCallOptions { clearance?: Clearance }`,
    used only by the 4 verbs. This keeps the narrow-options rule (`client.ts:136-155`): an unwired
    option is a compile error elsewhere.
- **Depends on:** none.
- **Files:** `ts/src/client.ts` (docs at :507-508, :678-679 too), `ts/tests/clearance.test.ts` (new).
- **Approach:**
  - Validate before `credentialedCall` and throw `InvalidArgumentError(msg, Code.InvalidArgument)`;
    this runtime-checks JS callers too.
  - In each `send`, `headers: withClearance(headers, opts?.clearance)` returns `undefined` when both
    are undefined.
  - `verifyDecision` already passes `opts` through (:2215); only its type widens.
- **Edge cases:** same as P2; JS callers passing a non-string.
- **Acceptance:**
  - The existing `unit_plumbing.test.ts` "omitted sends no headers" passes unmodified.
  - Header present on the 4 verbs, with and without a credential, and on both attempts of the #275 retry.
  - An invalid value throws `InvalidArgumentError` with no transport call.
  - `npm run typecheck`, `npm run build` and `npm test` are green.
  - Python `test_compatibility_citations_resolve.py` is green; shifted `ts/src/client.ts:N` citations re-pointed.
- **Tests:** `ts/tests/clearance.test.ts`, reusing `fakeTransport` / `refreshWire` from `unit_plumbing.test.ts`.

### P4 — Go: `go/clearance` package
- **Risk:** simple
- **Status:** DONE (Opus verify PASS, batched with P5, 1 round). Verifier notes, non-blocking: `md.Copy()` after `FromOutgoingContext` is redundant (that map is already a copy), harmless; the error message reads "not one of" twice.
- **Delivers:** the D6 API, plus the `Header = "x-seam-clearance"` const and `ErrClearance`.
- **Depends on:** none.
- **Files:** `go/clearance/clearance.go`, `go/clearance/clearance_test.go`, `go/README.md` (a short section).
- **Approach:** see D6. Tests follow the `routing_test.go` raw-invoke style: a TCP/bufconn server with
  `UnknownServiceHandler` invoking `/seam.api.v1.SeamCoordination/ReplayDecision` and
  `/GetCommitmentProof` by name. This is because generated stubs are outside the go module.
- **Edge cases:**
  - Invalid or empty value returns `ErrClearance` with the ctx unchanged.
  - A ctx with NO outgoing metadata: `FromOutgoingContext` returns nil and `MD.Set` on nil panics, so
    start from `metadata.MD{}`. Test it.
  - Document that a caller's later raw `AppendToOutgoingContext` of the key can still duplicate; the
    runtime (tonic) reads the first value.
  - A second `NewContext` replaces the value rather than appending.
  - Other outgoing metadata (tenant, credential) is preserved.
- **Acceptance:**
  - The server receives exactly one `x-seam-clearance` value equal to the chosen one, on both verbs.
  - Without the helper, no header is sent.
  - Invalid input returns `errors.Is(err, ErrClearance)`.
  - `go test ./...` and `go vet ./...` are green; the Python citation test is green.

### P5 — Java + Kotlin: `Clearance` enum + interceptor
- **Risk:** simple
- **Status:** DONE (Opus verify PASS, batched with P4, 1 round). Divergence: Kotlin `parse` throws `IllegalArgumentException` directly instead of using `require` (same type). Known asymmetry: a Java caller passing `null` to Kotlin `parse(String)` gets Kotlin's NPE where Java's `parse` throws IAE. Null was not in scope.
- **Delivers:** the D5 API in both languages, with `HEADER` / `KEY` constants.
- **Depends on:** none.
- **Files:** `java/src/main/java/com/zer07labs/seam/Clearance.java`, `java/src/test/.../ClearanceTest.java`,
  `kotlin/src/main/kotlin/com/zer07labs/seam/Clearance.kt`, `kotlin/src/test/.../ClearanceTest.kt`.
- **Approach:**
  - Modelled on `TenantRouting` (`ForwardingClientCall.start`), but it `removeAll(KEY)` then `put`.
  - `parse` is exact-match and throws on anything else, including the enum constant *names*
    (`"PUBLIC"`): the wire string is the only accepted spelling.
  - Tests use the in-process server and hand-built `MethodDescriptor` pattern from `TenantRoutingTest`.
- **Acceptance:**
  - The in-process server sees exactly one value on both verbs, and none without the interceptor.
  - `parse` round-trips all six values and rejects `"public"`, `"PUBLIC"`, `""`, `"Restricted"`.
  - `./gradlew test --no-daemon` is green in both `java/` and `kotlin/` (JDK 17).

### P6 — Docs, compatibility, changelog
- **Risk:** simple
- **Status:** DONE (Opus verify GAPS then PASS, 2 rounds; round 1 found citation bookkeeping only: two missed re-points in PROGRESS and historical log lines rewritten by the remap script, restored).
- **Depends on:** P2–P5.
- **Files:**
  - `COMPATIBILITY.md`: §4 table, the :360-363 "…and nothing else" surface list, the "N/A, no client" rows
  - `README.md`: :701-702 contradicts the change; :623/:655 method lists
  - `DEFERRED.md`, `CHANGELOG.md`
  - `DECISIONS.md`: close/supersede :2994 (Q2), record D1–D6
  - `ASSUMPTIONS.md`: mark :1489-1494 superseded
  - `PROGRESS.md`: re-point any `DEFERRED.md:2` citation
- **Approach:**
  - **COMPATIBILITY §4:** a row in the Identity/credential surface table beside `x-seam-tenant`, plus
    a prose paragraph covering:
    - the six values
    - exact runtime versions: GetCommitmentProof since ≤0.4.0 (`1e3bbdda`); GetDecision seal
      attestation since 0.61.0 (#1535), allocation since 0.76.0; ReplayDecision since 0.101.0 (#1812)
    - semantics: on GetDecision clearance never errors, it only changes the `CLEARANCE_DENIED`
      availability on the view; on replay/proof it decides `PERMISSION_DENIED`
    - the allow/deny/peer-cert caveat
    - the default
  - **DEFERRED.md:2:** close the entry by removing the line; DECISIONS records the closure.
  - **README:** one short "Clearance" subsection near the decision-read methods, placed so no cited
    README line shifts. Check `test_compatibility_citations_resolve.py`, especially the anchor at README :166.
  - **CHANGELOG:** an `### Added — clearance on the decision reads (#384; ReplayDecision needs runtime 0.101.0+)` entry
    under `## Unreleased`. Check that no `CHANGELOG.md:N` citation shifts, or repoint it.
- **Acceptance:**
  - The full Python suite is green (citation tests).
  - `DEFERRED.md` no longer carries the #273 Q2 line.
  - COMPATIBILITY names all five languages' entry points.

### P7 — Release (post-merge, not a code phase)
- After merge to main, the change rides the next runtime-dispatched release (`release-on-runtime.yml`).
- Read back the published version: the `v<ver>` tag, `publish.yml` green, Cloudsmith internal +
  partner, `go/v<ver>`.
- Report it to the wave leader in the done report; seam-adapters raises its pin next.
- If the runtime has not published a new version by then, report the merge plus "publishes with
  runtime 0.103.0".

## Long-term posture
- The constants and option names are a public API addition. They are additive and default-off, so
  nothing existing changes.
- The value set is a closed copy of the runtime enum. If the runtime adds a classification, every SDK
  needs a release. That is acceptable, and the right failure mode: an unknown value fails loudly
  client-side instead of silently reading Public.
- Java and Kotlin are build-from-source only, so their helper reaches nobody until they are published.
  That is pre-existing (`COMPATIBILITY.md` ~355).

## Enterprise concerns
- **Security:** the SDK never decides clearance; it forwards the caller's assertion. The runtime's
  posture decides whether that assertion is trusted. The docs must not imply that the header grants
  access on a deny or peer-cert plane.
- **Observability:** a denied read stays `PERMISSION_DENIED`, which callers already map.

## Open questions
None for the owner. D1–D6 were decided by Opus as above.

## Plan review
- Round 1 (fresh Opus, against the code and runtime origin/main): **REVISE**. D1–D6 confirmed sound.
  Applied:
  - the citation-test gate is in every code phase, because P2–P5 edit cited files
  - P6's file list is widened
  - P1 acceptance needs a deterministic before/after repro
  - the Go nil-MD panic edge
  - exact per-verb runtime versions, and the GetDecision never-errors semantics
  - the CHANGELOG heading is reworded to survive the retitle
  - Python checks isinstance before the set lookup
- Round 2: not run. Every finding was a fully specified edit with no design change.
