# Read the runtime version over the data plane: `SeamTrust.ServerInfo` (B-RTVER, SDK half)

> **Issue:** [#307](https://github.com/zer07labs/seam-sdk/issues/307), "Release v0.63.0 did not publish".
> The register ID is B-RTVER (seam-mcp `plans/cross-repo/seam-runtime-post-onboarding.md:36-55`, epic
> zer07labs/seam-mcp#50).
> **Unblocked by:** seam-runtime PR #1544, merge `2e29be29` ("release train 0.63.0: the runtime version is
> readable by a client", seam-runtime#1360, now CLOSED). The BSR module `buf.build/zer07labs/seam` carries
> it, and `make generate` has pulled it, so the local stubs are current.
> **Contract source:** `seam-runtime/crates/seam-api/proto/seam/api/v1/seam.proto` at `2e29be29`, read with
> `git -C ../seam-runtime show 2e29be29:<path>` and never from the working tree, which may hold another
> branch's WIP. The parts that matter are `ServerInfoResponse` (:1326-1332, with its doc block) and
> `rpc ServerInfo(Empty) returns (ServerInfoResponse)` on `service SeamTrust` (:1363-1366, with its doc
> comment). The server side is `crates/seamd/src/grpc.rs:2030-2040` at the same commit (it reads
> `build_info::version()`, which is `env!("CARGO_PKG_VERSION")`, `crates/seamd/src/build_info.rs`).
> **Anchors** are true at seam-sdk `4760f9b` (= `origin/main` = `feat/server-info` HEAD).

## Status

TODO. Five phases, none started.

**Release state at plan time. Read this before Phase 5.** Runtime 0.63.0's `dispatch-sdk` stamped and tagged
**`v0.63.0` / `go/v0.63.0` at `4760f9b`** ("chore(release): v0.63.0 — follow the runtime version"). That
commit's CI regenerates from the BSR, so `check-contract` refuses with `+ SeamTrust/ServerInfo` in both
languages. CI run 40814094659 shows this: python and typescript failed at "check-contract (full surface
gate)", and `ci-ok` failed. Then `publish.yml` run 40814097723 failed at `ci-green` (npm, python and
registry-smoke were skipped). **v0.63.0 is tagged and was not published** (`git ls-remote --tags origin
'v0.63*'` → `v0.63.0^{}` and `go/v0.63.0^{}` = `4760f9b`). The same thing happened to v0.61.0 (#273) and
v0.50.0. `main` stays red until this plan's PR merges.

## Context

**Why.** B-RTVER asks that "a client learns the runtime version from discovery and from the data plane"
(`seam-mcp/plans/cross-repo/seam-runtime-post-onboarding.md:53-55`). The runtime shipped both halves in
0.63.0:
- `runtime_version` on `GET /v1/discovery`, which seam-control-plane#513/#528 republishes. seam-mcp
  already auto-detects from that (seam-mcp `PROGRESS.md:915`).
- the gRPC read this plan wires.

| Wire | Shape | Proto semantics (cited, `seam.proto` @ `2e29be29`) |
|---|---|---|
| `SeamTrust.ServerInfo(Empty)` | unary, returns `ServerInfoResponse` | "for a data-plane client that needs to pick a compatible SDK or adapter. Like `IssuerAid` it names no subject and needs no credential: only the plane's transport (TLS / mTLS) gates it." Additive (:1363-1366). |
| `ServerInfoResponse.runtime_version = 1` | `string` | "a semver string (the `seamd` crate version, e.g. "0.63.0"). Always set." It comes from the source `GET /version` reports, "so the transports cannot disagree. Nothing else about the build is carried" (:1326-1331). |

There is no commit field. The owner decided on 2026-10-28 to drop `runtime_commit` (the `2e29be29` commit
message says field 2 never shipped, so nothing is reserved). The response therefore has exactly one field
today.

**The gate.** `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` exits **5** with exactly
`+ SeamTrust/ServerInfo` in the python and the ts stubs. **Behind it is a second refusal.** Re-running
against a scratch rpc manifest that already declares the verb (`SEAM_RPC_MANIFEST=…`, measured) exits
**6** with exactly `+ ServerInfoResponse/runtime_version` in both languages. So the manifest diff Phase 3
writes is +1 RPC line and +1 field line, and nothing else. CLAUDE.md's rule applies: "a field the stubs
carry and the manifest does not is a DECISION". This plan's **Decisions** section is that decision.

**Measured baseline** (`cd python && .venv/bin/pytest -q`): **1 failed, 2395 passed, 39 skipped**. The one
failure is `test_field_manifest_gate.py::test_an_exact_match_of_the_known_lag_downgrades_to_a_note_naming_the_lag_file`
(`:1100`). It feeds the committed field manifest against the ambient stubs, so `runtime_version` breaks
its "exact match". This is the same pre-existing red that #273 had (`plans/archive/record-explain.md:107-110`),
and it goes green when Phase 3 writes the manifest. Any other failure during Phases 1-2 belongs to the phase.

**The precedent: `IssuerAid`, wired identically in all three clients.**
- **Python sync:** `def issuer_aid(self, *, timeout: float = DEFAULT_TIMEOUT_S) -> str: return
  self._trust.IssuerAid(pb.Empty(), timeout=timeout).issuer_aid` (`python/seam_sdk/client.py:1258-1259`,
  under `# ── Trust / verification (data plane)` :1256). It has no docstring.
- **Python async:** the same, awaited (`python/seam_sdk/aio.py:971-972`, section header :969).
- **TS:** `issuerAid(opts?: UnaryCallOptions) { return this.trust.issuerAid({}, call(opts)).then((r) =>
  r.issuerAid); }` (`ts/src/client.ts:1717-1719`). It is not `async`, it takes `UnaryCallOptions` rather
  than `CredentialedCallOptions` (:115-123), and it has no TSDoc.
- **Naming:** each method is the RPC name in snake_case / camelCase. That holds for every verb, including
  the ones whose return value is named differently: `register_context` → `.content_ref`,
  `report_outcome` → `.recorded` (`client.py:1210`), and `verify_*` → `.valid`.
- **Return:** a single-scalar response is **unwrapped** to the scalar (`-> str`, `-> bool`). A structured
  response is returned as the raw `pb` message (`get_decision -> pb.DecisionRecordView`, `client.py:1119`).
- **Error mapping:** automatic. `self._trust` is `_MappedStub(rpc.SeamTrustStub(channel))`
  (`client.py:305`; `errors.py:624-643`), so any `grpc.RpcError` becomes the typed subclass for its code
  via `map_rpc_error` (`errors.py:582-621`, `_BY_CODE` :567-579), and `UNIMPLEMENTED` becomes
  `UnimplementedError` (`errors.py:559-560`, :577). aio uses `_AioMappedStub` (`aio.py:82`, :133). TS maps
  through `errorMappingInterceptor()` on the transport (`client.ts:884`; `ts/src/errors.ts:353`, :366, :384).
- **What an unauthenticated read must NOT get:** no `credential=` parameter, no `_credentialed_call` /
  `credentialedCall`, no ticket, no `seam-request-call-v1` signature, and no bound-agent default
  (`client.py:295-298`). Compare `get_commitment_proof` (`client.py:1316-1333`), which goes through
  `_credentialed_call`. The only header it carries is `x-seam-tenant`, and only when the client was built
  with `tenant=`. That header is a channel-wide routing interceptor (`client.py:331-344`, `aio.py:159-165`,
  `client.ts:877-884`), not a credential, and it applies to every call, `IssuerAid` included.
- **Retry posture:** none. The SDK's only retry is the single ticket refresh on credentialed verbs
  (`client.py:141-146`, D-NO-CRED-NO-RETRY at :603), and a credential-free read has nothing to refresh. A
  deadline breach is `DeadlineExceededError`, bounded by `DEFAULT_TIMEOUT_S` (2 s).

**How a newer verb on an older runtime is documented.** No verb maps `UNIMPLEMENTED` specially. The one
precedent is `authorize`: "An old runtime without the Authorize service raises `UnimplementedError`;
adapters typically degrade to their Observe tier on it" (`client.py:428-430`, `client.ts:948-949`). A
runtime older than 0.63.0 has `SeamTrust` but not this method, so the call returns `UNIMPLEMENTED`
(tonic's unknown-method answer). The SDK surfaces that as `UnimplementedError` (Py, a `grpc.RpcError`) or
`UnimplementedError` (TS, a `ConnectError`), with no extra code.

**What the consumer actually needs** (work-generation policy: no helper without a consumer):
- seam-mcp already compares versions itself. `seam_mcp_common.compat.resolve(runtime_version) ->
  CompatAnswer` parses the version into PEP 440 (`common/src/seam_mcp_common/compat.py:119-190`), and
  `discovery._runtime_version` normalises semver to that spelling and rejects malformed input
  (`common/src/seam_mcp_common/discovery.py:251-268`). Its input is a **string**.
- Auto-detection already works over CP discovery (seam-mcp `PROGRESS.md:915`: "B-RTVER CP half closed,
  seam-runtime#1360 still open, no longer blocking").
- Nothing in seam-mcp or seam-adapters calls a gRPC server-info read today (grep for
  `ServerInfo|server_info(` finds only seam-mcp's own MCP tool named `server_info`).
- The data-plane read is therefore the second source the spec asks for, and a client that reaches only
  the data plane (no CP) can feed its string straight into `compat.resolve`. **A version-comparison
  helper in the SDK has no consumer**, and it would duplicate a parser seam-mcp owns.

**Corrections to the brief.**
- `IssuerAid` has no docstring or TSDoc anywhere, so "follow it exactly" cannot cover documentation.
  `server_info` gets a docstring (see Phase 1), as `verify_commitment` (`client.py:1268-1269`) and others do.
- The call site that "names an RPC across both languages" in `scripts/check-contract.sh` is the
  manifest set comparison (probe 4, header `:39-49`). Probes 1/1b/1c name fixed symbols (`VerifyPartyAttestation`,
  the Authorize surface, the admin surface) and do not touch `SeamTrust/ServerInfo`. Nothing in the gate
  checks that the hand-written clients call a verb. Only the refusal message demands it.
- No test enumerates credential-free verbs. Three test-side lists name `issuer_aid` and must gain
  `server_info`:
  - the deadline matrices in `python/tests/test_authorize.py` (sync `test_every_public_method_enforces_timeout`,
    `:480`, entry `:500`; aio `test_aio_deadlines_enforced`, `:578`, entry `:603`);
  - the live round-trips (`python/tests/test_integration.py:87`, `ts/tests/integration.test.ts:111`).
- `python/tests/test_client_parity.py:28` enforces sync/aio parity **as sets** and `:64` enforces it **by
  signature**, so the async twin is mandatory, not a convention. The 16-verb credential tables
  (`test_credential_wiring.py`, `ts/tests/unit_plumbing.test.ts:328`) cover credentialed verbs only and
  must **not** gain it.

## Phases

All phases land in `seam-sdk`. There are no cross-repo writes. Shared API (see **Decisions D1**):
- `SeamClient.server_info(*, timeout=DEFAULT_TIMEOUT_S) -> str` (sync and aio);
- `SeamClient.serverInfo(opts?: UnaryCallOptions): Promise<string>` (TS).

Each returns `ServerInfoResponse.runtime_version` verbatim.

---

### Phase 1: Python sync and async verb, unit tests

- **Status:** DONE (2026-10-29). As planned. Divergences: the verifier's three minor notes were taken (real credential header names, raw-cause assertion, an empty-string test), and the docstring says "the runtime always sets it".
- **Risk:** complex. It is small, but it fixes a public name and return type in the reference language,
  which is a one-way door that Phase 2 mirrors.
- **Delivers:** `SeamClient.server_info()` and `seam_sdk.aio.SeamClient.server_info()`, both returning the
  runtime version string, credential-free, raising `UnimplementedError` on runtime < 0.63.0.
- **Depends on:** none (stubs are current).
- **Files:**
  - `python/seam_sdk/client.py`: add `server_info` directly after `issuer_aid` (:1258-1259), in the Trust
    section.
  - `python/seam_sdk/aio.py`: the awaited twin after `issuer_aid` (:971-972).
  - `python/tests/test_server_info.py` (new).
  - `python/tests/test_authorize.py`: add `lambda: client.server_info(timeout=0.1)` beside the `issuer_aid`
    entries at `:500` and `:603`. `HangingSeam` hangs every CamelCase method (`:237-244`), so
    `ServerInfo` hangs with no fixture change.
- **Approach:**
  - Body: `return self._trust.ServerInfo(pb.Empty(), timeout=timeout).runtime_version`, and the awaited
    form in aio. It has the same signature as `issuer_aid` (keyword-only `timeout`, nothing else), which
    keeps `test_client_parity.py:64` green.
  - Docstring, identical in substance on both clients. Keep it short:
    - it is the runtime's version, a semver string such as `"0.63.0"`, returned verbatim and not
      parsed or normalised;
    - it needs no credential or ticket (only TLS/mTLS gates it), and the SDK never retries it;
    - a runtime older than 0.63.0 raises `UnimplementedError`; fall back to an explicit version or to CP
      discovery;
    - it is server-asserted and unsigned: an input for picking a compatible SDK or adapter, not a
      trust signal (see *Enterprise concerns*).
  - *Rejected:*
    - (a) Returning `pb.ServerInfoResponse`. It breaks the codebase's single-scalar unwrap convention
      (`issuer_aid`, `register_context`, `report_outcome`, `verify_*`). The contract carries one field
      today. Its "Nothing else about the build is carried" line (seam.proto:1326-1328 at `2e29be29`) is a
      comment, not a `reserved` or frozen message, and the RPC name is generic, so a bare `str` IS a one-way
      door. It is still the right one: no consumer needs more (D2), and growth gets a new verb or an additive
      keyword (*Long-term posture*).
    - (b) Naming it `runtime_version()`. Every client method is named after its RPC, and a second
      naming scheme for one verb is a permanent irregularity.
    - (c) Catching `UnimplementedError` and returning `None`. That conflates "old runtime" with any other
      absence, and the caller already has a typed exception to catch.
    - (d) Validating semver in the SDK. The runtime guarantees the shape, and seam-mcp's parser already
      refuses malformed input with a note. A second validator would be a second, divergent opinion.
- **Edge cases:**
  - **Runtime < 0.63.0:** `UnimplementedError` (still a `grpc.RpcError` with `.code() ==
    UNIMPLEMENTED`), raised `from` the raw error, per the `map_rpc_error` contract (`errors.py:586-594`).
  - **Empty string** (a non-conforming server): returned as `""`. The SDK does not invent a refusal the
    contract does not define. The docstring says the runtime always sets it.
  - **`tenant=` through a `seam-cell-router`:** the header rides along as on every call, so the answer is
    the version of the cell that served it. No special casing.
  - **Bound client (`agent=`):** still credential-free. A test pins that no `seam-*` credential metadata
    is sent.
- **Acceptance criteria:**
  1. Against an in-process grpc server whose `SeamTrust` servicer answers
     `ServerInfoResponse(runtime_version="0.63.0")`, `server_info()` returns `"0.63.0"` on both clients.
  2. The request is `pb.Empty()`, and the call's metadata carries no `seam-request-call-v1` /
     `seam-ticket` / subject header even on a client built with `agent=` (a recording interceptor, or the
     fake servicer reading `context.invocation_metadata()`).
  3. Against a server that does not register `SeamTrust` at all, both clients raise. This is a
     stand-in for a pre-0.63.0 runtime, which registers the service but lacks the method; both yield
     `UNIMPLEMENTED`. Both clients raise `UnimplementedError`, `isinstance(e, grpc.RpcError)`, and
     `e.__cause__` is the raw error.
  4. `test_client_parity.py` is green, by set and by signature.
  5. Both deadline matrices in `test_authorize.py` include `server_info` and pass.
- **Tests:** `test_server_info.py` covers AC1-AC3 for sync and aio. Failure path: AC3. Full gate: `cd python &&
  .venv/bin/pytest -q`, `ruff check python`, and `ruff format --check python`. **Expected until Phase 3:
  exactly the one known `test_field_manifest_gate.py` failure** (see *Context*).
- **Docs:** docstrings only.

### Phase 2: TypeScript mirror

- **Status:** DONE (2026-10-29). As planned; the router-transport harness worked first time.
- **Risk:** simple. It mirrors Phase 1's decided shape.
- **Delivers:** `SeamClient.serverInfo(opts?)` resolving to the runtime version string, behaviour-identical
  to Phase 1.
- **Depends on:** Phase 1 (Python is the reference).
- **Files:**
  - `ts/src/client.ts`: add `serverInfo` directly after `issuerAid` (:1717-1719).
  - `ts/tests/server_info.test.ts` (new).
- **Approach:**
  - `serverInfo(opts?: UnaryCallOptions) { return this.trust.serverInfo({}, call(opts)).then((r) =>
    r.runtimeVersion); }`. Same shape as `issuerAid`: not `async`, `UnaryCallOptions` (no `credential`).
    The inferred return is `Promise<string>`, and TSDoc carries the same four points as the Python
    docstring.
  - No `index.ts` change. A `string` return exposes no generated type, so the dual-declaration list
    (`ts/src/index.ts:53-84`) and the `export type` list (:87-102) are untouched.
- **Edge cases:** as Phase 1. TS-specific: the client constructed over an external transport has no
  `errorMappingInterceptor` unless the caller adds it. That is today's documented behaviour for every
  verb, not a new one.
- **Acceptance criteria:**
  1. With `trust` stubbed as `verify_anchor.test.ts:66-80` does, `serverInfo()` resolves to the stub's
     `runtimeVersion` and sends an empty request with no `headers` key, including on a client built
     with `{ agent }` (the TS equivalent of Phase 1 AC2: no credential or ticket header).
  2. Over `createRouterTransport` (exported by `@connectrpc/connect` ^2, `ts/package.json:32`) with **no**
     `SeamTrust` service registered and `interceptors: [errorMappingInterceptor()]`, `serverInfo()` rejects
     with `UnimplementedError`, which is `instanceof ConnectError`. `createRouterTransport` is new to
     `ts/tests`, so a failure here is first checked as a harness problem, not an SDK bug.
  3. `npm run typecheck`, `npm run build` and `npm test` are green, and the built `.d.ts` declares
     `serverInfo(opts?: UnaryCallOptions): Promise<string>`.
- **Tests:** `server_info.test.ts` covers AC1-AC2. Python full suite: still exactly the one known failure.
- **Docs:** TSDoc only.

### Phase 3: record the contract decision, live coverage

- **Status:** DONE (2026-10-29). As planned, except that the expected version was read from the export's Cargo.toml with tomllib, because `cargo metadata` refuses the export (see *As run*).
- **Risk:** simple.
- **Delivers:** `contract/rpc-manifest.txt` declares `SeamTrust/ServerInfo` and `contract/field-manifest.txt`
  declares `ServerInfoResponse/runtime_version`. The gate exits 0, and the live lanes assert the version
  against a real 0.63.0 runtime.
- **Depends on:** Phases 1 and 2. The verb is wired before it is recorded, as the gate's refusal text and
  CLAUDE.md require.
- **Files:**
  - `contract/rpc-manifest.txt` and `contract/field-manifest.txt`, written by
    `scripts/check-contract.sh --write-manifest`;
  - `python/tests/test_integration.py` (in `test_full_round_trip`, beside `:87`);
  - `ts/tests/integration.test.ts` (in "full round trip", beside `:111`).
- **Approach:**
  - **Regenerate first** (`make generate`), then `--write-manifest`, and **review the diff**. It must be
    exactly `+SeamTrust/ServerInfo` (after `SeamTrust/IssuerAid`, `rpc-manifest.txt:71`) and
    `+ServerInfoResponse/runtime_version` in `field-manifest.txt`. `contract/event-field-manifest.txt`,
    which the same run rewrites, must come out byte-identical (`git diff --stat contract/` names two
    files).
  - **Build the runtime from a clean export, never the shared checkout** (memory:
    build-pinned-runtime-from-export; the #273 Phase 3 incident, `record-explain.md:57-61`). With
    `S=/private/tmp/claude-501/-Users-Shared-zer07labs-seam-sdk/adb62dc5-b2b9-402c-b0f4-a26fc5bb6d7a/scratchpad`:
    ```
    # already built at plan time: $S/sr-0.63.0 is a `git archive 2e29be29` export (seamd-v0.63.0)
    # and $S/rt-target-063 its target dir; rebuild only if either is missing:
    #   git -C ../seam-runtime archive 2e29be29 | tar -x -C "$S/sr-0.63.0"
    #   (cd "$S/sr-0.63.0" && CARGO_TARGET_DIR="$S/rt-target-063" cargo build --release -p seamd --bin seam-grpc)
    export SEAM_GRPC_BIN="$S/rt-target-063/release/seam-grpc"
    export SEAM_EXPECTED_RUNTIME_VERSION="$(cargo metadata --no-deps --format-version 1 \
      --manifest-path "$S/sr-0.63.0/Cargo.toml" \
      | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"]=="seamd"))')"
    ```
    The expected value is `0.63.0` (workspace `version`, `Cargo.toml:87` at `2e29be29`; `seamd` inherits
    it). The value is derived from the export's own manifest and never typed by hand.
    *As run:* `cargo metadata` refuses the export (the private `zer07labs` registry is configured only in
    the shared checkout's environment), so the value was read from the same file with tomllib:
    `python/.venv/bin/python -c 'import sys,tomllib; print(tomllib.load(open(sys.argv[1],"rb"))["workspace"]["package"]["version"])' "$S/sr-0.63.0/Cargo.toml"`
    → `0.63.0`. Same source, still never typed by hand.
  - **How the test learns the expected version (decision D4).** Nothing is hard-coded per release:
    - **Always:** `server_info()` returns a non-empty semver string,
      `^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`. This holds on every runtime ≥ 0.63.0,
      including CI's `seamd:main` image, whose version the job does not know.
    - **When `SEAM_EXPECTED_RUNTIME_VERSION` is set:** exact equality. The local run above always sets it,
      and this phase's AC requires that it was set.
  - *Rejected:*
    - (a) Comparing to the SDK's own version. SDK 0.63.1 pairs with runtime 0.63.0, so lockstep is broken
      exactly here, and CI's `seamd:main` can be ahead of both.
    - (b) Asking the binary. `seam-grpc` has no `--version` flag at `2e29be29` (`crates/seamd/src/bin/seam-grpc.rs`).
    - (c) Reading a runtime source path from the test. That couples the test to a checkout layout, and an
      env var also works for `SEAM_GRPC_ADDR`.
- **Edge cases:**
  - The CI integration lane is advisory and may skip (`scripts/test_ci_gate.py:12`), and it lifts
    `seam-grpc` from `seamd:main` (`.github/workflows/ci.yml:241-300`). Record whether the local live run
    executed rather than skipped before claiming live coverage.
  - A `seamd:main` image older than 0.63.0 would raise `UnimplementedError` in CI. `main` has carried
    `2e29be29` since the 0.63.0 train, so this is not expected. If it happens, it is the image lagging,
    not the SDK.
- **Acceptance criteria:**
  1. `STREAM=1 EVENTS=1 ./scripts/check-contract.sh; echo $?` prints `0`.
  2. `git diff contract/` is exactly those two `+` lines, with no removals, and
     `contract/event-field-manifest.txt` is unchanged.
  3. `test_field_manifest_gate.py` is fully green, including the exact-lag test that was red before this
     phase. The Python suite is then 0 failed.
  4. With `SEAM_GRPC_BIN` and `SEAM_EXPECTED_RUNTIME_VERSION` set as above, the Python and TS live tests
     pass, the version equals `0.63.0`, and the run log shows they executed (not skipped).
- **Tests:** the two live assertions, the full Python and TS suites, and the gate. Failure path (manual,
  not committed): delete the new rpc line, confirm exit 5 naming it, restore; delete the field line,
  confirm exit 6 naming it, restore.
- **Docs:** none (Phase 4).

### Phase 4: docs, compatibility, changelog

- **Status:** TODO.
- **Risk:** simple.
- **Delivers:** a reader can find the verb in the README, `COMPATIBILITY.md` names the runtime it needs and
  the 0.63.1 pairing, and the CHANGELOG records it and the unpublished 0.63.0.
- **Depends on:** Phases 1-3.
- **Files:** `README.md`, `COMPATIBILITY.md`, `CHANGELOG.md`, `plans/README.md`, `PROGRESS.md`.
- **Approach:**
  - **README:**
    - In the BSR-state block (`README.md:92-104`), append to the coordination-surface paragraph: "Since
      runtime 0.63.0 (seam-runtime#1360) it also carries `SeamTrust.ServerInfo` →
      `ServerInfoResponse.runtime_version = 1`." Do not re-stamp the 2026-08-31 probe line; it describes
      a different measurement.
    - In *Data-plane surface* (`:602-610`), add a short **Runtime version (runtime 0.63.0+, seam-sdk#307)**
      paragraph. It covers:
      - `server_info()` / `serverInfo()` return the semver string verbatim, credential-free;
      - an older runtime raises `UnimplementedError`;
      - feed the string to your own compatibility resolver (seam-mcp's `compat.resolve` is one);
      - it is server-asserted, so use TLS on a non-loopback endpoint;
      - Go/Java/Kotlin generate it from the BSR module and carry no client.
  - **COMPATIBILITY.md:**
    - A pairing paragraph directly after the v0.61.1 one (`:144-150`), in the same style: "**SDK v0.63.1
      pairs with runtime 0.63.0.** SDK v0.63.0 was tagged at `4760f9b` and never published: the runtime's
      0.63.0 release dispatch (seam-runtime#1544) tagged it before this repo had wired
      `SeamTrust.ServerInfo`, so the contract gate exited 5 on that commit and `publish.yml` refused
      (#307). A public tag is not re-cut, so the server-info verb (seam-sdk#307) ships as v0.63.1, and the
      `v0.63.0` tags stay where they are, unpublished. The runtime's next release must be 0.64.0 or later,
      because 0.63.1 is taken here. Pin `seam-sdk 0.63.1` beside seamd 0.63.0."
      - Write it **unconditionally in this PR**, as #273 did (`record-explain.md:436-441`).
    - A row in the table (header `:152`): "Runtime version read: `server_info()`/`serverInfo()`
      (seam-sdk#307) | seam-runtime 0.63.0 (seam-runtime#1544, #1360) | **compatible, except this verb**:
      an earlier runtime answers `UNIMPLEMENTED`, surfaced as `UnimplementedError`; nothing else changes |
      runtime `main` @ `2e29be29` (seam-runtime#1544)".
    - The adapters row (`:65`) is **not** touched here (see Phase 5).
  - **CHANGELOG.md:**
    - Under `## Unreleased` (`:17`), add **### Added**: "**Read the runtime version over the data plane
      (seam-sdk#307; runtime 0.63.0+, seam-runtime#1360).** Python `server_info()` (sync and async), TS
      `serverInfo()`: the `seamd` version string, verbatim, with no credential. An earlier runtime raises
      `UnimplementedError`. Go, Java and Kotlin generate the verb from the BSR module; they carry no
      client." Also add the line "These entries first ship in **0.63.1**: v0.63.0 was tagged and never
      published (see COMPATIBILITY.md)", mirroring `CHANGELOG.md:25-26`.
    - Under the bot's existing `## 0.63.0 — 2026-10-29` heading (`:19`, present on `main` since `4760f9b`,
      empty), add one line: "Tagged, never published (see COMPATIBILITY.md). It carried no entries; 0.63.1
      supersedes it." This follows `## 0.61.0`'s line (`:49`), worded for an empty heading.
  - **Citations:** the inserts start after line 17. Run `python3 scripts/shift_changelog_citations.py .
    17 <delta>` (delta = lines inserted), then `python/tests/test_compatibility_citations_resolve.py`. There
    are 8 `CHANGELOG.md:N` citations in tracked non-archive docs today. Also re-anchor any `README.md:N`
    or `contract/*-manifest.txt:N` citation the README insert or the manifest write moved (`grep -rn
    'README.md:[0-9]\|manifest.txt:[0-9]' --include='*.md' . | grep -v plans/archive`).
  - **plans/README.md:** replace the `_(none)_` active row with `server-info.md` | #307, TODO → status.
    The file lists no active plan today (`plans/README.md:14`), even though `plans/operator-dpop-signer.md`
    sits in `plans/`. That stale row is out of scope; mention it to `/sweep`.
- **Edge cases:** the CHANGELOG retitle on release (`scripts/retitle_changelog.sh`) shifts citations itself.
  Do not pre-shift for it.
- **Acceptance criteria:**
  1. `test_compatibility_citations_resolve.py` is green.
  2. The README names both `server_info` and `serverInfo`, says `UnimplementedError` on < 0.63.0, and says
     it is credential-free.
  3. COMPATIBILITY has the row citing `2e29be29` and seam-runtime#1544, and the 0.63.1 pairing paragraph.
  4. CHANGELOG has the Unreleased Added entry and the line under `## 0.63.0`.
- **Tests:** the citation gate, then the full suites once more (Python, TS, Go, `verify/`, Java/Kotlin with JDK
  17) per `ci-spend-local-first`. Go/Java/Kotlin/verify are untouched but are part of CI.
- **Docs:** this phase. No `seam/docs` or `seam/CLAUDE.md` change: no dependency edge is added, and the
  contract is described at its source.

### Phase 5: release and hand-off (post-merge)

- **Status:** TODO.
- **Risk:** simple, but it is a release.
- **Delivers:** SDK **0.63.1** on Cloudsmith `internal` and `partner` (`publish.yml`'s `promote-partner`,
  `:768`), #307 closed, and consumers told.
- **Depends on:** the PR merged to `main`, and `main`'s `ci-ok` green.
- **Approach:**
  1. **Re-confirm the v0.63.0 outcome:** `gh run view 40814097723` (ci-green failed),
     `git ls-remote --tags origin 'v0.63*'`, and nothing at 0.63.0 on Cloudsmith
     (`python/.venv/bin/python scripts/check_registry_drift.py`, which is read-only; exit 2 is
     infrastructure, never a verdict).
  2. **Ship 0.63.1 by manual dispatch** (the #273 → 0.61.1 and 0.50.1 precedent):
     `gh workflow run release-on-runtime.yml -f version=0.63.1 -f wire_framing_version=3`.
     - The framing input is required on a manual run because the latch is true
       (`release-on-runtime.yml:97-101`; `contract/wire-framing.json:39` `supported: 3`).
     - The workflow refuses unless every `ci-ok` on `main`'s HEAD is success (`:175-219`). A refusal writes
       nothing, so a re-run is safe.
     - Expect `check_registry_drift.py` to report drift in the interim (`main` declares 0.63.0,
       Cloudsmith's newest is 0.62.0). Close any issue it opens with the 0.63.1 evidence.
  3. **Verify publication:** the `publish` run is green through `promote-partner`;
     `check_registry_drift.py` is clean for 0.63.1 in `internal` and `partner`. Run
     `./scripts/promote-to-partner.sh 0.63.1` only if the automatic job did not run.
  4. **Close #307** with the version, the merge commit, the release and publish run ids, and the pairing
     (seamd 0.63.0).
  5. **Messages:**
     - **seam-mcp-b2:** `server_info()` is published in 0.63.1. It returns the raw semver string, which
       feeds `compat.resolve` after the same normalisation `discovery._runtime_version` applies. An older
       runtime raises `UnimplementedError`, so fall back to CP discovery or an explicit version. seam-mcp
       pins `seam-sdk==0.62.0` (`common/pyproject.toml:19`, `onboard/pyproject.toml:16`), so using it
       needs a pin move. Whether to add a data-plane fallback at all is theirs to decide.
     - **seam-adapters-1b:** 0.63.1 is published. Core pins `seam-sdk>=0.62.0,<0.63`
       (`seam-adapters/core/pyproject.toml:115`), which excludes it. Raising the pin is theirs; the
       credential-free `issuer_aid` passthrough at `transport_grpc.py:2146` is the shape to copy if
       core wants `server_info`.
     - **seam-runtime train owner:** 0.63.1 is taken here; the next runtime release must be 0.64.0 or later.
  6. **Re-quote the adapters pin if it is raised:** when seam-adapters merges a pin raise, this repo's
     `sibling-quotes` job (`ci.yml:685`) goes red against `COMPATIBILITY.md:65`. Re-quote right after
     their merge (memory: sibling pin raise blocks release; the 0.51.0/0.56.0 losses). Use one small PR,
     as #305 and #306 did.
- **Acceptance criteria:**
  1. 0.63.1 is on `internal` and `partner`, and its wheel's `SeamClient.server_info` exists in a clean venv
     (`publish.yml`'s clean-venv import step).
  2. #307 is closed with a comment naming the version, the merge commit and the runtime pairing.
  3. The Phase 4 0.63.1 paragraph is true as published.
- **Tests:** none beyond the publish workflow's own gates.
- **Docs:** the `PROGRESS.md` release line; archive this plan via `/sweep` once verified.

---

## Long-term posture

- **One-way doors:** the method names `server_info` / `serverInfo`, and the `str` / `Promise<string>`
  return. If the proto ever grows `ServerInfoResponse` (it says it will not), the additive path is a new
  verb returning the raw message, such as `server_info_response()`. Changing this one's return type would
  break callers under a version number that cannot say so (`CHANGELOG.md:9-12`).
- **Reversible:** all prose, and the test's expected-version mechanism.
- **Debt avoided:**
  - no SDK version parser competing with seam-mcp's `compat` (D2);
  - no special `UNIMPLEMENTED` mapping that a future verb would have to copy;
  - no cached version in the client: a rollout (drain, never swap) can change the answer between calls.
- **Debt accepted:** Go/Java/Kotlin have no client, consistent with their shim-only scope (`README.md:138-140`;
  `CHANGELOG.md` 0.57.0 precedent).

## Enterprise concerns

- **Security / trust:**
  - The value is **server-asserted and unsigned**, and the read is credential-free by design. Over
    plaintext, an on-path attacker can forge it.
  - It must drive compatibility selection only, never an authorization or verification decision. The
    docstrings and README say so, and recommend TLS on any non-loopback endpoint.
  - It discloses the build version to anyone who can reach the plane. That is the runtime's decision,
    matching unauthenticated `GET /v1/discovery`; the SDK adds nothing.
- **Correctness under partial failure:** one call, no retry, and a 2 s default deadline. Failures are typed
  (`UnavailableError`, `DeadlineExceededError`, `UnimplementedError`), never a fabricated version.
- **Compatibility:** additive. No existing verb changes. On a runtime < 0.63.0 only this verb raises.
- **Observability:** none added.
- **Rollback:** a revert. There is no persisted state and no wire-framing change (`wire-framing.json`
  untouched).
- **CI spend:** run the full local gate before the single push (memory: ci-spend-local-first), and one PR.

## Decisions (Opus, consequential but decidable)

- **D1. Carry the verb and its one field. Wire both in Python (sync and async) and TS as `server_info` /
  `serverInfo -> str`,** mirroring `IssuerAid`: RPC-named, credential-free, unwrapped single scalar, no
  retry. This is the decision the exit-5 and exit-6 refusals ask for, and it is recorded in the manifest
  commit.
- **D2. No version-comparison helper.** The only consumer (seam-mcp) owns `compat.resolve` and takes a
  string. A helper here would be unused surface and a second parser that could disagree with theirs.
- **D3. `UNIMPLEMENTED` surfaces as the existing typed `UnimplementedError`, documented,** following the
  `authorize` precedent. No `None`, and no new error class.
- **D4. The live test asserts semver shape always, and equality when `SEAM_EXPECTED_RUNTIME_VERSION` is
  set.** The local run derives that value from the export's `cargo metadata`.
- **D5. Go, Java and Kotlin: no code** (D2 of `record-explain.md`; they ship no in-package transport).
- **D6. Release as 0.63.1 by manual dispatch** (the brief and the #273 precedent). The v0.63.0 tags stay
  unpublished.

## Open questions (defaults chosen; `/implement` logs them `UNCONFIRMED` when implemented)

- **Q1: return a plain string (default), or the raw `pb.ServerInfoResponse` / `ServerInfoResponse`?**
  Default: string. It matches every other single-scalar verb, and the contract carries one field today.
  The proto's "nothing else" is a comment, not a freeze, so this is a real one-way door. The default
  still holds: growth gets a new verb or an additive keyword, and the raw message would cost a TS root
  type export and a convention break for no consumer.
- **Q2: a version-comparison helper (e.g. `runtime_at_least("0.63.0")`)?** Default: no (D2). Revisit only
  if a consumer that does not already parse versions asks.
- **Q3: also pass the expected version in CI** (set `SEAM_EXPECTED_RUNTIME_VERSION` in the `integration`
  job's from-source branch)? Default: no. The lifted-image branch cannot know it, and the from-source
  branch is used only for lockstep trains. Add it the next time `SEAM_RUNTIME_BUILD_REF` is set.

## PR strategy

One PR from `feat/server-info` (already at `origin/main` = `4760f9b`, the bot's v0.63.0 release commit),
matching #273/#304. Phases 1-4 land as one commit per phase. The PR body carries D1's decision text,
because the manifest diff needs its justification beside it, and it says the merge unblocks `main`
(red since `4760f9b`) and is released as 0.63.1. Phase 5 is post-merge and produces no PR, except the
conditional adapters re-quote.

## Plan review

One round, fresh Opus, verdict **SOUND**, run 2026-10-29. Checked: the issuer_aid wiring, the gate
(exit 5, then 6 behind it, both reproduced), the proto at `2e29be29`, the deadline lists, and that no
other verb registry names `issuer_aid`. Six edits applied:
- Phase 3 reuses the already-built `sr-0.63.0` / `rt-target-063`.
- Q1 and Phase 1 rejection (a) no longer claim the proto forbids growth.
- TS AC1 adds the `{ agent }` bound-client check.
- TS AC2 flags `createRouterTransport` as new to the tests.
- Phase 1 AC3 is labelled a stand-in.
- `HangingSeam` is cited as `:227` (class) and `:237-244` (hang logic).

