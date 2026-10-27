# Operator Ed25519 DPoP signer for management-plane calls (all five languages)

> **Issue:** [#290](https://github.com/zer07labs/seam-sdk/issues/290). **Owner decision 2026-10-27:** all
> five languages (Python, TypeScript, Go, Java, Kotlin) in one train. Rejected alternative: a TS + Python
> first cut.
> **Grammar source:** `seam-runtime/docs/specs/mgmt-dpop.md` at runtime `origin/main` `a9ddb982`, re-checked at
> `15f5ebb6`. The last spec commit is `7ea99e96` (P19 R3).
> **Clean-room rule:** every construction is transcribed from that spec. `crates/**/*.rs` and the control
> plane's TS were read only to extract test-vector values and runtime configuration. The vector values come
> from the spec's own *Golden vector* table, which matches the runtime's `mgmt_dpop::tests::golden_vector`
> and the control plane's `src/mgmt-dpop.test.ts:29-42` byte for byte (compared by script).
> **Anchors** are true at seam-sdk `584823a`. Re-check them before editing.

## Status

TODO. Planned 2026-10-27.

## Context

**Why.** The management console is adding an opt-in "Bind token to a key (DPoP)" mint. The browser generates
an Ed25519 key, the control plane mints an operator token carrying `cnf.jkt`, and the console reveals the
private JWK once. Nothing can spend that token today:
- The runtime refuses a `cnf` token presented as `Bearer` (`scheme_mismatch`) and requires a fresh proof on
  every call.
- No SDK can produce that proof.
- So the control plane cannot move `SEAM_MINT_DPOP_BINDING` from `machines` to `all`
  (`seam-runtime/deploy/helm/seam/values/aws-stg/seam-control-plane.yaml:29` is `"machines"`), and the
  console toggle cannot default on.

The console's page links #290 as the signer it depends on
(`seam-console-ui/apps/*/operator-tokens/page.tsx`).

**What the runtime requires** (spec; quoted shapes, not paraphrase):
- **Credential:** `authorization: DPoP <token>` plus `dpop: <proof>` in gRPC metadata. Over HTTP, the
  `Authorization` and `DPoP` headers.
- **Proof:** a compact JWS.
  - Header: exactly `{typ:"dpop+jwt", alg:"EdDSA", jwk:{kty:"OKP",crv:"Ed25519",x}}`. A `d` member is
    refused.
  - Claims: exactly `{jti,htm,htu,iat,ath,seam_bd}`. `iat` must be within ±60 s. A `nonce` is refused, and
    a proof over 8 KiB is refused.
- **gRPC `htu`:** `grpc://<operator aud><full method>`. The authority is `SEAM_RUNTIME_AUD`, default
  `seam-runtime`, not the dialled address.
- **gRPC `seam_bd`:** SHA-256 of the protobuf-encoded request message, without the frame prefix. `htm` is
  `POST`.
- **Replay:** each proof is burned once, so each attempt needs its own proof.
- **Coverage:** the management plane is gRPC 9100 (`SeamAdmin`, `SeamEvents`) and HTTP 9099. Every
  management RPC is unary or server-streaming.
- **When a proof is needed:**
  - A `cnf` token needs a proof on every listener, loopback included.
  - A non-loopback listener refuses an unbound token outright (R2, runtime 0.55.0).
  - Runtime 0.54.0 (R1, `7aa16cae`) is the first that accepts bound tokens at all.

**What the SDKs have today.**
- **Python** (sync only; `aio.py:792` points async callers at the sync admin client):
  - `SeamAdminClient.connect(target, *, token=None, credentials=None)` at `python/seam_sdk/admin.py:278-298`.
  - It wraps the channel in `_BearerAuthInterceptor` (`admin.py:186-211`, setting
    `("authorization", f"Bearer {token}")` at `:193`, unary-unary and unary-stream only).
- **TS:**
  - `connect(baseUrl, opts?: {token?})` at `ts/src/admin.ts:204-211`, on `@connectrpc/connect-node`
    `createGrpcTransport`.
  - It pushes `bearerAuth(token)` (`admin.ts:176-180`) after `errorMappingInterceptor()`.
- **Go, Java and Kotlin have no gRPC client and no stubs.** They ship crypto, identity and routing shims, and
  the established placement for per-call behaviour is an interceptor factory:
  - Go: `go/routing/routing.go:61` `UnaryInterceptor`, `:71` `StreamInterceptor`, and `:81` `WithTenant`,
    the `[]grpc.DialOption` bundle.
  - Java: `TenantRouting.java:67` `interceptor(String)`.
  - Kotlin: `TenantRouting.kt:57`.
- **Ed25519 per language:**
  - Python: `cryptography` (`crypto.py:20-22`).
  - TS: `@noble/curves/ed25519` and `@noble/hashes/sha256` (`crypto.ts:7-8`).
  - Go: stdlib `crypto/ed25519` (`go/crypto/agent.go:29`).
  - Java and Kotlin: BouncyCastle `bcprov-jdk18on:1.78.1`, chosen because the JDK cannot derive a public key
    from a raw seed (`java/build.gradle.kts:8-9`). Seed to key is at `SeamCrypto.java:107` and
    `SeamCrypto.kt:117`. Kotlin duplicates the Java code rather than depending on it.
- **JWS today:** none of the five SDKs signs a JWS; they only verify TCTs. **No SDK parses a JWK.** No
  management code makes HTTP calls on 9099.
- **Live tests:**
  - Python's live management tests mint operator tokens locally with a public golden test key
    (`python/tests/operator_token.py:23`, `mint_operator_token` at `:31`, `aud` default `seam-runtime` at
    `:34`).
  - They spawn `seam-grpc` with the management listener on `127.0.0.1` (`python/tests/live_server.py:245`),
    which is the *optional* DPoP posture.
  - CI's `integration` job (`.github/workflows/ci.yml:241`) runs Python and TS live. Go, Java and Kotlin
    have no live tests.

**Corrections to the issue as written.**
1. *"A console-minted bound token (aws-stg) can call SeamAdmin against a DPoP-required runtime listener."*
   aws-stg's management ports admit only `callers: [control-plane, seam-relay]`
   (`seam-runtime/deploy/helm/seam/values/aws-stg/seam-server.yaml:91-92`, enforced by
   `templates/authorizationpolicy.yaml:20-23`). Nothing outside the cluster can reach them, CI included.
   Phase 9 therefore proves this criterion with a scripted smoke run whose realistic outcome is a dry-run
   `AWAITING-HUMAN` handoff, not a CI test. CI proves the SDK's side against a local loopback runtime: a
   `cnf` token needs a valid proof on *every* listener (spec, *Binding rules*), so the proof check exercised
   there is the same one the required listener runs (Phase 3; see D6). The required posture's own rule,
   refusing an *unbound* Bearer token with `no_cnf`, is checked by Phase 9's optional unbound case.
2. *"gRPC interceptor / HTTP hook per language."* No SDK makes management HTTP calls, so the "HTTP hook" is a
   header-producing helper (proof plus `Authorization`) a caller wraps around their own HTTP client. It is
   not an HTTP client.

## Phases

All phases land in `seam-sdk`. There are no cross-repo writes; aws-stg is touched only by Phase 9's
read-mostly smoke run.

Shared API (Opus decision; see **Decisions**). Each language exposes the same four things, named in its own
idiom:

1. **`OperatorDpopKey`:** parsed from the console's one-time reveal, the JWK JSON
   `{"kty":"OKP","crv":"Ed25519","x":…,"d":…}`, given as a string or a parsed object.
   - Also constructible from a raw 32-byte seed.
   - Exposes `x` and `jkt` (the RFC 7638 thumbprint over `{"crv":"Ed25519","kty":"OKP","x":…}`).
   - Never serialises `d`. `toString`/`repr` redacts.
2. **`mgmt_dpop_proof(key, token, htm, htu, body, *, iat, jti)`:** the pure primitive. It emits the header
   and claims in the spec's member order with no whitespace and no HTML escaping, signs them with Ed25519,
   and returns the compact JWS.
3. **The gRPC hook:** an interceptor that, per call, computes `htu` = `grpc://<aud><full method>` and
   `seam_bd` = SHA-256 of the request's wire bytes. It sets `authorization: DPoP <token>` and
   `dpop: <proof>`, re-signing on every attempt. It covers unary and server-streaming calls.
4. **The HTTP hook:** `mgmt_dpop_http_headers(key, token, method, url, body)` returns
   `{"Authorization": "DPoP …", "DPoP": …}`. `htu` is built from the URL: `https`, the host lowercased, the
   default port dropped, query and fragment dropped. Userinfo is refused.

Defaults: `aud` comes from the token's own `aud` claim when it is a single string, else `seam-runtime`, and
the caller can override it. `iat` is the wall clock. `jti` is 16 random bytes, base64url-encoded (22
chars). Both are injectable for tests only.

---

### Phase 1: vendor the spec, add the conformance vector and the Python primitive

- **Status:** DONE (2026-10-27; see the divergences below)
- **Divergences from the planned approach (recorded at implementation):**
  - **Errors:** `DpopError(ValueError)` is the base for every local refusal, and `DpopKeyError(DpopError)`
    is reserved for key and binding faults. The plan named only `DpopKeyError(ValueError)`, which would
    misname an oversized body as a key fault. Logged in `ASSUMPTIONS.md`.
  - **Printable ASCII:** `htu`, `jti` and `aud` must be printable ASCII, and the token must be visible
    ASCII. This makes the signed JSON byte-identical across all five encoders, so `ensure_ascii=True`
    replaces the planned `False` with no effect on bytes. Logged in `ASSUMPTIONS.md`.
  - **Base64 helper:** `dpop.py` has its own two-line `_b64url` instead of importing `crypto.py`'s private
    `_b64url_nopad`, keeping the module free of a dependency on another module's private names.
  - **HTML-escaping case:** the `&`, `<`, `>` case puts those characters in `jti` (`html_sensitive_jti`),
    not `htu`. It exercises the same encoder behaviour, and an HTTP URL carrying them would be
    percent-encoded anyway.
  - **Source pin:** the golden group's provenance sits in the file's top-level `description`, not a
    per-group `source` field.
  - **Phase 2 helpers landed here:** `_peek_token_claims` and `_token_cnf_jkt` were built in this phase,
    with tests, because they are pure functions of the same module.
- **Risk:** complex
- **Delivers:**
  - A byte-checked vendored copy of the spec.
  - A conformance vector file every language consumes.
  - The Python key, primitive and HTTP helper, KAT-exact.
- **Depends on:** none.
- **Files:**
  - `docs/specs/mgmt-dpop.md` (new; vendored copy with the standard pinned-copy header).
  - `scripts/check_vendored_spec.py` (register it in the vendored-copy table at `:136-150`).
  - `conformance/mgmt_dpop_vector.json` (new).
  - `python/seam_sdk/dpop.py` (new).
  - `python/seam_sdk/__init__.py` (exports plus `__all__`, `:30`, `:108`).
  - `python/tests/test_mgmt_dpop.py` (new).
- **Approach:**
  - **Vendor the spec through the existing pinned-copy mechanism.** It already drives the `spec pin` CI job
    (`ci.yml:657-682`). Then upstream spec drift reddens CI instead of silently staling the SDK. This is the
    same rule `verify/docs/seam-event.v1.md` follows.
  - **The vector file holds three groups:**
    - `golden`: the spec's inputs and outputs verbatim (seed, htm, htu, token, message hex `0a0361636d`, iat,
      jti, jkt, x, ath, seam_bd, proof), with `"source": "seam-runtime docs/specs/mgmt-dpop.md @ <sha>"`.
    - `derived`: SDK-computed cross-language cases, labelled as such. They are:
      - an `Empty` message, where seam_bd hashes the empty string;
      - an HTTP case with a query string, a default port and an upper-case host, recording the expected
        normalised `htu`;
      - an `htu` carrying `&`, `<` and `>`, to catch HTML-escaping JSON encoders.
      These pin five-way agreement, not runtime agreement, and the file says so.
    - `jwk_rejects`: malformed reveals, each with the expected error class. The cases are a wrong `kty`, a
      wrong `crv`, `d` not decoding to 32 bytes, `x` not matching the `x` derived from `d`, missing members,
      and padded base64url.
  - **`dpop.py` builds the JSON by hand-ordered serialisation.** It uses
    `json.dumps(obj, separators=(",", ":"), ensure_ascii=False)` on dicts built in spec order; insertion
    order is preserved. Signing uses `cryptography` Ed25519 from the seed. It reuses `_b64url_nopad` from
    `crypto.py:28` rather than adding a third base64 helper.
  - **The JWK loader cross-checks `x` against the `x` derived from `d`.** A copy-paste error in the reveal
    then fails at load time with a named error, not later as an opaque runtime 401. It rejects a JWK that
    carries `alg`/`use` values contradicting EdDSA, and ignores benign extra members such as `kid`.
  - **Errors:** `DpopKeyError(ValueError)` lives in `dpop.py`, not `errors.py`. Keeping it out of `errors.py`
    keeps `test_errors_is_import_light.py`'s scope untouched. This error is a local input fault, never a
    wire error.
  - *Rejected:* a JOSE library (`python-jose`, `jwcrypto`). It would add a dependency and does not
    guarantee member order or the exact-member rule. The construction is about 60 lines.
- **Edge cases and failure modes:**
  - A non-ASCII token: `ath` is over the token's ASCII bytes, so refuse non-ASCII.
  - An empty token or jti.
  - A jti over 256 bytes.
  - A proof over 8 KiB, which is reachable only through a pathological `htu`. Refuse locally with a clear
    error rather than send a guaranteed 401.
  - A body over 1 MiB: refuse locally with a clear error. The runtime would answer 413 or
    `RESOURCE_EXHAUSTED`.
- **Acceptance criteria:**
  1. `mgmt_dpop_proof` over the golden inputs returns the spec's proof string exactly, and the key's `jkt`,
     `x`, `ath` and `seam_bd` equal the golden outputs.
  2. Every `derived` case matches its recorded output, and every `jwk_rejects` case raises `DpopKeyError`.
  3. `scripts/check_vendored_spec.py` passes locally against runtime `origin/main`. Changing one byte of the
     vendored copy makes it fail.
  4. `repr(key)` and `str(key)` contain neither `d` nor the seed. A test asserts this.
  5. The decoded header has exactly three members and the claims exactly six, in spec order.
- **Tests:** `test_mgmt_dpop.py` covers the KAT, the derived cases, the rejects, the redaction, member
  order, every local refusal, and a mutation check: flipping one byte of the seed changes the proof.
- **Docs:** none yet (Phase 10).

### Phase 2: Python `SeamAdminClient` speaks DPoP

- **Status:** DONE (2026-10-27)
- **Divergences (recorded at implementation):**
  - `connect` also takes `clock=` (the hook the edge cases below ask for). It is probed once at `connect`,
    so a float clock (`lambda: time.time()`) fails there rather than on every call.
  - `aud=` or `clock=` without `dpop_key=` raises `DpopError`. Both parameters are meaningless on the
    Bearer path.
  - The Bearer path still accepts an opaque, non-JWS token (dev/test tokens). Only a token that decodes
    *and* carries `cnf` is refused there.
  - The token-claims peek helper landed in Phase 1, not here.
- **Risk:** complex
- **Delivers:** `SeamAdminClient.connect(target, *, token=None, dpop_key=None, aud=None, credentials=None)`.
  With `dpop_key`, every `SeamAdmin` and `SeamEvents` call carries `authorization: DPoP` plus a fresh proof.
- **Depends on:** Phase 1.
- **Files:**
  - `python/seam_sdk/admin.py`: a new `_DpopAuthInterceptor` beside `_BearerAuthInterceptor`, and the
    `connect` parameters.
  - `python/seam_sdk/dpop.py`: the token-claims peek helper.
  - `python/tests/test_admin.py` and `python/tests/test_mgmt_dpop_interceptor.py` (new).
- **Approach:**
  - **`_DpopAuthInterceptor`** implements `UnaryUnaryClientInterceptor` and `UnaryStreamClientInterceptor`,
    matching the Bearer one (`admin.py:207`, `:210`). Per invocation it:
    - computes `htu` from `client_call_details.method`;
    - computes `seam_bd` over `request.SerializeToString()`. No management input message contains a map
      (all 16 `SeamAdmin` RPCs and the 3 `SeamEvents` RPCs were walked), so the bytes equal the stub's own
      serialisation;
    - mints a proof;
    - appends both headers, preserving `x-seam-tenant` (`_tenant_metadata`, `admin.py:166-173`).
  - **Construction-time checks.** `connect` refuses `dpop_key` without `token`. It decodes the token's
    payload segment without verifying it: the SDK holds no operator public key, and the runtime is the
    verifier. It then checks two things:
    - (a) there is a `cnf.jkt`; without one, DPoP is guaranteed `scheme_mismatch`;
    - (b) `cnf.jkt == key.jkt`; otherwise it is guaranteed `key_mismatch`.
    Either failure raises `DpopKeyError` naming the fault, with no network call. A token with `cnf` passed as
    `token=` without `dpop_key` raises too: as Bearer it is guaranteed `scheme_mismatch`, and the console
    reveal pairs them. This is the clearest failure to give the operator.
  - **`aud`:** the explicit argument wins, then a single-string token `aud`, then `"seam-runtime"`. A list
    `aud` with no override raises, because guessing the `htu` authority would be wrong half the time.
  - **Retries:** the SDK's admin channel configures no gRPC service-config retry. Confirm that, and pin it
    with a test, because a transport-level retry would resend a burned proof. Any SDK-level retry re-enters
    the interceptor and so re-signs.
  - *Rejected:* `grpc.metadata_call_credentials`. It needs TLS (`admin.py:189-190`), and it cannot see the
    request message, so `seam_bd` would be impossible.
- **Edge cases and failure modes:**
  - **Clock skew over 60 s:** the runtime answers 401. Document it, and expose a `clock` hook (tests and
    unusual hosts only).
  - **Streaming:** `stream_events` with `timeout=None` (`admin.py:611`) signs once at call start. The proof
    is only checked at call start, so a long stream is fine.
  - **Concurrency:** the interceptor is stateless apart from the key. Proofs on concurrent calls differ by
    `jti`, which is random per call.
  - **Token expiry:** out of scope; the runtime refuses an expired token as it does today.
- **Acceptance criteria:**
  1. An in-process `grpc.server` fake `SeamAdmin` captures the metadata and the raw request bytes. For
     `EnrollTenant`, `ListTenants` and the unary-stream `StreamEvents`, it checks two things:
     - the `dpop` proof verifies under the key;
     - `seam_bd` equals SHA-256 of the bytes the *server received*, and `htu` equals `grpc://<aud><full method>`, for example
       `grpc://seam-runtime/seam.api.v1.SeamAdmin/ListTenants` (one slash).
  2. Two consecutive calls carry different `jti` values and different proofs.
  3. Each misuse raises `DpopKeyError` before any connection is made. The cases are `dpop_key` without
     `token`, a token without `cnf`, a mismatched `jkt`, a `cnf` token without `dpop_key`, and a list `aud`
     without an override.
  4. The Bearer path is unchanged: `test_admin.py:190-198` still passes untouched.
  5. `x-seam-tenant` survives alongside the DPoP headers.
- **Tests:** `test_mgmt_dpop_interceptor.py` (in-process server; all of the above) and the existing
  `test_admin.py`.
- **Docs:** the `connect` docstring. README in Phase 10.

### Phase 3: Python live, against a real runtime

- **Status:** DONE (2026-10-27)
- **Divergences (recorded at implementation):**
  - **Replay case:** builds its proof with the public primitive and sends it twice on a raw stub, instead
    of capturing an SDK proof through a hook. This proves the same property (the runtime burns a proof
    once): the first send must succeed. The interceptor's re-signing is pinned separately, by five calls on
    one client.
  - **Live-suite registry:** the file is registered in `test_live_fixtures_are_isolated.py` (`LIVE_SUITES`;
    the anti-vacuity floor goes 6 → 7) as well as in the CI step.
- **Risk:** complex
- **Delivers:** live proof against `seam-grpc` that a bound token plus SDK proofs is accepted, and that each
  defined misuse is refused.
- **Depends on:** Phase 2.
- **Files:**
  - `python/tests/operator_token.py`: add `cnf_jkt: str | None = None` to `mint_operator_token` (`:31`).
    This is test-only and is the analogue of the runtime's reference minter.
  - `python/tests/test_mgmt_dpop_live.py` (new).
  - **No harness change:** `live_server.spawn_server` is used as-is.
- **Approach:**
  - **Posture.** The default spawn binds management on `127.0.0.1` with `SEAM_DEV_INSECURE=1`
    (`live_server.py:242`, `:245`), which is the optional posture. A `cnf` token is checked there exactly as
    on a required listener: "A token **with** `cnf.jkt` must come with a valid proof on every call, on every
    listener" (spec), and the runtime's own tests exercise this on loopback. So every assertion about what
    the *SDK* sends is fully exercised.
  - **What is deliberately not tested here:** that a required listener refuses *unbound* Bearer tokens. That
    is runtime behaviour, owned and tested by the runtime. Spawning a required posture locally would need
    dev-insecure dropped (`seam-runtime boot.rs:451` refuses a non-loopback bind under it), a non-dev boot
    configuration, a private-CIDR ack (`boot.rs:751`, `:767`), and non-loopback readiness probing
    (`live_server.py:97`, `:115`, `:140`). That is a large harness for a property the SDK does not own.
    Phase 9 covers the required posture on a real deployment (D6).
  - **Cases:**
    - accepted: a `cnf` token plus `dpop_key` calls `ListTenants`, `EnrollTenant` and a short
      `StreamEvents` successfully;
    - refused: the same token as Bearer, sent through a raw stub because the SDK refuses this at
      construction;
    - refused: a token bound to a different key;
    - refused: a replayed proof (a test-only hook captures a proof and resends it on a raw stub);
    - refused: an `iat` 120 s old (injected clock);
    - refused: a proof whose `seam_bd` covers different bytes (injected via the primitive on a raw stub).
- **Edge cases and failure modes:** a runtime image older than 0.54.0 fails the accept-case loudly, which is
  correct, since `seamd:main` is always newer. Port collisions: reuse `live_server`'s free-port helper.
- **Acceptance criteria:**
  1. With `SEAM_GRPC_BIN` set (the CI integration job), every case above passes.
  2. Each refusal surfaces as the SDK's typed unauthenticated error carrying the runtime's fixed message,
     `management call refused: DPoP proof of possession failed`.
  3. Mutation check, recorded in `PROGRESS.md`: temporarily computing `seam_bd` over different bytes inside
     the interceptor makes the live accept-case fail.
  4. The new file is collected by the integration job's Python live step (`ci.yml:406-408`), as shown in
     that job's log on the PR.
- **Tests:** `test_mgmt_dpop_live.py`.
- **Docs:** none.

### Phase 4: TypeScript primitive and KAT

- **Status:** TODO
- **Risk:** complex
- **Delivers:** `ts/src/dpop.ts` with `OperatorDpopKey`, `mgmtDpopProof` and `mgmtDpopHttpHeaders`,
  re-exported through `ts/src/index.ts` (`export *`, `:8-9`).
- **Depends on:** Phase 1 (the vector file).
- **Files:** `ts/src/dpop.ts` (new), `ts/src/index.ts`, `ts/tests/mgmt_dpop.test.ts` (new).
- **Approach:**
  - Use `@noble/curves/ed25519` and `@noble/hashes/sha256`, as `crypto.ts:7-8` does.
  - Use `Buffer` base64url, matching `crypto.ts:14-18`.
  - JSON comes from `JSON.stringify` over object literals in spec order. String-keyed insertion order is
    guaranteed for non-integer keys.
  - Randomness for `jti` comes from `globalThis.crypto.getRandomValues`, as `crypto.ts:1438` does.
  - Errors are a `DpopKeyError` class.
  - Check that no new export name collides with a generated name (`test_shadowed_names_comment.py`).
- **Edge cases:** the same local refusals as Phase 1. TS strings are UTF-16, so `ath` and `jti` sizes are
  measured over UTF-8 bytes.
- **Acceptance criteria:** the same five as Phase 1, against the same `conformance/mgmt_dpop_vector.json`.
- **Tests:** `mgmt_dpop.test.ts` with `node --test` (`ts/package.json:46`).
- **Docs:** none.

### Phase 5: TypeScript admin client speaks DPoP, plus live tests

- **Status:** TODO
- **Risk:** complex
- **Delivers:** `connect(baseUrl, { token, dpopKey, aud })` in `ts/src/admin.ts`, with a `dpopAuth`
  interceptor replacing `bearerAuth` when `dpopKey` is given. Includes live tests against a loopback runtime (D6).
- **Depends on:** Phase 4. TS has its own minter (`ts/tests/operator_token.ts:33`) and its own spawn
  (`ts/tests/admin.test.ts:48-55`), so there is no code dependency on Phase 3. Phase 3's case list is the
  spec to mirror.
- **Files:**
  - `ts/src/admin.ts`.
  - `ts/tests/mgmt_dpop_interceptor.test.ts` (new) and `ts/tests/admin.test.ts` (live cases).
  - `ts/tests/operator_token.ts`: `mintOperatorToken` gains `cnfJkt` in its `opts` (`:35`).
- **Approach:**
  - **Unary:** `seam_bd` = SHA-256 of `toBinary(req.method.input, req.message)` (`@bufbuild/protobuf` v2).
  - **Server-streaming** (`StreamEvents`): `req.message` is an `AsyncIterable`. Pull exactly one message,
    sign over its bytes, and replay it through a fresh one-element async iterable. If the iterable yields
    zero or more than one message, throw. No management RPC is client-streaming, so that would be a bug.
  - **Interceptor order:** `errorMappingInterceptor()` stays outermost (`admin.ts:205`), so DPoP refusals map
    to the typed error.
  - The construction-time checks mirror Phase 2.
  - The `SeamAdminClient` constructor signature stays unchanged. `unit_plumbing.test.ts:177` builds it from
    a fake transport.
- **Edge cases:** a retry-wrapped call must re-sign per attempt. Connect re-runs interceptors per call; pin
  that with a test.
- **Acceptance criteria:**
  1. A real in-process `node:http2` server on an ephemeral port captures the raw request bytes and metadata.
     It taps the HTTP/2 stream *before* any Connect adapter, collects the body, and strips the 5-byte gRPC
     frame prefix. Router handlers see decoded messages, so they must not be used for this, and the test
     must never re-serialise a decoded message. It verifies
     `seam_bd` against the bytes it received, for unary calls and `StreamEvents`. `fakeTransport`
     serialises nothing, so it cannot prove this.
  2. The live cases from Phase 3 pass in TS against `seam-grpc`.
  3. `unit_plumbing.test.ts` and the existing Bearer tests pass unchanged.
- **Tests:** as listed. `npm run typecheck`, `npm run build` and `npm test`.
- **Docs:** none.

### Phase 6: Go `mgmtdpop` package

- **Status:** TODO
- **Risk:** complex
- **Delivers:** `go/mgmtdpop` with:
  - `ParseJWK(json []byte) (*Key, error)` and `KeyFromSeed`;
  - `Proof(key, token, htm, htu string, body []byte, opts ...Option) (string, error)`;
  - `HTTPHeaders(...)`;
  - `UnaryInterceptor(key, token, aud)`, `StreamInterceptor(...)` and `DialOptions(...)`, shaped like
    `go/routing/routing.go:61-81`.
- **Depends on:** Phase 1.
- **Files:** `go/mgmtdpop/mgmtdpop.go`, `go/mgmtdpop/interceptor.go`, `go/mgmtdpop/mgmtdpop_test.go`,
  `go/mgmtdpop/interceptor_test.go` (all new).
- **Approach:**
  - **JSON:** structs with declared field order (as `enroll_proof.go:25-29` relies on), encoded through a
    `json.Encoder` with `SetEscapeHTML(false)`. Strip the trailing newline the Encoder adds. The `derived`
    vector case with `&`, `<` and `>` exists to catch exactly this.
  - **Request bytes:** `proto.Marshal` via `encoding.GetCodec("proto")`, the same codec grpc-go uses on the
    wire.
  - **The stream interceptor must defer the real stream.** grpc-go writes headers when the stream is created,
    before the request is known. So the interceptor returns a lazy `ClientStream`: its first `SendMsg` signs,
    appends the metadata to the captured context, calls the real streamer, and then forwards the message.
    `Header`, `RecvMsg` or `CloseSend` before `SendMsg` returns a clear error. `Context()` works before
    `SendMsg` and returns the captured context. The generated server-streaming stubs always call `SendMsg`
    first. Errors from `NewStream` now surface from the first `SendMsg`, which callers of generated stubs
    already handle.
  - Go 1.21 module (`go/go.mod:3`). No new dependencies; grpc v1.66.3 is already required.
- **Edge cases:** context cancellation before `SendMsg`; concurrent use of one interceptor (stateless apart
  from the key).
- **Acceptance criteria:**
  1. The KAT, `derived` and `jwk_rejects` cases from the shared vector pass.
  2. A `bufconn` server with a generic handler that sees raw bytes, using a passthrough codec, verifies
     `seam_bd` against the received bytes for unary and server-streaming calls.
  3. `go vet` is clean, and `go test ./...` passes under the CI Go 1.22 (`ci.yml:489`).
- **Tests:** as listed.
- **Docs:** `go/README.md` usage block.

### Phase 7: Java `MgmtDpop`

- **Status:** TODO
- **Risk:** complex
- **Delivers:** `com.zer07labs.seam.MgmtDpop`:
  - `Key.fromJwk(String)` and `Key.fromSeed(byte[])`;
  - `proof(...)` and `httpHeaders(...)`;
  - `interceptor(Key, String token, String aud)` returning `io.grpc.ClientInterceptor`.
- **Depends on:** Phase 1.
- **Files:** `java/src/main/java/com/zer07labs/seam/MgmtDpop.java` (new), `java/src/test/java/.../MgmtDpopTest.java` (new).
- **Approach:**
  - Ed25519 via BouncyCastle, as `SeamCrypto.java:107-114` does.
  - JSON via ordered maps (`LinkedHashMap`, the pattern at `SeamCrypto.java:660`) through a Gson built with
    `disableHtmlEscaping()`. The default `new Gson()` at `SeamCrypto.java:41` escapes HTML.
  - **The interceptor uses delayed start.** It wraps `ClientCall`. `start(listener, headers)` is buffered;
    on the single `sendMessage(req)`, the request bytes are read through
    `method.getRequestMarshaller().stream(req)`, which gives exactly the wire bytes for any marshaller. It
    then signs, adds both headers, and calls the real `start` followed by `sendMessage`. `request(n)`
    (async stubs call it before `sendMessage`), `cancel` and `halfClose` before start are queued and replayed
    in order. grpc-java's own `io.grpc.internal.DelayedClientCall` lives in grpc-core, which is not on the
    classpath (only `grpc-api`, `:14`). So this is a deliberate, small reimplementation on
    `ForwardingClientCall`/`ClientCall`, modelled on that class's queue-then-drain semantics. Do not add a
    grpc-core dependency for it. Marshalling the request twice (once to sign, once by the real call) is
    acceptable.
- **Edge cases:** cancel before `sendMessage`; client-streaming method types refused with a clear
  `IllegalStateException`.
- **Acceptance criteria:**
  1. The shared vector passes.
  2. A `grpc-inprocess` server (test deps at `java/build.gradle.kts:19-20`) with a raw-bytes marshaller
     verifies `seam_bd` against the bytes it received, for unary and server-streaming calls.
  3. `./gradlew test` passes on JDK 17.
- **Tests:** as listed.
- **Docs:** none (Phase 10 README).

### Phase 8: Kotlin `MgmtDpop`

- **Status:** TODO
- **Risk:** complex
- **Delivers:** the Kotlin twin of Phase 7: `object MgmtDpop`, `MgmtDpop.Key`, and the same interceptor
  semantics.
- **Depends on:** Phase 1. It mirrors Phase 7's design; Phase 7 is not a code dependency, because Kotlin
  duplicates rather than depends (`kotlin/build.gradle.kts:9`).
- **Files:** `kotlin/src/main/kotlin/com/zer07labs/seam/MgmtDpop.kt` (new), `kotlin/src/test/kotlin/.../MgmtDpopTest.kt` (new).
- **Approach:** as Phase 7, in idiomatic Kotlin: `linkedMapOf` (pattern at `SeamCrypto.kt:649`), and a Gson
  built with `disableHtmlEscaping()`.
- **Acceptance criteria:** the same three as Phase 7.
- **Tests:** as listed.
- **Docs:** none.

### Phase 9: aws-stg end-to-end smoke (the issue's second acceptance criterion)

- **Status:** TODO
- **Risk:** complex
- **human-run:** yes, expected. The agent builds and dry-runs; an owner runs it.
- **Delivers:**
  - `scripts/handoff/2026-10-27-mgmt-dpop-aws-stg.sh`, built from `seam/scripts/handoff/_template.sh` (and its
    `lib.sh`), wrapping `scripts/smoke/mgmt_dpop_aws_stg.py`. The script:
    - (1) generates an Ed25519 key in memory;
    - (2) mints a **bound** operator token from the aws-stg control plane at
      `POST /api/control-plane/operator-tokens` (the route the console and relay use; see
      `seam-control-plane/src/http/anchors.test.ts:34` and `SEAM_RELAY_TOKEN_MINT_URL` in
      `seam-runtime/deploy/helm/seam/values/aws-stg/seam-relay.yaml`), sending a `DPoP` mint proof with
      `htm: POST` and `htu` set to that exact URL, so the control plane sets `cnf.jkt` from our key;
    - (3) reaches the runtime's TLS gRPC management listener on 9100 from an identity the mesh admits;
    - (4) calls the read-only `SeamAdmin/ListTenants` through
      `SeamAdminClient.connect(..., dpop_key=..., credentials=grpc.ssl_channel_credentials(<CA>))`;
    - (5) asserts success, then asserts the same bound token sent as Bearer is refused. That refusal is
      `scheme_mismatch` on any listener, so it proves only the binding.
    - (6) **Required-posture case, optional input:** an **unbound** operator token (a console mint with the
      DPoP toggle off, or the same mint request with no proof from a human caller) sent as Bearer must be
      refused. That is the required listener's `no_cnf` rule (spec *Binding rules*). Without this input the
      run reports "required posture: not exercised" instead of claiming it.
  - **Handoff contract,** per `seam/scripts/handoff/lib.sh`:
    - Dry-run is the **default**; `--apply` executes (`lib.sh:12`).
    - The verify step always runs, so in dry-run it checks only local preconditions: inputs present, CA file
      readable, Python client importable. It makes no network call.
    - Steps never echo argv that could carry secrets. Pass them only through the environment and print
      redacted placeholders.
    - seam-sdk has neither `scripts/preflight.sh` nor `lib.sh`, so the script is **self-contained** and
      reproduces the template's shape without sourcing `lib.sh`. The precedent is
      `seam-connectors/scripts/handoff/2026-10-23-objstore-live-buckets.sh:12-13` ("lib.sh is not
      vendored into this repo").
- **Depends on:** Phase 2. It uses only the Python client; Phase 3 is not needed.
- **Files:** `scripts/smoke/mgmt_dpop_aws_stg.py` (new), `scripts/handoff/2026-10-27-mgmt-dpop-aws-stg.sh`
  (new).
- **Why a handoff is the expected path.** Each premise needed for an agent run is unproven or crosses a trust
  boundary:
  - **Mint identity:** a fleet credential always binds its pinned fleet key. A proof from a fleet caller is
    verified against that pinned key (`seam-control-plane src/http/routes/mint.ts:162`, `jkt: pinned`), and
    `return pinned ?? v.jkt` (`:170`) binds it. Only a non-fleet caller binds the proof's own key: a human,
    or an Auth0 M2M client, which must send a proof (`:148`). On aws-stg, the M2M client is seam-relay's own; using it
    means borrowing another service's secret. Alternatively, a human mints in the console and passes the
    revealed JWK plus token in through the environment. That is the console flow the issue names, and it is
    held only by the owner.
  - **Reachability:** the management ports admit only `callers: [control-plane, seam-relay]`
    (`seam-server.yaml:91-92`). No `kubectl` or port-forward access for sessions is documented
    (`seam/docs/delivery/11-k8s-multicloud-deployment.md:123`). Widening an AuthorizationPolicy for a test
    is out of scope.
  - **TLS:** 9100 serves TLS (`seam-server.yaml:62-63`). The CA bundle and the SAN to dial (the relay dials
    `https://seam-server:9100`) must be supplied.
  So the script takes, as inputs, the token plus JWK (the console path, preferred) or the M2M client
  credentials, along with the dial target, the CA and the SAN override. It runs wherever the owner has an
  admitted identity.
- **Edge cases:**
  - **aws-stg runtime older than 0.54.0:** the bound token is refused. The script reports the runtime image
    tag, if it is given one, and labels the failure accordingly.
  - **The control plane refuses the mint proof (`dpop_proof_invalid`):** the script prints the `htu` it
    signed so the mismatch is visible. A real rule mismatch between the CP and the runtime spec is a
    **bug** to file in seam-control-plane, with evidence.
  - **Secrets:** the token and JWK come only from the environment, are never written to disk, never echoed,
    and are redacted in all output.
- **Acceptance criteria:**
  1. The default (dry-run) invocation succeeds locally with placeholder inputs, makes no network call, and
     its transcript is recorded in `PROGRESS.md`.
  2. `PROGRESS.md` records `AWAITING-HUMAN: scripts/handoff/2026-10-27-mgmt-dpop-aws-stg.sh` with the
     3-line handoff, or, if the owner runs it during this train, the successful `ListTenants`, the bound-as-
     Bearer refusal and the unbound `no_cnf` refusal (or "not exercised"), with a timestamp.
  3. Nothing in aws-stg is modified by building or dry-running it.
  4. A unit test runs both the shell wrapper (dry-run) and the Python script's argument and secret handling
     with fake secret values, and asserts that none of them appears in stdout, stderr or the handoff log.
- **Tests:** the dry run, plus the redaction test above (`python/tests/test_smoke_script_redaction.py`).
  The test lives under `python/tests`, so the existing Python CI job collects it.
- **Docs:** the script's header is the how-to.

### Phase 10: docs, compatibility and changelog

- **Status:** TODO
- **Risk:** simple
- **Delivers:**
  - `README.md`'s admin-auth section (`:448-472`) gains "Bound (DPoP) operator tokens". It shows, per
    language, how to load the console's one-time reveal (the `{"kty":"OKP","crv":"Ed25519","x":…,"d":…}`
    JSON shown next to the token) and connect with it.
  - Handling guidance for the private JWK: environment or secret manager, never committed, shown once.
  - The clock-skew note.
  - The HTTP-helper usage.
  - `COMPATIBILITY.md`: a bound token needs runtime ≥ 0.54.0; the required posture is ≥ 0.55.0.
  - A `CHANGELOG.md` entry.
- **Depends on:** Phases 2, 5, 6, 7 and 8. Phase 9's result is recorded but does not gate this phase.
- **Files:** `README.md`, `COMPATIBILITY.md`, `CHANGELOG.md`, `go/README.md`.
- **Acceptance criteria:**
  1. Each of the five language snippets runs as written. The Python and TS snippets are executed by a doc
     test against the in-process fake; the Go, Java and Kotlin snippets compile in their test sources.
  2. The README never shows a real-looking private key. It uses the golden test seed's JWK and labels it.
  3. `COMPATIBILITY.md` names 0.54.0 and 0.55.0 with their runtime PRs (#1428, #1463).
- **Tests:** the snippet tests above.
- **Docs:** this phase. No `seam/docs/` contract changes: the SDK implements an existing runtime spec, and
  no dependency edge is added, so no `seam/CLAUDE.md` edit is needed.

## Long-term posture

- **A public API, five times over: `dpop_key=` / `dpopKey` and the `MgmtDpop` surfaces.** It is additive, so
  removing it later would be breaking. That is why the shape is deliberately minimal (key, primitive, gRPC
  hook, HTTP hook), mirrors RFC 9449 vocabulary, and stays transport-agnostic in its primitive. No class
  hierarchy, no pluggable signer interface: that is YAGNI until a non-Ed25519 or HSM-held key exists, and
  the primitive can grow a `sign` callback additively then.
- **Vendored spec plus spec-pin gate:** the SDK cannot silently drift from the runtime's rule.
- **Debt avoided:** no JOSE dependency in five ecosystems, and no "TS + Python now, others later" split that
  would leave three languages unable to reach the management plane once `SEAM_MINT_DPOP_BINDING=all` ships.
- **Not a one-way door:** the default `aud` derivation and the 16-byte `jti` can change without an API change.

## Enterprise concerns

- **Security:**
  - The private key never leaves the process: there is no logging and no repr.
  - Token claims are peeked only for operator-error diagnostics, never trusted.
  - Every attempt gets a fresh proof, so replay protection holds.
  - Local refusals mirror the runtime's caps (8 KiB proof, 1 MiB body, 256-byte jti).
- **Reliability:**
  - Clock skew beyond ±60 s is the dominant field failure. It is documented, and the 401 text is fixed by
    the runtime, so the SDK error message adds "check the host clock" when the error is DPoP-related.
  - A runtime store outage surfaces as `INTERNAL`, not as a credential fault, so the SDK must not map it to
    "bad key".
- **Observability:** the runtime owns `seam_mgmt_auth_rejected_total{reason}`. The SDK adds no telemetry.
- **Rollback:** every change is additive and opt-in (`dpop_key` absent means today's Bearer path,
  unchanged), so rollback is a revert.

## Decisions (Opus, consequential but decidable)

- **D1. Placement in Go, Java and Kotlin is interceptor factories, not clients.** Those SDKs have no gRPC
  client; this matches `routing`/`TenantRouting`.
- **D2. The `aud` default comes from the token's `aud` claim.** The runtime accepts a token only when its
  `aud` matches `SEAM_RUNTIME_AUD`, which is the spec's `htu` authority, so the token already names it.
  Explicit override wins; a list `aud` without an override raises.
- **D3. The SDK fails fast at construction on a `cnf`/key mismatch, a missing `cnf`, or a `cnf` token
  without a key.** Every one of these is a guaranteed runtime 401 with an opaque fixed message.
- **D4. The vector file is split into golden (runtime-pinned) and derived (five-way agreement) groups**,
  labelled so nobody mistakes derived cases for runtime truth.
- **D5. The spec is vendored under `docs/specs/`.** It is not verifier material, so it does not go in
  `verify/docs/`. `check_vendored_spec.py`'s `VENDORED` tuple (`:139-151`) takes a free-form `local` path,
  and `--from gh` reads any remote path (`:281`).
- **D6. Live SDK tests run on the loopback (optional) posture only.** A `cnf` token is proof-checked
  identically on every listener, so every SDK-side property is exercised there. Refusing *unbound* tokens on
  a required listener is runtime behaviour, tested by the runtime. A local required-posture spawn would need
  a non-dev boot and a non-loopback harness (Phase 3 *Approach*) for no SDK coverage gain. The
  required listener's own rule (unbound Bearer refused with `no_cnf`) is exercised by Phase 9's optional
  unbound case and reported as "not exercised" when that input is absent.

## Open questions (defaults chosen; `/implement` logs them `UNCONFIRMED` when implemented)

- **Q1:** in Phase 9, which mint path does the owner use, the console reveal or the relay M2M client?
  Default: the console reveal. It is the issue's own wording, and it needs no borrowed secret.
- **Q2:** does the control plane's HTTP `htu` check on `POST /operator-tokens` follow the runtime spec's
  HTTP rule? Phase 9 surfaces it; a mismatch is a bug to file in that repo, not an SDK workaround.

## Plan review

Two review rounds, each by a fresh Opus reviewer that checked the plan against the code.

- **Round 1: REVISE.**
  - The local required-posture spawn cannot boot: dev-insecure refuses a non-loopback bind, and the harness
    is loopback-only. Replaced by D6 (loopback live tests only).
  - The version check was dropped: `seam-grpc` has no version to read.
  - TS has its own minter and spawn, so Phase 5 now depends on Phase 4 only.
  - Phase 9's mint path, its fleet-versus-M2M binding and TLS were all corrected, and an `AWAITING-HUMAN`
    handoff became the expected path.
  - Anchors fixed: Go `:81`, Java `:19-20`, `unit_plumbing:177`.
  - Added the Go lazy-stream `Context()` note, and noted that Java's `DelayedClientCall` lives in grpc-core
    (reimplement on `ForwardingClientCall`).
  - Phase 5 AC1 now needs a real HTTP/2 server, and the Phase 2 `htu` wording is fixed.
- **Round 2: REVISE**, all concrete:
  - A bound token sent as Bearer is `scheme_mismatch` on any listener, so it proves no posture. Added the
    optional unbound-token case (`no_cnf`) and stopped claiming required-posture coverage without it.
  - Phase 9 now follows the handoff `lib.sh` contract: dry-run by default with `--apply`, a verify step that
    runs in dry-run with local checks only, no argv echo, and self-contained (connectors precedent).
  - Phase 5 AC1 must tap the raw HTTP/2 body before the adapter.
  - The `mint.ts` anchors were corrected (`:162`, `:170`).
  - The leftover "both postures" wording was removed.
- **Verdict after applying round 2: SOUND.** The cap is two rounds. Every round-2 item was a factual or
  wording correction with code evidence, not requirements ambiguity, so all were applied without a third
  draft.
