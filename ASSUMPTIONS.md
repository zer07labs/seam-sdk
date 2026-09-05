# Assumptions — seam-sdk adopts the seam-runtime backlog-closeout landing (2026-07)

Working assumptions taken during `/implement` of `plans/archive/adopt-runtime-2026-07.md`, to
reconcile later. Each is the strongest option given what the code showed; none is a one-way door.
Reconciled 2026-08-16 — see `DECISIONS.md` for the full record.

## check-contract default mode is RPC-only; streamed-payload fields gate under STREAM=1
- **Assumed:** the SDK's CI must stay green against the **currently published BSR**, which carries
  `VerifyPartyAttestation` (A4) but not yet the four streamed-payload mirror fields (they land only after
  the runtime proto-mirror's user-gated BSR push).
- **Chose:** `make check-contract` hard-gates on `VerifyPartyAttestation` (always) and only **reports** the
  streamed-payload fields by default, becoming a hard gate under `STREAM=1`. CI runs the default mode. When
  the Phase-0 push lands on the BSR, flip the CI step (or a Phase-6 job) to `STREAM=1` to lock the streamed
  surface in too.
- **Alternatives:** (a) hard-gate everything now — would turn CI red until the BSR push, coupling the SDK's
  green build to a runtime-side user-gated action; (b) gate nothing — loses the freshness guarantee that is
  the phase's whole point.
- **Blast radius if wrong:** low/reversible — one env flag on one CI step. If the streamed fields must be
  enforced sooner, set `STREAM=1`; if the RPC gate is too strict, it is a one-line probe change.
- **Status:** CONFIRMED (2026-08-16). The escalation this entry named as the eventual target already
  happened: `.github/workflows/ci.yml` now runs `STREAM=1 EVENTS=1` as permanent hard gates on both
  check-contract steps, and `README.md` states the BSR carries the full surface. (This entry originally
  said "CI runs the default mode" — that clause is now stale; the env-flag split itself — lenient default
  for local mid-regeneration trees, hard gate in CI — is unchanged and correct.) See DECISIONS.md.

## generate-local is the development baseline; the BSR is the release source
- **Assumed:** SDK development should not be blocked waiting on the (user-gated, immutable) BSR push, while
  releases must still come from the published contract of record.
- **Chose:** documented + tooled `make generate-local RUNTIME=../seam-runtime` as the iteration baseline
  (always current with the runtime tree) and `make generate` (BSR) as the release source. All later phases
  (2–6) develop against `generate-local`.
- **Alternatives:** assume the BSR is always fresh — the runtime's A13 history (a `buf push` that used to
  silent-skip) says it may not be, and a stale contract would pass locally and break on release.
- **Blast radius if wrong:** none structural — it is a documented workflow, not a code contract.
- **Status:** CONFIRMED (2026-08-16). Verified: the `Makefile` still has both targets exactly as
  described; `ci.yml`/`publish.yml` only ever call `make generate` (BSR); `README.md` documents
  `generate-local` for iteration; and `python/tests/test_workflows_generate_through_the_makefile.py`
  enforces that no workflow calls raw `buf generate`. Nothing drifted. See DECISIONS.md.

## The live attestation valid-case pins the runtime's chain_head_attestation KAT
- **Assumed:** the Phase-2 live test needs a genuinely-valid attestation for the "verifies" case, and the
  SDK must stay Seam-crate-free and not re-implement the chain-head signature framing.
- **Chose:** pin the runtime's committed `chain_head_attestation` KAT (issuer seed + precomputed signature)
  directly in the test — derive the party pubkey from the seed with the standard `cryptography`/`@noble`
  ed25519, register it via the admin plane, and submit the KAT attestation verbatim (its `issuer_aid` is
  part of the signed preimage, so it is passed exactly). A known-good signature from the runtime is the
  gold standard; the SDK never re-derives the framing (that is Phase 4's `verify/` job, kept independent).
- **Alternatives:** (a) add a client-side chain-head signer to the crypto shim — new product crypto surface
  the plan explicitly rejected for Phase 2; (b) read the vector from a sibling runtime checkout — a fragile
  path that differs between local and CI. Phase 5 will formalize this KAT into `conformance/vectors.json`.
- **Blast radius if wrong:** low — a test-only fixture. If the runtime regenerates the KAT, the pinned
  constants must be refreshed (a deliberate, reviewable update, flagged by the test going red).
- **Status:** CONFIRMED (amended) (2026-08-16). The decision to pin a runtime-signed KAT rather than
  re-derive the framing client-side is correct and unchanged. The *mechanism* was amended, scoped to the
  two Python/TS attestation tests this entry was originally about: Phase 5 had since added this same KAT
  to `conformance/vectors.json`, but `python/tests/test_verify_attestation.py` and
  `ts/tests/verify_attestation.test.ts` still carried their own hand-copied literal. Both now load the KAT
  from `conformance/vectors.json` (matching the loader pattern `test_conformance.py` / `conformance.test.ts`
  already use) and the duplicated literals are deleted, so a runtime KAT regen reddens both of these
  instead of silently diverging. **Not closed by this pass:** `verify/src/verify.rs` (the Rust crate, a
  different test — payload-framing, not attestation registration) carries two more independent hardcoded
  copies of the same KAT (`attested_len: 1000` etc. at ~line 488 and ~515) that a regen still wouldn't
  catch; out of scope here since it's a separate assumption's territory (Rust crate hygiene), not this
  Python/TS entry — worth its own follow-up if it's ever worth the churn. See DECISIONS.md.

## The verify/ authenticity goldens are pinned to a runtime commit
- **Assumed:** the independent verifier must be tested against the SAME golden streams the runtime tests
  its own verifier with, or "the two verifiers agree" (Phase 5) is unprovable — but the goldens are
  generated in the runtime and can be regenerated (`REGEN_GOLDENS=1`).
- **Chose:** copy the runtime goldens verbatim into `verify/tests/goldens/` and pin the source commit in the
  test-module doc (seam-runtime @ fd633c9). A runtime golden regen becomes a deliberate, reviewable SDK
  update (the copied fixture drifts → a test fails), never a silent divergence. Phase 3 copies only the two
  it uses (attested, fabricated); Phase 4 adds `payload_rewrite`.
- **Alternatives:** read the goldens from a sibling runtime checkout at test time — a fragile path that
  differs local vs CI, and couples the SDK's green build to a runtime checkout being present.
- **Blast radius if wrong:** low — test fixtures. A drift is caught by a failing test, and the fix is a
  re-copy from the named commit.
- **Status:** CONFIRMED (2026-08-16). Verified: `verify/tests/goldens/` exists and is populated
  (`attested_chain.jsonl`, `fabricated_chain.jsonl`, `payload_rewrite.jsonl`), the pin (seam-runtime
  commit `fd633c9`) is a real, reachable commit in the sibling checkout, the SDK's goldens are
  byte-for-byte identical (SHA-256) to that commit's fixtures, and there has been no runtime-side drift
  since (`git log fd633c9..HEAD -- crates/seam-verify/tests/goldens/` is empty). See DECISIONS.md.

## The streamed digest-recompute helper lives on the admin module, keyed to a single record
- **Assumed:** Phase 6 (the plan marks it optional; implemented per the "do it fully" decision) needs an
  in-client counterpart to `verify/`'s design-a, but the client already has the full authenticity story via
  the standalone `verify/` tool over exported streams — so the in-client helper should be minimal.
- **Chose:** `verify_streamed_record_digest(event)` / `verifyStreamedRecordDigest(event)` verifies ONE
  streamed v2 `DECISION_SEALED` (recompute + compare to the wire digest), placed next to `stream_events` on
  the admin module and re-exported. It reuses Phase 5b's `record_digest_v2` framing (no third impl). A
  full streamed *chain* walk (attestation verification over a live feed) is deliberately left to `verify/`
  on an exported stream — porting the whole `--issuer` pass into Py+TS would be a second maintenance
  surface for the authenticity logic with no consumer asking for it yet.
- **Alternatives:** (a) a full in-client `verify_streamed_chain` — heavier, duplicates the attestation
  logic; (b) no in-client helper at all — but acceptance 2 wants a client-side recompute that matches the
  runtime.
- **Blast radius if wrong:** low — additive API. If a full streamed-chain verify is later wanted, it builds
  on the same `record_digest_v2` + `verify_chain_head_attestation` primitives already shipped.
- **Status:** CONFIRMED (2026-08-16). Verified: `verify_streamed_record_digest`/`verifyStreamedRecordDigest`
  are behaviorally equivalent in both languages, both tested (genuine/rewrite/strip/v1/v3-plus), and
  documented in `README.md`. No consumer has asked for the broader `verify_streamed_chain` since — the
  minimal scope holds. See DECISIONS.md.

## `timeout` means per-RPC, not an overall call budget

- **Assumed:** callers who need a hard overall bound already impose their own outer clock.
  True of the one consumer we know: `seam-agent-core`'s `Gate` wraps every call in
  `asyncio.wait_for`, and `SessionBinder` does the same per step.
- **Chose:** keep per-RPC and **document it explicitly** (`client.py`, above `DEFAULT_TIMEOUT_S`).
  Most methods make one wire call, so the distinction is invisible; it bites on `authorize`,
  which can make up to six (a cold/stale admit is 2 RTT, then Authorize, then on
  `UNAUTHENTICATED` a refresh of 2 RTT plus the retried Authorize), and on `run_decision` /
  `open_session`, which each begin with the challenge→Admit handshake.
- **Alternatives:** an overall budget — the semantics most callers would assume from the name.
  Rejected for now, not forever: it means threading a deadline through the ticket lifecycle and
  deciding what a partially-spent budget means for a refresh, which is a contract change for
  every existing caller in exchange for a bound the only consumer that needs it already has.
- **Blast radius if wrong:** a caller sizing an outer deadline as `1x timeout` sees spurious
  cancellations on the refresh path, where the SDK legitimately needs more. That is the failure
  the documentation above is meant to prevent; the adapters' `Gate` already sizes for it.
- **Status:** CONFIRMED (2026-08-16). Verified: `client.py`'s doc comment is still accurate to the
  code (the six-call worst case above), TS carries the mirrored doc, and Go/Java/Kotlin have no
  client (crypto-shim only) so no gap there. No second consumer wanting an overall budget has
  surfaced — `seam-aegis` calls `seam_sdk` directly but only from a diagnostic check harness with
  no hard-bound requirement; its production path goes through `seam-agent-core`, which already
  imposes `timeout_s`. Revisit if that changes; an overall budget stays addable later as a distinct
  parameter rather than a redefinition of `timeout`. See DECISIONS.md.

## The `protobuf` floor is derived from the generated stubs, not chosen

- **Assumed:** consumers can move to protobuf 7.x. `_gen` is emitted by buf's remote
  `protocolbuffers/python` plugin, which tracks latest, so this is not really optional — every
  wheel we build already contains gencode that demands it.
- **Chose:** `protobuf>=7.35.1,<8`, matching the gencode currently emitted, plus
  `tests/test_protobuf_floor.py`, which DERIVES the required version from the emitted stubs and
  fails when a regenerate outruns the declared floor. The number will move; the guard is what
  keeps it correct without anyone remembering. `requires-python` also moves to `>=3.10`, because
  protobuf 7.x requires it — 3.9 was already broken in practice, just at import time rather than
  at resolve time.
- **Alternatives:** pin the buf plugin version to freeze the gencode (buf remote plugins do
  support version pinning, and this would trade "the floor moves" for "the stubs go stale" —
  worth revisiting if the floor churns); leave `>=5` and document the hazard (it is what shipped,
  and it broke a consumer's entire suite with an error that named protobuf rather than us).
- **Blast radius if wrong:** a consumer pinned to protobuf 5.x or 6.x can no longer resolve
  seam-sdk. That is the correct outcome — the alternative is resolving successfully and failing
  at `import seam_sdk` — but it IS a breaking change for such a consumer and wants a minor bump
  and a release note.
- **Status:** CONFIRMED (2026-08-16). The floors shipped in 0.7.13 (2026-08-03) exactly as chosen
  (`protobuf>=7.35.1,<8`, `requires-python>=3.10`), with the release-framing concern this entry
  raised already addressed: `CHANGELOG.md`'s 0.7.13 section carries an explicit warning block
  stating the version number can't signal the break (seam-sdk follows the runtime's version; a
  minor bump was structurally impossible under "one version everywhere"), a table of what each old
  floor allowed, and confirmation that resolvers still do the safe thing. `test_protobuf_floor.py`
  still derives and enforces the floor from the emitted stubs. See DECISIONS.md.

## The `grpcio` floor is derived the same way, and needs the LATER of two versions
- **Assumed:** consumers can move to grpcio 1.64+. Same reasoning as protobuf above, and found by
  the verification pass on that very change — the identical defect was sitting three lines away in
  the same dependency list.
- **Chose:** `grpcio>=1.64`, plus `tests/test_grpcio_floor.py`, which derives the requirement from
  the calling-convention markers present in `_gen` rather than pinning a number (buf's remote grpc
  plugin tracks latest, and unlike `seam_pb2.py` the grpc stub carries no version constant to read).
  1.64 rather than 1.63 because the stubs need BOTH halves of the registered-method convention:
  `_registered_method=True` on the client (1.63) and `server.add_registered_method_handlers`, emitted
  unguarded, on the server (1.64). Verified by installing 1.60/1.62/1.63/1.64 and calling both.
- **Alternatives:** rejected `>=1.63`, which is what checking only the client half yields — it
  installs, connects, and then raises `AttributeError` from every `add_*Servicer_to_server`, so it
  moves the failure later and makes it look like the consumer's fixture bug. Rejected pinning
  without a guard, for the same reason as protobuf: the number moves on a regenerate.
- **Blast radius if wrong:** a consumer pinned below grpcio 1.64 can no longer resolve seam-sdk.
  As above, that is the correct outcome — the old `>=1.60` let a resolver pick a grpcio where
  `SeamClient.connect()` dies with an opaque `TypeError` — but it is breaking for such a consumer.
- **Status:** CONFIRMED (2026-08-16). Same resolution as the protobuf floor above — shipped in
  0.7.13 with the same framing. `test_grpcio_floor.py` still derives and enforces `grpcio>=1.64`
  from the calling-convention markers present in `_gen`. See DECISIONS.md.

## Testing (not just building) `verify/` at its declared MSRV
- **Plan:** `plans/archive/close-out-w1-w7-loose-ends.md` (Phase 1)
- **Assumed:** running the *test* profile at the MSRV does not overstate the promise made to
  consumers, who never build the tests.
- **Chose:** run both `cargo build --locked` and `cargo test --locked` in the `verify-msrv` job.
  Verified rather than assumed at the time of writing: `verify/`'s direct dev-dependencies are a
  strict subset of its normal dependencies and declare a strictly lower MSRV, so the test profile
  cannot raise the floor above what a consumer needs. Testing is the stronger check and catches a
  dependency that requires more than it declares — the whole point of the job.
- **Alternatives:** build-only at MSRV (weaker — misses anything only the tests exercise); a
  separate build-at-MSRV and test-at-MSRV pair (correct if the two ever diverge, but two jobs today
  for a condition that does not exist).
- **Blast radius if wrong:** if a dev-dependency ever declares a higher MSRV than the normal
  dependencies, this job would force `rust-version` upward to satisfy something consumers never
  compile — an MSRV that is *too high*, i.e. an unnecessarily narrow promise rather than a broken
  one. Reversible in one commit by splitting the job. The `verify-msrv` job comment records the
  condition and the correct response.
- **Status:** CONFIRMED (2026-09-01). Re-measured, not assumed: `verify/Cargo.toml`'s
  `[dev-dependencies]` are `sha2`, `base64` and `serde_json` — a strict subset of
  `[dependencies]` (`prost`, `sha2`, `ed25519-dalek`, `base64`, `serde`, `serde_json`), so the test
  profile resolves nothing a consumer does not already compile and cannot raise the floor. The
  declared `rust-version = "1.85"` still comes from normal deps only (`prost` / `base64ct` /
  `zeroize`), and `verify/tests/msrv.rs` derives it from `cargo metadata` on every run, so the
  divergence this entry guards against would fail a test rather than wait to be noticed. The
  single-job choice stands. See DECISIONS.md.

## v3 validates every input; v2 deliberately still does not

- **Plan:** `plans/archive/record-digest-v3.md` (Phase 3)
- **Assumed:** `record_digest_v3` / `recordDigestV3` should refuse any input it cannot faithfully
  represent, rather than coerce it — and `record_digest_v2` should keep its current lenient
  behaviour, leaving the two versions with different opinions about what a valid call is.
- **Chose:** Validate every v3 slot, inside `recordDigestV3`'s own body, touching no helper v2
  shares. Bytes slots must be a one-byte-per-element buffer of the right length; string slots must be
  actual strings with no unpaired surrogates; integer slots must be in range and exactly
  representable. Every refusal happens before a single byte is hashed.

  The trigger is not tidiness — it is that some of these coercions produce an **alias**, not a
  mismatch. **In TypeScript**, a 32-character string passed as a sub-digest hashes as 32 zero bytes,
  which is a digest a legitimate all-zeros sub-digest also produces; `2**64 + 5` hashes as `5`. A
  mismatch is caught downstream by the comparison the function exists to feed. An alias is caught
  nowhere. That is the same class of collision the spec's own framing rules exist to prevent
  (`seam-event.v1.md`, "The outer count, and the collision it prevents"), so refusing is the
  version-consistent answer, not extra strictness.

  **Scoping corrected at reconcile (2026-08-24):** those two inputs *raise* in Python rather than
  aliasing, so the alias argument is TypeScript-specific and was originally stated too broadly.
  Python's validation earns its place by a different route — v2 accepts a
  `memoryview(array("I", [0]*32))` and frames a length prefix claiming 32 while hashing 128 bytes,
  which is the same injectivity break arriving through a different door.

  v2 keeps the coercions. Issue #56 requires `record_digest_v2` to stay byte-identical forever and
  the v2 vectors untouched in the diff; adding guards there would not change a single digest byte,
  but it would put v2's frozen function back under review, which is precisely what that requirement
  is protecting against.
- **Alternatives:** (a) Leave v3 lenient too, for symmetry — rejected once the alias was demonstrated
  rather than theorised: symmetry is not worth a silent collision. (b) Harden v2 in the same change —
  rejected as out of scope for a phase whose contract is "v2 is untouched"; it is a decision about
  the v2/v3 pair and belongs to whoever revisits v2 next.
- **Blast radius if wrong:** A caller relying on one of the coercions (passing a `number` above 2^53
  for `sealedAt`, say, or a plain object with a `length`) now gets an exception where it previously
  got a digest. **Corrected at reconcile:** "every such digest was wrong, so no correct caller
  breaks" is too strong. A proto3-JSON int64-as-string (`sealedAt: "123"`) coerced *correctly*
  through `BigInt` before and is now refused — loudly, at the first record, with the fix named in the
  message. Accepting strings is what reopens `BigInt("")→0n` and `BigInt([5])→5n`, so the trade is
  still right; the justification simply does not extend to "nothing that used to work stops working."
  Cheap to reverse: the validators are a contiguous block at the top of one function in each
  language.
- **Status:** CONFIRMED (2026-08-24) — see `DECISIONS.md`, "reconcile `plans/record-digest-v3.md`'s ASSUMPTIONS.md (4 entries)".

## The v1 skip is a downgrade hole, closed structurally rather than documented

- **Plan:** `plans/archive/record-digest-v3.md` (Phase 4)
- **Assumed:** `seam-verify` should REFUSE a `DECISION_SEALED` that declares `schema_version < 2`
  while carrying `ciphertext_digest` (tag 10) or any of tags 11/12/13, rather than skipping it as the
  link-only v1 record it claims to be.
- **Chose:** Refuse. `schema_version < 2` exempts a record from the digest recompute, because a v1
  record's historical digest genuinely is not stream-recomputable. That exemption is reachable by an
  attacker: rewrite a structural column, relabel the version to 1, and no recompute ever runs. It is
  the one downgrade direction the recompute cannot catch by construction — every other version is
  dispatched to a formula and fails the comparison; a downgrade *into the skip* means there is no
  comparison to fail. The spec supplies the discriminator: `ciphertext_digest` "is absent (no wire
  bytes) only on `schema_version = 1` payloads", and tags 11/12/13 arrived with v3, so a payload
  declaring v1 while carrying any of them is a covered record wearing v1's exemption. Each of the four
  columns is decoy-proven independently (a decoy guarding only on tag 10 initially passed the test,
  which is how the per-column parametrization got written).
- **Alternatives:** (a) Document it as a residual in `COMPATIBILITY.md`, as the Phase 4 verifier
  suggested — rejected: a verifier's entire job is catching downgrades, and this is one, with a cheap
  spec-grounded test for it. (b) Refuse every v1 record — rejected outright: real pre-A14 records
  exist in real chains, and refusing them would make the verifier unrunnable over an archive. The
  guard therefore keys on the COLUMNS, never on the version alone, and a genuine v1 record still
  verifies and is still counted as not-recomputed.
- **Blast radius if wrong:** A producer that emits `schema_version = 1` alongside a `ciphertext_digest`
  — i.e. one contradicting the spec — would now be refused where it previously passed. No conforming
  producer is affected, and the existing v1 golden still verifies green. Cheap to reverse: one
  contiguous block in `verify_authenticity`.
- **Status:** CONFIRMED (2026-08-24) — see `DECISIONS.md`, "reconcile `plans/record-digest-v3.md`'s ASSUMPTIONS.md (4 entries)".

## `frame`'s `len() as u32` truncates above 4 GiB, in Rust only

- **Plan:** `plans/archive/record-digest-v3.md` (Phase 4)
- **Assumed:** It is acceptable that `record_digest_v3`'s `frame` closure casts `part.len() as u32`,
  which truncates silently for a single field of 4 GiB or more. Python raises there and TypeScript
  wraps.
- **Chose:** Mirror `record_digest_v2` exactly. The cast is v2's, byte-for-byte, and the phase's
  contract is that v3's framing is v2's framing plus three slots — introducing a divergence in the
  shared closure would be a worse defect than the one it fixes. Reaching it also requires a
  multi-gigabyte single field already parsed into memory, at which point the stream has other problems.
- **Alternatives:** Check the length and refuse. Worth doing for BOTH versions at once, as its own
  change, not asymmetrically inside a v3 transcription.
- **Blast radius if wrong:** A >4 GiB field would frame with a truncated length prefix and produce a
  digest that disagrees with every other implementation — reported as a mismatch, never as a pass.
- **Status:** CONFIRMED (2026-08-24) — see `DECISIONS.md`, "reconcile `plans/record-digest-v3.md`'s ASSUMPTIONS.md (4 entries)".

## The v3 conformance cases this repo designed live in a second file, not in `conformance/vectors.json`

- **Plan:** `plans/archive/record-digest-v3.md` (Phase 4.5)
- **Assumed:** that `conformance/vectors.json` has exactly one author — seam-runtime's emitter —
  because `sdk-digest-parity` byte-diffs the whole file, and that adding this repo's five extra
  cases to it would therefore turn seam-runtime's CI red for a reason that is not drift.
- **Chose:** take the runtime's bytes verbatim, and put the five extra cases in
  `conformance/record_digest_v3_extended.json`, loaded alongside by all three SDK conformance suites.
  Strongest option because it keeps coverage the shared file cannot carry (`mode: ""` vs
  `mode: null`; decomposed non-ASCII) without either side losing byte-identity, and because adopting
  those cases upstream later is then a copy rather than a re-render — the extended file uses the same
  `indent=2` / `ensure_ascii=True` rendering.
- **Alternatives:** (a) push this repo's `cases`-array shape upstream — rejected: reopens a landed
  runtime PR to make the file cosmetically different and no more correct, and the array shape was the
  outlier among that file's blocks; (b) drop the five cases — rejected: they are the only vectors
  covering the two traps the spec singles out; (c) keep them as unit tests only — rejected: they are
  cross-language contracts, and a unit test in one language cannot pin a distinction a TS or Rust
  transcription is liable to collapse.
- **Blast radius if wrong:** low and local. If seam-runtime adopts the cases, the extended file is
  deleted and its cases move into the shared one; nothing else changes. If it declines, the file
  stays and the SDK keeps coverage the runtime does not. Neither outcome touches the wire, the
  formula, or any published digest.
- **Status:** CONFIRMED (2026-08-24) — see `DECISIONS.md`, "reconcile `plans/record-digest-v3.md`'s ASSUMPTIONS.md (4 entries)". — proposed to seam-runtime; their call.

## A tag-10 strip stays `False`, while a tag-11/12 strip raises
- **Plan:** `plans/archive/record-digest-v3.md` (Phase 6a/6b)
- **Assumed:** the spec's per-tag table (`seam-event.v1.md` §"Presence on the wire") saying a tag-10
  strip on `schema_version >= 2` must **refuse** means the same thing our helper's `False` already
  means — a failing verdict — and not that it must become an exception.
- **Chose:** kept tag 10's long-standing boolean and gave only tags 11/12 the typed raise. The
  distinct-reporting requirement ("reported distinctly from a digest mismatch") is attached in the
  spec to 11/12 and to nothing else; §Ordering & integrity Verification (c), which the table cites,
  is written for the chain verifier, where REFUSE is a *fail* verdict rather than an error channel.
  A boolean helper answering "does this verify?" expresses that fail as `False`.
- **Alternatives:** raising on a tag-10 strip too. Rejected because it would change shipped v2
  behaviour, which the standing "`record_digest_v2` must stay byte-identical forever" constraint
  covers behaviourally as well as byte-wise, and because it would invent a distinctness the spec
  does not ask for.
- **Blast radius if wrong:** a v3 record stripped of tag 10 reports `False` where an operator might
  have wanted a raise. The record fails either way, so no record verifies that should not — the cost
  is diagnostic richness, not integrity. Reversible in one line.
- **Status:** CONFIRMED (2026-08-25, /reconcile — see DECISIONS.md)

## The runtime accepts an `AuthorizeRequest.tool_input` whose canonical bytes were derived by the caller
- **Plan:** `plans/archive/authorize-single-canonicalization.md` (Phase 4, issue #60)
- **Assumed:** the runtime re-derives `tool_input_digest` from the `tool_input` bytes it receives and
  compares it to the digest on the request, but does **not** independently assert that those bytes
  are canonical JCS.
- **Chose:** `authorize(canonical=…)` accepts the caller's bytes without re-canonicalizing them.
  Re-deriving to validate would reinstate the second derivation the parameter exists to remove, so
  there is no version of this feature that also checks its input.
- **Alternatives:** re-canonicalize and compare (self-defeating — that IS the second derivation);
  refuse to add the parameter at all and leave every consumer to reimplement the `seam-adapters`
  normalization workaround (rejected: the workaround is what #60 asked us to make unnecessary).
- **Blast radius if wrong:** if the runtime *does* validate canonicality, a caller passing
  non-canonical bytes gets a clean server-side rejection rather than silent acceptance — which is a
  better outcome than the one assumed here, not a worse one. The genuinely unbounded case is the
  reverse: the runtime accepts them and an advisory audit row carries bytes a third-party auditor
  cannot re-derive the digest from. Not reversible after the fact for rows already written.
  **Cannot be answered from this repo** — answering it needs the runtime's **Rust**, and the
  clean-room constraint is that this repo's crypto/digest implementations are written from the
  published spec and never from that Rust. (The constraint targets the implementation, not the
  contract: `../seam-runtime/crates/seam-api/proto/**` *is* read — `Makefile:29`'s `generate-local`
  runs `buf generate ../seam-runtime` against exactly that path. An earlier wording of this line
  said `crates/**` was unreadable outright, which forbade the proto and contradicted the build.)
  Filed as a question upstream.
- **Owner / re-open trigger:** whoever next changes `AuthorizeRequest` handling in `seam-runtime`,
  or the first consumer to report an `authorize(canonical=…)` call refused for a reason other than
  policy. Added 2026-09-04 — this entry had no trigger, which is how an assumption becomes scenery.
- **Status:** UNCONFIRMED (reviewed 2026-09-04, unchanged). A claim about runtime acceptance
  behaviour that only the runtime can settle; nothing this cycle exercised it.

## The runtime's JCS renders an integer ≥ `10**21` the way ES6 does
- **Plan:** `plans/archive/authorize-single-canonicalization.md` (Phase 3, issue #60)
- **Assumed:** unknown, and deliberately not relied on.
- **Chose:** refuse the whole range. The committed predicate — accept an integer iff JCS renders it
  as itself — refuses everything at or above `10**21` for free, because a plain decimal form can
  never equal an exponential rendering. So the SDK never emits a byte string in that range that the
  float arm could not already have emitted, and the question does not gate anything.
- **Alternatives:** accept exactly-representable integers ≥ `10**21` and emit `1e+21` (correct per
  RFC 8785, but it is the one range where a naive integer-preserving runtime could disagree, and
  guessing there is a signed-digest interop break); ask upstream first and block on the answer
  (rejected — it blocks a fix for a live defect on a question that changes nothing today).
- **Blast radius if wrong:** none today. Being wrong means only that the SDK is stricter than it
  needs to be for values essentially nobody sends. Widening later is additive; the reverse would not
  be. Filed as a question upstream.
- **Owner / re-open trigger:** the first caller to canonicalize a tool input containing an integer
  at or above `10**21`. Until one exists this cannot be settled and does not need to be. Added
  2026-09-04 — this entry had no trigger.
- **Status:** UNCONFIRMED (reviewed 2026-09-04, unchanged). Deliberately not relied on; settling it
  needs the runtime's JCS, not this repo's.

## The field manifest spells an entry `<Message>/<field_name>`, names only

- **Plan:** `plans/post-adoption-hardening-and-acdp-readiness.md` (Phase 5)
- **Logged retroactively at reconcile time.** The plan's Open questions named this as an entry
  `/implement` should write while implementing the phase, and it did not. Recording the miss rather
  than back-dating it: an assumptions log that only contains the assumptions someone remembered is
  the same defect as a citation that only looks checked.
- **Assumed:** that the manifest should declare **names**, not types, tag numbers, cardinality or
  `optional`-ness — and that `<Message>/<field_name>` (message unqualified, field lowercased) is the
  right spelling for both extractors to agree on.
- **Chose:** names only. A tag number would be strictly more information, but the manifest is
  extracted from two independently generated stub sets and the two languages do not agree on how to
  render a type; names are the largest surface both can produce identically. The lowercasing is
  forced rather than chosen: protoc emits `MYFIELD_FIELD_NUMBER` for a `myField` proto field, so the
  Python side can only ever produce `myfield`, and the TS side must fold to match.
- **Alternatives:** include tag numbers (catches a *renumbering*, which names miss — but no extractor
  can read them from the `.pyi` without parsing the value, and a renumber is already a breaking
  change `buf breaking` catches); include types (the two languages disagree on spelling, so it
  would produce a permanently red gate the documented escape cannot clear).
- **Blast radius if wrong:** low and reversible. The gate would miss a same-name field changing type
  or tag — both of which `buf breaking` catches at the contract, which is where they originate. The
  header states the limit explicitly under "WHAT THIS FILE DOES **NOT** CHECK", so a reader is not
  left to infer coverage the file does not have. Changing the spelling is one extractor edit plus
  `--write-manifest`.
- **Status:** CONFIRMED (2026-08-31). Held in practice across the phase: both extractors agreed at
  223 on local stubs and at 228 in CI with zero diff in either direction, and the two keyword-named
  fields (`ResumeRequest/raise`, `AdminResumeRequest/raise`) — the case that breaks a `__slots__`
  reading — are declared and matched under this spelling.

## Phase 8 converts the vendored citation rather than grandfathering it

- **Plan:** `plans/post-adoption-hardening-and-acdp-readiness.md` (Phase 8, issue #73)
- **Logged retroactively at reconcile time**, same miss as the entry above.
- **Assumed:** that converting the one pre-existing `ANCHORED` citation into the vendored spec was
  better than grandfathering it with a `#73` comment. The phase permitted either explicitly.
- **Chose:** convert — though the reason recorded at the time was **wrong**, and is corrected here
  rather than restated. It read "Phase 9's regeneration half refreshes that same vendored file";
  measured afterwards, the last refresh (`c7331b6`, PR #80) preceded Phase 8 by about two hours and
  the regeneration commit never touched the file. The decision holds on the durable reason instead:
  the copy is refreshed whole-file on upstream's cadence, so the *next* refresh drifts any line
  anchor into it, whenever that is.
- **Alternatives:** grandfather with a comment (cheaper, and leaves the drift to fire once more);
  convert every `ANCHORED` entry to needle-based (a larger change with its own risk, explicitly out
  of scope, and wrong for files this repo edits itself, where a drifting line number is real signal).
- **Blast radius if wrong:** low. Converting drops the line-position assertion for one claim and
  replaces it with three line-number-free ones. If the trade proves wrong, `ANCHORED` still exists
  and re-adding an entry is a one-line change.
- **Status:** CONFIRMED (2026-08-31; evidence upgraded 2026-09-05 — the prediction was TESTED and
  held). Phase 8 refreshed the vendored spec whole-file to `ac325d7`: 69 insertions, 5 deletions,
  so every line number below the first insertion moved. Nothing broke, because the citation had
  been converted rather than grandfathered — the exact case the two alternatives differ on. The
  original wording is kept below because how a status was reached matters as much as the status.
  Recorded as **on the durable reason, not on in-run evidence**: An earlier
  version of this line claimed the choice was "vindicated within the same run" because the converted
  citation did not move while the `CHANGELOG.md` one drifted. That is vacuous: the converted citation
  did not move because nothing refreshed the vendored file, and a *grandfathered* anchor would
  equally not have moved. The `CHANGELOG.md` comparison is a different file with a different cause,
  which this very rule says it does not reach. **The choice is not yet exercised**; the first upstream
  refresh after this will be the test. See `DECISIONS.md`, "Citations into vendored files are quoted,
  never line-anchored".

## Cloudsmith quarantine is not wanted for the 0.7.39-0.7.43 band
- **Plan:** `plans/post-adoption-hardening-and-acdp-readiness.md` (Phase 10, issue #52)
- **Assumed:** that nobody wants installs of the band *blocked* — only documented. Issue #52
  recommended yanking; Phase 10 decided to document instead, and quarantine is the reversible
  middle path between the two (Cloudsmith blocks download while retaining the artifact).
- **Chose:** do nothing beyond documenting. Quarantine costs a working consumer exactly what
  deletion costs them — their next install fails — while buying back only reversibility, and the
  no-yank reasoning in `DECISIONS.md` turns on the harm to that consumer rather than on whether
  the act can be undone.
- **Alternatives:** quarantine the five versions (blocks the affected *and* the unaffected, but is
  reversible); yank as #52 asked (same harm, permanent); do nothing at all and skip the row
  (rejected outright — nothing was yanked, so the document is the only barrier).
- **Blast radius if wrong:** low and reversible in the direction that matters. If blocking installs
  turns out to be wanted, quarantine is still available and `yank.yml` now actually authenticates.
  Being wrong the other way — quarantining when it was not wanted — breaks builds that work today
  and cannot be undone for anyone whose CI ran in the interim.
- **Owner / re-open trigger:** whoever holds a Cloudsmith credential, on issue #43, where both
  known-bad bands are consolidated for one decision. Added 2026-09-04 — this entry had no trigger.
- **Status:** UNCONFIRMED (reviewed 2026-09-04, unchanged) — this is the one option worth raising
  rather than settling unilaterally, per the phase's own Rejected-alternatives note. Consolidated
  onto issue #43 on 2026-09-02 so both known-bad bands get one answer instead of two; still awaiting
  a human with a Cloudsmith credential. Re-verified this cycle that nothing can quietly create a
  third band while the decision waits: `publish.yml` resolves every `ci-ok` check run for the
  release SHA through the check-runs API and treats an absent conclusion as a refusal, so today's
  red `main` blocks publication rather than repeating the 0.7.39-0.7.43 pattern.

## The enum manifest carries names only, not numeric tags

- **Plan:** `plans/gate-blindness-hardening.md`, Open Question 1
- **Logged retroactively**, same miss `plans/post-adoption-hardening-and-acdp-readiness.md`'s Phase
  8/10 entries above were: the plan's own Open Questions section said this was "recorded as a
  deliberate scope line in the manifest header, and as an `UNCONFIRMED` assumption" — neither half
  happened. `git diff b064e07..HEAD -- ASSUMPTIONS.md` was empty before this entry, and
  `contract/field-manifest.txt`'s header has no such line (verified by reading it; not edited here —
  this manifest is generated from the stubs by `--write-manifest` and is off-limits to hand-edit).
  The plan's own Open Q1 wording is corrected in the same change that adds this entry.
- **Assumed:** the enum section of `contract/field-manifest.txt` only needs to catch a VALUE being
  added or removed — not a value keeping its name but changing its underlying protobuf tag.
- **Chose:** `<Enum>#<VALUE>` (name only, no tag number). The tag is what `buf breaking` already
  protects upstream at the proto source; duplicating it here would create a second copy that must be
  kept in sync on every regeneration, for a case the BSR module's own breaking-change gate already
  covers.
- **Alternatives:** `<Enum>#<VALUE>=<tag>` — would also catch a value silently renumbered without
  its name changing (a real gap this SDK cannot itself detect today), at the cost of a manifest line
  that changes shape on every proto-side renumber, not just on an added/removed value.
- **Blast radius if wrong:** low, but not zero — a renumbered enum value with the same name would
  pass this SDK's own gate silently (the name-only comparison sees no change) and rely entirely on
  `buf breaking` catching it upstream, before the SDK ever regenerates against it. If that upstream
  gate is ever bypassed or misses this case, wire protocol values could shift underneath a client
  that never noticed.
- **Owner / re-open trigger:** whoever next adds or reviews `buf breaking` config for
  `seam.api.v1`'s enums (in `seam-runtime`) — if that gate is ever found not to cover a same-name
  renumber, this assumption needs revisiting before the next enum-touching regeneration lands.
- **Status:** CONFIRMED (2026-09-04) — **on measured behaviour, not on the config's name.** The
  re-open trigger ("whoever next reviews `buf breaking` config for `seam.api.v1`'s enums") came due
  this cycle and was worked rather than deferred. `../seam-runtime/buf.yaml:23-25` sets
  `breaking: use: [WIRE_JSON]`, and `../seam-runtime/.github/workflows/ci.yml:173-181` runs
  `buf breaking --against` a materialised `main`. Reading that config is not evidence that it covers
  the case, so both forms of the gap were executed against `buf` 1.66.0 rather than reasoned about:
  - a **renumber** (name kept, tag 1 -> 3) is refused twice, for the deleted *name* and the deleted
    *number*;
  - a **swap** (`FOO_A`/`FOO_B` exchange tags, so no name and no number is deleted — the form that
    defeats a delete-only rule) is refused as `Enum value "2" ... changed name from "FOO_B" to
    "FOO_A"`.
  So the name<->number binding is protected in both directions, and the entry's "if that upstream
  gate ... misses this case" clause is now measured false rather than merely hoped against.
  **The residual risk is narrower and worth stating precisely:** that step carries
  `if: github.ref != 'refs/heads/main'`, so it compares PR heads only. A change reaching `main`
  without a PR is never compared, and the same push publishes the BSR module this SDK generates
  from. That is a bypass question about the runtime's branch protection, not a coverage question
  about `WIRE_JSON` — a different risk from the one this entry logged, and out of this repo's
  reach. See DECISIONS.md.

## `plans/` stays outside the citation guard; `PROGRESS.md` does not

- **Plan:** `plans/gate-blindness-hardening.md`, Open Question 2
- **Logged retroactively**, same miss as the entry above — the plan said this was "logged as an
  assumption so the distinction is explicit rather than incidental," and it was not, until now.
- **Assumed:** a historical plan document and a live, resumed-run-facing document need different
  citation rules, even though both live under `plans/`-adjacent tooling and both carry `file:line`
  citations.
- **Chose:** `python/tests/test_compatibility_citations_resolve.py`'s `DOCS` covers
  `COMPATIBILITY.md`, `DECISIONS.md` and `PROGRESS.md`, never anything under `plans/`. A plan
  document records what was true when it was written; forcing its citations to keep resolving
  against current code would either freeze the code those citations touch or falsify the historical
  record by silently repointing it. `PROGRESS.md` is different in kind, not degree: it is what
  `/implement` reads *instead of re-scanning the repo* on a resumed run, so a stale anchor there
  misdirects the next run's actions rather than merely misleading a reader.
- **Alternatives:** guard `plans/` too, exempting only closed/archived plans — rejected as needing a
  closed/open distinction the tooling does not otherwise track, for a document class this repo
  already treats as append-only history (`plans/archive/`).
- **Blast radius if wrong:** low. If a still-open, actively-executing plan's citations are found to
  rot in a way that matters (misdirecting execution the same way a stale `PROGRESS.md` anchor
  would), the fix is adding one entry to `DOCS` — the guard's shape already supports it.
- **Owner / re-open trigger:** whoever next finds a citation drift inside an OPEN (not archived) plan
  document causing a real misdirection during `/implement` — that would be evidence the open/archived
  line, not the `plans/`-vs-`PROGRESS.md` line, is where this guard should actually cut.
- **Status:** UNCONFIRMED (reviewed 2026-09-04, unchanged). Phase 5's verification round found three
  stale line references inside `PROGRESS.md` that the guard could not see — but they were **bare**
  `:NNN` refs carrying no path, and `test_compatibility_citations_resolve.py` matches backticked
  `file:line`, so a pathless number is invisible in *every* guarded document, `PROGRESS.md`
  included. That is a different gap in the same guard, orthogonal to where the `plans/` line cuts,
  and it does not move this assumption. It was closed at the source instead: those three refs now
  name what they point at rather than where it sits. See DECISIONS.md.

## `contract/expected-local-lag.txt` is a window, not a permanent excuse

- **Plan:** `plans/gate-blindness-hardening.md`, Open Question 3
- **Logged retroactively**, same miss as the two entries above — the plan said this was "Logged
  `UNCONFIRMED` with a re-open trigger," and until now the trigger existed only in the plan text,
  nowhere this file's own reconcile process would surface it.
- **Assumed:** the five-field gap between the committed field manifest and a freshly regenerated
  local stub tree is temporary — it closes once the runtime's ACDP BSR module republishes the
  `ContextBinding` receipt-slot and `retraction` fields — not a standing feature of local
  development.
- **Chose:** record the known gap in `contract/expected-local-lag.txt` (with an `EXPECTED-FROM` date
  stamp and an age printed on every match) so `check-contract.sh` can downgrade the refusal to a
  short NOTE for exactly this recorded set, while CI — which always regenerates fresh from the BSR —
  stays the sole authority and still exits 6 regardless. `--write-manifest` deletes the file on
  every rewrite, so a stale recorded lag cannot silently outlive the manifest state it described.
- **Alternatives:** do not record the lag at all (every local `check-contract` run reads as a full,
  undowngraded regression, training developers to stop reading the refusal text carefully); make the
  downgrade permanent/unconditional for these five fields (would hide a REAL future regression that
  happened to touch the same five field names).
- **Blast radius if wrong:** low structurally (worst case is a NOTE where a plain pass would do), but
  the honest failure mode is social, not technical: if the BSR republish never lands, the file
  becomes permanent scenery nobody looks at twice, and the NOTE's "not a new regression" framing
  stops being true without anyone deciding that on purpose.
- **Owner / re-open trigger:** whoever is running `/implement` or reviewing this repo's contract gate
  60 days from `EXPECTED-FROM` (see the file's own header) — if `contract/expected-local-lag.txt` is
  still present and its five fields still match the local/BSR gap at that point, the split recorded
  here is not a window and this assumption needs to be revisited, per the plan's own Open Q3 text.
- **Status:** UNCONFIRMED (reviewed 2026-09-04, and the window this entry names has started to
  close on its own). `EXPECTED-FROM` is 2026-08-31, so the 60-day trigger is still far off — but the
  *contents* are no longer merely stale, they are now actively wrong in CI: seam-runtime merged its
  ACDP P3 key-revocation work and pushed the BSR, so a CI regeneration emits two `ContextBinding`
  fields (tags 12-13) the manifest does not declare. Note the direction, because an earlier
  wording here had it backwards: CI fails on the gate's NOT-IN-THE-MANIFEST branch — a two-field
  **surplus** — and never consults this file at all. Seven is the local-stub-vs-BSR delta, and it
  becomes a recorded *gap* only once tags 12-13 are declared. Local checkouts still show exactly
  the recorded five, so this repo stays green while `main` does not — and the file's own NOTE now
  teaches a **wrong cause** on every local run: it explains the lag as "a BSR module that has not
  yet republished these", when the BSR has republished and gone two fields further. The local
  stubs are simply old. Re-recording it is Phase 8's, not a hand-edit here — which is exactly the divergence the entry warned the window would
  produce. Resolving it needs the BSR regeneration credentials this workstation lacks, so the entry
  stays open and the fix stays interlocked with Phase 8. Recorded rather than papered over.
  This cycle also produced the first hard evidence for the **social** failure mode this entry names
  rather than the technical one: the NOTE's own closing sentence claimed "so this STILL exits 6
  below" unconditionally, which is false whenever the event surface also disagrees, and it survived
  a full phase plus four verification rounds precisely because that block is the one every local run
  prints and nobody re-reads. Fixed (the sentence is now conditional, with both branches pinned by
  tests), but the mechanism it demonstrates is the one to watch at day 60. See DECISIONS.md.

## `seam.event.v1` gets its own manifest file, not a partition of the api one

- **Plan:** `plans/consumer-decoders-and-event-surface.md`, Phase 5
- **Assumed:** the two contract surfaces this SDK generates from are better served by two manifest
  files with two exit codes than by one file with a third partition — even though everything else in
  the field gate (extractors, comparison, write escape) is shared.
- **Chose:** `contract/event-field-manifest.txt`, exit 8, precedence over exit 6. The decisive reason
  is mechanical rather than aesthetic: `manifest_fields`' stripper is a NEGATIVE filter,
  "everything that is not an enum line", so a third partition is unreachable *whatever* delimiter it
  picks — `%`, `@` and `!` are all free in a proto identifier and all still land in its set. Sharing
  the file means rewriting the api gate's filter for the event gate's benefit. Second reason:
  `--write-manifest` deletes `contract/expected-local-lag.txt` on every api field write, and the api
  surface has a recorded lag while the event surface has none.
- **Alternatives:** one file with a `seam.event.v1/` line prefix (still `#`-free, so
  `manifest_fields` still claims it — trades a file boundary for a convention the stripper cannot
  see); reuse exit 6 (makes a real event regression indistinguishable at the exit status from the
  recorded api lag that CI and `CLAUDE.md` both say to read past).
- **Blast radius if wrong:** low and cheap to reverse. Merging the two files later is a stripper
  rewrite plus a manifest concatenation; nothing outside `scripts/check-contract.sh` and its two test
  files reads either manifest.
- **Owner / re-open trigger:** whoever next needs an ENUM partition on the event side. That is the
  moment the "no enums" precondition is deliberately retired, and it is also the moment the
  one-file-with-two-partitions question is worth re-asking, since the event file would then need the
  same negative-filter problem solved anyway.
- **Status:** CONFIRMED (2026-09-01). The decisive mechanical reason was independently re-derived
  during Phase 5's verification round, and it came back **stronger** than this entry claimed:
  `manifest_event_fields` deliberately omits the second `grep -v '#'` that `manifest_fields` needs,
  and a `#`-bearing field line is therefore reported MISSING (exit 8) on the event side where the
  api stripper would silently DROP it — measured, 90 against 91. The shared-file alternative would
  have inherited that silent drop for the event surface. Exit 8's precedence over 6 was also
  reproduced end-to-end, including against the real recorded lag. See DECISIONS.md.

## `PolicyEnforcement` and `CollectiveOutcome` stay off `ts/src/index.ts`'s named export list

- **Plan:** `plans/consumer-decoders-and-event-surface.md`, Open question 1
- **Assumed:** consumers reach the decoded DTO types through inference from
  `policyEnforcementOf`/`collectiveOutcomeOf`'s return types and reach the generated schemas through
  `pb.`, so neither hand-written DTO type needs promoting to a root named export.
- **Chose:** leave both off. Phase 4 did not need them there — `ts/tests/policy_enforcement.test.ts`
  imports `PolicyEnforcementSchema` straight from the generated module, exactly as
  `collective_outcome.test.ts` does — and the public surface is easier to widen later than to narrow.
- **Alternatives:** add both to the named type list now. Rejected as an unforced public-surface
  decision, and it carries a hazard that runs OPPOSITE to the intuition: both names are also declared
  by the generated module, so adding the *generated* name to the explicit list makes the generated
  type win the root name and silently displace the hand-written DTO. Proven — `tsc --noEmit` exits 0
  and a `$typeName` probe compiles. The dual-declaration comment at `ts/src/index.ts:18` records it.
- **Blast radius if wrong:** low. Adding a named export later is additive; removing one is breaking.
  The failure mode of the current choice is ergonomic (a consumer writes `ReturnType<typeof …>`),
  not correctness.
- **Owner / re-open trigger:** whoever next has a consumer that genuinely cannot name the type — or
  the next time a third decoder of this shape lands, since three is when a pattern is worth exporting
  deliberately rather than case by case.
- **Status:** UNCONFIRMED (reviewed 2026-09-04, unchanged). Phase 4 shipped and merged (#93) without
  either type reaching the named export list and without a consumer needing it; the count of
  decoders of this shape is still two, not three. Nothing this cycle tested the assumption, which is
  the correct outcome for one whose evidence can only come from a consumer. See DECISIONS.md.

## `policy_enforcement_of`'s presence enumeration is orientation, not contract

- **Plan:** `plans/consumer-decoders-and-event-surface.md`, Phase 3 / Open question 2
- **Assumed:** the three sites that carry `policy_enforcement` on a `SessionStep` (commit-terminal,
  sealed-idempotent replay, pending-commitment seal retry) are stable enough to document, and the
  runtime will not quietly add a fourth.
- **Chose:** enumerate the three rather than state a general rule, and say in the docstring that the
  list describes the runtime as measured rather than a guarantee to branch on. Every short general
  rule anyone has written for this field has been wrong, including both in the proto's own comment
  and one in the issue that measured them.
- **Alternatives:** state a rule ("populated on any step that reports a seal") — self-contradictory,
  since the expiry seal reports a seal and carries no `policy_enforcement`. Or say nothing — leaves a
  reader to infer presence from `decision_id`, which the proto comment's analogy actively encourages
  and which is exactly backwards.
- **Blast radius if wrong:** low for correctness (`None` is returned either way and the decoder does
  not branch on the list), medium for trust: a docstring that enumerates and is wrong is worse than
  one that declines to enumerate.
- **Owner / re-open trigger:** seam-runtime#526. If `freshly_sealed` lands — a client currently
  cannot tell whether *this* call performed the seal or re-reported one — this docstring is the first
  thing that goes stale.
- **Status:** UNCONFIRMED (reviewed 2026-09-04, deferred — not answerable here). The enumeration is a
  claim about runtime behaviour, and the only evidence that could settle it is seam-runtime#526's
  matrix, which is why the docstring cites the issue rather than a line of code. Nothing in this repo
  can promote it, and the docstring already says the list is orientation rather than a guarantee to
  branch on — so the cost of it being wrong stays bounded to trust, as the entry records. Stays open
  against #526. See DECISIONS.md.


## Appending a new workstream to `PROGRESS.md` rather than starting a fresh one

- **Plan:** `plans/digest-correctness-and-gate-repair.md`, Phase 1 / Open question 6
- **Assumed:** `PROGRESS.md` can carry a fourth workstream section appended at the bottom without a
  reader mistaking the earlier three for current state.
- **Chose:** append. A fresh `PROGRESS.md` was written first and turned **25 guard tests red** at
  once: `python/tests/test_compatibility_citations_resolve.py` binds 44 anchored claims and 39
  quoted line-bindings
  plus a 30-citation floor to this document's *content*, and the document cites itself by line in
  three places, at least two of which are live and accurate. Replacing it destroys the evidence those
  assertions are made of. The appended section opens by saying so, so the next person meets the
  constraint before they meet the temptation.
- **Alternatives:** (a) a fresh `PROGRESS.md` with the old one moved to `progress/archive/` — clean
  to read, but every anchored claim would need re-pointing at a path that is no longer the one the
  guard scans, and the self-citations would have to be recomputed by hand. (b) Relax the guard to
  span both files — widens the blast radius of the mechanism that has caught four real drifts this
  workstream alone, to buy tidiness. (c) Lower the citation floor — removes the ratchet's whole point.
- **Blast radius if wrong:** low and slow. The file grows monotonically (2123 → ~2310 lines this
  phase) and eventually someone reads a stale workstream as current. It costs a confused reader, not
  a bad publish. The failure mode of the alternative is a guard that no longer guards.
- **Owner / re-open trigger:** the next workstream after this one. If a fifth section is needed, that
  is the point to solve it properly rather than append a fourth time — likely by teaching the guard
  to scan a directory rather than a file, so archiving stops costing 25 assertions.
- **Status:** UNCONFIRMED (reviewed 2026-09-04, unchanged — and now with evidence that the question
  is real rather than theoretical). Deliberately not solved under run pressure. Phases 4-7 appended
  to the same `PROGRESS.md` workstream and the citation guard held throughout, but only because
  every phase re-measured its own citations after formatting; two citations in this run pointed at
  the wrong target while still *resolving*, which a remap cannot detect and only anchoring caught.
  That is the cost this entry predicted, paid once per phase, and it is still unamortised.

## Refusing duck-typed integers (`numpy.int64`, `gmpy2.mpz`) in the Python digest slots

- **Plan:** `plans/digest-correctness-and-gate-repair.md`, Phase 2 (found by verification, not planned)
- **Assumed:** no caller passes a non-`int` integer type — one implementing `__index__` without
  subclassing `int` — to `record_digest_v2`, `record_digest_v3` or `verify_chain_head_attestation`.
- **Chose:** `isinstance(value, int)` in the shared `_uint_slot`, which refuses `numpy.int64` and
  `gmpy2.mpz` where they previously produced a digest. This is the rule `record_digest_v3` has
  enforced since it was written; the alternative would have made v2 and the attestation verifier
  *more* permissive than v3, which is a new asymmetry in a phase about closing them.
- **Alternatives:** accept anything with `__index__` (excluding `bool` explicitly, since
  `True.__index__()` is `1`). Strictly more permissive and restores the pre-phase behaviour for
  numeric-stack callers — but it would then need applying to v3 too, widening a validator that has
  been narrow and uncontested for its whole life, to serve a caller nobody has reported.
- **Blast radius if wrong:** a caller doing `record_digest_v2(sealed_at=np.int64(...))` gets a
  `TypeError` where they previously got a correct digest. Loud, at the first record, with a message
  naming the type — not a silent wrong answer. `enum.IntEnum` and ordinary `int` subclasses are
  unaffected. Protobuf `uint64`/`uint32` fields return `type(v) is int` under both the `upb` and
  pure-Python implementations, verified end-to-end, so the SDK's own decode path is clear.
- **Owner / re-open trigger:** the first report of a `TypeError` from a numeric-stack caller. The
  fix is one `hasattr(value, "__index__")` in `_uint_slot`, applied to all three framings at once.
- **Status:** UNCONFIRMED (reviewed 2026-09-04, unchanged). The assumption is about callers outside
  this repo, which nothing here can settle; it is recorded so the trigger is recognisable rather
  than debugged from scratch. No such caller has surfaced.

## `toJSON` is not honoured by `jcsCanonicalize`

- **Plan:** `plans/digest-correctness-and-gate-repair.md`, Phase 3
- **Assumed:** no caller relies on `toJSON()` being called during canonicalization. An object
  carrying one raises today (the walk reaches the function value and refuses it), and this phase's
  plain-object guard does not change that — it was checked, not inherited by accident.
- **Chose:** keep refusing. `JSON.stringify` would call `toJSON`, so this is a deliberate divergence
  from the function JCS is usually explained in terms of. The reason is that honouring it makes the
  canonical bytes depend on a method the digest cannot see: a `toJSON` that changed between releases
  would silently change a signed digest, in TypeScript only, since Python has no equivalent hook.
- **Alternatives:** call `toJSON()` before the type test, matching `JSON.stringify`. Friendlier for
  callers with domain objects, and the natural expectation for anyone who has used `stringify`. It
  loses the cross-language property that both SDKs agree on which inputs have a digest at all — the
  property §9 and §10 of `COMPATIBILITY.md` exist to defend — so it was not taken to be convenient.
- **Blast radius if wrong:** a caller with `toJSON` on a request object gets a `TypeError` instead of
  a digest. Loud and at the first call, not a silent wrong answer. They convert explicitly at the
  boundary, which is the same fix the `Date` case asks for.
- **Owner / re-open trigger:** the first report of a caller whose request objects carry `toJSON`. If
  it is taken up, it must be taken up in Python too — as an explicit protocol, not a JS-only hook —
  or the divergence it creates is worse than the inconvenience it removes.
- **Status:** UNCONFIRMED (reviewed 2026-09-04, unchanged). About callers outside this repo, which
  nothing here can settle. No consumer has reported a `toJSON`-bearing value reaching
  `jcsCanonicalize`.

## `engines.node` is `>=20` because that is what CI verifies, not because 20 is the true floor

- **Plan:** `plans/digest-correctness-and-gate-repair.md`, Phase 3
- **Assumed:** Node 20 is the oldest runtime this SDK should claim. It is the version all four
  workflow jobs pin, so it is the oldest one anything has actually been proven on.
- **Chose:** `">=20"`, with `python/tests/test_node_engines_floor.py` binding it to the CI pins so
  the two cannot drift apart. The real floor is probably lower — nothing in `ts/src/` obviously needs
  20 — but "probably lower" is not a number to publish in a manifest consumers install against.
- **Alternatives:** derive the true floor by testing on 18 and 16 in CI. That is the correct answer
  and it costs two more CI legs on every PR, for a runtime nobody has asked for. Declaring `>=18`
  without a leg to prove it would be exactly the unverified-number defect this test exists to stop.
- **Blast radius if wrong:** a consumer on Node 18 gets an `npm` engine warning (or an error under
  `engine-strict`) for a runtime that might have worked. Visible at install time, not at verify time,
  which is the direction that matters here.
- **Owner / re-open trigger:** the first consumer who needs Node 18. The fix is a CI leg on 18 and
  then lowering the floor — in that order, never the reverse.
- **Status:** UNCONFIRMED (reviewed 2026-09-04, unchanged). Deliberately conservative; the floor is
  a claim about what was tested. No Node leg was added or removed this cycle, so the evidence behind
  `>=20` is exactly what it was when the entry was written.

## Java and Kotlin implement the `exp` rule but do not yet read the shared vector

- **Plan:** `plans/digest-correctness-and-gate-repair.md`, Phase 3
- **Assumed:** `SeamCrypto.java` and `SeamCrypto.kt` genuinely implement the normative `exp` rule.
  This is read from the source (`instanceof Number` + `longValue()`; `as? Number` + `toLong()`) and
  is the reason Go's rule was adopted as the 3-of-5 majority — but it is **read, not measured.**
- **Chose:** ship the vector with Go, Python and TypeScript consumers, and leave Java and Kotlin as
  follow-up. This workstation has no JDK, so a consumer written for them could not be executed before
  being committed. CI does run `./gradlew test`, so it would have been verified there — but writing
  an unrunnable test and letting CI be its first execution is how a vacuous test lands, and this run
  has already spent four verification rounds on exactly that failure mode.
- **Alternatives:** write both consumers blind and let CI adjudicate. Faster, and probably fine —
  they are short JSON-reading tests against implementations already believed correct. Rejected
  because "probably fine, CI will tell us" is the reasoning that produced the placeholder-AID test in
  Phase 2, which passed while asserting nothing.
- **Blast radius if wrong:** if Java or Kotlin in fact diverges, the vector says three languages agree
  and implies five. The claim is scoped in the vector's own header and in `COMPATIBILITY.md` §10 to
  the three that read it, so the document does not overstate what is checked.
- **Owner / re-open trigger:** the next session with a JDK available, or the next change to either
  file's `exp` handling. The work is ~40 lines per language, mirroring
  `go/crypto/tct_exp_vector_test.go`.
- **Status:** UNCONFIRMED (reviewed 2026-09-04, unchanged). Not a design question — an unrun test,
  recorded as such rather than written blind. Still unrun: the JVM legs need a JDK 17 this
  workstation does not have, so the shared vector remains read by Python/TS/Go/Rust only.

## `contract/rpc-manifest.txt` covers one package, and Phase 5 shipped a tripwire rather than extending it

- **Assumed:** `seam.event.v1` declares zero services today. This is **measured**, not assumed —
  `python/seam_sdk/_gen/seam/event/v1/seam_event_pb2_grpc.py` is a 159-byte scaffold with no service
  block, and a test asserts it against the real committed stub rather than the fixture's copy.
- **Chose:** refuse a non-empty event verb surface with exit 7 (structural precondition), instead of
  extending `contract/rpc-manifest.txt` to a second package. The manifest's entries are bare
  `Service/Method` names with no package qualifier, so covering two packages needs a format decision:
  package-qualify every line in one file, or add a second file. Both are defensible and the choice
  changes `--write-manifest`, `manifest_rpcs`, and every existing line.
- **Alternatives:** pick a format now and extend the manifest. Rejected because the manifest would
  have zero event entries, so the format would be chosen against an empty set and discovered wrong by
  the first real verb — and because a tripwire converts "a verb arrived unnoticed" from silent to
  loud, which is the whole failure mode, without committing to a shape.
- **Blast radius if wrong:** if a verb lands on `seam.event.v1`, CI goes red with exit 7 and a message
  naming the verb and the decision to make. That is the intended behaviour, not a defect — but it
  *will* block the branch that lands it until the format decision is made, so whoever lands the first
  event RPC pays for this deferral in the same PR.
- **Owner / re-open trigger:** the first `seam.event.v1` service. The gate's own message states the
  decision and the two candidate shapes.
- **Status:** UNCONFIRMED as a design choice (reviewed 2026-09-04, unchanged) — deliberately
  deferred, with the trigger wired to fire loudly rather than left to be noticed. The tripwire
  shipped this cycle and has never fired: `seam.api.v1` is still the only package the RPC manifest
  covers, and the event surface reached by `assert_event_surface_preconditions` declares **no**
  services and has no manifest of its own. Nothing has yet asked for the second package that would settle it.
