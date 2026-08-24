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
- **Status:** UNCONFIRMED

## v3 validates every input; v2 deliberately still does not

- **Plan:** `plans/record-digest-v3.md` (Phase 3)
- **Assumed:** `record_digest_v3` / `recordDigestV3` should refuse any input it cannot faithfully
  represent, rather than coerce it — and `record_digest_v2` should keep its current lenient
  behaviour, leaving the two versions with different opinions about what a valid call is.
- **Chose:** Validate every v3 slot, inside `recordDigestV3`'s own body, touching no helper v2
  shares. Bytes slots must be a one-byte-per-element buffer of the right length; string slots must be
  actual strings with no unpaired surrogates; integer slots must be in range and exactly
  representable. Every refusal happens before a single byte is hashed.

  The trigger is not tidiness — it is that three of these coercions produce an **alias**, not a
  mismatch. A 32-character string passed as a sub-digest hashes as 32 zero bytes, which is a digest a
  legitimate all-zeros sub-digest also produces; `2**64 + 5` hashes as `5`. A mismatch is caught
  downstream by the comparison the function exists to feed. An alias is caught nowhere. That is the
  same class of collision the spec's own framing rules exist to prevent (`seam-event.v1.md`, "The
  outer count, and the collision it prevents"), so refusing is the version-consistent answer, not
  extra strictness.

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
  got a digest. Every such digest was wrong — it could not have matched a wire value produced by the
  runtime — so no correct caller breaks. Cheap to reverse: the validators are a contiguous block at
  the top of one function in each language.
- **Status:** UNCONFIRMED

## The v1 skip is a downgrade hole, closed structurally rather than documented

- **Plan:** `plans/record-digest-v3.md` (Phase 4)
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
- **Status:** UNCONFIRMED

## `frame`'s `len() as u32` truncates above 4 GiB, in Rust only

- **Plan:** `plans/record-digest-v3.md` (Phase 4)
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
- **Status:** UNCONFIRMED
