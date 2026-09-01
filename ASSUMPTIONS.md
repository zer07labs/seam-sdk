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
- **Status:** UNCONFIRMED

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
- **Status:** UNCONFIRMED

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
- **Status:** CONFIRMED (2026-08-31) — **on the durable reason, not on in-run evidence.** An earlier
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
- **Status:** UNCONFIRMED — this is the one option worth raising rather than settling unilaterally,
  per the phase's own Rejected-alternatives note.
