# Assumptions — seam-sdk adopts the seam-runtime backlog-closeout landing (2026-07)

Working assumptions taken during `/implement` of `plans/adopt-runtime-2026-07.md`, to reconcile later.
Each is the strongest option given what the code showed; none is a one-way door.

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
- **Status:** UNCONFIRMED

## generate-local is the development baseline; the BSR is the release source
- **Assumed:** SDK development should not be blocked waiting on the (user-gated, immutable) BSR push, while
  releases must still come from the published contract of record.
- **Chose:** documented + tooled `make generate-local RUNTIME=../seam-runtime` as the iteration baseline
  (always current with the runtime tree) and `make generate` (BSR) as the release source. All later phases
  (2–6) develop against `generate-local`.
- **Alternatives:** assume the BSR is always fresh — the runtime's A13 history (a `buf push` that used to
  silent-skip) says it may not be, and a stale contract would pass locally and break on release.
- **Blast radius if wrong:** none structural — it is a documented workflow, not a code contract.
- **Status:** UNCONFIRMED

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
- **Status:** UNCONFIRMED

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
- **Status:** UNCONFIRMED

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
- **Status:** UNCONFIRMED
