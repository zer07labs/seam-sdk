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

## `timeout` means per-RPC, not an overall call budget

- **Assumed:** callers who need a hard overall bound already impose their own outer clock.
  True of the one consumer we know: `seam-agent-core`'s `Gate` wraps every call in
  `asyncio.wait_for`, and `SessionBinder` does the same per step.
- **Chose:** keep per-RPC and **document it explicitly** (`client.py`, above `DEFAULT_TIMEOUT_S`).
  Most methods make one wire call, so the distinction is invisible; it bites on `authorize`,
  which can make up to four (a cold/stale admit is 2 RTT, then Authorize, then on
  `UNAUTHENTICATED` a refresh of 2 RTT plus the retried Authorize), and on `run_decision` /
  `open_session`, which each begin with the challenge→Admit handshake.
- **Alternatives:** an overall budget — the semantics most callers would assume from the name.
  Rejected for now, not forever: it means threading a deadline through the ticket lifecycle and
  deciding what a partially-spent budget means for a refresh, which is a contract change for
  every existing caller in exchange for a bound the only consumer that needs it already has.
- **Blast radius if wrong:** a caller sizing an outer deadline as `1x timeout` sees spurious
  cancellations on the refresh path, where the SDK legitimately needs more. That is the failure
  the documentation above is meant to prevent; the adapters' `Gate` already sizes for it.
- **Status:** UNCONFIRMED — revisit if a second consumer wants an overall budget. Changing it
  later is additive if introduced as a distinct parameter rather than a redefinition of `timeout`.

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
- **Status:** UNCONFIRMED — the `requires-python` and floor bumps are metadata breaking changes;
  confirm the release framing before publishing.

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
- **Status:** UNCONFIRMED — folds into the same release framing as the protobuf floor above.
