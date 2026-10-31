# `verify/` parity with seam-runtime 0.67.0 "code-health A4" (seam-sdk#316)

> **Issue:** [#316](https://github.com/zer07labs/seam-sdk/issues/316). **Upstream:** seam-runtime#1557
> (`4f70c2c4`, release train 0.67.0, code-health A1–A7). The spec text is already vendored (seam-sdk#317).
> **Normative text:** `verify/docs/seam-event.v1.md`, a verbatim pin of the runtime's
> `docs/specs/seam-event.v1.md` @ `4f70c2c`. The relevant clauses are (b′) at `:291` and "Payload binds to kind" at `:800-805`.
> **Reference implementation (read-only, never linked):** `seam-runtime origin/main:crates/seam-verify/src/entry.rs`
> and `src/main.rs`. **Anchors:** seam-sdk `71d9955`, seam-runtime `origin/main` = `37576658` (re-anchored at plan
> review from `273cd578`; `git diff 273cd578 37576658 -- crates/seam-verify/src docs/specs/seam-event.v1.md` is
> empty, as is the diff of `crates/seam-verify/tests`, `crates/seam-store/src/lib.rs` and `event.rs`, so every runtime
> citation below holds at both). Both contain `4f70c2c4`. Every runtime citation below is
> `origin/main:`; the runtime working tree was not read.
> **Runtime-side defects:** tracked by seam-runtime#1561 (the runtime's `--allow-uncovered` false green, and the
> spec omitting the (b′) preimages and tables). This plan references it; it files nothing.

## Status

IN PROGRESS. P0 and P1 DONE (PR A); P2–P5 TODO (PR B). **All phases are unblocked.** OQ-1 is resolved as **(b) ∥ (a)**, decided by Fable at plan
review; owner input was not needed (see OQ-1). Phases 2 and 3 transcribe from runtime `entry.rs` under the scoped
D-043 carve-out, validated against Phase 0's runtime-produced vectors, while seam-runtime#1561 carries the spec
fix. **Owner checkpoint:** `publish-verify` is `workflow_dispatch` only (`.github/workflows/publish.yml:524-528`),
so nothing reaches partners until the owner dispatches it after PR B merges.

## Context

**What A4 changed upstream.** The runtime's verifier used to link stored digests and recompute only
`DECISION_SEALED`. Under A4 it does five things:

1. **Payload binds to kind** (spec `:800-805`). Each payload field belongs to exactly one kind, and a known kind must
   carry its own payload. A known advisory kind, or the `chain_anchor` audit entry, that carries
   `digest`/`checksum` is refused. The runtime enforces this in **every mode**, integrity included: `check_kind_payload`
   (`origin/main:crates/seam-verify/src/main.rs:273-361`) is called at the top of `verify_chain` (`:542`),
   before the link check. Its refusal markers are `KIND/PAYLOAD MISMATCH` (`:337`, `:346`) and
   `ADVISORY EVENT WITH CHAIN FIELDS` (`:353`).
2. **(b′) Every chained body recomputes under `--issuer`** (`entry.rs:161-199`, called from `verify_issuer`
   `main.rs:705-722` for every link with no `payload`):
   - `AUDIT_ENTRY`, under the domain its action selects. The actions in `AuditAction::ALL` minus `fact_appended`
     map to `seam.audit.management.v1` (`entry.rs:25`, `:49-56`). Seven other domains form a closed table
     (`entry.rs:28-45`). The preimage is `entry.rs:84-104`, mirroring the store's `ActionEntry::new`
     (`origin/main:crates/seam-store/src/lib.rs:5040-5085`) and `audit_system_action` (`lib.rs:3345-3375`).
   - `CHAIN_HEAD_ATTESTATION`, under `seam.audit.chain-attest-entry.v1` (`entry.rs:115-125`; store
     `lib.rs:5164-5177`).
   - `ERASURE_CERTIFICATE`, under `seam.audit.erasure-cert.v2` (`entry.rs:127-146`; store `lib.rs:849-878`).
   - A mismatch is `ENTRY REWRITE`, exit 2 (`main.rs:712-721`).
3. **Classification is bound.** An `AUDIT_ENTRY`'s envelope `classification` must be its action's label:
   `Confidential` for `execute.scope_deny` and `boundary.data_flagged`, `Pii` for `gdpr_erasure`, `Internal`
   otherwise (`entry.rs:67-73`, derived from the store's `AuditReason::classification`, `lib.rs:159-171`). An
   attestation must be `Internal` and a certificate `Pii` (`KIND_CLASSIFICATION_CONTRACT`,
   `origin/main:crates/seam-store/src/event.rs:131-145`; `entry.rs:76-81`, `:179-188`). A relabel is an
   `ENTRY REWRITE` naming "…'s classification".
4. **Uncovered ⇒ refused under `--issuer`.** This covers an unknown action, `fact_appended`, or an unknown kind with
   chain fields. The spec states the refusal itself: "uncovered and REFUSED under `--issuer`" (vendored spec `:291`).
   The runtime counts it in `verify_issuer` and refuses in `cmd_chain` after authenticity passes
   (`main.rs:1409-1429`, message "…cannot recompute…"). `--allow-uncovered` reports instead. It is human-only:
   given with `--json`, with `--bridge`, or outside `chain`, it is a usage error, exit 1 (`main.rs:1768-1773`).
   Under `--allow-uncovered` with uncovered > 0 the runtime still prints `CHAIN VERIFIED + AUTHENTICATED` and exits
   0 (`main.rs:1500-1529`). That is a false green against spec `:1677-1681` ("MUST NOT fold them into a green
   claim"), tracked as seam-runtime#1561. This crate does **not** mirror it (Phase 4).
5. **The `--json` shape is deliberately unchanged.** `entries`/`uncovered` are human-report-only
   (`main.rs:655-660`). This is pinned by `origin/main:crates/seam-verify/tests/entry_recompute.rs:392-411`.

**What `verify/` does today (seam-sdk `71d9955`).**

- **Parse.** `verify/src/wire.rs` decodes only the tags verification needs (`:16-86`). It does **not** decode the
  envelope `classification` (tag 7) or `session_id` (tag 9), and it does not decode tags 14, 15, 17, 21 or 26
  (`learning_decision`, `learning_outcome`, `budget_breach`, `session_lifecycle`, `event_redriven`). The JSON
  projection `SeamEventJson` (`:267-305`) drops those keys too. `Event` (`:433-462`) therefore cannot express
  "which payloads are present", nor two preimage inputs.
- **Classify.**
  - `is_link` keys on field presence (`wire.rs:950-952`).
  - `is_advisory` lists `ADVISORY_KINDS` (`:983-1004`) plus the `chain_anchor` action (`:955-963`).
  - `is_modelled`/`MODELLED_KINDS` (`:971`, `:1029-1043`) drives the `unverified content` disclosure.
- **Integrity.** `chain_by_tenant` (`verify/src/verify.rs:180-321`) walks per-tenant links and counts advisory and
  unverifiable events (`:205-216`). It records `unmodelled` links (`:283`). There is no kind/payload check anywhere.
- **Authenticity.** `verify_authenticity_anchored` (`verify.rs:730-1020`) runs **two loops**. The first
  (`:760-820`) recomputes every `DECISION_SEALED` under record digest v4 (strip vs. mismatch, `:806-819`). It
  keys on `e.decision` plus `e.digest`, without requiring `checksum`, which the runtime does require
  (`main.rs:891-894`). The second loop (`:822-997`) checks attestations: tenant agreement, pin, signature,
  vacuous, below-window `continue` (`:943-950`), at-anchor `continue` (`:951-968`), position, ceiling. Then
  `covering == 0` ⇒ refuse (`:999`). `IssuerReport` (`:493-520`) carries `attestations`, `covered_prefix`,
  `records_recomputed`, `covering` and `below_window`.
- **Multi-tenant.** `verify_authenticity_by_tenant` (`:1044-1072`) fans out per tenant over `report.tenants`.
- **CLI.**
  - `cmd_chain` (`verify/src/main.rs:215-561`) uses exit codes **0 / 1 / 2 only** (`:16-18`, `FAILED = 2` at
    `:30`; README `:15`).
  - The refusal helper is `fail()` (`:154-161`). `io_error()` (`:166-172`) emits JSON on stdout under `--json` too.
  - `--strict` refuses `unverifiable` (`:301-312`).
  - Single-tenant `--issuer` goes through `verify_authenticity[_anchored]` (`:324-351`); multi-tenant goes through
    `verify_authenticity_by_tenant` (`:352-359`).
  - The `--json` object is printed at `:393-437`. Banners (`:439-452`) include `CHAIN AUTHENTICATED` and
    `WINDOW AUTHENTICATED`.
  - The `unverified content` line (`:471-487`) is printed unconditionally.
  - Flag validation: "requires --issuer" at `:764-777`, "chain-only" at `:794-801`.
- **Bundle.** `bundle` step 2 (`verify/src/bundle.rs:459-519`) calls the same `chain_anchored` +
  `verify_authenticity_anchored`, so library-level changes reach it automatically.
- **No bridge mode.** `--bridge` appears nowhere in `verify/src`, `verify/tests` or `verify/README.md`. The usage
  text is at `main.rs:37-40` and the argument parser at `:695-748`. The runtime's `bridge.rs` is k8s P16, a feature
  this crate never had.

**Pressure-tested facts that shape the phases.**

- **No fixture refresh is needed for attestation rows.** An independent Python transcription of the three runtime
  preimages was run over every committed stream. Every chained `CHAIN_HEAD_ATTESTATION` in `verify/tests/goldens/*.jsonl`
  (4 files) and `verify/fixtures/evidence-bundle/*/events.jsonl` (4 bundles) recomputes under
  `chain-attest-entry.v1` and carries `classification: "Internal"`. All eight streams also satisfy the
  kind/payload binding. These are real runtime-produced KATs for the attestation preimage. None contains a
  chained `AUDIT_ENTRY` or `ERASURE_CERTIFICATE`. The goldens are byte-identical to
  `origin/main:crates/seam-verify/tests/goldens/` today.
- **Large synthetic-test churn.** Synthetic test streams break under the new rules.
  - `tests/verifier.rs` `chain()`/`chain_of()` (`:49-73`, 24 call sites) build `DECISION_SEALED` links with **no
    payload**, and `("ERASURE_CERTIFICATE", "")` links with no payload (`:433`). The binding refuses these in
    integrity mode.
  - Every synthetic attestation helper chains an arbitrary digest (`Sha256("att-{seq}")`) with no envelope
    classification. These are `tests/authenticity.rs:370-405`, `anchored.rs:117-150`, `truncation.rs:118-145`,
    `multi_tenant.rs:355-440` and `conformance.rs:224`. The recompute refuses them under `--issuer`.
- **The spec does not carry the preimages (critical, OQ-1).** (b′) names the AUDIT_ENTRY domains by short name and says
  "the closed table is `seam-verify/src/entry.rs`". That is a path in a private repo. The vendored spec contains
  none of the following:
  - the domain strings, except `seam.audit.context-recall.v1`;
  - the action-entry framing (seven length-prefixed strings, a **raw unframed** `u64le occurred_at`, then the actor
    frame **only when present**);
  - the `chain-attest-entry.v1` or `erasure-cert.v2` framing;
  - the action→classification map;
  - which kind is `Internal` and which is `Pii`.

  `grep -n "seam.audit\." verify/docs/*.md` finds only the record, context, participation and participants digests,
  and the two attestation-signature domains. Meanwhile `verify/DECISIONS.md` D-035 says every implementation here
  was "written from the published spec … never from the runtime's Rust", and `verify/README.md:38-40` says
  "Everything it does is specified in `docs/`". The runtime session confirms the gap (runtime answer 1): the spec
  spells only `chain-attest-entry.v1`, `erasure-cert.v2` and `context-recall.v1`; the framing is code-only
  (`entry.rs:84-104`). **Resolved by OQ-1 → (b) ∥ (a)** with the D-043 carve-out; the spec fix is seam-runtime#1561.
- **The runtime is not one source of truth on five points** (all confirmed by the runtime session; spec errors
  are covered by seam-runtime#1561):
  - `entry.rs:155` documents `Body::Uncovered` as "Reported, never a failure", while `main.rs:1415-1428` refuses it.
    The doc comment is stale (runtime answer 7).
  - The spec's Chain bullet lists the chained kinds as `DECISION_SEALED`, `AUDIT_ENTRY`, `ERASURE_CERTIFICATE`
    (`seam-event.v1.md:797-799`), omitting `CHAIN_HEAD_ATTESTATION`. Both runtime implementations chain and recompute
    it (`entry.rs:178-183`). A spec error (runtime answer 10).
  - The spec's `AUDIT_ENTRY` section says "a consumer MUST treat an unknown value as opaque (render it, never
    reject the row)" (`:118`), while (b′) refuses an uncovered action under `--issuer`. Per runtime answer 10, `:118`
    governs delivery consumers; verifiers are governed by (b′) `:291` and the disclose-or-refuse rule `:1677-1681`.
  - The spec says `context_recalled`'s `actor` "is empty" (`:137`), but the writer passes `None`
    (`origin/main:crates/seam-store/src/lib.rs:4742`), and `Some("")` digests differently: it appends a four-zero-byte
    length frame (`entry.rs:99-102`). "Empty" should read "absent" (runtime answer 4). This crate hashes per the code;
    the spec-text error is recorded under the D-043 carve-out, with seam-runtime#1561 as the fix.
  - The issue brief says "`namespace` and `occurred_at` are outside the preimage". That holds for the attestation
    and the certificate only (spec `:291`, "Their envelope …"). An `AUDIT_ENTRY`'s envelope `tenant`, `namespace`,
    `session_id` and `occurred_at` are **inside** its preimage (`entry.rs:86-98`; store `lib.rs:5058-5068`).
- **SDK decoders do not verify chains.** `python/seam_sdk` and `ts/src` contain no `prev_checksum` walk, no running
  head and no entry-domain string. The only digest helper is per-record `DECISION_SEALED`
  (`python/seam_sdk/admin.py:88`, `ts/src/admin.ts:140`), which A4 does not touch. Out of scope.
- **No in-repo or sibling consumer parses `verify --json`.** A search of `python/`, `ts/`, `go/`, `scripts/`,
  `.github/`, `seam-adapters`, `seam-mcp`, `seam-connectors`, `seam-learning` and `seam-aegis` found only prose
  mentions (e.g. `seam-mcp/onboard/src/seam_mcp_onboard/_docs/07-technical-reference.md:155`). The one programmatic
  consumer is the runtime's `differential` harness. It invokes this binary at a pinned SHA (`SEAM_SDK_REF`,
  `origin/main:.github/workflows/ci.yml:68-80`), compares exit codes, and checks diagnosis markers on the internal
  side (`tests/differential.rs:1170-1205`). Its public consumers are third parties, so the JSON contract still binds.

**Goal.** Bring `verify/` to verdict parity with the runtime's A4 behaviour, in every output path: human, `--json`,
`bundle`, and the library API. Keep three invariants: a third party can rebuild it from `docs/`, `cargo tree -e normal`
lists zero Seam crates, and no green is reported over a chained entry this build did not recompute.

## Phases

### Phase 0: Runtime-produced entry vectors

- **Status:** DONE (2026-10-30). Divergences: lines end with a trailing newline (the runtime's helpers join without
  one); the system partition's attestation omits `tenant`, which the test reads as `""`; a window+anchor
  `--from-anchor` test was added (verifier gap). The certificate's issuer and signature are runtime test
  placeholders, valid for recompute only. **Risk:** simple.
- **Delivers:** a committed stream that holds every A4 domain, a certificate, and attestations for three
  partitions (`acme`, `beta`, `""`), byte-vendored. Phases 2–4 are proven against it. Nothing hand-signed.
- **Depends on:** nothing. It only needs a clean `git archive 37576658` export of seam-runtime (memory:
  build-pinned-runtime-from-export; never the shared checkout). `crates/seam-verify/src` and `tests` are unchanged since `273cd578`.
- **Files:**
  - `verify/tests/goldens/entry_domains.jsonl` (new);
  - `verify/tests/goldens/entry_domains.window.jsonl` + `entry_domains.anchor.json` (new, the anchored-window cut
    for Phase 3's ordering tests);
  - `verify/tests/goldens/entry_domains.swapped-attestation.json` (new, the genuinely signed earlier attestation
    for the below-base swap test);
  - `verify/tests/goldens/README.md`, *pending, see OQ-6*;
  - `verify/tests/entry_vectors.rs` (new).
- **Approach:**
  1. In the export, run the body of `origin/main:crates/seam-verify/tests/entry_recompute.rs` `stream()` (`:60-188`,
     seed `21×32`) through a throw-away test that writes `relay_events()` as JSON lines, one per line, via
     `SeamEvent::to_json`. Record the issuer AID it prints.
  2. Produce the anchored window the same way. `entry_domains.window.jsonl` is cut from a **different** stream:
     `anchored.rs` `two_anchor_stream` (`origin/main:crates/seam-verify/tests/anchored.rs:80`) via
     `window_from(&events, 2)`, so that one attestation lies **below** the window base. Its issuer is
     `ISSUER_SEED`'s AID, not the `21×32` one; record both.
  3. **Capture the swapped attestation's bytes too.** The runtime's
     `a_swapped_attestation_below_the_window_base_fails` (`anchored.rs:540-571`) signs a **fresh** attestation with
     `ISSUER_SEED` (`sign_chain_head_for_tenant(1, head1, ATTESTED_AT, 4, "acme")`) and splices its `attested_len`,
     `attested_head` and `signature` into the window's first row. Have the throw-away test write that attestation
     (all fields) as `entry_domains.swapped-attestation.json`. Phase 3 splices the captured fields; it never
     hand-signs, and this crate holds no issuer seed.
  4. Copy the bytes, with `.gitattributes` keeping git off them as for the bundles (README `:339`).
  5. Record provenance (runtime commit, test function, seed, AID) in the file header comment of
     `tests/entry_vectors.rs`. This is precedent D-038/D-040: fixtures "captured from the runtime's own test".
  - *Rejected:* generating vectors from an in-repo Python transcription (the D-035 style). It proves only that
    two transcriptions written from the same reading agree, not that either matches the store.
  - *Rejected as an oracle:* the runtime's `crates/seam-store/tests/golden_chained_events_json.json`. It is a JSON
    shape golden whose digests are placeholders (e.g. `"digest": "ERERER…E="`, a `0x11` fill), so no recompute can
    match it. It is unusable as a preimage KAT.
  - *Rejected:* adding blocks to `conformance/vectors.json`. The runtime's `sdk-digest-parity` job whole-file-diffs
    that file against its own emitter (`origin/main:scripts/sdk-digest-parity.sh:40-58`), so a new block turns a
    required runtime check red.
- **Edge cases:**
  - The stream contains a crypto-shredded tenant (`beta`) and a system partition with a v1 attestation. Both must
    stay, because they are the cases most likely to differ.
  - `actor` must stay `null` (not `""`) on no-actor entries. The JSON writer emits `null`, since there is no
    `skip_serializing_if` on `AuditEntryEvent.actor` (`event.rs:406`).
- **Acceptance (falsifiable):**
  - `entry_vectors.rs` asserts that the file holds chained `AUDIT_ENTRY` rows for exactly these 12 actions:
    `party_registered`, `hold_placed`, `hold_released`, `boundary.data_flagged`, `admit.compat_reject`,
    `execute.scope_deny`, `ciphertext_evicted`, `gdpr_erasure`, `crypto_shred_purge`, `context_recalled`,
    `tenant_kek_shred`, `config_snapshot_installed`. It also asserts at least one chained `ERASURE_CERTIFICATE`
    and attestations for all three tenants.
  - Plain `chain` (current code) verifies the file with exit 0.
  - `chain --issuer <AID> --strict` exits 0 on current code, because nothing recomputes yet. Phase 4 replaces this
    with entries-recomputed assertions.
  - The swapped-attestation file passes `seam_verify::verify_anchor` (`verify/src/verify.rs:1082`) under the
    window's issuer AID, and its `attested_len` is 1,
    below the window base of 2.
  - The sha256 of each vendored file is asserted in the test, so a silent edit is red.
- **Tests:** the assertions above. Also a negative control: deleting one line makes plain `chain` exit 2
  (`BROKEN CHAIN`), which proves the file is a real chain.
- **Docs:** none (provenance lives in the test header).

### Phase 1: Payload binds to kind

- **Status:** DONE (2026-10-30). Divergences: the `--issuer`-path helpers chained payload-less seals (the plan
  assumed v4). They now use real v4 records from a new spec-written `verify/tests/support/mod.rs`, and their
  signed ceilings rose from 2 to 4. `conformance.rs` needed no change. Unmodelled JSON slots accept only an
  object (`OpaqueObject`), matching the runtime's typed decoder. **Risk:** complex. It changes integrity-mode
  verdicts, and the test churn is wide.
- **Delivers:** `KIND/PAYLOAD MISMATCH` and `ADVISORY EVENT WITH CHAIN FIELDS` refusals, in every mode (plain `chain`,
  `--strict`, `--issuer`, `bundle`), matching runtime `main.rs:273-361`.
- **Depends on:** nothing. The spec text at `:800-805` is fully normative. It is not gated on OQ-1.
- **Files:** `verify/src/wire.rs`, `verify/src/verify.rs`, and the tests `verify/tests/verifier.rs`,
  `truncation.rs`, `multi_tenant.rs`, `anchored.rs`, `authenticity.rs`, `conformance.rs` and `bundle.rs` (helper
  updates). Also a new `verify/tests/kind_payload.rs`.
- **Approach:**
  - **Presence.** Give `Event` payload-presence **booleans** covering all 11 payload slots (tags 13, 14, 15, 16,
    17, 18, 21, 22, 23, 24, 26). For the five unmodelled slots the boolean is the whole record; nothing of their
    content is kept.
    - For protobuf, declare tags 14, 15, 17, 21 and 26 on `SeamEventPb` as presence-only
      `#[prost(bytes = "vec", optional)]`. Message and bytes share wire type 2, so decoding needs no model of their
      contents. This keeps the crate's "decode only what verification needs" rule (`wire.rs:1-9`).
    - For JSON, add the five keys to `SeamEventJson` as `Option<serde::de::IgnoredAny>`, so `null` reads as absent,
      matching serde `Option` on the runtime side.
  - **Rule.** Add `pub fn check_kind_payload(e: &Event) -> Result<(), String>` in `verify.rs`, a table of
    `(field label, present, owner kind)`. Call it **first** in `chain_by_tenant`'s loop (`verify.rs:205`), before the
    link/advisory split, as the runtime does at `main.rs:542`. Every library entry point then gets it, including
    `bundle` via `chain_anchored` (`bundle.rs:475`). It enforces three things:
    1. No payload is present that belongs to a kind other than `e.kind`.
    2. A **known** kind (the 11 owners) carries its own payload. An unknown kind may carry none of the known ones.
    3. `is_advisory()` with `digest` or `checksum` present ⇒ refuse.

    Use the runtime's marker strings verbatim and its field labels (e.g. `payload (tag 13)`), so the differential
    harness's diagnosis map can be extended to both sides later.
  - **Test churn.** Fix it at the helpers, not per test. `verifier.rs` `event()` gains a minimal payload for each
    known kind. `chain(n)` emits a `DECISION_SEALED` with a stub `payload` object; integrity never recomputes, and
    `--issuer` paths already use real v4 payloads. `("ERASURE_CERTIFICATE", "")` gains a stub certificate. Keep the
    current test intent, and add the binding tests next to it.
  - *Rejected:* enforcing only under `--issuer`. That diverges from the runtime (`origin/main:crates/seam-verify/
    tests/authenticity.rs:302-319`, `a_sealed_decision_dressed_as_an_advisory_kind_fails`, asserts
    the refusal under plain `chain` and `--strict`). A relabelled seal would also still count as a link in integrity
    mode, which is the hole the spec names.
  - *Rejected:* decoding the advisory payload messages. That is unneeded surface; presence is the whole rule.
- **Edge cases:**
  - An unknown kind with digest+checksum and no known payload is still a link and is disclosed as unmodelled
    (`verify.rs:283`). It does not count as a mismatch.
  - A `chain_anchor` with chain fields is refused, where today it links (`wire.rs:950`).
  - A `DECISION_SEALED` with `payload: null` in JSON reads as absent and is refused.
  - **Dedup identity.** `Event.bytes` is the re-encode in `with_identity` (`wire.rs:873-947`), and it runs on
    **both** transports: the JSON path (`:787`) and the protobuf path (`:861-863`, which overwrites the raw
    `bytes`). For each present unmodelled slot `with_identity` encodes an **empty** sub-message (`Some(vec![])`),
    whichever transport delivered it, so presence is part of identity and one event gets the same identity over
    JSON and protobuf. Without it a mismatched copy and a clean copy of one event could dedup into whichever arrived
    first. That is fail-safe, since a dropped event contributes nothing, but explicit is better. Resolves OQ-8.
  - The refusal runs before `unverifiable` counting, so a stripped-and-relabelled event reports the binding
    first. This matches the runtime.
- **Acceptance (falsifiable):**
  1. Every committed golden and bundle still verifies, in every mode it verified in before.
  2. A sealed decision relabelled as `LEARNING_DECISION` exits 2 with `KIND/PAYLOAD MISMATCH` and
     `carries payload (tag 13)` under no flags, `--strict` and `--issuer`.
  3. Grafting `audit_entry` onto a `DECISION_SEALED` exits 2 with `which only a AUDIT_ENTRY`.
  4. Stripping a seal's payload exits 2 with `carries no DECISION_SEALED payload`.
  5. A chained `chain_anchor` exits 2 with `ADVISORY EVENT WITH CHAIN FIELDS`.
  6. A chained `chain_anchor` inside an evidence bundle's window makes `bundle` exit 2 with
     `ADVISORY EVENT WITH CHAIN FIELDS` (the binding reaches it through `chain_anchored`, `bundle.rs:475`).
  7. The `bundle` CLI still passes over all 4 shipped fixtures (`verify/fixtures/evidence-bundle/{full,minimal,
     other-issuer,shredded}`).
  8. One event carrying an unmodelled payload (e.g. tag 21 `session_lifecycle`), delivered once as JSON and once as
     base64 protobuf in one stream, collapses to one event: the chain verifies with no duplicate or impostor
     refusal.
  9. `cargo tree -e normal` is unchanged.
- **Tests:** `kind_payload.rs` holds one test per row of the 11-entry table, each for a foreign payload on another
  kind and for a missing own payload, on **both** transports (JSON and base64 protobuf). The protobuf case
  hand-encodes tag 14/15/17/21/26 bytes, so the presence decode itself is tested. Mutation check: deleting rule (2)
  must turn the "stripped payload" test red, and deleting the `is_advisory` arm must turn the anchor test red.
  `wire.rs` unit tests also pin presence detection for each new tag. `bundle.rs` gains the chained-`chain_anchor`
  refusal (criterion 6) and the four-fixture CLI pass (criterion 7); `kind_payload.rs` gains the cross-transport
  dedup test (criterion 8).
- **Docs:** none here (Phase 5).

### Phase 2: Preimage framework and the `AUDIT_ENTRY` domain table

- **Status:** TODO, unblocked (OQ-1 resolved: transcribe under D-043). **Risk:** complex. It adds a new trust claim
  and a new refusal.
- **Delivers:**
  - Under `--issuer`, every chained `AUDIT_ENTRY` recomputes under its action's domain and its envelope
    classification is bound.
  - A mismatch is refused as `ENTRY REWRITE`.
  - An unknown action and `fact_appended` are counted as uncovered, but **not yet refused**; Phase 4 adds the
    refusal.
  - The `DECISION_SEALED` arm is **unchanged** (see Approach).
- **Depends on:** Phase 1, which guarantees `audit_entry` is present on every `AUDIT_ENTRY`. Phase 0 supplies the
  vectors. Source of the transcription: runtime `origin/main:crates/seam-verify/src/entry.rs` @ `37576658`, under
  the D-043 carve-out (OQ-1).
- **Files:**
  - `verify/src/entry.rs` (new module): the frame helper, the domain table, the classification table,
    `audit_entry_digest`, `enum Body { Recomputed, Rewritten(&'static str), Uncovered }`, and `recompute(&Event)`;
  - `verify/src/wire.rs`: envelope `classification` (tag 7, `string`) and `session_id` (tag 9, `optional string`)
    on `SeamEventPb`, `SeamEventJson` and `Event`, plus the dedup re-encode;
  - `verify/src/verify.rs`: the first loop of `verify_authenticity_anchored`, and `IssuerReport`;
  - `verify/src/lib.rs` re-exports;
  - `verify/tests/entry_recompute.rs` (new).
- **Approach:**
  - **Placement.** At the top of `verify_authenticity_anchored`'s **first** loop (`verify.rs:760`), for every link
    (`is_link()`) whose kind is not `DECISION_SEALED` (by binding: `decision.is_none()`), call
    `entry::recompute(e)`. `Rewritten` returns `Err` immediately. `Recomputed` increments
    `IssuerReport.entries_recomputed`. `Uncovered` pushes `(seq, kind, action)` onto `IssuerReport.uncovered`.
    That loop already finishes before the attestation loop starts, so the "recompute before every attestation
    check" ordering is structural. Phase 3 pins it with tests.
  - **Ordering differs from the runtime on multi-defect streams.** The runtime runs recompute and attestation checks
    for each event in **one** loop (`main.rs:705-722`: recompute, then that event's attestation branch), so it
    reports the first defect by sequence. This crate runs every recompute (loop 1) before any attestation check
    (loop 2). On a stream with an attestation defect at seq 3 and a rewrite at seq 9, both exit 2, but the runtime
    names the seq-3 attestation and this crate names the seq-9 `ENTRY REWRITE`. Single-defect streams agree on both
    code and marker. The README says so (Phase 5), and the differential cases proposed in Cross-repo item 3 stay
    single-defect.
  - **The `DECISION_SEALED` arm stays as it is.** Plan review asked whether to narrow it to links, as the runtime does
    (`main.rs:891-894` keys on `payload` + `digest` + `checksum`). That would be a **relaxation**: today an
    unchained `DECISION_SEALED` with `schema_version != 4` or no `ciphertext_digest` is refused
    (`verify.rs:773-798`), because those checks run before the `let Some(wire_digest) … else continue` at
    `:801-803`. The spec does not require the relaxation. Clause (c) refuses "a `DECISION_SEALED` whose
    `schema_version` is not `4`" and a v4 one lacking `ciphertext_digest`, with no link qualifier (`:291-292`), and
    "a verifier that meets a record `schema_version` it does not implement refuses … rather than skipping the
    record" (`:1659`). So today's refusal is kept. This is deliberately stricter than the runtime on unchained
    seals, and D-042 records it.
  - **Domain table.** Management covers 16 labels (store `lib.rs:237-270` minus `fact_appended`). The other domains:
    - legal-hold: `hold_placed`, `hold_released`;
    - archive-evict: `ciphertext_evicted`;
    - boundary: `boundary.data_flagged`;
    - denial: `admit.compat_reject`, `execute.scope_deny`;
    - purge: `crypto_shred_purge`;
    - erasure: `gdpr_erasure`, `tenant_kek_shred`;
    - context-recall: `context_recalled`.

    `fact_appended` returns `None`, which means uncovered.
  - **Preimage** (transcribed from `entry.rs:84-104`, which mirrors the store's `ActionEntry::new`
    `lib.rs:5058-5075`; framing confirmed code-only by runtime answer 1): `frame(domain)`,
    `frame(action)`, `frame(envelope tenant)`, `frame(envelope namespace)`,
    `frame(envelope session_id or "")`, `frame(subject)`, `frame(reason)`, then the raw `u64le(envelope occurred_at)`
    with **no** frame, then `frame(actor)` only if `actor` is `Some` (`Some("")` appends a zero-length frame;
    `None` appends nothing). Here `frame(x) = u32le(len) ‖ x`. **Hash per the code, not spec `:137`:** a
    `context_recalled` entry's actor is absent (`None`, `lib.rs:4742`), so it gets no actor frame, although the spec
    calls it "empty" (D-043 carve-out; fix in seam-runtime#1561). Classification is checked **before** hashing
    (`entry.rs:173-175`), as an exact, case-sensitive byte comparison (runtime answer 5).
  - **Library API.** `IssuerReport` gains `pub entries_recomputed: usize` and `pub uncovered: Vec<Uncovered>` (a new
    pub struct with `seq`, `tenant`, `kind`, `action: Option<String>`). This is a semver-breaking change to a
    published 0.x crate, so Phase 5 bumps it to 0.5.0.
  - *Rejected:* recomputing inside `chain_by_tenant` (integrity). The spec gates (b′) on `--issuer`, and without a
    signed head a recomputed digest proves nothing a forger could not also recompute.
  - *Rejected:* a separate pass after the attestation loop. It would let the below-window `continue` (`:950`) run
    before a rewrite is seen, which is the exact ordering (b′) forbids.
- **Edge cases:**
  - **System partition.** The preimage tenant, namespace and session are all `""` (`lib.rs:3363`, `:3382-3384`),
    which matches its envelope (runtime answer 2).
  - **`session_id`.** Absent and `""` both frame as `""`. The runtime writes `Some("")` (`event.rs:1608`) and
    `entry.rs:91` uses `unwrap_or("")`. This equivalence is code-only; the spec is silent (runtime answer 3), so it
    falls under D-043.
  - **`actor`.** Absent versus `""` produces two different digests. JSON `null` is `None`. `Some("")` is not
    forbidden by any writer contract; it digests as a four-zero-byte frame (runtime answer 4).
  - **Envelope = digested values.** For every writer the runtime traced, the envelope `tenant`, `namespace`,
    `session_id` and `occurred_at` equal the digested values (`lib.rs:3259-3273`; the move writers use `""`
    namespace and session, `lib.rs:4864-4880`, `:4969-4985`). Not every `audit_action` caller was traced (runtime
    answer 2). An untraced divergent writer would surface as a false `ENTRY REWRITE`; Phase 0's stream is the guard
    for the writers it covers.
  - **Dedup.** Adding `classification`/`session_id` to the JSON re-encode makes dedup identity finer. Two chained
    copies differing only in classification become an impostor refusal instead of a silent collapse. That is
    stricter, and correct.
  - **Unknown kinds.** An unmodelled kind under `--issuer` is now **uncovered** as well as `unmodelled`, and both
    are disclosed.
  - An `AUDIT_ENTRY` link carrying no `audit_entry` is impossible after Phase 1. If it appears anyway, count it
    uncovered (runtime `entry.rs:167-169`), never pass it.
- **Acceptance (falsifiable):**
  - Over `entry_domains.jsonl`, `chain --issuer <AID> --strict` recomputes every chained `AUDIT_ENTRY`. The library
    test asserts `entries_recomputed` equals the count of chained, non-seal `AUDIT_ENTRY` rows.
  - Each mutation in the table below exits 2 with `ENTRY REWRITE` and `AUDIT_ENTRY`, while plain `chain` on the same
    bytes exits 0.
  - An unchained `DECISION_SEALED` relabelled to `schema_version: 3` is still refused under `--issuer` (exit 2,
    `CANNOT VERIFY`), exactly as before this phase. A test pins it, so a later "parity" narrowing cannot relax it
    silently.
  - Relabelling the `action` to `party_registered_v2` puts exactly one `AUDIT_ENTRY` in `uncovered`, with action
    `party_registered_v2` (not yet refused). Attestations and the certificate also read as uncovered until Phase 3,
    so assert on the `AUDIT_ENTRY` members, not on the total count.
- **Tests (mutation per preimage field, each on the Phase 0 stream, links untouched):**
  - `domain`, by moving an action across domains: rewrite `hold_placed` → `ciphertext_evicted`, keep the rest. This
    must fail. It proves the domain is in the preimage and the table is not a pass-through.
  - `action`, `tenant` (envelope), `namespace` (envelope), `session_id` (set where it was empty, and empty where it
    was set), `subject`, `reason`, `occurred_at ± 1`.
  - `actor`: `None→Some("")`, `Some→None`, and changed value. In particular, the `context_recalled` row (actor
    `None`) with its actor set to `Some("")` must **not** match its recorded digest. That pins "absent → no actor
    frame" against the spec's "is empty" reading.
  - Classification relabel, on the `execute.scope_deny` row (`Confidential` → `Internal`), the `gdpr_erasure` row
    (`Pii` → `Internal`), and an `Internal` row → `Public`.
  - A table-completeness unit test: each label maps to exactly one domain, `fact_appended` → `None`,
    `tenant_move_in` → management. This mirrors `entry.rs:207-220`.
  - **Carve-out tripwire** (D-043): read `verify/docs/seam-event.v1.md`; if it contains the string
    `seam.audit.management.v1`, fail with "the vendored spec now carries the (b′) tables: retire the D-043 carve-out
    and re-derive `entry.rs` from the spec". It asserts no counts or line numbers. Today the string is absent
    (`grep -c` gives 0).
  - Strip-vs-rewrite does not apply here. An `AUDIT_ENTRY` has no mandatory-absent slot.
- **Docs:** rustdoc on `entry.rs`, naming its source (runtime `entry.rs` @ `37576658`), D-043, and
  seam-runtime#1561.

### Phase 3: Attestation and certificate preimages, the classification contract, and ordering

- **Status:** TODO, unblocked (OQ-1 resolved). **Risk:** complex.
- **Delivers:** `CHAIN_HEAD_ATTESTATION` recomputes under `seam.audit.chain-attest-entry.v1` and
  `ERASURE_CERTIFICATE` under `seam.audit.erasure-cert.v2`. Their envelope classification is bound (`Internal`,
  `Pii`). Ordering against anchors is pinned by tests.
- **Depends on:** Phase 2.
- **Files:**
  - `verify/src/entry.rs`;
  - helper updates in `verify/tests/authenticity.rs`, `anchored.rs`, `truncation.rs`, `multi_tenant.rs` and
    `conformance.rs`: each synthetic attestation must chain the real entry digest and carry
    `"classification":"Internal"`;
  - `verify/tests/entry_recompute.rs`.
- **Approach:**
  - **Attestation preimage** (`entry.rs:115-125`, store `lib.rs:5164-5177`). Each part is framed:
    `frame("seam.audit.chain-attest-entry.v1")`, `frame(u64le attested_len)`, `frame(attested_head)`,
    `frame(u64le attested_at)`, `frame(u32le digest_schema)`, `frame(issuer_aid)`, `frame(signature)`. The payload
    `tenant` is **not** in it (store doc `lib.rs:5162-5163`).
  - **Certificate preimage** (`entry.rs:127-146`, store `lib.rs:849-878`): `frame("seam.audit.erasure-cert.v2")`,
    `frame(subject)`, `frame(u32le |erased|)`, `frame(id)` for each erased id, `frame(u32le |held|)`, `frame(id)`
    for each held id, `frame(u64le erased_at)`, `frame(chain_head)`, `frame(issuer_aid)`, `frame(signature)`. v2
    only. A non-match is a rewrite, never "older format" (spec `:291`).
  - **Classification first,** as for `AUDIT_ENTRY`.
  - **Test helpers.** Each test file's `attestation_event` computes the entry digest **locally**, with test-only
    code transcribed independently. It does not call `seam_verify::entry`, so a framing bug cannot pass its own
    tests. The existing `att_digest` helpers already follow this pattern (`authenticity.rs:343`).
  - *Rejected:* exempting attestations because their signature already binds them. The signature excludes the
    envelope classification, and a below-window attestation's position is never checked
    (`verify.rs:943-950`). The runtime's `a_swapped_attestation_below_the_window_base_fails`
    (`origin/main:crates/seam-verify/tests/anchored.rs:536-571`) is exactly that case: a genuinely signed earlier
    attestation swapped into a below-base row, which only the recompute catches.
- **Edge cases:**
  - **The anchor file.** The `--from-anchor` / `--expect-anchor` documents are not window links. They keep their
    signature-only validation (`main.rs:181-213`); see OQ-7.
  - **v1 system-partition attestations** (`tenant: ""`) use the same entry framing.
  - **`below_window` and at-anchor attestations** are recomputed in loop 1 before loop 2 skips them.
- **Acceptance (falsifiable):**
  - All 8 committed streams still verify under `--issuer`. This was verified offline at plan time.
  - Over `entry_domains.jsonl`, `entries_recomputed` equals the count of every chained non-seal link.
  - A swapped below-base attestation exits 2 with `ENTRY REWRITE` and `CHAIN_HEAD_ATTESTATION`, **not** a signature
    or position error. The test splices `entry_domains.swapped-attestation.json`'s `attested_len`, `attested_head`
    and `signature` into `entry_domains.window.jsonl`'s first row, as runtime `anchored.rs:540-571` does, and runs
    with `--from-anchor entry_domains.anchor.json`. Nothing is hand-signed.
  - An in-window attestation with `attested_at + 1` exits 2 with `ENTRY REWRITE`, not a signature failure. This
    proves loop-1-before-loop-2.
- **Tests:**
  - **Attestation, a mutation per field:** `attested_len`, `attested_head`, `attested_at`, `digest_schema`,
    `issuer_aid`, `signature`, and `classification → Public`. Also a negative control: mutating the payload `tenant`
    alone is caught by the **signature** (v2) and the tenant-agreement check, not by the entry digest. Assert the
    marker `ATTESTATION TENANT MISMATCH` or a signature failure, so nobody later "fixes" the preimage by adding
    tenant.
  - **Certificate, a mutation per field:** `subject`, append to `erased`, append to `held`, move an id from `erased`
    to `held` (the collision v2 exists to stop, store doc `lib.rs:843-846`), reorder `erased`, `erased_at`,
    `chain_head`, `issuer_aid`, `signature`, and `classification → Internal`.
  - **Ordering:** in the anchored window, an attestation at `attested_len == base_len` with its classification
    relabelled, and one below base with its classification relabelled. Both exit 2 with `ENTRY REWRITE`.
  - **KAT:** the attestation rows in the four goldens and four bundles recompute. Unit-test `chain_attest_digest`
    against one row's wire `digest`.
- **Docs:** rustdoc.

### Phase 4: Uncovered refusal, `--allow-uncovered`, and no false green on any output

- **Status:** TODO. **Risk:** complex. A CLI flag and a refusal are both public contract.
- **Delivers:** an uncovered chained entry is REFUSED under `--issuer`, in the library, CLI and bundle (spec
  `:291`, "uncovered and REFUSED under `--issuer`"). `--allow-uncovered` (chain only, human only) prints the full
  diagnostic report instead, and **still exits 2**. The verifier gets a no-false-green audit of every banner and
  JSON path.
- **Depends on:** Phase 2, for `IssuerReport.uncovered`. It is code-independent of the Phase 3 preimages, but it
  ships after Phase 3 so attestations and certificates are never transiently "uncovered" on `main`.
- **Files:** `verify/src/verify.rs`, `verify/src/main.rs`, `verify/src/lib.rs`, and
  `verify/tests/entry_recompute.rs`, `verifier.rs`, `bundle.rs`, `multi_tenant.rs`.
- **Approach:**
  - **Library.** Refusal lives in the library, not only the CLI. At the end of `verify_authenticity_anchored`, after
    `covering == 0` (`verify.rs:999`, which keeps the runtime's precedence: attestation failures first, then
    uncovered), return `Err` if `!uncovered.is_empty()`, using the runtime's wording ("…cannot recompute…"). Add a
    `pub struct AuthOptions { pub allow_uncovered: bool }` and a `verify_authenticity_anchored_with(…, &AuthOptions)`.
    The existing three functions keep their signatures and the strict default, so an embedder (`lib.rs:9-15`) cannot
    get `Ok` over an uncovered entry without opting in. `bundle` never opts in. With the option set, the `Ok` report
    carries a non-empty `uncovered`, and rustdoc states that such a report is **not** an authentication; the CLI maps
    it to exit 2.
    - *Rejected:* the runtime's CLI-only placement (`main.rs:1409-1429`). Here the library is a supported surface,
      and a CLI-only gate would hand embedders and `bundle` a false green.
  - **CLI.**
    - `--allow-uncovered` is accepted only on `chain`, only with `--issuer`, never with `--json`.
    - Otherwise it is a usage error through the **existing `usage()` path**: `eprintln!` of the reason, then
      `usage()`, which prints the usage text and exits 1 (`main.rs:32-122`, `exit(1)` at `:121`), the same pattern
      as the requires-`--issuer` and chain-only checks (`:764-801`). No JSON is printed, including under `--json`:
      argument validation runs before `cmd_chain`, and `usage()` never writes stdout. It is **not** an `io_error`
      JSON.
    - "With `--issuer`" is stricter than the runtime, which silently accepts a no-op (OQ-3).
    - `bundle` and `erasure-cert` reject the flag ("chain-only"), like `--from-anchor`.
  - **Human report under `--issuer`.** Two lines are printed unconditionally, zero included: `entries recomputed: N
    (audit, attestation and erasure entry digests)` and `uncovered: N`. This follows the same "a coverage disclosure
    that vanishes at zero is indistinguishable from never measured" rule as `main.rs:464-470`. Multi-tenant per-tenant
    lines gain `entries recomputed`.
  - **Under `--allow-uncovered` with uncovered > 0: exit 2.** The banner contains neither `VERIFIED` nor
    `AUTHENTICATED` (note that `UNVERIFIED` contains `VERIFIED`, so it is excluded too). Proposed:
    `AUTHENTICITY NOT ESTABLISHED: N uncovered chained entr(y/ies) (--allow-uncovered diagnostic report)`. The full
    diagnostic report follows: each uncovered `(seq, tenant, kind, action)`, plus the report lines a green run
    prints after its banner (links, `entries recomputed`, attestation coverage, `unverified content`). The
    banner match at `main.rs:441-452` (the AUTHENTICATED arms under `--issuer`) is replaced, not printed alongside, and no report line may contain
    `VERIFIED`. Exit 2 rather than 0 because
    spec `:1677-1681` says a verifier claiming recompute coverage "MUST NOT fold them into a green claim", and this
    crate's README defines exit 0 as verified (`README.md:15`). This **deliberately diverges** from the runtime,
    whose `CHAIN VERIFIED + AUTHENTICATED`, exit 0 (`main.rs:1500-1529`) is the false green tracked in
    seam-runtime#1561. D-042 records it. With uncovered == 0 the flag changes nothing: the normal banner and exit 0.
    Resolves OQ-2.
  - **`--json`.** The shape is **unchanged**: no new keys, matching runtime `entry_recompute.rs:392-411`. A JSON
    green is unreachable with an uncovered entry, because the flag cannot pair with `--json` and the default
    refuses. Any rewrite or uncovered refusal arrives as `{"verified":false,"error":…}`, exit 2.
  - **No-false-green audit.** Enumerate every success print in `main.rs` and `bundle.rs` and add a test per path.
    1. `CHAIN AUTHENTICATED` (single tenant);
    2. `CHAIN AUTHENTICATED … per tenant`;
    3. `WINDOW AUTHENTICATED`;
    4. `WINDOW AUTHENTICATED … per tenant`;
    5. the JSON `"authenticated":true` (top-level `:378-384`, and per tenant `:367-373`);
    6. `EVIDENCE BUNDLE VERIFIED`;
    7. `ERASURE CERTIFICATE VERIFIED`.

    Path 7 is a signature check over a certificate document, not a chain entry. A4 does not touch it, and the README
    must say so explicitly (OQ-7).
- **Edge cases:**
  - Uncovered in one tenant of a multi-tenant window refuses the whole call ("there is no such thing as some tenants
    authenticated", `verify.rs:1041`).
  - `--strict` does not change uncovered behaviour; the runtime asserts the same (`entry_recompute.rs:329-330`).
  - Without `--issuer`, an unmodelled kind is still disclosed and not refused. Integrity verdicts are unchanged.
  - A rewrite takes precedence over uncovered: it is immediate in loop 1.
- **Acceptance (falsifiable):**
  1. An unknown action exits 2 under `--issuer`, under `--issuer --strict`, and under `--issuer --json`, where it
     emits `"verified":false` and the error contains "cannot recompute".
  2. `--issuer --allow-uncovered` on a stream with one uncovered entry exits **2**, prints `uncovered: 1` and that
     entry's `(seq, tenant, kind, action)`, and its output contains neither the substring `VERIFIED` nor
     `AUTHENTICATED`. On a genuine `entry_domains.jsonl` (uncovered 0) the same flags exit 0 with the normal banner.
  3. `--allow-uncovered --json` exits 1 with empty stdout (the `usage()` path). `--allow-uncovered` without
     `--issuer` exits 1. `bundle … --allow-uncovered` exits 1.
  4. An unknown kind with chain fields and no payload exits 2 under `--issuer`, and also exits 2 under
     `--allow-uncovered`, with the diagnostic report.
  5. `fact_appended` exits 2 under `--issuer`. The fixture for this is the stream with one row's action relabelled;
     its digest is the fact checksum, so it must not be judged as management.
  6. A bundle whose window carries an uncovered entry exits 2 at step 2.
  7. The JSON on a genuine `entry_domains.jsonl` run is byte-for-byte the same shape as before: there is no
     `entries` key and no `uncovered` key.
- **Tests:** each criterion, on both transports where the parser is involved. Mutation checks:
  - Removing the library refusal must turn the embedder test red (`verify_authenticity` returns `Err`), not only the
    CLI test.
  - Removing the banner switch, or mapping the diagnostic run to exit 0, must turn criterion 2 red.
- **Docs:** usage text (`main.rs:32-122`), and `lib.rs` crate docs (`:17-55`).

### Phase 5: Docs, the spec pin header, decisions, and version

- **Status:** TODO. **Risk:** simple.
- **Delivers:** documentation that states what this build now does.
- **Depends on:** Phases 1–4.
- **Files:**
  - `verify/README.md`;
  - `verify/docs/seam-event.v1.md` (**pin header only**);
  - `verify/DECISIONS.md`;
  - `verify/src/lib.rs` docs;
  - `verify/Cargo.toml` (`version = "0.5.0"`);
  - `CHANGELOG.md` (repo root), an entry under `## Unreleased` (`CHANGELOG.md:17`);
  - `verify/proto/seam/event/v1/seam_event.proto`, *pending OQ-5*.
- **Approach:**
  - **README.**
    - Rewrite `:88-91` ("never recompute"). The integrity-mode `unverified content` paragraph (`:74-96`) stays true
      for plain `chain`; add that `--issuer` refuses such a link as uncovered.
    - Add a "Payload binds to kind" paragraph next to `:68-72`.
    - Under AUTHENTICITY (`:98-157`), add the entry recompute, the classification binding, the uncovered refusal,
      `--allow-uncovered` and the new report lines.
    - Note the absence of `chain --bridge` and that it is out of scope.
    - **Named exception for the entry preimages**, next to the existing one for `seam-commitment-digest.v2.md`
      (`README.md:34`), and qualify "Everything it does is specified in `docs/`" (`:38-40`): the (b′) action-entry,
      `chain-attest-entry.v1` and `erasure-cert.v2` framings, the domain table and the classification map are
      transcribed from seam-runtime `crates/seam-verify/src/entry.rs` @ `37576658` until the spec carries them
      (seam-runtime#1561; D-043).
    - **Forward compatibility.** No domain is carried on the wire, and the runtime plans no discriminator (runtime
      answer 8). A future domain bump (e.g. `chain-attest-entry.v2`) therefore reads as `ENTRY REWRITE` to this
      version, not as uncovered. Say so under "What it cannot tell you".
    - **Ordering.** On a stream with more than one defect, this build may name a different first defect than the
      runtime's verifier (Phase 2); the exit code agrees.
    - `--allow-uncovered` exits 2, unlike the runtime's verifier (Phase 4).
    - An unchained `DECISION_SEALED` that is non-v4 or lacks `ciphertext_digest` is refused here (exit 2); the
      runtime's verifier skips it (it checks only events carrying payload, digest and checksum, runtime
      `main.rs:891-894`). Spec `:289`, `:291-292` and `:1659` back the refusal.
  - **Spec header.** Replace "NOT YET IMPLEMENTED by this repo's `verify/` … Parity is seam-sdk#316" (`:6-7`) with an
    "implemented by `verify/` 0.5.0 (seam-sdk#316)" line. **Do not touch the body.** Run
    `python scripts/check_vendored_spec.py --from local:../seam-runtime`. The PIN regex only reads the first line
    (`scripts/check_vendored_spec.py:107-111`), so the header edit is safe. The gate proves it.
  - **DECISIONS.**
    - D-041: the kind/payload binding in integrity mode.
    - D-042: the entry recompute; library-level refusal (stricter than the runtime's CLI-only placement);
      `--allow-uncovered` semantics, including **exit 2 under a banner with neither `VERIFIED` nor `AUTHENTICATED`**,
      a deliberate divergence from the runtime's false green (seam-runtime#1561) on the authority of spec
      `:1677-1681`; the refusal itself cited from spec `:291`; the `DECISION_SEALED` arm kept stricter than the
      runtime's link-only keying (Phase 2); the multi-defect ordering difference; and the `--json` shape unchanged.
    - D-043: **the scoped carve-out** from D-035's clean-room claim, modelled on the README's named exception
      (`README.md:34`). It names runtime commit `37576658` (`crates/seam-verify/src/entry.rs`) as the source of the
      three preimages, the domain table and the classification map; records the code-over-spec readings (absent
      `session_id` ≡ `""`; `context_recalled`'s actor absent, not "empty" as spec `:137` says); names
      seam-runtime#1561 as the spec fix; states that validation is against Phase 0's runtime-produced vectors; and
      **expires** when the vendored spec carries the tables. The tripwire test (Phase 2) fails at that re-pin with
      "retire the carve-out".
  - **Version.** `0.4.0 → 0.5.0`: breaking `IssuerReport` fields and new refusals. Publishing is `workflow_dispatch`
    only (`.github/workflows/publish.yml:524-528`), so it is an owner step after merge.
  - **CHANGELOG.** Under `## Unreleased`: `seam-verify` 0.5.0, the new refusals, `--allow-uncovered` (exit 2), and the
    breaking `IssuerReport` change.
- **Acceptance (falsifiable):**
  - `check_vendored_spec.py` exits 0.
  - `CHANGELOG.md`'s `## Unreleased` section names `seam-verify` 0.5.0.
  - `grep -n "never recompute\|NOT YET IMPLEMENTED" verify/README.md verify/docs/seam-event.v1.md` returns
    nothing.
  - Every README command block reproduces: run each shown command against `entry_domains.jsonl` and diff the
    printed labels.
- **Tests:** an optional doc test pins the README's `entries recomputed` and `uncovered` lines to `main.rs` output.
  It follows the precedent of `python/tests/test_event_field_manifest_gate.py` pinning CLAUDE.md prose.
- **Docs:** this phase.

### Bridge mode: scoped out

This crate has no `chain --bridge` (evidence: `main.rs:37-40`, `:695-748`; no match in `verify/`). The runtime's
bridge (`origin/main:crates/seam-verify/src/bridge.rs`, k8s P16) has its own A4 obligations: both streams recompute,
`UNCOVERED ENTRY` is refused outright, and `MOVE-IN NOT YET ATTESTED` (`tests/bridge.rs:320-353`, `:731`). They have
no surface here to attach to. Porting bridge mode is a separate feature, not A4 parity. Phase 5 states this in the
README.

## Long-term posture (one-way doors)

- **New refusals.** These are public trust claims, each retractable only by a breaking release:
  - `KIND/PAYLOAD MISMATCH` and `ADVISORY EVENT WITH CHAIN FIELDS`, in **integrity** mode;
  - `ENTRY REWRITE` and the uncovered refusal, under `--issuer`.

  Streams that verified before can now fail: a producer emitting a known kind without its payload, a chained
  `chain_anchor`, or `fact_appended`. The runtime refuses all of them too.
- **No relaxation of the `DECISION_SEALED` arm.** Narrowing it to links, as the runtime does, would stop refusing an
  unchained seal with `schema_version != 4` or no `ciphertext_digest` (`verify.rs:773-798`). The spec does not ask
  for that (Phase 2), so it is not done, and a test pins the refusal. Relaxing it later would itself be a one-way
  door and needs its own decision.
- **New CLI flag `--allow-uncovered`.** Its semantics (chain-only, `--issuer`-only, never `--json` via the `usage()`
  path, exit 2 under a banner with neither `VERIFIED` nor `AUTHENTICATED`) are frozen at first release.
- **No new exit codes.** The 0/1/2 taxonomy holds. **No new JSON keys,** to match the runtime. Adding
  `entries_recomputed` to JSON later is additive and reversible; removing a key is not, so none is added now.
- **Library API.** New pub fields on `IssuerReport`, a new `Uncovered` struct, `AuthOptions`, `*_with` functions, and
  `check_kind_payload`. Mark `IssuerReport`, `Uncovered` and `AuthOptions` `#[non_exhaustive]` now. This release
  breaks anyway, and the attribute makes later additions non-breaking.
- **Preimage framings are permanent** once a release accepts streams under them. A domain bump upstream with no wire
  discriminator turns into a false `ENTRY REWRITE` here, and the runtime plans no discriminator (OQ-RT-8); the
  README discloses it.
- **Provenance carve-out (D-043).** Retiring it is cheap (re-derive from the spec, the tripwire forces it); the
  framings it ships are the permanent part.

## Enterprise concerns

- **False red in an auditor's hands is the dominant risk.** Mitigations:
  - every committed runtime-produced stream must stay green (8 streams plus Phase 0);
  - each refusal is pinned by a test that was driven red first;
  - markers match the runtime's, so a differential case can be added on its side.
- **Independence.** The new code is SHA-256 and framing over bytes already parsed, so no dependency is added.
  `cargo tree -e normal` and `scripts/check-independence.sh` must stay green. This is CI job `verify`,
  `.github/workflows/ci.yml:523-560`.
- **Provenance honesty (OQ-1).** The preimages are transcribed from runtime code, so the README's named exception
  and D-043 say so until the spec carries them, and the tripwire forces the re-derive. Overstating clean-room
  provenance is the kind of oversell the README's "What it cannot tell you" section exists to prevent.
- **Performance.** Hashing each chained body once is O(n) and negligible beside the existing per-tenant `events`
  clone in `verify_authenticity_by_tenant` (`verify.rs:1052-1056`).
- **Security of output.** `kind` and `action` reach the uncovered listing from the wire. Escape them through `q()`
  (`main.rs:142`) on any JSON path; on human paths, print with `{:?}`.

## Open questions

**OQ-1: RESOLVED → (b) ∥ (a), decided by Fable at plan review; owner input not needed. Where do the three
preimages come from?** The vendored spec delegates the
`AUDIT_ENTRY` table to the runtime's private `entry.rs`, and it does not carry the action-entry, `chain-attest-entry.v1`
or `erasure-cert.v2` framings, nor the classification maps (see Context). The options:

- **(a) Spec first.** Ask seam-runtime to add the normative preimages and tables to `docs/specs/seam-event.v1.md`,
  re-pin, then implement Phases 2–3 from the spec. This preserves D-035 and README `:38-40`. It costs a runtime round
  trip.
- **(b) Transcribe now.** Port from `entry.rs` plus the store, prove the port against Phase 0's runtime-captured
  vectors, scope D-035 down in a new decision, and re-derive when the spec lands.
- **(c) Local doc.** Write an unpinned `verify/docs/entry-digests.md` from the runtime code. *Not recommended:* it is
  a second, unchecked spec.

**Decision: (b) and (a) in parallel.**
- **(b) now:** Phases 2–3 transcribe the preimages, the domain table and the classification map from runtime
  `entry.rs` @ `37576658`, validated against Phase 0's runtime-produced vectors (not against a second transcription).
- **Carve-out:** D-043 records a scoped exception to D-035, modelled on the README's named exception for
  `seam-commitment-digest.v2.md` (`README.md:34`). It names the runtime commit and seam-runtime#1561, and expires
  when the spec carries the tables.
- **Tripwire:** a test fails with "retire the carve-out" once the vendored spec contains
  `seam.audit.management.v1` (no counts, no line numbers).
- **(a) in parallel:** the spec fix is seam-runtime#1561, already filed; this plan does not file it.
- **Owner checkpoint:** none before merge. `publish-verify` is `workflow_dispatch` only, so the owner's dispatch is
  the gate before anything reaches partners.

The remaining questions have defaults. Each is pending confirmation unless marked resolved.

- **OQ-2: `--allow-uncovered` exit code. RESOLVED at plan review: exit 2.** The diagnostic report is printed under a
  banner with neither `VERIFIED` nor `AUTHENTICATED`. Authority: spec `:1677-1681` ("MUST NOT fold them into a
  green claim") and README `:15` ("exit 0 = verified"). The runtime's exit 0 is its false green
  (seam-runtime#1561), deliberately not mirrored (Phase 4, D-042).
- **OQ-3: `--allow-uncovered` without `--issuer`.** Default: usage error, exit 1, matching this crate's
  `--from-anchor requires --issuer` style (`main.rs:764-777`). The runtime accepts it as a no-op; a differential case
  would disagree only on this degenerate input.
- **OQ-4: placement of the uncovered refusal.** Default: the library, with an opt-in `AuthOptions` (Phase 4). This is
  stricter than the runtime, on purpose, as in D-036.
- **OQ-5: re-vendor `verify/proto/seam/event/v1/seam_event.proto`.** It is stale. It lacks tags 24–27 that `wire.rs`
  already decodes, and it differs from `origin/main:crates/seam-api/proto/seam/event/v1/seam_event.proto` from line 1,
  yet README `:337` calls it "the canonical protobuf schema". Default: re-vendor byte-verbatim in Phase 5, and add it
  to `check_vendored_spec.py`'s `VENDORED` list only if the script grows a non-Markdown header mode. Otherwise
  record the commit in README.
- **OQ-6: pinning the vendored jsonl goldens.** They are verbatim by comment only (`tests/authenticity.rs:3-5`).
  Default: sha256 assertions in `entry_vectors.rs` (Phase 0), plus a provenance header. A cross-repo pin waits until
  the runtime commits these vectors itself (Cross-repo, ask 2).
- **OQ-7: anchor documents and `erasure-cert`.** Default: no entry recompute for the `--from-anchor` /
  `--expect-anchor` document or the `erasure-cert` subcommand. They are not window links, and (b′) speaks of chained
  bodies in the stream. The README says so explicitly.
- **OQ-8: dedup identity of presence-only payloads. RESOLVED at plan review.** Presence is stored as booleans, and
  `with_identity` re-encodes each present unmodelled slot as an empty sub-message on **both** transports, so one
  event has one identity over JSON and protobuf; a Phase 1 test pins the collapse.

**Preimage questions for the seam-runtime-f8 session.** Answered by that session at runtime `37576658` ("runtime
answer N" below). Runtime answers cite the runtime's spec lines; the vendored copy
is offset by its pin header, so the line numbers below are the vendored file's. Resolutions are inline.

1. **OQ-RT-1.** Will `docs/specs/seam-event.v1.md` carry, normatively:
   - the action-entry preimage: seven `u32le`-length-framed strings `domain, action, tenant, namespace,
     session_id, subject, reason`, then **unframed** `u64le occurred_at`, then `frame(actor)` only when present;
   - all eight domain strings and the closed action→domain table;
   - the `chain-attest-entry.v1` and `erasure-cert.v2` framings;
   - the action→classification map and the per-kind fixed labels?

   (b′) currently points third parties at a private file.
   **Resolved (answer 1):** not yet. The spec carries (b′) as one paragraph pointing at `entry.rs`; only three domains
   are spelled; the framing is code-only (`entry.rs:84-104`). The runtime reports the doc defect; it is
   seam-runtime#1561. Handled by OQ-1 / D-043.
2. **OQ-RT-2.** Are an `AUDIT_ENTRY`'s envelope `tenant`, `namespace`, `session_id` and `occurred_at` always the exact
   values digested? This covers the move writers ("chain the identical shape through their own backend methods",
   `lib.rs:5028-5029`), the system partition, and any history import, re-tag or re-drive path. Is there any writer
   where the wire envelope is set after the digest?
   **Resolved (answer 2):** envelope == digested values for every traced writer (`seam-store/src/lib.rs:3259-3273`;
   move writers `lib.rs:4864-4880`, `:4969-4985`; system partition `lib.rs:3363`, `:3382-3384`; `session_id` always
   `Some` at `event.rs:1608`). Residual: not every `audit_action` caller was traced (Phase 2 edge case).
3. **OQ-RT-3.** `session_id`: is "absent ≡ `""`" normative for the preimage? The store always writes `Some("")`
   (`event.rs:1608`).
   **Resolved (answer 3):** code-only (`entry.rs:91`); the spec is silent. Implemented per code, recorded under D-043.
4. **OQ-RT-4.** `actor`: `None` and `Some("")` produce different digests. Can any writer produce `Some("")`, for
   example an empty token `sub`? The spec says `context_recalled`'s actor "is empty" (`seam-event.v1.md:137`); does
   that mean absent? The code passes `None` (`lib.rs:4742`).
   **Resolved (answer 4):** it means absent; spec `:137` "empty" is a spec error (seam-runtime#1561). `Some("")` is not
   forbidden and digests differently. Hash per code; Phase 2 tests that `Some("")` does not match the `None` digest.
5. **OQ-RT-5.** Is the classification comparison exact bytes (`"Internal"`, `"Confidential"`, `"Pii"`), with no case
   folding? Is the `AUDIT_ENTRY` action→label map normative, or derived from `AuditReason` and free to change per
   action? Today each action is written with exactly one reason variant (`entry.rs:64-66`).
   **Resolved (answer 5):** exact, case-sensitive literal match (`entry.rs:68-72`, `:173`). The shape is normative
   (spec `:291`); the map is code-only: `execute.scope_deny` and `boundary.data_flagged` → `Confidential`,
   `gdpr_erasure` → `Pii`, all else `Internal`. Under D-043.
6. **OQ-RT-6.** `fact_appended` has no production writer: only `conformance.rs:98-129` and backend test call sites.
   Is "uncovered, therefore refused under `--issuer`" intended to stay true if a production fact-append path ever
   chains it?
   **Resolved (answer 6):** `fact_appended` stays uncovered (`entry.rs:50-54`); its only writer is a test fixture.
7. **OQ-RT-7.** `entry.rs:155` says `Body::Uncovered` is "Reported, never a failure", while `main.rs:1415-1428`
   refuses it. Is the doc stale?
   **Resolved (answer 7):** yes, stale; `main.rs:1415` refuses under `--issuer`.
8. **OQ-RT-8: forward compatibility.** Neither domain is carried on the wire, so a future `chain-attest-entry.v2`
   (for example, tenant in the preimage after U-RT-3 Phase 4, store doc `lib.rs:5162-5163`) or a
   `management.v2` would read as `ENTRY REWRITE` to a verifier that predates it, rather than as uncovered. Will a
   domain bump come with a wire discriminator or a new action/kind, so older verifiers refuse it as uncovered?
   **Resolved (answer 8):** no discriminator is planned. A domain bump reads as `ENTRY REWRITE` to an older verifier.
   The README discloses it (Phase 5).
9. **OQ-RT-9.** Under `--allow-uncovered` with uncovered > 0, the runtime prints `CHAIN VERIFIED + AUTHENTICATED`
   and exits 0 (`main.rs:1500-1529`). Is that consistent with "no false green"? Would the runtime adopt a distinct
   banner (OQ-2)?
   **Resolved (answer 9):** a false green that conflicts with spec `:1678-1680`; a runtime defect (seam-runtime#1561).
   Do not mirror. This crate exits 2 (OQ-2).
10. **OQ-RT-10: spec consistency.** The Chain bullet (`:797-799`) omits `CHAIN_HEAD_ATTESTATION` from the chained
    kinds. Also confirm the `:118` "never reject the row" MUST applies to rendering consumers, not to `--issuer`
    verification.
    **Resolved (answer 10):** both are spec errors. `:797-799` omits `CHAIN_HEAD_ATTESTATION` (spec `:78` and
    `entry.rs:178-183` say it is chained); `:118` "never reject" is for delivery consumers, and `:1677-1681`
    (disclose-or-refuse, `--strict` MAY refuse) governs verifiers. **One correction:** the answer's "spec never says
    `--issuer` refuses uncovered" is wrong. Spec `:291` says the uncovered body is "REFUSED under `--issuer`". The
    refusal is cited from `:291`; `:1677-1681` is cited only for the disclosure rule and the `--strict` MAY.

## PR strategy

Two PRs, each passing the full local gate before push (memory: ci-spend-local-first):

1. **PR A: Phases 0 + 1.** Vectors (captured from a `37576658` export) and the kind/payload binding. It ships a self-contained,
   fully spec-backed refusal and absorbs the wide synthetic-test churn on its own, so the trust-claim PR's diff
   stays reviewable.
2. **PR B: Phases 2–5.** The recompute, the uncovered refusal, the D-043 carve-out and its tripwire, docs, the
   CHANGELOG entry and the 0.5.0 bump. OQ-1 is resolved, so PR B can follow PR A directly. It must land as one
   unit. Shipping Phase 2 without Phase 4 puts an `--issuer` on `main` that counts uncovered
   entries but still reports `AUTHENTICATED`, which is the false green #316 exists to remove. Shipping Phase 4
   before Phase 3 would refuse every genuine stream, since every attestation would be uncovered.

A crate release (`publish-verify`, `workflow_dispatch`) follows PR B as the owner checkpoint: nothing reaches
partners until the owner dispatches it.

## Cross-repo

No runtime **code** work is required for parity. **seam-runtime#1561** already tracks the two runtime-side defects
this plan depends on: the runtime's `--allow-uncovered` false green, and the spec omitting the (b′) preimage. This
plan references it and files nothing. The gaps:

1. **Spec gap (OQ-1, OQ-RT-1; seam-runtime#1561).** The spec text for (b′) delegates its normative content to
   `seam-runtime/crates/seam-verify/src/entry.rs`. That repo is private, so the published spec is insufficient to
   build an independent verifier. This contradicts the spec's own status as the integration surface (spec `:33-38`).
   The related spec-text errors (`:137` "empty" actor, `:797-799` chained kinds) belong with the same fix.
2. **No committed vectors.** The runtime's A4 tests build their streams in process (`entry_recompute.rs:60-188`,
   `seam_entries_e2e.rs`) and commit no stream. Committing `entry_recompute`'s stream under
   `crates/seam-verify/tests/goldens/` would let this repo vendor it byte-verbatim like the existing four goldens,
   instead of capturing from an export.
3. **The differential harness has no A4 cases.** `tests/differential.rs`'s case list (`:698-974`) has no entry
   rewrite, kind/payload mismatch, advisory-with-chain-fields or uncovered case, and its diagnosis map
   (`:1170-1197`) has no A4 markers. Once PR B merges, the runtime's `SEAM_SDK_REF` bump (`ci.yml:68-80`) is the
   natural point to add them. Until then, parity is asserted only by this repo's tests against runtime-captured
   bytes. Keep those cases **single-defect**: on multi-defect streams the two verifiers may name different first
   defects (Phase 2), on `--allow-uncovered` they deliberately disagree on the exit code (Phase 4), and an unchained
   non-v4 or commitment-less seal is refused here but skipped by the runtime (Phase 2; runtime `main.rs:891-894`).
4. **Stale doc comment** at `entry.rs:155` (OQ-RT-7, confirmed stale by runtime answer 7).
5. **Sibling note.** `seam-connectors` ships its own chain verifiers (`sdk/{rust,go,python,ts}/…/authenticity.*`).
   Its synthetic goldens (`contract/golden/seam-event.v1/chain/*.jsonl`) do **not** recompute under the A4 preimages:
   an offline probe shows `admit.compat_reject` and certificate rows MISMATCH. That repo's A4 adoption is its own
   decision; it does not block this plan.
6. **Store location.** The issue brief says the store side "lives under crates/seamd". It actually lives in
   `crates/seam-store/src/lib.rs` and `event.rs`; `seamd` is only a dev-dependency of the runtime verifier.

## Plan review

**Round 1: REVISE** (9 items, plus Fable on OQ-1). Applied at runtime `origin/main` `37576658`; each change was
re-verified against `verify/` and `git show origin/main:` before it was written.

- **Fable on OQ-1:** resolved as (b) ∥ (a) without owner input. Transcribe from runtime `entry.rs`, validated against
  Phase 0 vectors; D-043 carve-out modelled on `README.md:34`, naming `37576658` and seam-runtime#1561, expiring when
  the spec carries the tables; a tripwire test on `seam.audit.management.v1`. Phases 2–3 unblocked; the owner
  checkpoint is the `publish-verify` dispatch. Runtime answers 1–10 folded into OQ-RT-1..10 as resolved, with
  citations, and the README discloses the no-discriminator consequence. Addendum: hash per code for
  `context_recalled`'s absent actor (spec `:137` says "empty"), test that `Some("")` does not match, and record the
  spec error under D-043.
- **1.** `--allow-uncovered` with uncovered > 0 now exits 2, under a banner with neither `VERIFIED` nor
  `AUTHENTICATED`, with the full diagnostic report (spec `:1677-1681`). Phase 4 acceptance rewritten; the runtime
  `entry_recompute.rs` citation dropped as justification; recorded in D-042. OQ-2 resolved.
- **2.** The refusal is cited from spec `:291`; `:1677-1681` only for disclosure and the `--strict` MAY. Runtime answer
  10's "spec never says" is noted as wrong.
- **3.** Covered by the OQ-1 decision.
- **4.** Phase 0 captures the swapped attestation (`anchored.rs:540-571`, signed with `ISSUER_SEED`) instead of
  hand-signing, and notes the window is cut from `two_anchor_stream` (`anchored.rs:80`).
- **5.** Presence is booleans; `with_identity` (`wire.rs:873-947`) re-encodes an empty sub-message on both
  transports; a cross-transport collapse test is added. OQ-8 resolved.
- **6.** `--allow-uncovered --json` goes through `usage()` (exit 1, no JSON; `main.rs:121`, `:764-801`), not
  `io_error`.
- **7.** On inspection the seal-arm narrowing is **not** required by the spec (clause (c) `:291-292` and `:1659` are
  unqualified), so today's refusal of an unchained non-v4 or commitment-less seal is kept, pinned by a test, and
  listed under one-way doors as a deliberate non-relaxation.
- **8.** The multi-defect ordering difference from the runtime (`main.rs:705-722`) is documented; differential cases
  stay single-defect.
- **9.** Phase 5 adds the CHANGELOG `Unreleased` entry; Phase 1 adds the `bundle` CLI pass over all 4 fixtures and
  the chained-`chain_anchor` bundle refusal; the runtime `authenticity.rs` citation is fixed to `:302-319`; the
  oracle discussion rejects `golden_chained_events_json.json` (placeholder digests).
- **PR strategy:** PR B is no longer gated on OQ-1; it carries the carve-out, tripwire and CHANGELOG.

### Round 2 — REVISE (4 precise items), applied without a third round

The items were mechanical and named their own fix; none turned on a requirement ambiguity.
- Phase 2: the uncovered assertion is now about the `AUDIT_ENTRY` members, because attestations and the
  certificate are also uncovered until Phase 3.
- Phase 4: the replaced banner is the AUTHENTICATED match at `main.rs:441-452`, not the `:451` fallback.
- The unchained non-v4 or commitment-less seal divergence (refused here, skipped by the runtime) is added to the
  README disclosures (Phase 5) and to cross-repo item 3, and kept out of the differential cases.
- The spec citation for the no-green rule is unified to `:1677-1681`.
Round 2 confirmed decision 7 (keep today's unchained-seal refusal) against spec `:289`, `:291-292` and `:1659`, and
`verify.rs:773-803`. Verdict after round 2: **SOUND**.
