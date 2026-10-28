# Explain a sealed record: `DecisionRecordView` policy and seal attestation (B-RECORD-EXPLAIN, SDK half)

> **Issue:** [#273](https://github.com/zer07labs/seam-sdk/issues/273) (register ID B-RECORD-EXPLAIN; consumer
> seam-mcp P4b, `seam-mcp/plans/post-onboarding.md:613-637`; epic zer07labs/seam-mcp#50).
> **Unblocked by:** seam-runtime PR #1535 (`7d538c54`, "release train 0.61.0: GetDecision explains the seal",
> seam-runtime#1361 train A). The BSR module `buf.build/zer07labs/seam` carries it, and `make generate` has
> pulled it: the local stubs are current.
> **Contract source:** `seam-runtime/crates/seam-api/proto/seam/api/v1/seam.proto` at `7d538c54`
> (`DecisionRecordView` :1064-1107, `SealAttestation` :1109-1123, `SealAttestationAvailability` :1125-1144,
> `SealReason` :1146-1157, `PolicyEnforcement` :742-745 with its doc block above). The generated stubs win
> over this summary: `python/seam_sdk/_gen/seam/api/v1/seam_pb2.pyi:579-605` (`SealAttestation` :607-616,
> enums :43 and :53), `ts/gen/seam/api/v1/seam_pb.ts:2043-2176` (enums from :3870 and :3934).
> **Anchors** are true at seam-sdk `b77609a`. **Re-check them before editing:** the bot's
> `chore(release): v0.61.0` commit `32ab80d` has since landed on `main` (see *Status*), so rebase first.

## Status

Phases 1-4 DONE (2026-10-28), finalized; Phase 5 (release 0.61.1, consumer messages) runs post-merge.

**Release state at plan time — read before Phase 5.** Runtime 0.61.0's `dispatch-sdk` fired while this
plan was being written. `release-on-runtime.yml` saw `main` (`b77609a`) green, because that commit's CI
ran before the BSR push, so it stamped and tagged **`v0.61.0` / `go/v0.61.0` at `32ab80d`**. That commit's
own CI regenerates from the BSR, so `check-contract` exits 6 there (verified locally: the same seven fields
and twelve enum values below), `ci-ok` goes red, and `publish.yml`'s "CI is green for this commit" job refuses.
**Confirmed at 17:51Z: v0.61.0 is tagged and was not published.** The `ci` runs on `main`, `v0.61.0` and
`go/v0.61.0` failed, and so did `publish` run 40739395352. This is exactly what happened to v0.50.0
(`COMPATIBILITY.md:119-125`). `main` stays red until this plan's PR merges. Phase 5 handles it.

## Context

**Why.** seam-mcp P4b's `explain_decision(decision_id)` explains a sealed record after the fact. Until
0.61.0 the record view carried only structural columns (`DecisionRecordView` fields 1-8,
`contract/field-manifest.txt:267-274`). The runtime has now added:

| Wire | Shape | Proto semantics (cited) |
|---|---|---|
| `DecisionRecordView.policy_version = 9` | `string` | STAGED policy, digest-bound; empty on a solo, legacy or unpoliced record (`seam.proto:1073-1078`). |
| `DecisionRecordView.policy_rules_digest = 10` | `bytes` | rules digest that actually BOUND; length 0 means none bound, otherwise 32 bytes (`:1079-1083`). |
| `DecisionRecordView.policy_enforcement = 11` | `PolicyEnforcement` | DERIVED from the record's digest-bound columns, **always present** (including after crypto-shred and archive). It does **not** withhold after eviction, so the immediate response's meaning 3 cannot occur here (`:1084-1095`). |
| `DecisionRecordView.seal_attestation = 12` | `SealAttestation` | Chain-bound but **not client-verifiable**: not a TCT input, so `verify_decision` does not cover it. Absent only on a runtime older than the field. The payload is meaningful only under `RECORDED`, and a clearance refusal is `CLEARANCE_DENIED`, never an RPC error (`:1096-1106`). |
| `SealAttestation.availability = 1` | `SealAttestationAvailability` | **Growth policy:** an unrecognised value, *including UNSPECIFIED*, MUST be read as WITHHELD, never RECORDED (`:1112-1114`). The server never emits UNSPECIFIED (`:1124`). |
| `SealAttestation.seal_reason = 2` | `SealReason` | Meaningful only under RECORDED, UNSPECIFIED otherwise. An unrecognised value reads as unknown (`:1114`, `:1117`). |
| `SealAttestation.collective_outcome = 3` | `optional CollectiveOutcome` | Present **iff** RECORDED **and** COMMIT, describing the sealing round (`:1119-1122`). |

The availability states, verbatim in substance (`seam.proto:1126-1143`):
- `RECORDED`: the commitment opened and carries an attestation.
- `NOT_RECORDED`: it opened and carries none, because an older runtime sealed it. "For such a record, the
  seal-time immediate response is the only source."
- `KEY_UNAVAILABLE`: crypto-shredded. "The structural columns and `policy_enforcement` still answer."
- `ARCHIVED`: the ciphertext is in cold storage; cold-replay the archive bundle.
- `CLEARANCE_DENIED`: the caller's `x-seam-clearance` is below the decrypt floor.
- `UNAVAILABLE`: a transient store or KMS fault (a retry may succeed), or an attestation this runtime cannot
  decode.

> **Phase 3 note (2026-10-28).** A first live run reported `RECORDED` on "0.61.0". That build came from the
> shared seam-runtime checkout, which held uncommitted train-B work on `feat/1361-train-b`, so it measured
> train B, not 0.61.0. seam-runtime-f8 confirmed that `7d538c54` has no attestation writer. The live lanes
> were re-run on a seam-grpc built from a clean `git archive 7d538c54` export, and the paragraph below
> stands. **Lesson:** build a pinned runtime from an export or a worktree, never from the shared checkout.

**Runtime timeline.** Train A (0.61.0) authors **no** attestations. Every live record reads `NOT_RECORDED` or
another non-RECORDED state until train B (0.62.0) writes them. Train B has **no wire change**: its release
checklist says "there is no wire change, so the BSR push is a no-op label move"
(`seam-runtime/plans/1361-record-explain.md`, Phase 2 release checklist item 3). Participant verdicts stay
on `GetCommitmentProof` → `commitment.explanation`, and `ReplayView` is unchanged. seam-mcp agreed to both in
seam-mcp#123 (merged `3b8ca54`).

**What the SDK has today.**
- **Python** returns the raw message: `SeamClient.get_decision` → `pb.DecisionRecordView`
  (`python/seam_sdk/client.py:1113-1142`) and `AsyncSeamClient.get_decision` (`python/seam_sdk/aio.py:854-868`).
  After regeneration the new fields are already *reachable* as raw attributes. What is missing is the
  presence-aware, fail-closed *reading* this SDK provides for every comparable field.
- **TypeScript:** `SeamClient.getDecision` returns the generated `DecisionRecordView` (`ts/src/client.ts:1526-1534`),
  which is root-exported as a type (`ts/src/index.ts:92`, schema :113).
- **The decoders this plan extends:**
  - `policy_enforcement_of` (`python/seam_sdk/_policy.py:163-199`) / `policyEnforcementOf` (`ts/src/client.ts:576-590`)
    take `DecisionResponse | SessionStep` and return `None`/`undefined` iff the field is absent.
  - `collective_outcome_of` (`python/seam_sdk/_collective.py:99-173`) / `collectiveOutcomeOf` (`ts/src/client.ts:401-423`)
    raise `UnknownCollectiveVerdictError` (`python/seam_sdk/errors.py:104-128`, `ts/src/client.ts:291-301`)
    on UNSPECIFIED or any unknown verdict. That follows `CollectiveVerdict`'s growth policy: "clients MUST
    treat as failure → FailPolicy" (`seam.proto:556`).
- **Stale prose this release makes false:** all four sites say `GetDecision` does not carry
  `policy_enforcement` / `collective_outcome`:
  - `_policy.py:28-40`;
  - `_collective.py:8-12`;
  - `ts/src/client.ts:500-504`;
  - the `PolicyEnforcement.enforced` "THREE meanings" blocks (`_policy.py:129-154`, `ts/src/client.ts:443-466`),
    whose meaning 3 does not occur on a record view.
- **Go, Java and Kotlin have no transport and no client.** They are crypto, identity, routing and DPoP shims only
  (`go/README.md:3-6`; `README.md:135-138`, "Go/Java/Kotlin are standalone crypto shims (no generated transport
  in-package)"; status table `README.md:657-659`). No hand-written code in those trees touches any
  coordination message (`grep` over `go/ java/ kotlin/` for `GetDecision|CollectiveOutcome|PolicyEnforcement`
  finds nothing). The precedent for a new contract field is a single sentence: "Go, Java and Kotlin carry the
  generated fields" (`CHANGELOG.md:127`, the 0.57.0 `stream_id` entry). `collective_outcome` (C5) and
  `effective_threshold` were likewise decoded in Python and TS only.

**The gate.** `STREAM=1 EVENTS=1 ./scripts/check-contract.sh` exits **6** with exactly seven fields
(`DecisionRecordView/{policy_enforcement,policy_rules_digest,policy_version,seal_attestation}`,
`SealAttestation/{availability,collective_outcome,seal_reason}`) and twelve enum values
(`SealAttestationAvailability#…` ×7, `SealReason#…` ×5), identical in both stub trees. Per CLAUDE.md's
"a field the stubs carry and the manifest does not is a DECISION" rule, that decision is this plan's
**Decisions** section, and `--write-manifest` runs only in Phase 3, after both languages are wired.

**Corrections to the brief.**
- `python/tests/test_field_manifest_gate.py::test_an_exact_match_of_the_known_lag_downgrades_to_a_note_naming_the_lag_file`
  is **red right now** (measured: 1 failed, 135 passed across the eight affected test files). It feeds the
  real committed manifest against ambient stubs, so the seven unrecorded fields break its "exact match".
  It is not a pre-existing flake: it goes green when the manifest is written (Phase 3 AC).
- The consumer reads through **seam-adapters core**, not the SDK directly. `GrpcTransport.get_decision`
  returns core's own `DecisionRecord`, built by `_decision_readback`, which copies the eight structural fields
  "explicitly rather than by reflection" (`seam-adapters/core/seam_agent_core/transport_grpc.py:399-417`,
  `gate.py:1172`). P4b therefore also needs a core change. That is not an SDK ask, but Phase 5 tells seam-mcp
  about it.

## Phases

All phases land in `seam-sdk`. There are no cross-repo writes. Shared API (Opus decision, see **Decisions**):

1. **`policy_enforcement_of(resp)` / `policyEnforcementOf(resp)` also accept a `DecisionRecordView`.** This is
   the same decoder, with the union widened to three carriers. On a record of runtime ≥ 0.61.0 it always
   returns an instance. On an older runtime it returns `None`/`undefined`.
2. **`seal_attestation_of(view)` / `sealAttestationOf(view)`** (new), returning a frozen `SealAttestation`
   DTO, or `None`/`undefined` iff the field is absent (runtime < 0.61.0):
   - `availability`: the closed string set `"RECORDED" | "NOT_RECORDED" | "KEY_UNAVAILABLE" | "ARCHIVED" |
     "CLEARANCE_DENIED" | "UNAVAILABLE" | "UNRECOGNIZED"`;
   - `seal_reason` / `sealReason`: `None`/`undefined` unless availability is `"RECORDED"`, then
     `"COMMIT" | "CANCEL" | "EXPIRE_TTL" | "EXPIRE_SUSPEND_CAP" | "UNRECOGNIZED"`;
   - `collective_outcome` / `collectiveOutcome`: the existing `CollectiveOutcome` DTO, set only when
     availability is `"RECORDED"`, reason is `"COMMIT"` **and** the wire carries one.
3. **`policy_version` and `policy_rules_digest` stay raw.** They are plain proto3 scalars with no presence
   and no enum, so they have nothing to decode. The docs say how to read them (empty = none; digest length
   0 or 32), and that they are display values, not `record_digest_v4` inputs (see *Edge cases*, Phase 1).

---

### Phase 1: Python decoders, prose corrections, unit tests

- **Status:** DONE (2026-10-28). As planned. Divergences: the `HasField`-raises paragraph in `_policy.py` needed no edit (its non-carrier list is still right); the "THREE distinct meanings" sentence was re-scoped to the immediate carriers by wrapping, keeping the needle intact; an extra all-availabilities × payload test closed the verifier's AC2 gap.
- **Risk:** complex. It adds a public API (one-way door) and changes a normative reading rule.
- **Delivers:** `seam_sdk.seal_attestation_of`, `seam_sdk.SealAttestation`, a three-carrier
  `policy_enforcement_of`, and docs that stop saying `GetDecision` carries neither field.
- **Depends on:** none (stubs are current).
- **Files:**
  - `python/seam_sdk/_collective.py`:
    - the module title (:1-2) and `collective_outcome_of`'s "a read verb that never does" (:105-106) stay
      true for the top-level field; add only a pointer to `seal_attestation_of`;
    - extract the body of `collective_outcome_of` (:152-173) into a private
      `_decode_collective(outcome, decision_id) -> CollectiveOutcome`;
    - `collective_outcome_of` keeps its signature and behaviour;
    - fix the header's item 1 (:8-12): `GetDecision` carries no top-level `collective_outcome`, but since
      0.61.0 it carries one inside `seal_attestation` (read with `seal_attestation_of`).
  - `python/seam_sdk/_seal.py` (new): `SealAttestation` and `seal_attestation_of`. A sibling module, because
    `_policy.py`'s "no enum here" premise (:3-5) must stay true.
  - `python/seam_sdk/_policy.py`:
    - widen the `Union` (:164) to `pb.DecisionRecordView`, and the module title (:1) and the decoder's
      "Accepts a `DecisionResponse` **or** a `SessionStep`" / "One decoder, two message types" (:166, :173)
      to three carriers;
    - rewrite "When the field is present" (:26-40) to say `GetDecision` carries it since 0.61.0, derived and
      always present. This includes the "immediate response only ... about the VERB" paragraph (:33-40),
      which names `GetDecision` as a non-carrier; `ReplayDecision` still is one;
    - scope the "THREE meanings" block (:131-149) to the immediate carriers (keep the phrase "three
      distinct meanings": it is a `BOTH_LANGUAGES` needle, `test_presence_rules_agree_across_languages.py:82-86`), adding that on a record view
      meaning 3 does not occur, while meaning 2's fail-open case and the runtime's LOW concurrent-open
      limit (`seam.proto:1091-1094`) still apply;
    - update the `HasField`-raises paragraph (:178-186), whose list of non-carriers is still right.
  - `python/seam_sdk/errors.py`: `UnknownCollectiveVerdictError`'s docstring (:105-110) gains the third
    carrier.
  - `python/seam_sdk/__init__.py`: import beside :10-11 and add both names to `__all__` (near :159-166).
  - `python/seam_sdk/client.py` `get_decision` docstring (:1120-1131) and `python/seam_sdk/aio.py`
    `get_decision` (:854, no docstring today): one sentence each pointing at `policy_enforcement_of` /
    `seal_attestation_of`. Sync/async parity is otherwise automatic, because both return the same
    `pb.DecisionRecordView` and the decoders are pure functions; no client method changes.
  - `python/tests/test_seal_attestation.py` (new); `python/tests/test_policy_enforcement.py` (extend);
    `python/tests/test_collective_outcome.py` (one regression test for the extraction);
    `python/tests/test_presence_rules_agree_across_languages.py` (see Tests);
    `python/tests/fixtures/seal_attestation_cases.json` (new; the case table Phase 2 reuses).
- **Approach:**
  - **Decode against each enum's own growth policy, not one blanket rule.**
    - `availability`: UNSPECIFIED and unknown values map to `"UNRECOGNIZED"` and never raise. The proto
      says to read them as WITHHELD (`seam.proto:1112-1114`). That is a reading rule, not a
      fail-to-FailPolicy rule, so raising would contradict it.
    - `"UNRECOGNIZED"` is kept distinct from the runtime's own `"UNAVAILABLE"` because the remedies differ:
      upgrade the SDK versus retry.
    - When availability is anything but RECORDED, the payload is **not read**: `seal_reason` and
      `collective_outcome` are `None` whatever the wire carries ("meaningful ONLY under RECORDED",
      `:1102-1103`).
  - **`seal_reason`** under RECORDED: UNSPECIFIED and unknown values map to `"UNRECOGNIZED"` ("read as
    unknown", `:1114`) and never raise.
  - **`collective_outcome`** is decoded only under RECORDED + COMMIT + `HasField`, through
    `_decode_collective`. An **unknown `CollectiveVerdict` raises `UnknownCollectiveVerdictError`**
    (with `view.decision_id`), because that enum's growth policy is the fail-closed one (`:556`) and
    `SealAttestation`'s doc defers to it rather than overriding it.
    - This is the one place a record read can raise. `get_decision` itself never does: it returns the raw
      view, and decoding is opt-in. See **Decisions D3** and **Open questions Q1**.
  - **Absent `collective_outcome` under RECORDED + COMMIT** → `None`, not `ProtocolViolationError`. Absence
    carries no claim, which is fail-closed. The Authorize TRANSFORM-without-input precedent raises because
    there absence would forward untransformed input (fail-open). Train B itself seals *no* attestation
    rather than a fabricated one in its one degenerate case (quorum threshold `None` → `NOT_RECORDED`).
  - **A collective present outside RECORDED + COMMIT** (e.g. RECORDED + CANCEL) is ignored → `None`
    (withhold rather than guess at a contract violation).
  - **Field types:** `availability: str` and `seal_reason: Optional[str]` with the closed set in a comment,
    and no convenience boolean. This matches `CollectiveOutcome.verdict` (`_collective.py:67-69`) and
    `PolicyEnforcement`'s "no second truthiness" rule (`_policy.py:122-126`). A caller writes
    `att.availability == "RECORDED"`.
  - **No raw-int fields.** The raw value stays reachable on `view.seal_attestation` for diagnostics, so
    every public name added here is one fewer to keep forever.
  - *Rejected:*
    - (a) Raising on unknown availability, like `collective_outcome_of`. It contradicts the proto's
      explicit WITHHELD reading and would fail a read for a reason the runtime says is benign.
    - (b) Mapping unknown availability to `"UNAVAILABLE"`. It conflates "the runtime could not read it"
      with "this SDK cannot name it".
    - (c) A separate `policy_enforcement_of_record`. That would be a second decoder for one field, the
      exact duplication `_policy.py:173-176` argues against.
    - (d) Wrapping `get_decision` to return a DTO. That breaks its `pb.DecisionRecordView` return type,
      which the adapters core and every caller depend on.
    - (e) Decoding `policy_rules_digest` into hex or `None`. It is raw `bytes` with a length rule, and a
      helper would add API surface without removing a hazard.
- **Edge cases:**
  - **Runtime < 0.61.0:** both decoders return `None`.
  - **`NOT_RECORDED`, the 0.61.x norm:** an instance with `availability="NOT_RECORDED"`, `seal_reason=None`,
    `collective_outcome=None`. Not an error. The docstring says the seal-time immediate response is the
    only source for such a record (`:1129-1130`).
  - **`KEY_UNAVAILABLE` / `ARCHIVED` / `CLEARANCE_DENIED`:** an instance, no payload.
    - On `KEY_UNAVAILABLE`, `policy_enforcement_of(view)` still answers (`:1132-1133`).
    - This SDK sends no `x-seam-clearance` header (none in `client.py` or `client.ts`), so every read is
      at the default PUBLIC, and a record whose handling rule needs more reads `CLEARANCE_DENIED`. Say so
      in the docstring. A clearance option is out of scope (Open questions Q2).
  - **`UNAVAILABLE`:** the docstring notes a retry may succeed. The SDK does not retry, because the RPC
    succeeded.
  - **UNSPECIFIED availability** → `"UNRECOGNIZED"`. **RECORDED + UNSPECIFIED reason** →
    `seal_reason="UNRECOGNIZED"`, collective `None`.
  - **RECORDED + COMMIT with an unknown verdict:** raises `UnknownCollectiveVerdictError(raw, decision_id)`.
  - **`policy_version` / `policy_rules_digest` vs `record_digest_v4`:** the record digest distinguishes
    `None` from `""`/`b""` (`python/seam_sdk/crypto.py:859-947`, "``None`` is not ``b""``" :887). The view's
    fields are presence-less scalars, so they **cannot** be fed back into `record_digest_v4`, which also
    needs inputs the view lacks. State this in `seal_attestation_of`'s module doc and in the README.
  - **`enforced=True` on a record view:** names the policy id; the revision is not bound (the same caveat as
    today, `seam.proto` PolicyEnforcement doc).
  - **A message with neither field passed from untyped Python:** `HasField` raises `ValueError`, as
    `policy_enforcement_of` does today (`test_policy_enforcement.py:313-325`). `seal_attestation_of`
    inherits it, and a test pins it.
- **Acceptance criteria:**
  1. `seal_attestation_of(pb.DecisionRecordView())` is `None`. For each of the six named availability values
     it returns an instance with that name. For 0 and for 99 it returns `"UNRECOGNIZED"`. None of these
     raises.
  2. For every availability other than RECORDED, a wire payload carrying `seal_reason=COMMIT` and a valid
     collective decodes to `seal_reason is None and collective_outcome is None`.
  3. RECORDED + COMMIT + an APPROVED collective decodes to a `CollectiveOutcome` equal, field for field, to
     what `collective_outcome_of` returns for a `DecisionResponse` carrying the same message, including
     `effective_threshold` presence.
  4. RECORDED + COMMIT + verdict 0 or 99 raises `UnknownCollectiveVerdictError` whose `decision_id` is the
     view's. RECORDED + COMMIT with no collective → `collective_outcome is None` and no raise. RECORDED +
     CANCEL + collective → `collective_outcome is None`.
  5. `policy_enforcement_of(view)` returns `None` for a view without field 11, and an instance (including
     `enforced=False`) when present, with `policy_id` presence preserved exactly as for the other two
     carriers.
  6. `SealAttestation` is frozen and has exactly the three fields. A test asserts the field set, so adding
     a boolean is a visible edit.
  7. `collective_outcome_of`'s existing tests pass unchanged (the extraction is behaviour-preserving).
  8. `_policy.py` no longer contains "a fetched or replayed decision reads" (the Phase 1 `RETRACTED`
     entry passes), and its module title and decoder docstring name three carriers. `_collective.py`'s
     statement that `GetDecision` carries no top-level `collective_outcome` stays, since it is still true.
- **Tests:**
  - `test_seal_attestation.py`:
    - the AC1-AC4 table, parametrised over every availability value from the `pb` enum descriptor, so a
      new value added by a later regen falls into the `"UNRECOGNIZED"` case until it is named;
    - the payload-ignored matrix;
    - the unknown-verdict raise and its pickling, as `test_collective_outcome.py:94` does;
    - the `ValueError` on a non-carrier;
    - a wire round-trip (`SerializeToString` → `FromString`) for a RECORDED + COMMIT view;
    - a descriptor test asserting that `seal_attestation` and `collective_outcome` have presence and
      `policy_version`/`policy_rules_digest` do not. That is the claim the "stay raw" decision rests on,
      checked the way `test_the_descriptor_claims_in_the_docstring_are_true` (`test_policy_enforcement.py:329`)
      checks its own.
  - `test_policy_enforcement.py`:
    - add `DecisionRecordView` to `test_both_message_types_decode_identically` (:128);
    - extend the descriptor test (:329) to field 11 with presence;
    - the non-carrier list (:313) stays `AuthorizeResponse`, `TerminalResponse`, `SessionStatusResponse`
      and must **not** gain `DecisionRecordView`.
  - `test_presence_rules_agree_across_languages.py`:
    - add to `RETRACTED` the operative wrong claim, "a fetched or replayed decision reads" (present
      verbatim in both `_policy.py:30-31` and `client.ts:503`, after `_text`'s normalisation), with the
      reason "seam-runtime#1361 train A: GetDecision carries policy_enforcement since 0.61.0". Not "do
      **not** carry": that fragment is too easy to reword around and would also catch a still-true
      sentence about `ReplayDecision`.
    - **Scope it to `(PY_POLICY,)` in Phase 1.** `client.ts:503` still carries the phrase until Phase 2, so
      a `(PY_POLICY, TS_CLIENT)` entry is red at the end of Phase 1. Phase 2 widens it to both paths and
      adds the `BOTH_LANGUAGES` pair (e.g. "does not withhold after eviction"). Each phase is then green
      on its own.
  - Failure paths: the unknown-verdict raise; the `ValueError` on a wrong message type.
  - Full gate: `cd python && .venv/bin/pytest -q`; `ruff check` and `ruff format --check`. **Expected
    result until Phase 3: exactly one failure,**
    `test_field_manifest_gate.py::test_an_exact_match_of_the_known_lag_downgrades_to_a_note_naming_the_lag_file`
    (pre-existing; see *Corrections to the brief*). Any other failure is this phase's.
- **Docs:** docstrings only (README is Phase 4).

### Phase 2: TypeScript mirror

- **Status:** DONE (2026-10-28). As planned. Divergences: "40 of the 167" reworded to a count-free phrase rather than re-measured; client.ts growth shifted seven pinned line citations in COMPATIBILITY.md/PROGRESS.md, renumbered to the same lines.
- **Risk:** complex. It adds a public TS API and widens a root-level union.
- **Delivers:** `sealAttestationOf`, the `SealAttestation` interface, a three-carrier `policyEnforcementOf`, and
  the corrected TS prose, behaviour-identical to Phase 1.
- **Depends on:** Phase 1 (Python is the reference each shim mirrors, `go/README.md:4-5`).
- **Files:**
  - `ts/src/client.ts`:
    - extract a module-private `decodeCollective(outcome, decisionId)` from `collectiveOutcomeOf` (:401-423);
    - add `SealAttestation` (readonly fields) and `sealAttestationOf(view: DecisionRecordView)` next to the
      collective block;
    - import `type DecisionRecordView`, `SealAttestationAvailability` and `SealReason` from the stubs
      (:10-36). Do **not** import the generated `SealAttestation` there: it would collide with the exported
      interface. Use `NonNullable<DecisionRecordView["sealAttestation"]>` if the wire type is needed;
    - widen `policyEnforcementOf` (:576-578) to `DecisionResponse | SessionStep | DecisionRecordView`, and
      its "Field numbers differ (7 … 3)" sentence (:560-561) to include 11 on `DecisionRecordView`;
    - rewrite :500-515 (the carrier paragraph and the "about the VERB" paragraph) and scope the meaning-3
      block (:443-466) as in Phase 1;
    - add a pointer from `getDecision` (:1526) to the two decoders;
    - update the `UnknownCollectiveVerdictError` doc (:285-290) for the third carrier.
  - `ts/src/index.ts`:
    - the dual-declaration comment (:53-84) goes from "FIVE" to "SIX", with a `pb.SealAttestation` entry,
      because the hand-written `SealAttestation` now shadows the generated one at the root;
    - the "40 of the 167" prose (:71) is re-measured or reworded so it does not state a stale count (the
      regen already added a message and two enums);
    - :72-84 also count: "These five", "adding one of these five", and "The last two differ from the first
      three" become six / the last three, with `SealAttestation` named as a decoded form;
    - `SealAttestation`'s generated type is **not** added to the `export type` list (:87-102); adding it
      would displace the DTO (:75-77).
  - `ts/tests/seal_attestation.test.ts` (new); `ts/tests/policy_enforcement.test.ts` (extend).
- **Approach:**
  - protobuf-es already models the presence this needs:
    - `sealAttestation?: SealAttestation` (`seam_pb.ts:2136`);
    - `collectiveOutcome?: CollectiveOutcome` (:2176);
    - `policyEnforcement?` (:2120).
    So `=== undefined` replaces `HasField`.
  - Enum lookups use protobuf-es's stripped names (`SealAttestationAvailability.RECORDED`,
    `SealReason.COMMIT`), as `COLLECTIVE_VERDICT_NAMES` does (:303-315).
  - Return fresh objects, never the `$typeName`-branded message (:582-585).
  - *Rejected:* exporting the generated enums at the root so callers can compare numbers. That puts the open
    enum back in the caller's hands, the inversion these decoders exist to prevent.
- **Edge cases:** as Phase 1. TS-specific:
  - a plain-JS caller passing a non-carrier gets `undefined` rather than an error, as `policyEnforcementOf`
    documents today (:566-575). Say the same for `sealAttestationOf`;
  - an enum value outside the generated `enum` (a newer runtime) is a plain number at runtime, so the lookup
    table returns `undefined`, which maps to `"UNRECOGNIZED"`.
- **Acceptance criteria:**
  1. The Phase 1 AC1-AC5 cases produce the same outputs in TS. Both test files read one fixture,
     `python/tests/fixtures/seal_attestation_cases.json` (input availability/reason/verdict ints →
     expected output or expected raise), created in Phase 1; TS reads it by path, as
     `ts/tests/operator_token.ts:75` already reaches into `python/tests/`.
  2. `python/tests/test_shadowed_names_comment.py` passes with the count word "SIX" and the new entry.
  3. `python/tests/test_presence_rules_agree_across_languages.py` passes, with the Phase 1 `RETRACTED`
     entry widened to `(PY_POLICY, TS_CLIENT)` and the new `BOTH_LANGUAGES` pair.
  4. `npm run typecheck`, `npm run build` and `npm test` are green. The `.d.ts` exposes `SealAttestation`,
     `sealAttestationOf` and the widened `policyEnforcementOf`, and no module-private decoder.
- **Tests:**
  - `seal_attestation.test.ts`: the same matrix as Python, plus a `toBinary`/`fromBinary` round-trip.
  - `policy_enforcement.test.ts`: the record-view carrier.
  - Failure path: the unknown-verdict throw carries the view's `decisionId`.
  - The presence-rules widening and `BOTH_LANGUAGES` pair (see Phase 1 Tests) land here.
  - Python full suite: still exactly the one known `test_field_manifest_gate.py` failure until Phase 3.
- **Docs:** TSDoc only.

### Phase 3: record the contract decision, live coverage

- **Status:** DONE (2026-10-28). As planned. Divergences: the enum-floor test in `test_field_manifest_gate.py` pinned the exact enum set, so it was renamed (`..._covers_every_enum`) and extended to six; the live run was first made against a dirty train-B build and redone on a clean `7d538c54` export (see the Phase 3 note under *Runtime timeline*).
- **Risk:** simple.
- **Delivers:** `contract/field-manifest.txt` declares the seven fields and twelve enum values. The gate
  exits 0. The live lanes assert the record view decodes against a real 0.61.x runtime.
- **Depends on:** Phases 1 and 2 (the decision is wired before it is recorded, as CLAUDE.md requires).
- **Files:**
  - `contract/field-manifest.txt`, written by `scripts/check-contract.sh --write-manifest`;
  - `python/tests/test_integration.py`;
  - `ts/tests/integration.test.ts` (beside the existing `getDecision` asserts, :85 and :109-110).
- **Approach:**
  - **Regenerate first** (`make generate`), so the manifest is written from BSR stubs and not stale ones,
    and confirm `git status` shows no stub drift (stubs are untracked; compare the gate's output).
  - Then `--write-manifest`, and **review the diff**: it must be exactly +7 field lines and +12 enum lines,
    with no removals and no other movement. A bare run rewrites the api manifest from whatever the local
    stubs are (CLAUDE.md). It also rewrites `contract/rpc-manifest.txt` and
    `contract/event-field-manifest.txt` in the same run (`scripts/check-contract.sh:612-680`); both must
    come out byte-identical.
  - **Live:**
    - after the existing RunDecision in each integration lane, `get_decision` → `policy_enforcement_of(view)`
      is not `None` and its `enforced` equals the immediate response's when that one is present;
    - `seal_attestation_of(view)` is not `None` and its availability is not `"UNRECOGNIZED"`;
    - **if** it is `"RECORDED"` (train B onward), `seal_reason == "COMMIT"` and the collective verdict equals
      the immediate response's.
    Written so it passes on 0.61.x (`NOT_RECORDED`) and on 0.62.0 alike, with no version branch.
  - *Rejected:* asserting `== "NOT_RECORDED"` live. It goes red the day train B ships, through no SDK change.
- **Edge cases:**
  - The integration lane is advisory and may skip (`scripts/test_ci_gate.py:52`). Record whether it actually
    executed before claiming live coverage.
  - The lane's runtime is `seamd:main` (`ci.yml` integration job). Before 0.61.0 is on that tag, the
    `not None` asserts would fail, so check the image carries 0.61.0 when running locally.
- **Acceptance criteria:**
  1. `STREAM=1 EVENTS=1 ./scripts/check-contract.sh; echo $?` prints `0`.
  2. `git diff contract/field-manifest.txt` is exactly the 19 additions listed in *Context*, and
     `git diff --stat contract/` names no other file.
  3. `test_field_manifest_gate.py` is fully green, including
     `test_an_exact_match_of_the_known_lag_downgrades_to_a_note_naming_the_lag_file`, which is red before this
     phase.
  4. The Python and TS live tests pass against a local 0.61.x `seam-grpc`, and the run log shows they executed
     rather than skipped.
- **Tests:** the two live assertions, the full Python and TS suites, and the gate itself. Failure path: delete
  one new manifest line locally, confirm exit 6 naming it, then restore it (manual check, not committed).
- **Docs:** none (Phase 4).

### Phase 4: docs, compatibility, changelog

- **Status:** DONE (2026-10-28). As planned. Divergences: the README's resend sentence and the matching `submit_*` docstrings (Python, and seven in TS, edited in place) no longer say "read `get_decision` for the outcome", because a 0.61.x record reads NOT_RECORDED. The CHANGELOG inserts moved `:101` to `:127`, not `:103`.
- **Risk:** simple.
- **Delivers:** a reader can learn from the README how to explain a record, and `COMPATIBILITY.md` names
  the runtime it needs.
- **Depends on:** Phases 1-3.
- **Files:** `README.md`, `COMPATIBILITY.md`, `CHANGELOG.md`, `plans/README.md` (active row), and
  `PROGRESS.md` (the checkpoint trail).
- **Approach:**
  - **README:** a short "Explaining a sealed record" passage beside the credentialed-reads paragraph
    (`README.md:610-623`). It covers:
    - the two decoders;
    - `NOT_RECORDED` as the norm until runtime 0.62.0, and what each state means (cite the proto, do not
      paraphrase beyond one line each);
    - the attestation is chain-bound but **not client-verifiable** (`verify_decision` does not cover it);
    - reads are at clearance PUBLIC;
    - participant verdicts come from `get_commitment_proof`, not the view;
    - `policy_version` / `policy_rules_digest` are display values, not `record_digest_v4` inputs;
    - Go/Java/Kotlin carry the generated fields only.
    Also add the fields to the BSR-state coordination-surface list (`README.md:97-104`).
  - **COMPATIBILITY.md §2** (table header :144):
    - a row: "Record explain: `policy_enforcement_of`/`policyEnforcementOf` on `DecisionRecordView`, and
      `seal_attestation_of`/`sealAttestationOf` (seam-sdk#273) | seam-runtime 0.61.0 (seam-runtime#1535,
      #1361 train A); `RECORDED` attestations from 0.62.0 (train B, no wire change) | **compatible**: on an
      earlier runtime both decoders return `None`/`undefined` | runtime `main` @ `7d538c54`";
    - plus a paragraph in the 0.50.1 style (`:119-125`), placed with the other pairing paragraphs under
      `### Runtime ↔ SDK` (:113, after the v0.54.3 / v0.56.0 ones), not beside the table: "**SDK v0.61.1 pairs with runtime 0.61.0.**
      v0.61.0 was tagged at `32ab80d` and never published …; the runtime's next release must be 0.62.0 or
      later". Written **unconditionally in this PR**: the owner chose 0.61.1 (Q3), and the precedent landed
      its paragraph before the release too (`98172b9`, #284, preceded the bot's `5329efd` v0.50.1 commit).
      The table has no SDK-version column (header :144: SDK change | Requires runtime | Earlier
      runtimes | Pinned from), so the 0.61.1 number lives in that paragraph, not the row.
  - **CHANGELOG.md:**
    - an **Unreleased → Added** entry, cross-language, with the Go/Java/Kotlin sentence;
    - an **Unreleased → Changed** entry for the corrected reading rule: `policy_enforcement_of` no longer
      returns `None` for a fetched record on runtime ≥ 0.61.0;
    - the `## 0.61.0` heading the bot wrote is left in place (as `## 0.56.0` was), with one line under it:
      "Tagged, never published (see COMPATIBILITY.md); these entries first ship in 0.61.1." The
      Unreleased entry says the same. A reader of the heading alone would otherwise think DPoP shipped
      in 0.61.0. This line is a **deliberate departure** from precedent, not a copy of it: the
      unpublished `## 0.50.0` (`CHANGELOG.md:172`, entries kept), `## 0.51.0` (:159) and `## 0.56.0`
      (:130) headings carry no such note.
  - **Citations:** inserting lines near the top of `CHANGELOG.md` moves every `CHANGELOG.md:N` citation
    below them. Run `scripts/shift_changelog_citations.py . <after_line> <delta>` and the citation gate
    (`python/tests/test_compatibility_citations_resolve.py`). DPoP's Phase 10 shifted 11 citations this way.
    Re-anchor any `contract/field-manifest.txt:N` citation the manifest write moved: `grep -rn
    'field-manifest.txt:[0-9]' --include='*.md'`. `test_compatibility_citations_resolve.py:450` is only a
    parser-shape fixture, not an anchor. seam-mcp cites `PolicyEnforcement`'s manifest rows as `:361-362`
    (`seam-mcp/plans/post-onboarding.md:562`), which is already stale (they sit at `:374-375` at `b77609a`)
    and will move again; that is seam-mcp's to fix, so mention it in the Phase 5 message.
- **Edge cases:** the CHANGELOG retitle on release (`scripts/retitle_changelog.sh`) shifts citations
  itself. Do not pre-shift for it.
- **Acceptance criteria:**
  1. `python/tests/test_compatibility_citations_resolve.py` is green.
  2. The README passage names both decoders in both languages, states "not client-verifiable", and states
     the PUBLIC-clearance default.
  3. The COMPATIBILITY row cites `7d538c54` and seam-runtime#1535, and the 0.61.1 pairing paragraph is
     present.
  4. `CHANGELOG.md:101` (cited in *Context* and D2) is `:103` after the rebase and `:127` after this phase's inserts; any new citation uses the
     rebased line.
- **Tests:** the citation gate; the full suites once more (Python, TS, Go, `verify/`, Java and Kotlin are
  untouched but run per `ci-spend-local-first`).
- **Docs:** this phase. No `seam/docs` or `seam/CLAUDE.md` change: no new dependency edge, and the contract
  is described at its source.

### Phase 5: release and hand-off (post-merge)

- **Status:** TODO
- **Risk:** simple, but it is a release with a fork in it.
- **Delivers:** a published SDK on Cloudsmith `internal` (and `partner`, which `publish.yml`'s `promote-partner`
  job copies automatically, :768) whose decision reads decode the new fields; #273 closed; consumers told.
- **Depends on:** the PR merged to `main` and `main`'s `ci-ok` green.
- **Approach:**
  1. **Confirm the v0.61.0 outcome.** Run `gh run list -w publish.yml`, `gh run view` on run 40739395352,
     and `git ls-remote --tags origin 'v0.61*'`. Expected: `publish` refused at "CI is green for this commit"
     and nothing on Cloudsmith at 0.61.0 (`scripts/check_registry_drift.py` reads both repos).
  2. **If 0.61.0 is unpublished (expected):** ship **0.61.1** by manual dispatch, the 0.50.1 precedent
     (owner-decided, Q3):
     `gh workflow run release-on-runtime.yml -f version=0.61.1 -f wire_framing_version=3`. The framing input
     is required on a manual run because the latch is true (`release-on-runtime.yml` framing step;
     `contract/wire-framing.json` `supported: 3`). A public tag is never re-cut (`COMPATIBILITY.md:122`).
     - **This takes 0.61.1 from the runtime's number space.** Tell the runtime train owner that its next
       release must be 0.62.0 or later, which train B already is.
     - The workflow's own guards still apply: it refuses unless every `ci-ok` on `main`'s HEAD is
       success (`release-on-runtime.yml:169-221`), and refuses a framing input that disagrees with
       `supported`. A refusal writes nothing, so a re-run is safe.
     - Expect `check_registry_drift.py` to report drift in the interim (`main` declares 0.61.0 since
       `32ab80d`; Cloudsmith's newest is 0.60.0). Close any issue it opens with the 0.61.1 evidence.
  3. **If, against expectation, 0.61.0 was refused before tagging:** ask the runtime lead to re-run
     `dispatch-sdk` for 0.61.0 (memory: contract-train dispatch order).
  4. **Verify publication:** the `publish` workflow is green; `check_registry_drift.py` is clean for the new
     version in `internal` and `partner`; and `pip download`/`npm view` against Cloudsmith resolves it.
     `promote-to-partner.sh` only if the automatic job did not run.
  5. **Close #273** with the evidence. Rationale in **Decisions D5**: the SDK half's acceptance is met, and
     train B adds no wire surface.
  6. **Messages:**
     - **seam-mcp:** P4b's SDK dependency is published, records read `NOT_RECORDED` until runtime 0.62.0,
       and its SDK manifest citation `:361-362` is stale (`PolicyEnforcement/*` rows moved). Its reads go
       through seam-adapters core's `GrpcTransport.get_decision` (`onboard/.../tools/session_reads.py:20-22`),
       whose `_decision_readback` copies only eight fields (`transport_grpc.py:399-417`). P4b therefore
       needs, in order: a core change that widens `DecisionRecord`; a core pin raise from
       `seam-sdk>=0.59.0,<0.60` (`seam-adapters/core/pyproject.toml:101`) to `>=0.61.1,<0.62`; a core
       release; and seam-mcp's own move off `seam-sdk==0.59.0` / `seam-agent-core[sdk]==0.22.0`
       (`common/pyproject.toml:18-19`, `onboard/pyproject.toml:16`). Theirs to file.
     - **seam-sdk follow-up:** when seam-adapters merges that pin raise, this repo's `sibling-quotes` job
       goes red against `COMPATIBILITY.md`'s `>=0.59.0,<0.60` quote. Re-quote right after their merge
       (memory: sibling pin raise blocks release).
     - **seam-runtime (#1361):** the SDK half shipped as version X; 0.61.1 is taken if step 2 ran.
- **Acceptance criteria:**
  1. The released version is on Cloudsmith `internal` and `partner`, and its wheel's
     `seam_sdk.seal_attestation_of` imports from a clean venv (`publish.yml`'s clean-venv import step).
  2. #273 is closed with a comment naming the version, the merge commit and the runtime pairing.
  3. `COMPATIBILITY.md` states the pairing actually published: the Phase 4 0.61.1 paragraph is true. If
     step 3 ran instead, a follow-up PR replaces it.
- **Tests:** none beyond the publish workflow's own gates.
- **Docs:** the `PROGRESS.md` release line; archive this plan via `/sweep` once verified.

---

## Long-term posture

- **One-way doors (public contract, two languages):**
  - the names `seal_attestation_of` / `sealAttestationOf` and `SealAttestation`;
  - its three field names (`availability`, `seal_reason`/`sealReason`, `collective_outcome`/`collectiveOutcome`);
  - the string vocabularies, including the SDK-coined `"UNRECOGNIZED"`;
  - and the widened `policy_enforcement_of` union.
  Renaming any of them is breaking under a version number that cannot say so (`CHANGELOG.md:9-12`). They are
  kept minimal for that reason: no booleans and no raw ints. Adding either later is additive; removing one
  never is.
- **The strings track proto names minus the prefix**, so a future value (say `SEAL_REASON_SUPERSEDE`) gets
  the obvious spelling `"SUPERSEDE"` with no naming decision. Until an SDK names it, it reads
  `"UNRECOGNIZED"`, and the field-manifest gate (exit 6) forces that decision on the next regeneration.
- **Reversible:**
  - raising on an unknown verdict inside the attestation: strict → lenient is the safe direction to
    change later;
  - the private `_decode_collective` / `decodeCollective` extraction;
  - all prose.
- **Debt avoided:**
  - no second `PolicyEnforcement` decoder;
  - no SDK-side mirror of train B's state (nothing in the SDK changes at 0.62.0);
  - no clearance plumbing built ahead of a consumer.
- **Debt accepted:** Go/Java/Kotlin still have no decoders. That is consistent with their documented
  shim-only scope and with how C5 and `effective_threshold` shipped. An ergonomic client there is the
  standing README follow-up, not this issue.

## Enterprise concerns

- **Security / trust:** the attestation is chain-bound but **not client-verifiable**. Docs must not let a
  reader treat `seal_attestation_of` output as proof the way `verify_decision` output is. Nothing here logs
  or caches record content.
- **Correctness under partial failure:** every non-RECORDED state yields a typed instance with no payload,
  never an exception. `UNAVAILABLE` is documented as possibly transient. The decoders never retry.
- **Compatibility:** additive on the wire. On an older runtime both decoders return `None`. One behaviour
  change: `policy_enforcement_of` on a fetched record goes from always-`None` to an instance on runtime
  ≥ 0.61.0. That is the intended effect and is CHANGELOG'd under *Changed*.
- **Observability:** none added. The runtime owns it.
- **Rollback:** a revert. No persisted state and no wire framing change, so `wire-framing.json` is untouched
  (it is for crypto framings only).
- **CI spend:** run the full local gate before the single push (memory: `ci-spend-local-first`); one PR.

## Decisions (Opus, consequential but decidable)

- **D1. Carry all seven fields and twelve enum values; wire four, pass two through raw.**
  `policy_enforcement` goes through the existing decoder and `seal_attestation` through a new one.
  `policy_version` and `policy_rules_digest` are raw scalars with documented reading rules. This is the
  decision the exit-6 refusal asks for, and it is recorded in the manifest commit.
- **D2. Go, Java and Kotlin: no code.** They ship no generated transport in-package (`README.md:135-138`),
  and consumers generate from the BSR. "Readable in all five" is met for them by the BSR module itself plus a
  CHANGELOG/README sentence, as in 0.57.0 (`CHANGELOG.md:127`).
- **D3. Each enum follows its own normative growth policy.**
  - Availability and seal reason **never raise**: unknown maps to `"UNRECOGNIZED"`. For availability that
    reads as withheld (no payload); for a reason it reads as unknown, and the collective is not decoded.
  - `CollectiveVerdict` inside a RECORDED attestation **raises**, as on the immediate response, because the
    proto makes that one fail-closed and `SealAttestation` does not override it.
  - `get_decision` itself never raises for any of this.
- **D4. Absent or misplaced `collective_outcome` → `None`**, never a `ProtocolViolationError`. Absence makes
  no claim.
- **D5. #273 closes on the first published release carrying this, not at 0.62.0.**
  - #273's acceptance is "a release whose decision reads return the new fields, with COMPATIBILITY.md naming
    the runtime it needs" (`seam-mcp/plans/cross-repo/seam-sdk-post-onboarding.md:11-13`; `ReplayView` was
    dropped by the seam-mcp#123 amendment).
  - Train B has no wire change and so no SDK work.
  - Keeping #273 open for 0.62.0 would track runtime behaviour the SDK cannot influence.
  - Whether P4b *starts* before 0.62.0 is seam-mcp's call. seam-mcp#123 says it waits; the runtime plan says
    it can start. **P4b can build against 0.61.x:** policy and outcome are live, and the RECORDED path is
    testable with fakes. Only P4a-parity of the *tally* needs 0.62.0.
- **D6. Release as 0.61.1 by manual dispatch**, if 0.61.0 is confirmed unpublished. Owner-decided (Q3).

## Open questions (defaults chosen; `/implement` logs them `UNCONFIRMED` when implemented)

- **Q1:** should an unknown `CollectiveVerdict` inside a record's attestation raise (default, D3), or degrade
  to `collective_outcome=None` so an explain tool still shows availability and reason? Default: raise. It is
  consistent with the normative growth policy, and loosening later is additive. seam-mcp can catch
  `UnknownCollectiveVerdictError`.
- **Q2:** expose an `x-seam-clearance` option on the reads? Default: no, and add a `DEFERRED.md` line. No
  consumer asks for it, and the runtime decides what a caller's clearance claim is worth. Until then a
  restricted record reads `CLEARANCE_DENIED`.
- **Q3 — DECIDED by the owner-side session: (a).** How does this ship, given v0.61.0 was tagged at
  `32ab80d` and will not publish?
  - (a) **Default, recommended:** merge, then manually dispatch **0.61.1** (the 0.50.1 precedent). This
    takes 0.61.1 from the runtime's number space.
  - (b) Merge and let runtime 0.62.0 (train B) carry it. There is no manual dispatch, but both this feature
    and the already-merged DPoP signer (#290) stay unpublished until train B, which waits on train A
    being deployed on prd and partner.
  - Either way, `main` is red from `32ab80d` until this PR merges, so every other seam-sdk merge waits on it.

## PR strategy

One PR from `feat/record-explain`, rebased onto `origin/main` (which now includes the bot's `32ab80d`
release commit with the retitled CHANGELOG). Phases 1-4 land as one commit per phase. The PR body carries
the D1 decision text, because the manifest diff needs its justification beside it. Phase 5 is post-merge
and produces no PR, beyond an optional `PROGRESS.md`/`COMPATIBILITY.md` touch-up folded into the next
change.

## Plan review

**Round 1 (2026-10-28) — verdict: REVISE, fixes applied in place.** Checked against the code at
`b77609a` / `origin/main` `32ab80d`, the runtime proto at `7d538c54`, seam-adapters and seam-mcp. The
gate was run (`STREAM=1 EVENTS=1 ./scripts/check-contract.sh` → exit 6, the 7 + 12 claimed), and the lag
test was run (1 failed as claimed). The proto semantics, release inputs (`version` +
`wire_framing_version`, latch true, `supported: 3`), the `_decision_readback` claim and the D3 enum split
all hold. What changed:

1. **Presence-rules phasing was broken.** A Phase 1 `RETRACTED` entry over `(PY_POLICY, TS_CLIENT)` is red
   until Phase 2 rewrites `client.ts:503`. It is now scoped to Python in Phase 1 and widened in Phase 2.
   The needle is now "a fetched or replayed decision reads": "do **not** carry" was rewordable, and it also
   caught the still-true `ReplayDecision` clause. AC8 is now falsifiable. Before, it claimed a substring
   test enforced "no sentence says …" across three files, one of which (`_collective.py`) stays correct.
2. **Missed prose sites:** the `_policy.py` title and decoder docstring (:1, :166, :173); the TS VERB
   paragraph (:506-515, not just :500-504); the TS field-number sentence (:560-561); and the `index.ts`
   "these five / last two / first three" text (:72-84).
3. **TS import collision:** `client.ts` must not import the generated `SealAttestation`.
4. **Sync/async and discoverability:** `get_decision` docstring pointers added for `client.py`, `aio.py` and
   `client.ts`.
5. **Phase 1 and 2 verification** now says to expect exactly one known failure until Phase 3.
6. **Phase 2 AC1** is now a shared JSON fixture instead of a vague "shared table".
7. **Phase 3:** `--write-manifest` also rewrites the rpc and event manifests (`check-contract.sh:612-680`),
   so the AC now asserts no other `contract/` file changes.
8. **The release fork is now owner-decided (Q3 → (a)).** The 0.61.1 COMPATIBILITY paragraph is written
   unconditionally in Phase 4, which matches the precedent: `98172b9` landed before `5329efd`. The bot's
   `## 0.61.0` CHANGELOG heading gets a "never published" line. Phase 5 now names the workflow's ci-ok and
   framing guards and the interim registry drift.
9. **Consumer chain:** adapters core pins `seam-sdk>=0.59.0,<0.60` and seam-mcp pins `==0.59.0`, so P4b needs
   a core widening, a pin raise, a core release and a seam-mcp pin move. The adapters raise will redden
   `sibling-quotes` here, so a re-quote follow-up is listed.
10. **Anchor drift (minor):** the proto availability enum (:1125), pyi (:579, :607, :43/:53) and TS enums
    (:3870/:3934) are fixed. `CHANGELOG.md:101` becomes `:103` after the rebase (`:127` after Phase 4). PROGRESS's
    `test_integration.py` GetDecision anchors (:297, :393) are wrong (actual :57, :80, :107, :284).
    PROGRESS was not edited.

**No critical fork.** The public names, types and enum handling are consistent with each other and with
`collective_outcome_of` on the immediate response. Q1 (raise vs degrade on an unknown verdict inside a
RECORDED attestation) is the closest. Raise is defensible and reversible, but it hides availability and
reason from an explain tool on that path. seam-mcp should know to catch `UnknownCollectiveVerdictError`.

**Round 2 (2026-10-28) — verdict: SOUND, three small fixes applied.** Verified against `b77609a`:
the Phase 1 `RETRACTED` scoping holds (needle normalises to one hit each in `_policy.py:30-31` and
`client.ts:503`, zero in `_collective.py`; `RETRACTED` is `(phrase, paths, why)`,
`test_presence_rules_agree_across_languages.py:42-58`); `_policy.py:1/:164/:166/:173`,
`client.ts:500-515/:560-561/:576-578` and `index.ts:53-84/:87-102` are where cited; a same-module
import plus `export interface SealAttestation` would clash; `--write-manifest` rewrites all three
manifests (`check-contract.sh:612-679`), so `git diff --stat contract/` is a real check; the lag test
is `test_field_manifest_gate.py:1065`; `98172b9` is an ancestor of `5329efd`. Changed: (1) the 0.61.1
paragraph goes under `### Runtime ↔ SDK` (:113), and the "row's SDK version" sentence was dropped
(the table has no such column); (2) the CHANGELOG "never published" line is labelled a departure
(0.50.0/0.51.0/0.56.0 headings carry none); (3) Phase 1 keeps the "three distinct meanings" needle.
