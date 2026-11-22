# Flows W2: clients readers (seam-sdk + seam-mcp)

Dispatch: `/waves work 2`, unit `clients`. Owner GO 2026-11-22. **Readers only, no writer.**
Spec: master plan §6 W2; `flows-target/client-surfaces.md` S4, S5, A7, A9, A18; RTC §10 C4/C5 and §16.6;
runtime specs at seam-runtime `01a09caf` (`docs/specs/seam-commitment-digest.v6.md`, `seam-gate-block.v1.md`,
`seam-event.v1.md`).

## Inputs that exist today (checked 2026-11-22)

- On the BSR: `seam.event.v1` tags 28 `flow_ref` and 29 `chain` (manifested in #410).
- Vectors in `conformance/`: `commitment_digest_v6_vector.json`, `commitment_digest_v6_signed_vector.json`,
  `gate_block_vector.json` (#409, byte-pinned by the runtime's `sdk-digest-parity`).
- Runtime reference implementation:
  - `crates/seam-types/src/{commitment,gate}.rs`;
  - `scripts/commitment_digest_v6_vectors.py`, an independent stdlib-only generator.
- Chain vectors: runtime `fixtures/chain/chain_{genesis,link}_vectors.json` (hub `chain_bundle` v1).

## Not available yet (so not in this wave's code)

- `seam.api.v1` has no `flow_ref` (record or WhoAmI), no `Commitment.gate = 13` and no `Commitment.env = 14`.
  A7's record accessor and the proto-to-v6 input mapping wait for them. The v6 verifiers take the raw trailer
  bytes, which is what the vectors carry.
- C5 (attestation v3 and manifest helpers) and tag 30 need `chain_bundle` v2, the hub's B4 train before W4.

## Cross-port contract (A18): the same shape in every language, in that language's idiom

1. **Digest:** `commitment_digest_v6(commitment, field inputs)`, over exactly the v6 spec FIELDS 0–12.
   - The digest-only path takes `selection_digest`, `gate_digest`, `governing_doc_sha256` and `env` directly.
   - It refuses before hashing (`slot_length_not_32`, `env_not_sandbox_or_live`, `env_without_governing_doc`).
2. **Trailer decode:** `decode_commitment_trailers(trailers, scheme)` with scheme ∈ {v5, v6, none (scheme-free)}.
   - Markers strictly increasing, no unknown marker, nothing after the last trailer.
   - `0x05` is decoded by the gate-block decoder (strict, every `gate_*` and `marker_order` rule), and its
     `gate_digest = SHA-256(be64(19) ‖ "seam-gate-digest:v1" ‖ gate_body)` frames field 10.
   - `0x06` v1/v2 per the v6 spec frames fields 11 and 12.
   - The scheme rules come on top: `v5_refuses_*` and `v6_refuses_governing_body_v1`.
   - Returns field_10/11/12 encodings plus `governing_body_version`.
   - The selection trailer is handled as v5 already does.
3. **Gate block:** `decode_gate_body(body)` (strict) and `gate_digest(body)`. Readers only:
   `outage_classification` and `writer_refusals` are writer-side, so they are not ported (state this in the test).
4. **Statement selection:** `select_commitment_version(ext_raw_json)` returns `v5` or `v6`, or refuses.
   - Use the exact member set.
   - Detect duplicate members on the raw JSON at every depth of `ext`, comparing names after unescaping.
   - Enforce the lowercase-64-hex digest, the type, and the domain-value rules.
5. **TCT verify:** the existing commitment TCT verifier selects the version from the raw `ext`, applies that
   scheme's trailer rules, and recomputes under that version only. It never tries both and never falls back.
   - A commitment input may now carry `trailers` (the raw `0x05`/`0x06` bytes).
   - v5 behaviour is byte-unchanged, and every existing v5 test stays green.
6. **Tests:** read every section of the three vector files from `conformance/` and assert each row.
   - Refusal tests assert *refusal*. Rule names are advisory (spec §Refusal rules), so a test must not fail on a
     different applicable rule.
   - TS reads every `be64` as `BigInt` (`env_frame_length_max_be64` must refuse as truncated).

## A7 (S4): `flow_ref_of(event)`

Returns the event's `FlowRef` or none (absence is normal, ruling 6). It is documented as **attributed,
unsealed**. Python and TS are typed helpers; Go, Java and Kotlin are helpers over the generated stubs. The
record overload waits for the api field.

## S5 (A9) + RTC C4 readers: `verify/`

- Decode tag 28 (pb and JSON) and keep it **out of** `with_identity()`.
- Chained copies that differ only in `flow_ref` give a `FLOW_REF_CONFLICT` warning, exit 0, and are counted
  once.
- Identical stamps give no warning. A `stream_id` difference stays a hard forgery (regression).
- The digest recompute stays byte-unchanged.
- Decode tag 29. A chained event with it is keyed by `ChainKey` with `genesis(K)` (chain_bundle v1); without
  it, the legacy tenant rule applies. Legacy-tolerant, so V-checks wait for W5.
- Verify the chain vectors (copied byte-for-byte into `conformance/chain/`).
- S5 (v) (flow_ref.env vs the v6 env) needs the record's env, which the event stream does not carry yet:
  test it if a path exists, otherwise record it as deferred to S13/S16.
- The README says flow attribution is not sealed.

## Last item: the seam-mcp CI-cost pass (separate PR in seam-mcp)

Measure about 30 days of spend, add a fail-closed `merge_group` path filter, use the smallest runners, and add
concurrency cancel on PR workflows. Record before and after in the CI-cost doc and DECISIONS. Never remove a
required check without a fail-closed replacement, and never touch deploy jobs.

## Phases

| # | Phase | Status |
|---|---|---|
| P1 | Python A18 + A7 | DONE (73b7657) |
| P2 | TS A18 + A7 | DONE (0e9f999) |
| P3 | Go A18 + A7 | DONE A18 (b9079d2); A7 deferred to CL A17 (no generated stubs in the Go module) |
| P4 | Java + Kotlin A18 + A7 | DONE A18 (ac4ada3); A7 deferred to CL A17 (no generated stubs in either module) |
| P5 | verify/ A18 + S5 + C4 | DONE (6ee342e); S5 (v) deferred to S13/S16 |
| P6 | Integrate: one seam-sdk PR, docs (CHANGELOG, DECISIONS, COMPATIBILITY, README), full gates | DONE (0e1a2a2: one absent-trailers rule across ports) |
| P7 | seam-mcp CI-cost pass PR | DONE (seam-mcp#161, acfe00d3) |
