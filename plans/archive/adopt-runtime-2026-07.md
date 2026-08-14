# Plan — seam-sdk adopts the seam-runtime backlog-closeout landing (2026-07)

> **📦 ARCHIVED 2026-08-14 — DELIVERED, Phases 0–5 verified in both repos (Phase 6 partially
> delivered).** Phase 0 landed runtime-side via a restructure the plan didn't anticipate: the event
> schema was extracted into a canonical `seam.event.v1` package imported by `seam.api.v1`
> (`crates/seam-api/proto/seam/event/v1/seam_event.proto`), with all four mirror fields at the exact
> canonical tags (21/22/10/4) and `event_to_proto` populating them on both drain and live-tail
> stream paths, end-to-end tested. Phases 1–2: `make check-contract` + `verify_party_attestation`
> wrappers shipped. Phases 3–4: `chain --issuer` attestation + digest-v2 recompute shipped, framing
> KAT-pinned byte-exact, `verify/Cargo.toml` Seam-free. Phase 5: README says AUTHENTICITY, D-034
> entry in `verify/DECISIONS.md`, goldens + vectors byte-identical to the runtime, differential
> harness runs the public verifier in runtime CI. Phase 6: `verify_streamed_record_digest` +
> typed event accessors shipped with the events surface (beyond the "deferred" default).
> **Post-archive drift caught by the 2026-08-14 review:** runtime #251 later added
> `AUTHORIZE_EVALUATED` (tag 23, advisory) to the spec; the SDK verifier's advisory list missed it
> → reproduced false refusal under `--strict`. Fixed same-day with an SDK-side spec-sync tripwire;
> see `plans/consolidation-2026-08-14.md`.

> Written 2026-07-20 against seam-runtime `main` (post PRs #184–#198) and seam-sdk `main`
> (HEAD `fdba12d`). Every claim below was read from code in both repos, cited file:line. Source of
> truth is the runtime **code**, never a status doc.

## Context

The seam-runtime backlog-closeout campaign (#184–#197) landed several things a **client** of Seam is
supposed to be able to use or verify, and the SDK has not adopted any of them yet:

- **A4 (#186)** added a `VerifyPartyAttestation` RPC + `ChainHeadAttestation`/`VerifyAttestationRequest`
  messages to the SDK-facing contract (`seam-runtime/crates/seam-api/proto/seam/api/v1/seam.proto:262-283`).
  The SDK exposes the sibling `verify_party_anchor` (`python/seam_sdk/client.py:324`, `ts/src/client.ts:237`)
  but **no** `verify_party_attestation`.
- **A14 (#183)** upgraded the audit chain from *integrity* to *authenticity*: a v2 record digest
  recomputable from on-wire structural columns, and a signed `CHAIN_HEAD_ATTESTATION` verifiable against
  the pinned issuer key. The SDK's independent verifier (`verify/`) proves only the chain **link**
  (`checksum = H(prev ‖ digest)`, `verify/src/verify.rs:80-146`) — it takes `digest` as given and has no
  `--issuer` mode. Its README still claims INTEGRITY (`verify/README.md:59`).
- **CP-09 (#191)** revived `SESSION_LIFECYCLE` (advisory, tag 21) and **A8/A10 (#179/#196)** finalized the
  chained/classification story. `verify/` already treats `SESSION_LIFECYCLE` as advisory
  (`verify/src/wire.rs:277`); the SDK clients pass all event kinds through opaque.

**Two facts that reshape the naive plan, both verified:**

1. **The generated stubs are git-ignored, not committed.** `.gitignore` excludes `/gen/`,
   `python/seam_sdk/_gen/`, `ts/gen/` ("regenerated from the contract on release"). There is no
   committed drift to "fix"; `make generate` (from the BSR) / `make generate-local RUNTIME=../seam-runtime`
   refreshes them. So SDK work = the **hand-written wrappers + tests + the `verify/` tool**, which *are*
   committed. Only **Python and TypeScript** have hand-written clients (+ a `SeamAdminClient`); Go/Java/Kotlin
   are gen-only + a crypto shim (`README.md:161-170`).

2. **A genuine runtime contract-vs-wire drift exists, but it gates only *streamed-event decoding*, not the
   two core SDK deliverables.** The SDK-facing `seam.api.v1.SeamEvent` is meant to mirror the canonical
   `seam-store` wire (`SeamEventPb`) — its own comment says "Tags mirror `seam-event.v1`
   `DecisionSealedPb`" — but the mirror is **missing four fields**:

   | Field | Canonical wire (event.rs) | SDK proto (seam.proto) |
   |---|---|---|
   | `SeamEvent.session_lifecycle` | tag 21 (+ `SessionLifecyclePb`) | **absent** (message absent entirely) |
   | `SeamEvent.chain_head_attestation` | tag 22 | **absent** (message exists for SeamTrust, not wired into SeamEvent) |
   | `DecisionSealed.ciphertext_digest` | tag 10 (mandatory for v2) | **absent** (stops at `schema_version`=9) |
   | `AuditEntryEvent.actor` | tag 4 (operator attribution) | **absent** (stops at `reason`=3) |

   Consequence: a gRPC `StreamEvents` consumer generated from the contract silently drops
   `SESSION_LIFECYCLE` payloads, cannot decode `CHAIN_HEAD_ATTESTATION`, and — because `ciphertext_digest`
   is the one input it doesn't otherwise hold — **cannot recompute digest-v2 from the stream at all**.

   But: the `verify_party_attestation` RPC + `ChainHeadAttestation` message are **already** in the proto
   (SeamTrust), so the attestation client wrapper needs only a regen, not the mirror fix. And `verify/`
   reads the **raw `seam-event.v1` wire** via its own independent proto
   (`verify/proto/seam/event/v1/seam_event.proto`) — which the spec defines completely — so the `verify/`
   authenticity upgrade needs **no runtime change at all**. The mirror fix (Phase 0) is a prerequisite
   *only* for the SDK gRPC client to decode the new event payloads / verify streamed events (Phase 6).

**BSR freshness is unknown.** The SDK generates from `buf.build/zer07labs/seam`. The runtime pushes on
main-merge only when `BUF_TOKEN` is set (the A13 guard now fails loud otherwise,
`seam-runtime/.github/workflows/ci.yml:119-133`), so whether A4/A14 reached the BSR is open — and even a
fresh BSR lacks the four Phase-0 fields until Phase 0 lands and re-pushes. The plan verifies BSR state
and uses `generate-local` as the developer baseline.

**Out of scope (confirmed):** T3.5 archive-drain (`GET /v1/archive/bundles`, `POST /v1/archive/ack`) and
B2 `/metrics` are HTTP **management-plane** surfaces with **no proto/gRPC representation at all** — they
are net-new contract surface, not an SDK gap. The SDK's closest existing surface is
`SeamAdminClient.stream_events(follow=False, ack=True)` (`python/seam_sdk/admin.py:187`). Deferred with a
note.

---

## Phase ordering at a glance

| # | Phase | Repo | Depends on | Gated? |
|---|---|---|---|---|
| 0 | Mirror the 4 drift fields into `seam.api.v1` + BSR re-push | **seam-runtime** | — | BSR push = user-gated 1WD |
| 1 | BSR-freshness check + generate-local dev baseline | seam-sdk | — | — |
| 2 | `verify_party_attestation` client wrapper (Py + TS) | seam-sdk | 1 | — |
| 3 | `verify/` authenticity — attestation (`chain --issuer`, design-b) | seam-sdk | — | — |
| 4 | `verify/` authenticity — digest-v2 recomputation (design-a) | seam-sdk | 3 | — |
| 5 | Differential-harness closure + conformance regen + README AUTHENTICITY flip | both | 3, 4 | README flip = D-034 decision entry |
| 6 | *(optional)* SDK gRPC decodes the new event payloads + streamed digest-v2 verify | seam-sdk | 0, 1 | — |

Phases 2, 3 run in parallel after Phase 1 (2 needs the contract; 3 needs nothing). Phase 0 blocks only
Phase 6.

---

## Phase 0 — Mirror the four drift fields into `seam.api.v1` (seam-runtime)

**Delivers.** The SDK-facing contract byte-mirrors the canonical wire: `SeamEvent.session_lifecycle` (tag
21) + a `SessionLifecycle` message, `SeamEvent.chain_head_attestation` (tag 22), `DecisionSealed.ciphertext_digest`
(tag 10), `AuditEntryEvent.actor` (tag 4). A gRPC `StreamEvents` consumer can then decode every event
payload the runtime emits and recompute digest-v2 from the stream.

**Depends on.** Nothing.

**Files (seam-runtime).**
- `crates/seam-api/proto/seam/api/v1/seam.proto`: add the four fields at their exact canonical tags; add a
  `SessionLifecycle` message mirroring `SessionLifecyclePb` (`event.rs:581-591`: `phase`=1, `mode`=2,
  `policy_version`=3, `opened_at_millis`=4); wire `chain_head_attestation` to the existing
  `ChainHeadAttestation` message. Correct the now-false comments at `seam.proto:437` ("Tags mirror…"),
  `:466` ("Exactly one of the payload fields (13–18)"), `:474`.
- Wherever `seam.api.v1` ↔ `seam-store` conversion happens (the gRPC event mapping in
  `crates/seamd/src/grpc.rs` / the `SeamEvent` mapping): populate the four new fields end-to-end so a
  `StreamEvents` response actually carries them (an unpopulated proto field is as useless as a missing one).

**Approach.** Purely **additive at fixed tags** — the drift is one-directional (proto omits wire fields;
no field exists in proto-not-wire, no tag collisions). Adding at the canonical tag numbers is
`buf breaking`-safe under the `WIRE_JSON` policy (`seam-runtime/buf.yaml:18-20`). *Rejected:* inventing new
tag numbers — it would fork the SDK wire from the canonical wire permanently (a one-way door), and the two
are explicitly meant to be identical. The `SessionLifecycle` message must be a new type (none exists in
the proto); reuse the existing `ChainHeadAttestation` message for tag 22 (it already exists for SeamTrust,
tag-identical to `ChainHeadAttestationPb`).

**Edge cases & failure modes.**
- **Mapping omission** — adding the proto field but not populating it in the gRPC mapper yields a
  silently-empty field, indistinguishable to the client from the pre-fix state. The acceptance test must
  assert a *streamed* event carries the payload, not just that the proto compiles.
- **`ciphertext_digest` on v1 records** — v1 records legitimately have no tag 10; the field is `optional`
  and absent-on-v1 is correct. A **v2** record missing tag 10 is a strip attack (spec:156-166) — that's a
  verifier concern (Phase 4), not a mapping bug, but the mapper must never drop tag 10 on a v2 record.
- **`buf breaking` false alarm** — none expected (additive), but if the BSR base predates digest/checksum
  the check runs against `git#branch=buf-base` (main), so it compares to the current proto, not the BSR.

**Acceptance criteria.**
1. `seam.proto`'s `SeamEvent` contains `optional SessionLifecycle session_lifecycle = 21;` and
   `optional ChainHeadAttestation chain_head_attestation = 22;`; `DecisionSealed` contains
   `bytes ciphertext_digest = 10;`; `AuditEntryEvent` contains `optional string actor = 4;` — each at the
   exact tag, matching `event.rs`.
2. A `SessionLifecycle` message exists with fields `phase`=1, `mode`=2, `policy_version`=3,
   `opened_at_millis`=4.
3. `buf breaking --against '.git#branch=buf-base'` passes (additive).
4. A test drives a real `StreamEvents` and asserts a `SESSION_LIFECYCLE` event arrives with a populated
   `session_lifecycle` payload, and a v2 `DECISION_SEALED` arrives with a non-empty `ciphertext_digest`.
5. The three stale proto comments are corrected.

**Tests.** A seam-runtime gRPC integration test (extend the existing `crates/seamd/tests/grpc.rs`) that
opens a session (→ `SESSION_LIFECYCLE`), seals a v2 decision (→ `DECISION_SEALED` with `ciphertext_digest`),
and streams them, asserting the four fields decode. `buf breaking` in CI is the additive-safety gate.

**One-way door — the BSR re-push.** After the proto change merges, the contract must be pushed to
`buf.build/zer07labs/seam` for the SDK's `make generate` to see it. This runs on main-merge **iff
`BUF_TOKEN` is set**; publishing to the BSR is immutable per label — **user-gated, never auto-run here.**
Until it's pushed, the SDK uses `generate-local` (Phase 1).

---

## Phase 1 — BSR-freshness check + generate-local dev baseline (seam-sdk)

**Delivers.** A repeatable, verifiable answer to "what contract are the SDKs actually built against?", and
a `generate-local` workflow pinned to the runtime checkout so all later phases have the RPC + fields
regardless of BSR state.

**Depends on.** Nothing (Phase 0 sharpens what a *fresh* BSR should contain, but this phase runs first to
de-risk).

**Files.**
- `Makefile`: add a `check-contract` target that greps the generated stubs (or `buf` the module) for
  `VerifyPartyAttestation` and fails loudly if absent — the SDK equivalent of the runtime's
  published-surface gate.
- `scripts/` (new, or extend): a small script asserting the generated Python/TS stubs expose the expected
  symbols; wire it into `make check-contract`.
- `README.md`: document the BSR-vs-local decision (when to `generate` vs `generate-local`) and that the BSR
  push is a runtime-side, user-gated step.

**Approach.** Treat the contract the SDK builds against as a **verifiable input**, not an assumption —
directly mirroring the runtime's own hard-won lesson (the published-surface gate that had been merging
red). Prefer `generate-local RUNTIME=../seam-runtime` as the **developer baseline** for Phases 2–6 so work
is never blocked on a BSR push; the BSR remains the **release** source. *Rejected:* assuming the BSR is
fresh — the A13 history says it may not be, and a silent-stale contract would make Phases 2/6 pass locally
and break on release.

**Edge cases & failure modes.**
- **BSR has A4 but not Phase-0 fields** — likely if #186 pushed but Phase 0 hasn't. `check-contract` must
  distinguish "has VerifyPartyAttestation" (Phase 2 unblocked) from "has SeamEvent tag 21/22" (Phase 6
  unblocked) — two separate probes.
- **`buf registry login` not done** — `make generate` fails; `generate-local` is the fallback and must be
  documented as such.

**Acceptance criteria.**
1. `make check-contract` exits non-zero when the active stubs lack `VerifyPartyAttestation`, zero when
   present — proven by running it against a stale and a fresh regen.
2. `make generate-local RUNTIME=../seam-runtime` produces stubs containing `VerifyPartyAttestation` (the
   RPC is already in the runtime proto).
3. A documented record (in the PR or `README.md`) states what the BSR currently exposes (probed, with the
   command shown) and whether a re-push is pending.

**Tests.** `check-contract` is itself the test (run in the SDK's CI). A one-shot manual probe of the BSR
(`buf build buf.build/zer07labs/seam -o -# | grep`) recorded in the PR.

---

## Phase 2 — `verify_party_attestation` client wrapper (Python + TypeScript)

**Delivers.** `verify_party_attestation(party_id, attestation) -> bool` on the Python and TS data-plane
clients, mirroring `verify_party_anchor`.

**Depends on.** Phase 1 (a contract exposing the RPC — via `generate-local` if the BSR is stale).

**Files.**
- `python/seam_sdk/client.py`: add `verify_party_attestation` next to `verify_party_anchor` (~:324).
- `ts/src/client.ts`: add `verifyPartyAttestation` next to `verifyPartyAnchor` (~:237); re-export any new
  message type from `ts/src/index.ts` if the client's public surface needs it.
- `python/tests/test_integration.py`, `ts/tests/integration.test.ts`: env-gated live coverage.
- Unit coverage where a stub can be mocked without a live server.

**Approach.** Mirror the existing wrapper **exactly** — same signature shape (id + pb message → bare
`bool` from `.valid`), same stub-call pattern, same docstring register. The verified shapes to copy:

```python
# python/seam_sdk/client.py:324
def verify_party_anchor(self, party_id: str, anchor: pb.Anchor) -> bool:
    return self._trust.VerifyPartyAnchor(pb.VerifyAnchorRequest(party_id=party_id, anchor=anchor)).valid
```
```typescript
// ts/src/client.ts:237
async verifyPartyAnchor(partyId: string, anchor: Anchor): Promise<boolean> {
  return (await this.trust.verifyPartyAnchor({ partyId, anchor })).valid;
}
```

New: `verify_party_attestation(self, party_id, attestation: pb.ChainHeadAttestation) -> bool` calling
`VerifyPartyAttestation(pb.VerifyAttestationRequest(party_id=…, attestation=…)).valid`, and the TS twin.
*Rejected:* a richer typed wrapper that re-models the attestation — the anchor wrapper takes the pb message
directly and returns `bool`; consistency beats novelty, and the runtime returns exactly `{valid}`.

**Edge cases & failure modes.**
- **Unknown party / tampered attestation → `valid=false`, not an error** — the runtime returns
  `valid:false` for both (it's a boolean verdict, `seam.proto:282` "unknown party or any tamper =>
  valid=false"). The wrapper must surface `false`, never raise. A negative test asserts this.
- **Stale local stubs** — if `generate-local` wasn't run, `pb.ChainHeadAttestation` won't exist and the
  wrapper won't import; Phase 1's `check-contract` catches this before code review.
- **Go/Java/Kotlin** — out of scope (gen-only, no client wrapper). The regen makes the RPC callable on the
  raw generated stub in those languages; no hand-written surface is added (consistent with `README.md:161-170`).

**Acceptance criteria.**
1. `SeamClient.verify_party_attestation` (Py) and `verifyPartyAttestation` (TS) exist, take
   `(party_id, ChainHeadAttestation)`, return `bool`, and call `SeamTrust/VerifyPartyAttestation`.
2. Against a live runtime: a valid attestation for a registered party → `true`; a tampered signature, a
   tampered field, and an unknown party each → `false` (never an exception) — mirroring the runtime's own
   A4 test trio.
3. No change to any other client method; `verify_party_anchor` behavior byte-identical.
4. Both clients build against `generate-local` stubs.

**Tests.** Extend `test_integration.py` / `integration.test.ts` (env-gated, spawn `SEAM_GRPC_BIN` with
`SEAM_DEV_INSECURE`) with a register-party → attest → verify(valid/tampered/unknown) flow, mirroring
`seam-runtime/crates/seamd/tests/grpc.rs::grpc_verify_party_attestation_trio`.

---

## Phase 3 — `verify/` authenticity: attestation verification (`chain --issuer`, design-b)

**Delivers.** `seam-verify chain <FILE> --issuer <AID>` that, on top of the link check, verifies every
`CHAIN_HEAD_ATTESTATION` against the **pinned** issuer AID (signature + head-at-position) and **REFUSES a
stream with zero valid attestations** — catching a fabricated (internally-consistent) chain and a spliced
foreign attestation. The independent verifier reaches parity with the runtime's `chain --issuer` on the
attestation half.

**Depends on.** Nothing runtime-side (the `seam-event.v1` spec is complete). Must stay **Seam-crate-free**.

**Files.**
- `verify/proto/seam/event/v1/seam_event.proto`: add the `ChainHeadAttestation` payload (tag 22) to the
  independently-transcribed event proto.
- `verify/src/wire.rs`: parse `chain_head_attestation` (tag 22) into a `ChainHeadAttestationPb` + its JSON
  projection; extend `is_link()`/`is_advisory()` classification (CHAIN_HEAD_ATTESTATION is **chained** —
  it carries digest/checksum — so it advances the head like any link, but additionally it is *verified*
  under `--issuer`).
- `verify/src/verify.rs`: add `chain_head_attestation_payload()` (the framed preimage), the ed25519
  verify (reuse `aid_to_key` + the `ed25519_dalek` path already used by `erasure_certificate`), the
  head-at-position check, and the zero-attestations refusal.
- `verify/src/main.rs`: add the `--issuer <AID>` flag to `chain`, an `IssuerReport`, and the verdict
  wiring (mirrors the runtime's `verify_issuer`, `seam-runtime/crates/seam-verify/src/main.rs:353`).
- `verify/tests/authenticity.rs` (new): drive the golden trio.

**Approach.** Design-(b) first because it is the **cheaper, higher-leverage** half and reuses machinery
already present: `aid_to_key` (`verify.rs:174`) + the pinned-issuer ed25519 verify (`verify.rs:erasure_certificate`)
are exactly the pattern an attestation needs, and it closes the *fabricated-chain* hole (the sharpest
authenticity gap: an internally-consistent chain verifies under integrity-only). The framed preimage is
transcribed verbatim from the spec (`docs/specs/seam-event.v1.md:128-134`):

```
signature = Ed25519( SHA256(
    frame("seam.audit.chain-head-attestation.v1")
  ‖ frame(le64(attested_len)) ‖ frame(attested_head)
  ‖ frame(le64(attested_at)) ‖ frame(le32(digest_schema)) ‖ frame(issuer_aid) ) )
```
with `frame(x) = le32(len(x)) ‖ x`. The **pin is load-bearing** (same discipline as the erasure cert): the
key comes from the caller's `--issuer` AID, never from the attestation, or verification is tautological.
The **head-at-position** check (`attested_head == running_head at attested_len`) is what kills an
*authentic* attestation spliced into a forged chain. **Zero valid attestations ⇒ REFUSE** under `--issuer`
— a forger cannot mint one, so their absence is the fabricated-chain tell (a green-with-no-attestations
would be a coverage hole reporting green). *Rejected:* keying chained-ness on `kind` — the crate's
existing invariant is field-presence, and CHAIN_HEAD_ATTESTATION carries digest/checksum, so it's a link
by the same rule.

**Edge cases & failure modes.**
- **Attestation over a `seq` the stream doesn't reach** — `attested_len` beyond the stream length: the
  position check has no head to compare; treat as FAIL (an attestation must cover a prefix the stream
  actually contains).
- **Multiple attestations** — verify each; the report's covered-prefix is the max `attested_len` of any
  *valid* one. One invalid attestation is FAIL even if others pass (a forged one in the mix is an attack).
- **`digest_schema != 2`** — bound into the signature (spec:120-124) to block a v2→v1 downgrade claim; a
  mismatch between the attested schema and the records is a FAIL, not a silent pass.
- **`--issuer` on a stream with no attestations at all** — REFUSE (above), never "0 checked, PASS".
- **AID text form** — reuse `aid_to_key`'s dual-form handling (`aid:pubkey:` and `aid:pubkey:ed25519:`).

**Acceptance criteria.**
1. `chain --issuer <AID>` on `attested_chain.jsonl` (the runtime golden) → exit 0, report names ≥1
   attestation and the covered prefix length.
2. `chain --issuer <AID>` on `fabricated_chain.jsonl` → exit 2 (no valid attestation).
3. A stream with an *authentic* attestation spliced from another chain → exit 2 (head-at-position).
4. `chain` **without** `--issuer` still passes on `attested_chain.jsonl` (integrity-only, unchanged) —
   proving `--issuer` is the strictly-stronger gate.
5. `verify/Cargo.toml` gains **no** Seam dependency (the independence invariant, `verify/src/main.rs:1-16`).
6. The runtime's committed golden trio verdicts (attested→PASS, fabricated→FAIL) match this binary.

**Tests.** `verify/tests/authenticity.rs` runs the built `seam-verify` binary against copies of the
runtime golden trio (`seam-runtime/crates/seam-verify/tests/goldens/`), asserting exit codes. A unit test
of `chain_head_attestation_payload` against the `chain_head_attestation` KAT in
`seam-runtime/crates/seam-client/tests/conformance_vectors.json`.

---

## Phase 4 — `verify/` authenticity: digest-v2 recomputation (design-a)

**Delivers.** Under `--issuer`, the verifier recomputes each `DECISION_SEALED`'s v2 digest from the
on-wire structural columns and compares it to the wire `digest` (tag 19), and **REFUSES a v2 record with no
`ciphertext_digest` (tag 10)** — catching a *payload rewrite* (flip `outcome`, keep the triple) and a
tag-10 strip/downgrade, even in a stream with no attestation.

**Depends on.** Phase 3 (shares the `--issuer` plumbing and report).

**Files.**
- `verify/proto/seam/event/v1/seam_event.proto`: add the `DecisionSealed` payload (tag 13 on the envelope)
  with its structural fields incl. `ciphertext_digest` (tag 10).
- `verify/src/wire.rs`: parse the `DecisionSealed` payload (tags 1-10) + its JSON projection.
- `verify/src/verify.rs`: add `record_digest_v2()` — the framed formula — and the compare + strip refusal.
- `verify/src/main.rs`: fold the digest recompute into the `--issuer` pass; extend `IssuerReport`.
- `verify/tests/authenticity.rs`: add the `payload_rewrite` golden case.

**Approach.** Transcribe the digest-v2 framing verbatim from the spec
(`docs/specs/seam-event.v1.md:294-312`):
```
digest_v2 = SHA256(
    frame("seam.audit.record-digest.v2")
  ‖ frame(decision_id) ‖ frame(tenant) ‖ frame(namespace)
  ‖ frame(SHA256(ciphertext))            // == wire ciphertext_digest, payload tag 10
  ‖ frame(le64(sealed_at))
  ‖ frame(outcome) ‖ opt(mode) ‖ opt(policy_version) ‖ opt(supersedes)
  ‖ frame(le32(schema_version)) )        // == 2
```
`opt(x) = 0x00 | (0x01 ‖ frame(x))` — so `None ≠ Some("")` (load-bearing; a naive empty-string collapse
is a real bug). This is the point where the verifier must, unavoidably, decode the record's **structural
surface** — a deliberate widening of its parse scope (the crate's own note says a verifier "has no
business decoding a decision's payload", `verify/src/wire.rs:6-9`). That tension is *why* this is a
separate phase and a documented decision: design-a is the price of catching a payload rewrite in an
unattested stream. It stays Seam-free — it reads the raw wire per the transcribed proto, computes SHA-256
with `sha2`. *Rejected:* skipping design-a and relying on the attestation alone — an attestation only
covers a prefix and only exists if the runtime emitted one; a payload rewrite *below* the attested prefix
in an unattested tail would slip past design-b. Design-a makes every v2 record self-verifying.

**Edge cases & failure modes.**
- **v1 record (schema_version=1)** — v1 digest is the unframed historical formula and is **not**
  stream-recomputable (spec:314-324); the verifier must select by `schema_version` and *not* attempt v2
  recompute on a v1 record (that would false-fail). v1 records fall back to link-only.
- **v2 record missing tag 10** — REFUSE (strip attack, spec:156-166): the one input the recompute needs is
  gone, and a silent "can't check → pass" is exactly the downgrade the attacker wants.
- **`ciphertext_digest` present but `ciphertext` absent from the stream** — correct and expected: the
  stream carries `ciphertext_digest` (the SHA-256), never the ciphertext; the recompute uses the digest
  directly (`frame(ciphertext_digest)`), it does not re-hash ciphertext.
- **Ordering / framing drift** — a single wrong `frame`/`opt`/`le` produces a total mismatch (fails loud,
  never a subtle pass); pin against the runtime `record_digest_v2` KAT.

**Acceptance criteria.**
1. `chain --issuer <AID>` on `payload_rewrite.jsonl` (outcome flipped, triple intact) → exit 2 (recomputed
   v2 digest ≠ wire digest).
2. A hand-built v2 stream with a stripped tag 10 → exit 2 (strip refusal).
3. `attested_chain.jsonl` still → exit 0 (every genuine v2 digest recomputes correctly).
4. A v1 record in a stream is link-verified but **not** v2-recomputed (no false failure).
5. `record_digest_v2()` matches the `record_digest_v2` KAT vector byte-for-byte.
6. Still **no** Seam dependency in `verify/Cargo.toml`.

**Tests.** `verify/tests/authenticity.rs` gains the `payload_rewrite` + tag-10-strip cases (exit 2) and a
v1-record case (link-only). A unit test of `record_digest_v2` against the KAT.

---

## Phase 5 — Differential-harness closure + conformance regen + README AUTHENTICITY flip

**Delivers.** The runtime's differential harness runs the public verifier on **authenticity** cases and
the two agree; the SDK conformance corpus carries the golden trio + the A14 KAT vectors; `verify/README`
moves from INTEGRITY to AUTHENTICITY — but only after the payload-rewrite repro is *watched fail*.

**Depends on.** Phases 3 and 4 (the public verifier must have `--issuer` with both checks).

**Files.**
- **seam-runtime** `crates/seam-verify/tests/differential.rs`: extend `the_two_verifiers_agree_on_every_stream`
  with `--issuer` cases (attested→PASS, fabricated→FAIL, payload_rewrite→FAIL, spliced→FAIL); ensure the
  harness locates the public verifier (`SEAM_SDK_DIR` / sibling checkout — the current skip fires when it's
  absent, `differential.rs:135-144`).
- **seam-sdk** `conformance/vectors.json`: extend to carry (or reference) the `chain_head_attestation` and
  `record_digest_v2` vectors (from `seam-client/tests/conformance_vectors.json`), so the SDK's own
  conformance suite pins the A14 KATs. Copy the golden trio into an SDK fixtures dir.
- **seam-sdk** `verify/README.md`: INTEGRITY → AUTHENTICITY (line ~59 and the header claim), documenting
  `--issuer`.
- A decision record (SDK `plans/` or a `DECISIONS`-style note) capturing the D-034 authenticity upgrade.

**Approach.** The differential harness is the *only* thing that stops the independent verifier drifting
into a rubber stamp (`differential.rs:140-143`); extending it to `--issuer` cases is what proves the two
verifiers agree on **authenticity**, not just integrity. The README flip follows the **D-034 protocol**
(from the connectors' UPSTREAM-001 discipline): wording moves to AUTHENTICITY *only after* the
payload-rewrite repro has been **watched fail** under the new checks and recorded in a decision entry —
never a bare wording change. *Rejected:* flipping the README in Phase 3/4 — the claim isn't earned until
the differential harness proves parity and the repro is demonstrated red-then-green.

**Edge cases & failure modes.**
- **Harness can't find the public verifier** — the skip must not be mistaken for a pass; the acceptance
  requires the harness to actually **run** (SEAM_SDK_DIR set in the runtime CI, or the SDK checked out
  beside the runtime).
- **Golden drift** — if the runtime regenerates the goldens (`REGEN_GOLDENS=1`), the SDK copies drift;
  the plan pins the SDK fixtures to a specific runtime commit and adds a drift note ("regenerate from
  seam-runtime@<sha>").
- **Vector schema mismatch** — the SDK `conformance/vectors.json` currently has only `admission`/`tct`
  keys; adding `chain_head_attestation`/`record_digest_v2` must not break the existing Go/Java/Kotlin
  conformance shims that read it (they ignore unknown keys — verify).

**Acceptance criteria.**
1. `crates/seam-verify/tests/differential.rs` **runs** (not skips) with the public verifier present and
   asserts agreement on ≥4 `--issuer` cases (attested/fabricated/payload_rewrite/spliced).
2. The SDK conformance suite (Py + TS) verifies the `chain_head_attestation` + `record_digest_v2` KATs
   offline (byte-exact), and the existing Go/Java/Kotlin shims still pass on the extended vectors.
3. `verify/README.md` says AUTHENTICITY and documents `--issuer`; a decision entry records the upgrade
   with the payload-rewrite repro shown failing under the new check.
4. The golden-trio fixtures in the SDK match the runtime's committed goldens (byte-identical), pinned to a
   named runtime commit.

**Tests.** The extended `differential.rs` (runtime). The SDK conformance tests
(`python/tests/test_conformance.py`, `ts/tests/conformance.test.ts`) gain the two KATs. The README/decision
entry is a review artifact, not a test — but the repro it cites is Phase 4's `payload_rewrite` test.

---

## Phase 6 — *(optional)* SDK gRPC decodes the new event payloads + streamed digest-v2 verify

**Delivers.** The Python/TS clients surface `session_lifecycle` / `chain_head_attestation` / `actor` on
streamed events, and (optionally) a client-side `verify_streamed_chain` that recomputes digest-v2 from the
`StreamEvents` feed — closing the loop so an SDK user can verify authenticity live, not just from an
exported file.

**Depends on.** Phase 0 (the mirror) **and its BSR re-push**, plus Phase 1.

**Files.** `python/seam_sdk/`, `ts/src/`: optional typed accessors / a `KNOWN_KINDS` enum; optionally port
the Phase-4 digest-v2 recompute into a client helper (Python/TS, not linking `verify/`).

**Approach.** Deferred and optional because: (a) it is the **heaviest** piece (a second digest-v2 impl in
Py + TS), (b) it hard-depends on the user-gated BSR push, and (c) the primary authenticity story is
delivered by the standalone `verify/` tool (Phases 3–4) which works on exported streams today. Surface it
only if a user needs *live, in-client* verification. *Rejected for now:* building it before Phase 0's push
lands would be dead code against a contract the SDK can't yet generate.

**Acceptance criteria (when taken up).**
1. A streamed `SESSION_LIFECYCLE` event exposes its `session_lifecycle` payload (not kind-only) in Py + TS.
2. A streamed v2 `DECISION_SEALED` exposes `ciphertext_digest`; a client helper recomputes its v2 digest
   and matches the runtime.
3. `KNOWN_KINDS` (if added) includes `SESSION_LIFECYCLE` and `CHAIN_HEAD_ATTESTATION`; unknown kinds still
   pass through opaque (no regression).

**Tests.** Env-gated integration tests streaming real events post-Phase-0.

---

## Long-term posture & one-way doors

- **BSR push (Phase 0 tail)** — immutable per label; **user-gated**. The plan never auto-pushes. Until it's
  pushed, the SDK's *release* generation (`make generate` from the BSR) lacks the four fields; `generate-local`
  is the interim. Forecloses nothing if deferred — it only gates Phase 6 and the *release* (vs local) regen.
- **Any SDK package publish (PyPI / npm / Maven)** — out of scope here and **user-gated**; this plan ships
  code + tests, not releases. Flag before any `poetry publish` / `npm publish`.
- **The README AUTHENTICITY flip** — a claim, not just prose. Once shipped it tells third parties the
  independent verifier detects forged chains; it must be earned (Phase 5 gate) and is a D-034 decision
  entry, reversible only by retraction (expensive — it's a public trust claim).
- **`verify/` parse-surface widening (Phase 4)** — decoding the DecisionSealed structural columns
  permanently couples the verifier to the digest-v2 framing. Priced: it's the cost of catching a payload
  rewrite in an unattested stream. Kept behind `--issuer` so integrity-only callers are unaffected.
- **Tag-number choices (Phase 0)** — the four fields are pinned to the canonical wire tags (21/22/10/4);
  choosing *different* tags would fork the SDK wire from the canonical wire forever. Not a door we open.

## Enterprise concerns

- **Independence invariant (security)** — `verify/` links **zero** Seam crates; every phase touching it
  (3, 4) must keep `Cargo.toml` Seam-free (an acceptance criterion in each). This is the entire product
  claim — a verifier that imports Seam proves nothing.
- **The pin is the trust root (security)** — both attestation (Phase 3) and erasure-cert verification take
  the issuer key from the caller's `--issuer` AID, never from the artifact; the tautology guard is
  load-bearing and tested.
- **Fail-closed verdicts (reliability)** — every "can't verify" path (zero attestations, stripped tag 10,
  position mismatch, v1 pre-cutover under `--strict`) must **REFUSE**, never silently pass. This is the
  runtime's recurring-defect through-line ("a signal that reports healthy because it never looked") and the
  acceptance criteria enforce it per phase.
- **Contract-as-verifiable-input (reliability)** — Phase 1's `check-contract` prevents the SDK from
  silently building against a stale contract, mirroring the runtime's published-surface gate.
- **Observability** — the verifier's `--json` report should carry the new authenticity facts (attestation
  count, covered prefix, digest-recompute result) so a CI consumer can assert on them, not just exit code.
- **Migration/rollback** — Phase 0 is additive (no wire break); the SDK regen is reproducible from a pinned
  runtime commit; the golden fixtures are pinned to a named runtime SHA so a runtime golden regen is a
  deliberate, reviewable SDK update, not a silent drift.

## Open questions (confirm before /implement)

1. **Phase 0 ownership.** The four-field mirror is a **seam-runtime** change (a real contract-vs-wire drift
   in the runtime), not an SDK change. Confirm it should land as a seam-runtime PR (owned by whoever owns
   the runtime contract) and that this SDK plan may *depend on* it but not author it. *Proposed default:*
   yes — file it as a seam-runtime issue/PR; the SDK plan proceeds on Phases 1–5 (which don't need it) in
   parallel. **Assumption to confirm.**
2. **BSR push cadence.** Is `BUF_TOKEN` configured in seam-runtime CI (i.e., is the BSR being pushed on
   main-merge at all)? If not, `make generate` (release path) is already broken and Phase 1 should surface
   that as its headline finding. *Needs a fact I couldn't read from code* (it's a CI secret).
3. **digest-a scope.** Is catching a *payload rewrite in an unattested stream* in scope for the public
   verifier, or is attestation-only (Phase 3) sufficient for the product claim? Phase 4 is the heavier,
   parse-widening half. *Proposed default:* include it — the runtime's own `--issuer` does both, and the
   differential harness's `payload_rewrite` case demands it for parity. **Assumption to confirm.**
4. **Phase 6.** Is live in-client authenticity verification wanted, or is the standalone `verify/` tool the
   intended delivery vehicle? *Proposed default:* defer Phase 6; ship Phases 0–5. **Assumption to confirm.**
5. **SESSION_LIFECYCLE surfacing.** Once Phase 0 mirrors the payload, should the SDK clients expose it
   typed, or keep passing events through opaque (today's behavior)? *Proposed default:* opaque pass-through
   until a consumer needs it (no KNOWN_KINDS churn). **Assumption to confirm.**
