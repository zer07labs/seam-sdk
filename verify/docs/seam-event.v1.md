<!-- Pinned copy of seam-runtime/docs/specs/seam-event.v1.md @ 0b62cb7 (refreshed 2026-08-24 for B3
     record-digest v3). The runtime spec is the source of truth; refresh this copy whenever the spec
     changes — a stale copy here once shipped a real verifier bug (the AUTHORIZE_EVALUATED advisory
     omission), and it was stale again before this refresh: it carried no §Record digest (v3) at all,
     while src/verify.rs implements it.
     Refreshed VERBATIM, whole-file, deliberately: a reviewer can `diff` it against the sibling
     checkout and get nothing, which is a checkable claim. Cherry-picking only the v3 sections would
     read as tidier and would quietly end that property.
     The advisory-kind tripwire in src/wire.rs cross-checks the LIVE runtime spec when the sibling
     checkout is present; this file is what third parties build from when it is not. -->

# `seam-event.v1` — event-stream wire spec (language-neutral)

**Status:** Normative (v1 draft). The published contract for the runtime's **outbox** — the ordered,
hash-chained, classification- and tenant-tagged event stream that every external consumer reads:
`seam-connectors` (SIEM/Slack/data-platform/…) and the event-driven `seam-learning` plane. It is the
integration surface, the same way the open protocol specs are. Authored here (not in a connectors
crate) because it is shared and the runtime's `seam-store` outbox **emits** it.

> **Canonical form:** Protobuf (matches MACP/pb tooling). A **JSON projection** is defined for HTTP
> webhooks. The Rust side (`seam-store`) either generates the type from the schema or guards a
> hand-rolled struct with a schema-conformance test against the canonical fixtures.

## Why a spec, not a Rust struct

A wire schema (not a `seam-types` struct) is what lets a Python/Go/TS connector exist at all. The
`EventStream` Ring-0 trait (`append(&[u8])`) carries **opaque bytes**; this spec defines what those
bytes are. The kernel never names a connector; connectors never link the kernel.

## Event

```
SeamEvent {
  schema_version:  string   // "seam-event.v1"
  event_id:        string   // unique, stable per event (idempotency key for consumers)
  seq:             u64       // monotonic over the runtime's single ordered outbox — the ordering key
  occurred_at:     u64       // millis; injected at emit, never wall-clock-read on the binding path
  tenant:          string    // tenant_id (every event is tenant-tagged — invariant 10)
  namespace:       string    // namespace_id
  classification:  string    // the record/event classification label (drives per-consumer redaction)
  kind:            EventKind // see below
  session_id:      string?   // present for session-scoped events
  decision_id:     string?   // present for decision-sealed events
  cost_micros:     u64       // per-event cost signal (R11 — observability, not a record field)
  prev_checksum:   bytes     // hash-chain link → the head this event's chain extends (tag 12)
  digest:          bytes?    // §A — this entry's record/action digest; CHAINED kinds only (tag 19)
  checksum:        bytes?    // §A — the head this entry produces = H(prev_checksum ‖ digest) (tag 20)
  payload:         bytes     // kind-specific body (central seam-guard redaction on the outbox is NOT YET WIRED — see the Redaction note below)
}

enum EventKind {
  DECISION_SEALED   // a DecisionRecord reached a terminal outcome (Resolved/Expired/...)
  AUDIT_ENTRY       // an entry appended to the hash-chained audit log WITHOUT a sealed decision (tag 16)
  LEARNING_DECISION // ADVISORY — the per-dimension arm the orchestrator chose (not chained; tag 14)
  LEARNING_OUTCOME  // ADVISORY — a delayed correctness report for a decision (not chained; tag 15)
  BUDGET_BREACH     // ADVISORY — the 6.2 R9 escalation signal (not chained; tag 17)
  ERASURE_CERTIFICATE // the signed GDPR erasure attestation (CHAINED; tag 18)
  CHAIN_HEAD_ATTESTATION // the issuer-signed audit chain head (A14; CHAINED; tag 22)
  SESSION_LIFECYCLE // ADVISORY — a session lifecycle transition, "opened" only today (not chained; tag 21)
  AUTHORIZE_EVALUATED // ADVISORY — one advisory authorization was evaluated (not chained; tag 23)
}
```

> **Revived kind — `SESSION_LIFECYCLE` (CP-09), at its reserved tag 21.** This kind was once removed as
> never-implemented (A11: spec-declared with no payload struct, no prost tag, no emitter — a filter
> against it silently matched nothing). It returns **with its producer in the same change**, exactly as
> the removal note demanded: the runtime emits `phase: "opened"` on every INTERACTIVE session open (the
> producer the control plane's fail-closed retire/drain workflow consumes to learn which sessions are
> live). Terminals stay observable via `DECISION_SEALED`; a one-shot `run_decision` emits no "opened"
> (its seal arrives in the same call). The `spec_kind_sync` conformance test
> (`seam-store/tests/spec_kind_sync.rs`) continues to pin spec-set == emitted-set, and its dedicated
> revival guard now asserts the kind stays implemented. Tag 21 was reserved for precisely this revival
> (D-002) and is now permanently taken; the A14 attestation keeps tag 22.

### `AUDIT_ENTRY` (additive, tag 16 — chained)

A hash-chained audit event for actions that produce **no** `DecisionRecord` — nothing was
decided, but the refusal itself must be provable. Carries the chain link (`prev_checksum` is
the audit head it extends, plus `digest`/`checksum` per §A) and the envelope `decision_id` holds
the synthetic chain id (e.g. `admit-reject:<session_id>`, `scope-deny:<session_id>`).

> **Exception — the chain anchor.** One `AUDIT_ENTRY` variant, `action: "chain_anchor"`, is emitted
> **off-chain** (empty `prev_checksum`, no `digest`/`checksum`) — it *records* a chain head for the
> out-of-band notary/anchor without perturbing the chain it anchors. It is therefore **advisory** by the
> operational rule below (no `digest` ⇒ not a chain link), not a chained event, despite its `AUDIT_ENTRY`
> kind. A verifier keys on field presence, not on `kind` (see §Ordering & integrity).

```
AuditEntry {                               // payload at SeamEvent tag 16
  action:  string   // "admit.compat_reject" (enterprise 6.4) | "execute.scope_deny" (6.3)
  subject: string   // the agent acted on (the offending participant)
  reason:  string   // the rendered typed denial — no secrets, no free-text agent content
}
```

### `ERASURE_CERTIFICATE` (additive, tag 18 — chained)

The signed GDPR erasure attestation (enterprise 2.6): which decisions were crypto-shredded
for a data subject, which were withheld under legal hold, when, and the audit-chain head the
certificate anchors to. Ed25519-signed by the runtime **issuer key** — a data subject or
regulator verifies it from the published issuer AID alone (the domain-separated payload is
`seam.erasure-certificate.v1` length-prefixed framing of every field; see
`seam-trust-aitp::verify_erasure_certificate` for the reference verifier). The event is
**chained** (`prev_checksum` set): the attestation rides the same tamper-evident stream as
the `gdpr_erasure` audit entries it certifies.

```
ErasureCertificate {                       // payload at SeamEvent tag 18
  subject:     string   // the data subject (an AID or operator-scoped subject id)
  erased:      [string] // decision ids whose keys are destroyed (incl. previously shredded)
  held:        [string] // decision ids withheld by legal hold — disclosed, never silent
  erased_at:   u64      // injected run time (millis)
  chain_head:  bytes    // the audit-chain head at certification
  issuer_aid:  string   // the runtime issuer identity (same key as the TCT issuer)
  signature:   bytes    // Ed25519 over the domain-separated certificate payload
}
```

### `CHAIN_HEAD_ATTESTATION` (additive, tag 22 — chained) — A14

The audit chain's `(len, head)` **signed by the runtime issuer key** — the keyed root that closes the
fabricated-chain gap. An unkeyed SHA-256 chain with a public genesis lets a transport-controlling adversary
rebuild a self-consistent chain from any fork point; a signed head cannot be minted without the issuer key,
so a forged chain carries no valid attestation and fails verification. The event is **chained**
(`prev_checksum` set) so it is itself tamper-evident and `--strict`-clean, and rewriting any entry at or
before an attestation breaks a link on the path to a **signed** value.

```
ChainHeadAttestation {                     // payload at SeamEvent tag 22
  attested_len:  u64      // number of chain links covered = the head's 1-based position
  attested_head: bytes    // the checksum at position attested_len (32 bytes)
  attested_at:   u64      // injected millis
  issuer_aid:    string   // the runtime issuer identity (same key as the TCT + erasure cert)
  digest_schema: u32      // the record-digest formula the attested chain uses (2 = A14 v2) — the
                          // downgrade guard: bound into the signature so a v2 chain can't be claimed v1
  signature:     bytes    // Ed25519 over the signed framing below
}
```

**Signed framing** (over the 32-byte SHA-256 **digest**, never the preimage):

```
signature = Ed25519( SHA256(
    frame("seam.audit.chain-head-attestation.v1")
  ‖ frame(le64(attested_len)) ‖ frame(attested_head)
  ‖ frame(le64(attested_at)) ‖ frame(le32(digest_schema)) ‖ frame(issuer_aid) ) )
```

**Semantics — a true statement about a prefix.** An attestation asserts: *the entry at position
`attested_len` carries checksum `attested_head`, and the issuer said so.* The chain may advance between the
head read and the append (no lock is held across read→sign→append), so a "stale" attestation is simply one
over a shorter, still-covered prefix; a verifier checks the head **at that position**.

**Triggers.** Emitted at **boot** (every restart leaves a signed head immediately, covering restart gaps),
**every N chain entries** (`SEAM_CHAIN_ATTEST_EVERY`, default 1000; `0` disables — the every-N worker is
**ON by default**, unlike the opt-in retention worker, because an authenticity root that is opt-in is the
gap persisting by default), and at **every anchor boundary** (attest-then-anchor, so the externally
notarized `(len, head)` transitively pins an issuer-signed head — see `audit-anchor.md`). The empty chain
(`attested_len == 0`) is never signed (no genesis attestation).

**Verification** (`seam-verify chain --issuer <AID>`): (a) every `CHAIN_HEAD_ATTESTATION` verifies against
the **pinned** issuer AID (a mismatch is refused before any signature work — deriving the key from the
attestation's own `issuer_aid` would let a forgery verify against its forger), AND its `attested_head`
equals the running head after `attested_len` chained links (an authentic attestation replayed into a
fabricated chain dies on this position check); (b) for every `DECISION_SEALED`, recompute the record
digest (spec §Record digest) from its payload and compare it to the event's `digest` (tag 19) — a
mismatch is a **payload rewrite** (a structural column was changed after sealing; the chain link still
hashes, but the payload no longer matches it); (c) **a `schema_version >= 2` `DECISION_SEALED` that lacks
a non-empty `ciphertext_digest` (tag 10) ⇒ REFUSE.** A v2 record is *required* to carry its commitment, so
an absent tag 10 on a covered record is a **tag-10 strip / downgrade attack** — rewrite a field, drop the
commitment, leave the `(prev,digest,checksum)` triple intact (the signed head cannot catch it: tag 19 is
copied unchanged, so the head still matches and the signature verifies) — or a non-conforming producer.
Both fail under `--issuer`; treating the strip as *cannot-recompute, not-a-failure* is exactly the hole
design (a) exists to close. This is scoped to the covered class: v1 (`schema_version = 1`) records are not
recomputable and never required a commitment, so they are skipped, not failed; and without `--issuer` none
of (a)–(d) runs (a consumer with no issuer key legitimately checks integrity only); (d) **zero valid
attestations under `--issuer` ⇒ REFUSE** — a forger cannot mint one, so their absence is the
fabricated-chain tell, and a green-with-no-attestations would be a coverage hole reporting green.

### `SESSION_LIFECYCLE` (additive, tag 21 — advisory, not chained) — CP-09

A session lifecycle transition for the session named by the envelope `session_id`. **Advisory**: it
carries no `digest`/`checksum` and never perturbs the audit chain (a verifier keys on field presence,
§Ordering & integrity). Emitted on interactive session opens only; consumers MUST tolerate unknown
`phase` values (additive vocabulary).

```proto
message SessionLifecycle {           // envelope tag 21
  string phase = 1;                  // "opened" (only phase emitted today; vocabulary is additive)
  string mode = 2;                   // the canonical MACP mode id the session opened in
  string policy_version = 3;         // the policy bound at open
  uint64 opened_at_millis = 4;       // the caller-injected session clock at open
}
```

Envelope: `event_id = "{session_id}#lc:{phase}@{opened_at_millis}"` — salted with the open timestamp
because a session id can be RE-opened after sweep eviction, and delivery dedups by `event_id` (an
unsalted id would pin a deduping consumer to the first open's stale payload). `classification` is
**fixed `Internal`** (operational metadata — phase/mode/policy/timestamp; no subject, secret, or agent
content — so classification-gated redaction rules never fire on this kind: gate on `when_kind`).

### `AUTHORIZE_EVALUATED` (additive, tag 23 — advisory, not chained)

The audit row for one advisory authorization (`SeamAuthorization.Authorize`). That path **seals
nothing** — no decision record, no DEK, no chain append — so this event is the *only* trace the call ever
happened, and `authorize_id` (a ULID) is its handle. **Advisory**: no `digest`/`checksum`, empty
`prev_checksum`; chaining a hot per-tool-call loop into the audit ledger would let traffic volume drive
the chain. The envelope `decision_id` is deliberately **absent** — an `authorize_id` is not a
`decision_id`, and populating it would invite a consumer to join to a sealed decision that does not exist.

```proto
message AuthorizeEvaluated {           // envelope tag 23
  string authorize_id = 1;             // ULID — the handle returned to the caller
  optional string client_request_id = 2; // the caller's idempotent audit-join key, when supplied
  string agent_aid = 3;                // the VERIFIED caller AID (derived, never asserted)
  string agent_id = 4;                 // the registry identity the scope floor was evaluated against
  string tool_name = 5;
  string tool_input_digest = 6;        // "sha256:<hex>" over the RFC 8785 (JCS) canonical input
  string verdict = 7;                  // "ALLOW" | "DENY" | "TRANSFORM" | "ESCALATE"
  string reason = 8;                   // closed-set / operator-authored only (D-030)
  string policy_version = 9;
  optional string subject_digest = 10; // sha256(subject) hex — NEVER the raw subject
}
```

Envelope: `event_id = "{authorize_id}#az#{seq}"`; `classification` is **fixed `Internal`** (ids, digests,
and a closed-set reason — no subject, secret, or agent content can reach it, so classification-gated
redaction never fires: gate on `when_kind`).

**PII rule.** The end-user data subject rides ONLY as `subject_digest = sha256(subject)`. GDPR erasure
walks *decision records*; an outbox row is un-shredable, so a raw end-user id here would be an
un-erasable copy of it. The digest stays correlation-preserving — an erasure operator recomputes it.

**Emission contract.** Emission is per-namespace config (`authorize.emit_events`, default on) with an
`authorize.event_sample_rate` knob — **except for `ESCALATE`**, which always emits (sampling-exempt) and
whose append is **fail-closed**: an ESCALATE whose append fails returns an error rather than the verdict,
because an escalation nobody can ever see is not an escalation. ALLOW/DENY/TRANSFORM appends stay
fail-open (verdict returned, `seam.security` WARN logged). The `{authorize_id, client_request_id?,
agent_aid, agent_id, tool_name, tool_input_digest, subject_digest?, reason}` field set on an ESCALATE row
is the complete contract a future control-plane escalation inbox consumes — built from events alone, with
no wire change.

### `BUDGET_BREACH` (additive, tag 17 — advisory, not chained)

The enterprise-6.2 escalation signal on the R9 Suspended/HITL path. `severity: "hard"` means
the session is now **Suspended**, waiting for an approver to resume, raise the budget, or
cancel (its TTL is paused); `"soft"` is the once-per-session early warning. Joined to the
session by the envelope `session_id`; the envelope `cost_micros` carries the ledger's cost
spend (R11) — as it now also does on `DECISION_SEALED`.

```
BudgetBreach {                             // payload at SeamEvent tag 17
  severity:    string   // "hard" | "soft"
  dimension:   string   // "messages" | "tokens" | "cost_micros" | "wall_ms"
  limit:       u64      // the limit on the breached dimension
  messages:    u64      // ── the full ledger snapshot at the breach ──
  tokens:      u64
  cost_micros: u64
  wall_ms:     u64
}
```

`DECISION_SEALED` payloads carry the **structural** (non-encrypted) columns of the `DecisionRecord`
(`decision_id`, `tenant`, `namespace`, `mode`, `policy_version`, `outcome`, `supersedes`, `sealed_at`,
`schema_version`, …) — never the `Encrypted<Commitment>` plaintext. A consumer that needs the
commitment body holds the key; the stream never carries openable secrets.

Since `schema_version = 2` (**A14**) the payload **must** carry `ciphertext_digest` (payload **tag 10**):
`SHA256(ciphertext)` — the one input to the record digest a stream consumer does not hold, collapsed to
32 bytes. It discloses nothing (a hash of a high-entropy AEAD ciphertext) and lets a consumer recompute
the record `digest` from what it received (see §Record digest). It is absent (no wire bytes) only on
`schema_version = 1` payloads.

**A stripped tag 10 on a v2 record is an attack, not a safe downgrade.** Dropping tag 10 while leaving the
`(prev_checksum, digest, checksum)` triple intact lets an adversary rewrite a structural column and evade
the recompute — the signed head cannot catch it, because `digest` (tag 19) is copied unchanged. Under
`--issuer` a verifier therefore **fails** a `schema_version >= 2` `DECISION_SEALED` that lacks a non-empty
`ciphertext_digest` (see §Ordering & integrity Verification (c)); it does **not** treat the strip as a
downgrade to integrity-only. The legitimate "no issuer key ⇒ integrity-only" story is unchanged — it is a
property of running *without* `--issuer`, not of stripping a field the producer is required to emit.

### Advisory learning kinds (additive, v1)

`LEARNING_DECISION` and `LEARNING_OUTCOME` are **advisory**: emitted by the orchestrator layer
(`seamd`), **never** by the kernel, carrying **no binding authority**. They ride the same `SeamEvent`
envelope but are **not** part of the audit hash-chain (`prev_checksum` is empty) and are joined to a
decision by the envelope `decision_id`. They are **purely additive** — a `DECISION_SEALED` event's wire
bytes are byte-identical to the pre-learning schema (the new payloads live at fresh prost **tags 14/15**,
absent on a decision event). The external `seam-learning` plane consumes them; ordinary connectors that
don't understand them ignore them (tolerant-reader rule). Consumers dedup by `event_id`.

```
LearningDecision {                         // payload at SeamEvent tag 14
  policy_key: PolicyKey { tenant, task_type, context_class, mode }  // the posterior-keying tuple
  dimension:     string   // "policy" | "agent" — which decision dimension this arm is for
  algorithm_id:  string   // e.g. "thompson-v1"
  candidate:     string   // the chosen arm (policy/agent)
  experiment_id: string?  // optional A/B experiment id      (tag 5)
  algorithm_arm: string?  // optional experiment arm         (tag 6)
  features:      double[] // the served x (LinUCB); empty for Thompson (tag 7)
  schema_id:     string?  // the FeatureSchema x was encoded under; None for Thompson (tag 8)
  propensity:    double?  // P(arm | x) at serve time — for retroactive off-policy eval (IPS/SNIPS/DR).
                          // Reserved (tag 9); absent until the serving read populates it. Once real
                          // traffic flows an unlogged propensity is unrecoverable, so the slot is fixed now.
}

LearningOutcome {                          // payload at SeamEvent tag 15
  correct:     bool       // did the decision turn out right?
  verified_by: string?    // the reporter (system / human / automated feed) — for filter/weight
  policy_key:  PolicyKey? // the arm's OWNER KEY (tag 3) — additive, may be absent. See below.
}
```

**`LearningOutcome.policy_key` (tag 3, additive — #354).** Carries the per-arm **owner key
`(tenant, task_type, mode)`**, so a relay can partition by arm and give `seam-learning`'s
`OnlineEngine` the "one arm, one owner" precondition its LinUCB order-dependent γ discounting and
absolute-write posterior folding require. Without it, two relay partitions can carry the same arm and
race on the same posterior (a same-arm lost update).

Two contract properties consumers MUST respect:

- **`context_class` is always empty here** — it is computed from request-scoped features that are
  never sealed (see `DecisionRequest.features`), so it cannot be recomputed at outcome time. The owner
  key deliberately excludes it. **Do not treat this field as full arm identity**; it is not the same
  tuple as `LearningDecision.policy_key`, which does carry a real `context_class`.
- **Absent, never partial.** It is omitted entirely when the sealed record has no `mode`, or when the
  learning plane is disabled. A partial key with an empty `mode` would be *coarser than declared* and
  would silently merge distinct arms — the exact bug this field exists to prevent.

Being `optional`, an absent `policy_key` costs zero wire bytes, so pre-#354 goldens remain
byte-identical. Consumers that do not yet mirror tag 3 will **silently drop it on
decode→re-encode** (the tolerant-reader rule cuts both ways): mirror the field before keying
anything on it, or it will read as permanently absent.

The decision being scored is identified by the **envelope `decision_id`**, not a payload field — so the
`LEARNING_DECISION` (per dimension) and the later `LEARNING_OUTCOME` join on it.

## Ordering & integrity

- **Ordering** is by `seq`, monotonic over the runtime's **single ordered outbox stream** (one global
  hash chain). `tenant`/`namespace` are tags consumers **filter** on; they are not separate chains in v1.
  Consumers track one cursor (at-least-once delivery; `event_id` dedups). _Per-`(tenant,namespace)`
  sub-streams with independent cursors are a forward-compatible v2 enhancement._
- **Chain:** a **chained** event carries three fields — `prev_checksum` (the head it extends), `digest`
  (its own record/action digest), and `checksum` (the head it produces, `= H(prev_checksum ‖ digest)`).
  **Chained-ness is by field presence, not by `kind`:** an event is on the chain iff `digest` + `checksum`
  are present (equivalently, `prev_checksum` is non-empty). The chained kinds are `DECISION_SEALED`,
  `AUDIT_ENTRY`, and `ERASURE_CERTIFICATE` — **except** the `action: "chain_anchor"` `AUDIT_ENTRY`, which is
  emitted off-chain (no `digest`) and is *not* a link. Advisory kinds (`LEARNING_DECISION`,
  `LEARNING_OUTCOME`, `BUDGET_BREACH`) likewise set none of the three. A consumer
  verifies the whole chain **from the stream alone, without trusting the transport**: with
  `running_head = 32 zero bytes` (genesis), for each event **that has a `digest`** in `seq` order, assert
  `prev_checksum == running_head`, assert `checksum == H(prev_checksum ‖ digest)` (**this link is now
  cryptographically checkable** — the `digest` input is on the wire, §A), then advance
  `running_head = checksum`. This detects a forged/inserted/rewritten event, not merely a dropped one; an
  attacker stripping tags 19/20 off a chained event is caught at the next link (`prev_checksum ≠
  running_head`) — equivalent in power to dropping it, which a tail-strip aside is covered by the
  out-of-band anchor (`audit-anchor.md`). The `digest` is computed per §Record digest below — from
  `schema_version = 2` it covers every structural column a consumer acts on plus `SHA256(ciphertext)`,
  so a consumer recomputes it from the wire; it discloses nothing a consumer does not already hold.

## Retention & the relay-consumed cursor (R1)

The outbox is **garbage-collected against the relay's durably-consumed cursor**, never against the
operator ack-drain's `published` flag. A consumer relaying the outbox (e.g. `seam-connectors`) reports its
progress with `SeamEvents.ReportEventsConsumed(consumed_cursor)`; the runtime keeps a durable, **monotone**
high-water from it (a lower re-report is ignored) and prunes a row only when it is **both** below that
cursor **and** older than the retention window (`SEAM_OUTBOX_RETENTION_MILLIS`, default 7 days), always
retaining the current max-`seq` row so the `seq` allocator cannot regress.

- **Never pruned below what the relay needs.** Because prune deletes only `offset < consumed_cursor`, a row
  at or above the cursor is never removed — so the relay's contiguous resume (`from_seq = last + 1`) can
  never skip a deleted row and mis-read the gap as a chain violation.
- **`consumed_cursor` MUST be the relay's contiguous-delivery high-water.** It is the first offset the relay
  has **not** durably delivered downstream. The relay **must stop the cursor at the first row it could not
  deliver** (an undecodable/poison row it skipped on the follow-tail) — never advance past it — so that row
  stays `>= cursor` and is preserved for repair. Reporting a cursor past a skipped row would let the runtime
  prune an undelivered row.
- **Before any relay reports**, the cursor is absent and prune is a **strict no-op**: the outbox grows but
  is never corrupted. `ReportEventsConsumed` requires the operator `events:consume` scope (it drives a
  destructive prune).

## Record digest

The `digest` field (tag 19) on a `DECISION_SEALED` event is selected by the payload's `schema_version`.
All framing is byte-exact and any-language-reproducible. `frame(x) = le32(len(x)) ‖ x` (a little-endian
u32 length prefix, then the bytes). `opt(x) = 0x00` when the field is absent, `0x01 ‖ frame(x)` when
present — so `None` and `Some("")` are distinct. `le64`/`le32` are little-endian fixed-width integers.

### Record digest (v3) — `schema_version = 3` (B3)

v2 binds identity, the ciphertext, and every structural column on the wire. It does **not** bind the two
columns carrying the product's actual claims: **who participated** and **what context the decision
consumed**. Until B1/B2 those were a placeholder and an engine backfill, so digesting them would have
bound noise. v3 binds them, as two rolled-up 32-byte sub-digests plus the policy rules that gated the
commitment.

```
digest_v3 = SHA256(
    frame("seam.audit.record-digest.v3")          // domain + version, in-preimage
  ‖ frame(decision_id) ‖ frame(tenant) ‖ frame(namespace)
  ‖ frame(SHA256(ciphertext))                      // == the wire ciphertext_digest (payload tag 10)
  ‖ frame(le64(sealed_at))
  ‖ frame(outcome) ‖ opt(mode) ‖ opt(policy_version) ‖ opt(supersedes)
  ‖ frame(context_digest)                          // 32 bytes, below — wire tag 11
  ‖ frame(participation_digest)                    // 32 bytes, below — wire tag 12
  ‖ opt(policy_rules_digest)                       // 32 bytes when a policy was bound — wire tag 13
  ‖ frame(le32(schema_version))                    // == 3
)
```

Slot indices below are **0-based over the preimage above**, with slot 0 the domain tag: so
`context_digest` is slot 10, `participation_digest` 11, `policy_rules_digest` 12, `schema_version` 13.
(These are digest-preimage positions, not proto field numbers — on `DecisionSealed` the three new
columns take the free wire tags 11/12/13, which happen to be offset by one.)

Slots 1–9 are byte-identical to v2, and slot 0 differs only in its version suffix, and `schema_version` stays last. **The three
new slots are inserted before `schema_version`, not appended after it** — a verifier selects the whole formula by
`schema_version`, so position is fixed by this spec rather than by append order.

**Strings hash as their raw UTF-8 bytes**, with no normalization of any kind — no Unicode NFC/NFD, no
case folding, no trimming. This covers `ctx_ref`, `lineage_id`, mode ids, `agent_id`, `pinned_version`,
and the enum strings below. Ingress already constrains most of these to a safe ASCII charset, but the
digest does not rely on that and must not: normalization is a step three of four implementations would
implement differently, or skip.

**One framing rule, and exactly one exception, named.** In both sub-preimages below: *every field is
framed, every optional is `opt`-encoded, and every list is preceded by a bare `le32` count* — including
fixed-width fields such as the 32-byte `manifest_digest`. A list count is **4 bytes, not framed**. There
are four independent implementations of this in three languages; a rule with exceptions is where they
drift, so the single exception is called out where it occurs rather than left to be discovered: the
`scope(...)` blob is pre-existing bytes v3 reuses verbatim, and *its* internal counts are framed. See
`scope(...)` below. Nothing else in v3 frames a count.

The two sub-digest domain tags below are `seam.audit.context-provenance.v3` and
`seam.audit.participation.v3`, rather than the shorter `seam.ctx.v3` / `seam.part.v3` the B3 plan named.
The change is deliberate: every other domain string in this system is `seam.audit.<thing>.<version>`, and
a domain tag whose only job is to be unique and unmistakable should not be the one place the convention
breaks. It is recorded here because it is a change to a decided one-way door, and a silent one would be
worse than the inconsistency it fixes.

#### `context_digest` — `seam.audit.context-provenance.v3`

```
context_digest = SHA256(
    frame("seam.audit.context-provenance.v3")
  ‖ le32(len(context_provenance))                  // OUTER count, BARE le32 — see the collision note
  ‖ for each binding, in STORED ORDER:
        frame(ctx_ref) ‖ frame(fidelity) ‖ frame(classification)
      ‖ opt(lineage_id) ‖ frame(le32(version))
      ‖ le32(len(derived_from)) ‖ for each: frame(derived_from[i])
      ‖ opt(content_hash) ‖ opt(receipt_hash) ‖ opt(key_status) ‖ opt(resolved_status)
)
```

`fidelity` and `classification` encode as their **canonical PascalCase strings** — `Reference` /
`Digest` / `Value` / `Derivation`, and `Public` / `Internal` / `Confidential` / `Financial` / `Pii` /
`Phi` — never as ordinals. An ordinal silently renumbers the moment a variant is inserted into the
middle of an enum, and three of the four implementations would not notice.

**This PascalCase rule is scoped to these two fields and does not generalize.** It applies because both
are *closed* Seam-owned enums with a fixed variant list. It must **not** be extended by analogy to the
reserved slots below — see the payload note there.

`lineage_id`, `derived_from`, and `version` live on a nested `provenance` struct in the runtime's type;
the preimage **flattens them** into the order shown and adds no marker for the nesting. The nesting is
a Rust convenience, not a wire fact.

**Stored order is the caller's order** and is normative: inline `contexts` (as their content refs) first,
then cited `context_refs`, each in request order. Duplicates are refused at ingress. **The digest never
sorts and never de-duplicates** — it hashes what was stored. Sorting would force every implementation to
replicate a canonicalization step; de-duplicating would let a sealed record diverge from the request that
produced it.

The order is also the *open-time* order: the kernel seals the view's frozen bindings and never re-reads,
so a mid-session registration can never enter this preimage.

**The last four fields are RESERVED and are `0x00` (absent) on every record this build seals.** They are
where ACDP receipt provenance lands — retained `content_hash`, `receipt_hash`, `key_status`, and resolved
lifecycle status. Reserving them now means adopting receipts later fills presence bytes rather than
forcing a v4: a record sealed today and a record sealed after receipts land both recompute under this one
formula. Without the reservation, `schema_version` would stay 3 while the encoding changed underneath it,
and a verifier could not tell the two apart.

The reservation was confirmed against the ACDP implementation at the version this runtime pins, not
inferred: a remote resolution yields exactly these four pieces of provenance, each a **scalar**, and a
registry receipt is **0-or-1 per binding by schema** — not a chain. A per-hop receipt chain is the one
shape that would have forced a counted list here, and it does not exist: derivation ancestry resolves
each ancestor as its own binding with its own four slots.

**The four payload encodings are D3's to pin, and one of them is a trap.** Filling these slots changes no
grammar, but D3 must state, for each: the ASCII `sha256:<hex>` form for `content_hash`; *which* preimage
`receipt_hash` covers (ACDP's own receipt signing-hash excludes the signature block, so "the receipt's
hash" is ambiguous and two implementations will choose differently); the closed PascalCase strings for
`key_status`; and — the trap — that `resolved_status` is an **open** enum whose canonical form is ACDP's
*lowercase* wire string, taken verbatim, including values this spec cannot enumerate. Applying the
PascalCase rule above to it by analogy would produce a cross-language mismatch.

Two semantics D3 must also fix, because they are what keep a mutable registry value safe to seal:
`resolved_status` is the status **observed at resolution time** and is **never refreshed** — a future
"status refresh" job would invalidate every sealed digest — and a sealed `retracted` should be
impossible by ingress, so a verifier that sees one should raise an anomaly rather than accept it.

**Named residuals, recorded so they are not rediscovered as bugs:** an ACDP lineage-head receipt (a
serve-time freshness attestation, mutable by design), a transparency-log inclusion proof (re-derivable
against a growing tree), and — in the no-receipt case only — the fingerprint of the key that verified the
body. The first two are correctly excluded from an immutable digest. The third is a real, accepted gap: a
third-party verifier recovers it by re-fetching the body, which carries its own key id.

#### `participation_digest` — `seam.audit.participation.v3`

```
participation_digest = SHA256(
    frame("seam.audit.participation.v3")
  ‖ le32(len(participation))                       // OUTER count, BARE le32
  ‖ for each decl, in STORED ORDER:
        frame(agent_id) ‖ opt(subject)
      ‖ le32(len(declared_modes)) ‖ for each: frame(declared_modes[i])
      ‖ frame(scope(declared_scope)) ‖ frame(pinned_version) ‖ frame(manifest_digest)
)
```

**Stored order for `participation` is admission order, then delegated subjects.** The column is the
session view's admitted participants in the order the kernel admitted them, followed by one synthetic
declaration per `on_behalf_of` entry in request order — `agent_id = "subject:{i}"`, `subject = Some(..)`,
no declared modes, an empty bounded scope, unpinned version and manifest. Those synthetic decls exist so
that delegation is inside the erasure predicate; they are ordinary rows to the digest. As with context,
**no sorting and no de-duplication.**

`scope(...)` is the **existing** canonical scope encoding — the same bytes the runtime already writes
when it computes `manifest_digest`. It is **reused, never re-derived**: a second encoding of the same
value is a second thing to keep in sync. It is written out in full here because "reuse it" is not
implementable by someone who does not have the Rust source:

```
scope(Unrestricted) = frame(0x00)

scope(Bounded{tools, actions, mode_cap}) =
    frame(0x01)
  ‖ frame(le32(len(tools)))    ‖ for each: frame(tools[i])
  ‖ frame(le32(len(actions)))  ‖ for each: frame(actions[i])
  ‖ frame(le32(len(mode_cap))) ‖ for each: frame(mode_cap[i])
```

**Every component is `frame`d, the counts included** — so a count occupies 8 bytes (`le32(4)` then four
count bytes), not 4, and the variant tag occupies 5, not 1.

**This is the one place in v3 where a count is framed, and it is a deliberate exception, not the rule.**
Everywhere else — the two outer counts, `derived_from`, `declared_modes` — a count is a bare 4-byte
`le32`. The difference exists because these are not bytes v3 encodes: they are the existing `put_scope`
output, reused verbatim so that the scope encoding has exactly one definition. Copying its convention
outward, or v3's convention inward, both produce a digest that no other implementation reproduces. The
other natural misreading is "a tag byte then a count" — also wrong, for the same reason: every component
here goes through the same framing helper. `scope(Unrestricted)` is 5 bytes; an **empty** `Bounded` is 29. The empty
bounded case is not hypothetical: every synthetic `subject:{i}` declaration carries exactly it, so any
record with a delegated subject exercises it.

The three sets are in this order — tools, actions, mode_cap — and each is in **sorted** order, which
costs the implementer nothing because they are stored as ordered sets; sorted order is a property of the
container, not a canonicalization step.

The result is one opaque blob, which the participation preimage then frames again as a single field.
`frame(scope(...))` is deliberate, not a doubled frame to be optimized away: it keeps the scope encoding
substitutable as a unit.

`pinned_version` and `manifest_digest` are **always present**, never optional. An unpinned participant
carries the **empty version string** and the sentinel unpinned manifest digest, which is **32 zero
bytes** — both are *values that mean unpinned*, and the record is meant to be auditable as such.
Encoding "unpinned" as an absent field would make a legacy deployment's records indistinguishable from
stripped ones.

**Why a rolled-up digest and not the list itself.** `participation[].subject` is the GDPR erasure
predicate. Publishing raw subjects on an append-only outbox that connectors fan out to SIEM and Iceberg
would make erasure unenforceable at the sink. Publishing their digest does not. The same reasoning
applies to context content.

**Erasure keeps working.** Crypto-shred destroys the record's DEK; it never touches the `participation`
or `context_provenance` columns. So a shredded record still recomputes `digest_v3` identically and still
proves its place in the chain — exactly as it does under v2.

#### `None` is not `Some("")` is not an empty list

Three distinct things that a careless implementation collapses:

- **`None`** — `opt` emits a single `0x00` byte and nothing else.
- **`Some("")`** — `opt` emits `0x01 ‖ le32(0)`, five bytes. A present-but-empty string is *data*.
- **an empty list** — a bare `le32(0)` and no elements, 4 bytes. (Inside the `scope(...)` blob only,
  an empty set is `frame(le32(0))` = 8 bytes, per the named exception above.) A binding with
  `derived_from = []` and one with
  `derived_from = [""]` therefore differ, as do a record with zero participants and one whose single
  participant has an empty id (which ingress refuses, but the digest must not depend on that).

The same holds at the top level: a record with `participation = []` has a perfectly well-defined
`participation_digest` — `SHA256(frame(domain) ‖ le32(0))` — not an absent slot. Slots 10 and 11 are
`frame`d, never `opt`ed, precisely so that "no participants" and "field stripped" cannot alias.

#### The outer count, and the collision it prevents

Each per-element preimage is arguably self-delimiting, so the outer `le32` count looks redundant. It is
not, and the reason is on the record: the erasure-certificate **v1** framing omitted exactly this and
collided — `erased=["a","b"], held=[]` hashed identically to `erased=["a"], held=["b"]`, because the
concatenation could not tell where one list ended and the next began. v3 counts every list, inner and
outer, so no rearrangement of elements between lists can produce the same preimage.

#### Strip semantics for tags 11/12/13

`context_digest` (11) and `participation_digest` (12) are **mandatory** on a `schema_version = 3`
payload. A consumer that receives a v3 payload with either absent **must refuse to verify** — it must not
substitute an empty digest, and it must not fall back to the v2 formula. Absent-when-required is a strip
attack, and it must be reported distinctly from a digest mismatch so an operator can tell "someone
removed a field" from "someone rewrote one".

`policy_rules_digest` is `SHA256(JCS(policy_definition))` over the policy actually bound to the
session — JCS rather than file bytes, so the digest is representation-independent and an unchanged
policy keeps its digest when policy delivery moves from local files to the control plane. As a
`digest_v3` input it is opaque, so recomputation does not require re-deriving it; the formula is stated
so an auditor can independently check *what the slot attests*, which is the point of sealing it.

It attests **which bytes the runtime applied**, not that those bytes were authentic. Authenticity is
signed-control-plane-policy work, orthogonal and later. An unsigned policy's digest is exactly as
seal-worthy as an unsigned decision payload's ciphertext hash, which v2 already seals.

`policy_rules_digest` (13) is genuinely optional: absent means no policy was bound to that commitment,
which is today's common case. Absent ≠ `Some(empty)` — the `opt` presence byte distinguishes them.

#### What v3 still does not cover

`trust_basis`, `classification`, and `participants` (the flat id list) remain outside the digest. They
are bound inside the commitment TCT, which is why this is acceptable rather than an oversight — but it
is a real residual and a v4 candidate, recorded here rather than left to be rediscovered.

### Record digest (v2) — `schema_version = 2` (A14)

```
digest_v2 = SHA256(
    frame("seam.audit.record-digest.v2")          // domain + version, in-preimage
  ‖ frame(decision_id) ‖ frame(tenant) ‖ frame(namespace)
  ‖ frame(SHA256(ciphertext))                      // == the wire ciphertext_digest (payload tag 10)
  ‖ frame(le64(sealed_at))
  ‖ frame(outcome) ‖ opt(mode) ‖ opt(policy_version) ‖ opt(supersedes)
  ‖ frame(le32(schema_version))                    // == 2
)
```

Coverage equals identity + `SHA256(ciphertext)` + **every structural column `DECISION_SEALED` carries on
the wire** (`decision_id` … `schema_version`, payload tags 1–9). A consumer that holds the payload and
`ciphertext_digest` (tag 10) recomputes `digest_v2` and compares it to `digest` (tag 19): a mismatch means
a structural column (e.g. `outcome`) was rewritten after sealing — the link's `(prev,digest,checksum)`
triple stays internally consistent, but the recomputed digest no longer matches. The length-prefixed,
domain-tagged framing also removes the field-boundary collisions of v1 (`"ab","c"` vs `"a","bc"`).

### Record digest (v1, historical) — `schema_version = 1`

```
digest_v1 = SHA256(decision_id ‖ tenant ‖ namespace ‖ ciphertext ‖ le64(sealed_at))
```

Unframed concatenation over the **ciphertext** (which is off-wire), with no domain tag and no structural
columns. It is **not** recomputable by a stream consumer and it collides across field boundaries — the two
reasons A14 replaced it. This build emits v2 only; v1 is documented solely so a verifier can re-bind a
`schema_version = 1` record from a pre-A14 fixture. There is **no dual-emit**: a verifier selects the
formula by `schema_version` (`2 ⇒` v2, `1 ⇒` v1) — never silently green on a version it cannot recompute.

> ### ⚠️ Pre-cutover events carry no `digest`/`checksum`, and a verifier CANNOT tell them from advisory ones
>
> The `digest`/`checksum` fields (tags 19/20) were added *after* the runtime began emitting events. Every
> event written **before** that cutover carries neither — and by the presence rule above, an event with no
> `digest` is *not a link*. To a verifier reading bytes, a pre-cutover `DECISION_SEALED` is
> **indistinguishable from an advisory event**: both simply lack the fields.
>
> The consequence is the dangerous kind: a verifier run over historical outbox rows **skips them and
> reports a green chain** — a green that is a claim about history it never actually checked. Nothing is
> wrong, and nothing was verified.
>
> A conforming verifier MUST therefore either:
>
> 1. **disclose** how many events it skipped for want of chain fields (never silently fold them into
>    "advisory"), or
> 2. **refuse** the stream outright when any non-advisory event lacks them.
>
> The reference implementation (`seam-verify`) does both: it reports an `UNVERIFIABLE` count by default,
> and `--strict` refuses. Note this is *not* a tamper-detection hole — an attacker who strips tags 19/20
> from a **post**-cutover event is still caught at the next link, because the head it should have produced
> no longer matches. It is a **coverage** hole, and coverage holes that report green are how an audit trail
> becomes decorative.

## Redaction (R8)

Central redaction (`seam-guard`) is applied to event **text before serialization** — never by decoding
the opaque `EventStream` bytes downstream. A less-trusted connector therefore never sees a raw payload;
per-destination `redaction_profile` (in the connector manifest) can redact further.

> **Note:** central redaction is **not yet wired** onto the outbox, so until it is, emitted payloads are
> **not** centrally redacted. Treat this section as the target, not as current behaviour.

## JSON projection (webhooks)

The JSON projection is a field-for-field mapping of `SeamEvent` with `bytes` fields base64-encoded and
`u64` fields as JSON numbers.

> **Note:** an in-core signed-webhook emitter (signing the JSON body, carrying the `prev_checksum`/head
> range) is **not built** — there is no HTTP delivery loop or body-signing in the runtime today, only this
> projection. A consumer reads the outbox stream and delivers/signs on its own side. (Tracked: plan T3.4/T4.)

## Versioning

`schema_version` is `"seam-event.v1"`. Consumers MUST be **tolerant readers** (ignore unknown fields).
A breaking change bumps to `seam-event.v2`; the runtime may emit both during a migration window.
