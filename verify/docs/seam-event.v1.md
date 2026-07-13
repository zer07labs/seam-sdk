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
  payload:         bytes     // kind-specific body, already central-redacted (seam-guard) before emit
}

enum EventKind {
  DECISION_SEALED   // a DecisionRecord reached a terminal outcome (Resolved/Expired/...)
  AUDIT_ENTRY       // an entry appended to the hash-chained audit log WITHOUT a sealed decision (tag 16)
  SESSION_LIFECYCLE // open / suspended / resumed / expired transitions
  LEARNING_DECISION // ADVISORY — the per-dimension arm the orchestrator chose (not chained; tag 14)
  LEARNING_OUTCOME  // ADVISORY — a delayed correctness report for a decision (not chained; tag 15)
  BUDGET_BREACH     // ADVISORY — the 6.2 R9 escalation signal (not chained; tag 17)
  ERASURE_CERTIFICATE // the signed GDPR erasure attestation (CHAINED; tag 18)
}
```

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
}
```

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
  `LEARNING_OUTCOME`, `BUDGET_BREACH`, `SESSION_LIFECYCLE`) likewise set none of the three. A consumer
  verifies the whole chain **from the stream alone, without trusting the transport**: with
  `running_head = 32 zero bytes` (genesis), for each event **that has a `digest`** in `seq` order, assert
  `prev_checksum == running_head`, assert `checksum == H(prev_checksum ‖ digest)` (**this link is now
  cryptographically checkable** — the `digest` input is on the wire, §A), then advance
  `running_head = checksum`. This detects a forged/inserted/rewritten event, not merely a dropped one; an
  attacker stripping tags 19/20 off a chained event is caught at the next link (`prev_checksum ≠
  running_head`) — equivalent in power to dropping it, which a tail-strip aside is covered by the
  out-of-band anchor (`audit-anchor.md`). The `digest` is a hash over the **sealed** record (ciphertext +
  identity columns) — the same value that anchor publishes; it discloses nothing a consumer does not
  already hold.

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
`u64` fields as JSON numbers. Signed-webhook delivery (the in-core built-in) signs the JSON body and
carries the `prev_checksum`/head range it covers.

## Versioning

`schema_version` is `"seam-event.v1"`. Consumers MUST be **tolerant readers** (ignore unknown fields).
A breaking change bumps to `seam-event.v2`; the runtime may emit both during a migration window.
