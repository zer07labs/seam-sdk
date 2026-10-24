<!-- Pinned copy of seam-runtime/docs/specs/seam-event.v1.md @ ae40c52 tracking feat/w11-p7-p12-contract-train (refreshed 2026-10-24).
     Pre-vendored ahead of the runtime 0.57.0 train (k8s P7, seam-sdk#266); re-pin to main when it lands.
     Movement since 320a998: §"Delivery stream `stream_id`" — SeamEvent.stream_id = 27 (every kind,
     UNSEALED: in no digest, checksum or signature), `{stream_id}/` event_id prefix from the history
     boundary on, StreamEventsRequest.stream_id = 4 / ReportConsumedRequest.stream_id = 2 refused
     FAILED_PRECONDITION `stream_id_mismatch` when empty or foreign, no discovery RPC. The verifier
     carries it in event identity only; the admin helpers require it.
     Prior pin 320a998 (refreshed 2026-10-20). Movements since 32f8196, the runtime 0.48.0 train, landed with the
     runtime 0.50.0 train (seam-runtime#1380, #1359):
     1. SESSION_LIFECYCLE "opened" carries `pins` (repeated AgentPin { agent_id, version }): one entry
        per admitted participant, in admission order, at the registry version admission pinned, plus
        the in-flight accounting rule and the restart gap. Operational metadata outside every digest
        this crate checks; the verifier does not act on it. The SDKs carry it as a passthrough of the
        generated SessionLifecycle message (contract/event-field-manifest.txt).
     Earlier movements (32f8196, runtime 0.48.0 train, seam-runtime#1365, seam-sdk#265): record digest
     v4 (DECISION_SEALED tags 14-17; v1-v3 cannot-verify), commitment digest
     seam-commitment-digest:v3, and context digest seam.audit.context-provenance.v4 with the optional
     `receipt_key_status` slot. -->

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
  event_id:        string   // unique, stable per event (idempotency key for consumers); `{stream_id}/{local}` since k8s P7 — see §Delivery stream
  seq:             u64       // monotonic over ONE stream's single ordered outbox — the ordering key WITHIN a stream; `(stream_id, seq)` across streams
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
  tenant_seq:      u64?      // #973 — per-tenant outbox counter, gap-free per `tenant`, UNSEALED; see §Per-tenant `tenant_seq` (tag 25)
  payload:         bytes     // kind-specific body (central seam-guard redaction on the outbox is NOT YET WIRED — see the Redaction note below)
  stream_id:       string    // k8s P7 — the runtime cell's delivery stream (`SEAM_STREAM_ID`); empty on legacy rows; UNSEALED; see §Delivery stream (tag 27)
}

enum EventKind {
  DECISION_SEALED   // a DecisionRecord reached a terminal outcome (Resolved/Expired/...) (CHAINED)
  AUDIT_ENTRY       // an entry appended to the hash-chained audit log WITHOUT a sealed decision (CHAINED; tag 16)
  LEARNING_DECISION // ADVISORY — the per-dimension arm the orchestrator chose (not chained; tag 14)
  LEARNING_OUTCOME  // ADVISORY — a delayed correctness report for a decision (not chained; tag 15)
  BUDGET_BREACH     // ADVISORY — the 6.2 R9 escalation signal (not chained; tag 17)
  ERASURE_CERTIFICATE // the signed GDPR erasure attestation (CHAINED; tag 18)
  CHAIN_HEAD_ATTESTATION // the issuer-signed audit chain head (A14; CHAINED; tag 22)
  SESSION_LIFECYCLE // ADVISORY — a session lifecycle transition, "opened" only today (not chained; tag 21)
  AUTHORIZE_EVALUATED // ADVISORY — one advisory authorization was evaluated (not chained; tag 23)
  POLICY_DENIED     // ADVISORY — a bound policy REFUSED a commitment (not chained; tag 24)
  EVENT_REDRIVEN    // ADVISORY — an operator re-drove an existing outbox event by reference; wraps its bytes (not chained; tag 26)
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

**`action` is an open string set; a consumer MUST treat an unknown value as opaque** (render it, never
reject the row). #1293 adds four management values, all chained under the subject's tenant and all carrying
**commitments in `subject`, never a raw data subject** (`subject` holds one commitment, or several joined
by `,`):

| `action` | Written when | Entry id (envelope `decision_id`) |
|---|---|---|
| `erasure_previewed` | an operator previews a GDPR erasure (`erasure:preview`), before the preview is returned | `erasure-preview:<tenant>@<millis>` |
| `subject_commitments_recomputed` | an operator recomputes subject commitments (`erasure:preview`), before they are returned | `subject-recompute:<tenant>@<millis>` |
| `subject_commitment_recompute_refused` | a recompute named a subject that is tombstoned in the tenant | `subject-recompute-refused:<tenant>@<millis>` |
| `subject_commitment_tombstoned` | a GDPR erasure, before anything is destroyed (once per subject and tenant) | `subject-tombstone:<commitment>` |

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
  digest_schema: u32      // CEILING: the highest record-digest formula that may appear in the attested
                          // prefix (this build signs 4 = record digest v4) — the downgrade guard,
                          // bound into the signature. A bound, not a description: see below.
  signature:     bytes    // Ed25519 over the signed framing below
  tenant:        string   // (tag 7, U-RT-3 Phase 2) which tenant's chain this attests; "" for the
                          // system partition. Selects the signed framing (see below): non-empty ⇒
                          // v2, which signs it (the runtime mints v2 since #835 step 3); "" ⇒ v1.
                          // Since #835 step 4 a verifier accepts no other combination, so a
                          // non-empty value is always a signed claim. An in-stream reader also
                          // requires it to equal the enclosing envelope's `tenant` (see below).
}
```

**Reader obligations on `tenant` (U-RT-3 Phase 3) — part of Verification below, not the wire shape
itself.** These bind an attestation to a tenant only where that attribution is actually load-bearing:
during **authenticity verification under a pinned issuer** (`seam-verify chain --issuer <AID>`, clause
(a) below). Without `--issuer` this field, like every other payload field authenticity inspects (b)–(d),
is opaque bytes the tool never interprets — integrity checking binds an attestation to a tenant only via
the enclosing envelope, exactly as it always has. Under `--issuer`: a reader MUST prefer the payload's
own `tenant`, and MUST refuse the attestation outright if it differs from the enclosing envelope's
`tenant` — one of the two is a lie, and a reader that picks whichever field it happens to read first can
be steered to the wrong tenant's coverage. **Since #835 step 4 this includes a payload `tenant` that is
empty while the envelope's is not** (an attestation minted between U-RT-1 and Phase 2, formerly accepted
as "tenant-unbound" and refused only under strict verification): it is refused unconditionally, because
its signature (v1) never named the tenant whose chain it is attributed to.

**Signed framing** (over the 32-byte SHA-256 **digest**, never the preimage). Two framings. **v1** —
`tenant` is not signed. The runtime mints v1 for the system partition (`tenant == ""`) only; it minted it
for every partition before #835 step 3, and since step 4 a v1 signature is accepted only with an empty
`tenant`:

```
signature = Ed25519( SHA256(
    frame("seam.audit.chain-head-attestation.v1")
  ‖ frame(le64(attested_len)) ‖ frame(attested_head)
  ‖ frame(le64(attested_at)) ‖ frame(le32(digest_schema)) ‖ frame(issuer_aid) ) )
```

**v2** (#835) — the v1 frames under a new domain tag, then `tenant`. Only ever minted over a non-empty
`tenant`; the system partition (`tenant == ""`) stays v1. **Since #835 step 3 every tenant attestation
the runtime mints is v2**, so its `signature` bytes differ from what v1 would produce for the same fields
and a v1-only verifier rejects it:

```
signature = Ed25519( SHA256(
    frame("seam.audit.chain-head-attestation.v2")
  ‖ frame(le64(attested_len)) ‖ frame(attested_head)
  ‖ frame(le64(attested_at)) ‖ frame(le32(digest_schema)) ‖ frame(issuer_aid)
  ‖ frame(tenant) ) )
```

KAT: `chain_head_attestation_v2` in `crates/seam-client/tests/conformance_vectors_extended.json` (the
shared v1 block in `conformance_vectors.json` is unchanged, and verifies with its empty `tenant`).
**Verifier rule (#835 step 4 — strict, no fallback):** the attestation's own `tenant` selects exactly one
framing. Empty `tenant` → **v1 only** (a v2 signature over `""` is refused; v2 is never minted over an
empty tenant). Non-empty `tenant` → **v2 only**: a v1 signature carrying a non-empty `tenant` is refused,
because its `tenant` sits outside the signature and could have been relabelled. There is no grace period
and no toggle. **Consequence for history:** a tenant attestation minted before step 3 (v1, with or without
a payload `tenant`) no longer verifies, so a window or bundle containing one fails authenticity; verify
history from a v2 anchor onward. The party verify route (`VerifyPartyAttestation`) looks the party's key
up under this same signed `tenant`, so its partition is never a caller-chosen selector. Rollout order:
runtime verifier accepts v2 (step 1) → seam-sdk and seam-connectors verifiers (step 2) → runtime signs v2
(step 3) → every verifier refuses v1 for a non-empty tenant (step 4).

**Semantics — a true statement about a prefix.** An attestation asserts: *the entry at position
`attested_len` carries checksum `attested_head`, and the issuer said so.* The chain may advance between the
head read and the append (no lock is held across read→sign→append), so a "stale" attestation is simply one
over a shorter, still-covered prefix; a verifier checks the head **at that position**.

**`digest_schema` is a ceiling, not a description — and it selects nothing.** The field asserts *every
record in the attested prefix has `schema_version <= digest_schema`*; a producer sets it to the highest
formula its build can stamp, which for this build is `4`. A ceiling only ever rises, and an attestation is
never re-signed.

A verifier **must not** read this field to choose a digest formula; it reads each record's own
`schema_version`, and every value other than `4` is refused as unknown (§Record digest — the verifier is
v4-only). The ceiling's job is narrower and is about the *signed artifact*: an attestation is handed to an
external notary, so it must state the verification regime truthfully. A build that stamps v4 while signing
a lower `digest_schema` would be issuing, under the issuer key, exactly the downgrade claim this field
exists to prevent.

**Triggers.** Emitted at **boot** (every restart leaves a signed head immediately, covering restart gaps),
**every N chain entries** (`SEAM_CHAIN_ATTEST_EVERY`, default 1000; `0` disables — the every-N worker is
**ON by default**, unlike the opt-in retention worker, because an authenticity root that is opt-in is the
gap persisting by default), and at **every anchor boundary** (attest-then-anchor, so the externally
notarized `(len, head)` transitively pins an issuer-signed head — see `audit-anchor.md`). The empty chain
(`attested_len == 0`) is never signed (no genesis attestation).

**Per partition, the system partition included (#1196).** Chains are per tenant (U-RT-1), so every trigger
above signs one head **per partition with a non-empty chain** — each tenant's, and the **system partition's**
(wire `tenant == ""`, Postgres `tenant_id IS NULL`: the config-install `AUDIT_ENTRY`s of
[Tenant tag](#tenant-tag--a-producer-rule-invariant-10)). The system partition's attestation is a
`CHAIN_HEAD_ATTESTATION` whose envelope `tenant` **and** payload `tenant` are both `""`, signed by the same
issuer key under the same framing, chained onto that partition's own prior entry (entry id
`chain-attest:<attested_len>`, position = that partition's link count), and it is the third and last kind
that may be tenant-less on the wire. It exists because a whole-chain evidence bundle carries the system
partition and a verifier under `--issuer` requires a covering attestation for **every** partition in the
window, `""` included — an unattested system partition is indistinguishable from a fabricated one. A reader
treats it exactly as any tenant's: payload `""` agreeing with envelope `""` is agreement, **not** the
refused empty-payload case above, and it verifies under v1. The system partition is attested but **never
anchored** (`chain_anchor` is per tenant, `audit-anchor.md`) and has no `--from-anchor` scoped bundle.

**Verification** (`seam-verify chain --issuer <AID>`): (a) every `CHAIN_HEAD_ATTESTATION` verifies against
the **pinned** issuer AID (a mismatch is refused before any signature work — deriving the key from the
attestation's own `issuer_aid` would let a forgery verify against its forger), AND its `attested_head`
equals the running head after `attested_len` chained links (an authentic attestation replayed into a
fabricated chain dies on this position check) — **and, since U-RT-3 Phase 3, its payload `tenant` MUST
equal its envelope's, per "Reader obligations on `tenant`" above, and (since #835 step 4) its signature
MUST verify under the one framing that `tenant` selects**; (b) for every `DECISION_SEALED`, recompute the record
digest (spec §Record digest) from its payload and compare it to the event's `digest` (tag 19) — a
mismatch is a **payload rewrite** (a structural column was changed after sealing; the chain link still
hashes, but the payload no longer matches it); (c) **a `DECISION_SEALED` whose `schema_version` is not
`4` ⇒ REFUSE (UNKNOWN SCHEMA VERSION)**, and **a v4 `DECISION_SEALED` that lacks a non-empty
`ciphertext_digest` (tag 10) ⇒ REFUSE (MISSING COMMITMENT)**, or lacks any of its mandatory sub-digest
and binding tags 11, 12, 14, 15, 16, 17 ⇒ REFUSE (MISSING SUB-DIGEST). Every record is *required* to carry
them, so an absent one is a **strip / downgrade attack** — rewrite a field, drop its input, leave the
`(prev,digest,checksum)` triple intact (the signed head cannot catch it: tag 19 is copied unchanged, so
the head still matches and the signature verifies) — or a non-conforming producer. Both fail under
`--issuer`; treating the strip as *cannot-recompute, not-a-failure* is exactly the hole design (a) exists
to close. Nothing is skipped: there is no un-recomputable record class. Without `--issuer` none of (a)–(e)
runs (a consumer with no issuer key legitimately checks integrity only); (d) **zero valid
attestations under `--issuer` ⇒ REFUSE** — a forger cannot mint one, so their absence is the
fabricated-chain tell, and a green-with-no-attestations would be a coverage hole reporting green.
**An attestation whose `attested_len` is 0 ⇒ REFUSE, outright and unconditionally** — it makes no
claim (a conforming producer never signs the empty chain; see Triggers above), so its presence on the
wire is itself the non-conforming-producer tell, and it can never be the attestation that satisfies
this clause: a `CHAIN AUTHENTICATED` whose only warrant is a signature over nothing is the same
coverage hole reporting green, this time with the issuer's signature on it. (e)
**an attestation whose `digest_schema` is BELOW the highest `schema_version` of any `DECISION_SEALED` in
its attested prefix ⇒ REFUSE** — it is a signed downgrade claim, and it is reported **distinctly** from a
payload rewrite (b) and from a strip (c), because the three have different causes and different
remediations.

This is the consumer half of the ceiling the paragraph above makes normative for producers; without it
the field is an assertion nobody checks. It is *nearly* redundant cryptographically — `schema_version` is
framed into every record digest, which is bound into the checksum chain the attested head commits to, so
a per-record downgrade already breaks a link under (b). What (e) adds is narrower and is the whole point
of the field: it checks the **signed, externally-notarized artifact** against the chain it claims to
cover. The artifact is what a third party is handed, and the case (b) cannot reach is a **rolled-back
producer** — a build whose ceiling regressed below 4 signing an honest, unmodified chain that already
contains v4 records. Every link hashes, every digest recomputes, and the issuer has
nonetheless signed a false statement about the verification regime.

Three properties of (e) are load-bearing and a verifier that gets any of them wrong is worse than one
that omits the check:

- **`>=`, never `==`.** The check is `digest_schema >= max(schema_version)` over the prefix. A ceiling
  only ever rises and existing attestations are never re-signed, so an `==` reading would refuse a valid
  attestation the moment a future formula raises the producer's ceiling.
- **Over the attested PREFIX only** — the first `attested_len` chained links, not the whole chain. A
  stale attestation legitimately covers a shorter prefix than the chain's current length (see the
  read→sign→append note above), so comparing it against records sealed *after* it were signed would
  refuse a valid attestation for a race the design explicitly permits.
- **Each attestation independently.** A chain carries many, at different lengths and possibly from
  different issuer keys across a rotation; each is checked against its own prefix.

An `attested_len == 0` prefix is empty, so its maximum is undefined and (e) cannot fire — it never gets
the chance: clause (d) refuses the vacuous attestation itself, outright, before (e) is consulted.
Likewise a **non-empty** prefix that happens to
contain no `DECISION_SEALED` at all has no witness, so (e) cannot fire there either: the rule is
existential over the covered records, not a claim about the prefix's length. Stated because the two
natural implementations — a running maximum seeded at `0`, and an iterate-and-compare over the covered
records — must agree here, and only one of them makes that obvious.

**Anchored verification (clause (f) — windowed start).** A consumer may hold only a *window* of the
stream — a transport has a retention horizon, and an evidence bundle is deliberately scoped — so a
verifier MAY accept an **anchored start**: a `CHAIN_HEAD_ATTESTATION` artifact (the six payload fields
above, supplied out of band — e.g. one element of the public `GET /v1/anchors` feed) whose
`(attested_len, attested_head)` seeds the running head in place of genesis. An anchored start
**relocates the trust root**, so all of the following are normative:

- **(f0) — an anchored start is per tenant (U-RT-3 Phase 3).** Chains are per-`tenant` (see above), so
  an anchor seeds exactly one tenant's chain. A verifier checking a multi-tenant window MAY be given
  several anchors, **at most one per tenant**, each attributed to the tenant it names (its own payload
  `tenant` since Phase 2, or the envelope's when the anchor is loaded as a full event). An anchor naming
  a tenant absent from the window ⇒ REFUSE: the operator asked for a start the window does not contain,
  and silently dropping it would verify a start nobody chose. Two anchors naming the same tenant are a
  usage error. An anchor with no `tenant` (minted before Phase 3, or the system partition's) is a v1
  signature and seeds **only** the `""` partition (#835 step 4): the former fallback to the window's
  sole tenant is gone, since it seeded a tenant chain from a signature that never named that tenant.
- **Note — accepted-restart points in the production chain (#1009).** A verifier or tracker that assumes
  one unbroken chain per `tenant` WILL see breaks in production history that are not forks or loss: the
  legacy global-chained prefix (`audit_entry.tenant_seq` NULL — the audit column, not the wire field), a tenant whose per-tenant chain re-roots at genesis
  where an older tenant's links to a backfilled legacy row, and two interleaved system sub-chains in the
  NULL partition. They are enumerated, with how to confirm them read-only, in
  [`docs/runbooks/audit-chain-boundaries.md`](../runbooks/audit-chain-boundaries.md); resolve each with a
  per-tenant anchored start (f0), never by re-enrolling or rewriting rows.
- **(f1) — the anchor is validated before it is trusted, and only under a pinned issuer.** An
  anchored start is accepted only when `--issuer` is given, and the anchor's signature MUST verify
  against a pinned issuer AID under the signed framing above, before anything is verified from it.
  An unsigned, forged, or unpinned-issuer anchor ⇒ REFUSE — never fall back to genesis, and never
  seed an unverified head. A verifier that seeds an arbitrary caller-supplied head can be told to
  skip a tampered prefix; a bare `(len, head)` pair with no signature is a premise, not a claim, and
  MUST NOT be an accepted input shape. A forger cannot mint an issuer-signed anchor over a tampered
  prefix's head, which is exactly what makes this mode no weaker than a genesis start.
- **(f2) — a vacuous anchor is refused.** An anchor whose `attested_len` is 0 ⇒ REFUSE: it is the
  artifact clause (d) already refuses on the wire, and as a start it would re-create genesis seeding
  through the back door under an artifact no conforming producer signs.
- **(f3) — window positions are anchor-relative.** Link *k* of the window sits at absolute position
  `attested_len + k`, and the first chained event MUST extend `attested_head` (clause-(a) linking is
  otherwise unchanged). An in-window attestation attesting a position beyond the window ⇒ REFUSE
  (unchanged); attesting exactly the anchor's `attested_len` ⇒ its head MUST equal the anchor's;
  attesting a position *below* the anchor's cannot be checked against heads the window does not
  contain — its signature is still verified, and it is then skipped and REPORTED, never silently
  dropped and never counted toward (f4). (The read→sign→append race above can legitimately place
  such an attestation inside the window.)
- **(f4) — clause (d), re-scoped.** At least one valid attestation whose `attested_len` is
  **strictly greater** than the anchor's MUST be present, else REFUSE. Evaluated **per anchored
  tenant** (f0): an anchor for one tenant is never satisfied by another tenant's coverage. The anchor
  itself never satisfies (d): the anchor feed is public, so a fabricated window appended to a genuine
  anchor would otherwise authenticate with zero issuer coverage of its own. The anchor warrants the
  prefix; only an in-window attestation warrants the window.
- **(f5) — clause (e), re-scoped.** The ceiling is checked over the window's covered links only,
  with the running maximum seeded at 0 — never seeded from the anchor's `digest_schema`, which is a
  ceiling, not the prefix's actual maximum (seeding from it would refuse a valid in-window attestation
  whose ceiling is below the anchor's, violating the `>=`-never-`==` property above). Records at or
  below the anchor are not in the input; their regime is warranted solely by the anchor's own
  signed ceiling.
- **(f6) — the verdict states its premise.** An anchored verdict MUST report the anchor's
  `attested_len` and head. A green anchored verdict is a claim about the window and about the
  issuer-signed anchor — never about the prefix below it, which is covered exactly as far as an
  issuer signature covers it and no further.

What anchored verification does **not** weaken: within-window truncation, insertion, and reorder are
caught by (a) exactly as from genesis; tail truncation is exactly as visible as from genesis (the
integrity-only tail, and comparison against a later anchor); and a tampered prefix cannot be skipped,
because a forger cannot produce the issuer-signed anchor an anchored start requires.

### `SESSION_LIFECYCLE` (additive, tag 21 — advisory, not chained) — CP-09

A session lifecycle transition for the session named by the envelope `session_id`. **Advisory**: it
carries no `digest`/`checksum` and never perturbs the audit chain (a verifier keys on field presence,
§Ordering & integrity). Emitted on interactive session opens only; consumers MUST tolerate unknown
`phase` values (additive vocabulary).

```proto
message SessionLifecycle {           // envelope tag 21
  string phase = 1;                  // "opened" (only phase emitted today; vocabulary is additive)
  string mode = 2;                   // the canonical MACP mode id the session opened in
  string policy_version = 3;         // the policy the binding named at open — STAGED, not "bound"
  uint64 opened_at_millis = 4;       // the caller-injected session clock at open
  repeated AgentPin pins = 5;        // #1359 — per admitted participant, in admission order ("opened" only)
}

message AgentPin {
  string agent_id = 1;               // the registry agent id
  string version = 2;                // the registry version admission pinned (never re-pinned mid-session)
}
```

JSON: `session_lifecycle.pins: [{"agent_id": "...", "version": "..."}]`, **omitted when empty**.

**In-flight accounting (B-INFLIGHT, #1359).** A consumer derives the live sessions per `(tenant, agent,
version)` from the stream alone: a `SESSION_LIFECYCLE` `"opened"` adds one per pin; the session's
`DECISION_SEALED` (same envelope `tenant` + `session_id`) removes it. Every terminal state seals —
`Resolved`, `Cancelled`, and a TTL-elapsed session is sealed `Expired` before eviction (a session is
never evicted unsealed). One-shot decisions emit no `"opened"`; their seal arrives immediately. There
is no caught-up marker on the stream: a follow-tail consumer declares itself caught up at the head it
reads. **Restart gap:** live sessions are process-resident, so a runtime restart drops any still-open
session without a seal; such an `"opened"` is never followed by its `DECISION_SEALED`, and a consumer
must age it out against its own TTL bound.

**`policy_version` is STAGED, not proof of enforcement.** It names what the binding staged at open,
exactly as the identically named field on `seam.api.v1.DecisionResponse` does. A populated value is
not on its own evidence that the named policy's rules evaluated anything — and here it cannot be:
this event emits at `phase = "opened"`, **before anything seals**, so no enforcement fact exists yet.
The stream carries the companion one event later — `DecisionSealed.policy_rules_digest` (tag 13),
joinable by `session_id`. Read that, not this, for what actually bound.

Envelope: `event_id = "{tenant}:{session_id}#lc:{phase}@{opened_at_millis}"` (tenant-prefixed since
P12b, like the `POLICY_DENIED` id: session ids are client-chosen, so two tenants opening the same
session id in the same millisecond would otherwise collide under a global `event_id` dedup) — salted with the open timestamp
because a session id can be RE-opened after sweep eviction, and delivery dedups by `event_id` (an
unsalted id would pin a deduping consumer to the first open's stale payload). `classification` is
**fixed `Internal`** (operational metadata — phase/mode/policy/timestamp and registry agent pins; no subject, secret,
or agent content — so classification-gated redaction rules never fire on this kind: gate on `when_kind`).

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
  string agent_id = 4;                 // audit-only LABEL, never the scope-floor key (see agent_aid)
  string tool_name = 5;
  string tool_input_digest = 6;        // "hmac-sha256:<kid>:<hex>" — a KEYED commitment
  string verdict = 7;                  // "ALLOW" | "DENY" | "TRANSFORM" | "ESCALATE"
  string reason = 8;                   // closed-set / operator-authored only (D-030)
  string policy_version = 9;           // the policy the binding named — STAGED, not "ran under"
  optional string subject_digest = 10; // "hmac-sha256:<kid>:<hex>" — NEVER the raw subject
  repeated string subject_digests = 11; // one keyed commitment PER effective subject (#715); [0] == subject_digest
}
```

**`subject_digests` (tag 11, #715).** One keyed commitment per effective subject of the authorize call — the union of
`AuthorizeRequest.subject` and `.subjects`, deduped, `subject` first, then request order, at most 16. Each element is the
**same** commitment as `subject_digest` (same key, same `kid`, same per-tenant domain), so it is no weaker than tag 10: it cannot be tied to
a subject without the tenant's key and carries no bare-hash oracle. The row stays
append-only, as tag 10's is — what this field adds is that EVERY subject of a call is recomputable by the runtime's audited recompute
route (`POST /v1/erasure/subject-commitments`, see below), not only the first; `subject_digest` (10) stays populated with the first element for legacy
consumers. **Reader rule:** when `subject_digests` is non-empty, `subject_digest` MUST equal element 0 and a consumer SHOULD reject a row where it does not (or where tag 11 is set and tag 10 is absent). **Un-updated consumers see tag 10 only — one of up to 16 subjects, silently** (connector sinks, the SDK JSON codecs, any learning reader); deploy consumers before the producer. Subjects are committed **byte-exact**: the producer neither trims, case-folds nor normalizes, so a recompute must use the exact bytes the caller sent; the runtime commits what it is *told* is a subject. Every `AUTHORIZE_EVALUATED` row — and therefore every commitment on it — exists only when the row is emitted (`emit_events`, sampling) and survives only for the outbox retention window. Absent (empty) on rows written before the field existed and on subject-less calls — it is omitted from the
canonical JSON when empty. Every element is held to the commitment scheme (`hmac-sha256:…`). Adding it changes the
`seam_event_descriptor` golden: the vendored copies (seam-connectors, the hub manifest) move in lockstep.

**`policy_version` is STAGED, not proof of enforcement.** The authorize path produces **no
enforcement fact at all**, by design: it seals nothing, and v1 routes and records policy without
varying the verdict by policy content (no generic rule body exists — the scope floor, the guard and
the escalate list are the honest v1). A companion attestation here would be always-false, so there
is none; a populated `policy_version` proves only that a policy was routed and recorded.

Envelope: `event_id = "{authorize_id}#az#{seq}"`; `classification` is **fixed `Internal`** (ids, digests,
and a closed-set reason — no subject, secret, or agent content can reach it, so classification-gated
redaction never fires: gate on `when_kind`).

**PII rule.** The end-user data subject rides ONLY as `subject_digest` / `subject_digests`, and the request input ONLY as
`tool_input_digest`. Both are **keyed commitments**, not bare hashes:

```
hmac-sha256:<kid>:<hex>     hex = HMAC-SHA256(k_tenant, put(domain) ‖ put(tenant) ‖ put(value))
```

`put(x) = le32(len(x)) ‖ x` — a little-endian u32 byte-length prefix, then the raw bytes (identical to
`frame(x)` in §"Record digest"). `<hex>` is the lowercase hex of the full 32-byte HMAC.

GDPR erasure walks *decision records*; an outbox row is un-shredable, so a raw end-user id here would
be an un-erasable copy of it. A **bare** hash was never sufficient for that. An end-user identifier
has a small, enumerable preimage space, so `sha256(subject)` is a set-membership oracle: anyone
holding the row can confirm a guess at the identifier by brute force or a rainbow table, without
breaking anything. Keying the construction removes that oracle.

**`k_tenant` is per tenant (#1293).** In production it is a random 256-bit key minted on the tenant's first
use and stored wrapped under the tenant's #807 KEK; it is used only inside the runtime and never exported.
A tenant KEK rotation re-wraps it without changing it, so a tenant's `<kid>` is stable for the tenant's
lifetime. **A tenant crypto-shred (`shred-tenant`) destroys it**: every commitment ever emitted for that
tenant — including every downstream copy — becomes permanently unlinkable. A production runtime refuses to
derive commitment keys from its issuer seed; only a dev runtime does (`HMAC(seed, put(label) ‖ put(tenant))`,
which conceals nothing where the seed is public, e.g. `SEAM_DEV_INSECURE`). `<kid>` is a 4-byte key-id derived
from the key material itself, so a row always names the key it was written under.

**The request side is unchanged.** `seam.api.v1`'s request `tool_input_digest` is still
`sha256:<hex>` over the RFC 8785 (JCS) canonical input, and is still what `call_sig` covers. Only the
value this runtime *emits* is a commitment. The two are deliberately different constructions and must
not be compared to each other.

**What this preserves, and what it costs.**

- **Correlation is preserved within one tenant.** Two rows of a tenant sharing a commitment are the same
  underlying value, so joins, dedup and counting work. Commitments never correlate across tenants (the
  tenant is inside the MAC and the key is per tenant).
- **Recompute is in-band and audited, never unilateral (#1293).** Confirming that a given subject
  produced a given row requires `k_tenant`, which only the runtime holds. An erasure operator uses
  `POST /v1/erasure/subject-commitments` (scope `erasure:preview`; body `{tenant, subjects[1..16]}`;
  response `{tenant, kid, results:[{subject_index, commitment}]}` — raw subjects never echoed). Every
  call chains a `subject_commitments_recomputed` `AUDIT_ENTRY` before it answers, and a subject that
  has been erased in the tenant is **refused** (409, audited as `subject_commitment_recompute_refused`).
  There is no export and no offline recompute. (gRPC parity is a later, additive `seam.api.v1` RPC.)

**Erasure of a subject's commitments — the consumer obligation (#1293 D3).** A GDPR erasure
(`POST /v1/erasure`) first chains a `subject_commitment_tombstoned` `AUDIT_ENTRY` carrying the subject's
commitment, then crypto-shreds the subject's decision records. The runtime's own outbox rows age out
within the retention window (≥ 8 days after relay consumption); the long-lived copies are in the sinks,
and **a sink that retains `AUTHORIZE_EVALUATED` beyond the outbox window MUST support purge by
commitment**: given a commitment from the recompute route (today: the erasure operator's runbook step;
later: automated from the erasure certificate), delete or null every row of that tenant whose
`subject_digest` or any `subject_digests` element equals it. A sink MAY additionally purge on the
`subject_commitment_tombstoned` entry it receives on the stream. After a tenant crypto-shred no sink
action is required for linkability (the key is gone), though a sink MAY drop the tenant's rows.

**Pre-#1293 rows — read this before writing any query that spans the cutover.** No backward
compatibility is kept:

- Rows written before #484 carry **bare** `sha256:` values (brute-forceable permanently), and rows
  written between #484 and #1293 carry commitments under the retired **deployment-wide** key, which
  is derivable by anyone holding the issuer seed and which the runtime no longer holds. **Neither can
  be recomputed** by the route above. The runtime's copies have aged out of the outbox; **a sink MUST
  drop or null `subject_digest` / `subject_digests` / `tool_input_digest` on every
  `AUTHORIZE_EVALUATED` row emitted before the #1293 deploy** (one-time), keeping `authorize_id` for
  joins.
- **Rows across the cutover never join on a commitment.** A query spanning the deploy returns nothing
  rather than erroring. Join on `authorize_id`.
- **The SDK handle-log join.** An SDK's local handle log records the *request-side*
  `tool_input_digest`, which this change does not touch, so it no longer equals the value on the
  corresponding outbox row. The documented join is on `authorize_id` and stays correct; an
  improvised join on the digest breaks silently and returns empty.

**Emission contract.** Emission is per-namespace config (`authorize.emit_events`, default on) with an
`authorize.event_sample_rate` knob — **except for `ESCALATE`**, which always emits (sampling-exempt) and
whose append is **fail-closed**: an ESCALATE whose append fails returns an error rather than the verdict,
because an escalation nobody can ever see is not an escalation. ALLOW/DENY/TRANSFORM appends stay
fail-open (verdict returned, `seam.security` WARN logged). The `{authorize_id, client_request_id?,
agent_aid, agent_id, tool_name, tool_input_digest, subject_digest?, subject_digests?, reason}` field set on an ESCALATE row
is the complete event-side contract an escalation consumer reads — built from events alone, with no wire
change.

**An ESCALATE also writes a second, non-event row, and a consumer must not confuse the two.** Since A1
the runtime keeps a durable keyed record of every ESCALATE in its own table (`authorize_escalation`,
`crates/seam-store/migrations/0025_authorize_escalation.sql`), written in the **same store transaction**
as the outbox append — so the escalation inbox is no longer "built from events alone", and an
`AUTHORIZE_EVALUATED` row with `verdict: ESCALATE` implies a matching stored row (and the reverse). Two
differences matter to anyone joining across them. First, that table stores the caller's **raw**
`sha256:<hex>` `tool_input_digest`, while the outbox row above carries the `#484` keyed commitment — the
two are not equal and never join; join on `authorize_id`. Second, the table stores **no**
`subject_digest` at all. The stored row is also retention-bounded and is deleted on expiry, whereas the
outbox row's lifetime is the relay-GC window; neither is a mirror of the other.


### `POLICY_DENIED` (additive, tag 24 — advisory, not chained)

The audit row for a commitment a **bound policy refused**. Like `AUTHORIZE_EVALUATED`, that path
**seals nothing** — no decision record, no DEK, no chain append — so this event is the *only* trace the
refusal ever happened.

It exists because that refusal was otherwise durably **invisible** on the one-shot path: a
policy-denied `RunDecision` errors before the seal, before the metrics tick and before the outbox wake,
leaving no trace at all. For a system whose claim is an auditable decision boundary, "a refused action
leaves no record" is the wrong failure mode. This is a durable **trace**, deliberately not a decision
record — nothing was decided.

```proto
message PolicyDenied {                 // envelope tag 24
  string policy_version = 1;           // the policy the binding named — STAGED, not "ran under"
  string mode = 2;                     // the coordination mode the refused session was opened in
  string reason = 3;                   // ALREADY-REDACTED deny reason, PRE-JOINED (D-030, #542)
}
```

Envelope: `event_id = "{tenant}:{session_id}#pd#{seq}"` (tenant-prefixed since P5, because two
tenants may use the same session id); `session_id` is **present** (unlike
`AUTHORIZE_EVALUATED`, a refused commitment always has one, and it is the only handle a consumer has to
correlate the refusal with the attempt); `decision_id` is **absent** (nothing sealed, so there is no
decision to join to); `classification` is **fixed `Internal`** — gate redaction on `when_kind`.

**Advisory**: no `digest`/`checksum`, empty `prev_checksum`. A consumer must not attempt to link this
event into the audit chain; it was never appended to one.

**`policy_version` is STAGED, not proof of enforcement.** It names what the binding staged, exactly as
the identically named field on `seam.api.v1.DecisionResponse` does. A populated value is not on its own
evidence that the named policy's rules evaluated anything.

**Reason rule (D-030).** `reason` is built from the closed-set, operator-authored capability classes
the evaluator produced — never agent-proposed content, and with objector ids stripped, so a denial
cannot leak *who* objected to a consumer that may not be entitled to know.

**`reason` is ONE string and consumers MUST NOT split it.** The runtime's error boundary
(`seam_coord_macp::map_macp_err`) joins the evaluator's reasons with `"; "` before this producer ever
sees them, and the #542 redaction emits that *same* delimiter **inside** a single reason
(`... (objector ids withheld; see operator logs)`). Splitting the joined message back apart is
therefore lossy: two reasons yield **three** parts, one dangling mid-parenthetical. A repeated field
here could only ever be filled by shredding the text, so the wire carries what the runtime actually
holds. The `seam-coord-macp` test `the_joined_denial_message_is_not_safely_splittable` pins the
hazard, so a future rewording of the redaction cannot quietly make this advice stale.

**Volume.** Unlike the periodic `CHAIN_HEAD_ATTESTATION`, this is emitted per refused commitment; under
a strict bound policy that can be a material rate. Emission is fail-open — the refusal is already being
returned to the caller as a typed error, so a failed append must not convert a clean denial into a
different error.

### `EVENT_REDRIVEN` (additive, tag 26 — advisory, not chained) — #1176

An operator **re-drove** an existing outbox event by reference (DLQ retry option C,
`SeamEvents.RedriveEvents` / `POST /v1/events/redrive`, scope `events:redrive`). The operator names the
event by its coordinates — tenant + global `seq` (a DLQ letter's `tenant`/`seq` headers), or a bounded
`seq` range, optionally cross-checked by `event_id` — and the runtime reads **its own stored row** and
appends this wrapper. A DLQ letter's bytes never reach the main stream, so a forged letter (any consumer
or tenant can write a DLQ) cannot be laundered into `seam.events.v1` by a retry.

```proto
message EventRedriven {                // envelope tag 26
  bytes event = 1;                     // the original outbox row, VERBATIM seam-event.v1 protobuf
  string original_event_id = 2;        // copy of the inner event_id — the consumers' dedup key
  uint64 original_seq = 3;             // copy of the inner global seq
  string original_kind = 4;            // copy of the inner kind
}
```

**A wrapper, not a re-append.** A verbatim copy of the original row at a fresh offset would carry a
`seq` (and, for a chained kind, a `prev_checksum`) that no longer fits the stream: every chain-verifying
reader — the relay first — would read it as a replay. So the wrapper is an ordinary advisory event with
its own fresh `seq`/`tenant_seq`, and the original travels inside it untouched (every digest, checksum
and signature in it still verifies; it is never re-encoded).

Envelope: `event_id = "{original_event_id}#rd#{seq}"` (unique per re-drive; since k8s P7 `{stream_id}/{original_local}#rd#{seq}` — one prefix, never two, see §Delivery stream); `tenant`, `namespace`,
`classification`, `session_id` and `decision_id` are **copied from the inner event**, so tenant
partitioning and classification-gated redaction treat the wrapper exactly as they treat what it carries
(`classification` therefore **varies** — a re-driven `ERASURE_CERTIFICATE` is `Pii`). **Advisory**: no
`digest`/`checksum`, empty `prev_checksum`.

**Consumers.** A consumer that re-delivers the inner event (the relay, for a DLQ retry) dedups it on the
inner `event_id`, exactly as it dedups any at-least-once duplicate, so re-driving twice is harmless. The
three scalar copies let a router act without decoding `event`; a consumer that needs certainty decodes it.
An `EVENT_REDRIVEN` is itself never re-drivable (the operation answers `not_redrivable`; re-drive the
original seq).

**Audit.** Each call that re-drives anything first chains an `AUDIT_ENTRY` with action `events_redriven`
under the re-driven tenant; if that append fails, nothing is re-driven.

**Retention.** A re-drive needs the original row, so the outbox retention window has an 8-day floor (the
DLQ topic's 7-day retention plus a day of delivery lag; see §Retention). A seq retention removed anyway
answers `pruned` — never a silent no-op.

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

Every payload **must** carry `ciphertext_digest` (payload **tag 10**, since **A14**):
`SHA256(ciphertext)` — the one input to the record digest a stream consumer does not hold, collapsed to
32 bytes. It discloses nothing (a hash of a high-entropy AEAD ciphertext) and lets a consumer recompute
the record `digest` from what it received (see §Record digest). Payload tags 11-17 are likewise
mandatory except the genuinely optional tag 13 (§Record digest (v4)).

**A stripped tag 10 is an attack, not a safe downgrade.** Dropping tag 10 while leaving the
`(prev_checksum, digest, checksum)` triple intact lets an adversary rewrite a structural column and evade
the recompute — the signed head cannot catch it, because `digest` (tag 19) is copied unchanged. Under
`--issuer` a verifier therefore **fails** a `DECISION_SEALED` that lacks a non-empty
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

- **Ordering** is by `seq`, monotonic over the runtime's **single ordered outbox stream** — delivery
  and cursoring stay global *within one delivery stream* (one runtime cell, one database). Across cells
  `seq` restarts and is not comparable: key on `(stream_id, seq)` — see
  [Delivery stream](#delivery-stream-stream_id-additive-tag-27--every-kind-unsealed--k8s-p7). `tenant`/`namespace` are tags consumers **filter** on, not separate
  *delivery* streams in v1. Consumers track one cursor (at-least-once delivery; `event_id` dedups).
  _Per-`(tenant,namespace)` sub-streams with independent cursors are a forward-compatible v2
  enhancement._ **The hash chain itself is a different axis and is per-`tenant` since U-RT-1** — see
  the Chain bullet below; delivery being one global `seq`-ordered stream does not mean the chained
  events riding it form one global chain.
- **Chain:** a **chained** event carries three fields — `prev_checksum` (the head it extends), `digest`
  (its own record/action digest), and `checksum` (the head it produces, `= H(prev_checksum ‖ digest)`).
  **Chained-ness is by field presence, not by `kind`:** an event is on the chain iff `digest` + `checksum`
  are present (equivalently, `prev_checksum` is non-empty). The chained kinds are `DECISION_SEALED`,
  `AUDIT_ENTRY`, and `ERASURE_CERTIFICATE` — **except** the `action: "chain_anchor"` `AUDIT_ENTRY`, which is
  emitted off-chain (no `digest`) and is *not* a link. Advisory kinds (`LEARNING_DECISION`,
  `LEARNING_OUTCOME`, `BUDGET_BREACH`) likewise set none of the three. **Since U-RT-1 (tenant
  partitioning), a chained `AUDIT_ENTRY`'s `prev_checksum`/`checksum` are computed per-`tenant`, not
  over the whole database** — each tenant has its own chain from its own genesis, the same way each
  tenant gets its own `chain_anchor` per attestation tick (`audit-anchor.md`). The wire `seq` itself is
  unaffected (still the single global `outbox.seq`, §Ordering above) — only the chain link a chained
  event's `prev_checksum`/`checksum` participates in is now scoped by `tenant`. **A consumer therefore
  verifies one running chain per `tenant`, not one running chain over the whole interleaved stream**:
  for each distinct `tenant` value seen, track its own `running_head`, initialized to 32 zero bytes
  (genesis) the first time that tenant's `AUDIT_ENTRY` is observed; for each event **that has a
  `digest`**, in `seq` order **within that tenant's own subsequence**, assert `prev_checksum ==
  running_head`, assert `checksum == H(prev_checksum ‖ digest)` (**this link is now cryptographically
  checkable** — the `digest` input is on the wire, §A), then advance that tenant's `running_head =
  checksum`. A consumer that walks the raw interleaved stream with a single shared `running_head`
  across tenants will see spurious chain breaks the moment two tenants both have chain activity — this
  is not a transport bug, it is the (correct) per-tenant chain shape. This detects a forged/inserted/
  rewritten event within a tenant's chain, not merely a dropped one; an attacker stripping tags 19/20
  off a chained event is caught at that tenant's next link (`prev_checksum ≠ running_head`) —
  equivalent in power to dropping it, which a tail-strip aside is covered by the out-of-band anchor
  (`audit-anchor.md`). The `digest` is computed per §Record digest below (v4) — it covers every
  structural column a consumer acts on, `SHA256(ciphertext)`, and the sub-digests and bindings carried in
  payload tags 11-17, so a consumer recomputes it from the wire; it discloses nothing a consumer does not already hold.

### Per-tenant `tenant_seq` (additive, tag 25 — every kind, UNSEALED) — #973

`optional uint64 tenant_seq = 25`. The runtime's per-tenant **outbox** counter, stamped on **every** event
(chained and advisory) at append time: the same value it stores in `outbox.tenant_seq`, allocated under the
same lock as the global `seq`. `optional` because **`0` is a real value** (a tenant's first event) and
**absence means "predates the counter"**, which is not the same thing.

- **What it counts.** Every outbox event of one wire `tenant`, one per event, starting at `0` for a tenant
  first seen after the cutover. Allocation is serialized and a rolled-back append consumes nothing, so it is
  **gap-free**; commit order equals counter order. `tenant == ""` is the **system partition**: exactly the
  `AUDIT_ENTRY`s whose `action` is `config_snapshot_installed` or `config_section_removed`, plus the
  `CHAIN_HEAD_ATTESTATION` over that partition's own head (#1196; see
  [Tenant tag — a producer rule](#tenant-tag--a-producer-rule-invariant-10)); it has its own counter. (On
  Postgres that partition is stored as `tenant_id IS NULL`; an empty-string tenant on a tenant path is
  refused by `outbox_tenant_not_empty`. The Memory backend refuses it too and no longer folds it into the
  system partition.)
- **Three different counters — do not conflate them.**
  1. `SeamEvent.tenant_seq` (this field) = `outbox.tenant_seq`: counts **all** events of the tenant.
  2. `audit_entry.tenant_seq`: counts only **chained** audit entries; it is *not* on the event wire.
  3. `GET /v1/audit`'s `chain_index`: a position computed while building the response; not a column.
  Using (2) or (3) as a completeness key shows false gaps for any tenant with advisory events.
- **UNSEALED.** `tenant_seq` is in **no digest, checksum or signature** (D-W3-20) and must not be: putting it
  in a preimage would change every existing digest. It therefore detects **loss and duplication in the
  stream** (a faulty relay, retention loss, a missed ack), **not adversarial suppression** by a party that
  can rewrite the stream. Suppression stays covered by the per-tenant `CHAIN_HEAD_ATTESTATION`
  (`attested_len`). Event bytes are never hashed by the runtime; a re-encode of a decoded event is
  therefore safe so long as the decoder models tag 25 (every in-repo decoder does).
- **Legacy and cutover.** Events already stored carry no field and are not rewritten. The column counts
  ahead of the wire, so the first event that *carries* the field for a tenant may have `tenant_seq = N > 0`:
  a consumer MUST baseline on the first present value per tenant and MUST NOT assume it is `0`. The global
  `seq` at which the field begins to appear is the **`tenant_seq` cutoff** and the `seq` at which the producer
  begins refusing tenant-less events is the separate **tenant-tag cutoff**; both are published here — see
  *Cutoffs* below; until the relevant one is filled the corresponding "absent" is unclassifiable and consumers
  MUST NOT report it as a defect.
- **Cutoffs (two numbers, because the two changes shipped at different times).**
  - `tenant_seq cutoff seq: 25792` — the global `seq` of the first event that carries tag 25. #973 shipped alone
    in 0.34.0: measured in prod, 25791 is the last event without tag 25 and 25792 the first with it. Governs
    consumer rule 1 and rule 4 below.
  - `Tenant-tag cutoff seq: —` *(not yet published: the global `seq` of the first event produced after the
    deploy of the producer that refuses tenant-less events (#903, 0.41.0). It cannot be known before that
    deploy and is never to be guessed.)* Before it, an event may be tenant-less on the wire for reasons other
    than the system-partition kinds (`AUDIT_ENTRY` with `config_snapshot_installed` / `config_section_removed`,
    and the system `CHAIN_HEAD_ATTESTATION` of #1196); the
    spec makes no no-tenant-less claim for any `seq` between 25792 and this number. Until it is filled, a
    tenant-less event is not reportable as a producer defect.
  - The owner fills both lines from the relay/lakehouse archive, not from `min(seq)` of the live outbox, which is
    pruned after ack. See [`docs/runbooks/tenant-seq-cutoff.md`](../runbooks/tenant-seq-cutoff.md).
- **Consumer rule.** For each tenant `T` (wire `tenant`; `""` = system), over events in delivery order:
  1. `tenant_seq` absent and `seq` below the `tenant_seq` cutoff: legacy; ignore for completeness.
  2. The first event of `T` with `tenant_seq` present baselines the counter.
  3. Each later event of `T` must carry `previous + 1`. A larger value is a **gap** (report the missing
     range); an equal or smaller value is a **duplicate/replay** (drop by `event_id`; report if the
     `event_id` differs).
  4. `tenant_seq` absent **at or after** the `tenant_seq` cutoff is a producer defect.
  5. A gap is evidence of loss *in transit or retention*; for chained kinds confirm against the tenant's
     `CHAIN_HEAD_ATTESTATION.attested_len` before treating it as data loss.
- **Does not** give ordering across tenants (use `seq`), is scoped to one delivery stream (key it
  `(stream_id, tenant)` when a consumer reads several cells), does not backfill, and a database restored from an
  older snapshot re-issues counters already shipped (same hazard as `seq`, `docs/runbooks/outbox-seq-reset.md`);
  rule 3 reports it as a duplicate/regression. **Tag 25 is permanent** once consumers vendor the descriptor.

### Delivery stream `stream_id` (additive, tag 27 — every kind, UNSEALED) — k8s P7

`string stream_id = 27`. One consumer may read several runtime cells (prd, partner, aws-stg); each cell's
outbox `seq` (and `tenant_seq`) starts at 0 on its own database. `stream_id` names the cell's **delivery
stream**, so `(stream_id, seq)` is the identity a multi-cell consumer keys on.

- **Configured, persisted, write-once.** The runtime reads `SEAM_STREAM_ID` at boot (it must match
  `^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`; required outside `SEAM_DEV_INSECURE`, where it defaults to `dev`).
  The first boot records it in `deployment_stream` (migration `0042`); every later boot with a different
  value **refuses to start**. A database belongs to exactly one stream for life.
- **Per-stream scope.** `seq`, `tenant_seq`, the relay watermark (`outbox_relay_watermark`, keyed by
  `stream_id`) and the StreamEvents cursor are all scoped to one stream. Nothing is ordered across streams.
- **Prefix rule.** Every event appended from the boundary on carries `stream_id` and an `event_id` of
  `{stream_id}/{local}`, where `{local}` is the kind's id as documented in its section. The one exception
  in shape is `EVENT_REDRIVEN`: its id is `{stream_id}/{original_local}#rd#{seq}` — the original's own
  prefix is stripped first, so the id carries one prefix, never two. A stream id cannot contain `/`, so
  the first `/` always ends the prefix: ids from two streams can never collide, and a consumer's
  `event_id` dedup stays correct across cells. **Legacy rows are untouched**: they keep their
  bare id and an empty `stream_id`; nothing is rewritten.
- **UNSEALED.** `stream_id` and the prefix are in **no digest, checksum or signature** (the chain is
  per-tenant within a database and never spans streams). `seam-verify` therefore accepts bare, prefixed and
  mixed windows unchanged; a chained id is compared whole.
- **History boundary.** `deployment_stream.boundary_seq` is NULL until the first stream-stamped append,
  which sets it — in its own transaction — to its own outbox `seq`; it is set once and never moves.
  **Guarantee: every row with `seq >= boundary_seq` carries `stream_id`.** It is enforced by the database
  from `0042` on: `outbox.stream_id` has the CHECK `outbox_stream_id_set` (NOT NULL, added NOT VALID, so
  legacy rows stay readable but every new INSERT is checked). A pre-P7 binary does not set the column, so
  during a rolling deploy **old replicas fail their appends** (clients retry onto a new replica) instead of
  writing legacy rows above the boundary. The runtime logs `seam_stream_id` and `boundary_seq` (or `unset`)
  at info on boot. Consumers pin the boundary as `SEAM_STREAM_ID_CUTOFF_SEQ`: below it, a missing
  `stream_id` is legacy; at or after it, a missing `stream_id` is a producer defect.
- **Mismatch refusal.** `StreamEvents` (`StreamEventsRequest.stream_id = 4`) and `ReportEventsConsumed`
  (`ReportConsumedRequest.stream_id = 2`) must name this deployment's stream. An empty or different value is
  refused with `FAILED_PRECONDITION` `stream_id_mismatch` — `StreamEvents` before any event is read,
  `ReportEventsConsumed` before anything advances. The refusal **does not echo** the deployment's stream.
- **No discovery RPC.** A consumer is configured with the stream it reads (the same value as the cell's
  `SEAM_STREAM_ID`); there is deliberately no RPC that names it.
- **Kafka.** `seam-relay` sets the `seam-stream-id` record header to the event's `stream_id`, so a
  multi-cell topic can be partitioned or filtered without decoding the payload.
- **Tag 27 is permanent** once consumers vendor the descriptor.

## Tenant tag — a producer rule (invariant 10)

Every event carries a non-empty wire `tenant` (invariant 10). Since #903 this is **enforced at the producer,
fail-closed**: every `Store` path that appends an event (seal, audit entry, chain anchor, chain-head
attestation, erasure/retention audit, advisory append) refuses `tenant == ""` and appends nothing (fact append is refused at the backend, `commit_fact`);
the Postgres `CHECK (tenant_id <> '')` (migration `0030`) and the Memory backend are the second line.

The **only** tenant-less events are the three **system-partition kinds**: `AUDIT_ENTRY`s with `action` =
`config_snapshot_installed` or `config_section_removed` (deployment-global config; D-W3-22), and — since
#1196 — the `CHAIN_HEAD_ATTESTATION` that signs that partition's own head (envelope and payload `tenant` both
`""`; see [`CHAIN_HEAD_ATTESTATION`](#chain_head_attestation-additive-tag-22--chained--a14), *Per partition*).
They are the system partition (`tenant == ""` on the wire, `tenant_id IS NULL` in Postgres) and are written
only through `commit_system_audit`, each by its own tenant-less producer method (`audit_system_management`,
`record_system_chain_head_attestation`); the tenant-taking paths still refuse `""`. Any other kind or action
with an empty `tenant` is a producer defect. A legal hold on a decision with no tenant-bound sealed record
cannot be audited and is refused before it takes effect (a no-op place/release is unchanged). Adding a kind or
an action to the exempt set is a spec change, not a code-only change.

## Retention & the relay-consumed cursor (R1)

The outbox is **garbage-collected against the relay's durably-consumed cursor**, never against the
operator ack-drain's `published` flag. A consumer relaying the outbox (e.g. `seam-connectors`) reports its
progress with `SeamEvents.ReportEventsConsumed(consumed_cursor)`; the runtime keeps a durable, **monotone**
high-water from it (a lower re-report is ignored) and prunes a row only when it is **both** below that
cursor **and** older than the retention window (`SEAM_OUTBOX_RETENTION_MILLIS`, default **8 days**, never
less — #1176: an operator re-drive by reference needs the original row for as long as the DLQ keeps the
letter, 7 days, plus a day of delivery lag; a smaller configured value is raised to the floor), always
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

The `digest` field (tag 19) on a `DECISION_SEALED` event is the **record digest v4**. It is the only
record-digest formula: a producer stamps `schema_version = 4` on every record, and a verifier recomputes v4
only and **refuses** every other `schema_version` as unknown — it never skips one and never defaults to a
formula it was not asked for. (v1-v3 were retired by P7, 2026-10; no record sealed under them is
verifiable by this build, by design — production is recreated at the v4 cutover, not migrated.)

All framing is byte-exact and any-language-reproducible. `frame(x) = le32(len(x)) ‖ x` (a little-endian
u32 length prefix, then the bytes). `opt(x) = 0x00` when the field is absent, `0x01 ‖ frame(x)` when
present — so `None` and `Some("")` are distinct. `le64`/`le32` are little-endian fixed-width integers.

### Record digest (v4) — `schema_version = 4` (P7)

v4 binds identity, the ciphertext, every structural column on the wire, **who participated and what
context the decision consumed** (two rolled-up 32-byte sub-digests), the policy rules that gated the
commitment, and — new in v4 — the record's **classification**, its flat **participants** roster, and its
**trust basis** (as a keyed commitment plus the plain `auth_method`).

```
digest_v4 = SHA256(
    frame("seam.audit.record-digest.v4")          // domain + version, in-preimage
  ‖ frame(decision_id) ‖ frame(tenant) ‖ frame(namespace)
  ‖ frame(SHA256(ciphertext))                      // == the wire ciphertext_digest (payload tag 10)
  ‖ frame(le64(sealed_at))
  ‖ frame(outcome) ‖ opt(mode) ‖ opt(policy_version) ‖ opt(supersedes)
  ‖ frame(context_digest)                          // 32 bytes, below — wire tag 11
  ‖ frame(participation_digest)                    // 32 bytes, below — wire tag 12
  ‖ opt(policy_rules_digest)                       // 32 bytes when a policy was bound — wire tag 13
  ‖ frame(classification)                          // canonical PascalCase string — wire tag 14
  ‖ frame(participants_digest)                     // 32 bytes, below — wire tag 15
  ‖ frame(trust_basis_commitment)                  // "hmac-sha256:<kid>:<hex>", ASCII — wire tag 16
  ‖ frame(auth_method)                             // raw UTF-8 — wire tag 17
  ‖ frame(le32(schema_version))                    // == 4, ALWAYS LAST
)
```

Slot indices are **0-based over the preimage above**, with slot 0 the domain tag: `context_digest` is
slot 10, `participation_digest` 11, `policy_rules_digest` 12, `classification` 13, `participants_digest`
14, `trust_basis_commitment` 15, `auth_method` 16 and `schema_version` 17. (These are digest-preimage
positions, not proto field numbers — on `DecisionSealed` the columns from `context_digest` onward take
wire tags 11-17, offset by one.) **`schema_version` is always the last slot**: new slots are inserted
before it, never appended after it, and a verifier selects the whole formula by `schema_version`, so
position is fixed by this spec rather than by append order.

Every slot except `policy_rules_digest` (13) is **mandatory**: tags 10, 11, 12, 14, 15, 16 and 17 are
never empty on a conforming payload. `outcome` is framed as its canonical string (`Resolved` /
`Expired` / `Cancelled`); `mode`, `policy_version` and `supersedes` are `opt`-framed as their raw UTF-8
string values (the mode id, the policy version, and the superseded commitment as
`{session_id}/sha256:<hex>` — its RFC-MACP-0013 hash, verified at commit, see
[`seam-commitment-digest.v3.md`](seam-commitment-digest.v3.md#supersedes)), `0x00` when absent;
`classification` uses the same canonical PascalCase strings as inside `context_digest` below
(`Public` / `Internal` / `Confidential` / `Financial` / `Pii` / `Phi`), never an ordinal.

**Frozen string tables.** Three closed string sets are part of the digest contract, not just display
names: the `Classification::as_str` names above (tag 14, and inside `context_digest`), the `AUTH_METHODS`
vocabulary (`aitp-pinned-handshake`, `aitp-tct`, `aitp-pinned`, and the `none` sentinel; tag 17), and the
`TrustLevel::as_str` names (`Untrusted` / `Sandboxed` / `Trusted` / `Privileged`, the level suffix of
`trust_basis` inside the keyed tag 16). Renaming any entry changes the digests of every record sealed after
the rename, so a rename is a contract change (new `schema_version`), never a refactor. Each table is pinned
by a test in `seam-types`.

**Strings hash as their raw UTF-8 bytes**, with no normalization of any kind — no Unicode NFC/NFD, no
case folding, no trimming. This covers `ctx_ref`, `lineage_id`, mode ids, `agent_id`, `pinned_version`,
participant ids, `auth_method`, the commitment string, and the enum strings below. Ingress already
constrains most of these to a safe ASCII charset, but the digest does not rely on that and must not:
normalization is a step three of four implementations would implement differently, or skip.

**One framing rule, and exactly one exception, named.** In every sub-preimage below: *every field is
framed, every optional is `opt`-encoded, and every list is preceded by a bare `le32` count* — including
fixed-width fields such as the 32-byte `manifest_digest`. A list count is **4 bytes, not framed**. There
are four independent implementations of this in three languages; a rule with exceptions is where they
drift, so the single exception is called out where it occurs rather than left to be discovered: the
`scope(...)` blob is pre-existing bytes the digest reuses verbatim, and *its* internal counts are framed.
See `scope(...)` below. Nothing else frames a count.

**Sub-digest domain tags.** `participation_digest` keeps its `.v3` domain tag
(`seam.audit.participation.v3`): its grammar did not change in v4, and a domain tag names a grammar, not
the release that introduced it. `context_digest` is `seam.audit.context-provenance.v4` since B11: its
grammar gained a fifth receipt slot, `receipt_key_status` (owner decision 2026-10-18, ACDP conformance
vector `rcpt-005/B`). `.v4` is the **only** context-provenance formula; `.v1`–`.v3` are not dispatched by
any verifier (no backward compatibility — prod was recreated). `participants_digest` is new in v4
and is `seam.audit.participants.v4`. Every domain string in this system is
`seam.audit.<thing>.<version>`.

#### `context_digest` — `seam.audit.context-provenance.v4`

```
context_digest = SHA256(
    frame("seam.audit.context-provenance.v4")
  ‖ le32(len(context_provenance))                  // OUTER count, BARE le32 — see the collision note
  ‖ for each binding, in STORED ORDER:
        frame(ctx_ref) ‖ frame(fidelity) ‖ frame(classification)
      ‖ opt(lineage_id) ‖ frame(le32(version))
      ‖ le32(len(derived_from)) ‖ for each: frame(derived_from[i])
      ‖ opt(content_hash) ‖ opt(receipt_hash) ‖ opt(key_status) ‖ opt(resolved_status)
      ‖ opt(receipt_key_status)                    // .v4 — present EXACTLY when receipt_hash is
)
```

`fidelity` and `classification` encode as their **canonical PascalCase strings** — `Reference` /
`Digest` / `Value` / `Derivation`, and `Public` / `Internal` / `Confidential` / `Financial` / `Pii` /
`Phi` — never as ordinals. An ordinal silently renumbers the moment a variant is inserted into the
middle of an enum, and three of the four implementations would not notice.

**This PascalCase rule is scoped to closed, Seam-owned enums and does not generalize.** It applies to
these two fields, and to `key_status` and `receipt_key_status` below, because each has a fixed variant
list. It must **not** be
extended by analogy to `resolved_status`, which is an *open* ACDP enum with a lowercase wire form — see
the payload table below.

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

**The last five fields carry ACDP receipt provenance.** The first four were reserved by B3 and filled
by ACDP P1a; the fifth, `receipt_key_status`, was appended by `.v4`. They are populated on a **remote**
`acdp://` binding and absent (`0x00`) on a **local** `sha256:` one. A local ref has no registry, no producer DID and no receipt, so absent
is a true statement about that binding rather than a missing value.

**An absent slot is a single `0x00` byte**, so a local binding and a remote one recompute under the one
formula; a golden pins an absent-slot entry beside a populated one.

The reservation was confirmed against the ACDP implementation this runtime pins, not inferred: a remote
resolution yields exactly these four pieces of provenance, each a **scalar**, and a registry receipt is
**0-or-1 per binding by schema** — not a chain. A per-hop receipt chain is the one shape that would have
forced a counted list here, and it does not exist: derivation ancestry resolves each ancestor as its own
binding with its own receipt slots.

**`receipt_key_status` is paired with `receipt_hash`.** It is present **exactly when** `receipt_hash` is
(ACDP reports a receipt key status only for a verified receipt). A record holding one without the other
is **refused at seal**, errors on a store read, and is **refused by a verifier** before hashing — never
hashed as given. It answers RFC-ACDP-0010 §8 step 1: a receipt verified under a registry key that is in
the registry DID document's `verificationMethod` only (rotated out) is valid *history*, not a current
registry attestation, and the sealed record must say which (`rcpt-005/B`).

**The five payload encodings, pinned. One of them is a trap.**

| slot | encoding | source |
|---|---|---|
| `content_hash` | ASCII `sha256:<64-lowercase-hex>` | the **body**'s library-verified content hash |
| `receipt_hash` | ASCII `sha256:<64-lowercase-hex>` | ACDP's **`RegistryReceipt::preimage_hash()`** |
| `key_status` | **closed**, PascalCase | `CurrentlyAuthorized` · `HistoricallyAuthorized` · `HistoricallyAuthorizedPreCompromise` |
| `resolved_status` | **open**, ACDP's **lowercase** wire string, verbatim | the registry lifecycle status |
| `receipt_key_status` | **closed**, PascalCase | `Current` · `Historical` — ACDP's `VerifiedContext::receipt_key_status()`; NOT ACDP's lowercase JSON form |

- `key_status`'s third value, `HistoricallyAuthorizedPreCompromise`, became **producible** with ACDP
  P3 (RFC-ACDP-0014). Before P3 it was in the vocabulary and unreachable: the library's revocation
  phase was inert for Seam, so nothing could ever move a binding onto it. A reader who inferred from
  its absence in the field that it was reserved-for-future-use would now be wrong, and a consumer that
  handles only the first two values will meet the third the moment a producer publishes a revocation
  whose receipt-attested boundary post-dates the context (§7 step 2).
- `content_hash` comes from the **body**, not from the receipt. The body's hash is verified on every
  remote resolve whereas a receipt is optional, so sourcing it from the receipt would leave this absent
  against any registry that mints none — which is the whole v0.1.0 core-profile world.
- `receipt_hash` is named as a **function**, not a concept, because "the receipt's hash" is genuinely
  ambiguous: ACDP's receipt signing hash **excludes** the signature block, and two implementations will
  otherwise choose differently. It is the signature-excluding preimage, pinned against the spec's own
  `rcpt-001` golden vector.
- **The trap:** `resolved_status` is an **open** enum, so the "enums encode as canonical PascalCase"
  rule elsewhere in this document does **not** apply to it. Its canonical form is ACDP's lowercase wire
  string taken verbatim, including values this spec cannot enumerate. PascalCasing it by analogy with
  `key_status` produces a cross-language mismatch that is invisible until a second implementation
  recomputes the digest.

Two semantics that keep a mutable registry value safe to seal:

- `resolved_status` is the status **observed at resolution time** and is **never refreshed**. A future
  "status refresh" job would invalidate every sealed digest.
- A sealed `retracted` should be impossible, so **a verifier that sees one should raise an anomaly
  rather than accept it**. This is a **normative obligation on any verifier. It is not implemented,
  and on the current wire it is not implementable** — stated plainly because the wording here
  previously read as a claim about the shipped binary called `seam-verify`.
  * Not implemented: neither `seam-verify` nor the seam-sdk public verifier inspects
    `resolved_status`; both treat `context_digest` as opaque bytes.
  * Not implementable by any EXTERNAL verifier, and that is by design rather than by omission.
    `DecisionSealed` carries `bytes context_digest` and nothing else about context — no
    `resolved_status` appears anywhere in `seam_event.proto`. The **archive bundle is in the same
    position on purpose**: it carries the rolled-up `context_digest`, never the binding list, because
    putting provenance into external cold storage would put GDPR-reachable material there
    (`seam-types/src/archive.rs`, "Rolled up, never the lists"). `ReplayView` carries no provenance
    either. So every externalized form of a decision has deliberately discarded the field this
    anomaly is about.
    
    The check can therefore live in exactly one place today: a verifier with direct access to the
    stored `DecisionRecord` — in-process `get_record`, or the database. Anything else needs a wire
    change, and that wire change is in tension with the GDPR roll-up, so it is a design decision and
    not a chore. **This paragraph has now been wrong twice** — first claiming the verifier "already
    carries" the obligation, then naming replay and the archive bundle as able to. Check the carrier
    before extending it a third time.

  The obligation is unmet and currently unreachable, for **three independent reasons** — all must be
  named, because a future reader who lifts one will otherwise assume the others never existed:
  1. **The decision verbs refuse every `acdp://` ref outright** at ingress
     (`crates/seamd/src/facade.rs`, `require_context_ref_shape`), so no remote binding reaches a seal
     at all. This is the stronger guard, and it is the one actually load-bearing today.
  2. **P2 added the retraction predicate** (ACDP-0013). It lives at the two DECISION paths — both
     reach it through `facade::resolve_grounds_for_seal`, which fuses resolve → refuse → project so
     the refusal is not a separable call an edit can drop — and NOT in the resolver. A decision
     citing retracted grounds is refused before anything seals. It is deliberately NOT applied at the read-only `ResolveContext` facade, which
     must keep answering: retraction MARKS rather than deletes (RFC-ACDP-0013 §8.1) and the body
     still verifies. Because guard 1 stands, this predicate is currently **latent**; it exists so
     that lifting guard 1 does not open a window in which retracted grounds seal permanently.
  3. **P3 added the key-revocation predicate** (ACDP-0014). Same place, same shape, same reason:
     `facade::refuse_revoked_key` sits behind the same composite as guard 2, refuses grounds whose
     producer signing key Seam could not CLEAR against the revocations it holds (`Revoked`,
     `Unplaceable`, `KeyUnidentified` — deliberately not "signed by a revoked key", since under the
     third of those Seam does not know the key was revoked), and is likewise **not** applied at the
     read-only `ResolveContext` facade, which serves the verdict instead (RFC-ACDP-0014 §10: a §7
     fail-closed is *"a verification verdict, not a wire condition"*). Latent for the same reason
     guard 2 is.

  P1a records the status verbatim and adds no ingress refusal of its own; a second, P1a-local
  implementation of the predicate would have had to be unified with this one.

  **Whoever lifts guard 1 owes the verifier check**, not just the end-to-end refusal test. Both
  guards above are **producer-side**, and a verifier's whole job is to be independent of the
  producer — so "the producer will not emit one" is not a reason for a verifier not to check, it is
  the reason a verifier exists.
  
  And such a record is not hypothetical: `seam-store`'s
  `a_record_sealed_against_a_since_retracted_context_still_verifies_with_an_unchanged_digest`
  constructs, seals and digests exactly one, deliberately — `context_provenance_digest` refuses
  nothing, because a WORM record must not be re-judged by facts that arrived after it was sealed.
  It is the cross-language golden for the populated-D3 case
  (`scripts/v4-digest-reference.py`, `D3_POPULATED_CONTEXT`). So a corpus containing one verifies
  clean today, and that is correct chain behaviour: the anomaly is a **semantic** verdict layered
  above the hash chain, never a chain failure.

### `retraction` — served only, never sealed

`ResolveContext` also returns a per-binding `retraction` (proto tag 11 / HTTP `retraction`): Seam's
own RFC-ACDP-0013 §7.2 assessment, in a lowercase-with-underscore vocabulary of exactly three values
— `retracted` | `not_retracted` | `unknown`.

**It is NOT in any digest**, and it is absent from the four-encodings table above on purpose: that
table is the digest preimage, and a non-sealed field listed there is exactly the confusion this
distinction exists to prevent. The assessment is a read-time observation; `resolved_status` (tag 10)
is the sealed wire commitment. In Rust the separation is structural rather than conventional — the
assessment lives on a sibling `ResolvedContext`, never on `ContextBinding`, so it cannot reach
`context_provenance_digest`.

`unknown` is **not** a failure and must not be read as `not_retracted`. A registry that does not
implement `acdp-registry-lifecycle` omits its event history entirely (never as an empty array), so
"nothing was retracted" and "this registry cannot tell you" are indistinguishable on the wire.

Rationale and threat model: [`docs/design/acdp-retraction-not-erasure-decision.md`](../design/acdp-retraction-not-erasure-decision.md).

### `revocation` and `revocation_trust_class` — served only, never sealed

`ResolveContext` also returns a per-binding `revocation` (proto tag 12 / HTTP `revocation`) and
`revocation_trust_class` (tag 13): Seam's own RFC-ACDP-0014 §7 assessment of the producer's **body
signing key**, in a lowercase-with-underscore vocabulary of exactly six values —
`not_revoked` | `pre_compromise` | `revoked` | `unplaceable` | `key_unidentified` | `unknown` —
with a two-value trust class, `producer_signed` | `registry_attested` (§5 / §6), present only when a
statement actually acted.

**Three of the six are reserved, never served** (since acdp 0.15, B8; owner decision 2026-10-18):
`revoked`, `unplaceable` and `key_unidentified`. Those cases now fail the resolve, so there is no
verified content to carry them. They surface as errors instead: `CONTEXT_KEY_REVOKED`,
`CONTEXT_REVOCATION_UNAVAILABLE` (transient lookup failure) or `CONTEXT_REVOCATION_UNKNOWN` (any other
reason the check cannot answer). The values stay in the vocabulary, so a consumer must still parse
them.

**Neither is in any digest**, for the same reason and with the same structural guarantee as
`retraction`: both live on a sibling `ResolvedContext`, never on `ContextBinding`, so neither can
reach `context_provenance_digest`. What the revocation check *does* seal is `key_status` (tag 9),
which it may move to `HistoricallyAuthorizedPreCompromise` — that is the sealed consequence; these
two fields are the read-time explanation of it.

⚠️ **`not_revoked` is a bounded claim and must be read as one.** It attests *"we asked this registry
and it showed us nothing"* — never *"no revocation exists"*. RFC-ACDP-0014 §8 is explicit that an
absence of search results is not evidence of absence, and a registry that suppresses discovery
produces exactly this answer. A consumer treating `not_revoked` as a clean bill of health has
converted a statement about one moment and one registry into a global one.

`unknown` is a **different fact again** and must not be read as `not_revoked`: it means the
revocation check is disabled, so Seam did not ask at all. `not_revoked` says we asked and were shown
nothing; `unknown` says we did not ask. Collapsing the two is a silent fail-open. A lookup that fails
is never served as `unknown`: it refuses with `CONTEXT_REVOCATION_UNAVAILABLE` or
`CONTEXT_REVOCATION_UNKNOWN`.

⚠️ **Staleness alone is NOT a cause of `unknown`, and an implementation that treats it as one is
wrong.** A negative answer older than the staleness bound triggers **one synchronous re-source**
inside the call's existing budget; if that re-source fails or runs out of budget, the resolve
refuses (above). *Stale means re-ask, not degrade* — the alternative would leave nothing to repair the
staleness, and the check would decay to permanently off. The staleness bound is a Seam parameter, not
an RFC one: RFC-ACDP-0014 §11 says the window between compromise and consumer awareness *"is bounded
by consumer polling policy, not by this RFC"*.

⚠️ **A registry outage does not downgrade a known revocation.** A failed lookup never turns a
**positive** already held into a weaker answer: `pre_compromise` is still served, and a revoked key
still refuses with `CONTEXT_KEY_REVOKED`. §4 makes
revocation permanent, so forgetting one because a registry is unreachable would be the fail-open in
the other direction. An implementation that collapses *every* verdict to `unknown` on a failed lookup
is not conformant with what this field means.

Three of the six **refuse** at the two decision paths — `revoked`, `unplaceable`, `key_unidentified`
— and none of them refuses here (§10: a §7 fail-closed is *"a verification verdict, not a wire
condition"*). `key_unidentified` claims strictly less than the other two: it does not assert this key
is revoked, only that Seam holds revocations it could not compare this signature against.

Rationale and threat model: [`docs/design/acdp-key-revocation-decision.md`](../design/acdp-key-revocation-decision.md).

**ACDP-0011 lineage-head receipts are deliberately NOT here (P1b, deferred).** `verified_head_receipt()`
is populated only by ACDP's `fetch_current`, which this runtime does not call — reading it would add a
`/current` round trip per remote context on the decision path, to answer "is this the head" about a
record that seals *the version it was given*. Recorded as a decision rather than left as an unexplained
absence: `head_receipt_stale()` is not consulted, and a `None` head receipt has three distinct causes
(never fetched, none minted, or the lineage has no endorsable head) which must not be collapsed into
"stale".

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

**This is the one place in the record digest where a count is framed, and it is a deliberate exception, not the rule.**
Everywhere else — the two outer counts, `derived_from`, `declared_modes` — a count is a bare 4-byte
`le32`. The difference exists because these are not bytes the record digest encodes: they are the existing `put_scope`
output, reused verbatim so that the scope encoding has exactly one definition. Copying its convention
outward, or the record digest's convention inward, both produce a digest that no other implementation reproduces. The
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
or `context_provenance` columns, nor the `participants`, `classification`, `auth_method` or
`trust_basis_commitment` columns. So a shredded record still recomputes `digest_v4` identically and still
proves its place in the chain. (A **tenant** shred destroys the tenant's commitment key: the stored
`trust_basis_commitment` string still recomputes — boot re-verify frames the stored column and never
re-derives it — but it can no longer be linked to any `trust_basis` value.)

#### `participants_digest` — `seam.audit.participants.v4`

```
participants_digest = SHA256(
    frame("seam.audit.participants.v4")
  ‖ le32(len(participants))                       // count, BARE le32
  ‖ for each id, in STORED ORDER: frame(id)
)
```

`participants` is the record's flat id roster in **stored (admission) order** — no sorting, no
de-duplication. It is **mandatory** on the wire (tag 15) even when the roster is empty: the empty roster
is `SHA256(frame(domain) ‖ le32(0))`, never an absent slot or a zero sentinel. It is **unkeyed**: the
roster holds agent/role names, not data subjects, and is outside the erasure predicate.

#### `trust_basis_commitment` and `auth_method` — the trust basis

`trust_basis` is an erasure-predicate value and the outbox cannot be shredded, so it is **never** on the
wire, raw or as a bare hash (a bare hash of a small-preimage value is a set-membership oracle; #484,
#1293). Tag 16 instead carries a **keyed commitment** to it, the same construction as
`AUTHORIZE_EVALUATED`'s subject commitments (§AUTHORIZE_EVALUATED, *PII rule*):

```
trust_basis_commitment = "hmac-sha256:<kid>:<hex>"
    hex = HMAC-SHA256(k_tenant, put("seam.audit.trust-basis.v4") ‖ put(tenant) ‖ put(trust_basis))
```

`put(x) = le32(len(x)) ‖ x` (the little-endian u32 byte-length prefix, then the raw UTF-8 bytes — the same
framing as `frame(x)` above; defined with the *PII rule*).

The record digest frames the **string** (ASCII), not the HMAC bytes, so a verifier recomputes the record
digest from the wire without the key. A verifier cannot open the commitment, and is not meant to: it
proves the sealed record's trust basis cannot be rewritten after the fact, while staying unlinkable once
the tenant is shredded. The runtime stores the commitment in its own column and every recompute (boot
re-verify included) frames the stored column — it is never re-derived, because the key may since have
been rotated or shredded.

`auth_method` (tag 17) is the plain authentication-method label (`aitp-tct`, …), framed as its raw
UTF-8. It is not subject-bearing and is not keyed.

**No trust decision.** A seal with no trust decision (an in-process embedder calling the kernel with
`None`) stamps the sentinel `trust_basis = "none"` and `auth_method = "none"`, and the commitment is
computed over the sentinel — so tags 14-17 are never empty and a trust-less seal stays distinguishable.

**Fail closed on the key.** If the tenant's commitment key is unavailable (shredded, or an unwrap
failure) the seal is **refused** with reason `commitment_key_unavailable` and no record is written. A
producer never falls back to an unkeyed or empty commitment.

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
concatenation could not tell where one list ended and the next began. The record digest counts every
list, inner and outer, so no rearrangement of elements between lists can produce the same preimage.

#### Strip semantics for tags 11-17

`context_digest` (11), `participation_digest` (12), `classification` (14), `participants_digest` (15),
`trust_basis_commitment` (16) and `auth_method` (17) are **mandatory** on every payload. A consumer that
receives a payload with any of them absent **must refuse to verify** — it must not substitute an empty
value, and there is no older formula to fall back to. Absent-when-required is a strip
attack, and it must be reported distinctly from a digest mismatch so an operator can tell "someone
removed a field" from "someone rewrote one".

`policy_rules_digest` is `SHA256(JCS(policy_definition))` over the policy actually bound to the
session — JCS rather than file bytes, so the digest is representation-independent and an unchanged
policy keeps its digest when policy delivery moves from local files to the control plane. As a
`digest_v4` input it is opaque, so recomputation does not require re-deriving it; the formula is stated
so an auditor can independently check *what the slot attests*, which is the point of sealing it.

It attests **which bytes the runtime applied**, not that those bytes were authentic. Authenticity is
signed-control-plane-policy work, orthogonal and later. An unsigned policy's digest is exactly as
seal-worthy as an unsigned decision payload's ciphertext hash, which the digest already seals.

`policy_rules_digest` (13) is genuinely optional: absent means no policy was bound to that commitment,
which is today's common case. Absent ≠ `Some(empty)` — the `opt` presence byte distinguishes them
in the preimage, and *Presence on the wire* below explains why `Some(empty)` never reaches the preimage
in the first place.

#### Presence on the wire — why tags 10–17 are not `optional`

Five `DecisionSealed` fields carry a digest: `ciphertext_digest` (10), `context_digest` (11),
`participation_digest` (12), `policy_rules_digest` (13), `participants_digest` (15); three more carry a
mandatory string: `classification` (14), `trust_basis_commitment` (16), `auth_method` (17). None is
declared `optional`, while `mode` (4), `policy_version` (5) and `supersedes` (7) all are. All eight feed
either an `opt(...)` slot or a strip check, so what `len == 0` means on them is load-bearing, and this
section pins it.

**Why the digest slots are singular.** A digest slot's value domain is *{absent} ∪ {exactly 32 bytes}* —
the empty digest is not a value in it. Declaring the field singular makes that out-of-domain state
**unrepresentable by a conforming encoder**: proto3 emits no bytes for a singular scalar holding its
default, so a present-but-empty digest cannot leave a conforming producer. Declaring it `optional`
would make `Some(b"")` representable, and a representable-but-meaningless value is one some
implementation eventually produces.

**Why tags 4/5/7 are `optional`.** Their sealed columns are `Option`s, and the empty string is inside
their value domain — *`None` is not `Some("")`* above is explicit that a present-but-empty string is
data and that the digest must not depend on ingress refusing one. `opt(None)` and `opt(Some(""))` are
different preimages, so the wire must keep absence and emptiness apart. Were `mode` singular, a
legitimately-empty mode would encode as no bytes and decode as absent: the consumer would recompute
`opt(None)` against a record sealed over `opt(Some(""))` and report a rewrite that never happened.

Together these give the rule `DecisionSealed` actually obeys — apply it when adding a field:

> A `DecisionSealed` scalar is `optional` **iff** its preimage slot is `opt(...)` **and** the empty
> value is inside its value domain — exactly when absence and emptiness are two preimages the wire must
> keep apart. Every other field is singular: the always-`frame`d slots (tags 1–3, 6, 8–9) have no
> absent state to track, the digest slots (tags 10–13, 15) exclude the empty value by domain, whether
> their slot is `opt`ed (13) or not (10–12, 15), and the mandatory strings (tags 14, 16, 17) exclude it
> because an empty one is a strip.

> **The rule is `DecisionSealed`'s, not the package's — do not read it as a convention.** The envelope
> does not obey it: `SeamEvent` declares `digest` (19) and `checksum` (20) `optional bytes` while
> `prev_checksum` (12) is singular, and no one principle derives all three. The local facts instead: on
> `prev_checksum`, empty **is** a domain value — an advisory event carries an empty `prev_checksum` by
> design, and the genesis head is 32 zero bytes precisely so a chain-start link never aliases with "not
> chained" — so singular is faithful there. On 19/20, presence itself is the chained-ness bit (chained ⇔
> both present, §Ordering & integrity), and `optional` lets a stub consumer ask that question directly;
> but the empty digest is out of domain there too, so a singular declaration read under this section's
> `len == 0` rule would have served equally — that cardinality is a consistent choice, not a derivation.
> Nor does the flip hazard below have an analogue there: `prev_checksum` and `digest` are hashed by
> **raw concatenation** (`checksum == SHA256(prev_checksum ‖ digest)`), a preimage with no presence
> byte, so absent-versus-empty can never yield two different digests that two conforming consumers each
> believe.

**Producers MUST NOT emit a zero-length tag 10, 11, 12, 13, 14, 15, 16 or 17.** The canonical encoder cannot: prost
skips a singular scalar at its default, and the hand-written `DecisionSealedPb` it encodes through
declares these fields singular — the cardinality the descriptor pin below holds to this contract.

**Consumers MUST read a zero-length occurrence as absence** — on all eight tags, whether the field was
omitted or explicitly encoded with length zero. The second half is the part worth pinning: proto3
requires a decoder to *accept* an explicitly-encoded default value, so a non-conforming or hostile
producer can place `0x6a 0x00` (tag 13, length 0) on the wire even though a conforming one never will.
Defining `len == 0` as absent makes the mapping **total** over every byte sequence a decoder can be
handed, instead of resting on producers behaving:

| tag | `len == 0` means | consequence |
|-----|------------------|-------------|
| 10 `ciphertext_digest` | absent | a tag-10 strip → **refuse** (MISSING COMMITMENT) |
| 11 `context_digest` | absent | a strip → **refuse** (MISSING SUB-DIGEST), reported distinctly from a digest mismatch |
| 12 `participation_digest` | absent | as tag 11 |
| 13 `policy_rules_digest` | absent | `opt(None)` in the v4 preimage — a legitimate state, never a strip |
| 14 `classification` | absent | as tag 11 |
| 15 `participants_digest` | absent | as tag 11 (an empty roster is a 32-byte digest, never absent) |
| 16 `trust_basis_commitment` | absent | as tag 11 (a trust-less seal carries the `"none"` sentinel's commitment) |
| 17 `auth_method` | absent | as tag 11 (a trust-less seal carries `"none"`) |

This is what keeps `Some(b"")` out of the `digest_v4` preimage: the `opt(policy_rules_digest)` slot is
`opt(None)` or `opt(<32 bytes>)` and nothing else, which is why the conformance corpus ships exactly
two record-digest vector blocks — `record_digest_v4` and `record_digest_v4_absent_policy` — rather
than three. The JSON projection obeys the same rule by construction: all eight fields serialize
omitted-when-empty and parse missing-as-empty, so missing/`""` ⇔ absent there too.

A consumer decoding through generated stubs therefore cannot ask a presence question of these eight
fields (`HasField` and its equivalents are not generated for a proto3 scalar without explicit
presence), and does not need to: `len == 0` **is** the presence answer, by this rule. A consumer that
wants to tell "omitted" from "explicitly-encoded-empty" — to report a malformed producer rather than a
strip — must parse raw wire bytes rather than a decoded message. Both inputs verify identically either
way; only the diagnostic differs.

**Flipping any of these eight to `optional` would be a semantic break, even though it is wire-compatible.**
The bytes of a present, non-empty digest would not change, and this repo's `buf breaking` runs
`WIRE_JSON` (`buf.yaml`), which permits the flip — which is why this section exists rather than a lint
rule. What breaks is agreement between consumers: after the flip, a zero-length tag 13 frames as
`opt(None)` for a consumer testing emptiness and as `opt(Some(b""))` for one testing generated
presence, and the two recompute different digests from identical bytes. Cardinality is therefore pinned
per-tag in `fixtures/seam_event_descriptor.json`, which seam-store's
`descriptor_matches_the_canonical_encoder` holds against both this package's `.proto` and the
hand-written canonical encoder, and which is registered as its own group in the cross-repo golden
manifest — so the flip surfaces as a reviewed, coordinated re-pin, never a quiet one-line edit.

#### What the record digest binds, and what the commitment digest binds

v4 binds `trust_basis` (via its keyed commitment, tag 16), `auth_method`, `classification` and
`participants` directly in the record digest, so all four are now tamper-evident **from the wire**.
Before v4 they sat outside the record digest, and the claim that they were "bound inside the commitment
TCT" was only partly true. [`seam-commitment-digest:v3`](seam-commitment-digest.v3.md) frames
`auth_method` and the **raw** `trust_basis`, so those two were and still are bound into the TCT.
`classification` and `participants` are **not** framed by the commitment digest; v4 is the first thing
that binds them. The commitment digest keeps framing the raw `trust_basis` by design: it sits inside the
AEAD-encrypted, crypto-shreddable commitment ciphertext, and keying is needed only for the plaintext
outbox, so only tag 16 is keyed.

The commitment's `committer` (#802) and its sealed **explanation** (#804 — every accepted vote,
evaluation, objection and quorum ballot with its reason, an evaluation's `rationale_ref`, and its
confidence *or its absence*) need no slot here: both are part of the commitment plaintext, so they
are inside the ciphertext that `ciphertext_digest` (tag 10) already commits to, and both are also bound
into the TCT by [`seam-commitment-digest:v3`](seam-commitment-digest.v3.md). Neither is on this wire —
the explanation carries free text and data-subject reasons, and crypto-shred erases it with the record.

#### Worked vector

Every input fixed; the independent reference is `scripts/v4-digest-reference.py`, and the Rust pins are
`record_digest_v4_known_vector*` and `participants_digest_empty_is_count_zero` in `seam-store`.

| input | value |
|---|---|
| `decision_id` / `tenant` / `namespace` | `d1` / `acme` / `ns` |
| `ciphertext` | the 6 ASCII bytes `cipher` (the wire carries `SHA256` of them in tag 10) |
| `sealed_at` | `7` |
| `outcome`, `mode`, `policy_version`, `supersedes` | `Resolved`, absent, absent, absent |
| `context_digest` | `8e87a93fd65b0d756817d2dbe3d9346542a2ad8272cc525f2df23d4b73802f85` — one binding: `ctx_ref` `sha256:aa`, `Digest`, `Internal`, no lineage, `version` 1, `derived_from` `["x","y"]`, all five receipt slots absent (`.v4`) |
| `participation_digest` | `521bb2054af761c4b2374702c8e5a2963416b3b48d4058fb22bc84c3efb49d85` — one decl: `agent_id` `p1`, no subject, modes `["m1","m2"]`, `scope(Unrestricted)`, empty `pinned_version`, 32 zero bytes `manifest_digest` |
| `classification` | `Internal` |
| `participants` | `["p1","p2"]` → `participants_digest` = `daffd522fc0760d9bb38e2bfb949d6eeb958f45efcfb212f7f3870df1105e06d` |
| `trust_basis_commitment` | `hmac-sha256:k1:00` (framed as an opaque ASCII string; the vector does not exercise the HMAC) |
| `auth_method` | `aitp-tct` |
| `schema_version` | `4` |

| case | `digest_v4` |
|---|---|
| `policy_rules_digest` absent | `2c4fd0f7223dd53215c40f763e540786cbb9d1a9b3dd4646836c73f9ad7813c3` |
| `policy_rules_digest` = 32 × `0xAB` | `799e05b2b690b4a1bfb5ff57868aa69e62f518101d926181e5ec53f5b429dcdf` |

And `participants_digest([])` = `88693ab24c8d56e6a92f63cf57d094ae463264cf5c74b7ba31dbc905ea164997` (a bare
`le32(0)` after the framed domain).

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

**The record-digest version is separate from the stream version.** A `DECISION_SEALED` payload's own
`schema_version` (a `u32`, today `4`) selects the record-digest formula, and it moves independently of
`"seam-event.v1"`: P7 (record digest v4, payload tags 14-17) was a contract break inside
`seam-event.v1`. Tolerant reading does **not** extend to it: a verifier that meets a record
`schema_version` it does not implement refuses (UNKNOWN SCHEMA VERSION) rather than skipping the record.
A new record-digest formula retires the previous one outright — there is one formula per build, no
dual-emit, and no read path for retired versions — and it is released as one coordinated contract change
(runtime, `seam-sdk` verifier and vectors, and the golden manifest re-pin together).

Consumers MUST likewise tolerate an unknown event **`kind`**: it MUST NOT stall or fail delivery of
the stream. A delivery consumer skips it; a fail-loud consumer MAY instead divert it to a dead-letter
path and keep consuming — `seam-learning`'s decoder does exactly that, deliberately, and its enum is
kept closed on purpose. Adding a `kind` is an additive change within `seam-event.v1`, on the same
footing as adding a field.

**Tolerance never extends to *attesting* the stream — but chain verification does not key on `kind`
at all** (§Ordering & integrity: *"Chained-ness is by field presence, not by `kind`"*). An unmodelled
`kind` carrying `digest`/`checksum` **is a link**: a verifier MUST verify it and advance
`running_head` exactly as for a kind it models, because the link check needs no payload semantics —
`digest` is on the wire. Skipping it instead falsely reports the chain **broken at the next link**.

What an unmodelled `kind` costs is *content* coverage, not linkage: its `digest` cannot be recomputed
from a payload the consumer cannot parse, so a verifier claiming recompute coverage MUST disclose
such events as unverified content — the same disclose-or-refuse rule the pre-cutover note carries —
and MUST NOT fold them into a green claim. A `--strict` verifier MAY refuse the stream outright; that
is a refusal to attest, not a delivery failure, and the tolerant-reader rule does not forbid it.
