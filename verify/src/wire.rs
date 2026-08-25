//! The `seam-event.v1` wire format — **only the fields verification needs**.
//!
//! Transcribed from the published spec (`docs/seam-event.v1.md`) and the published schema
//! (`proto/seam/event/v1/seam_event.proto`). Nothing here is imported from Seam; the tags are read off
//! the spec, which is the point.
//!
//! Protobuf ignores fields it does not know, so this decodes a full `SeamEvent` while declaring only the
//! tags that bear on the chain. A verifier has no business decoding a decision's payload — it verifies a
//! hash chain, and the less of the message it needs to understand, the less there is to get wrong.

use prost::Message;
use serde::Deserialize;

/// The envelope, verification-relevant tags only.
#[derive(Clone, PartialEq, Message)]
pub struct SeamEventPb {
    #[prost(string, tag = "1")]
    pub schema_version: String,
    #[prost(string, tag = "2")]
    pub event_id: String,
    #[prost(uint64, tag = "3")]
    pub seq: u64,
    /// tag 4 — part of the event's IDENTITY. Two chain anchors over a quiet stream differ *only* here;
    /// drop it from the canonical form and they collapse into one "duplicate", discarding evidence.
    #[prost(uint64, tag = "4")]
    pub occurred_at: u64,
    /// tags 5/6 — part of the event's IDENTITY (like `occurred_at`): two otherwise-identical events in
    /// different tenants/namespaces are different events, and must not dedup into one.
    #[prost(string, tag = "5")]
    pub tenant: String,
    #[prost(string, tag = "6")]
    pub namespace: String,
    #[prost(string, tag = "8")]
    pub kind: String,
    /// tag 12 — the head this event extends.
    #[prost(bytes = "vec", tag = "12")]
    pub prev_checksum: Vec<u8>,
    /// tag 13 — the `DECISION_SEALED` payload. Read ONLY under `--issuer` (design-a, Phase 4), to
    /// recompute the record's digest-v2 from its structural columns and catch a payload rewrite. A verifier
    /// otherwise has no business decoding a decision's payload — this is the deliberate, `--issuer`-gated
    /// widening the plan prices.
    #[prost(message, optional, tag = "13")]
    pub payload: Option<DecisionSealedPb>,
    /// tag 16 — an `AUDIT_ENTRY`. We need only its `action`, to spot the off-chain `chain_anchor`.
    #[prost(message, optional, tag = "16")]
    pub audit_entry: Option<AuditEntryPb>,
    /// tag 18 — the signed erasure certificate.
    #[prost(message, optional, tag = "18")]
    pub erasure_certificate: Option<ErasureCertificatePb>,
    /// tag 19 — this entry's own digest. **Absent ⇒ not a chain link.**
    #[prost(bytes = "vec", optional, tag = "19")]
    pub digest: Option<Vec<u8>>,
    /// tag 20 — the head this entry produces, `= H(prev_checksum ‖ digest)`.
    #[prost(bytes = "vec", optional, tag = "20")]
    pub checksum: Option<Vec<u8>>,
    /// tag 22 — the issuer-signed `(len, head)` (A14). Present on a `CHAIN_HEAD_ATTESTATION`, which is
    /// itself chained (it carries digest/checksum like any link) AND additionally verified under `--issuer`.
    #[prost(message, optional, tag = "22")]
    pub chain_head_attestation: Option<ChainHeadAttestationPb>,
    /// tag 23 — the ADVISORY `AUTHORIZE_EVALUATED` payload (spec §AUTHORIZE_EVALUATED). Not chained: the
    /// authorize path seals nothing, so this row is the only trace the call happened. Decoded (not skipped)
    /// so the payload is part of the event's canonical identity across both transports.
    #[prost(message, optional, tag = "23")]
    pub authorize_evaluated: Option<AuthorizeEvaluatedPb>,
}

/// The `CHAIN_HEAD_ATTESTATION` payload (tag 22), transcribed from `seam-event.v1.md` §CHAIN_HEAD_ATTESTATION.
#[derive(Clone, PartialEq, Message)]
pub struct ChainHeadAttestationPb {
    #[prost(uint64, tag = "1")]
    pub attested_len: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub attested_head: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub attested_at: u64,
    #[prost(string, tag = "4")]
    pub issuer_aid: String,
    #[prost(uint32, tag = "5")]
    pub digest_schema: u32,
    #[prost(bytes = "vec", tag = "6")]
    pub signature: Vec<u8>,
}

/// The `AUDIT_ENTRY` payload (envelope tag 16). ALL of its fields are part of the event's canonical
/// identity: two chained audit entries differing only in `subject`/`reason` are two DIFFERENT events, and
/// collapsing them into one "duplicate" would discard evidence (and hide an impostor wearing a real id).
#[derive(Clone, PartialEq, Message)]
pub struct AuditEntryPb {
    #[prost(string, tag = "1")]
    pub action: String,
    #[prost(string, tag = "2")]
    pub subject: String,
    #[prost(string, tag = "3")]
    pub reason: String,
    /// tag 4 — the authenticated operator subject (rt-D §4); `None` on the unauthenticated plane.
    #[prost(string, optional, tag = "4")]
    pub actor: Option<String>,
}

/// The `AUTHORIZE_EVALUATED` payload (envelope tag 23) — ADVISORY, unchained. Transcribed from
/// `seam-event.v1.md` §AUTHORIZE_EVALUATED. Never verified (nothing is sealed); decoded only so the
/// payload participates in the canonical dedup identity.
#[derive(Clone, PartialEq, Message)]
pub struct AuthorizeEvaluatedPb {
    #[prost(string, tag = "1")]
    pub authorize_id: String,
    #[prost(string, optional, tag = "2")]
    pub client_request_id: Option<String>,
    #[prost(string, tag = "3")]
    pub agent_aid: String,
    #[prost(string, tag = "4")]
    pub agent_id: String,
    #[prost(string, tag = "5")]
    pub tool_name: String,
    #[prost(string, tag = "6")]
    pub tool_input_digest: String,
    #[prost(string, tag = "7")]
    pub verdict: String,
    #[prost(string, tag = "8")]
    pub reason: String,
    #[prost(string, tag = "9")]
    pub policy_version: String,
    #[prost(string, optional, tag = "10")]
    pub subject_digest: Option<String>,
}

/// The `DECISION_SEALED` payload (envelope tag 13) — the structural columns the digest-v2 recompute covers,
/// plus `ciphertext_digest` (tag 10, the one input a stream consumer does not otherwise hold). Transcribed
/// from `seam-event.v1.md` §DECISION_SEALED + §Record digest. `mode`/`policy_version`/`supersedes` are
/// `optional` — proto3 explicit presence — because the v2 framing distinguishes `None` from `Some("")`.
#[derive(Clone, PartialEq, Message)]
pub struct DecisionSealedPb {
    #[prost(string, tag = "1")]
    pub decision_id: String,
    #[prost(string, tag = "2")]
    pub tenant: String,
    #[prost(string, tag = "3")]
    pub namespace: String,
    #[prost(string, optional, tag = "4")]
    pub mode: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub policy_version: Option<String>,
    #[prost(string, tag = "6")]
    pub outcome: String,
    #[prost(string, optional, tag = "7")]
    pub supersedes: Option<String>,
    #[prost(uint64, tag = "8")]
    pub sealed_at: u64,
    #[prost(uint32, tag = "9")]
    pub schema_version: u32,
    /// tag 10 — `SHA256(ciphertext)`. Mandatory on v2; absent (empty) on v1. A v2 record missing it is a
    /// strip/downgrade attack, refused under `--issuer`.
    #[prost(bytes = "vec", tag = "10")]
    pub ciphertext_digest: Vec<u8>,
    /// tags 11/12/13 (B3) — 32-byte sub-digests. 11 and 12 are MANDATORY on `schema_version = 3`;
    /// 13 is genuinely optional (absent means no policy was bound, today's common case).
    ///
    /// **SINGULAR, not `optional` — this said the opposite until seam-runtime#435 settled it.** The
    /// argument for explicit presence was that absent and present-empty must not alias, since a record
    /// with no participants still has a well-defined `participation_digest`. That conclusion was right
    /// and the mechanism was wrong. A digest slot's value domain is {absent} ∪ {exactly 32 bytes}, so
    /// a singular field makes the empty value UNREPRESENTABLE by a conforming encoder — proto3 emits
    /// no bytes for a singular scalar at its default. `optional` would make `Some(b"")` encodable and
    /// meaningless, and a representable-but-meaningless value is one some implementation eventually
    /// produces. Absent still drives the refusal; it is carried by LENGTH rather than by a presence bit.
    ///
    /// The consumer rule (spec §"Presence on the wire") is a TOTAL mapping: `len == 0` is absent
    /// however the bytes arose — including an explicitly-encoded `0x6a 0x00`, which proto3 obliges a
    /// decoder to accept even though a conforming producer never emits one. Keeping `Option` here made
    /// prost decode exactly those bytes as `Some(b"")`, which this verifier then refused as MALFORMED
    /// — refusing a record the contract calls valid, and disagreeing with the Python and TS twins on
    /// identical bytes. Tags 4/5/7 above are the real `optional` case: the empty string IS in their
    /// domain, so `None` and `Some("")` are two preimages the wire must keep apart.
    #[prost(bytes = "vec", tag = "11")]
    pub context_digest: Vec<u8>,
    /// See tag 11 for the cardinality rule these three share.
    #[prost(bytes = "vec", tag = "12")]
    pub participation_digest: Vec<u8>,
    /// See tag 11. Absent (`len == 0`) is legitimate and frames as `opt(None)` in the v3 preimage.
    #[prost(bytes = "vec", tag = "13")]
    pub policy_rules_digest: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ErasureCertificatePb {
    #[prost(string, tag = "1")]
    pub subject: String,
    #[prost(string, repeated, tag = "2")]
    pub erased: Vec<String>,
    #[prost(string, repeated, tag = "3")]
    pub held: Vec<String>,
    #[prost(uint64, tag = "4")]
    pub erased_at: u64,
    #[prost(bytes = "vec", tag = "5")]
    pub chain_head: Vec<u8>,
    #[prost(string, tag = "6")]
    pub issuer_aid: String,
    #[prost(bytes = "vec", tag = "7")]
    pub signature: Vec<u8>,
}

// ---- the JSON projection (what a webhook sink holds) ----------------------------------------------
//
// Per the spec: a field-for-field mapping of the envelope with `bytes` fields **base64** and `u64` fields
// as JSON numbers. Absent optional fields are omitted entirely.

#[derive(Deserialize)]
pub struct SeamEventJson {
    #[serde(default)]
    pub schema_version: String,
    #[serde(default)]
    pub event_id: String,
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub occurred_at: u64,
    #[serde(default)]
    pub tenant: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub prev_checksum: String,
    #[serde(default)]
    pub digest: Option<String>,
    #[serde(default)]
    pub checksum: Option<String>,
    #[serde(default)]
    pub payload: Option<DecisionSealedJson>,
    #[serde(default)]
    pub audit_entry: Option<AuditEntryJson>,
    #[serde(default)]
    pub erasure_certificate: Option<ErasureCertificateJson>,
    #[serde(default)]
    pub chain_head_attestation: Option<ChainHeadAttestationJson>,
    #[serde(default)]
    pub authorize_evaluated: Option<AuthorizeEvaluatedJson>,
}

#[derive(Deserialize)]
pub struct ChainHeadAttestationJson {
    pub attested_len: u64,
    pub attested_head: String,
    pub attested_at: u64,
    pub issuer_aid: String,
    pub digest_schema: u32,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct AuditEntryJson {
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub subject: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub actor: Option<String>,
}

#[derive(Deserialize)]
pub struct AuthorizeEvaluatedJson {
    #[serde(default)]
    pub authorize_id: String,
    #[serde(default)]
    pub client_request_id: Option<String>,
    #[serde(default)]
    pub agent_aid: String,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub tool_input_digest: String,
    #[serde(default)]
    pub verdict: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub policy_version: String,
    #[serde(default)]
    pub subject_digest: Option<String>,
}

#[derive(Deserialize)]
pub struct DecisionSealedJson {
    #[serde(default)]
    pub decision_id: String,
    #[serde(default)]
    pub tenant: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub policy_version: Option<String>,
    #[serde(default)]
    pub outcome: String,
    #[serde(default)]
    pub supersedes: Option<String>,
    #[serde(default)]
    pub sealed_at: u64,
    #[serde(default)]
    pub schema_version: u32,
    /// base64 (STANDARD); absent/empty on v1.
    #[serde(default)]
    pub ciphertext_digest: Option<String>,
    /// base64 (STANDARD), tags 11/12/13 (B3). The `Option` here is serde's — "was the key in the
    /// object?" — and is folded away at the parse site: a missing key and `""` BOTH mean absent,
    /// matching the wire's total `len == 0` rule. This comment said the opposite (that `""` is a
    /// distinct present-but-empty state, refused as malformed) until seam-runtime#435 pinned the
    /// projection to the same rule as the wire. It matters because webhook and `GET /v1/events`
    /// consumers read this projection rather than the wire, and two projections that disagreed about
    /// absence would recompute two different digests from one record.
    #[serde(default)]
    pub context_digest: Option<String>,
    #[serde(default)]
    pub participation_digest: Option<String>,
    #[serde(default)]
    pub policy_rules_digest: Option<String>,
}

#[derive(Deserialize)]
pub struct ErasureCertificateJson {
    pub subject: String,
    pub erased: Vec<String>,
    pub held: Vec<String>,
    pub erased_at: u64,
    pub chain_head: String,
    pub issuer_aid: String,
    pub signature: String,
}

/// The one shape the verifier actually works on.
pub struct Event {
    pub event_id: String,
    pub seq: u64,
    pub occurred_at: u64,
    pub tenant: String,
    pub namespace: String,
    pub kind: String,
    pub prev_checksum: Vec<u8>,
    pub digest: Option<Vec<u8>>,
    pub checksum: Option<Vec<u8>>,
    /// The full `AUDIT_ENTRY` payload — all of it is dedup identity, not just `action` (two chained
    /// entries differing only in `subject`/`reason` are two different events).
    pub audit: Option<AuditEntry>,
    /// The `AUTHORIZE_EVALUATED` payload — advisory; carried only for the dedup identity.
    pub authorize: Option<AuthorizeEvaluatedPb>,
    pub cert: Option<Cert>,
    /// The `CHAIN_HEAD_ATTESTATION` payload, when this event is one. `None` otherwise.
    pub attestation: Option<Attestation>,
    /// The `DECISION_SEALED` payload — read only for the digest-v2 recompute under `--issuer`.
    pub decision: Option<Decision>,
    /// The canonical bytes this event decoded from (or re-encodes to) — the dedup identity.
    pub bytes: Vec<u8>,
}

#[derive(Clone)]
pub struct AuditEntry {
    pub action: String,
    pub subject: String,
    pub reason: String,
    pub actor: Option<String>,
}

#[derive(Clone)]
pub struct Decision {
    pub decision_id: String,
    pub tenant: String,
    pub namespace: String,
    pub mode: Option<String>,
    pub policy_version: Option<String>,
    pub outcome: String,
    pub supersedes: Option<String>,
    pub sealed_at: u64,
    pub schema_version: u32,
    pub ciphertext_digest: Vec<u8>,
    /// Tags 11/12/13 (B3). Absence is carried by LENGTH, not by `Option`: empty means "not on the
    /// wire", per the spec's total `len == 0` mapping (§"Presence on the wire"). `record_digest_v3`
    /// still depends on absent-vs-present — absent on a v3 record is a strip and is refused, while a
    /// 32-byte digest of an empty participation list is a legitimate value — but the empty digest is
    /// out of these slots' domain entirely, so there is no third state for `Option` to represent.
    pub context_digest: Vec<u8>,
    pub participation_digest: Vec<u8>,
    pub policy_rules_digest: Vec<u8>,
}

#[derive(Clone)]
pub struct Cert {
    pub subject: String,
    pub erased: Vec<String>,
    pub held: Vec<String>,
    pub erased_at: u64,
    pub chain_head: Vec<u8>,
    pub issuer_aid: String,
    pub signature: Vec<u8>,
}

impl Cert {
    /// Parse an erasure-certificate **document** in any of the shapes the reference emitter produces.
    ///
    /// A verifier that only accepts the form its author happened to test with is a verifier nobody can
    /// run, so all three are accepted:
    ///
    /// 1. a `{"issuer_aid": …, "cert": {…}}` wrapper (what `fixtures/` ships),
    /// 2. a bare `seam-event.v1` event line carrying an `ErasureCertificate` payload,
    /// 3. a bare certificate object.
    ///
    /// This lives here rather than in `main.rs` so the CLI and an embedding caller share ONE parse.
    /// When it was inline in the binary, an embedder had to reimplement the shape-sniffing to accept
    /// the same files the CLI accepts — which is exactly the kind of second implementation this crate
    /// exists to avoid.
    pub fn parse_document(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();

        // Unwrap `{"cert": {...}}` if present; otherwise work on the input as given.
        let unwrapped: String = serde_json::from_str::<serde_json::Value>(raw)
            .ok()
            .and_then(|v| v.get("cert").cloned())
            .map(|c| c.to_string())
            .unwrap_or_else(|| raw.to_string());
        let raw = unwrapped.as_str();

        if let Some(cert) = Event::parse(raw).ok().and_then(|e| e.cert) {
            return Ok(cert);
        }

        let j: ErasureCertificateJson =
            serde_json::from_str(raw).map_err(|e| format!("not an erasure certificate: {e}"))?;
        use base64::Engine;
        let d = |s: &str| base64::engine::general_purpose::STANDARD.decode(s);
        match (d(&j.chain_head), d(&j.signature)) {
            (Ok(chain_head), Ok(signature)) => Ok(Cert {
                subject: j.subject,
                erased: j.erased,
                held: j.held,
                erased_at: j.erased_at,
                chain_head,
                issuer_aid: j.issuer_aid,
                signature,
            }),
            _ => Err("chain_head/signature are not valid base64".to_string()),
        }
    }
}

#[derive(Clone)]
pub struct Attestation {
    pub attested_len: u64,
    pub attested_head: Vec<u8>,
    pub attested_at: u64,
    pub issuer_aid: String,
    pub digest_schema: u32,
    pub signature: Vec<u8>,
}

fn b64(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("bad base64: {e}"))
}

impl Event {
    /// Decode one line: the JSON projection, or base64-encoded protobuf.
    ///
    /// A consumer holds whichever the transport gave them — a webhook sink has JSON, an outbox relay has
    /// protobuf — and the verdict must not depend on which.
    pub fn parse(line: &str) -> Result<Self, String> {
        let line = line.trim();
        if line.starts_with('{') {
            let j: SeamEventJson =
                serde_json::from_str(line).map_err(|e| format!("not a seam-event.v1 JSON: {e}"))?;
            if j.schema_version.is_empty() || j.event_id.is_empty() {
                return Err(
                    "no schema_version/event_id — this is not a seam-event.v1 event".into(),
                );
            }
            let cert = j.erasure_certificate.map(|c| -> Result<Cert, String> {
                Ok(Cert {
                    subject: c.subject,
                    erased: c.erased,
                    held: c.held,
                    erased_at: c.erased_at,
                    chain_head: b64(&c.chain_head)?,
                    issuer_aid: c.issuer_aid,
                    signature: b64(&c.signature)?,
                })
            });
            let attestation = j
                .chain_head_attestation
                .map(|a| -> Result<Attestation, String> {
                    Ok(Attestation {
                        attested_len: a.attested_len,
                        attested_head: b64(&a.attested_head)?,
                        attested_at: a.attested_at,
                        issuer_aid: a.issuer_aid,
                        digest_schema: a.digest_schema,
                        signature: b64(&a.signature)?,
                    })
                });
            let decision = j.payload.map(|p| -> Result<Decision, String> {
                Ok(Decision {
                    decision_id: p.decision_id,
                    tenant: p.tenant,
                    namespace: p.namespace,
                    mode: p.mode,
                    policy_version: p.policy_version,
                    outcome: p.outcome,
                    supersedes: p.supersedes,
                    sealed_at: p.sealed_at,
                    schema_version: p.schema_version,
                    ciphertext_digest: p
                        .ciphertext_digest
                        .as_deref()
                        .map(b64)
                        .transpose()?
                        .unwrap_or_default(),
                    // Missing key and `""` BOTH mean absent, exactly as `len == 0` does on the wire.
                    // The spec pins this for the JSON projection explicitly ("all four fields
                    // serialize omitted-when-empty and parse missing-as-empty, so missing/`\"\"` ⇔
                    // absent there too"), and it matters because webhook and `GET /v1/events`
                    // consumers read this rather than the wire — if the two projections disagreed
                    // about absence they would recompute different digests from the same record.
                    // The strip signal is NOT lost by collapsing them: empty IS the absent signal,
                    // and `v3_required` refuses it for tags 11/12.
                    context_digest: p
                        .context_digest
                        .as_deref()
                        .map(b64)
                        .transpose()?
                        .unwrap_or_default(),
                    participation_digest: p
                        .participation_digest
                        .as_deref()
                        .map(b64)
                        .transpose()?
                        .unwrap_or_default(),
                    policy_rules_digest: p
                        .policy_rules_digest
                        .as_deref()
                        .map(b64)
                        .transpose()?
                        .unwrap_or_default(),
                })
            });
            let ev = Event {
                event_id: j.event_id,
                seq: j.seq,
                occurred_at: j.occurred_at,
                tenant: j.tenant,
                namespace: j.namespace,
                kind: j.kind,
                prev_checksum: b64(&j.prev_checksum)?,
                digest: j.digest.as_deref().map(b64).transpose()?,
                checksum: j.checksum.as_deref().map(b64).transpose()?,
                audit: j.audit_entry.map(|a| AuditEntry {
                    action: a.action,
                    subject: a.subject,
                    reason: a.reason,
                    actor: a.actor,
                }),
                authorize: j.authorize_evaluated.map(|a| AuthorizeEvaluatedPb {
                    authorize_id: a.authorize_id,
                    client_request_id: a.client_request_id,
                    agent_aid: a.agent_aid,
                    agent_id: a.agent_id,
                    tool_name: a.tool_name,
                    tool_input_digest: a.tool_input_digest,
                    verdict: a.verdict,
                    reason: a.reason,
                    policy_version: a.policy_version,
                    subject_digest: a.subject_digest,
                }),
                cert: cert.transpose()?,
                attestation: attestation.transpose()?,
                decision: decision.transpose()?,
                bytes: Vec::new(),
            };
            return Ok(ev.with_identity());
        }

        let raw = b64(line).map_err(|_| "neither JSON nor base64 protobuf".to_string())?;
        if raw.is_empty() {
            return Err("empty event".into());
        }
        let pb = SeamEventPb::decode(&raw[..])
            .map_err(|e| format!("base64 decoded, but is not a seam-event.v1 protobuf: {e}"))?;
        // Protobuf has no required fields — prost decodes arbitrary bytes into an all-default message.
        // Such a thing is not an event; it is noise that survived a decoder.
        if pb.schema_version.is_empty() || pb.event_id.is_empty() {
            return Err(
                "decoded as protobuf but has no schema_version/event_id — not a seam-event.v1 event"
                    .into(),
            );
        }
        Ok(Event {
            event_id: pb.event_id,
            seq: pb.seq,
            occurred_at: pb.occurred_at,
            tenant: pb.tenant,
            namespace: pb.namespace,
            kind: pb.kind,
            prev_checksum: pb.prev_checksum,
            digest: pb.digest,
            checksum: pb.checksum,
            audit: pb.audit_entry.map(|a| AuditEntry {
                action: a.action,
                subject: a.subject,
                reason: a.reason,
                actor: a.actor,
            }),
            authorize: pb.authorize_evaluated,
            cert: pb.erasure_certificate.map(|c| Cert {
                subject: c.subject,
                erased: c.erased,
                held: c.held,
                erased_at: c.erased_at,
                chain_head: c.chain_head,
                issuer_aid: c.issuer_aid,
                signature: c.signature,
            }),
            attestation: pb.chain_head_attestation.map(|a| Attestation {
                attested_len: a.attested_len,
                attested_head: a.attested_head,
                attested_at: a.attested_at,
                issuer_aid: a.issuer_aid,
                digest_schema: a.digest_schema,
                signature: a.signature,
            }),
            decision: pb.payload.map(|p| Decision {
                decision_id: p.decision_id,
                tenant: p.tenant,
                namespace: p.namespace,
                mode: p.mode,
                policy_version: p.policy_version,
                outcome: p.outcome,
                supersedes: p.supersedes,
                sealed_at: p.sealed_at,
                schema_version: p.schema_version,
                ciphertext_digest: p.ciphertext_digest,
                context_digest: p.context_digest,
                participation_digest: p.participation_digest,
                policy_rules_digest: p.policy_rules_digest,
            }),
            bytes: raw,
        }
        .with_identity())
    }

    /// Give the event a canonical byte identity.
    ///
    /// **Always** re-encode from the parsed fields, never keep the raw input bytes. Delivery is
    /// at-least-once, and the same event can arrive twice over *different* transports — once as JSON on a
    /// webhook, once as protobuf on a relay. Keying identity on the raw bytes would make those two look
    /// like different events, the second would be read as a second link, and the verifier would cry
    /// forgery over a perfectly healthy stream. Re-encoding through one projection collapses them.
    fn with_identity(mut self) -> Self {
        let pb = SeamEventPb {
            schema_version: "seam-event.v1".into(),
            event_id: self.event_id.clone(),
            seq: self.seq,
            occurred_at: self.occurred_at,
            tenant: self.tenant.clone(),
            namespace: self.namespace.clone(),
            kind: self.kind.clone(),
            prev_checksum: self.prev_checksum.clone(),
            payload: self.decision.as_ref().map(|d| DecisionSealedPb {
                decision_id: d.decision_id.clone(),
                tenant: d.tenant.clone(),
                namespace: d.namespace.clone(),
                mode: d.mode.clone(),
                policy_version: d.policy_version.clone(),
                outcome: d.outcome.clone(),
                supersedes: d.supersedes.clone(),
                sealed_at: d.sealed_at,
                schema_version: d.schema_version,
                ciphertext_digest: d.ciphertext_digest.clone(),
                // These MUST be carried. Identity is the re-encoded payload, and it is what collapses
                // the same event arriving as JSON on a webhook and as protobuf on a relay into one
                // chain link. Drop the three new fields here and two v3 records differing ONLY in
                // `participation_digest` re-encode to identical bytes — the dedup that exists to
                // prevent a false forgery alarm would start erasing evidence instead. This is the one
                // omission in the v3 wire work that fails silently rather than loudly.
                context_digest: d.context_digest.clone(),
                participation_digest: d.participation_digest.clone(),
                policy_rules_digest: d.policy_rules_digest.clone(),
            }),
            // The FULL payload, not just `action`: identity narrowed to one field would dedup two audit
            // entries that differ only in subject/reason — two events collapsed into one, evidence gone.
            audit_entry: self.audit.as_ref().map(|a| AuditEntryPb {
                action: a.action.clone(),
                subject: a.subject.clone(),
                reason: a.reason.clone(),
                actor: a.actor.clone(),
            }),
            authorize_evaluated: self.authorize.clone(),
            erasure_certificate: self.cert.as_ref().map(|c| ErasureCertificatePb {
                subject: c.subject.clone(),
                erased: c.erased.clone(),
                held: c.held.clone(),
                erased_at: c.erased_at,
                chain_head: c.chain_head.clone(),
                issuer_aid: c.issuer_aid.clone(),
                signature: c.signature.clone(),
            }),
            digest: self.digest.clone(),
            checksum: self.checksum.clone(),
            chain_head_attestation: self.attestation.as_ref().map(|a| ChainHeadAttestationPb {
                attested_len: a.attested_len,
                attested_head: a.attested_head.clone(),
                attested_at: a.attested_at,
                issuer_aid: a.issuer_aid.clone(),
                digest_schema: a.digest_schema,
                signature: a.signature.clone(),
            }),
        };
        self.bytes = pb.encode_to_vec();
        self
    }

    /// Is this event a link in the chain? **By field presence, per the spec — never by `kind`.**
    pub fn is_link(&self) -> bool {
        self.digest.is_some() && self.checksum.is_some()
    }

    /// Is it legitimately unchained (advisory), rather than pre-cutover history we cannot verify?
    pub fn is_advisory(&self) -> bool {
        if ADVISORY_KINDS.contains(&self.kind.as_str()) {
            return true;
        }
        // The chain anchor: an AUDIT_ENTRY by kind, off-chain by design (spec §AUDIT_ENTRY).
        self.audit
            .as_ref()
            .is_some_and(|a| a.action == "chain_anchor")
    }
}

/// The kinds that carry no chain fields BY DESIGN (spec `enum EventKind`, the `ADVISORY`-annotated ones).
///
/// **Must stay equal to the spec's ADVISORY set** (`seam-runtime/docs/specs/seam-event.v1.md`, mirrored
/// by the runtime verifier's `ADVISORY_KINDS` at `seam-runtime/crates/seam-verify/src/main.rs` and its
/// `advisory_kinds_matches_spec_annotations` tripwire). A kind missing here makes `--strict` refuse a
/// healthy stream carrying it — exactly the `AUTHORIZE_EVALUATED` false refusal this list once shipped
/// with. Pinned by `advisory_kinds_are_pinned_to_the_spec` below.
pub const ADVISORY_KINDS: &[&str] = &[
    "LEARNING_DECISION",
    "LEARNING_OUTCOME",
    "BUDGET_BREACH",
    "SESSION_LIFECYCLE",
    // ADVISORY per spec §AUTHORIZE_EVALUATED (tag 23): the authorize path seals nothing — no record, no
    // DEK, no chain append — so the row carries no digest/checksum by design. Its omission made --strict
    // refuse any stream containing a single ESCALATE verdict (emitted unconditionally).
    "AUTHORIZE_EVALUATED",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Spec-sync tripwire, mirroring the runtime verifier's `advisory_kinds_matches_spec_annotations`
    /// (`seam-runtime/crates/seam-verify/src/main.rs`, which pins its list against the ADVISORY-annotated
    /// `enum EventKind` block of `docs/specs/seam-event.v1.md`).
    ///
    /// Two layers, so it bites in every environment:
    ///
    /// 1. **Always** — the list is pinned against the hardcoded expected set below. A kind can only be
    ///    added/removed here by ALSO editing this test, and the loud names point straight at the spec
    ///    section to reconcile against.
    /// 2. **When the runtime checkout is reachable** — the list is additionally checked EQUAL to the
    ///    spec's own ADVISORY annotations, parsed the same way the runtime tripwire parses them. The
    ///    sibling is located like the differential harness locates ours: `SEAM_RUNTIME_DIR` overrides;
    ///    otherwise `../../seam-runtime` beside this repo. A set-but-wrong `SEAM_RUNTIME_DIR` is a hard
    ///    FAILURE (someone asked for the check; silently skipping it would keep a broken gate green);
    ///    an absent sibling with no override is a skip (a third party building this crate standalone
    ///    cannot be required to hold Seam's private repo — independence is the product claim).
    #[test]
    fn advisory_kinds_are_pinned_to_the_spec() {
        // Layer 1 — the hardcoded pin. Reconcile ONLY against seam-event.v1.md `enum EventKind`'s
        // ADVISORY annotations (the runtime tripwire enforces that side of the equality).
        let expected: BTreeSet<&str> = [
            "LEARNING_DECISION",
            "LEARNING_OUTCOME",
            "BUDGET_BREACH",
            "SESSION_LIFECYCLE",
            "AUTHORIZE_EVALUATED",
        ]
        .into();
        let ours: BTreeSet<&str> = ADVISORY_KINDS.iter().copied().collect();
        assert_eq!(
            ours, expected,
            "ADVISORY_KINDS drifted from the expected set. Reconcile with the spec's ADVISORY-annotated \
             EventKinds (seam-runtime/docs/specs/seam-event.v1.md) — a kind advisory in the spec but \
             missing here makes --strict refuse a healthy stream (the AUTHORIZE_EVALUATED regression); \
             one here but not in the spec would green an unverifiable stream."
        );

        // Layer 2 — the spec itself, when reachable.
        let spec_path = match std::env::var("SEAM_RUNTIME_DIR") {
            Ok(dir) => {
                let p = std::path::PathBuf::from(dir).join("docs/specs/seam-event.v1.md");
                assert!(
                    p.is_file(),
                    "SEAM_RUNTIME_DIR is set but {} does not exist. It was set on purpose; skipping \
                     would keep a broken spec-sync gate green forever.",
                    p.display()
                );
                p
            }
            Err(_) => {
                let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../seam-runtime/docs/specs/seam-event.v1.md");
                if !p.is_file() {
                    eprintln!(
                        "skipping spec cross-check: no sibling seam-runtime checkout (set \
                         SEAM_RUNTIME_DIR to enforce it)"
                    );
                    return;
                }
                p
            }
        };
        let spec = std::fs::read_to_string(&spec_path).expect("read seam-event.v1.md");
        let body = spec
            .split_once("enum EventKind {")
            .expect("spec must declare `enum EventKind {`")
            .1
            .split_once('}')
            .expect("`enum EventKind {` must be closed by `}`")
            .0;
        let spec_set: BTreeSet<String> = body
            .lines()
            .filter(|l| l.contains("ADVISORY"))
            .filter_map(|l| l.split_whitespace().next())
            .filter(|t| !t.is_empty() && t.chars().all(|c| c.is_ascii_uppercase() || c == '_'))
            .map(str::to_owned)
            .collect();
        let ours: BTreeSet<String> = ADVISORY_KINDS.iter().map(|s| (*s).to_owned()).collect();
        assert_eq!(
            ours,
            spec_set,
            "ADVISORY_KINDS must equal the spec's ADVISORY-annotated EventKinds ({})",
            spec_path.display()
        );
    }

    fn b64e(b: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    /// An AUTHORIZE_EVALUATED event must be recognized on BOTH transports — decoded from base64 protobuf
    /// (tag 23) and from the JSON projection — classify as advisory, and canonicalize to the SAME identity
    /// bytes (so an at-least-once redelivery over the other transport dedups instead of doubling).
    #[test]
    fn authorize_evaluated_is_advisory_on_both_transports() {
        let pb = SeamEventPb {
            schema_version: "seam-event.v1".into(),
            event_id: "az01#az#7".into(),
            seq: 7,
            occurred_at: 1_700,
            tenant: "acme".into(),
            namespace: "fraud".into(),
            kind: "AUTHORIZE_EVALUATED".into(),
            authorize_evaluated: Some(AuthorizeEvaluatedPb {
                authorize_id: "az01".into(),
                client_request_id: None,
                agent_aid: "aid:pubkey:agent".into(),
                agent_id: "agent-1".into(),
                tool_name: "payments.transfer".into(),
                tool_input_digest: "sha256:00".into(),
                verdict: "ESCALATE".into(),
                reason: "amount_over_floor".into(),
                policy_version: "p1".into(),
                subject_digest: None,
            }),
            ..Default::default()
        };
        let from_pb = Event::parse(&b64e(&pb.encode_to_vec())).expect("pb transport must parse");
        assert!(from_pb.is_advisory(), "AUTHORIZE_EVALUATED is advisory");
        assert!(!from_pb.is_link());
        assert_eq!(
            from_pb.authorize.as_ref().map(|a| a.verdict.as_str()),
            Some("ESCALATE"),
            "the tag-23 payload must be decoded, not skipped"
        );

        let json = r#"{"schema_version":"seam-event.v1","event_id":"az01#az#7","seq":7,
            "occurred_at":1700,"tenant":"acme","namespace":"fraud","kind":"AUTHORIZE_EVALUATED",
            "prev_checksum":"","authorize_evaluated":{"authorize_id":"az01",
            "agent_aid":"aid:pubkey:agent","agent_id":"agent-1","tool_name":"payments.transfer",
            "tool_input_digest":"sha256:00","verdict":"ESCALATE","reason":"amount_over_floor",
            "policy_version":"p1"}}"#
            .replace('\n', "");
        let from_json = Event::parse(&json).expect("JSON transport must parse");
        assert!(from_json.is_advisory());
        assert_eq!(
            from_pb.bytes, from_json.bytes,
            "one event, two transports — the canonical identity must collapse them"
        );
    }

    /// The v3 columns (tags 11/12/13) must survive BOTH transports, land in the slots their tag names,
    /// and canonicalize to the same identity.
    ///
    /// The slot assertions are the point. `context_digest` and `participation_digest` are adjacent,
    /// identically typed and identically sized, so a mapping that reads tag 12 into `context_digest`
    /// compiles, parses, and produces a perfectly well-formed record. Nothing but distinct values and
    /// a direct check can see it — and a swap on the PROTOBUF arm in particular is invisible to every
    /// stream-level test in this crate, because those all synthesize the JSON projection.
    #[test]
    fn the_v3_columns_survive_both_transports_and_land_in_the_slots_their_tags_name() {
        let ctx = vec![0x11u8; 32];
        let part = vec![0x22u8; 32];
        let rules = vec![0x33u8; 32];
        let cipher = vec![0x44u8; 32];

        let pb = SeamEventPb {
            schema_version: "seam-event.v1".into(),
            event_id: "d1#7".into(),
            seq: 7,
            occurred_at: 1_700,
            tenant: "acme".into(),
            namespace: "fraud".into(),
            kind: "DECISION_SEALED".into(),
            payload: Some(DecisionSealedPb {
                decision_id: "dec:v3".into(),
                tenant: "acme".into(),
                namespace: "fraud".into(),
                mode: None,
                policy_version: None,
                outcome: "Resolved".into(),
                supersedes: None,
                sealed_at: 1_700_000_000_000,
                schema_version: 3,
                ciphertext_digest: cipher.clone(),
                context_digest: ctx.clone(),
                participation_digest: part.clone(),
                policy_rules_digest: rules.clone(),
            }),
            ..Default::default()
        };
        let from_pb = Event::parse(&b64e(&pb.encode_to_vec())).expect("pb transport must parse");
        let d = from_pb.decision.as_ref().expect("a decision payload");
        assert_eq!(d.context_digest, ctx, "tag 11");
        assert_eq!(d.participation_digest, part, "tag 12");
        assert_eq!(d.policy_rules_digest, rules, "tag 13");

        let json = format!(
            r#"{{"schema_version":"seam-event.v1","event_id":"d1#7","seq":7,"occurred_at":1700,
            "tenant":"acme","namespace":"fraud","kind":"DECISION_SEALED","prev_checksum":"",
            "payload":{{"decision_id":"dec:v3","tenant":"acme","namespace":"fraud",
            "outcome":"Resolved","sealed_at":1700000000000,"schema_version":3,
            "ciphertext_digest":"{}","context_digest":"{}","participation_digest":"{}",
            "policy_rules_digest":"{}"}}}}"#,
            b64e(&cipher),
            b64e(&ctx),
            b64e(&part),
            b64e(&rules)
        )
        .replace('\n', "");
        let from_json = Event::parse(&json).expect("JSON transport must parse");
        let j = from_json.decision.as_ref().expect("a decision payload");
        assert_eq!(j.context_digest, ctx, "tag 11 (JSON)");
        assert_eq!(j.participation_digest, part, "tag 12 (JSON)");
        assert_eq!(j.policy_rules_digest, rules, "tag 13 (JSON)");

        assert_eq!(
            from_pb.bytes, from_json.bytes,
            "one v3 event, two transports — the canonical identity must collapse them, which it can \
             only do if `with_identity` carries the three new columns"
        );
    }

    /// Absent and present-and-empty are ONE thing on tags 11/12/13 — absent — and present-and-set is the
    /// other. This comment (and this test's name) asserted the opposite three-state reading until
    /// seam-runtime#435 pinned the rule; the body below always had to change with it, so leaving the
    /// prose behind would have left the file arguing with itself.
    ///
    /// The retracted argument was that folding `""` into absent would report a malformed record as a
    /// strip. It does reclassify that diagnostic — and the spec sanctions exactly that: telling
    /// "omitted" from "explicitly-encoded-empty" requires reading raw wire bytes rather than a decoded
    /// message, and "both inputs verify identically either way; only the diagnostic differs". What the
    /// old reading actually cost was worse than a diagnostic: it made a zero-length tag 13 — a
    /// legitimate absent policy — a MALFORMED refusal, failing records the contract calls valid.
    #[test]
    fn the_v3_columns_read_a_missing_key_and_an_empty_one_as_the_same_absence() {
        let parse = |field: &str| {
            Event::parse(&format!(
                r#"{{"schema_version":"seam-event.v1","event_id":"d1#7","seq":7,
                   "kind":"DECISION_SEALED","prev_checksum":"","payload":{{"decision_id":"dec:v3",
                   "tenant":"acme","namespace":"fraud","outcome":"Resolved","sealed_at":1,
                   "schema_version":3{field}}}}}"#
            ))
            .expect("parse")
            .decision
            .expect("a decision payload")
        };
        // Missing key and `""` are the SAME state — absent — matching the wire's total `len == 0`
        // rule. This assertion read the opposite way (`""` stays present) until seam-runtime#435
        // pinned the JSON projection to the same rule as the wire. Keeping them distinct here meant
        // a webhook consumer and a wire consumer could disagree about absence on the same record,
        // and so recompute two different digests from it — each believing the other's was tampered.
        assert!(
            parse("").context_digest.is_empty(),
            "an absent key is absent"
        );
        assert!(
            parse(r#","context_digest":"""#).context_digest.is_empty(),
            "a present-but-empty key means absent too — missing/`\"\"` are one state, not two"
        );
    }

    /// Two chained AUDIT_ENTRY events differing ONLY in the payload's subject/reason/actor are two
    /// DIFFERENT events. Identity narrowed to `action` alone deduped them into one — evidence discarded,
    /// and an impostor wearing a real id invisible.
    #[test]
    fn audit_entries_differing_only_in_subject_or_reason_are_distinct_identities() {
        let entry = |subject: &str, reason: &str, actor: Option<&str>| {
            let actor = actor
                .map(|a| format!(r#","actor":{}"#, serde_json::to_string(a).unwrap()))
                .unwrap_or_default();
            Event::parse(&format!(
                r#"{{"schema_version":"seam-event.v1","event_id":"a1","seq":4,"kind":"AUDIT_ENTRY",
                   "prev_checksum":"","audit_entry":{{"action":"execute.scope_deny",
                   "subject":"{subject}","reason":"{reason}"{actor}}}}}"#
            ))
            .expect("parse audit entry")
        };
        let base = entry("agent-1", "scope", None);
        assert_ne!(base.bytes, entry("agent-2", "scope", None).bytes, "subject");
        assert_ne!(base.bytes, entry("agent-1", "other", None).bytes, "reason");
        assert_ne!(
            base.bytes,
            entry("agent-1", "scope", Some("op@x")).bytes,
            "actor"
        );
        // And byte-identical redeliveries still collapse.
        assert_eq!(base.bytes, entry("agent-1", "scope", None).bytes);
    }
}
