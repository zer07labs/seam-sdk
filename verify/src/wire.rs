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

#[derive(Clone, PartialEq, Message)]
pub struct AuditEntryPb {
    #[prost(string, tag = "1")]
    pub action: String,
    #[prost(string, tag = "2")]
    pub subject: String,
    #[prost(string, tag = "3")]
    pub reason: String,
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
    pub kind: String,
    pub prev_checksum: Vec<u8>,
    pub digest: Option<Vec<u8>>,
    pub checksum: Option<Vec<u8>>,
    pub audit_action: Option<String>,
    pub cert: Option<Cert>,
    /// The `CHAIN_HEAD_ATTESTATION` payload, when this event is one. `None` otherwise.
    pub attestation: Option<Attestation>,
    /// The `DECISION_SEALED` payload — read only for the digest-v2 recompute under `--issuer`.
    pub decision: Option<Decision>,
    /// The canonical bytes this event decoded from (or re-encodes to) — the dedup identity.
    pub bytes: Vec<u8>,
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
                })
            });
            let ev = Event {
                event_id: j.event_id,
                seq: j.seq,
                occurred_at: j.occurred_at,
                kind: j.kind,
                prev_checksum: b64(&j.prev_checksum)?,
                digest: j.digest.as_deref().map(b64).transpose()?,
                checksum: j.checksum.as_deref().map(b64).transpose()?,
                audit_action: j.audit_entry.map(|a| a.action),
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
            kind: pb.kind,
            prev_checksum: pb.prev_checksum,
            digest: pb.digest,
            checksum: pb.checksum,
            audit_action: pb.audit_entry.map(|a| a.action),
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
            }),
            audit_entry: self.audit_action.as_ref().map(|a| AuditEntryPb {
                action: a.clone(),
                ..Default::default()
            }),
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
        const ADVISORY: &[&str] = &[
            "LEARNING_DECISION",
            "LEARNING_OUTCOME",
            "BUDGET_BREACH",
            "SESSION_LIFECYCLE",
        ];
        if ADVISORY.contains(&self.kind.as_str()) {
            return true;
        }
        // The chain anchor: an AUDIT_ENTRY by kind, off-chain by design (spec §AUDIT_ENTRY).
        self.audit_action.as_deref() == Some("chain_anchor")
    }
}
