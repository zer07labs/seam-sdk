//! Shared test helper: an **honest** v4 `DECISION_SEALED` payload and its record digest, built from the
//! spec (`docs/seam-event.v1.md` §Record digest) — never from `src/verify.rs`.
//!
//! It exists because of the kind/payload binding (spec §Ordering & integrity, "payload binds to kind": "a
//! known kind carries it"). The anchoring, truncation, multi-tenant and bundle suites used to chain
//! payload-less `DECISION_SEALED` links with an arbitrary digest; that is now refused in every mode, and
//! under `--issuer` a seal that does carry a payload is recomputed. So a seal that is orthogonal to what a
//! test proves still has to be a real one: this payload, chained under the digest returned here.
//!
//! Each suite pulls it in with `mod support;`, so any one of them uses only part of it.
#![allow(dead_code)]

use base64::Engine;
use sha2::{Digest, Sha256};

fn b64e(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn frame(pre: &mut Vec<u8>, x: &[u8]) {
    pre.extend_from_slice(&(x.len() as u32).to_le_bytes());
    pre.extend_from_slice(x);
}

fn sha(s: &str) -> Vec<u8> {
    Sha256::digest(s.as_bytes()).to_vec()
}

/// One honest v4 record for `decision_id` in `tenant`: the payload object, and the
/// `seam.audit.record-digest.v4` digest a chain link over it carries in tag 19.
pub fn v4_seal(decision_id: &str, tenant: &str) -> (serde_json::Value, Vec<u8>) {
    let ciphertext_digest = sha(&format!("ciphertext:{decision_id}"));
    let context_digest = sha("context");
    let participation_digest = sha("participation");
    let participants_digest = sha("participants");
    let trust_basis_commitment = format!("hmac-sha256:k1:{}", "cd".repeat(32));
    let (namespace, outcome, sealed_at, classification, auth_method) = (
        "fraud",
        "Resolved",
        1_700_000_000_000u64,
        "Internal",
        "aitp-pinned-handshake",
    );

    // frame(x) = le32(len) ‖ x; opt(None) = 0x00. mode/policy_version/supersedes/policy_rules_digest
    // are all absent here, so each is the single 0x00 byte.
    let mut pre: Vec<u8> = Vec::new();
    frame(&mut pre, b"seam.audit.record-digest.v4");
    frame(&mut pre, decision_id.as_bytes());
    frame(&mut pre, tenant.as_bytes());
    frame(&mut pre, namespace.as_bytes());
    frame(&mut pre, &ciphertext_digest);
    frame(&mut pre, &sealed_at.to_le_bytes());
    frame(&mut pre, outcome.as_bytes());
    pre.extend_from_slice(&[0x00, 0x00, 0x00]); // opt(mode), opt(policy_version), opt(supersedes)
    frame(&mut pre, &context_digest);
    frame(&mut pre, &participation_digest);
    pre.push(0x00); // opt(policy_rules_digest)
    frame(&mut pre, classification.as_bytes());
    frame(&mut pre, &participants_digest);
    frame(&mut pre, trust_basis_commitment.as_bytes());
    frame(&mut pre, auth_method.as_bytes());
    frame(&mut pre, &4u32.to_le_bytes());
    let digest = Sha256::digest(&pre).to_vec();

    let payload = serde_json::json!({
        "decision_id": decision_id,
        "tenant": tenant,
        "namespace": namespace,
        "outcome": outcome,
        "sealed_at": sealed_at,
        "schema_version": 4,
        "ciphertext_digest": b64e(&ciphertext_digest),
        "context_digest": b64e(&context_digest),
        "participation_digest": b64e(&participation_digest),
        "classification": classification,
        "participants_digest": b64e(&participants_digest),
        "trust_basis_commitment": trust_basis_commitment,
        "auth_method": auth_method,
    });
    (payload, digest)
}

/// The `AUDIT_ENTRY` digest of a `seam.audit.management.v1` entry, for a synthetic chained entry whose
/// content is orthogonal to what a test proves. Under `--issuer` every chained `AUDIT_ENTRY` recomputes
/// (spec (b′)), so an arbitrary digest is now an `ENTRY REWRITE`. The framing is the D-043 transcription
/// (`src/entry.rs`); the runtime vectors in `tests/entry_recompute.rs` are what prove it, not this.
pub fn management_entry_digest(
    action: &str,
    tenant: &str,
    namespace: &str,
    subject: &str,
    reason: &str,
    occurred_at: u64,
) -> Vec<u8> {
    let mut pre = Vec::new();
    for part in [
        "seam.audit.management.v1",
        action,
        tenant,
        namespace,
        "",
        subject,
        reason,
    ] {
        frame(&mut pre, part.as_bytes());
    }
    pre.extend_from_slice(&occurred_at.to_le_bytes());
    Sha256::digest(&pre).to_vec()
}
