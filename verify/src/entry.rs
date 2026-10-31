//! (b′) — recompute the digest of every chained entry body that is not a sealed decision.
//!
//! `chain` links STORED digests: a chained entry whose fields were rewritten, with its digest left as it
//! was, still links. Under `--issuer` the signed head pins those digests, so recomputing each one from the
//! event's own fields turns a field rewrite into a hard failure (`ENTRY REWRITE`). Spec: (b′) in
//! `docs/seam-event.v1.md`.
//!
//! # Provenance — a scoped exception to the clean-room rule (D-043)
//!
//! Everything else in this crate is written from `docs/` alone (D-035). This module is not, because the
//! vendored spec does not carry what it needs: (b′) names the `AUDIT_ENTRY` domains by short name and
//! delegates "the closed table" to the runtime's private `seam-verify/src/entry.rs`, and it spells neither
//! the action-entry framing nor the action→classification map. So the domain table, the classification
//! map and the preimage framing below are **transcribed** from seam-runtime
//! `crates/seam-verify/src/entry.rs` @ `37576658` (which mirrors the store's `ActionEntry::new` and
//! `audit_system_action`), and are proven against runtime-produced vectors
//! (`tests/goldens/entry_domains.jsonl`), not against a second transcription. The spec fix is
//! seam-runtime#1561. The exception expires when the vendored spec carries the tables:
//! `tests/entry_recompute.rs` holds a tripwire that goes red the moment it does, so this module is then
//! re-derived from the spec.
//!
//! Where the code and the spec text disagree, this module hashes per the code, and each case is recorded
//! under D-043:
//!
//! * `context_recalled`'s `actor` is **absent** (the writer passes `None`), so it contributes no actor
//!   frame. The spec calls it "empty"; `Some("")` would append a four-zero-byte frame and digest
//!   differently.
//! * An absent `session_id` and `""` frame identically (`unwrap_or("")`); the spec is silent.
//! * The classification is an exact, case-sensitive comparison of the envelope label.
//!
//! Only `AUDIT_ENTRY` is recomputed here. `CHAIN_HEAD_ATTESTATION` and `ERASURE_CERTIFICATE` read as
//! [`Body::Uncovered`] until their preimages land (plan `verify-a4-parity.md`, Phase 3).

use sha2::{Digest, Sha256};

use crate::wire::{AuditEntry, Event};

/// The domain management entries are digested under: every management action, the tenant-move writers
/// and the system partition's config actions.
///
/// Transcribed from seam-runtime `entry.rs` @ `37576658` (D-043; spec fix seam-runtime#1561).
pub(crate) const MANAGEMENT_DOMAIN: &str = "seam.audit.management.v1";

/// The management actions: the store's `AuditAction` labels minus `fact_appended` (see [`audit_domain`]).
///
/// Transcribed from seam-runtime `seam-store/src/lib.rs` `audit_action_enum!` @ `37576658`, which
/// `entry.rs` reads as `AuditAction::ALL` (D-043; spec fix seam-runtime#1561).
const MANAGEMENT_ACTIONS: &[&str] = &[
    "session_resumed",
    "party_registered",
    "party_removed",
    "cross_namespace_grant_placed",
    "cross_namespace_grant_revoked",
    "tenant_enrolled",
    "tenant_revoked",
    "config_snapshot_installed",
    "config_section_removed",
    "events_redriven",
    "erasure_previewed",
    "subject_commitments_recomputed",
    "subject_commitment_recompute_refused",
    "subject_commitment_tombstoned",
    "tenant_move_out",
    "tenant_move_in",
];

/// `fact_appended` chains the fact's own checksum, not an action-entry digest, and has no production
/// writer: recomputing it under management would fail every genuine one, so it is uncovered.
const FACT_APPENDED: &str = "fact_appended";

/// The non-management writers, each with the closed set of actions it emits.
///
/// Transcribed from seam-runtime `entry.rs` @ `37576658` (D-043; spec fix seam-runtime#1561).
const DOMAINS: &[(&str, &[&str])] = &[
    (
        "seam.audit.legal-hold.v1",
        &["hold_placed", "hold_released"],
    ),
    ("seam.audit.archive-evict.v1", &["ciphertext_evicted"]),
    ("seam.audit.boundary.v1", &["boundary.data_flagged"]),
    (
        "seam.audit.denial.v1",
        &["admit.compat_reject", "execute.scope_deny"],
    ),
    ("seam.audit.purge.v1", &["crypto_shred_purge"]),
    (
        "seam.audit.erasure.v1",
        &["gdpr_erasure", "tenant_kek_shred"],
    ),
    ("seam.audit.context-recall.v1", &["context_recalled"]),
];

/// The domain a chained `AUDIT_ENTRY` with `action` is digested under; `None` for `fact_appended` and
/// for an action this build does not know (a newer producer), which is reported uncovered rather than
/// guessed.
pub(crate) fn audit_domain(action: &str) -> Option<&'static str> {
    if action == FACT_APPENDED {
        return None;
    }
    if MANAGEMENT_ACTIONS.contains(&action) {
        return Some(MANAGEMENT_DOMAIN);
    }
    DOMAINS
        .iter()
        .find(|(_, actions)| actions.contains(&action))
        .map(|(domain, _)| *domain)
}

/// The envelope classification the store stamps on an `AUDIT_ENTRY` with `action`. It is outside the
/// digest, and each action is written with exactly one reason variant, so the action fixes it.
///
/// Transcribed from seam-runtime `entry.rs` @ `37576658`, derived there from the store's
/// `AuditReason::classification` (D-043; spec fix seam-runtime#1561).
fn audit_classification(action: &str) -> &'static str {
    match action {
        "execute.scope_deny" | "boundary.data_flagged" => "Confidential",
        "gdpr_erasure" => "Pii",
        _ => "Internal",
    }
}

/// Append `x` as one frame: `u32le(len) ‖ x`.
fn frame(h: &mut Sha256, x: &[u8]) {
    h.update((x.len() as u32).to_le_bytes());
    h.update(x);
}

/// `e`'s `AUDIT_ENTRY` digest under `domain`, from the event's own fields.
///
/// The framing, transcribed from seam-runtime `entry.rs` @ `37576658` (D-043; spec fix
/// seam-runtime#1561): seven frames (domain, action, envelope tenant, envelope namespace, envelope
/// `session_id` or `""`, subject, reason), then the envelope `occurred_at` as a raw, **unframed**
/// `u64le`, then a frame for the actor **only when there is one** — `Some("")` appends a zero-length
/// frame, `None` appends nothing.
pub(crate) fn audit_entry_digest(e: &Event, a: &AuditEntry, domain: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in [
        domain,
        a.action.as_str(),
        e.tenant.as_str(),
        e.namespace.as_str(),
        e.session_id.as_deref().unwrap_or(""),
        a.subject.as_str(),
        a.reason.as_str(),
    ] {
        frame(&mut h, part.as_bytes());
    }
    h.update(e.occurred_at.to_le_bytes());
    if let Some(actor) = a.actor.as_deref() {
        frame(&mut h, actor.as_bytes());
    }
    h.finalize().into()
}

/// What recomputing one chained, non-`DECISION_SEALED` link found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Body {
    /// Its fields produce the digest the chain links.
    Recomputed,
    /// Its fields, or its classification, do not match: rewritten after it was chained. Names what.
    Rewritten(&'static str),
    /// This build has no preimage for it (an unknown or uncovered action, or a kind not recomputed
    /// here). Counted in `IssuerReport::uncovered`; never a pass.
    Uncovered,
}

/// Recompute `e`'s chained digest. `e` is a chain link whose kind/payload pair `check_kind_payload`
/// has already bound, so the `AUDIT_ENTRY` arm reads its own payload.
pub(crate) fn recompute(e: &Event) -> Body {
    let Some(stored) = e.digest.as_deref() else {
        return Body::Uncovered;
    };
    if e.kind != "AUDIT_ENTRY" {
        return Body::Uncovered;
    }
    // Impossible after the kind/payload binding; counted uncovered rather than passed if it appears.
    let Some(a) = e.audit.as_ref() else {
        return Body::Uncovered;
    };
    let Some(domain) = audit_domain(&a.action) else {
        return Body::Uncovered;
    };
    // Checked before hashing, as the runtime does: a relabel is named as such, not as a field rewrite.
    if e.classification != audit_classification(&a.action) {
        return Body::Rewritten("AUDIT_ENTRY's classification");
    }
    if audit_entry_digest(e, a, domain).as_slice() == stored {
        Body::Recomputed
    } else {
        Body::Rewritten("AUDIT_ENTRY")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One action, one domain: a label shared by two writers would make the table pick one of them and
    /// fail every entry the other wrote. Mirrors seam-runtime `entry.rs`'s `every_action_maps_to_one_domain`.
    #[test]
    fn every_action_maps_to_one_domain() {
        let mut all: Vec<&str> = MANAGEMENT_ACTIONS.to_vec();
        for (_, actions) in DOMAINS {
            all.extend(actions.iter());
        }
        let n = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), n, "an action label appears under two domains");
        assert!(!all.contains(&FACT_APPENDED), "fact_appended has no domain");
        assert_eq!(
            MANAGEMENT_ACTIONS.len(),
            16,
            "AuditAction::ALL minus fact_appended"
        );
        for (domain, actions) in DOMAINS {
            for action in *actions {
                assert_eq!(audit_domain(action), Some(*domain), "{action}");
            }
        }
        for action in MANAGEMENT_ACTIONS {
            assert_eq!(audit_domain(action), Some(MANAGEMENT_DOMAIN), "{action}");
        }
        assert_eq!(audit_domain("no_such_action"), None);
        assert_eq!(audit_domain("tenant_move_in"), Some(MANAGEMENT_DOMAIN));
        assert_eq!(audit_domain("fact_appended"), None);
    }

    #[test]
    fn the_classification_map_matches_the_runtime_table() {
        assert_eq!(audit_classification("execute.scope_deny"), "Confidential");
        assert_eq!(
            audit_classification("boundary.data_flagged"),
            "Confidential"
        );
        assert_eq!(audit_classification("gdpr_erasure"), "Pii");
        assert_eq!(audit_classification("hold_placed"), "Internal");
    }
}
