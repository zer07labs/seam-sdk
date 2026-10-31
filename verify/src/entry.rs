//! (b′) — recompute the digest of every chained entry body that is not a sealed decision.
//!
//! `chain` links STORED digests: a chained entry whose fields were rewritten, with its digest left as it
//! was, still links. Under `--issuer` the signed head pins those digests, so recomputing each one from the
//! event's own fields turns a field rewrite into a hard failure (`ENTRY REWRITE`). Spec: (b′) in
//! `docs/seam-event.v1.md`. Three kinds are recomputed:
//!
//! * `AUDIT_ENTRY`, under the domain its action selects ([`audit_domain`]), with its envelope
//!   classification bound to the action;
//! * `CHAIN_HEAD_ATTESTATION`, under `seam.audit.chain-attest-entry.v1` ([`chain_attest_digest`]);
//! * `ERASURE_CERTIFICATE`, under `seam.audit.erasure-cert.v2` ([`erasure_cert_digest`]).
//!
//! The last two have their envelope classification bound to the label the store's emitter fixes for the
//! kind ([`KIND_CLASSIFICATION_CONTRACT`]).
//!
//! # Provenance — a scoped exception to the clean-room rule (D-043)
//!
//! Everything else in this crate is written from `docs/` alone (D-035). This module is not, because the
//! vendored spec does not carry what it needs: (b′) names the `AUDIT_ENTRY` domains by short name and
//! delegates "the closed table" to the runtime's private `seam-verify/src/entry.rs`, and it spells neither
//! the action-entry framing nor the action→classification map. It names the attestation and certificate
//! entry domains but spells neither framing, and the per-kind classification contract lives only in the
//! store's code. So the domain table, the classification map, the three preimage framings and the
//! per-kind contract below are **transcribed** from seam-runtime `crates/seam-verify/src/entry.rs` @
//! `37576658` (which mirrors the store's `ActionEntry::new`, `audit_system_action`,
//! `chain_attest_entry_digest` and `erasure_cert_entry_digest`) and from `crates/seam-store/src/event.rs`
//! `KIND_CLASSIFICATION_CONTRACT` @ `37576658`. They are proven against runtime-produced vectors
//! (`tests/goldens/entry_domains.jsonl`, the four runtime goldens and the four evidence bundles), not
//! against a second transcription. The spec fix is seam-runtime#1561. The exception expires when the
//! vendored spec carries the tables: `tests/entry_recompute.rs` holds a tripwire that goes red the moment
//! it does, so this module is then re-derived from the spec.
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
//! Any other chained kind reads as [`Body::Uncovered`].

use sha2::{Digest, Sha256};

use crate::wire::{Attestation, AuditEntry, Cert, Event};

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

/// The per-kind classification contract: `"varies"` means the emitter lets the label vary; a concrete
/// label means the emitter FIXES it, outside the digest. Only the two fixed rows of the kinds recomputed
/// here are read ([`fixed_classification`]); the rest are carried so the table stays a whole
/// transcription, comparable row for row with its source.
///
/// Transcribed from seam-runtime `seam-store/src/event.rs` `KIND_CLASSIFICATION_CONTRACT` @ `37576658`,
/// which `entry.rs` reads (D-043; spec fix seam-runtime#1561).
const KIND_CLASSIFICATION_CONTRACT: &[(&str, &str)] = &[
    ("DECISION_SEALED", "varies"),
    ("AUDIT_ENTRY", "varies"),
    ("LEARNING_DECISION", "varies"),
    ("LEARNING_OUTCOME", "varies"),
    ("BUDGET_BREACH", "Internal"),
    ("ERASURE_CERTIFICATE", "Pii"),
    ("CHAIN_HEAD_ATTESTATION", "Internal"),
    ("SESSION_LIFECYCLE", "Internal"),
    ("AUTHORIZE_EVALUATED", "Internal"),
    ("POLICY_DENIED", "Internal"),
    ("EVENT_REDRIVEN", "varies"),
];

/// The label the store's emitter fixes for `kind`, outside its digest; `""` (which no envelope carries
/// legitimately) for a kind with no row.
///
/// Transcribed from seam-runtime `entry.rs` @ `37576658` (D-043; spec fix seam-runtime#1561).
fn fixed_classification(kind: &str) -> &'static str {
    KIND_CLASSIFICATION_CONTRACT
        .iter()
        .find(|(k, _)| *k == kind)
        .map_or("", |(_, label)| *label)
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

/// SHA-256 over `parts`, each one framed.
fn framed(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        frame(&mut h, part);
    }
    h.finalize().into()
}

/// The chained digest of a `CHAIN_HEAD_ATTESTATION`.
///
/// The framing, transcribed from seam-runtime `entry.rs` @ `37576658`, which mirrors the store's
/// `chain_attest_entry_digest` (D-043; spec fix seam-runtime#1561): every part framed — the domain
/// `seam.audit.chain-attest-entry.v1`, `u64le(attested_len)`, `attested_head`, `u64le(attested_at)`,
/// `u32le(digest_schema)`, `issuer_aid`, `signature`. The payload `tenant` is **not** in it: the v2
/// signature binds the tenant, and the signature is in here.
pub(crate) fn chain_attest_digest(a: &Attestation) -> [u8; 32] {
    framed(&[
        b"seam.audit.chain-attest-entry.v1",
        &a.attested_len.to_le_bytes(),
        &a.attested_head,
        &a.attested_at.to_le_bytes(),
        &a.digest_schema.to_le_bytes(),
        a.issuer_aid.as_bytes(),
        &a.signature,
    ])
}

/// The chained digest of an `ERASURE_CERTIFICATE`, under `seam.audit.erasure-cert.v2` only.
///
/// The framing, transcribed from seam-runtime `entry.rs` @ `37576658`, which mirrors the store's
/// `erasure_cert_entry_digest` (D-043; spec fix seam-runtime#1561): every part framed — the domain,
/// `subject`, `u32le(|erased|)`, each erased id, `u32le(|held|)`, each held id, `u64le(erased_at)`,
/// `chain_head`, `issuer_aid`, `signature`. The counts are what v2 adds: without them an id moved from
/// `erased` to `held` frames identically. v1 predates every deployment, so there is no fallback — a
/// certificate that does not recompute under v2 is a rewrite, never an "older format" (spec (b′)).
pub(crate) fn erasure_cert_digest(c: &Cert) -> [u8; 32] {
    let erased_n = (c.erased.len() as u32).to_le_bytes();
    let held_n = (c.held.len() as u32).to_le_bytes();
    let erased_at = c.erased_at.to_le_bytes();
    let mut parts: Vec<&[u8]> = vec![
        b"seam.audit.erasure-cert.v2",
        c.subject.as_bytes(),
        &erased_n,
    ];
    parts.extend(c.erased.iter().map(|id| id.as_bytes()));
    parts.push(&held_n);
    parts.extend(c.held.iter().map(|id| id.as_bytes()));
    parts.extend([
        &erased_at[..],
        &c.chain_head,
        c.issuer_aid.as_bytes(),
        &c.signature,
    ]);
    framed(&parts)
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
/// has already bound, so each arm reads its own kind's payload. The classification is checked before
/// hashing, as the runtime does: a relabel is named as such, not as a field rewrite.
pub(crate) fn recompute(e: &Event) -> Body {
    let Some(stored) = e.digest.as_deref() else {
        return Body::Uncovered;
    };
    // A payload missing from its own kind is impossible after the kind/payload binding; it is counted
    // uncovered rather than passed if it appears.
    let (what, digest) = match e.kind.as_str() {
        "AUDIT_ENTRY" => {
            let Some(a) = e.audit.as_ref() else {
                return Body::Uncovered;
            };
            let Some(domain) = audit_domain(&a.action) else {
                return Body::Uncovered;
            };
            if e.classification != audit_classification(&a.action) {
                return Body::Rewritten("AUDIT_ENTRY's classification");
            }
            ("AUDIT_ENTRY", audit_entry_digest(e, a, domain))
        }
        "CHAIN_HEAD_ATTESTATION" => {
            let Some(a) = e.attestation.as_ref() else {
                return Body::Uncovered;
            };
            if e.classification != fixed_classification("CHAIN_HEAD_ATTESTATION") {
                return Body::Rewritten("CHAIN_HEAD_ATTESTATION's classification");
            }
            ("CHAIN_HEAD_ATTESTATION", chain_attest_digest(a))
        }
        "ERASURE_CERTIFICATE" => {
            let Some(c) = e.cert.as_ref() else {
                return Body::Uncovered;
            };
            if e.classification != fixed_classification("ERASURE_CERTIFICATE") {
                return Body::Rewritten("ERASURE_CERTIFICATE's classification");
            }
            ("ERASURE_CERTIFICATE", erasure_cert_digest(c))
        }
        _ => return Body::Uncovered,
    };
    if digest.as_slice() == stored {
        Body::Recomputed
    } else {
        Body::Rewritten(what)
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

    fn rows(rel: &str) -> Vec<Event> {
        let path = format!("{}/{rel}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{path}: {e}"))
            .lines()
            .map(|l| Event::parse(l).expect("parses"))
            .collect()
    }

    fn row(rel: &str, seq: u64) -> Event {
        rows(rel)
            .into_iter()
            .find(|e| e.seq == seq)
            .expect("that seq")
    }

    /// KAT: a runtime-written attestation row's wire `digest` is what [`chain_attest_digest`] computes.
    #[test]
    fn chain_attest_digest_matches_a_runtime_row() {
        let e = row("tests/goldens/entry_domains.jsonl", 22);
        let a = e
            .attestation
            .as_ref()
            .expect("seq 22 is acme's attestation");
        assert_eq!(
            chain_attest_digest(a).as_slice(),
            e.digest.as_deref().unwrap()
        );
    }

    /// KAT: the runtime-written certificate row's wire `digest` is what [`erasure_cert_digest`] computes.
    #[test]
    fn erasure_cert_digest_matches_the_runtime_row() {
        let e = row("tests/goldens/entry_domains.jsonl", 14);
        let c = e.cert.as_ref().expect("seq 14 is the certificate");
        assert_eq!(
            erasure_cert_digest(c).as_slice(),
            e.digest.as_deref().unwrap()
        );
    }

    /// Every chained attestation and certificate in every committed stream recomputes: the Phase 0
    /// vectors, the four runtime goldens and the four evidence bundles.
    #[test]
    fn every_attestation_and_certificate_in_the_committed_streams_recomputes() {
        let mut total = 0;
        for rel in [
            "tests/goldens/entry_domains.jsonl",
            "tests/goldens/entry_domains.window.jsonl",
            "tests/goldens/attested_chain.jsonl",
            "tests/goldens/fabricated_chain.jsonl",
            "tests/goldens/payload_rewrite.jsonl",
            "tests/goldens/two_tenant_chain.jsonl",
            "fixtures/evidence-bundle/full/events.jsonl",
            "fixtures/evidence-bundle/minimal/events.jsonl",
            "fixtures/evidence-bundle/other-issuer/events.jsonl",
            "fixtures/evidence-bundle/shredded/events.jsonl",
        ] {
            for e in rows(rel) {
                if e.is_link()
                    && matches!(
                        e.kind.as_str(),
                        "CHAIN_HEAD_ATTESTATION" | "ERASURE_CERTIFICATE"
                    )
                {
                    assert_eq!(recompute(&e), Body::Recomputed, "{rel} seq {}", e.seq);
                    total += 1;
                }
            }
        }
        // 3 + 2 + 1 + 0 + 1 + 2 attestations and 1 certificate in the goldens, 2 per bundle.
        assert_eq!(total, 18);
    }

    /// The per-kind contract fixes `CHAIN_HEAD_ATTESTATION` at `Internal`; the runtime row carries it, and
    /// any other label (case included) is a rewrite named as a relabel, not a field rewrite.
    #[test]
    fn the_classification_contract_binds_chain_head_attestation() {
        assert_eq!(fixed_classification("CHAIN_HEAD_ATTESTATION"), "Internal");
        let mut e = row("tests/goldens/entry_domains.jsonl", 22);
        assert_eq!(e.classification, "Internal");
        for label in ["Public", "INTERNAL", ""] {
            e.classification = label.into();
            assert_eq!(
                recompute(&e),
                Body::Rewritten("CHAIN_HEAD_ATTESTATION's classification"),
                "{label:?}"
            );
        }
    }

    /// The per-kind contract fixes `ERASURE_CERTIFICATE` at `Pii`.
    #[test]
    fn the_classification_contract_binds_erasure_certificate() {
        assert_eq!(fixed_classification("ERASURE_CERTIFICATE"), "Pii");
        let mut e = row("tests/goldens/entry_domains.jsonl", 14);
        assert_eq!(e.classification, "Pii");
        for label in ["Internal", "PII", ""] {
            e.classification = label.into();
            assert_eq!(
                recompute(&e),
                Body::Rewritten("ERASURE_CERTIFICATE's classification"),
                "{label:?}"
            );
        }
    }

    /// The transcribed contract, row for row with the store's `KIND_CLASSIFICATION_CONTRACT`; a kind with
    /// no row reads `""`, which no envelope label matches.
    #[test]
    fn the_kind_classification_contract_matches_the_runtime_table() {
        assert_eq!(KIND_CLASSIFICATION_CONTRACT.len(), 11);
        assert_eq!(fixed_classification("AUDIT_ENTRY"), "varies");
        assert_eq!(fixed_classification("DECISION_SEALED"), "varies");
        assert_eq!(fixed_classification("BUDGET_BREACH"), "Internal");
        assert_eq!(fixed_classification("NO_SUCH_KIND"), "");
    }

    /// The certificate's lists are ordered and counted: reordering `erased`, or moving an id across to
    /// `held`, changes the digest (the second is the collision v2's counts exist to stop). The Phase 0
    /// certificate erases one id, so reordering is pinned here rather than on the stream.
    #[test]
    fn erased_order_and_list_membership_are_in_the_certificate_digest() {
        let mut c = row("tests/goldens/entry_domains.jsonl", 14).cert.unwrap();
        c.erased = vec!["d1".into(), "d3".into()];
        c.held = vec![];
        let base = erasure_cert_digest(&c);
        c.erased.reverse();
        assert_ne!(erasure_cert_digest(&c), base, "reordered erased");
        c.erased = vec!["d1".into()];
        c.held = vec!["d3".into()];
        assert_ne!(erasure_cert_digest(&c), base, "an id moved to held");
    }
}
