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
//! The last two have their envelope classification bound to the label the spec fixes for the kind
//! ([`fixed_classification`]).
//!
//! # Provenance — from the spec (D-035; D-043 retired by D-044)
//!
//! Like the rest of this crate, this module is written from `docs/` (D-035). The domain table, the
//! action→classification map, the three preimage framings and the two fixed kind labels are all in
//! `docs/seam-event.v1.md` §"(b′) preimages: the closed entry tables" (vendored @ `b4d1366`,
//! seam-runtime#1699, which closed #1561). Until that re-pin they were transcribed from the runtime's own
//! code under the D-043 carve-out. The spec's tables match that transcription row for row, so nothing
//! here changed except the source it cites, and `tests::the_tables_are_the_vendored_spec_tables` now pins
//! this module to the spec text itself. They are still proven against runtime-produced vectors
//! (`tests/goldens/entry_domains.jsonl`, the four runtime goldens and the four evidence bundles).
//!
//! The three readings D-043 recorded as "code over spec" are now the spec's own text:
//!
//! * `context_recalled`'s `actor` is **absent, never `""`**, so it contributes no actor frame;
//!   `Some("")` would append a four-zero-byte frame and digest differently.
//! * An absent `session_id` frames as `""` ("absent ≡ `\"\"`").
//! * The classification is an exact, case-sensitive comparison of the envelope label.
//!
//! Any other chained kind reads as [`Body::Uncovered`].

use sha2::{Digest, Sha256};

use crate::wire::{Attestation, AuditEntry, Cert, Event};

/// The domain management entries are digested under: every management action, the tenant-move writers
/// and the system partition's config actions. Spec: `docs/seam-event.v1.md` §"(b′) preimages: the closed entry tables".
pub(crate) const MANAGEMENT_DOMAIN: &str = "seam.audit.management.v1";

/// The management actions: the store's `AuditAction` labels minus `fact_appended` (see [`audit_domain`]).
///
/// The `seam.audit.management.v1` row of the spec's table, in its order.
const MANAGEMENT_ACTIONS: &[&str] = &[
    "session_resumed",
    "session_cancelled",
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

/// `fact_appended` chains the fact's own checksum, not an action-entry digest: the spec names it
/// **uncovered**, and recomputing it under management would fail every genuine one.
const FACT_APPENDED: &str = "fact_appended";

/// The non-management writers, each with the closed set of actions it emits: the spec table's other rows.
const DOMAINS: &[(&str, &[&str])] = &[
    (
        "seam.audit.legal-hold.v1",
        // `hold_carried` (Flows W4 R4c-b §2.2, runtime 0.115.0): `subject` cites the tenant-chain
        // `hold_placed` entry. Mirrors seam-runtime `crates/seam-verify/src/entry.rs`.
        &["hold_placed", "hold_released", "hold_carried"],
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
/// digest, and each action is written with exactly one reason variant, so the action fixes it: the spec
/// table's envelope `classification` column.
fn audit_classification(action: &str) -> &'static str {
    match action {
        "execute.scope_deny" | "boundary.data_flagged" => "Confidential",
        "gdpr_erasure" => "Pii",
        _ => "Internal",
    }
}

/// The envelope label the spec fixes for each non-`AUDIT_ENTRY` kind recomputed here, outside its
/// digest: "Envelope `classification` is `Internal`" (`CHAIN_HEAD_ATTESTATION`) and "… is `Pii`"
/// (`ERASURE_CERTIFICATE`), both in `docs/seam-event.v1.md` §"(b′) preimages: the closed entry tables".
///
/// D-043's transcription carried the store's whole eleven-row per-kind contract; only these two rows
/// were ever read, and only these two are in the spec, so only these two remain (D-044).
const FIXED_KIND_CLASSIFICATION: &[(&str, &str)] = &[
    ("CHAIN_HEAD_ATTESTATION", "Internal"),
    ("ERASURE_CERTIFICATE", "Pii"),
];

/// The label the spec fixes for `kind`, outside its digest; `""` (which no envelope carries
/// legitimately) for any other kind.
fn fixed_classification(kind: &str) -> &'static str {
    FIXED_KIND_CLASSIFICATION
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
/// The framing, per the spec's `AUDIT_ENTRY` preimage: seven frames (domain, action, envelope tenant, envelope namespace, envelope
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
/// The framing, per the spec's `CHAIN_HEAD_ATTESTATION` preimage: every part framed — the domain
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
/// The framing, per the spec's `ERASURE_CERTIFICATE` preimage: every part framed — the domain,
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
            17,
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

    /// Only the two kinds recomputed here have a fixed label; any other kind reads `""`, which no envelope
    /// label matches.
    #[test]
    fn only_the_recomputed_kinds_have_a_fixed_label() {
        assert_eq!(FIXED_KIND_CLASSIFICATION.len(), 2);
        for kind in [
            "AUDIT_ENTRY",
            "DECISION_SEALED",
            "BUDGET_BREACH",
            "NO_SUCH_KIND",
        ] {
            assert_eq!(fixed_classification(kind), "", "{kind}");
        }
    }

    /// The vendored spec's (b′) table — every `| domain | actions | classification |` row — is exactly
    /// what this module digests under and binds: no action the spec lists is missing here, none is added,
    /// and each one's domain and envelope label agree. This is what makes "written from the spec" a
    /// checked claim rather than a comment (D-044); the vectors separately prove it against the runtime.
    #[test]
    fn the_tables_are_the_vendored_spec_tables() {
        let spec = include_str!("../docs/seam-event.v1.md");
        let section = spec
            .split_once("##### (b′) preimages: the closed entry tables")
            .expect("the vendored spec carries the (b′) preimage section")
            .1;
        let ticked = |s: &str| -> Vec<String> {
            s.split('`').skip(1).step_by(2).map(str::to_owned).collect()
        };
        let mut from_spec = Vec::new();
        for line in section.lines().filter(|l| l.starts_with("| `seam.audit.")) {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            let domain = ticked(cells[1]).remove(0);
            let label = ticked(cells[3]).remove(0);
            for action in ticked(cells[2]) {
                from_spec.push((action, domain.clone(), label.clone()));
            }
        }
        assert!(!from_spec.is_empty(), "the spec table parsed to zero rows");
        let mut ours: Vec<(String, String, String)> = MANAGEMENT_ACTIONS
            .iter()
            .map(|a| (a.to_string(), MANAGEMENT_DOMAIN.to_owned()))
            .chain(
                DOMAINS
                    .iter()
                    .flat_map(|(d, acts)| acts.iter().map(move |a| (a.to_string(), d.to_string()))),
            )
            .map(|(a, d)| {
                let label = audit_classification(&a).to_owned();
                (a, d, label)
            })
            .collect();
        from_spec.sort();
        ours.sort();
        assert_eq!(ours, from_spec);
        for (action, domain, _) in &from_spec {
            assert_eq!(audit_domain(action), Some(domain.as_str()), "{action}");
        }
        assert_eq!(audit_domain(FACT_APPENDED), None);
        assert!(section.contains("Envelope `classification` is `Internal`"));
        assert!(section.contains("Envelope `classification` is `Pii`"));
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
