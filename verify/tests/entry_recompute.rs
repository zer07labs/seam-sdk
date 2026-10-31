//! (b′) entry recompute under `--issuer` (plan `plans/verify-a4-parity.md`, Phases 2 and 3; seam-sdk#316):
//! `AUDIT_ENTRY`, `CHAIN_HEAD_ATTESTATION` and `ERASURE_CERTIFICATE`.
//!
//! The oracle is `tests/goldens/entry_domains.jsonl`, written by seam-runtime's own code (provenance in
//! `tests/entry_vectors.rs`). Every genuine chained non-seal link in it must recompute; every mutation
//! below changes one preimage input (or the bound classification) and leaves every link untouched, so
//! plain `chain` stays green over the same bytes and only the recompute can catch it. The ordering
//! tests use the runtime's anchored window (`entry_domains.window.jsonl` + `.anchor.json`) and its
//! genuinely signed earlier attestation (`entry_domains.swapped-attestation.json`); nothing here is
//! signed by this repository.
//!
//! The domain table and framing are transcribed from the runtime under the D-043 carve-out
//! (`src/entry.rs`); [`the_vendored_spec_does_not_yet_carry_the_entry_tables`] is that carve-out's
//! tripwire.

use std::process::Command;

use seam_verify::wire::Event;
use serde_json::Value;

const VERIFIED: i32 = 0;
const FAILED: i32 = 2;

/// The AID of the `21×32` seed that signs `entry_domains.jsonl` (see `tests/entry_vectors.rs`).
const ENTRY_ISSUER: &str = "aid:pubkey:1UIH2hlJd9z0atv-wrwudbUtWopCGE_t_cAAJPDj6No";

fn stream() -> Vec<Value> {
    let path = format!(
        "{}/tests/goldens/entry_domains.jsonl",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(path)
        .expect("golden must exist")
        .lines()
        .map(|l| serde_json::from_str(l).expect("one JSON event per line"))
        .collect()
}

fn body(rows: &[Value]) -> String {
    rows.iter().map(|r| r.to_string() + "\n").collect()
}

/// The stream with `edit` applied to the row at `seq`.
fn mutated(seq: u64, edit: impl FnOnce(&mut Value)) -> Vec<Value> {
    let mut rows = stream();
    let row = rows
        .iter_mut()
        .find(|r| r["seq"] == seq)
        .expect("the stream has that seq");
    edit(row);
    rows
}

fn run(name: &str, rows: &[Value], args: &[&str]) -> (i32, String) {
    let path = std::env::temp_dir().join(format!("entry-rc-{name}-{}.jsonl", std::process::id()));
    std::fs::write(&path, body(rows)).unwrap();
    let mut a: Vec<&str> = vec!["chain", path.to_str().unwrap()];
    a.extend_from_slice(args);
    let out = Command::new(env!("CARGO_BIN_EXE_seam-verify"))
        .args(&a)
        .output()
        .expect("run seam-verify");
    let _ = std::fs::remove_file(&path);
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap(), s)
}

fn events(rows: &[Value]) -> Vec<Event> {
    rows.iter()
        .map(|r| Event::parse(&r.to_string()).expect("parses"))
        .collect()
}

/// The library path: integrity, then per-tenant authenticity.
fn authenticate(
    rows: &[Value],
) -> Result<std::collections::BTreeMap<String, seam_verify::IssuerReport>, String> {
    let evs = events(rows);
    let report = seam_verify::chain(&evs).expect("integrity holds");
    seam_verify::verify_authenticity_by_tenant(&evs, &report, &[ENTRY_ISSUER.to_owned()])
}

/// The mutation is invisible to `chain` and fatal under `--issuer`, as an `ENTRY REWRITE` of an
/// `AUDIT_ENTRY`.
fn assert_rewrite(name: &str, rows: &[Value]) {
    assert_rewrite_of(name, rows, "AUDIT_ENTRY");
}

/// The mutation is invisible to `chain` and fatal under `--issuer`, as an `ENTRY REWRITE` naming
/// `what` — and never as a signature failure, which only the attestation loop (after the recompute)
/// could report.
fn assert_rewrite_of(name: &str, rows: &[Value], what: &str) {
    let (code, out) = run(&format!("{name}-plain"), rows, &[]);
    assert_eq!(
        code, VERIFIED,
        "{name}: plain chain must stay green:\n{out}"
    );
    let (code, out) = run(name, rows, &["--issuer", ENTRY_ISSUER]);
    assert_eq!(code, FAILED, "{name}: --issuer must refuse:\n{out}");
    assert!(out.contains("ENTRY REWRITE"), "{name}:\n{out}");
    assert!(out.contains(what), "{name}:\n{out}");
    assert!(!out.contains("does not verify"), "{name}:\n{out}");
}

/// Every chained link that is not a sealed decision: what (b′) recomputes.
fn chained_non_seal_links(rows: &[Value]) -> usize {
    rows.iter()
        .filter(|r| {
            r["kind"] != "DECISION_SEALED" && r["digest"].is_string() && r["checksum"].is_string()
        })
        .count()
}

fn chained_audit_entries(rows: &[Value]) -> usize {
    rows.iter()
        .filter(|r| {
            r["kind"] == "AUDIT_ENTRY"
                && r["digest"].is_string()
                && r["checksum"].is_string()
                && r["payload"].is_null()
        })
        .count()
}

// ---- the genuine stream ---------------------------------------------------------------------------

#[test]
fn every_chained_audit_entry_recomputes() {
    let rows = stream();
    let want = chained_audit_entries(&rows);
    assert_eq!(want, 15, "the Phase 0 stream's chained AUDIT_ENTRY rows");
    let links = chained_non_seal_links(&rows);
    assert_eq!(
        links,
        want + 1 + 3,
        "plus one certificate and three attestations"
    );
    let reports = authenticate(&rows).expect("the genuine stream authenticates");
    let got: usize = reports.values().map(|r| r.entries_recomputed).sum();
    assert_eq!(got, links, "every chained, non-seal link must recompute");
    let uncovered: Vec<_> = reports.values().flat_map(|r| &r.uncovered).collect();
    assert!(
        uncovered.is_empty(),
        "no genuine link may read as uncovered: {uncovered:?}"
    );

    let (code, out) = run("genuine", &rows, &["--issuer", ENTRY_ISSUER, "--strict"]);
    assert_eq!(code, VERIFIED, "{out}");
}

/// Absent and `""` frame alike (runtime `entry.rs` `unwrap_or("")`; D-043): dropping a `""` session to
/// `null`, or omitting the key, still recomputes.
#[test]
fn an_absent_session_frames_as_empty() {
    for (name, edit) in [
        (
            "session-null",
            Box::new(|r: &mut Value| r["session_id"] = Value::Null) as Box<dyn Fn(&mut Value)>,
        ),
        (
            "session-missing",
            Box::new(|r: &mut Value| {
                r.as_object_mut().unwrap().remove("session_id");
            }),
        ),
    ] {
        let rows = mutated(6, |r| edit(r));
        let (code, out) = run(name, &rows, &["--issuer", ENTRY_ISSUER]);
        assert_eq!(code, VERIFIED, "{name}:\n{out}");
    }
}

// ---- one mutation per preimage input --------------------------------------------------------------

/// Moving an action across domains must fail: the domain is in the preimage, and the table is not a
/// pass-through. `hold_placed` (legal-hold) → `ciphertext_evicted` (archive-evict); both are `Internal`,
/// so this reaches the hash rather than the classification check.
#[test]
fn a_domain_move_is_a_rewrite() {
    assert_rewrite(
        "domain",
        &mutated(7, |r| {
            r["audit_entry"]["action"] = "ciphertext_evicted".into()
        }),
    );
}

/// Same domain (management), different action: the action label itself is in the preimage.
#[test]
fn an_action_change_is_a_rewrite() {
    assert_rewrite(
        "action",
        &mutated(6, |r| r["audit_entry"]["action"] = "party_removed".into()),
    );
}

/// The envelope tenant is in the preimage. It is also the chain's partition key, so rewriting it on the
/// wire moves the link into another tenant's chain and plain `chain` refuses first (`BROKEN CHAIN`). The
/// recompute is therefore exercised at the library level: `acme`'s own events, one with its envelope
/// tenant rewritten, against `acme`'s own unmodified window.
#[test]
fn an_envelope_tenant_change_is_a_rewrite() {
    let rows = stream();
    let evs = events(&rows);
    let report = seam_verify::chain(&evs).expect("integrity holds");
    let tc = &report.tenants["acme"];
    let mut acme: Vec<Event> = evs.into_iter().filter(|e| e.tenant == "acme").collect();
    acme.iter_mut()
        .find(|e| e.seq == 6)
        .expect("seq 6 is acme's")
        .tenant = "acmf".into();
    let err = match seam_verify::verify_authenticity_anchored(
        &acme,
        &tc.heads,
        &tc.max_schema_by_link,
        &[ENTRY_ISSUER.to_owned()],
        tc.base_len,
        &tc.heads[0],
    ) {
        Ok(_) => panic!("a rewritten envelope tenant must not recompute"),
        Err(e) => e,
    };
    assert!(err.contains("ENTRY REWRITE"), "{err}");
    assert!(err.contains("AUDIT_ENTRY"), "{err}");
    assert!(err.contains("seq 6"), "{err}");
}

#[test]
fn an_envelope_namespace_change_is_a_rewrite() {
    assert_rewrite(
        "namespace",
        &mutated(6, |r| r["namespace"] = "fraud2".into()),
    );
}

#[test]
fn a_session_change_is_a_rewrite() {
    assert_rewrite(
        "session-set",
        &mutated(6, |r| r["session_id"] = "s9".into()),
    );
    assert_rewrite(
        "session-emptied",
        &mutated(9, |r| r["session_id"] = "".into()),
    );
}

#[test]
fn a_subject_change_is_a_rewrite() {
    assert_rewrite(
        "subject",
        &mutated(6, |r| r["audit_entry"]["subject"] = "party-2".into()),
    );
}

#[test]
fn a_reason_change_is_a_rewrite() {
    assert_rewrite(
        "reason",
        &mutated(6, |r| r["audit_entry"]["reason"] = "registered!".into()),
    );
}

#[test]
fn an_occurred_at_change_is_a_rewrite() {
    assert_rewrite(
        "occurred-plus",
        &mutated(6, |r| r["occurred_at"] = 1001.into()),
    );
    assert_rewrite(
        "occurred-minus",
        &mutated(6, |r| r["occurred_at"] = 999.into()),
    );
}

#[test]
fn an_actor_change_is_a_rewrite() {
    assert_rewrite(
        "actor-dropped",
        &mutated(6, |r| r["audit_entry"]["actor"] = Value::Null),
    );
    assert_rewrite(
        "actor-changed",
        &mutated(6, |r| r["audit_entry"]["actor"] = "op@evil".into()),
    );
    assert_rewrite(
        "actor-none-to-empty",
        &mutated(10, |r| r["audit_entry"]["actor"] = "".into()),
    );
}

/// `context_recalled`'s actor is ABSENT (the writer passes `None`), so it contributes no actor frame.
/// The spec text calls it "empty"; hashing it as `Some("")` appends a four-zero-byte frame and must NOT
/// match the recorded digest. Pins the code reading against the spec text (D-043, seam-runtime#1561).
#[test]
fn context_recalled_with_an_empty_actor_does_not_recompute() {
    let rows = mutated(15, |r| {
        assert_eq!(r["audit_entry"]["action"], "context_recalled");
        assert!(r["audit_entry"]["actor"].is_null(), "recorded as absent");
        r["audit_entry"]["actor"] = "".into();
    });
    assert_rewrite("context-recalled-empty-actor", &rows);
}

// ---- the bound classification ---------------------------------------------------------------------

#[test]
fn a_relabelled_classification_is_a_rewrite() {
    for (name, seq, from, to) in [
        ("class-scope-deny", 11, "Confidential", "Internal"),
        ("class-gdpr", 13, "Pii", "Internal"),
        ("class-internal", 6, "Internal", "Public"),
    ] {
        let rows = mutated(seq, |r| {
            assert_eq!(r["classification"], from, "{name}: the recorded label");
            r["classification"] = to.into();
        });
        assert_rewrite(name, &rows);
        let (_, out) = run(name, &rows, &["--issuer", ENTRY_ISSUER]);
        assert!(
            out.contains("AUDIT_ENTRY's classification"),
            "{name}:\n{out}"
        );
    }
}

// ---- CHAIN_HEAD_ATTESTATION: one mutation per preimage field ---------------------------------------

/// `acme`'s attestation in the Phase 0 stream (genesis mode, covering).
const ATT_SEQ: u64 = 22;
/// The erasure certificate in the Phase 0 stream.
const CERT_SEQ: u64 = 14;

fn att(seq: u64, edit: impl FnOnce(&mut Value)) -> Vec<Value> {
    mutated(seq, |r| {
        assert_eq!(r["kind"], "CHAIN_HEAD_ATTESTATION");
        edit(&mut r["chain_head_attestation"]);
    })
}

/// Flip the first byte of a base64 field.
fn flip(v: &mut Value) {
    use base64::Engine;
    let e = base64::engine::general_purpose::STANDARD;
    let mut b = e.decode(v.as_str().unwrap()).unwrap();
    b[0] ^= 0x01;
    *v = e.encode(b).into();
}

#[test]
fn an_attestation_field_change_is_a_rewrite() {
    for (name, rows) in [
        (
            "att-len",
            att(ATT_SEQ, |a| {
                a["attested_len"] = (a["attested_len"].as_u64().unwrap() + 1).into()
            }),
        ),
        ("att-head", att(ATT_SEQ, |a| flip(&mut a["attested_head"]))),
        (
            "att-at",
            att(ATT_SEQ, |a| {
                a["attested_at"] = (a["attested_at"].as_u64().unwrap() + 1).into()
            }),
        ),
        (
            "att-schema",
            att(ATT_SEQ, |a| {
                a["digest_schema"] = (a["digest_schema"].as_u64().unwrap() + 1).into()
            }),
        ),
        (
            "att-issuer",
            att(ATT_SEQ, |a| {
                a["issuer_aid"] = "aid:pubkey:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw".into()
            }),
        ),
        ("att-signature", att(ATT_SEQ, |a| flip(&mut a["signature"]))),
    ] {
        assert_rewrite_of(name, &rows, "CHAIN_HEAD_ATTESTATION");
    }
}

#[test]
fn a_relabelled_attestation_classification_is_a_rewrite() {
    let rows = mutated(ATT_SEQ, |r| {
        assert_eq!(r["classification"], "Internal");
        r["classification"] = "Public".into();
    });
    assert_rewrite_of(
        "att-class",
        &rows,
        "CHAIN_HEAD_ATTESTATION's classification",
    );
}

/// Negative control: the payload `tenant` is NOT in the entry preimage (store doc on
/// `chain_attest_entry_digest`). Relabelling it alone recomputes, and is caught later by the tenant
/// agreement check or the v2 signature. Pinned so nobody "fixes" the preimage by adding the tenant.
#[test]
fn an_attestation_payload_tenant_change_is_not_an_entry_rewrite() {
    let rows = att(ATT_SEQ, |a| {
        assert_eq!(a["tenant"], "acme");
        a["tenant"] = "beta".into();
    });
    let (code, out) = run("att-tenant", &rows, &["--issuer", ENTRY_ISSUER]);
    assert_eq!(code, FAILED, "{out}");
    assert!(!out.contains("ENTRY REWRITE"), "{out}");
    assert!(
        out.contains("ATTESTATION TENANT MISMATCH") || out.contains("does not verify"),
        "{out}"
    );
}

// ---- ERASURE_CERTIFICATE: one mutation per preimage field -----------------------------------------

fn cert(edit: impl FnOnce(&mut Value)) -> Vec<Value> {
    mutated(CERT_SEQ, |r| {
        assert_eq!(r["kind"], "ERASURE_CERTIFICATE");
        let c = &mut r["erasure_certificate"];
        assert_eq!(c["erased"], serde_json::json!(["d1"]));
        assert_eq!(c["held"], serde_json::json!(["d2"]));
        edit(c);
    })
}

/// Reordering `erased` is pinned by a unit test in `src/entry.rs`: this certificate erases one id.
#[test]
fn a_certificate_field_change_is_a_rewrite() {
    for (name, rows) in [
        (
            "cert-subject",
            cert(|c| c["subject"] = "aid:pubkey:ed25519:subject-a5".into()),
        ),
        (
            "cert-erased-append",
            cert(|c| c["erased"] = serde_json::json!(["d1", "d9"])),
        ),
        (
            "cert-held-append",
            cert(|c| c["held"] = serde_json::json!(["d2", "d9"])),
        ),
        // The collision v2's counts exist to stop: an id moved from `erased` to `held`.
        (
            "cert-erased-to-held",
            cert(|c| {
                c["erased"] = serde_json::json!([]);
                c["held"] = serde_json::json!(["d1", "d2"]);
            }),
        ),
        (
            "cert-erased-at",
            cert(|c| c["erased_at"] = (c["erased_at"].as_u64().unwrap() + 1).into()),
        ),
        ("cert-chain-head", cert(|c| flip(&mut c["chain_head"]))),
        (
            "cert-issuer",
            cert(|c| c["issuer_aid"] = "aid:pubkey:cert-issuer2".into()),
        ),
        ("cert-signature", cert(|c| flip(&mut c["signature"]))),
    ] {
        assert_rewrite_of(name, &rows, "ERASURE_CERTIFICATE");
    }
}

#[test]
fn a_relabelled_certificate_classification_is_a_rewrite() {
    let rows = mutated(CERT_SEQ, |r| {
        assert_eq!(r["classification"], "Pii");
        r["classification"] = "Internal".into();
    });
    assert_rewrite_of("cert-class", &rows, "ERASURE_CERTIFICATE's classification");
}

// ---- ordering against the anchor --------------------------------------------------------------------

/// The AID of the `07×32` seed that signs the anchored window (see `tests/entry_vectors.rs`).
const WINDOW_ISSUER: &str = "aid:pubkey:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";

fn golden_path(name: &str) -> String {
    format!("{}/tests/goldens/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn window() -> Vec<Value> {
    std::fs::read_to_string(golden_path("entry_domains.window.jsonl"))
        .expect("golden must exist")
        .lines()
        .map(|l| serde_json::from_str(l).expect("one JSON event per line"))
        .collect()
}

fn run_window(name: &str, rows: &[Value]) -> (i32, String) {
    let anchor = golden_path("entry_domains.anchor.json");
    run(
        name,
        rows,
        &["--issuer", WINDOW_ISSUER, "--from-anchor", &anchor],
    )
}

/// The window's first row is A1, the anchor itself (`attested_len == base_len == 2`). Splice in the
/// runtime's genuinely signed attestation of an EARLIER head (len 1): its signature verifies and its
/// position lies below the window, so only the recompute can object. Mirrors runtime `anchored.rs`
/// `a_swapped_attestation_below_the_window_base_fails`, from its captured bytes — never re-signed.
fn swapped_below_base() -> Vec<Value> {
    let swapped: Value = serde_json::from_str(
        &std::fs::read_to_string(golden_path("entry_domains.swapped-attestation.json")).unwrap(),
    )
    .unwrap();
    let mut rows = window();
    let a = &mut rows[0]["chain_head_attestation"];
    assert_eq!(a["attested_len"], 2, "the window opens on A1");
    assert_eq!(swapped["attested_len"], 1, "an earlier head, below base");
    for k in ["attested_len", "attested_head", "signature"] {
        a[k] = swapped[k].clone();
    }
    rows
}

#[test]
fn a_swapped_attestation_below_the_window_base_is_a_rewrite() {
    let (code, out) = run_window("swapped-below", &swapped_below_base());
    assert_eq!(code, FAILED, "{out}");
    assert!(
        out.contains("ENTRY REWRITE") && out.contains("CHAIN_HEAD_ATTESTATION"),
        "{out}"
    );
    assert!(
        !out.contains("does not verify"),
        "not a signature failure:\n{out}"
    );
}

#[test]
fn a_relabelled_attestation_at_the_window_base_is_a_rewrite() {
    let mut rows = window();
    assert_eq!(rows[0]["chain_head_attestation"]["attested_len"], 2);
    rows[0]["classification"] = "Public".into();
    let (code, out) = run_window("at-base-class", &rows);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("ENTRY REWRITE"), "{out}");
    assert!(
        out.contains("CHAIN_HEAD_ATTESTATION's classification"),
        "{out}"
    );
}

#[test]
fn a_relabelled_attestation_below_the_window_base_is_a_rewrite() {
    let mut rows = swapped_below_base();
    rows[0]["classification"] = "Public".into();
    let (code, out) = run_window("below-base-class", &rows);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("ENTRY REWRITE"), "{out}");
    assert!(
        out.contains("CHAIN_HEAD_ATTESTATION's classification"),
        "{out}"
    );
}

/// An in-window (covering) attestation with `attested_at + 1` is refused as an `ENTRY REWRITE`, not as
/// the signature failure the attestation loop would report: the recompute runs first.
#[test]
fn an_in_window_attestation_rewrite_is_caught_before_its_signature() {
    let mut rows = window();
    let a = &mut rows[3]["chain_head_attestation"];
    assert_eq!(a["attested_len"], 5, "covering: above base 2");
    a["attested_at"] = (a["attested_at"].as_u64().unwrap() + 1).into();
    let (code, out) = run_window("in-window-at", &rows);
    assert_eq!(code, FAILED, "{out}");
    assert!(
        out.contains("ENTRY REWRITE") && out.contains("CHAIN_HEAD_ATTESTATION"),
        "{out}"
    );
    assert!(
        !out.contains("does not verify"),
        "not a signature failure:\n{out}"
    );
}

// ---- uncovered, and the seal arm left as it was ---------------------------------------------------

/// An action this build has no domain for is uncovered: counted, not recomputed, and (until Phase 4)
/// not refused. It is the only uncovered link: the attestations and the certificate recompute.
#[test]
fn an_unknown_action_is_uncovered() {
    let rows = mutated(6, |r| {
        r["audit_entry"]["action"] = "party_registered_v2".into()
    });
    let reports = authenticate(&rows).expect("uncovered is not yet refused");
    let audit: Vec<_> = reports
        .values()
        .flat_map(|r| &r.uncovered)
        .filter(|u| u.kind == "AUDIT_ENTRY")
        .collect();
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0].action.as_deref(), Some("party_registered_v2"));
    assert_eq!(audit[0].seq, 6);
    assert_eq!(audit[0].tenant, "acme");
    assert_eq!(
        reports.values().map(|r| r.uncovered.len()).sum::<usize>(),
        1
    );
    let got: usize = reports.values().map(|r| r.entries_recomputed).sum();
    assert_eq!(got, chained_non_seal_links(&rows) - 1);
}

/// `fact_appended` has no domain (it chains the fact's own checksum), so it is uncovered too.
#[test]
fn fact_appended_is_uncovered() {
    let rows = mutated(6, |r| r["audit_entry"]["action"] = "fact_appended".into());
    let reports = authenticate(&rows).expect("uncovered is not yet refused");
    let audit: Vec<_> = reports
        .values()
        .flat_map(|r| &r.uncovered)
        .filter(|u| u.kind == "AUDIT_ENTRY")
        .collect();
    assert_eq!(audit.len(), 1, "{audit:?}");
    assert_eq!(audit[0].action.as_deref(), Some("fact_appended"));
}

/// The `DECISION_SEALED` arm is deliberately NOT narrowed to links (D-042): an unchained seal relabelled
/// to `schema_version: 3` is refused under `--issuer`, exactly as before (b′) landed. Stricter than the
/// runtime, which skips unchained seals; pinned so a later "parity" change cannot relax it silently.
#[test]
fn an_unchained_non_v4_seal_is_still_refused() {
    let mut rows = stream();
    let mut seal = rows
        .iter()
        .find(|r| r["seq"] == 5 && r["kind"] == "DECISION_SEALED")
        .expect("seq 5 is a seal")
        .clone();
    let o = seal.as_object_mut().unwrap();
    o.remove("digest");
    o.remove("checksum");
    o.insert("seq".into(), 25.into());
    o.insert("event_id".into(), "dev/unchained#25".into());
    seal["payload"]["schema_version"] = 3.into();
    rows.push(seal);

    let (code, out) = run("unchained-v3-plain", &rows, &[]);
    assert_eq!(
        code, VERIFIED,
        "unchained history is disclosed, not refused, without --issuer:\n{out}"
    );
    let (code, out) = run("unchained-v3", &rows, &["--issuer", ENTRY_ISSUER]);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("CANNOT VERIFY"), "{out}");
}

// ---- the D-043 carve-out tripwire -----------------------------------------------------------------

/// D-043 transcribes the (b′) tables from the runtime because the vendored spec does not carry them. The
/// day it does, the carve-out must be retired and `src/entry.rs` re-derived from the spec.
#[test]
fn the_vendored_spec_does_not_yet_carry_the_entry_tables() {
    let spec = std::fs::read_to_string(format!(
        "{}/docs/seam-event.v1.md",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the vendored spec must exist");
    assert!(
        !spec.contains("seam.audit.management.v1"),
        "the vendored spec now carries the (b′) tables: retire the D-043 carve-out and re-derive \
         `entry.rs` from the spec"
    );
}
