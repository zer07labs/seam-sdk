//! Runtime-produced entry vectors (plan `plans/verify-a4-parity.md`, Phase 0; seam-sdk#316).
//!
//! # Provenance
//!
//! Every `tests/goldens/entry_domains*` file was written by seam-runtime's own test code, from a clean
//! `git archive 37576658` export of seam-runtime (`origin/main`, which contains the A4 commit
//! `4f70c2c4`). Each event is serialized with `SeamEvent::to_json`, one per line. Nothing here was
//! hand-signed, and this crate holds no issuer seed. The precedent is D-038/D-040: fixtures "captured
//! from the runtime's own test".
//!
//! * `entry_domains.jsonl`: the body of `crates/seam-verify/tests/entry_recompute.rs` `stream()`, which
//!   produces one entry from every audit writer, an erasure certificate, and signed heads for `acme`,
//!   `beta` (crypto-shredded) and the system partition `""` (a v1 attestation). Issuer seed: the test's
//!   `SEED` constant, `21×32`. Issuer AID: [`ENTRY_ISSUER`].
//! * `entry_domains.window.jsonl` and `entry_domains.anchor.json`: `crates/seam-verify/tests/anchored.rs`
//!   `two_anchor_stream()` cut by `window_from(&events, 2)`, and that stream's anchor A1 (the `anchor_json`
//!   shape). This is a DIFFERENT stream from the one above. Issuer seed: `ISSUER_SEED`, `07×32`. Issuer
//!   AID: [`WINDOW_ISSUER`].
//! * `entry_domains.swapped-attestation.json`: the genuinely signed earlier attestation from
//!   `anchored.rs` `a_swapped_attestation_below_the_window_base_fails` (`:540-571`), namely
//!   `sign_chain_head_for_tenant(1, head1, ATTESTED_AT, 4, "acme")` under `ISSUER_SEED`, written with all
//!   of its fields in the `anchor_json` shape. Phase 3 splices its fields into the window's first row.
//!
//! The capture was a throw-away test appended to those two runtime test files inside the export only.
//! It was never committed to either repository. The sha256 pins below make any later edit red.

use std::process::Command;

use sha2::{Digest, Sha256};

const VERIFIED: i32 = 0;
const FAILED: i32 = 2;

/// The AID of the `21×32` seed (`entry_recompute.rs` `SEED`) that signs `entry_domains.jsonl`.
const ENTRY_ISSUER: &str = "aid:pubkey:1UIH2hlJd9z0atv-wrwudbUtWopCGE_t_cAAJPDj6No";
/// The AID of the `07×32` seed (`anchored.rs` `ISSUER_SEED`) that signs the window, anchor and swap.
const WINDOW_ISSUER: &str = "aid:pubkey:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";

const PINS: [(&str, &str); 4] = [
    (
        "entry_domains.jsonl",
        "e2abedcdb95de971d6b3e7030c3a70ba9442b291b29d32dd754ae05cedd32396",
    ),
    (
        "entry_domains.window.jsonl",
        "19250e3d3f8e41a60411b95bfec6e89bc5322c6cc4c29862d575254bd3e68c66",
    ),
    (
        "entry_domains.anchor.json",
        "45cd6ad8c7a4e9228e035ae4210f3eb40726fd504b5037cff60fbbfc81e608ef",
    ),
    (
        "entry_domains.swapped-attestation.json",
        "198112d7f68911be1b6b9e5f73e583473364a9cf7a91c69fc2aed95c8e7e4b16",
    ),
];

const ACTIONS: [&str; 12] = [
    "party_registered",
    "hold_placed",
    "hold_released",
    "boundary.data_flagged",
    "admit.compat_reject",
    "execute.scope_deny",
    "ciphertext_evicted",
    "gdpr_erasure",
    "crypto_shred_purge",
    "context_recalled",
    "tenant_kek_shred",
    "config_snapshot_installed",
];

fn golden_path(name: &str) -> String {
    format!("{}/tests/goldens/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn golden(name: &str) -> String {
    std::fs::read_to_string(golden_path(name)).expect("golden must exist")
}

fn rows(name: &str) -> Vec<serde_json::Value> {
    golden(name)
        .lines()
        .map(|l| serde_json::from_str(l).expect("each line is one JSON event"))
        .collect()
}

fn is_chained(e: &serde_json::Value) -> bool {
    e["checksum"].is_string() && e["digest"].is_string()
}

fn run(name: &str, body: &str, args: &[&str]) -> (i32, String) {
    let path = std::env::temp_dir().join(format!("entry-vec-{name}-{}.jsonl", std::process::id()));
    std::fs::write(&path, body).unwrap();
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

#[test]
fn every_vendored_vector_matches_its_sha256_pin() {
    for (name, want) in PINS {
        let bytes = std::fs::read(golden_path(name)).expect("golden must exist");
        let got: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            got, want,
            "{name} changed: re-capture it from the runtime, never edit it"
        );
    }
}

#[test]
fn the_stream_holds_chained_entries_for_exactly_the_twelve_actions() {
    let events = rows("entry_domains.jsonl");
    let mut actions: Vec<&str> = events
        .iter()
        .filter(|e| e["kind"] == "AUDIT_ENTRY")
        .inspect(|e| assert!(is_chained(e), "an unchained AUDIT_ENTRY: {e}"))
        .map(|e| e["audit_entry"]["action"].as_str().expect("an action"))
        .collect();
    actions.sort_unstable();
    actions.dedup();
    let mut want = ACTIONS.to_vec();
    want.sort_unstable();
    assert_eq!(actions, want);

    // `actor` stays `null`, not `""`, on an entry with no actor (`event.rs:406`: no skip_serializing_if).
    let no_actor = events
        .iter()
        .filter(|e| e["kind"] == "AUDIT_ENTRY")
        .filter(|e| e["audit_entry"]["actor"].is_null())
        .count();
    assert!(no_actor >= 1, "the stream must keep a no-actor entry");
    assert!(events
        .iter()
        .filter(|e| e["kind"] == "AUDIT_ENTRY")
        .all(|e| e["audit_entry"]["actor"] != ""));
}

#[test]
fn the_stream_holds_a_chained_certificate_and_attestations_for_three_partitions() {
    let events = rows("entry_domains.jsonl");
    assert!(
        events
            .iter()
            .any(|e| e["kind"] == "ERASURE_CERTIFICATE" && is_chained(e)),
        "at least one chained ERASURE_CERTIFICATE"
    );
    for tenant in ["acme", "beta", ""] {
        assert!(
            events.iter().any(|e| e["kind"] == "CHAIN_HEAD_ATTESTATION"
                && is_chained(e)
                && e["tenant"] == tenant
                // The system partition's payload omits an empty `tenant`, so absent reads as "".
                && e["chain_head_attestation"]["tenant"].as_str().unwrap_or("") == tenant
                && e["chain_head_attestation"]["issuer_aid"] == ENTRY_ISSUER),
            "an attestation for tenant {tenant:?}"
        );
    }
}

#[test]
fn plain_chain_verifies_the_stream() {
    let (code, out) = run("plain", &golden("entry_domains.jsonl"), &[]);
    assert_eq!(code, VERIFIED, "{out}");
}

/// The runtime's own stream is fully green under `--issuer --strict`, with the uncovered refusal in
/// force: every chained non-seal link recomputes (15 `AUDIT_ENTRY`, 1 `ERASURE_CERTIFICATE`, 3
/// `CHAIN_HEAD_ATTESTATION`), and nothing is uncovered. Both disclosures are printed, zero included.
#[test]
fn chain_with_issuer_and_strict_verifies_the_stream() {
    let (code, out) = run(
        "issuer-strict",
        &golden("entry_domains.jsonl"),
        &["--issuer", ENTRY_ISSUER, "--strict"],
    );
    assert_eq!(code, VERIFIED, "{out}");
    assert!(
        out.starts_with("CHAIN AUTHENTICATED (integrity + issuer-signed head, per tenant)"),
        "{out}"
    );
    assert!(
        out.contains("  entries recomputed: 19 (audit, attestation and erasure entry digests)\n"),
        "{out}"
    );
    assert!(out.contains("  uncovered         : 0\n"), "{out}");
    assert!(!out.contains("UNCOVERED ENTRY"), "{out}");
}

/// Negative control: the file is a real chain, so dropping one middle line breaks a link.
#[test]
fn deleting_one_line_breaks_the_chain() {
    let body = golden("entry_domains.jsonl");
    let lines: Vec<&str> = body.lines().collect();
    let cut: Vec<&str> = lines
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 7)
        .map(|(_, l)| *l)
        .collect();
    let (code, out) = run("deleted-line", &(cut.join("\n") + "\n"), &[]);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("BROKEN CHAIN"), "{out}");
}

#[test]
fn the_swapped_attestation_is_genuinely_signed_and_lies_below_the_window_base() {
    let att = seam_verify::wire::Attestation::parse_document(&golden(
        "entry_domains.swapped-attestation.json",
    ))
    .expect("the swapped attestation parses as an anchor document");
    seam_verify::verify_anchor(&att, &[WINDOW_ISSUER.to_owned()])
        .expect("the swapped attestation verifies under the window's issuer");
    assert_eq!(att.attested_len, 1);
    assert_eq!(att.tenant, "acme");

    let anchor =
        seam_verify::wire::Attestation::parse_document(&golden("entry_domains.anchor.json"))
            .expect("the anchor parses");
    assert_eq!(anchor.attested_len, 2, "the window base is 2");
    assert!(att.attested_len < anchor.attested_len);

    let window = rows("entry_domains.window.jsonl");
    assert_eq!(window[0]["kind"], "CHAIN_HEAD_ATTESTATION");
    assert_eq!(window[0]["chain_head_attestation"]["attested_len"], 2);
}

/// The window and its anchor are a matched pair: the runtime cut them from one stream, so they verify
/// together under the window's issuer. Phase 3's ordering tests rely on that.
#[test]
fn the_window_authenticates_from_its_anchor() {
    let anchor = golden_path("entry_domains.anchor.json");
    let (code, out) = run(
        "window",
        &golden("entry_domains.window.jsonl"),
        &["--issuer", WINDOW_ISSUER, "--from-anchor", &anchor],
    );
    assert_eq!(code, VERIFIED, "{out}");
    assert!(out.contains("WINDOW AUTHENTICATED"), "{out}");
}
