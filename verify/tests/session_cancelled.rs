//! RT3 operator admin-cancel: the `session_cancelled` management audit entry (seam-sdk#378).
//!
//! # Provenance
//!
//! `tests/goldens/session_cancelled_chain.jsonl` is copied byte-for-byte from seam-runtime's
//! `crates/seam-verify/tests/goldens/session_cancelled_chain.jsonl` at `c551425` (seam-runtime#1773,
//! branch `feat/rt3-tenant-cancel`). The runtime's real `Seam::cancel_session_admin` path wrote it; it
//! was not hand-built, and this crate holds no issuer seed. Seven events: the system partition's
//! config entry, the tenant `design-partner`'s config entry, the session's lifecycle, **one
//! `session_cancelled` `AUDIT_ENTRY`** (seq 3, reason "runaway spend", actor "op@example"), the seal,
//! and a signed head for each partition.
//!
//! Only the cancel entry is byte-stable across a regeneration: the config entries carry a wall-clock
//! time and the seal ciphertext is AEAD-nonced. So the file is vendored as committed, and pinned here.
//!
//! Before this pin the published verifier refused this chain under `--issuer` as an UNCOVERED ENTRY
//! (exit 2); that refusal is what the control plane's `session:cancel` grant waited on.

use std::process::Command;

use sha2::{Digest, Sha256};

const VERIFIED: i32 = 0;
const FAILED: i32 = 2;

const GOLDEN: &str = "session_cancelled_chain.jsonl";
const PIN: &str = "0f21af191a13ca2653d1f191f52952ef6d3c953edaf638e3ef4b2639da9deece";

/// The issuer AID on both of the vector's `CHAIN_HEAD_ATTESTATION` rows.
const ISSUER: &str = "aid:pubkey:QwRr_kCSs-lJlOraFdzCDYqqB7ZY_TlU644O-4vcpd4";

fn golden() -> String {
    let path = format!("{}/tests/goldens/{GOLDEN}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(path).expect("golden must exist")
}

fn run(name: &str, body: &str, args: &[&str]) -> (i32, String) {
    let path = std::env::temp_dir().join(format!("cancel-{name}-{}.jsonl", std::process::id()));
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
fn the_vector_matches_its_sha256_pin() {
    let got: String = Sha256::digest(golden().as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(got, PIN, "re-copy it from the runtime, never edit it");
}

#[test]
fn the_vector_carries_exactly_one_session_cancelled_entry() {
    let cancels: Vec<serde_json::Value> = golden()
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|e| e["kind"] == "AUDIT_ENTRY" && e["audit_entry"]["action"] == "session_cancelled")
        .collect();
    assert_eq!(cancels.len(), 1);
    assert_eq!(cancels[0]["classification"], "Internal");
}

/// The whole stream authenticates under `--issuer --strict`: the cancel entry recomputes under
/// `seam.audit.management.v1`, and nothing is left uncovered.
#[test]
fn the_cancel_chain_authenticates_with_nothing_uncovered() {
    let (code, out) = run("strict", &golden(), &["--issuer", ISSUER, "--strict"]);
    assert_eq!(code, VERIFIED, "{out}");
    assert!(
        out.starts_with("CHAIN AUTHENTICATED (integrity + issuer-signed head, per tenant)"),
        "{out}"
    );
    assert!(out.contains("  uncovered         : 0\n"), "{out}");
    assert!(!out.contains("UNCOVERED ENTRY"), "{out}");
}

/// The cancel entry's content is really recomputed, not waved through: one changed byte of its
/// reason is an entry rewrite.
#[test]
fn a_rewritten_cancel_reason_fails_as_an_entry_rewrite() {
    let body = golden();
    assert_eq!(
        body.matches("runaway spend").count(),
        1,
        "the reason appears once"
    );
    let tampered = body.replace("runaway spend", "runaway spenD");
    let (code, out) = run("rewrite", &tampered, &["--issuer", ISSUER]);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("ENTRY REWRITE"), "{out}");
    assert!(
        out.contains("session_cancelled") || out.contains("AUDIT_ENTRY"),
        "{out}"
    );
}
