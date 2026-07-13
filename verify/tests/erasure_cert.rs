//! The erasure certificate, driven against the **published reference vector**.
//!
//! `fixtures/erasure_certificate_vector.json` is a real signature from the real signer. It is shipped
//! precisely so that this tool can be checked against something nobody has to take on faith — including
//! by you, right now, with `cargo test`.
//!
//! The negative cases are the ones that matter, and each is a forgery a *motivated* party would actually
//! attempt: claiming to have deleted something you kept, backdating the deletion, and signing the whole
//! thing yourself.

use std::process::Command;

const VERIFIED: i32 = 0;
const FAILED: i32 = 2;

fn vector() -> serde_json::Value {
    let raw = include_str!("../fixtures/erasure_certificate_vector.json");
    serde_json::from_str(raw).expect("the published vector must be valid JSON")
}

fn issuer() -> String {
    vector()["issuer_aid"].as_str().unwrap().to_string()
}

fn run(name: &str, doc: &serde_json::Value, aid: &str) -> (i32, String) {
    let path = std::env::temp_dir().join(format!("cert-{name}-{}.json", std::process::id()));
    std::fs::write(&path, serde_json::to_string(doc).unwrap()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_seam-verify"))
        .args(["erasure-cert", path.to_str().unwrap(), "--issuer", aid])
        .output()
        .expect("run seam-verify");
    let _ = std::fs::remove_file(&path);
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap(), s)
}

#[test]
fn the_published_reference_vector_verifies_from_the_issuer_aid_alone() {
    let (code, out) = run("genuine", &vector(), &issuer());
    assert_eq!(code, VERIFIED, "the shipped vector MUST verify:\n{out}");
    assert!(out.contains("ERASURE CERTIFICATE VERIFIED"), "{out}");
    // The held count must be surfaced. A certificate that quietly omits what it did NOT erase is how
    // "we deleted your data" becomes a lie of omission.
    assert!(out.contains("held      : 1"), "{out}");
}

#[test]
fn laundering_a_held_decision_into_the_erased_list_fails() {
    // THE forgery that matters: "we erased it" — about a record kept intact under a legal hold. The
    // signature covers both lists, so moving an id between them breaks it.
    let mut v = vector();
    let held = v["cert"]["held"].as_array_mut().unwrap().remove(0);
    v["cert"]["erased"].as_array_mut().unwrap().push(held);

    let (code, out) = run("laundered", &v, &issuer());
    assert_eq!(code, FAILED, "a laundered held-decision MUST fail:\n{out}");
}

#[test]
fn backdating_the_erasure_fails() {
    // The field a party under a regulatory deadline has an actual motive to move.
    let mut v = vector();
    let t = v["cert"]["erased_at"].as_u64().unwrap();
    v["cert"]["erased_at"] = serde_json::json!(t - 86_400_000 * 40);

    let (code, out) = run("backdated", &v, &issuer());
    assert_eq!(code, FAILED, "a backdated certificate MUST fail:\n{out}");
}

#[test]
fn reordering_the_erased_list_fails() {
    // List ORDER is part of the signed content. If it were not, ids could be permuted freely — which
    // would mean the signature does not actually pin the list it claims to.
    let mut v = vector();
    v["cert"]["erased"].as_array_mut().unwrap().reverse();

    let (code, out) = run("reordered", &v, &issuer());
    assert_eq!(code, FAILED, "reordering the signed list MUST fail:\n{out}");
}

#[test]
fn a_different_chain_head_fails() {
    let mut v = vector();
    v["cert"]["chain_head"] = serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");

    let (code, out) = run("rechained", &v, &issuer());
    assert_eq!(
        code, FAILED,
        "a certificate re-anchored to another chain MUST fail:\n{out}"
    );
}

#[test]
fn a_certificate_is_rejected_against_an_issuer_you_did_not_pin() {
    // The tautology trap, and the reason `--issuer` exists at all.
    //
    // A certificate is verified against the key it NAMES. Let it supply its own issuer and the check is
    // circular: an attacker forges a certificate, signs it with their own key, names their own AID — and
    // it verifies perfectly, against themselves.
    //
    // A signature only means something relative to a key you already trusted. The pin is where that trust
    // enters, and this is the test that says so.
    let other = "aid:pubkey:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let (code, out) = run("wrong-issuer", &vector(), other);
    assert_eq!(
        code, FAILED,
        "a certificate must be REJECTED against an issuer the holder did not pin:\n{out}"
    );
    assert!(out.contains("REJECTED"), "{out}");
}

#[test]
fn a_mangled_signature_is_rejected_not_panicked_on() {
    let mut v = vector();
    v["cert"]["signature"] = serde_json::json!("AAAA");

    let (code, out) = run("short-sig", &v, &issuer());
    assert_eq!(
        code, FAILED,
        "a malformed signature must fail cleanly:\n{out}"
    );
}
