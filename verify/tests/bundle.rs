//! `seam-verify bundle` against **real** `seam-evidence-bundle.v1` directories.
//!
//! `fixtures/evidence-bundle/` was written by the runtime's own export path
//! (`seamd::Seam::export_evidence_bundle`, seam-runtime@460d163 on `feat/835-step4-refuse-v1-tenant`,
//! #1303 — which signs tenant attestations v2, #835 step 3) running the scenario of the runtime's
//! `crates/seam-verify/tests/bundle.rs` `fixture()`: seal `d0`, attest (the anchor), seal the target
//! `d1` with an inline context, seal `d2`, attest (the cover). Issuer seed 7×32. Re-exported for #835
//! step 4: the previous export (seam-runtime@e75528f, 0.44.0) carried v1 tenant attestations, which a
//! step-4 verifier refuses. The commitment, context and policy members are byte-identical to that
//! export; the anchor, events, binding and manifest moved with the v2 signatures (and the record's
//! freshly-encrypted `ciphertext_digest`). Every directory also verifies under the runtime's internal
//! oracle (`seam-verify-internal bundle`) at that commit, so a disagreement here is a disagreement
//! between two verifiers.
//!
//! * `full/` — `--disclose context,policy`: all seven files.
//! * `minimal/` — no disclosures: context and policy withheld with the exporter's reason.
//! * `shredded/` — the target's key destroyed before export: commitment and binding withheld.
//! * `other-issuer/` — the same scenario under issuer seed 9×32: a genuine bundle from a key you did
//!   not pin.
//!
//! No byte here is hand-invented. Every negative starts from one of those directories and makes ONE
//! edit; where the edit is to a member, the manifest is re-hashed so the refusal under test is the
//! content check and not the manifest hash.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

const VERIFIED: i32 = 0;
const USAGE: i32 = 1;
const FAILED: i32 = 2;

/// Issuer seed 7×32 — the AID `fixtures/evidence-bundle/{full,minimal,shredded}` were exported under.
const ISSUER: &str = "aid:pubkey:6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";
/// Issuer seed 9×32 — `other-issuer/`.
const OTHER: &str = "aid:pubkey:_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/evidence-bundle")
        .join(name)
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_seam-verify"))
        .args(args)
        .output()
        .expect("run seam-verify");
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), s)
}

fn verify(dir: &Path, aid: &str) -> (i32, String) {
    run(&["bundle", dir.to_str().unwrap(), "--issuer", aid])
}

/// A private copy of a fixture to edit.
fn copy(from: &str, tag: &str) -> PathBuf {
    let to = std::env::temp_dir().join(format!("seam-sdk-bundle-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&to);
    std::fs::create_dir_all(&to).unwrap();
    for e in std::fs::read_dir(fixture(from)).unwrap() {
        let e = e.unwrap();
        std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
    }
    to
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn edit_manifest(dir: &Path, edit: impl FnOnce(&mut serde_json::Value)) {
    let p = dir.join("manifest.json");
    let mut m = read_json(&p);
    edit(&mut m);
    std::fs::write(&p, serde_json::to_vec_pretty(&m).unwrap()).unwrap();
}

/// Replace a member's bytes, then re-hash it in the manifest.
fn replace_and_rehash(dir: &Path, file: &str, bytes: Vec<u8>) {
    std::fs::write(dir.join(file), &bytes).unwrap();
    let hex: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    edit_manifest(dir, |m| {
        m["files"][file]["sha256"] = hex.into();
        m["files"][file]["bytes"] = bytes.len().into();
    });
}

fn edit_and_rehash(dir: &Path, file: &str, edit: impl FnOnce(&mut serde_json::Value)) {
    let mut v = read_json(&dir.join(file));
    edit(&mut v);
    replace_and_rehash(dir, file, serde_json::to_vec_pretty(&v).unwrap());
}

// ── genuine bundles ───────────────────────────────────────────────────────────────────────────

#[test]
fn a_full_runtime_bundle_verifies_every_step() {
    let (code, out) = verify(&fixture("full"), ISSUER);
    assert_eq!(code, VERIFIED, "{out}");
    for want in [
        "EVIDENCE BUNDLE VERIFIED (seam-evidence-bundle.v1)",
        "decision  : dec:d1",
        "window authenticated from the issuer-signed anchor (base_len 2)",
        "is a chained link of tenant 'design-partner'",
        "TCT verifies against the pinned issuer",
        "signed binding ties this Commitment",
        "context.json recomputes the chained context_digest",
        "SHA-256(policy.json) is the chained policy_rules_digest",
        "withheld: participation",
    ] {
        assert!(out.contains(want), "missing '{want}' in\n{out}");
    }
}

#[test]
fn json_output_reports_the_verdict_and_the_withheld_items() {
    let (code, out) = run(&[
        "bundle",
        fixture("minimal").to_str().unwrap(),
        "--issuer",
        ISSUER,
        "--json",
    ]);
    assert_eq!(code, VERIFIED, "{out}");
    let v: serde_json::Value = serde_json::from_str(out.lines().next().unwrap()).unwrap();
    assert_eq!(v["verified"], true);
    assert_eq!(v["decision_id"], "dec:d1");
    assert_eq!(v["tct"], "verified");
    assert_eq!(v["base_len"], 2);
    let withheld: Vec<&str> = v["withheld"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["item"].as_str().unwrap())
        .collect();
    assert_eq!(withheld, ["context", "policy", "participation"]);
}

#[test]
fn disclosures_are_optional_and_their_absence_is_reported() {
    let (code, out) = verify(&fixture("minimal"), ISSUER);
    assert_eq!(code, VERIFIED, "{out}");
    assert!(out.contains("withheld: context (not disclosed"), "{out}");
    assert!(
        !out.contains("recomputes the chained context_digest"),
        "{out}"
    );
}

#[test]
fn a_shredded_record_verifies_its_link_and_says_why_the_commitment_is_missing() {
    let (code, out) = verify(&fixture("shredded"), ISSUER);
    assert_eq!(code, VERIFIED, "{out}");
    assert!(
        out.contains("withheld: commitment (the record is crypto-shredded"),
        "{out}"
    );
    assert!(!out.contains("TCT"), "{out}");
}

#[test]
fn the_library_and_the_cli_agree() {
    let r = seam_verify::verify_bundle(&fixture("full"), ISSUER, 1_800_000_000).unwrap();
    assert_eq!(r.decision_id, "dec:d1");
    assert_eq!(r.tenant, "design-partner");
    assert_eq!(r.anchor_len, 2);
    assert_eq!(r.tct_verified, Some(true));
    assert!(r.covering >= 1);
}

// ── the pin ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_genuine_bundle_from_an_issuer_you_did_not_pin_is_refused() {
    // Itself genuine: it verifies against its own issuer.
    assert_eq!(verify(&fixture("other-issuer"), OTHER).0, VERIFIED);
    let (code, out) = verify(&fixture("other-issuer"), ISSUER);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("you pinned"), "{out}");
    // And the right bundle against the wrong pin.
    let (code, out) = verify(&fixture("full"), OTHER);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("you pinned"), "{out}");
}

#[test]
fn relabelling_a_foreign_bundle_as_the_pinned_issuer_is_refused() {
    // The manifest is unsigned, so a forger can name any issuer. The anchor, attestations, TCT and
    // binding are signed by the key they were signed by, and that is what gets checked.
    let d = copy("other-issuer", "relabel");
    edit_manifest(&d, |m| {
        m["issuer"]["aid"] = ISSUER.into();
        m["issuer"]["ed25519_public_key"] =
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c".into();
    });
    let (code, out) = verify(&d, ISSUER);
    assert_eq!(code, FAILED, "{out}");
    assert!(out.contains("step 2: ANCHOR REJECTED"), "{out}");
    let _ = std::fs::remove_dir_all(&d);
}

// ── one edit each ─────────────────────────────────────────────────────────────────────────────

type Edit = Box<dyn Fn(&Path)>;

fn assert_refused(base: &str, cases: Vec<(&str, Edit, &str)>) {
    for (name, edit, expect) in cases {
        let d = copy(base, &name.replace(' ', "-"));
        edit(&d);
        let (code, out) = verify(&d, ISSUER);
        assert_eq!(code, FAILED, "{name}: must be refused (exit 2)\n{out}");
        assert!(
            out.contains("EVIDENCE BUNDLE FAILED VERIFICATION"),
            "{name}\n{out}"
        );
        assert!(
            out.contains(expect),
            "{name}: expected '{expect}' in\n{out}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[test]
fn step_1_manifest_tampers_are_refused() {
    assert_refused(
        "full",
        vec![
            (
                "member byte appended",
                Box::new(|d: &Path| {
                    let p = d.join("anchor.json");
                    let mut b = std::fs::read(&p).unwrap();
                    b.push(b' ');
                    std::fs::write(&p, b).unwrap();
                }),
                "anchor.json: sha256",
            ),
            (
                "listed member missing",
                Box::new(|d: &Path| std::fs::remove_file(d.join("binding.json")).unwrap()),
                "binding.json: the manifest lists it, but it cannot be read",
            ),
            (
                "size lies",
                Box::new(|d: &Path| {
                    edit_manifest(d, |m| m["files"]["policy.json"]["bytes"] = 1.into())
                }),
                "policy.json: size",
            ),
            (
                "unknown format",
                Box::new(|d: &Path| {
                    edit_manifest(d, |m| m["format"] = "seam-evidence-bundle.v2".into())
                }),
                "a verifier refuses a format it does not know",
            ),
            (
                "binding unlisted",
                Box::new(|d: &Path| {
                    edit_manifest(d, |m| {
                        m["files"].as_object_mut().unwrap().remove("binding.json");
                    })
                }),
                "must come as a pair",
            ),
            (
                "events unlisted",
                Box::new(|d: &Path| {
                    edit_manifest(d, |m| {
                        m["files"].as_object_mut().unwrap().remove("events.jsonl");
                    })
                }),
                "required file 'events.jsonl' is not listed",
            ),
            (
                "disclosed disagrees",
                Box::new(|d: &Path| {
                    edit_manifest(d, |m| {
                        m["disclosed"]
                            .as_array_mut()
                            .unwrap()
                            .retain(|x| x != "context");
                    })
                }),
                "'disclosed' and 'files' disagree about context",
            ),
            (
                "path escape",
                Box::new(|d: &Path| {
                    edit_manifest(d, |m| {
                        m["files"]["../manifest.json"] =
                            serde_json::json!({"sha256": "", "bytes": 0});
                    })
                }),
                "is not a plain member name",
            ),
            (
                "public key copy lies",
                Box::new(|d: &Path| {
                    edit_manifest(d, |m| {
                        m["issuer"]["ed25519_public_key"] = "00".repeat(32).into()
                    })
                }),
                "issuer.ed25519_public_key is not the pinned AID's key",
            ),
        ],
    );
}

#[test]
fn step_2_wrong_anchor_and_broken_window_are_refused() {
    assert_refused(
        "full",
        vec![
            (
                // A genuine issuer-signed attestation from the same chain, but not the window's start:
                // the covering attestation carried inside events.jsonl itself.
                "anchor is the cover",
                Box::new(|d: &Path| {
                    let events = std::fs::read_to_string(d.join("events.jsonl")).unwrap();
                    let cover = events
                        .lines()
                        .rfind(|l| l.contains("chain_head_attestation"))
                        .unwrap()
                        .as_bytes()
                        .to_vec();
                    replace_and_rehash(d, "anchor.json", cover);
                }),
                "step 2:",
            ),
            (
                // A genuine anchor signed by a key you did not pin.
                "anchor from another issuer",
                Box::new(|d: &Path| {
                    let foreign =
                        std::fs::read(fixture("other-issuer").join("anchor.json")).unwrap();
                    replace_and_rehash(d, "anchor.json", foreign);
                }),
                "step 2: ANCHOR REJECTED",
            ),
            (
                "anchor_attested_len lies",
                Box::new(|d: &Path| {
                    edit_manifest(d, |m| m["inclusion"]["anchor_attested_len"] = 1.into())
                }),
                "inclusion.anchor_attested_len is not anchor.json's attested_len",
            ),
            (
                "decision dropped from the window",
                Box::new(|d: &Path| {
                    let events = std::fs::read_to_string(d.join("events.jsonl")).unwrap();
                    let kept: String = events
                        .lines()
                        .filter(|l| !l.contains("\"decision_id\":\"dec:d1\""))
                        .map(|l| format!("{l}\n"))
                        .collect();
                    assert_ne!(kept, events, "the edit must drop a line");
                    replace_and_rehash(d, "events.jsonl", kept.into_bytes());
                }),
                "step 2:",
            ),
        ],
    );
}

#[test]
fn step_3_inclusion_tampers_are_refused() {
    assert_refused(
        "full",
        vec![
            (
                "manifest names another decision in the window",
                Box::new(|d: &Path| edit_manifest(d, |m| m["decision_id"] = "dec:d2".into())),
                "is not the decision link's checksum",
            ),
            (
                "manifest names a decision not in the window",
                Box::new(|d: &Path| edit_manifest(d, |m| m["decision_id"] = "dec:d0".into())),
                "carries no chained DECISION_SEALED for 'dec:d0'",
            ),
            (
                "manifest names another tenant",
                Box::new(|d: &Path| edit_manifest(d, |m| m["tenant"] = "acme".into())),
                "the manifest says 'acme'",
            ),
        ],
    );
}

#[test]
fn step_4_commitment_tampers_are_refused() {
    assert_refused(
        "full",
        vec![
            (
                "action rewritten",
                Box::new(|d: &Path| {
                    edit_and_rehash(d, "commitment.json", |v| v["action"] = "REJECT".into())
                }),
                "step 4: commitment.json: the TCT does not verify",
            ),
            (
                "explanation reworded",
                Box::new(|d: &Path| {
                    edit_and_rehash(d, "commitment.json", |v| {
                        v["explanation"][0]["reason"] = "looked fine".into()
                    })
                }),
                "step 4: commitment.json: the TCT does not verify",
            ),
            (
                "absent confidence claimed as zero",
                Box::new(|d: &Path| {
                    edit_and_rehash(d, "commitment.json", |v| {
                        v["explanation"][0]["confidence"] = 0.0.into()
                    })
                }),
                "step 4: commitment.json: the TCT does not verify",
            ),
            (
                "non-canonical confidence",
                Box::new(|d: &Path| {
                    edit_and_rehash(d, "commitment.json", |v| {
                        v["explanation"][0]["confidence"] = 1.5.into()
                    })
                }),
                "not a canonical value",
            ),
            (
                "tct signature flipped",
                Box::new(|d: &Path| {
                    edit_and_rehash(d, "commitment.json", |v| {
                        let t = v["signed_artifact"].as_str().unwrap().to_owned();
                        let (head, sig) = t.rsplit_once('.').unwrap();
                        let flipped = if sig.starts_with('A') { "B" } else { "A" };
                        v["signed_artifact"] = format!("{head}.{flipped}{}", &sig[1..]).into();
                    })
                }),
                "step 4:",
            ),
        ],
    );
}

#[test]
fn step_4_an_expired_tct_is_refused_against_the_injected_clock() {
    let err = seam_verify::verify_bundle(&fixture("full"), ISSUER, u64::MAX / 2).unwrap_err();
    assert!(
        matches!(&err, seam_verify::BundleError::Failed { step: 4, message } if message.contains("expired")),
        "{err}"
    );
}

#[test]
fn step_5_binding_tampers_are_refused() {
    assert_refused(
        "full",
        vec![
            (
                "binding names another decision",
                Box::new(|d: &Path| {
                    edit_and_rehash(d, "binding.json", |v| v["decision_id"] = "dec:d2".into())
                }),
                "step 5: binding.json: the signature does not verify",
            ),
            (
                "binding re-dated",
                Box::new(|d: &Path| {
                    edit_and_rehash(d, "binding.json", |v| v["bound_at"] = 1.into())
                }),
                "step 5: binding.json: the signature does not verify",
            ),
            (
                // A genuine binding, validly signed — by a key you did not pin.
                "binding from another issuer",
                Box::new(|d: &Path| {
                    let foreign =
                        std::fs::read(fixture("other-issuer").join("binding.json")).unwrap();
                    replace_and_rehash(d, "binding.json", foreign);
                }),
                "step 5: binding.json: it names issuer",
            ),
        ],
    );
}

#[test]
fn step_5_a_genuine_binding_for_a_different_commitment_is_refused() {
    // An empty `signed_artifact` is the spec's `identity: local-sealed` shape: no TCT, so step 4 has
    // no signature to check and the binding is the ONLY thing tying the Commitment to the chain. An
    // edited field must then be caught by the binding's recomputed commitment digest — the check a
    // verifier that trusted the TCT alone would never reach.
    let d = copy("full", "binding-digest");
    edit_and_rehash(&d, "commitment.json", |v| {
        v["signed_artifact"] = "".into();
        v["action"] = "REJECT".into();
    });
    let (code, out) = verify(&d, ISSUER);
    assert_eq!(code, FAILED, "{out}");
    assert!(
        out.contains("step 5: binding.json: it binds a different Commitment than commitment.json"),
        "{out}"
    );

    // And without the edit, a TCT-less Commitment still verifies on the binding alone, and says so.
    let d2 = copy("full", "binding-only");
    edit_and_rehash(&d2, "commitment.json", |v| v["signed_artifact"] = "".into());
    let (code, out) = verify(&d2, ISSUER);
    assert_eq!(code, VERIFIED, "{out}");
    assert!(out.contains("has no TCT"), "{out}");
    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_dir_all(&d2);
}

#[test]
fn step_6_disclosure_tampers_are_refused() {
    assert_refused(
        "full",
        vec![
            (
                "context fidelity",
                Box::new(|d: &Path| {
                    edit_and_rehash(d, "context.json", |v| {
                        v["bindings"][0]["fidelity"] = "Value".into()
                    })
                }),
                "step 6: context.json does not recompute the chained context_digest",
            ),
            (
                "context binding dropped",
                Box::new(|d: &Path| {
                    edit_and_rehash(d, "context.json", |v| v["bindings"] = serde_json::json!([]))
                }),
                "step 6: context.json does not recompute",
            ),
            (
                "policy re-canonicalized",
                Box::new(|d: &Path| {
                    let v = read_json(&d.join("policy.json"));
                    replace_and_rehash(d, "policy.json", serde_json::to_vec_pretty(&v).unwrap());
                }),
                "step 6: SHA-256(policy.json) is not the chained policy_rules_digest",
            ),
        ],
    );
}

// ── exit 1: nothing was verified, nothing was refused ─────────────────────────────────────────

#[test]
fn usage_and_io_errors_exit_1() {
    let missing = std::env::temp_dir().join("seam-sdk-bundle-does-not-exist");
    assert_eq!(verify(&missing, ISSUER).0, USAGE);

    let empty = std::env::temp_dir().join(format!("seam-sdk-bundle-empty-{}", std::process::id()));
    std::fs::create_dir_all(&empty).unwrap();
    let (code, out) = verify(&empty, ISSUER);
    assert_eq!(code, USAGE, "{out}");
    assert!(out.contains("cannot read manifest.json"), "{out}");
    let _ = std::fs::remove_dir_all(&empty);

    let full = fixture("full");
    let full = full.to_str().unwrap();
    assert_eq!(run(&["bundle", full]).0, USAGE, "no --issuer");
    assert_eq!(
        run(&["bundle", full, "--issuer", ISSUER, "--issuer", OTHER]).0,
        USAGE,
        "two pins"
    );
    assert_eq!(
        run(&["bundle", full, "--issuer", ISSUER, "--from-anchor", "x"]).0,
        USAGE
    );
    assert_eq!(run(&["bundle", full, "--issuer", "not-an-aid"]).0, USAGE);
}
