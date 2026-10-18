//! `seam-commitment-digest:v2` / `seam-explanation-digest:v1` and the TCT, against the shared
//! cross-repo vectors in `../conformance/` — the same files the five SDKs are held to.
//!
//! * `commitment_digest_v2_vector.json` is the runtime's own vector
//!   (`crates/seam-trust-aitp/tests/fixtures/commitment_digest_v2_vector.json`): the all-empty case and
//!   a populated one with decomposed combining marks, an absent confidence beside a stated `0.0`, and a
//!   REAL TCT from the real signer.
//! * `vectors.json`'s `tct` block is the SDK conformance copy of the same framing, with its own TCT.
//!
//! Excluded from the published package (see `Cargo.toml`), for the reason `tests/conformance.rs` is:
//! it reads the ONE copy of these files rather than vendoring a second one to drift. The spec's worked
//! examples are pinned by unit tests in `src/commitment.rs`, which ship with the crate.

use seam_verify::commitment::{
    commitment_digest, explanation_digest, verify_tct, Commitment, ExplanationEntry,
};
use serde_json::Value;

fn load(name: &str) -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../conformance")
        .join(name);
    serde_json::from_str(
        &std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("{}: {e} — this test refuses to skip", p.display())),
    )
    .unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn text(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_owned()
}

/// The REST projection: byte fields as JSON number arrays, absent optionals as `null`.
fn commitment(c: &Value) -> Commitment {
    let artifact = match c.get("signed_artifact") {
        Some(Value::Array(a)) => {
            String::from_utf8(a.iter().map(|b| b.as_u64().unwrap() as u8).collect()).unwrap()
        }
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    };
    Commitment {
        id: text(c, "id"),
        action: text(c, "action"),
        authority: text(c, "authority"),
        supersedes: c
            .get("supersedes")
            .and_then(Value::as_str)
            .map(str::to_owned),
        auth_method: text(c, "auth_method"),
        trust_basis: text(c, "trust_basis"),
        committer: text(c, "committer"),
        explanation: c["explanation"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| ExplanationEntry {
                kind: text(e, "kind"),
                participant: text(e, "participant"),
                proposal_id: text(e, "proposal_id"),
                value: text(e, "value"),
                reason: text(e, "reason"),
                confidence: e.get("confidence").and_then(Value::as_f64),
                rationale_ref: e
                    .get("rationale_ref")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            })
            .collect(),
        signed_artifact: artifact,
    }
}

/// A clock inside every vector TCT's `[iat, exp]`.
const NOW: u64 = 1_800_000_000;

#[test]
fn every_runtime_vector_case_reproduces_and_its_tct_verifies() {
    let v = load("commitment_digest_v2_vector.json");
    let issuer = v["issuer_aid"].as_str().unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 2, "the vector lost its cases");
    let mut signed = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let c = commitment(&case["commitment"]);
        assert_eq!(
            hex(&explanation_digest(&c.explanation).unwrap()),
            case["explanation_digest"].as_str().unwrap(),
            "{name}: explanation_digest"
        );
        let d = commitment_digest(&c).unwrap();
        assert_eq!(
            hex(&d),
            case["commitment_digest"].as_str().unwrap(),
            "{name}: commitment_digest"
        );
        if c.signed_artifact.is_empty() {
            continue;
        }
        signed += 1;
        verify_tct(issuer, &c.signed_artifact, &d, NOW)
            .unwrap_or_else(|e| panic!("{name}: the real TCT must verify: {e}"));

        // Any bound field edited: the digest moves, and the TCT no longer binds it.
        let mut edited = c.clone();
        edited.action.push('!');
        let d2 = commitment_digest(&edited).unwrap();
        assert!(verify_tct(issuer, &c.signed_artifact, &d2, NOW).is_err());
        // An absent confidence is not 0.0: flipping it moves the digest.
        let mut edited = c.clone();
        if let Some(e) = edited
            .explanation
            .iter_mut()
            .find(|e| e.confidence.is_none())
        {
            e.confidence = Some(0.0);
            assert_ne!(commitment_digest(&edited).unwrap(), d, "{name}");
        }
        // The pin is load-bearing.
        let other = "aid:pubkey:_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg";
        assert!(verify_tct(other, &c.signed_artifact, &d, NOW).is_err());
        // Expiry is enforced, against the injected clock.
        assert!(verify_tct(issuer, &c.signed_artifact, &d, u64::MAX / 2).is_err());
    }
    assert!(
        signed >= 1,
        "the vector carries no signed case — nothing checked the TCT"
    );
}

#[test]
fn the_sdk_conformance_tct_block_reproduces_and_verifies() {
    let v = load("vectors.json");
    let t = &v["tct"];
    let c = commitment(&t["inputs"]["commitment"]);
    assert_eq!(
        hex(&explanation_digest(&c.explanation).unwrap()),
        t["explanation_digest_hex"].as_str().unwrap()
    );
    let d = commitment_digest(&c).unwrap();
    assert_eq!(hex(&d), t["commitment_digest_hex"].as_str().unwrap());
    verify_tct(
        t["issuer_aid"].as_str().unwrap(),
        t["signed_artifact_jws"].as_str().unwrap(),
        &d,
        NOW,
    )
    .expect("the conformance TCT must verify");
}
