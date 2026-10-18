//! `seam-commitment-digest:v3` / `seam-explanation-digest:v1` and the TCT, against the shared
//! cross-repo vectors in `../conformance/` — the same files the five SDKs are held to.
//!
//! * `commitment_digest_v3_vector.json` is the runtime's own vector
//!   (`crates/seam-trust-aitp/tests/fixtures/commitment_digest_v3_vector.json`), byte-identical: the
//!   all-empty case, the present-but-empty `supersedes` case, and a populated one with decomposed
//!   combining marks, an absent confidence beside a stated `0.0`, and a REAL self-attestation TCT from
//!   the real signer.
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
    let v = load("commitment_digest_v3_vector.json");
    assert_eq!(v["commitment_digest_domain"], "seam-commitment-digest:v3");
    let issuer = v["issuer_aid"].as_str().unwrap();
    let cases = v["cases"].as_array().unwrap();
    let names: Vec<&str> = cases.iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        ["all_empty", "empty_supersedes", "populated_signed"],
        "the vector's cases changed"
    );
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

// ── failure paths: tokens minted here with the vector's own issuer seed ─────────────────────────────

/// The vector's issuer seed (`"issuer_seed": "[7u8; 32]"`).
const SEED: [u8; 32] = [7u8; 32];

fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Sign `header.payload` (both RAW JSON text, so a test can write duplicate keys) with [`SEED`].
fn mint(header: &str, payload: &str) -> String {
    use ed25519_dalek::{Signer, SigningKey};
    let input = format!("{}.{}", b64(header.as_bytes()), b64(payload.as_bytes()));
    let sig = SigningKey::from_bytes(&SEED).sign(input.as_bytes());
    format!("{input}.{}", b64(&sig.to_bytes()))
}

const HEADER: &str = r#"{"alg":"EdDSA","typ":"aitp-tct+jwt"}"#;

/// The signed case's real claims, re-assembled from parts so each test can vary exactly one.
fn claims(grants: &str, ext: &str) -> String {
    let v = load("commitment_digest_v3_vector.json");
    let aid = v["issuer_aid"].as_str().unwrap();
    format!(
        r#"{{"aud":"{aid}","cnf":{{"jkt":"--6IM5l0OosLj9yWskISYhUA3n_3CURQkmrYMSha_ck"}},"exp":4913600000,"ext":{ext},"grants":{grants},"iat":1760000000,"iss":"{aid}","jti":"j","sub":"{aid}","ver":"aitp/0.2"}}"#
    )
}

fn signed_case() -> (String, [u8; 32]) {
    let v = load("commitment_digest_v3_vector.json");
    let c = commitment(&v["cases"][2]["commitment"]);
    (
        v["issuer_aid"].as_str().unwrap().to_owned(),
        commitment_digest(&c).unwrap(),
    )
}

fn good_ext(d: &[u8; 32]) -> String {
    format!(
        r#"{{"com.zer07labs.seam":{{"commitment_digest":"{}","type":"seam:commitment"}}}}"#,
        hex(d)
    )
}

const GRANTS: &str = r#"["aitp.attestation"]"#;

/// The minting helper itself must reproduce a token the verifier accepts — otherwise every refusal
/// below could be the helper's fault rather than the rule's.
#[test]
fn a_token_minted_with_the_vector_seed_verifies() {
    let (aid, d) = signed_case();
    let t = mint(HEADER, &claims(GRANTS, &good_ext(&d)));
    verify_tct(&aid, &t, &d, NOW).expect("the control token must verify");
}

#[test]
fn every_tct_rule_is_enforced() {
    let (aid, d) = signed_case();
    let ext = good_ext(&d);
    let cases: Vec<(&str, String, String)> = vec![
        (
            "typ",
            r#"{"alg":"EdDSA","typ":"JWT"}"#.into(),
            claims(GRANTS, &ext),
        ),
        (
            "alg",
            r#"{"alg":"ES256","typ":"aitp-tct+jwt"}"#.into(),
            claims(GRANTS, &ext),
        ),
        (
            "the retired two-grant form",
            HEADER.into(),
            claims(
                &format!(
                    r#"["seam:commitment","seam-commitment-digest:{}"]"#,
                    hex(&d)
                ),
                &ext,
            ),
        ),
        (
            "an extra grant",
            HEADER.into(),
            claims(r#"["aitp.attestation","seam:commitment"]"#, &ext),
        ),
        ("no grant", HEADER.into(), claims("[]", &ext)),
        (
            "a second ext namespace",
            HEADER.into(),
            claims(
                GRANTS,
                &format!(
                    r#"{{"com.example":{{}},"com.zer07labs.seam":{{"commitment_digest":"{}","type":"seam:commitment"}}}}"#,
                    hex(&d)
                ),
            ),
        ),
        (
            "an extra member in the binding",
            HEADER.into(),
            claims(
                GRANTS,
                &format!(
                    r#"{{"com.zer07labs.seam":{{"commitment_digest":"{}","note":"x","type":"seam:commitment"}}}}"#,
                    hex(&d)
                ),
            ),
        ),
        (
            "a wrong type",
            HEADER.into(),
            claims(
                GRANTS,
                &format!(
                    r#"{{"com.zer07labs.seam":{{"commitment_digest":"{}","type":"seam:other"}}}}"#,
                    hex(&d)
                ),
            ),
        ),
        (
            "an uppercase digest",
            HEADER.into(),
            claims(
                GRANTS,
                &format!(
                    r#"{{"com.zer07labs.seam":{{"commitment_digest":"{}","type":"seam:commitment"}}}}"#,
                    hex(&d).to_uppercase()
                ),
            ),
        ),
        ("no ext", HEADER.into(), claims(GRANTS, "null")),
        (
            "a duplicate commitment_digest (first one wrong)",
            HEADER.into(),
            claims(
                GRANTS,
                &format!(
                    r#"{{"com.zer07labs.seam":{{"commitment_digest":"{}","commitment_digest":"{}","type":"seam:commitment"}}}}"#,
                    "00".repeat(32),
                    hex(&d)
                ),
            ),
        ),
        (
            "a duplicate top-level claim",
            HEADER.into(),
            claims(GRANTS, &ext).replacen(
                r#""ver":"aitp/0.2""#,
                r#""ver":"aitp/0.2","ver":"aitp/0.2""#,
                1,
            ),
        ),
        (
            "a duplicate header member",
            r#"{"alg":"EdDSA","typ":"x","typ":"aitp-tct+jwt"}"#.into(),
            claims(GRANTS, &ext),
        ),
    ];
    for (what, h, p) in cases {
        assert!(
            verify_tct(&aid, &mint(&h, &p), &d, NOW).is_err(),
            "{what} must be refused"
        );
    }

    // iss == sub == aud: a token whose subject or audience is another AID is not a self-attestation.
    let other = "aid:pubkey:_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg";
    for field in ["sub", "aud"] {
        let p = claims(GRANTS, &ext).replacen(
            &format!(r#""{field}":"{aid}""#),
            &format!(r#""{field}":"{other}""#),
            1,
        );
        assert!(
            verify_tct(&aid, &mint(HEADER, &p), &d, NOW).is_err(),
            "{field} != iss must be refused"
        );
    }

    // The digest must be THIS Commitment's v3 recompute: a token binding a different digest is refused.
    let mut wrong = d;
    wrong[0] ^= 1;
    assert!(verify_tct(&aid, &mint(HEADER, &claims(GRANTS, &ext)), &wrong, NOW).is_err());
}
