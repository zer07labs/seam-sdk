//! `seam-commitment-digest:v5` / `seam-explanation-digest:v2` and the TCT, against the shared
//! cross-repo vectors in `../conformance/` — the same files the five SDKs are held to.
//!
//! * `commitment_digest_v5_signed_vector.json` is the runtime's own vector
//!   (`crates/seam-trust-aitp/tests/fixtures/commitment_digest_v5_signed_vector.json`, seam-runtime#1727),
//!   byte-identical: the all-empty case, the present-but-empty `supersedes` case, a populated one with
//!   decomposed combining marks, an absent confidence beside a stated `0.0`, three voter verification
//!   records that genuinely re-verify, and REAL self-attestation TCTs from the real signer for it
//!   governed (field 11 present) and ungoverned; and three cases exercising the field 9/10 slots.
//! * `commitment_digest_v5_vector.json` is the spec's own vector (`scripts/commitment_digest_v5_vectors.py`,
//!   an independent implementation of the v5 text): the field 11 slot alone and beside 9 and 10. Its
//!   `governing_trailer_refusals` are not exercised here: they pin the runtime's `0x06` trailer decoder,
//!   and a verifier only ever reads field 11 from the commitment, never a trailer.
//! * `vectors.json`'s `tct` block is the SDK conformance copy of the same framing, with its own TCT.
//!
//! Excluded from the published package (see `Cargo.toml`), for the reason `tests/conformance.rs` is:
//! it reads the ONE copy of these files rather than vendoring a second one to drift. The spec's worked
//! examples are pinned by unit tests in `src/commitment.rs`, which ship with the crate.

use seam_verify::bundle::parse_voter_verification;
use seam_verify::commitment::{
    commitment_digest, commitment_digest_with_explanation, explanation_digest, verify_tct,
    Commitment, ExplanationEntry,
};
use seam_verify::voter::verify_commitment_voters;
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

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

/// A voter record in either projection: the REST one (byte fields as number arrays) or `vectors.json`'s
/// (`<field>_hex`), normalised to the REST one and parsed by the bundle's own parser.
fn voter(e: &Value) -> Option<seam_verify::commitment::VoterVerification> {
    let v = e.get("voter_verification")?;
    if v.is_null() {
        return None;
    }
    let mut v = v.clone();
    let o = v.as_object_mut().unwrap();
    for k in ["content_digest", "signature", "signer_certificate"] {
        if let Some(h) = o.remove(&format!("{k}_hex")) {
            o.insert(k.into(), serde_json::json!(unhex(h.as_str().unwrap())));
        }
    }
    Some(parse_voter_verification(&v).unwrap())
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
                voter_verification: voter(e),
            })
            .collect(),
        selection_digest: None,
        certificate_digest: None,
        // REST projection: 32 raw bytes as a JSON number array, `null` when ungoverned.
        governing_doc_sha256: c
            .get("governing_doc_sha256")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(|b| b.as_u64().unwrap() as u8).collect()),
        signed_artifact: artifact,
    }
}

/// A clock inside every vector TCT's `[iat, exp]`.
const NOW: u64 = 1_800_000_000;

#[test]
fn every_runtime_vector_case_reproduces_and_its_tct_verifies() {
    let v = load("commitment_digest_v5_signed_vector.json");
    assert_eq!(v["commitment_digest_domain"], "seam-commitment-digest:v5");
    assert_eq!(v["explanation_digest_domain"], "seam-explanation-digest:v2");
    let issuer = v["issuer_aid"].as_str().unwrap();
    let cases = v["cases"].as_array().unwrap();
    let names: Vec<&str> = cases.iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "all_empty",
            "empty_supersedes",
            "populated_signed",
            "populated_signed_ungoverned",
            "selection_present",
            "certificate_present",
            "both_present"
        ],
        "the vector's cases changed"
    );
    let mut signed = 0;
    let mut governed_signed = 0;
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let mut c = commitment(&case["commitment"]);
        c.selection_digest = case
            .get("selection_digest")
            .and_then(Value::as_str)
            .map(unhex);
        c.certificate_digest = case
            .get("certificate_digest")
            .and_then(Value::as_str)
            .map(unhex);
        assert_eq!(
            hex(&explanation_digest(&c.explanation).unwrap()),
            case["explanation_digest"].as_str().unwrap(),
            "{name}: explanation_digest"
        );
        // Every voter record the vector seals genuinely re-verifies against the vector's issuer.
        verify_commitment_voters(&c.explanation, issuer, None)
            .unwrap_or_else(|e| panic!("{name}: voter records: {e}"));
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

        // Field 11 is bound: stripping the governing document (or adding one) breaks the TCT.
        let mut flipped = c.clone();
        flipped.governing_doc_sha256 = match &c.governing_doc_sha256 {
            Some(_) => {
                governed_signed += 1;
                None
            }
            None => Some(vec![0x34; 32]),
        };
        let d3 = commitment_digest(&flipped).unwrap();
        assert!(
            verify_tct(issuer, &c.signed_artifact, &d3, NOW).is_err(),
            "{name}: field 11 must be TCT-bound"
        );

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
        signed >= 2,
        "the vector carries fewer than two signed cases — governed and ungoverned TCTs unchecked"
    );
    assert_eq!(governed_signed, 1, "exactly one signed case is governed");
}

#[test]
fn every_spec_vector_case_reproduces() {
    let v = load("commitment_digest_v5_vector.json");
    assert_eq!(v["commitment_digest_domain"], "seam-commitment-digest:v5");
    let cases = v["cases"].as_array().unwrap();
    let names: Vec<&str> = cases.iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "all_empty",
            "doc_present",
            "doc_and_selection_present",
            "doc_and_certificate_present",
            "all_slots_present",
            "populated_ungoverned",
            "populated_governed"
        ],
        "the vector's cases changed"
    );
    let slot = |case: &Value, k: &str| case.get(k).and_then(Value::as_str).map(unhex);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let mut c = commitment(&serde_json::json!({
            "id": case["commitment"]["id"], "action": case["commitment"]["action"],
            "authority": case["commitment"]["authority"], "supersedes": case["commitment"]["supersedes"],
            "auth_method": case["commitment"]["auth_method"],
            "trust_basis": case["commitment"]["trust_basis"],
            "committer": case["commitment"]["committer"], "explanation": [],
        }));
        c.selection_digest = slot(case, "selection_digest");
        c.certificate_digest = slot(case, "certificate_digest");
        c.governing_doc_sha256 = slot(case, "governing_doc_sha256");
        // Only the explanation digest is published here; the entries are the signed vector's.
        let e: [u8; 32] = unhex(case["explanation_digest"].as_str().unwrap())
            .try_into()
            .unwrap();
        assert_eq!(
            hex(&commitment_digest_with_explanation(&c, &e).unwrap()),
            case["commitment_digest"].as_str().unwrap(),
            "{name}: commitment_digest"
        );
        // The trailer's last 32 bytes ARE field 11 (body = version 0x01 ‖ digest).
        if let (Some(t), Some(doc)) = (case["governing_trailer"].as_str(), &c.governing_doc_sha256)
        {
            assert_eq!(&unhex(t)[6..], doc.as_slice(), "{name}: trailer payload");
        }
    }
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
    assert_eq!(
        verify_commitment_voters(&c.explanation, t["issuer_aid"].as_str().unwrap(), None),
        Ok(1),
        "the conformance vote's voter record must re-verify"
    );
    // ...and it is bound to the vector's own decision, `dec:acme:s-conformance-0000000`.
    let did = t["inputs"]["decision_id"].as_str().unwrap();
    let (tenant, session) = did.strip_prefix("dec:").unwrap().split_once(':').unwrap();
    let iss = t["issuer_aid"].as_str().unwrap();
    assert_eq!(
        verify_commitment_voters(&c.explanation, iss, Some((tenant, session))),
        Ok(1)
    );
    assert!(verify_commitment_voters(&c.explanation, iss, Some((tenant, "s-other"))).is_err());
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
//
// Since S-4 (seam-runtime #2031) a commitment TCT is signed by a seal key the issuer certifies, so the
// tokens below are minted the way the runtime's test support mints them: the seal key of
// `SeededSealKeys::new(SEED)`, certified for the UTC hour of `iat`, with the certificate in `ext`.

/// The vector's issuer seed (`"issuer_seed": "[7u8; 32]"`).
const SEED: [u8; 32] = [7u8; 32];

/// The minted tokens' `iat`.
const IAT: u64 = 1_760_000_000;

fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// The seeded seal key: `sha256("seam.seal-key.fixed.v1" ‖ SEED)`.
fn seal_key() -> ed25519_dalek::SigningKey {
    use sha2::{Digest, Sha256};
    let seed: [u8; 32] = Sha256::new()
        .chain_update(b"seam.seal-key.fixed.v1")
        .chain_update(SEED)
        .finalize()
        .into();
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

/// The seal key's untagged AID, the tokens' `iss == sub == aud`.
fn seal_aid() -> String {
    format!("aid:pubkey:{}", b64(seal_key().verifying_key().as_bytes()))
}

/// The issuer-signed `{cert, sig}` member certifying [`seal_key`] for the hour containing [`IAT`].
fn cert_member() -> String {
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    let issuer = SigningKey::from_bytes(&SEED);
    let issuer_aid = format!("aid:pubkey:{}", b64(issuer.verifying_key().as_bytes()));
    let nb = IAT * 1000 - (IAT * 1000) % 3_600_000;
    let mut cert = Vec::new();
    let framed = |out: &mut Vec<u8>, b: &[u8]| {
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(b);
    };
    framed(&mut cert, b"seam.seal-key-cert.v1");
    framed(&mut cert, seal_key().verifying_key().as_bytes());
    cert.extend_from_slice(&nb.to_le_bytes());
    cert.extend_from_slice(&(nb + 3_600_000).to_le_bytes());
    framed(&mut cert, issuer_aid.as_bytes());
    let sig = issuer.sign(&Sha256::digest(&cert));
    format!(
        r#"{{"cert":"{}","sig":"{}"}}"#,
        b64(&cert),
        b64(&sig.to_bytes())
    )
}

/// `{"com.zer07labs.seam": statement, "com.zer07labs.seam.seal-key-cert": member}`, plus `extra` members.
fn ext_of(statement: &str, extra: &str) -> String {
    format!(
        r#"{{{extra}"com.zer07labs.seam":{statement},"com.zer07labs.seam.seal-key-cert":{}}}"#,
        cert_member()
    )
}

/// Sign `header.payload` (both RAW JSON text, so a test can write duplicate keys) with the seal key.
fn mint(header: &str, payload: &str) -> String {
    use ed25519_dalek::Signer;
    let input = format!("{}.{}", b64(header.as_bytes()), b64(payload.as_bytes()));
    let sig = seal_key().sign(input.as_bytes());
    format!("{input}.{}", b64(&sig.to_bytes()))
}

const HEADER: &str = r#"{"alg":"EdDSA","typ":"aitp-tct+jwt"}"#;

/// The signed case's claims, re-assembled from parts so each test can vary exactly one.
fn claims(grants: &str, ext: &str) -> String {
    let aid = seal_aid();
    let jkt = seam_verify::commitment::jwk_thumbprint(seal_key().verifying_key().as_bytes());
    format!(
        r#"{{"aud":"{aid}","cnf":{{"jkt":"{jkt}"}},"exp":4913600000,"ext":{ext},"grants":{grants},"iat":{IAT},"iss":"{aid}","jti":"j","sub":"{aid}","ver":"aitp/0.3"}}"#
    )
}

fn signed_case() -> (String, [u8; 32]) {
    let v = load("commitment_digest_v5_signed_vector.json");
    let c = commitment(&v["cases"][2]["commitment"]);
    (
        v["issuer_aid"].as_str().unwrap().to_owned(),
        commitment_digest(&c).unwrap(),
    )
}

fn good_ext(d: &[u8; 32]) -> String {
    ext_of(
        &format!(
            r#"{{"commitment_digest":"{}","type":"seam:commitment"}}"#,
            hex(d)
        ),
        "",
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
                &ext_of(
                    &format!(
                        r#"{{"commitment_digest":"{}","type":"seam:commitment"}}"#,
                        hex(&d)
                    ),
                    r#""com.example":{},"#,
                ),
            ),
        ),
        (
            "an extra member in the binding",
            HEADER.into(),
            claims(
                GRANTS,
                &ext_of(
                    &format!(
                        r#"{{"commitment_digest":"{}","note":"x","type":"seam:commitment"}}"#,
                        hex(&d)
                    ),
                    "",
                ),
            ),
        ),
        (
            "a wrong type",
            HEADER.into(),
            claims(
                GRANTS,
                &ext_of(
                    &format!(
                        r#"{{"commitment_digest":"{}","type":"seam:other"}}"#,
                        hex(&d)
                    ),
                    "",
                ),
            ),
        ),
        (
            "an uppercase digest",
            HEADER.into(),
            claims(
                GRANTS,
                &ext_of(
                    &format!(
                        r#"{{"commitment_digest":"{}","type":"seam:commitment"}}"#,
                        hex(&d).to_uppercase()
                    ),
                    "",
                ),
            ),
        ),
        ("no ext", HEADER.into(), claims(GRANTS, "null")),
        (
            "a duplicate commitment_digest (first one wrong)",
            HEADER.into(),
            claims(
                GRANTS,
                &ext_of(
                    &format!(
                        r#"{{"commitment_digest":"{}","commitment_digest":"{}","type":"seam:commitment"}}"#,
                        "00".repeat(32),
                        hex(&d)
                    ),
                    "",
                ),
            ),
        ),
        (
            "a duplicate top-level claim",
            HEADER.into(),
            claims(GRANTS, &ext).replacen(
                r#""ver":"aitp/0.3""#,
                r#""ver":"aitp/0.3","ver":"aitp/0.3""#,
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
    let aid_pin = aid.clone();
    let aid = seal_aid();
    for field in ["sub", "aud"] {
        let p = claims(GRANTS, &ext).replacen(
            &format!(r#""{field}":"{aid}""#),
            &format!(r#""{field}":"{other}""#),
            1,
        );
        assert!(
            verify_tct(&aid_pin, &mint(HEADER, &p), &d, NOW).is_err(),
            "{field} != iss must be refused"
        );
    }
    let aid = aid_pin;

    // The digest must be THIS Commitment's v5 recompute: a token binding a different digest is refused.
    let mut wrong = d;
    wrong[0] ^= 1;
    assert!(verify_tct(&aid, &mint(HEADER, &claims(GRANTS, &ext)), &wrong, NOW).is_err());
}
