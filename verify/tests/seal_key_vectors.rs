//! Deep-cleanup S-4 (seam-runtime #2031, runtime 0.123.0): the seal-key certificate and the commitment TCT
//! it roots, against `../conformance/seal_key_cert_vector.json` (the runtime's own vector, byte-identical)
//! and `seam-runtime/docs/specs/seam-commitment-digest.v6.md` §Seal key.
//!
//! Every refusal is minted here from a control token that verifies, and changes ONE thing.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use seam_verify::commitment::{
    commitment_digest, jwk_thumbprint, parse_seal_key_cert, tct_jti, verify_seal_key_cert,
    verify_tct, verify_tct_sealed_at, Commitment, SEAL_KEY_MAX_WINDOW_MS,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const NOW: u64 = 1_800_000_000;

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

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

fn aid_of(k: &SigningKey) -> String {
    format!("aid:pubkey:{}", b64(k.verifying_key().as_bytes()))
}

fn cert_bytes(seal_pk: &[u8], nb: u64, na: u64, issuer_aid: &str) -> Vec<u8> {
    let mut c = Vec::new();
    for (i, part) in [
        &b"seam.seal-key-cert.v1"[..],
        seal_pk,
        &[],
        issuer_aid.as_bytes(),
    ]
    .into_iter()
    .enumerate()
    {
        if i == 2 {
            c.extend_from_slice(&nb.to_le_bytes());
            c.extend_from_slice(&na.to_le_bytes());
            continue;
        }
        c.extend_from_slice(&(part.len() as u32).to_le_bytes());
        c.extend_from_slice(part);
    }
    c
}

/// One minted commitment TCT and what to vary in it.
struct Mint {
    issuer: SigningKey,
    seal: SigningKey,
    /// The key that signs the JWS (the seal key unless a test says otherwise).
    signer: Option<SigningKey>,
    nb: u64,
    na: u64,
    iat: u64,
    /// The AID the certificate names (the issuer's unless a test says otherwise).
    cert_aid: Option<String>,
    /// Appended to the certificate bytes.
    trailing: Vec<u8>,
    /// The `ext` certificate member, overriding the real one.
    member: Option<Value>,
    /// Extra `ext` members.
    extra_ext: Option<(String, Value)>,
    /// `iss == sub == aud`, overriding the seal AID.
    self_aid: Option<String>,
    /// The `jti` claim: the seal path's `tct_jti(RECORD, iat * 1000)` unless a test says otherwise.
    jti: String,
}

fn commitment() -> Commitment {
    Commitment {
        id: "c-s4".into(),
        action: "BLOCK".into(),
        authority: "treasury".into(),
        supersedes: None,
        auth_method: "pinned-key".into(),
        trust_basis: "attested".into(),
        committer: String::new(),
        explanation: vec![],
        selection_digest: None,
        certificate_digest: None,
        governing_doc_sha256: None,
        signed_artifact: String::new(),
    }
}

const IAT: u64 = 1_700_000_000;
/// The record the minted tokens seal into (the `jti` derivation input).
const RECORD: &str = "dec:acme:s-seal-key-vector-0000";

fn base() -> Mint {
    Mint {
        issuer: SigningKey::from_bytes(&[7; 32]),
        seal: SigningKey::from_bytes(&[0x5e; 32]),
        signer: None,
        nb: IAT * 1000 - 30_000,
        na: IAT * 1000 + 870_000,
        iat: IAT,
        cert_aid: None,
        trailing: vec![],
        member: None,
        extra_ext: None,
        self_aid: None,
        jti: tct_jti(RECORD, (IAT * 1000) as i64).unwrap(),
    }
}

impl Mint {
    fn issuer_aid(&self) -> String {
        aid_of(&self.issuer)
    }

    fn cert(&self) -> Vec<u8> {
        let aid = self.cert_aid.clone().unwrap_or_else(|| self.issuer_aid());
        let mut c = cert_bytes(self.seal.verifying_key().as_bytes(), self.nb, self.na, &aid);
        c.extend_from_slice(&self.trailing);
        c
    }

    fn token(&self) -> String {
        let cert = self.cert();
        let member = self.member.clone().unwrap_or_else(|| {
            json!({"cert": b64(&cert), "sig": b64(&self.issuer.sign(&Sha256::digest(&cert)).to_bytes())})
        });
        let seal_aid = self.self_aid.clone().unwrap_or_else(|| aid_of(&self.seal));
        let d = commitment_digest(&commitment()).unwrap();
        let mut ext = json!({
            "com.zer07labs.seam": {"commitment_digest": hex(&d), "type": "seam:commitment"},
            "com.zer07labs.seam.seal-key-cert": member,
        });
        if let Some((k, v)) = &self.extra_ext {
            ext[k] = v.clone();
        }
        let claims = json!({
            "aud": seal_aid, "iss": seal_aid, "sub": seal_aid,
            "cnf": {"jkt": jwk_thumbprint(self.seal.verifying_key().as_bytes())},
            "exp": 4_853_600_000u64, "iat": self.iat, "jti": self.jti, "ver": "aitp/0.3",
            "grants": ["aitp.attestation"], "ext": ext,
        });
        let input = format!(
            "{}.{}",
            b64(br#"{"alg":"EdDSA","typ":"aitp-tct+jwt"}"#),
            b64(claims.to_string().as_bytes())
        );
        let signer = self.signer.as_ref().unwrap_or(&self.seal);
        format!("{input}.{}", b64(&signer.sign(input.as_bytes()).to_bytes()))
    }

    fn verify(&self) -> Result<(), String> {
        let d = commitment_digest(&commitment()).unwrap();
        verify_tct(&self.issuer_aid(), &self.token(), &d, NOW)
    }
}

#[test]
fn the_seal_key_cert_vector_rebuilds_and_verifies() {
    let v = load("seal_key_cert_vector.json");
    let s = |k: &str| v[k].as_str().unwrap().to_owned();
    let n = |k: &str| v[k].as_u64().unwrap();
    let issuer = SigningKey::from_bytes(&unhex(&s("issuer_seed_hex")).try_into().unwrap());
    let seal = SigningKey::from_bytes(&unhex(&s("seal_seed_hex")).try_into().unwrap());
    assert_eq!(aid_of(&issuer), s("issuer_aid"));
    assert_eq!(hex(seal.verifying_key().as_bytes()), s("seal_pk_hex"));
    assert_eq!(s("domain"), "seam.seal-key-cert.v1");

    let cert = unhex(&s("cert_hex"));
    let sig = unhex(&s("sig_hex"));
    assert_eq!(
        cert,
        cert_bytes(
            seal.verifying_key().as_bytes(),
            n("not_before_ms"),
            n("not_after_ms"),
            &s("issuer_aid")
        ),
        "the framing reproduces the vector's certificate"
    );
    assert_eq!(hex(&Sha256::digest(&cert)), s("cert_digest_hex"));
    assert_eq!(v["ext_member"]["cert"], b64(&cert));
    assert_eq!(v["ext_member"]["sig"], b64(&sig));

    let f = verify_seal_key_cert(&s("issuer_aid"), &cert, &sig).expect("verifies under the pin");
    assert_eq!(f, parse_seal_key_cert(&cert).unwrap());
    assert_eq!(f.seal_aid(), s("seal_aid"));
    assert_eq!(f.not_before_ms, n("not_before_ms"));
    assert_eq!(f.not_after_ms, n("not_after_ms"));

    let other = aid_of(&SigningKey::from_bytes(&[8; 32]));
    assert!(verify_seal_key_cert(&other, &cert, &sig).is_err());
    for i in 0..cert.len() {
        let mut bad = cert.clone();
        bad[i] ^= 1;
        assert!(
            verify_seal_key_cert(&s("issuer_aid"), &bad, &sig).is_err(),
            "cert byte {i}"
        );
    }
    for i in 0..sig.len() {
        let mut bad = sig.clone();
        bad[i] ^= 1;
        assert!(
            verify_seal_key_cert(&s("issuer_aid"), &cert, &bad).is_err(),
            "sig byte {i}"
        );
    }
}

#[test]
fn the_control_token_verifies() {
    base().verify().expect("the control token must verify");
}

#[test]
fn an_issuer_signed_tct_is_refused() {
    // The pre-0.123.0 shape: signed by the issuer, iss == sub == aud == issuer, no certificate member.
    let m = base();
    let d = commitment_digest(&commitment()).unwrap();
    let aid = m.issuer_aid();
    let claims = json!({
        "aud": aid, "iss": aid, "sub": aid,
        "cnf": {"jkt": jwk_thumbprint(m.issuer.verifying_key().as_bytes())},
        "exp": 4_853_600_000u64, "iat": IAT, "jti": "j", "ver": "aitp/0.3",
        "grants": ["aitp.attestation"],
        "ext": {"com.zer07labs.seam": {"commitment_digest": hex(&d), "type": "seam:commitment"}},
    });
    let input = format!(
        "{}.{}",
        b64(br#"{"alg":"EdDSA","typ":"aitp-tct+jwt"}"#),
        b64(claims.to_string().as_bytes())
    );
    let t = format!(
        "{input}.{}",
        b64(&m.issuer.sign(input.as_bytes()).to_bytes())
    );
    let e = verify_tct(&aid, &t, &d, NOW).unwrap_err();
    assert!(e.contains("seal-key-cert"), "{e}");
    // Signed by the issuer key with a real certificate attached is still not the seal key's signature.
    let m = Mint {
        signer: Some(SigningKey::from_bytes(&[7; 32])),
        ..base()
    };
    assert!(m.verify().is_err());
}

#[test]
fn the_window_cap_is_exact() {
    let at = IAT * 1000;
    let ok = Mint {
        nb: at,
        na: at + SEAL_KEY_MAX_WINDOW_MS,
        ..base()
    };
    ok.verify().expect("exactly the cap verifies");
    let wide = Mint {
        nb: at,
        na: at + SEAL_KEY_MAX_WINDOW_MS + 1,
        ..base()
    };
    assert!(wide.verify().is_err(), "one ms over the cap");
    assert_eq!(SEAL_KEY_MAX_WINDOW_MS, 3_630_000);
    let inverted = Mint {
        nb: at + 1,
        na: at,
        ..base()
    };
    assert!(inverted.verify().is_err());
    assert!(parse_seal_key_cert(&cert_bytes(&[7; 32], 0, i64::MAX as u64, "a")).is_none());
    assert!(parse_seal_key_cert(&cert_bytes(&[7; 32], u64::MAX - 5, u64::MAX, "a")).is_none());
}

#[test]
fn iat_must_lie_in_the_window_with_no_grace() {
    let at = IAT * 1000;
    let w = |nb: u64, na: u64| Mint { nb, na, ..base() };
    w(at, at + 1000).verify().expect("iat·1000 == not_before");
    w(at - 1000, at).verify().expect("iat·1000 == not_after");
    assert!(
        w(at + 1, at + 900_000).verify().is_err(),
        "iat before the window"
    );
    assert!(
        w(at - 900_000, at - 1).verify().is_err(),
        "iat after the window"
    );
    assert!(
        w(at + 1000, at + 2000).verify().is_err(),
        "one second early"
    );
    assert!(w(at - 2000, at - 1000).verify().is_err(), "one second late");
}

#[test]
fn the_certificate_must_name_the_pinned_issuer() {
    let other = SigningKey::from_bytes(&[8; 32]);
    // Signed by the pinned issuer, naming another AID.
    let named_other = Mint {
        cert_aid: Some(aid_of(&other)),
        ..base()
    };
    assert!(named_other.verify().is_err());
    // A forger certifies the seal key under their own AID, with their own key.
    let forged = Mint {
        issuer: other,
        ..base()
    };
    let d = commitment_digest(&commitment()).unwrap();
    let pinned = aid_of(&SigningKey::from_bytes(&[7; 32]));
    assert!(verify_tct(&pinned, &forged.token(), &d, NOW).is_err());
    assert!(
        forged.verify().is_ok(),
        "control: it verifies under its own pin"
    );
    // The tagged spelling of the pinned key is a different AID string: the compare is exact.
    let tagged = Mint {
        cert_aid: Some(
            base()
                .issuer_aid()
                .replace("aid:pubkey:", "aid:pubkey:ed25519:"),
        ),
        ..base()
    };
    assert!(tagged.verify().is_err());
}

#[test]
fn the_certificate_member_and_ext_shape_are_exact() {
    let m = base();
    let cert = m.cert();
    let sig = m.issuer.sign(&Sha256::digest(&cert)).to_bytes();
    let cases = [
        (
            "a third member",
            json!({"cert": b64(&cert), "sig": b64(&sig), "x": 1}),
        ),
        ("sig missing", json!({"cert": b64(&cert)})),
        (
            "padded base64",
            json!({"cert": format!("{}=", b64(&cert)), "sig": b64(&sig)}),
        ),
        (
            "standard base64",
            json!({"cert": base64::engine::general_purpose::STANDARD.encode(&cert), "sig": b64(&sig)}),
        ),
        ("not a string", json!({"cert": 1, "sig": b64(&sig)})),
        ("not an object", json!([b64(&cert), b64(&sig)])),
    ];
    for (what, member) in cases {
        let t = Mint {
            member: Some(member),
            ..base()
        };
        assert!(t.verify().is_err(), "{what}");
    }
    // A certificate for another seal key than the one that signed the token.
    let other_seal = SigningKey::from_bytes(&[0x5f; 32]);
    let c2 = cert_bytes(
        other_seal.verifying_key().as_bytes(),
        m.nb,
        m.na,
        &m.issuer_aid(),
    );
    let other_member =
        json!({"cert": b64(&c2), "sig": b64(&m.issuer.sign(&Sha256::digest(&c2)).to_bytes())});
    assert!(Mint {
        member: Some(other_member),
        ..base()
    }
    .verify()
    .is_err());
    // A token claiming the issuer (not the seal key) as its subject.
    assert!(Mint {
        self_aid: Some(base().issuer_aid()),
        ..base()
    }
    .verify()
    .is_err());
    // An extra ext namespace.
    assert!(Mint {
        extra_ext: Some(("com.example".into(), json!({}))),
        ..base()
    }
    .verify()
    .is_err());
}

#[test]
fn trailing_certificate_bytes_are_refused() {
    assert!(Mint {
        trailing: vec![0],
        ..base()
    }
    .verify()
    .is_err());
}

/// `verify_strict`: a signature whose R is a small-order point is refused even where the cofactorless
/// equation would hold; the identity encoding is the simplest one.
#[test]
fn a_small_order_r_is_refused() {
    let m = base();
    let cert = m.cert();
    let mut sig = m.issuer.sign(&Sha256::digest(&cert)).to_bytes();
    sig[..32].copy_from_slice(&{
        let mut r = [0u8; 32];
        r[0] = 1;
        r
    });
    assert!(verify_seal_key_cert(&m.issuer_aid(), &cert, &sig).is_err());
}

/// Evidence grade: `iat == floor(sealed_at / 1000)` of the chained `DECISION_SEALED`.
#[test]
fn the_evidence_grade_check_binds_iat_to_the_chained_seal_time() {
    let m = base();
    let d = commitment_digest(&commitment()).unwrap();
    let t = m.token();
    let pin = m.issuer_aid();
    let ms = IAT * 1000;
    verify_tct_sealed_at(&pin, &t, &d, NOW, RECORD, ms).unwrap();
    assert!(verify_tct_sealed_at(&pin, &t, &d, NOW, RECORD, ms + 1000).is_err());
    assert!(verify_tct_sealed_at(&pin, &t, &d, NOW, RECORD, ms - 1).is_err());
}

/// Evidence grade, P4: the `jti` must be `tct_jti` over the CHAINED record's `decision_id` and exact
/// `sealed_at`. A genuine seal replayed onto another record, or with its seal time shifted inside its
/// second (same `iat`), is refused.
#[test]
fn a_genuine_seal_replayed_onto_another_record_is_refused() {
    let m = base();
    let d = commitment_digest(&commitment()).unwrap();
    let t = m.token();
    let pin = m.issuer_aid();
    let ms = IAT * 1000;
    verify_tct_sealed_at(&pin, &t, &d, NOW, RECORD, ms).unwrap();
    for (id, at, why) in [
        ("dec:acme:s-other-record", ms, "another decision_id"),
        (RECORD, ms + 999, "the seal time shifted inside its second"),
        ("", ms, "no decision_id"),
    ] {
        let e = verify_tct_sealed_at(&pin, &t, &d, NOW, id, at).unwrap_err();
        assert!(
            e.contains("seals a different record") && e.contains("jti"),
            "{why}"
        );
    }
    // A token whose `jti` is not the derivation at all (an AITP-valid random v4) is refused too.
    let mut other = base();
    other.jti = "00000000-0000-4000-8000-000000000000".into();
    let e = verify_tct_sealed_at(&pin, &other.token(), &d, NOW, RECORD, ms).unwrap_err();
    assert!(e.contains("seals a different record"), "a random v4 jti");
    // The plain (non-evidence-grade) check does not read the jti, per RFC-AITP-0005 §2.2.
    assert!(other.verify().is_ok());
}
