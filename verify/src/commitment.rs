//! The Commitment and its rooted TCT: `seam-commitment-digest:v3`, `seam-explanation-digest:v1`, and
//! the self-attestation `aitp-tct+jwt` that carries the digest in its `ext` claim.
//!
//! Written from `seam-runtime/docs/specs/seam-commitment-digest.v3.md` (not vendored here; the
//! evidence-bundle spec in `docs/evidence-bundle.v1.md` cites it) and pinned by
//! `conformance/commitment_digest_v3_vector.json` (three cases, one a real TCT from the real signer)
//! and by `conformance/vectors.json`'s `tct` block. The five SDK crypto shims implement the same
//! framing; this is a sixth port, from the same text, linking none of them.
//!
//! **Where the digest travels.** The TCT is an AITP self-attestation: `grants` is exactly
//! `["aitp.attestation"]` and the digest rides in `ext["com.zer07labs.seam"]`. The pinned spec's own
//! "Where the digest travels" section still describes the retired two-grant form; the vectors are the
//! source of truth for the token's shape, and they carry the `ext` form.
//!
//! Framing, unlike the record digest's: `F(x) = be64(len(x)) ‖ x` — **big-endian, 8-byte** lengths.
//!
//! **Why every field is length-prefixed, and why that must never be "simplified".** The fields are
//! arbitrary text, and UTF-8 permits `U+0000`. With a NUL separator instead of a length prefix, the
//! tuples `("a\0b", "c")` and `("a", "b\0c")` would collide on one preimage, so one Commitment would
//! verify under another's TCT. The explanation list is counted for the same reason: no entry can
//! migrate across a boundary without changing the bytes.

use sha2::{Digest, Sha256};

/// The `kind` words the explanation digest frames — lowercase ASCII, exactly; never the proto enum name.
pub const EXPLANATION_KINDS: &[&str] = &["vote", "evaluation", "objection", "ballot"];

/// The TCT protocol version a Seam-minted TCT carries (`aitp/0.2`).
pub const TCT_VER: &str = "aitp/0.2";

/// One sealed explanation entry, in the shape the digest reads it.
#[derive(Clone, Debug, PartialEq)]
pub struct ExplanationEntry {
    pub kind: String,
    pub participant: String,
    pub proposal_id: String,
    pub value: String,
    pub reason: String,
    /// `None` = the evaluator declined to claim. NOT the same bytes as `Some(0.0)`.
    pub confidence: Option<f64>,
    pub rationale_ref: Option<String>,
}

/// A Commitment as the v3 framing reads it, plus its TCT.
#[derive(Clone, Debug, PartialEq)]
pub struct Commitment {
    pub id: String,
    pub action: String,
    pub authority: String,
    pub supersedes: Option<String>,
    pub auth_method: String,
    pub trust_basis: String,
    pub committer: String,
    pub explanation: Vec<ExplanationEntry>,
    /// The compact-JWS TCT. Empty only for a record sealed under `identity: local-sealed`.
    pub signed_artifact: String,
}

fn be64_frame(h: &mut Sha256, x: &[u8]) {
    h.update((x.len() as u64).to_be_bytes());
    h.update(x);
}

/// `seam-explanation-digest:v1` over entries in sealed order. Refuses (never hashes) an unknown kind
/// or a non-canonical confidence: NaN, infinite, outside `[0.0, 1.0]`, or `-0.0`.
pub fn explanation_digest(entries: &[ExplanationEntry]) -> Result<[u8; 32], String> {
    let mut h = Sha256::new();
    be64_frame(&mut h, b"seam-explanation-digest:v1");
    h.update((entries.len() as u64).to_be_bytes());
    for (i, e) in entries.iter().enumerate() {
        if !EXPLANATION_KINDS.contains(&e.kind.as_str()) {
            return Err(format!("explanation[{i}]: unknown kind {:?}", e.kind));
        }
        be64_frame(&mut h, e.kind.as_bytes());
        be64_frame(&mut h, e.participant.as_bytes());
        be64_frame(&mut h, e.proposal_id.as_bytes());
        be64_frame(&mut h, e.value.as_bytes());
        be64_frame(&mut h, e.reason.as_bytes());
        match e.confidence {
            None => h.update([0u8]),
            Some(c) => {
                if !c.is_finite() || !(0.0..=1.0).contains(&c) || c.is_sign_negative() {
                    return Err(format!(
                        "explanation[{i}]: confidence {c:?} is not a canonical value in [0.0, 1.0]"
                    ));
                }
                h.update([1u8]);
                h.update(c.to_bits().to_be_bytes());
            }
        }
        match &e.rationale_ref {
            None => h.update([0u8]),
            Some(r) => {
                h.update([1u8]);
                be64_frame(&mut h, r.as_bytes());
            }
        }
    }
    Ok(h.finalize().into())
}

/// The domain tag, field 0 of the commitment-digest preimage.
pub const COMMITMENT_DIGEST_DOMAIN: &[u8] = b"seam-commitment-digest:v3";

/// `seam-commitment-digest:v3`: SHA-256 over nine fields in the spec's order, each `F`-framed except
/// field 4. `supersedes` carries a presence byte — absent is `0x00`, present is `0x01 ‖ F(value)` — so
/// an absent prior and a present empty one are different digests. Field 8 is the 32 RAW bytes of the
/// explanation digest.
pub fn commitment_digest(c: &Commitment) -> Result<[u8; 32], String> {
    let explanation = explanation_digest(&c.explanation)?;
    let mut h = Sha256::new();
    for field in [
        COMMITMENT_DIGEST_DOMAIN,
        c.id.as_bytes(),
        c.action.as_bytes(),
        c.authority.as_bytes(),
    ] {
        be64_frame(&mut h, field);
    }
    match &c.supersedes {
        None => h.update([0u8]),
        Some(s) => {
            h.update([1u8]);
            be64_frame(&mut h, s.as_bytes());
        }
    }
    for field in [
        c.auth_method.as_bytes(),
        c.trust_basis.as_bytes(),
        c.committer.as_bytes(),
        explanation.as_slice(),
    ] {
        be64_frame(&mut h, field);
    }
    Ok(h.finalize().into())
}

/// The RFC 7638 JWK thumbprint of an Ed25519 key, pinned to the AITP input
/// `{"crv":"Ed25519","kty":"OKP","x":"<b64url key>"}` (members sorted, no whitespace), b64url-unpadded.
pub fn jwk_thumbprint(key: &[u8; 32]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let jwk = format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
        b64.encode(key)
    );
    b64.encode(Sha256::digest(jwk.as_bytes()))
}

/// The only grant a Seam commitment TCT carries: it is an AITP self-attestation, not a delegation.
pub const ATTESTATION_GRANT: &str = "aitp.attestation";

/// The `ext` namespace the commitment binding lives under.
pub const EXT_NAMESPACE: &str = "com.zer07labs.seam";

/// The `type` inside [`EXT_NAMESPACE`] that marks a commitment binding.
pub const EXT_TYPE: &str = "seam:commitment";

/// Parse JSON into a `Value`, REFUSING a duplicate object key at any depth.
///
/// `serde_json::Value` keeps the last of two equal keys silently. In a signed token that is a
/// parser-differential hole: the signature covers both members, and a consumer that keeps the FIRST
/// would read a different digest from the same bytes than this verifier does. So the token's claims
/// are parsed strictly and a duplicate is a refusal, never a choice.
fn parse_no_duplicate_keys(bytes: &[u8]) -> Result<serde_json::Value, String> {
    use serde::de::{DeserializeSeed, Deserializer, Error, MapAccess, SeqAccess, Visitor};
    use std::fmt;

    struct Strict;
    impl<'de> DeserializeSeed<'de> for Strict {
        type Value = serde_json::Value;
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Strict {
        type Value = serde_json::Value;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a JSON value")
        }
        fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
            Ok(v.into())
        }
        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
            Ok(v.into())
        }
        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
            Ok(v.into())
        }
        fn visit_f64<E: Error>(self, v: f64) -> Result<Self::Value, E> {
            serde_json::Number::from_f64(v)
                .map(serde_json::Value::Number)
                .ok_or_else(|| E::custom("a non-finite number"))
        }
        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
            Ok(v.into())
        }
        fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
            Ok(v.into())
        }
        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(serde_json::Value::Null)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(v) = a.next_element_seed(Strict)? {
                out.push(v);
            }
            Ok(out.into())
        }
        fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
            let mut out = serde_json::Map::new();
            while let Some(k) = a.next_key::<String>()? {
                if out.contains_key(&k) {
                    return Err(A::Error::custom(format!("duplicate key {k:?}")));
                }
                let v = a.next_value_seed(Strict)?;
                out.insert(k, v);
            }
            Ok(out.into())
        }
    }

    let mut de = serde_json::Deserializer::from_slice(bytes);
    let v = Strict.deserialize(&mut de).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(v)
}

/// Verify a Seam-minted self-attestation TCT against a **pinned** issuer AID, and that it roots
/// exactly the Commitment whose digest is `digest`.
///
/// Checks, all fail-closed: exactly three non-empty compact-JWS segments, each strict unpadded
/// base64url; header `typ == "aitp-tct+jwt"` and `alg == "EdDSA"`; the Ed25519 signature over
/// `header.payload` under the pinned key; claims parsed with duplicate keys REFUSED; `ver ==
/// "aitp/0.2"`, `iss == aud == sub == pinned`; `iat <= now <= exp` (integer seconds); `cnf.jkt` is
/// the thumbprint of the subject's key; `grants` is exactly `["aitp.attestation"]`; and `ext` is
/// exactly `{"com.zer07labs.seam":{"type":"seam:commitment","commitment_digest":"<hex>"}}` — no other
/// namespace, no other member — with `<hex>` the lowercase hex of `digest`.
pub fn verify_tct(
    pinned_aid: &str,
    token: &str,
    digest: &[u8; 32],
    now_secs: u64,
) -> Result<(), String> {
    use base64::Engine;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let parts: Vec<&str> = token.split('.').collect();
    let [h64, p64, s64] = parts.as_slice() else {
        return Err("the TCT is not a compact JWS (three segments)".into());
    };
    if h64.is_empty() || p64.is_empty() || s64.is_empty() {
        return Err("the TCT has an empty JWS segment".into());
    }
    let seg = |s: &str, what: &str| {
        b64.decode(s)
            .map_err(|e| format!("the TCT's {what} segment is not base64url: {e}"))
    };
    let header = parse_no_duplicate_keys(&seg(h64, "header")?)
        .map_err(|e| format!("the TCT header is not strict JSON: {e}"))?;
    let payload_bytes = seg(p64, "payload")?;
    let sig: [u8; 64] = seg(s64, "signature")?
        .try_into()
        .map_err(|_| "the TCT signature is not 64 bytes".to_string())?;
    if header.get("typ").and_then(|v| v.as_str()) != Some("aitp-tct+jwt") {
        return Err("the TCT header's typ is not aitp-tct+jwt".into());
    }
    if header.get("alg").and_then(|v| v.as_str()) != Some("EdDSA") {
        return Err("the TCT header's alg is not EdDSA".into());
    }

    let key = crate::verify::aid_to_key(pinned_aid)?;
    let vk = VerifyingKey::from_bytes(&key).map_err(|e| format!("bad issuer key: {e}"))?;
    let signing_input = &token.as_bytes()[..h64.len() + 1 + p64.len()];
    vk.verify(signing_input, &Signature::from_bytes(&sig))
        .map_err(|_| "the TCT signature does not verify against the pinned issuer".to_string())?;

    let claims = parse_no_duplicate_keys(&payload_bytes)
        .map_err(|e| format!("the TCT payload is not strict JSON: {e}"))?;
    if !claims.is_object() {
        return Err("the TCT payload is not a JSON object".into());
    }
    let s = |k: &str| claims.get(k).and_then(|v| v.as_str());
    if s("ver") != Some(TCT_VER) {
        return Err(format!("the TCT's ver is not {TCT_VER}"));
    }
    if s("iss") != Some(pinned_aid) {
        return Err("the TCT's iss is not the pinned issuer".into());
    }
    if s("aud") != Some(pinned_aid) || s("sub") != Some(pinned_aid) {
        return Err("the TCT is not self-issued to the pinned issuer (aud/sub)".into());
    }
    let n = |k: &str| claims.get(k).and_then(|v| v.as_u64());
    let (Some(iat), Some(exp)) = (n("iat"), n("exp")) else {
        return Err("the TCT's iat/exp are not integer seconds".into());
    };
    if exp < now_secs {
        return Err(format!("the TCT expired at {exp} (now {now_secs})"));
    }
    if iat > now_secs {
        return Err(format!("the TCT is not valid until {iat} (now {now_secs})"));
    }
    if claims.pointer("/cnf/jkt").and_then(|v| v.as_str()) != Some(jwk_thumbprint(&key).as_str()) {
        return Err("the TCT's cnf.jkt is not the thumbprint of the issuer key".into());
    }
    if claims.get("grants") != Some(&serde_json::json!([ATTESTATION_GRANT])) {
        return Err(format!(
            "the TCT's grants are not exactly [\"{ATTESTATION_GRANT}\"] (a commitment TCT is a \
             self-attestation and carries no other grant)"
        ));
    }
    let Some(ext) = claims.get("ext").and_then(|e| e.as_object()) else {
        return Err("the TCT carries no ext object".into());
    };
    if ext.len() != 1 {
        return Err(format!(
            "the TCT's ext carries a namespace other than {EXT_NAMESPACE} (exactly one is allowed)"
        ));
    }
    let Some(binding) = ext.get(EXT_NAMESPACE).and_then(|b| b.as_object()) else {
        return Err(format!("the TCT's ext has no {EXT_NAMESPACE} object"));
    };
    if binding.len() != 2 || binding.get("type").and_then(|t| t.as_str()) != Some(EXT_TYPE) {
        return Err(format!(
            "the TCT's ext.{EXT_NAMESPACE} is not exactly {{\"type\":\"{EXT_TYPE}\",\
             \"commitment_digest\":…}}"
        ));
    }
    let want = crate::verify::hex(digest);
    if binding.get("commitment_digest").and_then(|d| d.as_str()) != Some(want.as_str()) {
        return Err(
            "the TCT's ext does not bind this Commitment's seam-commitment-digest:v3 (forged \
             token, or an edited field)"
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        crate::verify::hex(b)
    }

    /// Spec § The explanation digest: `explanation_digest([])`.
    #[test]
    fn empty_explanation_matches_the_spec() {
        assert_eq!(
            hex(&explanation_digest(&[]).unwrap()),
            "eb7853dc086ef5385db8408cf35c9c984e845ccc03d269102f942eed7806ce40"
        );
    }

    fn empty_commitment() -> Commitment {
        Commitment {
            id: String::new(),
            action: String::new(),
            authority: String::new(),
            supersedes: None,
            auth_method: String::new(),
            trust_basis: String::new(),
            committer: String::new(),
            explanation: vec![],
            signed_artifact: String::new(),
        }
    }

    /// `commitment_digest_v3_vector.json` case `all_empty`, inlined so a packaged crate tests it.
    #[test]
    fn all_empty_commitment_matches_the_vector() {
        assert_eq!(
            hex(&commitment_digest(&empty_commitment()).unwrap()),
            "9238441205cd395f9507a5152e2c67f93fa83ca8d336d2ce7b8e01a385c3dd2e"
        );
    }

    /// Case `empty_supersedes`: a present empty prior is `0x01 ‖ be64(0)`, never the absent `0x00`.
    #[test]
    fn empty_supersedes_is_not_absent_supersedes() {
        let mut c = empty_commitment();
        c.supersedes = Some(String::new());
        assert_eq!(
            hex(&commitment_digest(&c).unwrap()),
            "b7f0e7a2a14e91f0d7dc1a56781a39f7601bce4df979f3b25a58aa9d86d3263c"
        );
    }

    /// The domain literal the cross-language framing test greps for.
    #[test]
    fn the_domain_tag_is_v3() {
        assert_eq!(COMMITMENT_DIGEST_DOMAIN, b"seam-commitment-digest:v3");
    }

    #[test]
    fn a_duplicate_key_is_refused_at_any_depth() {
        assert!(parse_no_duplicate_keys(br#"{"a":1,"a":1}"#).is_err());
        assert!(parse_no_duplicate_keys(br#"{"x":{"y":[{"z":1,"z":2}]}}"#).is_err());
        assert!(parse_no_duplicate_keys(br#"{"a":1} trailing"#).is_err());
        assert_eq!(
            parse_no_duplicate_keys(br#"{"a":[1,2.5,"s",null,true],"b":{}}"#).unwrap(),
            serde_json::json!({"a":[1,2.5,"s",null,true],"b":{}})
        );
    }

    fn entry(conf: Option<f64>) -> ExplanationEntry {
        ExplanationEntry {
            kind: "evaluation".into(),
            participant: "p".into(),
            proposal_id: "x".into(),
            value: "v".into(),
            reason: String::new(),
            confidence: conf,
            rationale_ref: None,
        }
    }

    /// Absent is not zero — the reason the digest exists.
    #[test]
    fn absent_confidence_is_not_zero() {
        assert_ne!(
            explanation_digest(&[entry(None)]).unwrap(),
            explanation_digest(&[entry(Some(0.0))]).unwrap()
        );
    }

    #[test]
    fn non_canonical_confidence_and_unknown_kind_are_refused_not_hashed() {
        for bad in [f64::NAN, f64::INFINITY, -0.0, 1.5, -0.1] {
            assert!(explanation_digest(&[entry(Some(bad))]).is_err(), "{bad:?}");
        }
        let mut e = entry(None);
        e.kind = "EXPLANATION_KIND_EVALUATION".into();
        assert!(explanation_digest(&[e]).is_err());
    }
}
