//! The Commitment and its rooted TCT: `seam-commitment-digest:v5`, `seam-explanation-digest:v2`, and
//! the self-attestation `aitp-tct+jwt` that carries the digest in its `ext` claim.
//!
//! Written from `seam-runtime/docs/specs/seam-commitment-digest.v5.md` and the v4 text it extends (not
//! vendored here; the evidence-bundle spec in `docs/evidence-bundle.v1.md` cites it) and pinned by
//! `conformance/commitment_digest_v5_signed_vector.json` (seven cases, two of them real TCTs from the
//! real signer, one governed and one not, and three exercising the field 9/10 slots),
//! `conformance/commitment_digest_v5_vector.json` (the field 11 slot cases) and `conformance/vectors.json`'s
//! `tct` block. v5 (seam-runtime #1711) adds field 11, `governing_doc_sha256`: the SHA-256 of the tenant
//! governing document, a presence slot like fields 9 and 10. Since v4 (seam-runtime
//! #1687, D-045): every vote, ballot and objection entry carries a sealed voter verification record (`VV`,
//! framed into the explanation digest), and fields 9 (selection) and 10 (Gate certificate) are
//! always-framed presence slots after the explanation digest. The record's own signature is re-checked
//! by [`crate::voter`]. The five SDK crypto shims implement the same
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

/// The TCT protocol version a Seam-minted TCT carries (`aitp/0.3`, AITP 0.17.0). Strict: AITP
/// 0.17.0 cut over with no dual-accept, so an `aitp/0.2` TCT — any record sealed before the
/// runtime's 0.17.0 deploy — is refused. That is a history boundary by design.
pub const TCT_VER: &str = "aitp/0.3";

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
    /// The sealed voter verification record (#1687): present on every `vote`, `ballot` and `objection`
    /// the runtime seals, absent on an `evaluation`. Framed as `VV` into `seam-explanation-digest:v2`.
    pub voter_verification: Option<VoterVerification>,
}

/// The method words a `VV` block may frame — lowercase ASCII, exactly. `cp_signed` is declared by the
/// spec but not yet served: it digests, and [`crate::voter`] refuses to re-check it.
pub const VOTER_METHODS: &[&str] = &["pop", "cp_signed"];

/// A sealed voter verification record (`voter-verification.v1.md` § The sealed record), field for field.
#[derive(Clone, Debug, PartialEq)]
pub struct VoterVerification {
    /// `pop` or `cp_signed`.
    pub method: String,
    /// The signer AID.
    pub principal: String,
    /// The 32 raw bytes of `seam-vote-content-v1` (a different length is refused, not hashed).
    pub content_digest: Vec<u8>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub signature: Vec<u8>,
    /// Empty for `pop`.
    pub signer_certificate: Vec<u8>,
    pub tenant: String,
    pub namespace: String,
    pub session_id: String,
    /// `0` on the one-shot `RunDecision` path.
    pub opened_at_millis: u64,
    pub issuer: String,
    pub audience: String,
    pub accepted_at_ms: u64,
}

/// A Commitment as the v5 framing reads it, plus its TCT.
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
    /// Field 9, the selection block's digest. `None` on every record this release seals.
    pub selection_digest: Option<Vec<u8>>,
    /// Field 10, the Gate certificate digest. `None` on every record this release seals.
    pub certificate_digest: Option<Vec<u8>>,
    /// Field 11 (v5, seam-runtime#1711): the SHA-256 of the tenant governing document the decision was
    /// governed by. `None` on an ungoverned record; a present value must be 32 bytes.
    pub governing_doc_sha256: Option<Vec<u8>>,
    /// The compact-JWS TCT. Empty only for a record sealed under `identity: local-sealed`.
    pub signed_artifact: String,
}

fn be64_frame(h: &mut Sha256, x: &[u8]) {
    h.update((x.len() as u64).to_be_bytes());
    h.update(x);
}

/// The explanation digest's domain tag.
pub const EXPLANATION_DIGEST_DOMAIN: &[u8] = b"seam-explanation-digest:v2";

/// `seam-explanation-digest:v2` over entries in sealed order. Refuses (never hashes) an unknown kind,
/// a non-canonical confidence (NaN, infinite, outside `[0.0, 1.0]`, or `-0.0`), an unknown voter
/// method word, or a voter content digest that is not 32 bytes.
pub fn explanation_digest(entries: &[ExplanationEntry]) -> Result<[u8; 32], String> {
    let mut h = Sha256::new();
    be64_frame(&mut h, EXPLANATION_DIGEST_DOMAIN);
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
        match &e.voter_verification {
            None => h.update([0u8]),
            Some(v) => {
                if !VOTER_METHODS.contains(&v.method.as_str()) {
                    return Err(format!(
                        "explanation[{i}]: unknown voter verification method {:?}",
                        v.method
                    ));
                }
                if v.content_digest.len() != 32 {
                    return Err(format!(
                        "explanation[{i}]: voter content_digest is {} bytes, not 32",
                        v.content_digest.len()
                    ));
                }
                h.update([1u8]);
                be64_frame(&mut h, v.method.as_bytes());
                be64_frame(&mut h, v.principal.as_bytes());
                be64_frame(&mut h, &v.content_digest);
                h.update(v.issued_at_ms.to_be_bytes());
                h.update(v.expires_at_ms.to_be_bytes());
                be64_frame(&mut h, &v.signature);
                be64_frame(&mut h, &v.signer_certificate);
                be64_frame(&mut h, v.tenant.as_bytes());
                be64_frame(&mut h, v.namespace.as_bytes());
                be64_frame(&mut h, v.session_id.as_bytes());
                h.update(v.opened_at_millis.to_be_bytes());
                be64_frame(&mut h, v.issuer.as_bytes());
                be64_frame(&mut h, v.audience.as_bytes());
                h.update(v.accepted_at_ms.to_be_bytes());
            }
        }
    }
    Ok(h.finalize().into())
}

/// The domain tag, field 0 of the commitment-digest preimage.
pub const COMMITMENT_DIGEST_DOMAIN: &[u8] = b"seam-commitment-digest:v5";

/// `seam-commitment-digest:v5`: SHA-256 over twelve fields in the spec's order, each `F`-framed except
/// fields 4, 9, 10 and 11. `supersedes` carries a presence byte — absent is `0x00`, present is `0x01 ‖
/// F(value)` — so an absent prior and a present empty one are different digests. Field 8 is the 32 RAW
/// bytes of the explanation digest (v2). Fields 9, 10 and 11 (selection, Gate certificate, governing
/// document) are `0x00` absent, else `0x01 ‖ be64(32) ‖ 32 raw bytes`; a present digest of any other
/// length is refused, never hashed. v4 is deleted, not dual-verified: a v4 TCT does not verify here.
pub fn commitment_digest(c: &Commitment) -> Result<[u8; 32], String> {
    commitment_digest_with_explanation(c, &explanation_digest(&c.explanation)?)
}

/// [`commitment_digest`] with field 8 supplied as the 32-byte explanation digest instead of recomputed
/// from `c.explanation` (which is ignored). For vectors that publish only the digest; a verifier of a
/// real record uses [`commitment_digest`], which binds the entries.
pub fn commitment_digest_with_explanation(
    c: &Commitment,
    explanation: &[u8; 32],
) -> Result<[u8; 32], String> {
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
    for (name, slot) in [
        ("selection_digest", &c.selection_digest),
        ("certificate_digest", &c.certificate_digest),
        ("governing_doc_sha256", &c.governing_doc_sha256),
    ] {
        match slot {
            None => h.update([0u8]),
            Some(d) if d.len() == 32 => {
                h.update([1u8]);
                be64_frame(&mut h, d);
            }
            Some(d) => {
                return Err(format!(
                    "{name} is {} bytes; a present digest must be 32",
                    d.len()
                ))
            }
        }
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
/// "aitp/0.3"`, `iss == aud == sub == pinned`; `iat <= now <= exp` (integer seconds); `cnf.jkt` is
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
            "the TCT's ext does not bind this Commitment's seam-commitment-digest:v5 (forged \
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
            "cabe83af912ea38ef4525f5a7d8580b4c4e217417edc0c93f936d2c18c4fd8f5"
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
            selection_digest: None,
            certificate_digest: None,
            governing_doc_sha256: None,
            signed_artifact: String::new(),
        }
    }

    fn d(h: &str) -> Vec<u8> {
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect()
    }

    /// `seam-governing-doc:test-vector`'s SHA-256, the v5 vectors' field 11 value.
    const DOC: &str = "3488696887c9b0454b0947e69ec0b51c62c9d63f3f840ea98f3fd3b8e1004a05";

    /// `commitment_digest_v5_vector.json` case `all_empty`, inlined so a packaged crate tests it.
    #[test]
    fn all_empty_commitment_matches_the_vector() {
        assert_eq!(
            hex(&commitment_digest(&empty_commitment()).unwrap()),
            "f31f8081790860a42529c30c4b75626213c6ad36b7c797ba172a2246eab41207"
        );
    }

    /// Case `empty_supersedes`: a present empty prior is `0x01 ‖ be64(0)`, never the absent `0x00`.
    #[test]
    fn empty_supersedes_is_not_absent_supersedes() {
        let mut c = empty_commitment();
        c.supersedes = Some(String::new());
        assert_eq!(
            hex(&commitment_digest(&c).unwrap()),
            "9bf7e384a2d8b003c1cb5669b8198dcd5784401797d0897586baa87afeba4ce3"
        );
    }

    /// The domain literal the cross-language framing test greps for.
    #[test]
    fn the_domain_tags_are_v5_and_v2() {
        assert_eq!(COMMITMENT_DIGEST_DOMAIN, b"seam-commitment-digest:v5");
        assert_eq!(EXPLANATION_DIGEST_DOMAIN, b"seam-explanation-digest:v2");
    }

    /// Cases `selection_present`, `certificate_present`, `both_present`: the field 9/10 slots, with the
    /// vector's own digests, inlined so a packaged crate tests them.
    #[test]
    fn the_selection_and_certificate_slots_match_the_vector() {
        let sel = d("b71424be32b4e9de8d5b7b1ce5333d1469a68c6ee7b936ba44d175ccd3723c15");
        let cert = d("f0ad9d4e2d95e36ccbfbb0e9277108af979854634cc45989fa719079d3ffb1ca");
        let mut c = empty_commitment();
        c.selection_digest = Some(sel);
        c.certificate_digest = Some(cert);
        assert_eq!(
            hex(&commitment_digest(&c).unwrap()),
            "41d8c1bf6b8dcb855e89744a185ed73de32086d280e80159f44d28d68e595d0e"
        );
    }

    /// Cases `doc_present` and `all_slots_present`: field 11, alone and beside fields 9 and 10.
    #[test]
    fn the_governing_document_slot_matches_the_vector() {
        let mut c = empty_commitment();
        c.governing_doc_sha256 = Some(d(DOC));
        assert_eq!(
            hex(&commitment_digest(&c).unwrap()),
            "f3adf45b1eea210f1022bb53a9bf63d8219f309702506075da35dbeb419b749e"
        );
        c.selection_digest = Some(d(
            "b71424be32b4e9de8d5b7b1ce5333d1469a68c6ee7b936ba44d175ccd3723c15",
        ));
        c.certificate_digest = Some(d(
            "f0ad9d4e2d95e36ccbfbb0e9277108af979854634cc45989fa719079d3ffb1ca",
        ));
        assert_eq!(
            hex(&commitment_digest(&c).unwrap()),
            "9f157ab8e92dccef403f4c817a18be02e3ab1ac70b0fdc9a3e062c461d3e3746"
        );
    }

    #[test]
    fn a_slot_digest_that_is_not_32_bytes_is_refused_not_hashed() {
        for len in [0usize, 31, 33] {
            let mut c = empty_commitment();
            c.selection_digest = Some(vec![1; len]);
            assert!(commitment_digest(&c).is_err(), "selection {len}");
            let mut c = empty_commitment();
            c.certificate_digest = Some(vec![1; len]);
            assert!(commitment_digest(&c).is_err(), "certificate {len}");
            let mut c = empty_commitment();
            c.governing_doc_sha256 = Some(vec![1; len]);
            assert!(commitment_digest(&c).is_err(), "governing doc {len}");
        }
    }

    fn record() -> VoterVerification {
        VoterVerification {
            method: "pop".into(),
            principal: "aid:pubkey:ed25519:x".into(),
            content_digest: vec![5; 32],
            issued_at_ms: 1,
            expires_at_ms: 2,
            signature: vec![9; 64],
            signer_certificate: vec![],
            tenant: "t".into(),
            namespace: "n".into(),
            session_id: "s".into(),
            opened_at_millis: 0,
            issuer: "i".into(),
            audience: "a".into(),
            accepted_at_ms: 1,
        }
    }

    /// A record is bound: present vs absent, and any field edit, moves the digest; a bad method word or
    /// a short content digest is refused.
    #[test]
    fn the_voter_record_is_bound_and_validated() {
        let mut e = entry(None);
        e.kind = "vote".into();
        let bare = explanation_digest(std::slice::from_ref(&e)).unwrap();
        e.voter_verification = Some(record());
        let with = explanation_digest(std::slice::from_ref(&e)).unwrap();
        assert_ne!(bare, with);
        let mut edited = e.clone();
        edited.voter_verification.as_mut().unwrap().accepted_at_ms += 1;
        assert_ne!(explanation_digest(&[edited]).unwrap(), with);
        let mut bad = e.clone();
        bad.voter_verification.as_mut().unwrap().method = "POP".into();
        assert!(explanation_digest(&[bad]).is_err());
        let mut bad = e;
        bad.voter_verification.as_mut().unwrap().content_digest = vec![5; 31];
        assert!(explanation_digest(&[bad]).is_err());
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
            voter_verification: None,
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
