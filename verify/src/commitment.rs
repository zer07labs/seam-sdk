//! The Commitment and its rooted TCT: `seam-commitment-digest:v2`, `seam-explanation-digest:v1`, and
//! the self-issued `aitp-tct+jwt` that carries the digest in its `grants`.
//!
//! Written from `seam-runtime/docs/specs/seam-commitment-digest.v2.md` (not vendored here; the
//! evidence-bundle spec in `docs/evidence-bundle.v1.md` cites it) and pinned by that spec's two worked
//! examples, by `conformance/commitment_digest_v2_vector.json` (a real TCT from the real signer) and
//! by `conformance/vectors.json`'s `tct` block. The five SDK crypto shims implement the same framing;
//! this is a sixth port, from the same text, linking none of them.
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

/// A Commitment as the v2 framing reads it, plus its TCT.
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

/// `seam-commitment-digest:v2`: SHA-256 over nine `F`-framed fields, in the spec's order. An absent
/// `supersedes` is the empty string. Field 8 is the 32 RAW bytes of the explanation digest.
pub fn commitment_digest(c: &Commitment) -> Result<[u8; 32], String> {
    let explanation = explanation_digest(&c.explanation)?;
    let mut h = Sha256::new();
    for field in [
        b"seam-commitment-digest:v2".as_slice(),
        c.id.as_bytes(),
        c.action.as_bytes(),
        c.authority.as_bytes(),
        c.supersedes.as_deref().unwrap_or("").as_bytes(),
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

/// Verify a Seam-minted, self-issued TCT against a **pinned** issuer AID, and that it roots exactly
/// the Commitment whose digest is `digest`.
///
/// Checks, all fail-closed: exactly three non-empty compact-JWS segments, each strict unpadded
/// base64url; header `typ == "aitp-tct+jwt"` and `alg == "EdDSA"`; the Ed25519 signature over
/// `header.payload` under the pinned key; claims `ver == "aitp/0.2"`, `iss == aud == sub == pinned`;
/// `iat <= now <= exp` (integer seconds); `cnf.jkt` is the thumbprint of the subject's key; and
/// `grants` is exactly `["seam:commitment", "seam-commitment-digest:<hex>"]`, the two grants the spec
/// says a Seam TCT carries, in that order.
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
    let header: serde_json::Value = serde_json::from_slice(&seg(h64, "header")?)
        .map_err(|e| format!("the TCT header is not JSON: {e}"))?;
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

    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("the TCT payload is not JSON: {e}"))?;
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
    let want = [
        "seam:commitment".to_string(),
        format!("seam-commitment-digest:{}", crate::verify::hex(digest)),
    ];
    let grants: Option<Vec<&str>> = claims
        .get("grants")
        .and_then(|g| g.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect());
    if grants.as_deref() != Some(&[want[0].as_str(), want[1].as_str()][..]) {
        return Err(
            "the TCT's grants do not bind this Commitment's seam-commitment-digest:v2 (forged \
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

    /// Spec § Worked example — all fields empty.
    #[test]
    fn all_empty_commitment_matches_the_spec() {
        let c = Commitment {
            id: String::new(),
            action: String::new(),
            authority: String::new(),
            supersedes: None,
            auth_method: String::new(),
            trust_basis: String::new(),
            committer: String::new(),
            explanation: vec![],
            signed_artifact: String::new(),
        };
        assert_eq!(
            hex(&commitment_digest(&c).unwrap()),
            "78edca52ba1e88f13a78e5569742bfce0b51474ca840bf38a8dde414d5515784"
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
