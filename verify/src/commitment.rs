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
///
/// `proposal` (option selection, seam-runtime 0.90.0) is additive under `seam-explanation-digest:v2`: the kind
/// set is closed per release, and a new word is not a new framing, so no tag moves.
pub const EXPLANATION_KINDS: &[&str] = &["vote", "evaluation", "objection", "ballot", "proposal"];

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
    /// Field 9, the selection block's digest (`crate::selection::selection_digest` over the sealed body),
    /// `None` when the decision did not run under option selection. A verifier frames it only from its
    /// own recomputation over the body, never from a stated digest.
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
    let claims = verify_tct_envelope(pinned_aid, token, now_secs)?;
    let binding = sole_seam_statement(&claims)?;
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

/// Everything [`verify_tct`] checks except the `ext` statement: the compact JWS, the header, the
/// signature under the pinned key, the strict (duplicate-refusing) claims parse, `ver`, `iss`/`aud`/
/// `sub`, `iat`/`exp`, `cnf.jkt` and `grants`. Returns the parsed claims. Shared by the v5-only
/// [`verify_tct`] and the version-selecting [`verify_commitment_tct`], so the two cannot drift on any
/// check but the one that differs.
fn verify_tct_envelope(
    pinned_aid: &str,
    token: &str,
    now_secs: u64,
) -> Result<serde_json::Value, String> {
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
    Ok(claims)
}

/// The TCT's `ext` must be an object carrying exactly one namespace, [`EXT_NAMESPACE`], whose value is an
/// object; returns that statement object. (A Seam-minted TCT carries no other namespace; this verifier
/// has always refused one, under v5 and now under v6 alike.)
fn sole_seam_statement(
    claims: &serde_json::Value,
) -> Result<&serde_json::Map<String, serde_json::Value>, String> {
    let Some(ext) = claims.get("ext").and_then(|e| e.as_object()) else {
        return Err("the TCT carries no ext object".into());
    };
    if ext.len() != 1 {
        return Err(format!(
            "the TCT's ext carries a namespace other than {EXT_NAMESPACE} (exactly one is allowed)"
        ));
    }
    ext.get(EXT_NAMESPACE)
        .and_then(|b| b.as_object())
        .ok_or_else(|| format!("the TCT's ext has no {EXT_NAMESPACE} object"))
}

// ==================================================================================================
// `seam-commitment-digest:v6` (Flows W2, A18) — beside v5, never instead of it.
//
// Written from `seam-runtime/docs/specs/seam-commitment-digest.v6.md` and `seam-gate-block.v1.md` and
// pinned by `conformance/commitment_digest_v6_vector.json`, `commitment_digest_v6_signed_vector.json`
// and `gate_block_vector.json`. v6 is v5 plus field 12 (the env, `sandbox` or `live`) and with field 10
// defined as the Gate digest. Every v5 function above is byte-unchanged; nothing here calls into the
// v5 hash except `commitment_digest_under(V5, ..)`, which delegates to it.
//
// The scheme is never read off the bytes: an ungoverned v6 seal looks exactly like an ungoverned v5
// seal. A verifier takes it from the signed statement ([`select_commitment_version`]) and recomputes
// under that version only — never both, never a fallback.
// ==================================================================================================

/// The v6 domain tag, field 0.
pub const COMMITMENT_DIGEST_DOMAIN_V6: &[u8] = b"seam-commitment-digest:v6";

/// The statement member that names the digest version, REQUIRED from v6 on.
pub const COMMITMENT_DIGEST_DOMAIN_MEMBER: &str = "commitment_digest_domain";

/// The governing-document trailer's marker.
pub const GOVERNING_TRAILER: u8 = 0x06;

/// Which commitment digest a record is recomputed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitmentDigestVersion {
    V5,
    V6,
}

/// A refusal of the whole commitment, before anything is hashed. `rule` is the spec's rule name, which is
/// **advisory** (spec §Refusal rules): where an input breaks more than one rule, another applicable name
/// is equally conforming. Only the refusal is normative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentRefusal {
    pub rule: &'static str,
    pub detail: String,
}

impl CommitmentRefusal {
    fn new(rule: &'static str, detail: impl Into<String>) -> Self {
        Self {
            rule,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for CommitmentRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} ({})", self.detail, self.rule)
    }
}

impl From<crate::gate::GateRefusal> for CommitmentRefusal {
    fn from(g: crate::gate::GateRefusal) -> Self {
        Self::new(g.rule(), g.to_string())
    }
}

/// A presence slot's encoding: `0x00` absent, else `0x01 ‖ be64(len) ‖ bytes` (fields 9–12).
pub fn encode_slot(x: Option<&[u8]>) -> Vec<u8> {
    match x {
        None => vec![0],
        Some(x) => {
            let mut v = Vec::with_capacity(9 + x.len());
            v.push(1);
            v.extend_from_slice(&(x.len() as u64).to_be_bytes());
            v.extend_from_slice(x);
            v
        }
    }
}

/// The commitment digest under `version`, with field 8 supplied as the explanation digest and fields 10
/// and 12 supplied directly (the digest-only path; a verifier derives them from the trailers with
/// [`decode_commitment_trailers`]). `c.certificate_digest` is **ignored**: field 10 is `field_10`.
/// Fields 9 and 11 are `c.selection_digest` and `c.governing_doc_sha256`.
///
/// Under v5 it is exactly [`commitment_digest_with_explanation`] (field 10 the opaque v5 slot), and an
/// env refuses (`v5_refuses_env`). Under v6 it refuses, before hashing, a present field 9/10/11 that is
/// not 32 bytes (`slot_length_not_32`), an env that is not exactly `sandbox`/`live`
/// (`env_not_sandbox_or_live`, the empty string included: empty is not absence), and an env without a
/// governing document (`env_without_governing_doc`).
pub fn commitment_digest_under(
    version: CommitmentDigestVersion,
    c: &Commitment,
    explanation: &[u8; 32],
    field_10: Option<&[u8]>,
    env: Option<&[u8]>,
) -> Result<[u8; 32], CommitmentRefusal> {
    if version == CommitmentDigestVersion::V5 {
        if env.is_some() {
            return Err(CommitmentRefusal::new(
                "v5_refuses_env",
                "a v5 commitment digest cannot frame an env",
            ));
        }
        let mut v5 = c.clone();
        v5.certificate_digest = field_10.map(<[u8]>::to_vec);
        return commitment_digest_with_explanation(&v5, explanation)
            .map_err(|e| CommitmentRefusal::new("slot_length_not_32", e));
    }
    for (name, slot) in [
        ("selection_digest", c.selection_digest.as_deref()),
        ("gate_digest", field_10),
        ("governing_doc_sha256", c.governing_doc_sha256.as_deref()),
    ] {
        if let Some(d) = slot {
            if d.len() != 32 {
                return Err(CommitmentRefusal::new(
                    "slot_length_not_32",
                    format!("{name} is {} bytes; a present digest must be 32", d.len()),
                ));
            }
        }
    }
    if let Some(e) = env {
        if !crate::gate::is_flow_env(e) {
            return Err(CommitmentRefusal::new(
                "env_not_sandbox_or_live",
                "the env is not exactly the bytes `sandbox` or `live`",
            ));
        }
        if c.governing_doc_sha256.is_none() {
            return Err(CommitmentRefusal::new(
                "env_without_governing_doc",
                "field 12 (env) is present but field 11 (governing document) is absent",
            ));
        }
    }
    let mut h = Sha256::new();
    for field in [
        COMMITMENT_DIGEST_DOMAIN_V6,
        c.id.as_bytes(),
        c.action.as_bytes(),
        c.authority.as_bytes(),
    ] {
        be64_frame(&mut h, field);
    }
    h.update(encode_slot(c.supersedes.as_deref().map(str::as_bytes)));
    for field in [
        c.auth_method.as_bytes(),
        c.trust_basis.as_bytes(),
        c.committer.as_bytes(),
        explanation.as_slice(),
    ] {
        be64_frame(&mut h, field);
    }
    h.update(encode_slot(c.selection_digest.as_deref()));
    h.update(encode_slot(field_10));
    h.update(encode_slot(c.governing_doc_sha256.as_deref()));
    h.update(encode_slot(env));
    Ok(h.finalize().into())
}

/// `seam-commitment-digest:v6` over `c` (explanation recomputed from its entries), with field 10 the
/// Gate digest and field 12 the env. See [`commitment_digest_under`] for the refusals.
pub fn commitment_digest_v6(
    c: &Commitment,
    gate_digest: Option<&[u8]>,
    env: Option<&[u8]>,
) -> Result<[u8; 32], CommitmentRefusal> {
    let e = explanation_digest(&c.explanation)
        .map_err(|e| CommitmentRefusal::new("explanation_invalid", e))?;
    commitment_digest_under(CommitmentDigestVersion::V6, c, &e, gate_digest, env)
}

/// A decoded `0x06` body, either version (the scheme-free decode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoverningBody {
    /// `0x01 ‖ doc_sha256` — v5's body, exactly 33 bytes.
    V1 { doc_sha256: [u8; 32] },
    /// `0x02 ‖ doc_sha256 ‖ (0x00 | 0x01 ‖ F(env))`. `env` is `None` for a governed seal whose namespace
    /// maps to no (flow, env).
    V2 {
        doc_sha256: [u8; 32],
        env: Option<String>,
    },
}

impl GoverningBody {
    pub fn version(&self) -> u8 {
        match self {
            Self::V1 { .. } => 1,
            Self::V2 { .. } => 2,
        }
    }
    pub fn doc_sha256(&self) -> &[u8; 32] {
        match self {
            Self::V1 { doc_sha256 } | Self::V2 { doc_sha256, .. } => doc_sha256,
        }
    }
    pub fn env(&self) -> Option<&str> {
        match self {
            Self::V1 { .. } => None,
            Self::V2 { env, .. } => env.as_deref(),
        }
    }
}

/// Decode a `0x06` body of either version (the trailer's body, after `marker ‖ u32le(len)`). Scheme-free:
/// both versions are accepted and reported, and every rule that needs no scheme is applied. A be64 env
/// length is compared as a `u64`, so 2^64−1 refuses as truncated instead of wrapping.
pub fn decode_governing_body(body: &[u8]) -> Result<GoverningBody, CommitmentRefusal> {
    let r = |rule, d: &str| Err(CommitmentRefusal::new(rule, d));
    let Some((&version, rest)) = body.split_first() else {
        return r("governing_body_empty", "the 0x06 body is zero bytes");
    };
    match version {
        1 => match <[u8; 32]>::try_from(rest) {
            Ok(doc_sha256) => Ok(GoverningBody::V1 { doc_sha256 }),
            Err(_) => r(
                "governing_body_length",
                "a 0x06 body v1 is not exactly 33 bytes",
            ),
        },
        2 => {
            if rest.len() < 32 {
                return r(
                    "governing_body_truncated",
                    "the doc digest runs past the body",
                );
            }
            let (doc, slot) = rest.split_at(32);
            let doc_sha256 = <[u8; 32]>::try_from(doc).expect("32 bytes");
            let env = match slot.split_first() {
                None => {
                    return r(
                        "env_presence_missing",
                        "a 0x06 body v2 ends right after the doc digest",
                    )
                }
                Some((0, [])) => None,
                Some((0, _)) => {
                    return r(
                        "governing_body_trailing_bytes",
                        "bytes follow the absent env",
                    )
                }
                Some((1, frame)) => {
                    if frame.len() < 8 {
                        return r(
                            "governing_body_truncated",
                            "the env length runs past the body",
                        );
                    }
                    let (len, tail) = frame.split_at(8);
                    let len = u64::from_be_bytes(len.try_into().expect("8 bytes"));
                    if len > tail.len() as u64 {
                        return r(
                            "governing_body_truncated",
                            "the env bytes run past the body",
                        );
                    }
                    let (env, trailing) = tail.split_at(len as usize);
                    if !crate::gate::is_flow_env(env) {
                        return r(
                            "env_not_sandbox_or_live",
                            "the 0x06 env is not exactly the bytes `sandbox` or `live`",
                        );
                    }
                    if !trailing.is_empty() {
                        return r(
                            "governing_body_trailing_bytes",
                            "bytes follow the env frame",
                        );
                    }
                    Some(String::from_utf8(env.to_vec()).expect("a flow env is ASCII"))
                }
                Some(_) => {
                    return r(
                        "env_presence_invalid",
                        "the env presence byte is not 0x00 or 0x01",
                    )
                }
            };
            Ok(GoverningBody::V2 { doc_sha256, env })
        }
        _ => r(
            "governing_body_unknown_version",
            "the 0x06 body version is neither 0x01 nor 0x02",
        ),
    }
}

/// A decoded `0x05`/`0x06` trailer run: the Gate block with its recomputed digest, and the governing body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitmentTrailers {
    pub gate: Option<crate::gate::GateBlock>,
    /// `seam-gate-digest:v1` recomputed over the `0x05` body (never taken from beside it, VG1).
    pub gate_digest: Option<[u8; 32]>,
    pub governing: Option<GoverningBody>,
}

impl CommitmentTrailers {
    pub fn governing_doc_sha256(&self) -> Option<&[u8; 32]> {
        self.governing.as_ref().map(GoverningBody::doc_sha256)
    }
    pub fn env(&self) -> Option<&str> {
        self.governing.as_ref().and_then(GoverningBody::env)
    }
    /// `1`, `2`, or `None` without a `0x06` trailer.
    pub fn governing_body_version(&self) -> Option<u8> {
        self.governing.as_ref().map(GoverningBody::version)
    }
    /// v6 field 10's encoding.
    pub fn field_10(&self) -> Vec<u8> {
        encode_slot(self.gate_digest.as_ref().map(|d| d.as_slice()))
    }
    /// Field 11's encoding (either version).
    pub fn field_11(&self) -> Vec<u8> {
        encode_slot(self.governing_doc_sha256().map(|d| d.as_slice()))
    }
    /// v6 field 12's encoding.
    pub fn field_12(&self) -> Vec<u8> {
        encode_slot(self.env().map(str::as_bytes))
    }
}

/// Decode the raw `0x05`/`0x06` trailer bytes a commitment appends (spec §The `0x06` trailer, Gate spec
/// §The trailer). `scheme` is `Some(V5)`/`Some(V6)` for a reader that knows the scheme (a verifier, from
/// statement selection), or `None` for the scheme-free decode.
///
/// Always applied: each trailer is `marker ‖ u32le(len) ‖ body`; markers strictly increase (a repeated or
/// misordered `0x05`/`0x06` refuses, `marker_order`); a marker outside `0x01`–`0x07` refuses
/// (`unknown_marker`); a length or body past the input refuses; the `0x05` body is decoded strictly
/// ([`crate::gate::decode_gate_body`]) and the `0x06` body by [`decode_governing_body`]; and a `0x05` is
/// legal only beside a `0x06` body v2 whose env is present and equal to the Gate body's
/// (`gate_env_binding`). Then the scheme's rules: under v5 a `0x05` (`v5_refuses_gate_block`) or a body v2
/// (`v5_refuses_governing_body_v2`) refuses; under v6 a body v1 (`v6_refuses_governing_body_v1`).
///
/// **Input scope.** This takes the `0x05`/`0x06` run only. The other known markers (`0x01`–`0x04`,
/// `0x07`) are not all length-framed alike, and this crate never opens a sealed trailer list: field 9
/// comes from the disclosed selection body as it does under v5. One of them here refuses
/// (`trailer_out_of_scope`) rather than being skipped unread.
pub fn decode_commitment_trailers(
    trailers: &[u8],
    scheme: Option<CommitmentDigestVersion>,
) -> Result<CommitmentTrailers, CommitmentRefusal> {
    let mut out = CommitmentTrailers::default();
    let mut pos = 0usize;
    let mut last = 0u8;
    while let Some(&marker) = trailers.get(pos) {
        if !(0x01..=0x07).contains(&marker) {
            return Err(CommitmentRefusal::new(
                "unknown_marker",
                format!("trailer marker {marker:#04x} is outside 0x01-0x07"),
            ));
        }
        if marker <= last {
            return Err(CommitmentRefusal::new(
                "marker_order",
                format!("trailer marker {marker:#04x} does not strictly follow {last:#04x}"),
            ));
        }
        last = marker;
        let truncated = if marker == crate::gate::GATE_TRAILER {
            "gate_trailer_truncated"
        } else {
            "governing_trailer_truncated"
        };
        if marker != crate::gate::GATE_TRAILER && marker != GOVERNING_TRAILER {
            return Err(CommitmentRefusal::new(
                "trailer_out_of_scope",
                format!(
                    "trailer marker {marker:#04x} is not a 0x05/0x06 trailer; pass only that run"
                ),
            ));
        }
        let Some(len) = trailers.get(pos + 1..pos + 5) else {
            return Err(CommitmentRefusal::new(
                truncated,
                "the trailer's u32le length runs past the input",
            ));
        };
        let len = u32::from_le_bytes(len.try_into().expect("4 bytes")) as usize;
        let start = pos + 5;
        let Some(body) = trailers.get(start..start.saturating_add(len)) else {
            return Err(CommitmentRefusal::new(
                truncated,
                "the trailer's body runs past the input",
            ));
        };
        if marker == crate::gate::GATE_TRAILER {
            out.gate = Some(crate::gate::decode_gate_body(body)?);
            out.gate_digest = Some(crate::gate::gate_digest(body));
        } else {
            out.governing = Some(decode_governing_body(body)?);
        }
        pos = start + len;
    }
    match scheme {
        Some(CommitmentDigestVersion::V5) => {
            if out.gate.is_some() {
                return Err(CommitmentRefusal::new(
                    "v5_refuses_gate_block",
                    "a v5 commitment carries a 0x05 Gate block",
                ));
            }
            if out.governing_body_version() == Some(2) {
                return Err(CommitmentRefusal::new(
                    "v5_refuses_governing_body_v2",
                    "a v5 commitment carries a 0x06 body v2",
                ));
            }
        }
        Some(CommitmentDigestVersion::V6) if out.governing_body_version() == Some(1) => {
            return Err(CommitmentRefusal::new(
                "v6_refuses_governing_body_v1",
                "a v6 commitment carries a 0x06 body v1",
            ));
        }
        _ => {}
    }
    if let Some(g) = &out.gate {
        if out.env() != Some(g.env.as_str()) {
            return Err(CommitmentRefusal::new(
                "gate_env_binding",
                "a 0x05 Gate block needs a 0x06 body v2 whose env is present and equal to the Gate env",
            ));
        }
    }
    Ok(out)
}

/// A statement that selected a version, with the digest it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedStatement {
    pub version: CommitmentDigestVersion,
    pub commitment_digest: [u8; 32],
}

/// Parse raw statement/`ext` JSON: not JSON refuses `statement_not_json`; then a duplicate member name at
/// ANY depth refuses `statement_duplicate_member`. The duplicate guard is [`parse_no_duplicate_keys`]: a
/// streaming visitor that sees every member as the deserializer reads it off the raw text (names after
/// JSON unescaping, so `"type"` and `"type"` collide) — never a map parse that keeps the last of two.
fn parse_statement_json(raw: &[u8]) -> Result<serde_json::Value, CommitmentRefusal> {
    serde_json::from_slice::<serde_json::Value>(raw)
        .map_err(|e| CommitmentRefusal::new("statement_not_json", e.to_string()))?;
    parse_no_duplicate_keys(raw)
        .map_err(|e| CommitmentRefusal::new("statement_duplicate_member", e))
}

fn select_from_statement(
    statement: &serde_json::Value,
) -> Result<SelectedStatement, CommitmentRefusal> {
    let Some(obj) = statement.as_object() else {
        return Err(CommitmentRefusal::new(
            "statement_not_object",
            "the statement is not a JSON object",
        ));
    };
    let has = |k: &str| obj.contains_key(k);
    let version = match obj.len() {
        2 if has("type") && has("commitment_digest") => CommitmentDigestVersion::V5,
        3 if has("type") && has("commitment_digest") && has(COMMITMENT_DIGEST_DOMAIN_MEMBER) => {
            if obj[COMMITMENT_DIGEST_DOMAIN_MEMBER].as_str()
                != std::str::from_utf8(COMMITMENT_DIGEST_DOMAIN_V6).ok()
            {
                return Err(CommitmentRefusal::new(
                    "statement_domain_not_v6",
                    "commitment_digest_domain is not the string seam-commitment-digest:v6",
                ));
            }
            CommitmentDigestVersion::V6
        }
        _ => {
            return Err(CommitmentRefusal::new(
                "statement_member_set",
                "the statement's members are neither {type, commitment_digest} nor {type, \
                 commitment_digest, commitment_digest_domain}",
            ))
        }
    };
    if obj["type"].as_str() != Some(EXT_TYPE) {
        return Err(CommitmentRefusal::new(
            "statement_type",
            format!("the statement's type is not {EXT_TYPE}"),
        ));
    }
    let Some(hex) = obj["commitment_digest"]
        .as_str()
        .filter(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
    else {
        return Err(CommitmentRefusal::new(
            "statement_digest_not_lowercase_hex",
            "commitment_digest is not exactly 64 lowercase hex characters",
        ));
    };
    let mut commitment_digest = [0u8; 32];
    for (i, d) in commitment_digest.iter_mut().enumerate() {
        *d = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("lowercase hex");
    }
    Ok(SelectedStatement {
        version,
        commitment_digest,
    })
}

fn select_from_ext(ext: &serde_json::Value) -> Result<SelectedStatement, CommitmentRefusal> {
    let Some(ext) = ext.as_object() else {
        return Err(CommitmentRefusal::new(
            "statement_not_object",
            "the ext is not a JSON object",
        ));
    };
    select_from_statement(ext.get(EXT_NAMESPACE).ok_or_else(|| {
        CommitmentRefusal::new(
            "statement_missing",
            format!("the ext has no {EXT_NAMESPACE} member"),
        )
    })?)
}

/// Statement selection over the raw statement object text, by EXACT member set (spec §Verifiers:
/// choosing v5 or v6): `{type, commitment_digest}` ⇒ v5; `{type, commitment_digest,
/// commitment_digest_domain}` with the domain the string `seam-commitment-digest:v6` ⇒ v6; anything else
/// refuses. Member order is not significant. `type` must be `seam:commitment` and `commitment_digest`
/// exactly 64 lowercase hex characters.
pub fn select_commitment_version(
    raw_statement: &[u8],
) -> Result<SelectedStatement, CommitmentRefusal> {
    select_from_statement(&parse_statement_json(raw_statement)?)
}

/// [`select_commitment_version`] entered from the raw TCT `ext` object: the duplicate guard covers the
/// whole `ext` (every namespace, every depth), and the statement is its [`EXT_NAMESPACE`] member. Other
/// namespaces are tolerated HERE, as the spec's selection rule does; [`verify_commitment_tct`] keeps this
/// verifier's older, stricter rule that a Seam TCT's `ext` carries no other namespace.
pub fn select_commitment_version_in_ext(
    raw_ext: &[u8],
) -> Result<SelectedStatement, CommitmentRefusal> {
    select_from_ext(&parse_statement_json(raw_ext)?)
}

/// Verify a commitment TCT against a **pinned** issuer AID, choosing v5 or v6 from the signed statement
/// and recomputing under that version ONLY (spec §Verifiers: choosing v5 or v6). Returns the version.
///
/// Every envelope check of [`verify_tct`] applies unchanged (signature, `ver`, `iss`/`aud`/`sub`,
/// `iat`/`exp`, `cnf.jkt`, `grants`, the claims parsed with duplicate members refused at every depth,
/// which covers the whole `ext`). Then:
///
/// 1. the `ext` carries exactly the [`EXT_NAMESPACE`] statement, which selects the version;
/// 2. `trailers` (the raw `0x05`/`0x06` bytes; empty when the record has neither) decode under that
///    scheme ([`decode_commitment_trailers`]);
/// 3. under **v5**, field 10 is `c.certificate_digest` and field 11 the `0x06` v1 doc (or
///    `c.governing_doc_sha256` with no trailer, exactly as before); under **v6**, field 10 is the Gate
///    digest recomputed over the `0x05` body and fields 11/12 come from the `0x06` body v2 — a
///    `c.certificate_digest`, or a `c.governing_doc_sha256` with no `0x06` trailer, is refused, since v6
///    frames those fields from the trailers only;
/// 4. the recomputed digest must equal the statement's. A 2-member statement over a v6 commitment
///    therefore selects v5 and fails here; it is never retried under v6.
pub fn verify_commitment_tct(
    pinned_aid: &str,
    c: &Commitment,
    trailers: &[u8],
    now_secs: u64,
) -> Result<CommitmentDigestVersion, String> {
    let claims = verify_tct_envelope(pinned_aid, &c.signed_artifact, now_secs)?;
    sole_seam_statement(&claims)?;
    let sel = select_from_ext(&claims["ext"])
        .map_err(|r| format!("the TCT's statement selects no commitment digest version: {r}"))?;
    let t = decode_commitment_trailers(trailers, Some(sel.version))
        .map_err(|r| format!("the commitment's trailers are refused: {r}"))?;
    let explanation = explanation_digest(&c.explanation)?;
    let trailer_doc = t.governing_doc_sha256().map(|d| d.to_vec());
    if let (Some(stated), Some(sealed)) = (&c.governing_doc_sha256, &trailer_doc) {
        if stated != sealed {
            return Err(
                "the commitment's governing_doc_sha256 disagrees with its 0x06 trailer".into(),
            );
        }
    }
    let mut framed = c.clone();
    let digest = match sel.version {
        CommitmentDigestVersion::V5 => {
            framed.governing_doc_sha256 = trailer_doc.or(c.governing_doc_sha256.clone());
            commitment_digest_under(
                sel.version,
                &framed,
                &explanation,
                c.certificate_digest.as_deref(),
                None,
            )
        }
        CommitmentDigestVersion::V6 => {
            if c.certificate_digest.is_some() {
                return Err(
                    "under v6 field 10 is framed only from the 0x05 Gate block, never from \
                            a stated certificate_digest"
                        .into(),
                );
            }
            if c.governing_doc_sha256.is_some() && trailer_doc.is_none() {
                return Err(
                    "under v6 a governed commitment carries its doc in the 0x06 body v2; \
                            none was supplied"
                        .into(),
                );
            }
            framed.governing_doc_sha256 = trailer_doc;
            commitment_digest_under(
                sel.version,
                &framed,
                &explanation,
                t.gate_digest.as_ref().map(|d| d.as_slice()),
                t.env().map(str::as_bytes),
            )
        }
    }
    .map_err(|r| format!("the commitment digest is refused: {r}"))?;
    if digest != sel.commitment_digest {
        let tag = match sel.version {
            CommitmentDigestVersion::V5 => "seam-commitment-digest:v5",
            CommitmentDigestVersion::V6 => "seam-commitment-digest:v6",
        };
        return Err(format!(
            "the TCT's ext does not bind this Commitment's {tag} (commitment_digest_mismatch: forged \
             token, an edited field, or a statement naming the wrong version)"
        ));
    }
    Ok(sel.version)
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
