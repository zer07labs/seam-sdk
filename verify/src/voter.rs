//! Verified voters (seam-runtime #1687): the offline re-check of every sealed voter verification record.
//!
//! Written from `seam-runtime/docs/specs/voter-verification.v1.md` (not vendored here; the evidence-bundle
//! spec in `docs/evidence-bundle.v1.md` cites it) and pinned by `conformance/voter_pop_v1_payload_vector.json`.
//! Nothing of Seam's is linked: this is a port from the spec text, like [`crate::commitment`].
//!
//! Two framings meet here, and they must not be confused:
//!
//! * the **signed input** and the **content digest** use `framed(x) = u32_LE(len(x)) ‖ x`;
//! * the **entry bytes** (frozen, standalone) use the explanation family's `F(x) = u64_BE(len(x)) ‖ x`.
//!
//! What a record proves: the holder of the voter key the `principal` embeds signed exactly this entry, for
//! exactly this session open identity, content digest and runtime. **Distinct keys, not distinct parties.**
//! The content digest is NOT re-derived here: what it covers (the proposal content, the participant set,
//! on-behalf-of, the context hashes) is not in a Commitment or a bundle, so a record proves the voter
//! signed that digest, not what the digest covers.

use crate::commitment::ExplanationEntry;
use sha2::{Digest, Sha256};

/// The signed input's domain tag.
pub const VOTER_POP_DOMAIN: &[u8] = b"seam-voter-pop-v1";
/// The content digest's domain tag.
pub const VOTE_CONTENT_DOMAIN: &[u8] = b"seam-vote-content-v1";
/// The longest a proof may live: `expires_at − issued_at ≤ 15 min`.
pub const MAX_LIFETIME_MS: u64 = 15 * 60 * 1000;
/// How far ahead of the clock a proof may be issued: `issued_at ≤ now + 60 s`.
pub const MAX_SKEW_MS: u64 = 60 * 1000;

fn framed(m: &mut Vec<u8>, x: &[u8]) {
    m.extend_from_slice(&(x.len() as u32).to_le_bytes());
    m.extend_from_slice(x);
}

fn be64_frame(m: &mut Vec<u8>, x: &[u8]) {
    m.extend_from_slice(&(x.len() as u64).to_be_bytes());
    m.extend_from_slice(x);
}

/// The frozen `entry_bytes`: `F(kind) ‖ F(participant) ‖ F(proposal_id) ‖ F(value) ‖ F(reason) ‖ CONF ‖
/// REF`, with `CONF`/`REF` exactly as the explanation digest frames them (`-0.0` folded to `+0.0`).
pub fn entry_bytes(e: &ExplanationEntry) -> Vec<u8> {
    let mut b = Vec::new();
    for x in [&e.kind, &e.participant, &e.proposal_id, &e.value, &e.reason] {
        be64_frame(&mut b, x.as_bytes());
    }
    match e.confidence {
        None => b.push(0),
        Some(c) => {
            b.push(1);
            let c = if c == 0.0 { 0.0f64 } else { c };
            b.extend_from_slice(&c.to_bits().to_be_bytes());
        }
    }
    match &e.rationale_ref {
        None => b.push(0),
        Some(r) => {
            b.push(1);
            be64_frame(&mut b, r.as_bytes());
        }
    }
    b
}

/// One context binding the content digest covers: a `ctx_ref` and its verified `content_hash` (`""`
/// when the binding carries none).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentContext {
    pub ctx_ref: String,
    pub content_hash: String,
}

/// The policy a session-path vote binds: the policy id and its 32-byte `policy_rules_digest`.
#[derive(Clone, Copy, Debug)]
pub struct VotePolicy<'a> {
    pub policy_version: &'a str,
    pub rules_digest: &'a [u8; 32],
}

/// `seam-vote-content-v1`: what a vote is about. The runtime derives it from its own session state; it is
/// here so the vector can pin it, not because a verifier can re-derive it from a record.
///
/// `features` (one-shot only) are framed in ascending order of the key's UTF-8 bytes whatever order they
/// are given in; a key given twice is refused, never deduplicated. `policy` is `None` when there is none
/// or it is server-resolved (the one-shot path), framed `0x00`.
#[allow(clippy::too_many_arguments)]
pub fn vote_content_digest(
    mode: &str,
    proposal_id: &str,
    content: &str,
    participants: &[&str],
    on_behalf_of: &[&str],
    context: &[ContentContext],
    features: &[(&str, &str)],
    policy: Option<VotePolicy<'_>>,
) -> Result<[u8; 32], String> {
    let mut sorted = features.to_vec();
    sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    if let Some(w) = sorted.windows(2).find(|w| w[0].0 == w[1].0) {
        return Err(format!("feature key {:?} is given twice", w[0].0));
    }
    let mut m = Vec::new();
    framed(&mut m, VOTE_CONTENT_DOMAIN);
    framed(&mut m, mode.as_bytes());
    framed(&mut m, proposal_id.as_bytes());
    framed(&mut m, content.as_bytes());
    framed(&mut m, &(participants.len() as u32).to_le_bytes());
    for p in participants {
        framed(&mut m, p.as_bytes());
    }
    framed(&mut m, &(on_behalf_of.len() as u32).to_le_bytes());
    for o in on_behalf_of {
        framed(&mut m, o.as_bytes());
    }
    framed(&mut m, &(context.len() as u32).to_le_bytes());
    for c in context {
        framed(&mut m, c.ctx_ref.as_bytes());
        framed(&mut m, c.content_hash.as_bytes());
    }
    framed(&mut m, &(sorted.len() as u32).to_le_bytes());
    for (k, v) in &sorted {
        framed(&mut m, k.as_bytes());
        framed(&mut m, v.as_bytes());
    }
    match policy {
        None => m.push(0),
        Some(p) => {
            m.push(1);
            framed(&mut m, p.policy_version.as_bytes());
            framed(&mut m, p.rules_digest);
        }
    }
    Ok(Sha256::digest(&m).into())
}

/// Where a proof is addressed: the runtime (issuer, audience) and the session open identity.
#[derive(Clone, Copy, Debug)]
pub struct Target<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    pub tenant: &'a str,
    pub namespace: &'a str,
    pub session_id: &'a str,
    pub opened_at_millis: u64,
}

/// The `seam-voter-pop-v1` signed input.
pub fn signed_input(
    t: &Target<'_>,
    voter_aid: &str,
    content_digest: &[u8],
    issued_at_ms: u64,
    expires_at_ms: u64,
    entry_bytes: &[u8],
) -> Vec<u8> {
    let mut m = Vec::new();
    framed(&mut m, VOTER_POP_DOMAIN);
    framed(&mut m, t.issuer.as_bytes());
    framed(&mut m, t.audience.as_bytes());
    framed(&mut m, t.tenant.as_bytes());
    framed(&mut m, t.namespace.as_bytes());
    framed(&mut m, t.session_id.as_bytes());
    framed(&mut m, &t.opened_at_millis.to_le_bytes());
    framed(&mut m, voter_aid.as_bytes());
    framed(&mut m, content_digest);
    framed(&mut m, &issued_at_ms.to_le_bytes());
    framed(&mut m, &expires_at_ms.to_le_bytes());
    framed(&mut m, entry_bytes);
    m
}

/// The validity window at `at_ms`: `issued ≤ expires`, `expires − issued ≤ 15 min`, `issued ≤ at + 60 s`,
/// `at ≤ expires`.
pub fn window_holds(issued_at_ms: u64, expires_at_ms: u64, at_ms: u64) -> bool {
    issued_at_ms <= expires_at_ms
        && expires_at_ms - issued_at_ms <= MAX_LIFETIME_MS
        && issued_at_ms <= at_ms.saturating_add(MAX_SKEW_MS)
        && at_ms <= expires_at_ms
}

/// Ed25519 `verify_strict` with the key `aid` embeds. A P-256 (or any non-Ed25519) principal is refused:
/// this verifier carries no P-256 implementation, and it fails closed rather than skip.
fn signature_verifies(aid: &str, msg: &[u8], sig: &[u8]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let Ok(key) = crate::verify::aid_to_key(aid) else {
        return false;
    };
    let Ok(sig) = <[u8; 64]>::try_from(sig) else {
        return false;
    };
    VerifyingKey::from_bytes(&key)
        .map(|vk| vk.verify_strict(msg, &Signature::from_bytes(&sig)).is_ok())
        .unwrap_or(false)
}

/// Does this entry kind bind a voter? `vote`, `ballot` and `objection` do; `evaluation` and `proposal` do not.
pub fn binds_a_voter(kind: &str) -> bool {
    matches!(kind, "vote" | "ballot" | "objection")
}

/// Why a commitment's voters did not verify, and at which entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VoterFailure {
    /// A vote, ballot or objection with no record.
    Missing,
    /// A record on an entry kind that binds no voter (an evaluation, or an option-selection proposal).
    UnexpectedRecord,
    /// A method this verifier cannot re-check (`cp_signed`, declared, not served).
    UnsupportedMethod,
    /// A non-empty signer certificate on `pop`, or the window does not hold at `accepted_at_ms`.
    Malformed,
    /// The signature does not verify over the rebuilt input.
    BadSignature,
    /// The record is addressed to a runtime other than the pinned issuer.
    WrongIssuer,
    /// Two records disagree on `(tenant, namespace, session_id, opened_at_millis, audience)`.
    MixedSession,
    /// The records' tenant or session is not the decision's.
    WrongDecision,
}

impl std::fmt::Display for VoterFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Missing => "a vote, ballot or objection carries no voter verification record",
            Self::UnexpectedRecord => "an entry that binds no voter (an evaluation or a proposal) carries a voter verification record",
            Self::UnsupportedMethod => "the record's method cannot be re-checked offline (only `pop` is served)",
            Self::Malformed => "the record is malformed (a signer certificate on `pop`, or the window does not hold at accepted_at_ms)",
            Self::BadSignature => "the voter's signature does not verify over the rebuilt seam-voter-pop-v1 input",
            Self::WrongIssuer => "the record is addressed to a runtime other than the pinned issuer",
            Self::MixedSession => "the records come from more than one session (tenant, namespace, session, open time, audience)",
            Self::WrongDecision => "the records come from a session other than this decision's",
        })
    }
}

/// A [`VoterFailure`] at `explanation[index]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoterError {
    pub index: usize,
    pub failure: VoterFailure,
}

impl std::fmt::Display for VoterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "explanation[{}]: {}", self.index, self.failure)
    }
}

/// Re-check one entry's record from the record and the entry alone.
pub fn verify_record(e: &ExplanationEntry) -> Result<(), VoterFailure> {
    let r = e.voter_verification.as_ref().ok_or(VoterFailure::Missing)?;
    if r.method != "pop" {
        return Err(VoterFailure::UnsupportedMethod);
    }
    if !r.signer_certificate.is_empty()
        || r.content_digest.len() != 32
        || !window_holds(r.issued_at_ms, r.expires_at_ms, r.accepted_at_ms)
    {
        return Err(VoterFailure::Malformed);
    }
    let t = Target {
        issuer: &r.issuer,
        audience: &r.audience,
        tenant: &r.tenant,
        namespace: &r.namespace,
        session_id: &r.session_id,
        opened_at_millis: r.opened_at_millis,
    };
    let msg = signed_input(
        &t,
        &r.principal,
        &r.content_digest,
        r.issued_at_ms,
        r.expires_at_ms,
        &entry_bytes(e),
    );
    if signature_verifies(&r.principal, &msg, &r.signature) {
        Ok(())
    } else {
        Err(VoterFailure::BadSignature)
    }
}

/// The commitment-level check every verifier runs (spec § The sealed record, 1-5). Returns how many
/// records verified.
///
/// `issuer` is the pinned issuer AID, compared at the KEY level (the two textual AID forms name one key,
/// as everywhere else in this crate); an unparseable record issuer is [`VoterFailure::WrongIssuer`].
/// `decision` is `(tenant, session_id)` where the caller knows it (the bundle's manifest).
pub fn verify_commitment_voters(
    explanation: &[ExplanationEntry],
    issuer: &str,
    decision: Option<(&str, &str)>,
) -> Result<usize, VoterError> {
    let pinned = crate::verify::aid_to_key(issuer).ok();
    let mut session: Option<(&str, &str, &str, u64, &str)> = None;
    let mut verified = 0;
    for (index, e) in explanation.iter().enumerate() {
        let fail = |failure| VoterError { index, failure };
        let Some(r) = e.voter_verification.as_ref() else {
            if binds_a_voter(&e.kind) {
                return Err(fail(VoterFailure::Missing));
            }
            continue;
        };
        if !binds_a_voter(&e.kind) {
            return Err(fail(VoterFailure::UnexpectedRecord));
        }
        let theirs = crate::verify::aid_to_key(&r.issuer).ok();
        if pinned.is_none() || theirs != pinned {
            return Err(fail(VoterFailure::WrongIssuer));
        }
        let this = (
            r.tenant.as_str(),
            r.namespace.as_str(),
            r.session_id.as_str(),
            r.opened_at_millis,
            r.audience.as_str(),
        );
        match session {
            None => session = Some(this),
            Some(first) if first != this => return Err(fail(VoterFailure::MixedSession)),
            Some(_) => {}
        }
        if let Some((tenant, session_id)) = decision {
            if r.tenant != tenant || r.session_id != session_id {
                return Err(fail(VoterFailure::WrongDecision));
            }
        }
        verify_record(e).map_err(fail)?;
        verified += 1;
    }
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_bounds_are_inclusive_and_exact() {
        assert!(window_holds(0, MAX_LIFETIME_MS, 0));
        assert!(!window_holds(0, MAX_LIFETIME_MS + 1, 0));
        assert!(!window_holds(2, 1, 1));
        assert!(window_holds(MAX_SKEW_MS, MAX_SKEW_MS + 1, 0));
        assert!(!window_holds(MAX_SKEW_MS + 1, MAX_SKEW_MS + 2, 0));
        assert!(!window_holds(0, 10, 11));
    }

    #[test]
    fn negative_zero_confidence_frames_as_positive_zero() {
        let e = |c| ExplanationEntry {
            kind: "evaluation".into(),
            participant: String::new(),
            proposal_id: String::new(),
            value: String::new(),
            reason: String::new(),
            confidence: Some(c),
            rationale_ref: None,
            voter_verification: None,
        };
        assert_eq!(entry_bytes(&e(-0.0)), entry_bytes(&e(0.0)));
    }

    #[test]
    fn the_domain_tags_are_distinct() {
        assert_ne!(VOTER_POP_DOMAIN, VOTE_CONTENT_DOMAIN);
        assert_eq!(VOTER_POP_DOMAIN, b"seam-voter-pop-v1");
    }

    #[test]
    fn features_are_canonical_and_a_duplicate_key_is_refused() {
        let d = |f: &[(&str, &str)]| vote_content_digest("m", "p", "c", &[], &[], &[], f, None);
        assert_eq!(
            d(&[("b", "1"), ("a", "2")]).unwrap(),
            d(&[("a", "2"), ("b", "1")]).unwrap()
        );
        assert!(d(&[("a", "1"), ("a", "1")]).is_err());
        assert_ne!(d(&[]).unwrap(), d(&[("a", "")]).unwrap());
    }
    // ── the runtime's shared tamper table (seam-runtime#1713 `voter_verifier_agreement.rs`) ──────────

    use crate::commitment::VoterVerification;

    const SEAL_MS: u64 = 1_760_000_000_000;
    const SESSION: &str = "s-agree-0000000000000000";
    const OTHER_SESSION: &str = "s-agree-other-0000000000";

    fn aid_of(seed: [u8; 32]) -> String {
        use base64::Engine;
        let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        format!(
            "aid:pubkey:ed25519:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vk.to_bytes())
        )
    }

    fn issuer() -> String {
        aid_of([7; 32])
    }

    fn vote(who: &str) -> ExplanationEntry {
        ExplanationEntry {
            kind: "vote".into(),
            participant: who.into(),
            proposal_id: "p1".into(),
            value: "APPROVE".into(),
            reason: String::new(),
            confidence: None,
            rationale_ref: None,
            voter_verification: None,
        }
    }

    fn sign(e: &mut ExplanationEntry, seed: u8, issuer: &str, session: &str) {
        use ed25519_dalek::Signer;
        let t = Target {
            issuer,
            audience: "seam-runtime",
            tenant: "acme",
            namespace: "acme/fraud",
            session_id: session,
            opened_at_millis: SEAL_MS - 60_000,
        };
        let principal = aid_of([seed; 32]);
        let (issued, expires) = (SEAL_MS - 30_000, SEAL_MS + 300_000);
        e.voter_verification = None;
        let msg = signed_input(&t, &principal, &[5; 32], issued, expires, &entry_bytes(e));
        let sig = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).sign(&msg);
        e.voter_verification = Some(VoterVerification {
            method: "pop".into(),
            principal,
            content_digest: vec![5; 32],
            issued_at_ms: issued,
            expires_at_ms: expires,
            signature: sig.to_bytes().to_vec(),
            signer_certificate: vec![],
            tenant: "acme".into(),
            namespace: "acme/fraud".into(),
            session_id: session.into(),
            opened_at_millis: SEAL_MS - 60_000,
            issuer: issuer.into(),
            audience: "seam-runtime".into(),
            accepted_at_ms: SEAL_MS - 1_000,
        });
    }

    fn genuine() -> Vec<ExplanationEntry> {
        let iss = issuer();
        let mut eval = vote("a");
        eval.kind = "evaluation".into();
        let (mut a, mut b) = (vote("a"), vote("b"));
        sign(&mut a, 11, &iss, SESSION);
        sign(&mut b, 12, &iss, SESSION);
        vec![eval, a, b]
    }

    #[test]
    fn the_shared_tamper_table_agrees_with_the_runtime() {
        type Mutate = fn(&mut Vec<ExplanationEntry>);
        // (case, mutation, accepted without a decision, accepted bound to dec:acme:SESSION)
        let cases: &[(&str, Mutate, bool, bool)] = &[
            ("genuine", |_| {}, true, true),
            (
                "vote_without_record",
                |c| c[2].voter_verification = None,
                false,
                false,
            ),
            (
                "record_on_an_evaluation",
                |c| c[0].voter_verification = c[1].voter_verification.clone(),
                false,
                false,
            ),
            (
                "wrong_issuer",
                |c| {
                    for (e, seed) in c[1..].iter_mut().zip([11, 12]) {
                        sign(e, seed, "aid:pubkey:ed25519:another-runtime", SESSION);
                    }
                },
                false,
                false,
            ),
            (
                "mixed_sessions",
                |c| sign(&mut c[2], 12, &issuer(), OTHER_SESSION),
                false,
                false,
            ),
            (
                "transplanted_from_another_session",
                |c| {
                    for (e, seed) in c[1..].iter_mut().zip([11, 12]) {
                        sign(e, seed, &issuer(), OTHER_SESSION);
                    }
                },
                true,
                false,
            ),
            (
                "tampered_signature",
                |c| c[1].voter_verification.as_mut().unwrap().signature[0] ^= 1,
                false,
                false,
            ),
            // Beyond the runtime's table: the entry, the window and the method are all load-bearing.
            ("edited_reason", |c| c[1].reason.push('!'), false, false),
            (
                "outside_the_window",
                |c| c[1].voter_verification.as_mut().unwrap().accepted_at_ms = SEAL_MS + 300_001,
                false,
                false,
            ),
            (
                "cp_signed_is_not_served",
                |c| c[1].voter_verification.as_mut().unwrap().method = "cp_signed".into(),
                false,
                false,
            ),
            (
                "a_signer_certificate_on_pop",
                |c| c[1].voter_verification.as_mut().unwrap().signer_certificate = vec![1],
                false,
                false,
            ),
            (
                "an_objection_needs_one_too",
                |c| {
                    c[2].kind = "objection".into();
                    c[2].voter_verification = None;
                },
                false,
                false,
            ),
        ];
        let iss = issuer();
        for (name, mutate, unbound, bound) in cases {
            let mut c = genuine();
            mutate(&mut c);
            assert_eq!(
                verify_commitment_voters(&c, &iss, None).is_ok(),
                *unbound,
                "{name}: unbound"
            );
            assert_eq!(
                verify_commitment_voters(&c, &iss, Some(("acme", SESSION))).is_ok(),
                *bound,
                "{name}: decision-bound"
            );
        }
        assert_eq!(verify_commitment_voters(&genuine(), &iss, None), Ok(2));
        // The pin is compared by key: the untagged spelling of the same key is the same issuer.
        let untagged = iss.replace("aid:pubkey:ed25519:", "aid:pubkey:");
        assert_eq!(verify_commitment_voters(&genuine(), &untagged, None), Ok(2));
    }
}
