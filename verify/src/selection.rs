//! Option selection (seam-runtime 0.90.0, option selection S1): the sealed `seam.selection.weighted_plurality`
//! v1 block, its strict decode, `selection_digest` (commitment digest v5 field 9), `decide()`, and the
//! offline verifier's selection steps.
//!
//! Written from `seam-runtime/docs/specs/selection-rule.v1.md` §3-§5 (not vendored here; the evidence-bundle
//! spec in `docs/evidence-bundle.v1.md` cites it) and pinned by `conformance/selection_rule_v1_vectors.json`.
//! Nothing of Seam's is linked: this is a port from the spec text, like [`crate::commitment`] and
//! [`crate::voter`].
//!
//! **Absent means "not a selection decision", and nothing else.** A commitment with no selection block is
//! never reported as a passed selection, and a present block that does not decode is never downgraded to
//! "absent": it fails closed.
//!
//! Framing is the commitment digest's: `F(x) = be64(len(x)) ‖ x`, `U(n) = be64(n)`. The vote content digest
//! (step 8) is `seam-vote-content-v1`, which frames with `u32_LE(len) ‖ x` instead ([`crate::voter`]).

use sha2::{Digest, Sha256};

use crate::commitment::ExplanationEntry;
use crate::voter::{vote_content_digest, ContentContext, VotePolicy};

/// The selection digest's domain tag (`seam-commitment-digest.v5.md` § Field 9).
pub const SELECTION_DIGEST_DOMAIN: &[u8] = b"seam-selection-digest:v1";
/// The one rule v1 defines.
pub const RULE: &str = "seam.selection.weighted_plurality";
/// The one rule version v1 defines.
pub const RULE_VERSION: u32 = 1;
/// The only v1 tie policy.
pub const TIE: &str = "no_winner";
/// The only v1 abstention policy.
pub const ABSTENTION: &str = "excluded_counts_for_quorum";
/// Selection is admitted only on decision mode, so the content digest uses this constant (mode is not sealed).
pub const DECISION_MODE: &str = "macp.mode.decision.v1";
/// The `0x04` trailer's marker.
pub const SELECTION_TRAILER: u8 = 0x04;
/// The `0x04` trailer body's version byte (not a presence byte, and not hashed).
pub const SELECTION_BODY_V1: u8 = 0x01;

/// The sealed selection block (`body`, spec §4.2), field for field in body order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionBlock {
    pub rule: String,
    pub rule_version: u32,
    pub default_weight: u32,
    /// Overrides, strictly ascending by the participant's UTF-8 bytes.
    pub weights: Vec<(String, u32)>,
    pub tie: String,
    pub abstention: String,
    pub min_ballots: u32,
    /// The bound policy id (`VotePolicyRef.policy_version`).
    pub policy_version: String,
    /// The bound `policy_rules_digest`.
    pub rules_digest: [u8; 32],
    /// `OpenSessionRequest.participants`, request order.
    pub participants: Vec<String>,
    /// As opened, request order.
    pub on_behalf_of: Vec<String>,
    /// The sealed context pairs, sealed order (`content_hash` is `""` when the binding carries none).
    pub context: Vec<ContentContext>,
    /// Never empty: a no-winner session cannot commit.
    pub winner_proposal_id: String,
}

fn put_f(b: &mut Vec<u8>, x: &[u8]) {
    b.extend_from_slice(&(x.len() as u64).to_be_bytes());
    b.extend_from_slice(x);
}

fn put_u(b: &mut Vec<u8>, n: u64) {
    b.extend_from_slice(&n.to_be_bytes());
}

/// The canonical `body` (spec §4.2). Encodes what it is given; [`decode_body`] is where order and
/// presence are refused, so a caller holding a block from an untrusted transport re-decodes the bytes.
pub fn encode_body(s: &SelectionBlock) -> Vec<u8> {
    let mut b = Vec::new();
    put_f(&mut b, s.rule.as_bytes());
    put_u(&mut b, s.rule_version.into());
    put_u(&mut b, s.default_weight.into());
    put_u(&mut b, s.weights.len() as u64);
    for (p, w) in &s.weights {
        put_f(&mut b, p.as_bytes());
        put_u(&mut b, (*w).into());
    }
    put_f(&mut b, s.tie.as_bytes());
    put_f(&mut b, s.abstention.as_bytes());
    put_u(&mut b, s.min_ballots.into());
    put_f(&mut b, s.policy_version.as_bytes());
    put_f(&mut b, &s.rules_digest);
    put_u(&mut b, s.participants.len() as u64);
    for p in &s.participants {
        put_f(&mut b, p.as_bytes());
    }
    put_u(&mut b, s.on_behalf_of.len() as u64);
    for o in &s.on_behalf_of {
        put_f(&mut b, o.as_bytes());
    }
    put_u(&mut b, s.context.len() as u64);
    for c in &s.context {
        put_f(&mut b, c.ctx_ref.as_bytes());
        put_f(&mut b, c.content_hash.as_bytes());
    }
    put_f(&mut b, s.winner_proposal_id.as_bytes());
    b
}

/// `selection_digest = SHA-256(F("seam-selection-digest:v1") ‖ body)`: the 32 bytes v5 field 9 frames.
pub fn selection_digest(body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((SELECTION_DIGEST_DOMAIN.len() as u64).to_be_bytes());
    h.update(SELECTION_DIGEST_DOMAIN);
    h.update(body);
    h.finalize().into()
}

/// Why a block (or its `0x04` trailer) does not decode. Each refuses the whole commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeRefusal {
    /// A length or count overruns the bytes.
    Truncated,
    /// A u32 field's `be64` exceeds `2^32-1`.
    U32Overflow,
    /// `weights` not strictly ascending by participant bytes (duplicates included).
    WeightsNotCanonical,
    /// `rules_digest` is not exactly 32 bytes.
    RulesDigestNot32,
    /// A string is not UTF-8.
    InvalidUtf8,
    /// `winner_proposal_id` is empty.
    EmptyWinner,
    /// Bytes after the winner, or after the trailer's declared length.
    TrailingBytes,
    /// Trailer only: the marker is not `0x04`.
    WrongMarker,
    /// Trailer only: the declared length is zero.
    ZeroLengthBody,
    /// Trailer only: the body version byte is not `0x01`.
    UnknownVersion,
}

impl DecodeRefusal {
    /// The spec's name for the refusal.
    pub fn name(self) -> &'static str {
        match self {
            Self::Truncated => "truncated",
            Self::U32Overflow => "u32_overflow",
            Self::WeightsNotCanonical => "weights_not_canonical",
            Self::RulesDigestNot32 => "rules_digest_not_32",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::EmptyWinner => "empty_winner",
            Self::TrailingBytes => "trailing_bytes",
            Self::WrongMarker => "wrong_marker",
            Self::ZeroLengthBody => "zero_length_body",
            Self::UnknownVersion => "unknown_version",
        }
    }
}

impl std::fmt::Display for DecodeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: u64) -> Result<&'a [u8], DecodeRefusal> {
        let left = (self.b.len() - self.i) as u64;
        if n > left {
            return Err(DecodeRefusal::Truncated);
        }
        let n = n as usize;
        let out = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(out)
    }
    fn u(&mut self) -> Result<u64, DecodeRefusal> {
        let x = self.take(8)?;
        Ok(u64::from_be_bytes(x.try_into().expect("8 bytes")))
    }
    fn u32(&mut self) -> Result<u32, DecodeRefusal> {
        u32::try_from(self.u()?).map_err(|_| DecodeRefusal::U32Overflow)
    }
    /// A count whose items are each at least `min_item` bytes: one that cannot fit in what is left is
    /// refused before any allocation.
    fn count(&mut self, min_item: u64) -> Result<usize, DecodeRefusal> {
        let n = self.u()?;
        let left = (self.b.len() - self.i) as u128;
        if u128::from(n) * u128::from(min_item) > left {
            return Err(DecodeRefusal::Truncated);
        }
        Ok(n as usize)
    }
    fn f(&mut self) -> Result<&'a [u8], DecodeRefusal> {
        let n = self.u()?;
        self.take(n)
    }
    fn text(&mut self) -> Result<String, DecodeRefusal> {
        std::str::from_utf8(self.f()?)
            .map(str::to_owned)
            .map_err(|_| DecodeRefusal::InvalidUtf8)
    }
}

/// The strict structural decode (spec §4.2 *Strict decode*). Semantic checks are [`decide`]'s.
pub fn decode_body(b: &[u8]) -> Result<SelectionBlock, DecodeRefusal> {
    let mut r = Reader { b, i: 0 };
    let rule = r.text()?;
    let rule_version = r.u32()?;
    let default_weight = r.u32()?;
    let mut weights = Vec::new();
    for _ in 0..r.count(16)? {
        let p = r.text()?;
        let w = r.u32()?;
        weights.push((p, w));
    }
    if weights
        .windows(2)
        .any(|w| w[0].0.as_bytes() >= w[1].0.as_bytes())
    {
        return Err(DecodeRefusal::WeightsNotCanonical);
    }
    let tie = r.text()?;
    let abstention = r.text()?;
    let min_ballots = r.u32()?;
    let policy_version = r.text()?;
    let rules_digest: [u8; 32] = r
        .f()?
        .try_into()
        .map_err(|_| DecodeRefusal::RulesDigestNot32)?;
    let mut participants = Vec::new();
    for _ in 0..r.count(8)? {
        participants.push(r.text()?);
    }
    let mut on_behalf_of = Vec::new();
    for _ in 0..r.count(8)? {
        on_behalf_of.push(r.text()?);
    }
    let mut context = Vec::new();
    for _ in 0..r.count(16)? {
        let ctx_ref = r.text()?;
        let content_hash = r.text()?;
        context.push(ContentContext {
            ctx_ref,
            content_hash,
        });
    }
    let winner_proposal_id = r.text()?;
    if winner_proposal_id.is_empty() {
        return Err(DecodeRefusal::EmptyWinner);
    }
    if r.i != b.len() {
        return Err(DecodeRefusal::TrailingBytes);
    }
    Ok(SelectionBlock {
        rule,
        rule_version,
        default_weight,
        weights,
        tie,
        abstention,
        min_ballots,
        policy_version,
        rules_digest,
        participants,
        on_behalf_of,
        context,
        winner_proposal_id,
    })
}

/// `trailer_0x04 = 0x04 ‖ u32_LE(1 + len(body)) ‖ 0x01 ‖ body` (spec §4.3).
pub fn encode_trailer(body: &[u8]) -> Vec<u8> {
    let mut t = vec![SELECTION_TRAILER];
    t.extend_from_slice(&((body.len() + 1) as u32).to_le_bytes());
    t.push(SELECTION_BODY_V1);
    t.extend_from_slice(body);
    t
}

/// Decode one `0x04` trailer standing alone (spec §4.3). This crate never opens a sealed trailer list (the
/// bundle carries the body itself); this is here so the spec's trailer refusals are pinned.
pub fn decode_trailer(t: &[u8]) -> Result<SelectionBlock, DecodeRefusal> {
    if t.len() < 5 {
        return Err(DecodeRefusal::Truncated);
    }
    if t[0] != SELECTION_TRAILER {
        return Err(DecodeRefusal::WrongMarker);
    }
    let n = u32::from_le_bytes(t[1..5].try_into().expect("4 bytes")) as usize;
    if n == 0 {
        return Err(DecodeRefusal::ZeroLengthBody);
    }
    let rest = &t[5..];
    if rest.len() < n {
        return Err(DecodeRefusal::Truncated);
    }
    if rest.len() > n {
        return Err(DecodeRefusal::TrailingBytes);
    }
    if rest[0] != SELECTION_BODY_V1 {
        return Err(DecodeRefusal::UnknownVersion);
    }
    decode_body(&rest[1..])
}

/// The tally behind a [`Decision`]: each proposal's score in proposal order, and the ballot count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tally {
    pub scores: Vec<(String, u64)>,
    pub ballots: usize,
}

/// What `decide()` returns (spec §3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The unique top proposal.
    Winner {
        proposal_id: String,
        option: String,
        tally: Tally,
    },
    /// `below_min_ballots`, `no_positive_score` or `tie`.
    NoWinner { reason: &'static str, tally: Tally },
    /// A record or entry check failed; `at` is the entry index (`None` for a record check).
    Malformed {
        reason: &'static str,
        at: Option<usize>,
    },
}

fn validate_record(s: &SelectionBlock) -> Option<&'static str> {
    if s.rule != RULE {
        return Some("unknown_rule");
    }
    if s.rule_version != RULE_VERSION {
        return Some("unknown_rule_version");
    }
    if s.tie != TIE {
        return Some("unknown_tie");
    }
    if s.abstention != ABSTENTION {
        return Some("unknown_abstention");
    }
    if s.weights
        .windows(2)
        .any(|w| w[0].0.as_bytes() >= w[1].0.as_bytes())
    {
        return Some("weights_not_canonical");
    }
    if s.default_weight == 0 && s.weights.iter().all(|(_, w)| *w == 0) {
        return Some("zero_electorate");
    }
    if s.min_ballots == 0 {
        return Some("min_ballots_zero");
    }
    if s.participants.is_empty() {
        return Some("no_participants");
    }
    let mut seen = std::collections::HashSet::new();
    if !s.participants.iter().all(|p| seen.insert(p.as_str())) {
        return Some("duplicate_participant");
    }
    None
}

fn weight_of(s: &SelectionBlock, participant: &str) -> u32 {
    s.weights
        .iter()
        .find(|(p, _)| p == participant)
        .map_or(s.default_weight, |(_, w)| *w)
}

/// `decide(record, entries)` (spec §3): a pure function of the block (its winner is ignored) and the
/// explanation entries in sealed order. Checks run in the spec's order; the first failure is the result.
pub fn decide(s: &SelectionBlock, entries: &[ExplanationEntry]) -> Decision {
    use std::collections::HashSet;
    if let Some(reason) = validate_record(s) {
        return Decision::Malformed { reason, at: None };
    }
    let mut proposals: Vec<(&str, &str)> = Vec::new();
    let mut options: HashSet<&[u8]> = HashSet::new();
    let mut voted: HashSet<(&str, &str)> = HashSet::new();
    let mut approvers: HashSet<&str> = HashSet::new();
    let mut voters: Vec<&str> = Vec::new();
    let mut approvals: Vec<(&str, &str)> = Vec::new();
    let mut seen_vote = false;
    for (i, e) in entries.iter().enumerate() {
        let mal = |reason| Decision::Malformed {
            reason,
            at: Some(i),
        };
        match e.kind.as_str() {
            "proposal" => {
                if seen_vote {
                    return mal("proposal_after_vote");
                }
                if e.voter_verification.is_some() {
                    return mal("proposal_has_voter_record");
                }
                if !e.reason.is_empty() || e.confidence.is_some() || e.rationale_ref.is_some() {
                    return mal("proposal_has_extra_fields");
                }
                if e.proposal_id.is_empty() {
                    return mal("empty_proposal_id");
                }
                if e.value.is_empty() {
                    return mal("empty_option");
                }
                if proposals.iter().any(|(p, _)| *p == e.proposal_id) {
                    return mal("duplicate_proposal_id");
                }
                if !options.insert(e.value.as_bytes()) {
                    return mal("duplicate_option");
                }
                proposals.push((&e.proposal_id, &e.value));
            }
            "vote" => {
                seen_vote = true;
                if !proposals.iter().any(|(p, _)| *p == e.proposal_id) {
                    return mal("vote_unknown_proposal");
                }
                if !matches!(e.value.as_str(), "APPROVE" | "REJECT" | "ABSTAIN") {
                    return mal("vote_bad_value");
                }
                if !s.participants.contains(&e.participant) {
                    return mal("vote_not_participant");
                }
                let key = (e.participant.as_str(), e.proposal_id.as_str());
                if voted.contains(&key) {
                    return mal("duplicate_vote");
                }
                if e.value == "APPROVE" {
                    if !approvers.insert(&e.participant) {
                        return mal("double_approve");
                    }
                    approvals.push(key);
                }
                voted.insert(key);
                if !voters.contains(&e.participant.as_str()) {
                    voters.push(&e.participant);
                }
            }
            // Sealed, never scored: v1 has no objection veto.
            "evaluation" | "objection" => {}
            "ballot" => return mal("ballot_in_selection"),
            _ => return mal("unknown_kind"),
        }
    }
    if proposals.is_empty() {
        return Decision::Malformed {
            reason: "no_proposals",
            at: None,
        };
    }
    let mut scores: Vec<(String, u64)> = proposals
        .iter()
        .map(|(p, _)| ((*p).to_owned(), 0))
        .collect();
    for (voter, pid) in &approvals {
        let slot = scores
            .iter_mut()
            .find(|(p, _)| p == pid)
            .expect("a vote names a known proposal");
        slot.1 += u64::from(weight_of(s, voter));
    }
    let top = scores.iter().map(|(_, sc)| *sc).max().unwrap_or(0);
    let leaders: Vec<usize> = (0..scores.len()).filter(|&i| scores[i].1 == top).collect();
    let tally = Tally {
        scores,
        ballots: voters.len(),
    };
    if tally.ballots < s.min_ballots as usize {
        return Decision::NoWinner {
            reason: "below_min_ballots",
            tally,
        };
    }
    if top == 0 {
        return Decision::NoWinner {
            reason: "no_positive_score",
            tally,
        };
    }
    if leaders.len() > 1 {
        return Decision::NoWinner {
            reason: "tie",
            tally,
        };
    }
    let (pid, option) = proposals[leaders[0]];
    Decision::Winner {
        proposal_id: pid.to_owned(),
        option: option.to_owned(),
        tally,
    }
}

/// A selection decision that re-verified offline (spec §5 steps 6-9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionVerified {
    pub winner_proposal_id: String,
    /// How many `vote` entries' content digests linked to the sealed option they credit.
    pub votes_linked: usize,
}

/// Why a sealed selection did not re-verify (spec §5's verifier result names).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectionFailure {
    /// `decide()` found the record or entries malformed (a forgery).
    Malformed {
        reason: &'static str,
        at: Option<usize>,
    },
    /// `decide()` found no winner, but a winner was sealed.
    NoWinnerSealed { reason: &'static str },
    /// The winner recomputes to another proposal than the sealed one.
    WinnerMismatch { recomputed: String },
    /// The committed action is not the winner's sealed option, byte for byte.
    ActionMismatch,
    /// A `vote` entry carries no voter record.
    VoteUnverified { at: usize },
    /// A vote's signed content digest does not link to the sealed option it credits.
    ContentLinkMismatch { at: usize },
    /// A participant maps to two principals, or a principal to two participants.
    PrincipalNotOneToOne { at: usize },
}

impl SelectionFailure {
    /// The spec's result name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Malformed { .. } => "selection_malformed",
            Self::NoWinnerSealed { .. } => "selection_no_winner_sealed",
            Self::WinnerMismatch { .. } => "selection_winner_mismatch",
            Self::ActionMismatch => "selection_action_mismatch",
            Self::VoteUnverified { .. } => "selection_vote_unverified",
            Self::ContentLinkMismatch { .. } => "selection_content_link_mismatch",
            Self::PrincipalNotOneToOne { .. } => "selection_principal_not_one_to_one",
        }
    }
    /// The entry index the failure is at, where the spec names one.
    pub fn at(&self) -> Option<usize> {
        match self {
            Self::Malformed { at, .. } => *at,
            Self::VoteUnverified { at }
            | Self::ContentLinkMismatch { at }
            | Self::PrincipalNotOneToOne { at } => Some(*at),
            _ => None,
        }
    }
}

impl std::fmt::Display for SelectionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.name();
        match self {
            Self::Malformed { reason, at } => match at {
                Some(i) => write!(f, "{n} ({reason} at explanation[{i}])"),
                None => write!(f, "{n} ({reason})"),
            },
            Self::NoWinnerSealed { reason } => {
                write!(f, "{n} (the rule finds no winner: {reason})")
            }
            Self::WinnerMismatch { recomputed } => {
                write!(f, "{n} (the winner recomputes to '{recomputed}')")
            }
            Self::ActionMismatch => {
                write!(
                    f,
                    "{n} (the action is not the winning option, byte for byte)"
                )
            }
            Self::VoteUnverified { at }
            | Self::ContentLinkMismatch { at }
            | Self::PrincipalNotOneToOne { at } => write!(f, "{n} at explanation[{at}]"),
        }
    }
}

/// The offline verifier's selection steps (spec §5 steps 6-9), over a strictly decoded block, the sealed
/// entries and the committed action. Steps 1-3 and 5 (decode, digests, TCT, voter records) are the caller's.
pub fn verify_selection(
    s: &SelectionBlock,
    entries: &[ExplanationEntry],
    action: &str,
) -> Result<SelectionVerified, SelectionFailure> {
    let (winner, option) = match decide(s, entries) {
        Decision::Malformed { reason, at } => {
            return Err(SelectionFailure::Malformed { reason, at })
        }
        Decision::NoWinner { reason, .. } => {
            return Err(SelectionFailure::NoWinnerSealed { reason })
        }
        Decision::Winner {
            proposal_id,
            option,
            ..
        } => (proposal_id, option),
    };
    if winner != s.winner_proposal_id {
        return Err(SelectionFailure::WinnerMismatch { recomputed: winner });
    }
    if option.as_bytes() != action.as_bytes() {
        return Err(SelectionFailure::ActionMismatch);
    }
    let option_of = |pid: &str| {
        entries
            .iter()
            .find(|e| e.kind == "proposal" && e.proposal_id == pid)
            .map(|e| e.value.as_str())
    };
    let participants: Vec<&str> = s.participants.iter().map(String::as_str).collect();
    let on_behalf_of: Vec<&str> = s.on_behalf_of.iter().map(String::as_str).collect();
    let policy = VotePolicy {
        policy_version: &s.policy_version,
        rules_digest: &s.rules_digest,
    };
    let mut linked = 0;
    for (at, e) in entries.iter().enumerate() {
        if e.kind != "vote" {
            continue;
        }
        let Some(vv) = e.voter_verification.as_ref() else {
            return Err(SelectionFailure::VoteUnverified { at });
        };
        let content =
            option_of(&e.proposal_id).ok_or(SelectionFailure::ContentLinkMismatch { at })?;
        let want = vote_content_digest(
            DECISION_MODE,
            &e.proposal_id,
            content,
            &participants,
            &on_behalf_of,
            &s.context,
            &[],
            Some(policy),
        )
        .map_err(|_| SelectionFailure::ContentLinkMismatch { at })?;
        if vv.content_digest.as_slice() != want.as_slice() {
            return Err(SelectionFailure::ContentLinkMismatch { at });
        }
        linked += 1;
    }
    let mut p2a: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    let mut a2p: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for (at, e) in entries.iter().enumerate() {
        if e.kind != "vote" {
            continue;
        }
        let p = e.participant.as_str();
        let a = e
            .voter_verification
            .as_ref()
            .expect("checked above")
            .principal
            .as_str();
        if *p2a.entry(p).or_insert(a) != a || *a2p.entry(a).or_insert(p) != p {
            return Err(SelectionFailure::PrincipalNotOneToOne { at });
        }
    }
    Ok(SelectionVerified {
        winner_proposal_id: winner,
        votes_linked: linked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block() -> SelectionBlock {
        SelectionBlock {
            rule: RULE.into(),
            rule_version: 1,
            default_weight: 1,
            weights: vec![("bob".into(), 2)],
            tie: TIE.into(),
            abstention: ABSTENTION.into(),
            min_ballots: 2,
            policy_version: "loan-panel".into(),
            rules_digest: [7; 32],
            participants: vec!["orchestrator".into(), "alice".into(), "bob".into()],
            on_behalf_of: vec![],
            context: vec![],
            winner_proposal_id: "p2".into(),
        }
    }

    fn entry(kind: &str, who: &str, pid: &str, value: &str) -> ExplanationEntry {
        ExplanationEntry {
            kind: kind.into(),
            participant: who.into(),
            proposal_id: pid.into(),
            value: value.into(),
            reason: String::new(),
            confidence: None,
            rationale_ref: None,
            voter_verification: None,
        }
    }

    fn entries() -> Vec<ExplanationEntry> {
        vec![
            entry("proposal", "orchestrator", "p1", "rate 5%"),
            entry("proposal", "orchestrator", "p2", "rate 7%"),
            entry("vote", "alice", "p1", "APPROVE"),
            entry("vote", "bob", "p2", "APPROVE"),
        ]
    }

    #[test]
    fn a_block_round_trips_through_its_body() {
        let b = block();
        assert_eq!(decode_body(&encode_body(&b)), Ok(b.clone()));
        let t = encode_trailer(&encode_body(&b));
        assert_eq!(decode_trailer(&t), Ok(b));
    }

    #[test]
    fn strict_decode_refuses_by_name() {
        let body = encode_body(&block());
        let mut trailing = body.clone();
        trailing.push(0);
        assert_eq!(decode_body(&trailing), Err(DecodeRefusal::TrailingBytes));
        assert_eq!(
            decode_body(&body[..body.len() - 1]),
            Err(DecodeRefusal::Truncated)
        );
        let mut empty = block();
        empty.winner_proposal_id.clear();
        assert_eq!(
            decode_body(&encode_body(&empty)),
            Err(DecodeRefusal::EmptyWinner)
        );
        let mut unsorted = block();
        unsorted.weights = vec![("carol".into(), 1), ("bob".into(), 1)];
        assert_eq!(
            decode_body(&encode_body(&unsorted)),
            Err(DecodeRefusal::WeightsNotCanonical)
        );
        // A count that claims more items than the bytes could hold is refused before allocation.
        let mut huge = Vec::new();
        put_f(&mut huge, RULE.as_bytes());
        put_u(&mut huge, 1);
        put_u(&mut huge, 1);
        put_u(&mut huge, u64::MAX);
        assert_eq!(decode_body(&huge), Err(DecodeRefusal::Truncated));
        let mut over = Vec::new();
        put_f(&mut over, RULE.as_bytes());
        put_u(&mut over, 1u64 << 32);
        assert_eq!(decode_body(&over), Err(DecodeRefusal::U32Overflow));
    }

    #[test]
    fn the_weighted_winner_wins_and_a_weight_edit_flips_it() {
        match decide(&block(), &entries()) {
            Decision::Winner { proposal_id, .. } => assert_eq!(proposal_id, "p2"),
            d => panic!("{d:?}"),
        }
        let mut tampered = block();
        tampered.weights = vec![("alice".into(), 3)];
        match decide(&tampered, &entries()) {
            Decision::Winner { proposal_id, .. } => assert_eq!(proposal_id, "p1"),
            d => panic!("{d:?}"),
        }
        // The sealed winner is p2, so the verifier names the recomputed one.
        assert_eq!(
            verify_selection(&tampered, &entries(), "rate 7%"),
            Err(SelectionFailure::WinnerMismatch {
                recomputed: "p1".into()
            })
        );
    }

    #[test]
    fn an_unverified_vote_and_a_wrong_action_fail_by_name() {
        assert_eq!(
            verify_selection(&block(), &entries(), "rate 7% "),
            Err(SelectionFailure::ActionMismatch)
        );
        assert_eq!(
            verify_selection(&block(), &entries(), "rate 7%"),
            Err(SelectionFailure::VoteUnverified { at: 2 })
        );
    }
}
