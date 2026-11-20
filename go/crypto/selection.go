package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

// SelectionDigestDomain is the domain tag of the option-selection block digest that
// `seam-commitment-digest:v5` binds as field 9 (runtime 0.90.0, seam-runtime docs/specs/selection-rule.v1.md).
const SelectionDigestDomain = "seam-selection-digest:v1"

// SelectionWeight is one weight override of a SelectionBlock.
type SelectionWeight struct {
	Participant string `json:"participant"`
	Weight      uint32 `json:"weight"`
}

// SelectionContext is one sealed context pair of a SelectionBlock (ContentHash "" when the binding
// carries none).
type SelectionContext struct {
	CtxRef      string `json:"ctx_ref"`
	ContentHash string `json:"content_hash"`
}

// SelectionBlock is the sealed `seam.selection.weighted_plurality` block (selection-rule.v1 §4.2), field
// for field in `body` order — the generated `SelectionRecord` (`Commitment.selection = 12`) maps onto it
// one to one. Weights are strictly ascending by the participant's UTF-8 bytes; RulesDigest is the 32-byte
// bound `policy_rules_digest`; WinnerProposalID is never empty.
type SelectionBlock struct {
	Rule             string             `json:"rule"`
	RuleVersion      uint32             `json:"rule_version"`
	DefaultWeight    uint32             `json:"default_weight"`
	Weights          []SelectionWeight  `json:"weights"`
	Tie              string             `json:"tie"`
	Abstention       string             `json:"abstention"`
	MinBallots       uint32             `json:"min_ballots"`
	PolicyVersion    string             `json:"policy_version"`
	RulesDigest      []byte             `json:"-"`
	Participants     []string           `json:"participants"`
	OnBehalfOf       []string           `json:"on_behalf_of"`
	Context          []SelectionContext `json:"context"`
	WinnerProposalID string             `json:"winner_proposal_id"`
}

// SelectionBody is the canonical selection block `body` (selection-rule.v1 §4.2), framed only with
// F(x) = be64(len(x)) ‖ x and U(n) = be64(n). A block the runtime could not have sealed is refused, never
// hashed: weights not strictly ascending by participant UTF-8 bytes (duplicates included), a RulesDigest
// that is not 32 bytes, or an empty WinnerProposalID.
//
// Framing the block only binds it; Decide and VerifySelection (§3, §5 steps 6-9) recompute the winner
// from the sealed entries, and VerifyTCT runs VerifySelection whenever Commitment.Selection is set.
func SelectionBody(b SelectionBlock) ([]byte, error) {
	for i := 1; i < len(b.Weights); i++ {
		if bytes.Compare([]byte(b.Weights[i-1].Participant), []byte(b.Weights[i].Participant)) >= 0 {
			return nil, errors.New("selection weights are not strictly ascending by participant (weights_not_canonical)")
		}
	}
	if len(b.RulesDigest) != sha256.Size {
		return nil, fmt.Errorf("selection rules_digest must be %d bytes, got %d", sha256.Size, len(b.RulesDigest))
	}
	if b.WinnerProposalID == "" {
		return nil, errors.New("selection winner_proposal_id is empty (empty_winner)")
	}
	u := func(out []byte, n uint64) []byte { return binary.BigEndian.AppendUint64(out, n) }
	var out []byte
	out = be64Frame(out, []byte(b.Rule))
	out = u(out, uint64(b.RuleVersion))
	out = u(out, uint64(b.DefaultWeight))
	out = u(out, uint64(len(b.Weights)))
	for _, w := range b.Weights {
		out = be64Frame(out, []byte(w.Participant))
		out = u(out, uint64(w.Weight))
	}
	out = be64Frame(out, []byte(b.Tie))
	out = be64Frame(out, []byte(b.Abstention))
	out = u(out, uint64(b.MinBallots))
	out = be64Frame(out, []byte(b.PolicyVersion))
	out = be64Frame(out, b.RulesDigest)
	out = u(out, uint64(len(b.Participants)))
	for _, p := range b.Participants {
		out = be64Frame(out, []byte(p))
	}
	out = u(out, uint64(len(b.OnBehalfOf)))
	for _, o := range b.OnBehalfOf {
		out = be64Frame(out, []byte(o))
	}
	out = u(out, uint64(len(b.Context)))
	for _, c := range b.Context {
		out = be64Frame(out, []byte(c.CtxRef))
		out = be64Frame(out, []byte(c.ContentHash))
	}
	out = be64Frame(out, []byte(b.WinnerProposalID))
	return out, nil
}

// SelectionDigest is SHA-256(F("seam-selection-digest:v1") ‖ body): the 32 bytes v5 field 9 binds.
func SelectionDigest(body []byte) [32]byte {
	return sha256.Sum256(append(be64Frame(nil, []byte(SelectionDigestDomain)), body...))
}

// selectionSlot is field 9's 32 bytes: from Selection when set (giving both it and SelectionDigest is
// refused), else SelectionDigest as given (nil = absent).
func selectionSlot(c Commitment) ([]byte, error) {
	if c.Selection == nil {
		return c.SelectionDigest, nil
	}
	if c.SelectionDigest != nil {
		return nil, errors.New("give Selection or SelectionDigest, not both")
	}
	body, err := SelectionBody(*c.Selection)
	if err != nil {
		return nil, err
	}
	d := SelectionDigest(body)
	return d[:], nil
}

// The closed selection-rule.v1 vocabulary a record must carry (§3).
const (
	SelectionRule        = "seam.selection.weighted_plurality"
	SelectionRuleVersion = 1
	SelectionTie         = "no_winner"
	SelectionAbstention  = "excluded_counts_for_quorum"
	// SelectionMode is the canonical mode id a selection vote's `seam-vote-content-v1` digest frames.
	SelectionMode = "macp.mode.decision.v1"
)

// SelectionVoteValues are the vote values a selection session admits.
var SelectionVoteValues = []string{"APPROVE", "REJECT", "ABSTAIN"}

// SelectionScore is one proposal's weighted APPROVE total, in sealed proposal order.
type SelectionScore struct {
	ProposalID string `json:"proposal_id"`
	Score      uint64 `json:"score"`
}

// SelectionDecision is Decide's outcome. Result is "winner", "no_winner" or "malformed". Reason is set
// for no_winner ("below_min_ballots", "no_positive_score", "tie") and malformed (the §3 reason words).
// At is the entry index a malformed check failed at, -1 for a record-level check (Python's None).
// Scores and Ballots are set for winner and no_winner; WinnerProposalID and Option for winner.
type SelectionDecision struct {
	Result           string
	WinnerProposalID string
	Option           string
	Scores           []SelectionScore
	Ballots          int
	Reason           string
	At               int
}

func selectionRecordMalformed(b SelectionBlock) string {
	switch {
	case b.Rule != SelectionRule:
		return "unknown_rule"
	case b.RuleVersion != SelectionRuleVersion:
		return "unknown_rule_version"
	case b.Tie != SelectionTie:
		return "unknown_tie"
	case b.Abstention != SelectionAbstention:
		return "unknown_abstention"
	}
	for i := 1; i < len(b.Weights); i++ {
		if bytes.Compare([]byte(b.Weights[i-1].Participant), []byte(b.Weights[i].Participant)) >= 0 {
			return "weights_not_canonical"
		}
	}
	if b.DefaultWeight == 0 {
		allZero := true
		for _, w := range b.Weights {
			if w.Weight != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			return "zero_electorate"
		}
	}
	if b.MinBallots == 0 {
		return "min_ballots_zero"
	}
	if len(b.Participants) == 0 {
		return "no_participants"
	}
	seen := make(map[string]bool, len(b.Participants))
	for _, p := range b.Participants {
		if seen[p] {
			return "duplicate_participant"
		}
		seen[p] = true
	}
	return ""
}

// Decide is selection-rule.v1 §3 `decide(record, entries)`: a pure function of the selection record (its
// WinnerProposalID is ignored) and the sealed explanation entries (Kind as the lowercase digest word).
// Options compare by their UTF-8 bytes, never normalised. Twin of Python `decide` and Rust `decide`.
func Decide(record SelectionBlock, entries []ExplanationEntry) SelectionDecision {
	if bad := selectionRecordMalformed(record); bad != "" {
		return SelectionDecision{Result: "malformed", Reason: bad, At: -1}
	}
	weights := make(map[string]uint32, len(record.Weights))
	for _, w := range record.Weights {
		weights[w.Participant] = w.Weight
	}
	participants := make(map[string]bool, len(record.Participants))
	for _, p := range record.Participants {
		participants[p] = true
	}
	type vote struct{ who, pid string }
	proposals := map[string]string{}
	var order []string
	options := map[string]bool{} // Go string keys compare bytewise
	voted := map[vote]bool{}
	approvers := map[string]bool{}
	voters := map[string]bool{}
	var approvals []vote
	seenVote := false
	for i, e := range entries {
		mal := func(reason string) SelectionDecision {
			return SelectionDecision{Result: "malformed", Reason: reason, At: i}
		}
		switch e.Kind {
		case "proposal":
			switch {
			case seenVote:
				return mal("proposal_after_vote")
			case e.VoterVerification != nil:
				return mal("proposal_has_voter_record")
			case e.Reason != "" || e.Confidence != nil || e.RationaleRef != nil:
				return mal("proposal_has_extra_fields")
			case e.ProposalID == "":
				return mal("empty_proposal_id")
			case e.Value == "":
				return mal("empty_option")
			}
			if _, dup := proposals[e.ProposalID]; dup {
				return mal("duplicate_proposal_id")
			}
			if options[e.Value] {
				return mal("duplicate_option")
			}
			proposals[e.ProposalID] = e.Value
			order = append(order, e.ProposalID)
			options[e.Value] = true
		case "vote":
			seenVote = true
			v := vote{e.Participant, e.ProposalID}
			if _, ok := proposals[v.pid]; !ok {
				return mal("vote_unknown_proposal")
			}
			okValue := false
			for _, x := range SelectionVoteValues {
				if e.Value == x {
					okValue = true
					break
				}
			}
			if !okValue {
				return mal("vote_bad_value")
			}
			if !participants[v.who] {
				return mal("vote_not_participant")
			}
			if voted[v] {
				return mal("duplicate_vote")
			}
			if e.Value == "APPROVE" {
				if approvers[v.who] {
					return mal("double_approve")
				}
				approvers[v.who] = true
				approvals = append(approvals, v)
			}
			voted[v] = true
			voters[v.who] = true
		case "evaluation", "objection":
			// sealed, never scored (v1 admits no objection veto)
		case "ballot":
			return mal("ballot_in_selection")
		default:
			return mal("unknown_kind")
		}
	}
	if len(order) == 0 {
		return SelectionDecision{Result: "malformed", Reason: "no_proposals", At: -1}
	}
	score := make(map[string]uint64, len(order))
	for _, a := range approvals {
		w, ok := weights[a.who]
		if !ok {
			w = record.DefaultWeight
		}
		score[a.pid] += uint64(w)
	}
	scores := make([]SelectionScore, len(order))
	var top uint64
	for i, pid := range order {
		scores[i] = SelectionScore{ProposalID: pid, Score: score[pid]}
		if score[pid] > top {
			top = score[pid]
		}
	}
	var leaders []string
	for _, s := range scores {
		if s.Score == top {
			leaders = append(leaders, s.ProposalID)
		}
	}
	d := SelectionDecision{Scores: scores, Ballots: len(voters), At: -1}
	switch {
	case uint64(d.Ballots) < uint64(record.MinBallots):
		d.Result, d.Reason = "no_winner", "below_min_ballots"
	case top == 0:
		d.Result, d.Reason = "no_winner", "no_positive_score"
	case len(leaders) > 1:
		d.Result, d.Reason = "no_winner", "tie"
	default:
		d.Result, d.WinnerProposalID, d.Option = "winner", leaders[0], proposals[leaders[0]]
	}
	return d
}

// The VerifySelection result names (selection-rule.v1 §5).
const (
	SelectionVerified             = "verified"
	SelectionMalformed            = "selection_malformed"
	SelectionNoWinnerSealed       = "selection_no_winner_sealed"
	SelectionWinnerMismatch       = "selection_winner_mismatch"
	SelectionActionMismatch       = "selection_action_mismatch"
	SelectionVoteUnverified       = "selection_vote_unverified"
	SelectionContentLinkMismatch  = "selection_content_link_mismatch"
	SelectionPrincipalNotOneToOne = "selection_principal_not_one_to_one"
)

// SelectionResult is VerifySelection's outcome. Result is SelectionVerified or one of the §5 result
// names. At is the entry index the check failed at, -1 when the spec names none. Reason is Decide's
// reason for a malformed or no-winner record; Recomputed is this verifier's winner when it disagrees with
// the sealed one. WinnerProposalID and VotesLinked are set when verified.
type SelectionResult struct {
	Result           string
	WinnerProposalID string
	VotesLinked      int
	At               int
	Reason           string
	Recomputed       string
}

// OK reports Result == SelectionVerified.
func (r SelectionResult) OK() bool { return r.Result == SelectionVerified }

// VerifySelection is selection-rule.v1 §5 steps 6-9 over a sealed selection block, the sealed entries
// and `Commitment.action`. Step 6 recomputes the winner (Decide) and checks it is the sealed one; step 7
// checks the winner's option is action byte for byte; step 8 re-derives every vote's
// `seam-vote-content-v1` digest (SelectionMode, the proposal's option, the block's participants,
// on_behalf_of, context and policy) and checks it is the record's ContentDigest; step 9 checks
// participant <-> principal is one-to-one across the votes. It does not re-check signatures or the TCT:
// that is VerifyTCT's, which calls this when the commitment carries a block. Twin of Python
// `verify_selection`.
func VerifySelection(block SelectionBlock, entries []ExplanationEntry, action string) SelectionResult {
	d := Decide(block, entries)
	switch d.Result {
	case "malformed":
		return SelectionResult{Result: SelectionMalformed, Reason: d.Reason, At: d.At}
	case "no_winner":
		return SelectionResult{Result: SelectionNoWinnerSealed, Reason: d.Reason, At: -1}
	}
	if d.WinnerProposalID != block.WinnerProposalID {
		return SelectionResult{Result: SelectionWinnerMismatch, Recomputed: d.WinnerProposalID, At: -1}
	}
	if d.Option != action {
		return SelectionResult{Result: SelectionActionMismatch, At: -1}
	}
	proposals := map[string]string{}
	for _, e := range entries {
		if e.Kind == "proposal" {
			proposals[e.ProposalID] = e.Value
		}
	}
	ctx := make([]VoteContext, len(block.Context))
	for i, c := range block.Context {
		ctx[i] = VoteContext{CtxRef: c.CtxRef, ContentHash: c.ContentHash}
	}
	policy := &VotePolicyRef{PolicyVersion: block.PolicyVersion, RulesDigest: block.RulesDigest}
	linked := 0
	for i, e := range entries {
		if e.Kind != "vote" {
			continue
		}
		vv := e.VoterVerification
		if vv == nil {
			return SelectionResult{Result: SelectionVoteUnverified, At: i}
		}
		want, err := VoteContentDigest(VoteContent{
			Mode:         SelectionMode,
			ProposalID:   e.ProposalID,
			Content:      proposals[e.ProposalID],
			Participants: block.Participants,
			OnBehalfOf:   block.OnBehalfOf,
			Context:      ctx,
			Policy:       policy,
		})
		if err != nil || !bytes.Equal(vv.ContentDigest, want[:]) {
			return SelectionResult{Result: SelectionContentLinkMismatch, At: i}
		}
		linked++
	}
	byParticipant := map[string]string{}
	byPrincipal := map[string]string{}
	for i, e := range entries {
		if e.Kind != "vote" {
			continue
		}
		p, a := e.Participant, e.VoterVerification.Principal
		if got, ok := byParticipant[p]; ok && got != a {
			return SelectionResult{Result: SelectionPrincipalNotOneToOne, At: i}
		}
		if got, ok := byPrincipal[a]; ok && got != p {
			return SelectionResult{Result: SelectionPrincipalNotOneToOne, At: i}
		}
		byParticipant[p], byPrincipal[a] = a, p
	}
	return SelectionResult{Result: SelectionVerified, WinnerProposalID: d.WinnerProposalID, VotesLinked: linked, At: -1}
}

// SelectionDecodeError is a strict-decode refusal; Reason is the §4 reason word ("truncated",
// "u32_overflow", "invalid_utf8", "weights_not_canonical", "rules_digest_not_32", "empty_winner",
// "trailing_bytes").
type SelectionDecodeError struct{ Reason string }

func (e *SelectionDecodeError) Error() string { return "selection body: " + e.Reason }

type selReader struct {
	b []byte
	i int
}

func (r *selReader) take(n uint64) []byte {
	if n > uint64(len(r.b)-r.i) {
		panic(&SelectionDecodeError{"truncated"})
	}
	out := r.b[r.i : r.i+int(n)]
	r.i += int(n)
	return out
}

func (r *selReader) u() uint64 { return binary.BigEndian.Uint64(r.take(8)) }

func (r *selReader) u32() uint32 {
	n := r.u()
	if n > 0xFFFFFFFF {
		panic(&SelectionDecodeError{"u32_overflow"})
	}
	return uint32(n)
}

func (r *selReader) count(minItem uint64) uint64 {
	n := r.u()
	if n > uint64(len(r.b)-r.i)/minItem {
		panic(&SelectionDecodeError{"truncated"})
	}
	return n
}

func (r *selReader) raw() []byte { return r.take(r.u()) }

func (r *selReader) text() string {
	b := r.raw()
	if !utf8.Valid(b) {
		panic(&SelectionDecodeError{"invalid_utf8"})
	}
	return string(b)
}

// DecodeSelectionBody strictly decodes a selection block body (§4.2), refusing (a *SelectionDecodeError)
// anything the runtime could not have sealed. Semantic checks (rule name, version, electorate, ...) are
// Decide's, not the decoder's. Twin of Python `decode_selection_body`.
func DecodeSelectionBody(body []byte) (blk SelectionBlock, err error) {
	defer func() {
		if p := recover(); p != nil {
			de, ok := p.(*SelectionDecodeError)
			if !ok {
				panic(p)
			}
			blk, err = SelectionBlock{}, de
		}
	}()
	r := &selReader{b: body}
	blk.Rule = r.text()
	blk.RuleVersion = r.u32()
	blk.DefaultWeight = r.u32()
	blk.Weights = []SelectionWeight{}
	for n := r.count(16); n > 0; n-- {
		blk.Weights = append(blk.Weights, SelectionWeight{Participant: r.text(), Weight: r.u32()})
	}
	for i := 1; i < len(blk.Weights); i++ {
		if bytes.Compare([]byte(blk.Weights[i-1].Participant), []byte(blk.Weights[i].Participant)) >= 0 {
			return SelectionBlock{}, &SelectionDecodeError{"weights_not_canonical"}
		}
	}
	blk.Tie = r.text()
	blk.Abstention = r.text()
	blk.MinBallots = r.u32()
	blk.PolicyVersion = r.text()
	rd := r.raw()
	if len(rd) != sha256.Size {
		return SelectionBlock{}, &SelectionDecodeError{"rules_digest_not_32"}
	}
	blk.RulesDigest = append([]byte(nil), rd...)
	blk.Participants = []string{}
	for n := r.count(8); n > 0; n-- {
		blk.Participants = append(blk.Participants, r.text())
	}
	blk.OnBehalfOf = []string{}
	for n := r.count(8); n > 0; n-- {
		blk.OnBehalfOf = append(blk.OnBehalfOf, r.text())
	}
	blk.Context = []SelectionContext{}
	for n := r.count(16); n > 0; n-- {
		blk.Context = append(blk.Context, SelectionContext{CtxRef: r.text(), ContentHash: r.text()})
	}
	blk.WinnerProposalID = r.text()
	if blk.WinnerProposalID == "" {
		return SelectionBlock{}, &SelectionDecodeError{"empty_winner"}
	}
	if r.i != len(r.b) {
		return SelectionBlock{}, &SelectionDecodeError{"trailing_bytes"}
	}
	return blk, nil
}
