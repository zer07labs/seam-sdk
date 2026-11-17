package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
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
// This port frames the block (so a selection decision's TCT verifies) but does not recompute the winner:
// selection-rule.v1 §5 steps 6-9 are implemented by the Rust verifier (`verify/`) and the Python SDK.
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
