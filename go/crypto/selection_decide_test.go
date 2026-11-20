package crypto

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// selection_decide_test.go drives selection-rule.v1 §3 (Decide) over every `rule_cases` entry and §5
// steps 6-9 (VerifySelection) over every `sealed_cases` entry of conformance/selection_rule_v1_vectors.json,
// by result name, as Python's tests/test_selection_rule_v1.py does. Signatures in `sealed_cases` are
// placeholders: the selection steps never read them.

type selExpect struct {
	Result           string           `json:"result"`
	Reason           *string          `json:"reason"`
	At               *int             `json:"at"`
	WinnerProposalID *string          `json:"winner_proposal_id"`
	Option           *string          `json:"option"`
	Scores           []SelectionScore `json:"scores"`
	Ballots          *int             `json:"ballots"`
	Recomputed       *string          `json:"recomputed"`
	VotesLinked      *int             `json:"votes_linked"`
	raw              map[string]json.RawMessage
}

type selCases struct {
	RuleCases []struct {
		Name    string            `json:"name"`
		Record  selBlockJSON      `json:"record"`
		Entries []json.RawMessage `json:"entries"`
		Expect  json.RawMessage   `json:"expect"`
	} `json:"rule_cases"`
	SealedCases []struct {
		Name    string            `json:"name"`
		Block   selBlockJSON      `json:"block"`
		Entries []json.RawMessage `json:"entries"`
		Action  string            `json:"action"`
		Expect  json.RawMessage   `json:"expect"`
	} `json:"sealed_cases"`
}

func loadSelCases(t *testing.T) selCases {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "selection_rule_v1_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v selCases
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func parseExpect(t *testing.T, raw json.RawMessage) selExpect {
	t.Helper()
	var e selExpect
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &e.raw); err != nil {
		t.Fatal(err)
	}
	return e
}

// atOf maps the fixture's `at` (an index, or null for a record-level check) onto this port's -1.
func atOf(e selExpect) int {
	if e.At == nil {
		return -1
	}
	return *e.At
}

func TestSelectionEveryRuleCase(t *testing.T) {
	v := loadSelCases(t)
	if len(v.RuleCases) != 30 {
		t.Fatalf("%d rule_cases, want 30", len(v.RuleCases))
	}
	for _, c := range v.RuleCases {
		t.Run(c.Name, func(t *testing.T) {
			want := parseExpect(t, c.Expect)
			got := Decide(c.Record.block(t), selEntries(t, c.Entries))
			if got.Result != want.Result {
				t.Fatalf("result %q (%q), want %q", got.Result, got.Reason, want.Result)
			}
			if want.Reason != nil && got.Reason != *want.Reason {
				t.Fatalf("reason %q, want %q", got.Reason, *want.Reason)
			}
			if _, ok := want.raw["at"]; ok && got.At != atOf(want) {
				t.Fatalf("at %d, want %d", got.At, atOf(want))
			}
			if want.WinnerProposalID != nil && got.WinnerProposalID != *want.WinnerProposalID {
				t.Fatalf("winner %q, want %q", got.WinnerProposalID, *want.WinnerProposalID)
			}
			if want.Option != nil && got.Option != *want.Option {
				t.Fatalf("option %q, want %q", got.Option, *want.Option)
			}
			if want.Scores != nil && !reflect.DeepEqual(got.Scores, want.Scores) {
				t.Fatalf("scores %v, want %v", got.Scores, want.Scores)
			}
			if want.Ballots != nil && got.Ballots != *want.Ballots {
				t.Fatalf("ballots %d, want %d", got.Ballots, *want.Ballots)
			}
		})
	}
}

func TestSelectionEverySealedCase(t *testing.T) {
	v := loadSelCases(t)
	if len(v.SealedCases) != 13 {
		t.Fatalf("%d sealed_cases, want 13", len(v.SealedCases))
	}
	for _, c := range v.SealedCases {
		t.Run(c.Name, func(t *testing.T) {
			want := parseExpect(t, c.Expect)
			got := VerifySelection(c.Block.block(t), selEntries(t, c.Entries), c.Action)
			if got.Result != want.Result {
				t.Fatalf("result %q (reason %q, at %d), want %q", got.Result, got.Reason, got.At, want.Result)
			}
			if want.At != nil && got.At != *want.At {
				t.Fatalf("at %d, want %d", got.At, *want.At)
			}
			if want.Recomputed != nil && got.Recomputed != *want.Recomputed {
				t.Fatalf("recomputed %q, want %q", got.Recomputed, *want.Recomputed)
			}
			if want.Result == SelectionVerified {
				if !got.OK() || got.WinnerProposalID != *want.WinnerProposalID || got.VotesLinked != *want.VotesLinked {
					t.Fatalf("verified: %+v, want %+v", got, want)
				}
			} else if got.OK() {
				t.Fatal("OK on a refusal")
			}
		})
	}
}

// TestSelectionVerifyTCTWiring: VerifyTCT recomputes the winner whenever the commitment carries a block,
// fails closed on a block without entries, and is unchanged with no block.
func TestSelectionVerifyTCTWiring(t *testing.T) {
	v := loadSelCases(t)
	seed := hex.EncodeToString(make([]byte, 32))
	commit := func(name string) Commitment {
		for _, c := range v.SealedCases {
			if c.Name == name {
				blk := c.Block.block(t)
				return Commitment{
					ID: "cmt-sel", Action: c.Action, Authority: "policy", AuthMethod: "aitp",
					TrustBasis: "selection", Committer: "orchestrator",
					Explanation: selEntries(t, c.Entries), Selection: &blk,
				}
			}
		}
		t.Fatalf("no sealed case %q", name)
		return Commitment{}
	}
	sign := func(c Commitment) (string, string) { return signTCT(t, seed, c, 4853600000) }

	ok := commit("verified")
	iss, jws := sign(ok)
	if !VerifyTCT(iss, jws, ok, 1_700_000_000) {
		t.Fatal("a verified selection decision must verify")
	}

	// The same signed commitment with the entries withheld (only the published digest held): the
	// digest still binds, but the winner cannot be recomputed, so it fails closed.
	ed, err := ExplanationDigest(ok.Explanation)
	if err != nil {
		t.Fatal(err)
	}
	withheld := ok
	withheld.Explanation, withheld.ExplanationDigest = nil, ed[:]
	d1, err1 := seamCommitmentDigest(ok)
	d2, err2 := seamCommitmentDigest(withheld)
	if err1 != nil || err2 != nil || d1 != d2 {
		t.Fatal("withholding the entries must not change the commitment digest")
	}
	if VerifyTCT(iss, jws, withheld, 1_700_000_000) {
		t.Fatal("a selection block without explanation entries must fail closed")
	}

	// A correctly signed TCT over a tampered selection still refuses, by the selection steps alone.
	for _, name := range []string{"winner_id_tampered", "weight_tampered_flips_winner", "action_not_winner_option", "vote_without_voter_record"} {
		c := commit(name)
		iss, jws := sign(c)
		if VerifyTCT(iss, jws, c, 1_700_000_000) {
			t.Fatalf("%s: verified", name)
		}
	}

	// No block: unchanged — the same entries without Selection verify on the digest alone.
	plain := ok
	plain.Selection = nil
	iss, jws = sign(plain)
	if !VerifyTCT(iss, jws, plain, 1_700_000_000) {
		t.Fatal("no block must keep the pre-selection behaviour")
	}
	plain.Explanation, plain.ExplanationDigest = nil, ed[:]
	if !VerifyTCT(iss, jws, plain, 1_700_000_000) {
		t.Fatal("no block with entries withheld must keep the pre-selection behaviour")
	}
}

func TestDecodeSelectionBodyRoundTripsAndRefuses(t *testing.T) {
	block := loadSelVector(t).Codec.Block.block(t)
	body, err := SelectionBody(block)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeSelectionBody(body)
	if err != nil {
		t.Fatal(err)
	}
	again, err := SelectionBody(got)
	if err != nil || hex.EncodeToString(again) != hex.EncodeToString(body) {
		t.Fatalf("round trip: %v", err)
	}
	reason := func(b []byte) string {
		_, err := DecodeSelectionBody(b)
		var de *SelectionDecodeError
		if !errors.As(err, &de) {
			t.Fatalf("not a SelectionDecodeError: %v", err)
		}
		return de.Reason
	}
	cases := map[string][]byte{
		"truncated":      body[:len(body)-1],
		"trailing_bytes": append(append([]byte(nil), body...), 0),
		"invalid_utf8":   append(be64Frame(nil, []byte{0xff}), body[8+len(block.Rule):]...),
	}
	huge := append([]byte(nil), body...)
	off := 8 + len(block.Rule)
	copy(huge[off:off+8], []byte{0, 0, 0, 1, 0, 0, 0, 0}) // rule_version = 2^32
	cases["u32_overflow"] = huge
	for want, b := range cases {
		if got := reason(b); got != want {
			t.Fatalf("%s: got %q", want, got)
		}
	}
	empty := block
	empty.WinnerProposalID = "x"
	b, _ := SelectionBody(empty)
	b = append(b[:len(b)-9], be64Frame(nil, nil)...)
	if got := reason(b); got != "empty_winner" {
		t.Fatalf("empty_winner: got %q", got)
	}
}
