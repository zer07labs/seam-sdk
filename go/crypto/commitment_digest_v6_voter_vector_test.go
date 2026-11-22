package crypto

import (
	"encoding/hex"
	"testing"
)

// conformance/commitment_digest_v6_voter_vector.json: seam-commitment-digest:v6 with sealed voter records,
// copied byte for byte from seam-runtime crates/seam-trust-aitp/tests/fixtures/ (seamd 0.113.0) and kept
// identical by its sdk-digest-parity. Specs: seam-runtime docs/specs/seam-commitment-digest.v6.md and
// docs/specs/voter-verification.v1.md.
//
// Its vote, ballot and objection entries carry real seam-voter-pop-v1 records, so VerifyTCT is given the
// entries (not just the published explanation digest) and the commitment-level voter check runs against the
// vector's decision. A case passes under v6 AND VerifyCommitmentVoters(entries, issuer_aid, decision) with
// voters_verified records; a negative is refused by at least one of the two. Go's VerifyTCT does not re-check
// vote signatures (COMPATIBILITY.md), so the conjunction is what is asserted. `rule` is advisory (the vector's
// note says so) and is never compared: accepted_outside_window carries record_malformed, for one. Twin of
// python/tests/test_commitment_digest_v6_voters.py.

type v6VoterRow struct {
	Name             string       `json:"name"`
	Over             string       `json:"over"`
	Commitment       v6Commitment `json:"commitment"`
	Trailers         string       `json:"trailers"`
	CommitmentDigest string       `json:"commitment_digest"`
	Ext              string       `json:"ext"`
	SignedArtifact   string       `json:"signed_artifact"`
	Expect           string       `json:"expect"`
	Rule             string       `json:"rule"`
}

type v6VoterVector struct {
	CommitmentDigestDomain  string       `json:"commitment_digest_domain"`
	ExplanationDigestDomain string       `json:"explanation_digest_domain"`
	GateDigestDomain        string       `json:"gate_digest_domain"`
	IssuerAID               string       `json:"issuer_aid"`
	Decision                []string     `json:"decision"`
	VotersVerified          int          `json:"voters_verified"`
	Cases                   []v6VoterRow `json:"cases"`
	Negatives               []v6VoterRow `json:"negatives"`
}

func loadV6Voters(t *testing.T) (v6VoterVector, *VoterDecision) {
	t.Helper()
	var v v6VoterVector
	readConformance(t, "commitment_digest_v6_voter_vector.json", &v)
	if len(v.Decision) != 2 {
		t.Fatalf("decision must be [tenant, session_id], got %v", v.Decision)
	}
	return v, &VoterDecision{Tenant: v.Decision[0], SessionID: v.Decision[1]}
}

// commitment is the row as VerifyTCT reads it: the full commitment WITH its entries, the record's governing
// doc beside the raw trailers it must agree with.
func (r v6VoterRow) commitment(t *testing.T) Commitment {
	t.Helper()
	c := r.Commitment.toCommitment(t)
	c.GoverningDocSha256 = optInts(t, r.Commitment.GoverningDocSha256)
	c.Trailers = mustHex(t, r.Trailers)
	return c
}

func voterRecords(entries []ExplanationEntry) int {
	n := 0
	for _, e := range entries {
		if e.VoterVerification != nil {
			n++
		}
	}
	return n
}

func TestV6VoterVectorShape(t *testing.T) {
	var raw map[string]any
	readConformance(t, "commitment_digest_v6_voter_vector.json", &raw)
	v, _ := loadV6Voters(t)
	if v.CommitmentDigestDomain != "seam-commitment-digest:v6" {
		t.Fatalf("commitment domain drifted: %q", v.CommitmentDigestDomain)
	}
	if v.ExplanationDigestDomain != "seam-explanation-digest:v2" {
		t.Fatalf("explanation domain drifted: %q", v.ExplanationDigestDomain)
	}
	if v.GateDigestDomain != "seam-gate-digest:v1" {
		t.Fatalf("gate domain drifted: %q", v.GateDigestDomain)
	}
	lists := map[string]bool{}
	for k, val := range raw {
		if _, ok := val.([]any); ok {
			lists[k] = true
		}
	}
	if len(lists) != 3 || !lists["decision"] || !lists["cases"] || !lists["negatives"] {
		t.Fatalf("top-level list keys drifted: %v", lists)
	}
	if len(v.Cases) != 2 || len(v.Negatives) != 8 {
		t.Fatalf("expected 2 cases / 8 negatives, got %d / %d", len(v.Cases), len(v.Negatives))
	}
}

func TestV6VoterVectorCases(t *testing.T) {
	v, decision := loadV6Voters(t)
	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Expect != "v6" {
				t.Fatalf("unknown expect %q", tc.Expect)
			}
			if sel, err := SelectCommitmentVersion([]byte(tc.Ext)); err != nil || sel != CommitmentV6 {
				t.Fatalf("ext selects %v (%v), want v6", sel, err)
			}
			c := tc.commitment(t)
			entries := c.Explanation
			ed, err := ExplanationDigest(entries)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(ed[:]) != hex.EncodeToString(c.ExplanationDigest) {
				t.Fatalf("explanation digest: got %x want %x", ed, c.ExplanationDigest)
			}
			got, err := expectedCommitmentDigest(CommitmentV6, c)
			if err != nil || got != tc.CommitmentDigest {
				t.Fatalf("v6 digest: got %s (%v) want %s", got, err, tc.CommitmentDigest)
			}
			if !VerifyTCT(v.IssuerAID, tc.SignedArtifact, c, 0) {
				t.Fatal("the signed v6 TCT must verify with its entries and trailers")
			}
			if !VerifyCommitmentVoters(entries, v.IssuerAID, decision) {
				t.Fatal("the commitment's voter records must verify against the decision")
			}
			if n := voterRecords(entries); n != v.VotersVerified {
				t.Fatalf("voter records: got %d want %d", n, v.VotersVerified)
			}
		})
	}
}

func TestV6VoterVectorNegatives(t *testing.T) {
	v, decision := loadV6Voters(t)
	cases := map[string]bool{}
	for _, c := range v.Cases {
		cases[c.Name] = true
	}
	for _, r := range v.Negatives {
		t.Run(r.Name, func(t *testing.T) {
			if r.Expect != "refused" || !cases[r.Over] {
				t.Fatalf("expect %q over %q", r.Expect, r.Over)
			}
			c := r.commitment(t)
			tctOK := VerifyTCT(v.IssuerAID, r.SignedArtifact, c, 0)
			votersOK := VerifyCommitmentVoters(c.Explanation, v.IssuerAID, decision)
			if tctOK && votersOK {
				t.Fatal("must be refused by VerifyTCT or VerifyCommitmentVoters")
			}
		})
	}
}

func v6VoterNegative(t *testing.T, v v6VoterVector, name string) v6VoterRow {
	t.Helper()
	for _, r := range v.Negatives {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no negative %q", name)
	return v6VoterRow{}
}

// wrong_decision is a well-signed TCT whose records name another decision: only the decision the verifier
// knows can refuse it, so dropping that argument must let it through.
func TestV6VoterDecisionBindingRefusesWrongDecision(t *testing.T) {
	v, decision := loadV6Voters(t)
	r := v6VoterNegative(t, v, "wrong_decision")
	c := r.commitment(t)
	if !VerifyTCT(v.IssuerAID, r.SignedArtifact, c, 0) {
		t.Fatal("wrong_decision's TCT is well signed and must verify")
	}
	if !VerifyCommitmentVoters(c.Explanation, v.IssuerAID, nil) {
		t.Fatal("without the decision binding the records must verify")
	}
	if VerifyCommitmentVoters(c.Explanation, v.IssuerAID, decision) {
		t.Fatal("the decision binding must refuse wrong_decision")
	}
}

// The entries and their digest were rewritten together and the old TCT kept: the records still re-check, so
// it is the commitment digest under the signature that refuses it.
func TestV6VoterTamperedPublishedEntryBreaksSignedDigest(t *testing.T) {
	v, decision := loadV6Voters(t)
	r := v6VoterNegative(t, v, "tampered_published_entry")
	c := r.commitment(t)
	if !VerifyCommitmentVoters(c.Explanation, v.IssuerAID, decision) {
		t.Fatal("the tampered entries' records must still verify")
	}
	if VerifyTCT(v.IssuerAID, r.SignedArtifact, c, 0) {
		t.Fatal("the signed commitment digest must refuse the tampered entry")
	}
}
