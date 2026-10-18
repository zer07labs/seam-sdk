package crypto

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// conformance/commitment_digest_v2_vector.json is the runtime's reference vector for
// `seam-commitment-digest:v2` + `seam-explanation-digest:v1`. A port is conforming iff it reproduces
// every digest in it and verifies its signed_artifact against issuer_aid. The commitments are the REST
// projection: byte fields as JSON number arrays, absent confidence/rationale_ref/supersedes as null.
type v2Vector struct {
	CommitmentDigestDomain  string `json:"commitment_digest_domain"`
	ExplanationDigestDomain string `json:"explanation_digest_domain"`
	IssuerAID               string `json:"issuer_aid"`
	Cases                   []struct {
		Name       string `json:"name"`
		Commitment struct {
			ID                string             `json:"id"`
			Action            string             `json:"action"`
			Authority         string             `json:"authority"`
			Supersedes        *string            `json:"supersedes"`
			AuthMethod        string             `json:"auth_method"`
			TrustBasis        string             `json:"trust_basis"`
			Committer         string             `json:"committer"`
			SignedArtifact    []int              `json:"signed_artifact"`
			ExplanationDigest []int              `json:"explanation_digest"`
			Explanation       []ExplanationEntry `json:"explanation"`
		} `json:"commitment"`
		ExplanationDigest string `json:"explanation_digest"`
		CommitmentDigest  string `json:"commitment_digest"`
	} `json:"cases"`
}

func intsToBytes(t *testing.T, in []int) []byte {
	t.Helper()
	out := make([]byte, len(in))
	for i, b := range in {
		if b < 0 || b > 255 {
			t.Fatalf("byte out of range: %d", b)
		}
		out[i] = byte(b)
	}
	return out
}

func loadV2(t *testing.T) v2Vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "commitment_digest_v2_vector.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v v2Vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("vector is empty")
	}
	return v
}

func TestCommitmentDigestV2Vector(t *testing.T) {
	v := loadV2(t)
	if v.CommitmentDigestDomain != CommitmentDigestDomain || v.ExplanationDigestDomain != ExplanationDomain {
		t.Fatalf("domain tags drifted: %q / %q", v.CommitmentDigestDomain, v.ExplanationDigestDomain)
	}
	signed := 0
	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			vc := tc.Commitment
			if vc.Explanation == nil {
				vc.Explanation = []ExplanationEntry{}
			}
			ed, err := ExplanationDigest(vc.Explanation)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(ed[:]); got != tc.ExplanationDigest {
				t.Fatalf("explanation digest: got %s want %s", got, tc.ExplanationDigest)
			}
			published := intsToBytes(t, vc.ExplanationDigest)
			if hex.EncodeToString(published) != tc.ExplanationDigest {
				t.Fatalf("the vector's published explanation_digest disagrees with its own hex")
			}
			c := Commitment{
				ID: vc.ID, Action: vc.Action, Authority: vc.Authority, AuthMethod: vc.AuthMethod,
				TrustBasis: vc.TrustBasis, Committer: vc.Committer,
				ExplanationDigest: published, Explanation: vc.Explanation,
			}
			if vc.Supersedes != nil {
				c.Supersedes = *vc.Supersedes
			}
			// All three field-8 resolutions must agree: entries + published, entries only, published only.
			only := c
			only.ExplanationDigest = nil
			pubOnly := c
			pubOnly.Explanation = nil
			for name, cc := range map[string]Commitment{"entries+published": c, "entries": only, "published": pubOnly} {
				got, err := seamCommitmentDigest(cc)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if got != tc.CommitmentDigest {
					t.Fatalf("%s: commitment digest got %s want %s", name, got, tc.CommitmentDigest)
				}
			}
			if len(vc.SignedArtifact) > 0 {
				signed++
				jws := string(intsToBytes(t, vc.SignedArtifact))
				if !VerifyTCT(v.IssuerAID, jws, c, 0) {
					t.Fatal("signed_artifact must verify against issuer_aid")
				}
				tampered := c
				tampered.Explanation = cloneEntries(c.Explanation)
				tampered.Explanation[0].Reason += "-x"
				tampered.ExplanationDigest = nil
				if VerifyTCT(v.IssuerAID, jws, tampered, 0) {
					t.Fatal("a tampered explanation must not verify")
				}
			}
		})
	}
	if signed == 0 {
		t.Fatal("no case carries a signed_artifact; the signature path is untested")
	}
}

func TestExplanationDigestEmptyMatchesSpec(t *testing.T) {
	const want = "eb7853dc086ef5385db8408cf35c9c984e845ccc03d269102f942eed7806ce40"
	for name, entries := range map[string][]ExplanationEntry{"nil": nil, "empty": {}} {
		d, err := ExplanationDigest(entries)
		if err != nil || hex.EncodeToString(d[:]) != want {
			t.Fatalf("%s: got %x, %v; want %s", name, d, err, want)
		}
	}
	// The spec's worked example: all fields empty, no explanation held.
	got, err := seamCommitmentDigest(Commitment{})
	if err != nil || got != "78edca52ba1e88f13a78e5569742bfce0b51474ca840bf38a8dde414d5515784" {
		t.Fatalf("all-empty worked example: got %s, %v", got, err)
	}
}

func f64(f float64) *float64 { return &f }

func evalEntry(conf *float64) ExplanationEntry {
	return ExplanationEntry{Kind: "evaluation", Participant: "p", ProposalID: "p1", Value: "BLOCK", Confidence: conf}
}

// Absent is not zero: CONF = 0x00 and CONF = 0x01 ‖ be64(0) are different preimages.
func TestExplanationAbsentConfidenceIsNotZero(t *testing.T) {
	absent, err := ExplanationDigest([]ExplanationEntry{evalEntry(nil)})
	if err != nil {
		t.Fatal(err)
	}
	zero, err := ExplanationDigest([]ExplanationEntry{evalEntry(f64(0))})
	if err != nil {
		t.Fatal(err)
	}
	if absent == zero {
		t.Fatal("an absent confidence and a stated 0.0 must give different digests")
	}
	ref := ""
	withRef := evalEntry(nil)
	withRef.RationaleRef = &ref
	r, err := ExplanationDigest([]ExplanationEntry{withRef})
	if err != nil {
		t.Fatal(err)
	}
	if r == absent {
		t.Fatal("an absent rationale_ref and a stated empty one must give different digests")
	}
}

func TestExplanationRefusesNonCanonical(t *testing.T) {
	for name, e := range map[string]ExplanationEntry{
		"negative zero": evalEntry(f64(math.Copysign(0, -1))),
		"NaN":           evalEntry(f64(math.NaN())),
		"+Inf":          evalEntry(f64(math.Inf(1))),
		"-Inf":          evalEntry(f64(math.Inf(-1))),
		"above one":     evalEntry(f64(1.5)),
		"below zero":    evalEntry(f64(-0.1)),
		"unknown kind":  {Kind: "comment"},
		"enum name":     {Kind: "EXPLANATION_KIND_VOTE"},
		"uppercase":     {Kind: "Vote"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ExplanationDigest([]ExplanationEntry{e}); err == nil {
				t.Fatal("must be refused, not hashed")
			}
		})
	}
	for _, ok := range []float64{0, 0.5, 1} {
		if _, err := ExplanationDigest([]ExplanationEntry{evalEntry(f64(ok))}); err != nil {
			t.Fatalf("confidence %v must be accepted: %v", ok, err)
		}
	}
}

// VerifyTCT fails closed (false, no panic) when the held entries disagree with the published digest,
// or when an entry is malformed — even though the signature itself is valid.
func TestVerifyTCTRefusesInconsistentExplanation(t *testing.T) {
	v := load(t)
	c := v.TCT.Inputs.Commitment
	const now = 1_700_000_001
	ed, err := ExplanationDigest(c.Explanation)
	if err != nil {
		t.Fatal(err)
	}

	consistent := c
	consistent.ExplanationDigest = ed[:]
	if !VerifyTCT(v.TCT.IssuerAID, v.TCT.SignedArtifactJWS, consistent, now) {
		t.Fatal("entries + matching published digest must verify")
	}

	disagree := consistent
	disagree.Explanation = cloneEntries(c.Explanation)
	disagree.Explanation[1].Reason = "edited after sealing"
	if VerifyTCT(v.TCT.IssuerAID, v.TCT.SignedArtifactJWS, disagree, now) {
		t.Fatal("entries disagreeing with the published digest must not verify")
	}

	wrongLen := c
	wrongLen.Explanation = nil
	wrongLen.ExplanationDigest = ed[:31]
	if VerifyTCT(v.TCT.IssuerAID, v.TCT.SignedArtifactJWS, wrongLen, now) {
		t.Fatal("a truncated published digest must not verify")
	}

	for name, mutate := range map[string]func(*ExplanationEntry){
		"unknown kind":   func(e *ExplanationEntry) { e.Kind = "comment" },
		"-0.0":           func(e *ExplanationEntry) { e.Confidence = f64(math.Copysign(0, -1)) },
		"NaN confidence": func(e *ExplanationEntry) { e.Confidence = f64(math.NaN()) },
	} {
		bad := c
		bad.Explanation = cloneEntries(c.Explanation)
		mutate(&bad.Explanation[0])
		if VerifyTCT(v.TCT.IssuerAID, v.TCT.SignedArtifactJWS, bad, now) {
			t.Fatalf("%s must fail closed", name)
		}
	}
}
