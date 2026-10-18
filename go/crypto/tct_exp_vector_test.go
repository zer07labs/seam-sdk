package crypto

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Go is the NORMATIVE implementation of the `exp` rule in conformance/tct_exp_extended.json — the
// rule was adopted from this file (`payload["exp"].(float64)` + `int64(exp)`) because Java and
// Kotlin already agreed with it, making it the existing 3-of-5 majority, and because it is the
// strictest of the three shapes that were in the tree.
//
// Which is exactly why this test exists rather than being skipped as redundant. "Go is the
// reference" is a claim about the vector, and an unchecked claim is how a reference drifts away
// from the thing referencing it: someone edits VerifyTCT, the shims still agree with a vector that
// no longer describes any implementation, and the divergence reopens silently in the one language
// nobody re-measured. This binds them together.
type tctExpVector struct {
	IssuerAID  string `json:"issuer_aid"`
	Commitment struct {
		ID         string `json:"id"`
		Action     string `json:"action"`
		Authority  string `json:"authority"`
		Supersedes any    `json:"supersedes"`
		AuthMethod string `json:"auth_method"`
		TrustBasis string `json:"trust_basis"`
	} `json:"commitment"`
	Cases []struct {
		Name   string `json:"name"`
		Why    string `json:"why"`
		NowS   int64  `json:"now_s"`
		JWS    string `json:"jws"`
		Expect bool   `json:"expect"`
	} `json:"cases"`
}

func TestTCTExpVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "tct_exp_extended.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v tctExpVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("vector is empty; every assertion below would pass vacuously")
	}

	// A vector of nothing-but-refusals is free to satisfy: a VerifyTCT that returned false
	// unconditionally would pass it. At least one case must be a token that genuinely verifies.
	accepted := 0
	for _, c := range v.Cases {
		if c.Expect {
			accepted++
		}
	}
	if accepted == 0 {
		t.Fatal("no case expects acceptance; a VerifyTCT stuck at false would pass this whole test")
	}

	supersedes, _ := v.Commitment.Supersedes.(string) // JSON null -> "", which is the framing's own encoding
	c := Commitment{
		ID:         v.Commitment.ID,
		Action:     v.Commitment.Action,
		Authority:  v.Commitment.Authority,
		Supersedes: supersedes,
		AuthMethod: v.Commitment.AuthMethod,
		TrustBasis: v.Commitment.TrustBasis,
	}

	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			if got := VerifyTCT(v.IssuerAID, tc.JWS, c, tc.NowS); got != tc.Expect {
				t.Errorf("VerifyTCT(now=%d) = %v, want %v\n  %s", tc.NowS, got, tc.Expect, tc.Why)
			}
		})
	}
}
