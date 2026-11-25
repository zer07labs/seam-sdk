package crypto

import (
	"math"
	"strconv"
	"testing"
)

// S-4 evidence grade: VerifyTCTSealedAt requires iat == floor(sealedAtMs / 1000). Pinned by
// conformance/tct_sealed_at_vector.json (emitted by scripts/emit_tct_sealed_at_vector.py over the runtime's
// byte-identical commitment_digest_v6_signed_vector.json), the vector every SDK verifier answers. Same rule
// as seam-verify `verify_tct_sealed_at` and the runtime's `verify_commitment_sealed_at` (#2031).

type sealedAtVector struct {
	Source string `json:"source"`
	Over   string `json:"over"`
	Iat    int64  `json:"iat"`
	Cases  []struct {
		Name       string `json:"name"`
		SealedAtMs string `json:"sealed_at_ms"`
		Expect     string `json:"expect"`
	} `json:"cases"`
}

func TestTCTSealedAtVector(t *testing.T) {
	var v sealedAtVector
	readConformance(t, "tct_sealed_at_vector.json", &v)
	if v.Source != "conformance/commitment_digest_v6_signed_vector.json" {
		t.Fatalf("unexpected source %q", v.Source)
	}
	var s v6SignedVector
	readConformance(t, "commitment_digest_v6_signed_vector.json", &s)
	var c Commitment
	var token string
	found := false
	for _, tc := range s.Cases {
		if tc.Name == v.Over {
			c = tc.Commitment.toCommitment(t)
			c.Trailers = mustHex(t, tc.Trailers)
			token = tc.SignedArtifact
			found = true
		}
	}
	if !found {
		t.Fatalf("no signed case %q", v.Over)
	}
	if !VerifyTCT(s.IssuerAID, token, c, 0) {
		t.Fatal("control: the signed case must verify without sealed_at")
	}
	names := map[string]bool{}
	for _, tc := range v.Cases {
		names[tc.Name] = true
		ms, err := strconv.ParseUint(tc.SealedAtMs, 10, 64)
		if err != nil {
			t.Fatalf("%s: %v", tc.Name, err)
		}
		if got := VerifyTCTSealedAt(s.IssuerAID, token, c, 0, ms); got != (tc.Expect == "verified") {
			t.Errorf("%s: sealed_at_ms %d verified=%v, want %s", tc.Name, ms, got, tc.Expect)
		}
	}
	for _, n := range []string{"exact_second_boundary", "iat_plus_1s_at_boundary", "iat_minus_1s_at_boundary"} {
		if !names[n] {
			t.Errorf("vector lacks case %s", n)
		}
	}
	if VerifyTCTSealedAt(s.IssuerAID, token, c, 0, math.MaxUint64) {
		t.Error("u64::MAX must be refused")
	}
}
