package crypto

import (
	"math"
	"strconv"
	"testing"
)

// Evidence grade: VerifyTCTSealedAt requires iat == floor(sealedAtMs / 1000) (S-4) and
// jti == TCTJTI(decisionID, sealedAtMs) (seam-runtime 0.127.0 P4). Pinned by
// conformance/tct_sealed_at_vector.json (emitted by scripts/emit_tct_sealed_at_vector.py over the runtime's
// byte-identical commitment_digest_v6_signed_vector.json), the vector every SDK verifier answers. Same rule
// as seam-verify `verify_tct_sealed_at` and the runtime's `check_commitment_sealed_for`.

type sealedAtVector struct {
	Source     string `json:"source"`
	Over       string `json:"over"`
	Iat        int64  `json:"iat"`
	Jti        string `json:"jti"`
	DecisionID string `json:"decision_id"`
	JtiKat     struct {
		DecisionID string `json:"decision_id"`
		SealedAtMs string `json:"sealed_at_ms"`
		Jti        string `json:"jti"`
	} `json:"jti_kat"`
	Cases []struct {
		Name       string `json:"name"`
		DecisionID string `json:"decision_id"`
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
		if got := VerifyTCTSealedAt(s.IssuerAID, token, c, 0, tc.DecisionID, ms); got != (tc.Expect == "verified") {
			t.Errorf("%s: decision_id %q, sealed_at_ms %d verified=%v, want %s", tc.Name, tc.DecisionID, ms, got, tc.Expect)
		}
	}
	for _, n := range []string{
		"exact_second_boundary", "last_ms_of_the_second", "iat_plus_1s_at_boundary",
		"iat_minus_1s_at_boundary", "replayed_onto_another_record", "commitment_id_is_not_the_record_id",
	} {
		if !names[n] {
			t.Errorf("vector lacks case %s", n)
		}
	}
	if VerifyTCTSealedAt(s.IssuerAID, token, c, 0, v.DecisionID, math.MaxUint64) {
		t.Error("u64::MAX must be refused")
	}
}

func TestTCTJTIMatchesTheRuntimeKnownAnswerAndTheToken(t *testing.T) {
	var v sealedAtVector
	readConformance(t, "tct_sealed_at_vector.json", &v)
	ms, err := strconv.ParseInt(v.JtiKat.SealedAtMs, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := TCTJTI(v.JtiKat.DecisionID, ms); !ok || got != v.JtiKat.Jti {
		t.Errorf("kat: TCTJTI = %q, want %q", got, v.JtiKat.Jti)
	}
	var s v6SignedVector
	readConformance(t, "commitment_digest_v6_signed_vector.json", &s)
	if got, _ := TCTJTI(v.DecisionID, s.SealMs); got != v.Jti {
		t.Errorf("token: TCTJTI = %q, want %q", got, v.Jti)
	}
}
