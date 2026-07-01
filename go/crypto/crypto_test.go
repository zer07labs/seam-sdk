package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// vectors mirrors the fields of conformance/vectors.json this shim is pinned to.
type vectors struct {
	Admission struct {
		Inputs struct {
			AgentSeedHex string `json:"agent_seed_hex"`
			ReceiverAID  string `json:"receiver_aid"`
			PopNonce     string `json:"pop_nonce"`
			NowMs        int64  `json:"now_ms"`
		} `json:"inputs"`
		Derived struct {
			SenderAID string `json:"sender_aid"`
		} `json:"derived"`
		Presentation Presentation `json:"presentation"`
	} `json:"admission"`
	TCT struct {
		Inputs struct {
			IssuerSeedHex string     `json:"issuer_seed_hex"`
			Commitment    Commitment `json:"commitment"`
		} `json:"inputs"`
		IssuerAID         string `json:"issuer_aid"`
		SignedArtifactJWS string `json:"signed_artifact_jws"`
	} `json:"tct"`
}

func load(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v
}

func TestPinnedKeyPresentationIsByteExact(t *testing.T) {
	v := load(t)
	seed, err := hex.DecodeString(v.Admission.Inputs.AgentSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	got, err := BuildPresentation(seed, v.Admission.Inputs.ReceiverAID, v.Admission.Inputs.PopNonce, v.Admission.Inputs.NowMs)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, v.Admission.Presentation) {
		t.Fatalf("presentation mismatch:\n got=%+v\nwant=%+v", got, v.Admission.Presentation)
	}
}

func TestAIDDerivationMatches(t *testing.T) {
	v := load(t)
	seed, _ := hex.DecodeString(v.Admission.Inputs.AgentSeedHex)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if got := AIDFromPubkey(pub); got != v.Admission.Derived.SenderAID {
		t.Fatalf("aid mismatch: got %q want %q", got, v.Admission.Derived.SenderAID)
	}
}

func TestTCTVerifyValidAndTampered(t *testing.T) {
	v := load(t)
	c := v.TCT.Inputs.Commitment
	if !VerifyTCT(v.TCT.IssuerAID, v.TCT.SignedArtifactJWS, c, 1_700_000_001) {
		t.Fatal("valid TCT must verify")
	}
	tampered := c
	tampered.Action = "ALLOW"
	if VerifyTCT(v.TCT.IssuerAID, v.TCT.SignedArtifactJWS, tampered, 1_700_000_001) {
		t.Fatal("a tampered commitment must not verify")
	}
}

func TestTCTVerifyFailsClosed(t *testing.T) {
	v := load(t)
	c := v.TCT.Inputs.Commitment
	jws := v.TCT.SignedArtifactJWS
	iss := v.TCT.IssuerAID

	cases := []struct {
		name   string
		issuer string
		token  string
		now    int64
	}{
		{"expired", iss, jws, 9_999_999_999},
		{"not-3-parts", iss, "not.a", 1_700_000_001},
		{"wrong-issuer-key", "aid:pubkey:ed25519:" + repeat("A", 43), jws, 1_700_000_001},
		{"unsupported-aid", "did:web:example.com", jws, 1_700_000_001},
		{"tampered-signature", iss, jws[:len(jws)-4] + "AAAA", 1_700_000_001},
	}
	for _, tc := range cases {
		if VerifyTCT(tc.issuer, tc.token, c, tc.now) {
			t.Fatalf("%s must fail closed", tc.name)
		}
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
