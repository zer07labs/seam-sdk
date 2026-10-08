package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// enrollPopVector mirrors conformance/enroll_pop_v1_payload_vector.json — the cross-language contract for
// the enrolment proof-of-possession (#205). NO bless mode: a mismatch is a contract break, not a stale
// fixture.
type enrollPopVector struct {
	Domain string `json:"domain"`
	Cases  []struct {
		Name       string `json:"name"`
		Why        string `json:"why"`
		SeedHex    string `json:"seed_hex"`
		SubjectAID string `json:"subject_aid"`
		Tenant     string `json:"tenant"`
		Namespace  string `json:"namespace"`
		IssuedAtMs uint64 `json:"issued_at_ms"`
		Nonce      string `json:"nonce"`
		PayloadHex string `json:"payload_hex"`
		Signature  string `json:"signature"`
	} `json:"cases"`
}

func loadEnrollPop(t *testing.T) enrollPopVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "enroll_pop_v1_payload_vector.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v enrollPopVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("vector is empty; every assertion below would pass vacuously")
	}
	return v
}

func TestEnrollPopVector(t *testing.T) {
	v := loadEnrollPop(t)
	if v.Domain != EnrollPopV1Context {
		t.Fatalf("domain = %q, want %q", v.Domain, EnrollPopV1Context)
	}
	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			f := EnrollPopFields{
				SubjectAID: tc.SubjectAID,
				Tenant:     tc.Tenant,
				Namespace:  tc.Namespace,
				IssuedAtMs: tc.IssuedAtMs,
				Nonce:      tc.Nonce,
			}
			want, err := hex.DecodeString(tc.PayloadHex)
			if err != nil {
				t.Fatal(err)
			}
			if got := EnrollPopPayload(f); !bytes.Equal(got, want) {
				t.Errorf("payload mismatch (%s)\n got=%x\nwant=%x", tc.Why, got, want)
			}

			seed, err := hex.DecodeString(tc.SeedHex)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := EnrollPopSign(seed, f)
			if err != nil {
				t.Fatal(err)
			}
			// RAW 64 bytes — the gRPC form.
			wantSig, err := base64.RawURLEncoding.DecodeString(tc.Signature)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(sig, wantSig) {
				t.Errorf("raw signature mismatch (%s)", tc.Why)
			}
			// Unpadded base64url — the REST form.
			if got := base64.RawURLEncoding.EncodeToString(sig); got != tc.Signature {
				t.Errorf("base64url signature = %s, want %s", got, tc.Signature)
			}
		})
	}
}

func TestEnrollPopDoesNotVerifyForAnotherTenantOrNamespace(t *testing.T) {
	seed := bytes.Repeat([]byte{0x07}, ed25519.SeedSize)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	f := EnrollPopFields{SubjectAID: AIDFromPubkey(pub), Tenant: "tenant-a", Namespace: "ns-x", IssuedAtMs: 1760000000000, Nonce: "n0"}
	sig, err := EnrollPopSign(seed, f)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, EnrollPopPayload(f), sig) {
		t.Fatal("signature does not verify over its own payload")
	}
	for _, other := range []EnrollPopFields{
		{SubjectAID: f.SubjectAID, Tenant: "tenant-b", Namespace: "ns-x", IssuedAtMs: f.IssuedAtMs, Nonce: f.Nonce},
		{SubjectAID: f.SubjectAID, Tenant: "tenant-a", Namespace: "ns-y", IssuedAtMs: f.IssuedAtMs, Nonce: f.Nonce},
		{SubjectAID: f.SubjectAID, Tenant: "tenant-b", Namespace: "ns-y", IssuedAtMs: f.IssuedAtMs, Nonce: f.Nonce},
	} {
		if ed25519.Verify(pub, EnrollPopPayload(other), sig) {
			t.Fatalf("a proof for tenant-a/ns-x verified for %s/%s", other.Tenant, other.Namespace)
		}
	}
}

func TestEnrollPopSignRefusals(t *testing.T) {
	seed := bytes.Repeat([]byte{0x07}, ed25519.SeedSize)
	aid := AIDFromPubkey(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	ok := EnrollPopFields{SubjectAID: aid, Tenant: "acme", Namespace: "fraud", IssuedAtMs: 1, Nonce: "ok"}
	if _, err := EnrollPopSign(seed, ok); err != nil {
		t.Fatalf("valid fields refused: %v", err)
	}
	for _, n := range []string{"", strings.Repeat("x", 129), "has space", "pad=", "a+b", "a/b", "é", "a.b"} {
		bad := ok
		bad.Nonce = n
		if _, err := EnrollPopSign(seed, bad); err == nil {
			t.Errorf("nonce %q was accepted", n)
		}
	}
	if err := ValidateEnrollPopNonce(strings.Repeat("x", 128)); err != nil {
		t.Errorf("a 128-char nonce was refused: %v", err)
	}
	wrongAID := ok
	wrongAID.SubjectAID = "aid:pubkey:ed25519:11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	if _, err := EnrollPopSign(seed, wrongAID); err == nil {
		t.Error("signed for an AID that is not the seed's own")
	}
	if _, err := EnrollPopSign(seed[:31], ok); err == nil {
		t.Error("a 31-byte seed must be refused")
	}
}
