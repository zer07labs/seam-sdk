package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The agent-side helper and its REST form (#214), against the same shared vector as the raw signer: the
// REST `pop` object must match the vector's fields byte for byte once marshalled.
func TestEnrollProofRESTMatchesVector(t *testing.T) {
	v := loadEnrollPop(t)
	if len(v.Cases) < 6 {
		t.Fatalf("the vector lost cases (%d); it pins a wire contract", len(v.Cases))
	}
	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			seed, err := hex.DecodeString(tc.SeedHex)
			if err != nil {
				t.Fatal(err)
			}
			if aid := AIDFromPubkey(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)); aid != tc.SubjectAID {
				t.Fatalf("aid = %s, want %s", aid, tc.SubjectAID)
			}
			proof, err := EnrollPop(seed, tc.Tenant, tc.Namespace, tc.IssuedAtMs, tc.Nonce)
			if err != nil {
				t.Fatal(err)
			}
			// RAW 64 bytes — the gRPC form.
			wantSig, err := base64.RawURLEncoding.DecodeString(tc.Signature)
			if err != nil {
				t.Fatal(err)
			}
			if len(proof.Signature) != 64 || !bytes.Equal(proof.Signature, wantSig) {
				t.Errorf("raw signature mismatch (%s)", tc.Why)
			}
			if proof.IssuedAtMs != tc.IssuedAtMs || proof.Nonce != tc.Nonce {
				t.Errorf("proof = %d/%q, want %d/%q", proof.IssuedAtMs, proof.Nonce, tc.IssuedAtMs, tc.Nonce)
			}
			// Unpadded base64url — the REST form.
			if got := proof.SignatureB64URL(); got != tc.Signature {
				t.Errorf("SignatureB64URL = %s, want %s", got, tc.Signature)
			}
			rest := proof.ToREST()
			if want := (EnrollProofREST{IssuedAtMs: tc.IssuedAtMs, Nonce: tc.Nonce, Signature: tc.Signature}); rest != want {
				t.Errorf("ToREST = %+v, want %+v", rest, want)
			}
			gotJSON, err := json.Marshal(rest)
			if err != nil {
				t.Fatal(err)
			}
			wantJSON := `{"issued_at_ms":` + strconv.FormatUint(tc.IssuedAtMs, 10) +
				`,"nonce":"` + tc.Nonce + `","signature":"` + tc.Signature + `"}`
			if string(gotJSON) != wantJSON {
				t.Errorf("REST JSON\n got=%s\nwant=%s", gotJSON, wantJSON)
			}
			// It verifies against the vector's payload under the vector's AID.
			pub, err := aidToPubkey(tc.SubjectAID)
			if err != nil {
				t.Fatal(err)
			}
			payload, _ := hex.DecodeString(tc.PayloadHex)
			if !ed25519.Verify(ed25519.PublicKey(pub), payload, proof.Signature) {
				t.Error("proof does not verify over the vector payload")
			}
		})
	}
}

func TestEnrolmentProofDefaultsToNowAndAFresh22CharNonce(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	before := uint64(time.Now().UnixMilli())
	a, err := EnrolmentProof(seed, "acme", "fraud")
	if err != nil {
		t.Fatal(err)
	}
	b, err := EnrolmentProof(seed, "acme", "fraud")
	if err != nil {
		t.Fatal(err)
	}
	after := uint64(time.Now().UnixMilli())
	if a.IssuedAtMs < before || a.IssuedAtMs > after {
		t.Errorf("IssuedAtMs %d not in [%d, %d]", a.IssuedAtMs, before, after)
	}
	if len(a.Nonce) != 22 {
		t.Errorf("nonce %q is not 22 characters", a.Nonce)
	}
	if err := ValidateEnrollPopNonce(a.Nonce); err != nil {
		t.Errorf("default nonce refused: %v", err)
	}
	if a.Nonce == b.Nonce {
		t.Error("the default nonce must be random per proof")
	}
	f := EnrollPopFields{SubjectAID: AIDFromPubkey(pub), Tenant: "acme", Namespace: "fraud", IssuedAtMs: a.IssuedAtMs, Nonce: a.Nonce}
	if !ed25519.Verify(pub, EnrollPopPayload(f), a.Signature) {
		t.Error("default proof does not verify")
	}
}

func TestEnrollPopRefusals(t *testing.T) {
	seed := bytes.Repeat([]byte{0x07}, ed25519.SeedSize)
	for _, n := range []string{"", strings.Repeat("x", 129), "has space", "pad=", "a+b", "a/b", "é", "a.b", "ok\n"} {
		if _, err := EnrollPop(seed, "acme", "fraud", 1, n); err == nil {
			t.Errorf("nonce %q was accepted", n)
		}
	}
	if _, err := EnrollPop(seed[:31], "acme", "fraud", 1, "ok"); err == nil {
		t.Error("a 31-byte seed must be refused")
	}
	if _, err := EnrolmentProof(seed[:31], "acme", "fraud"); err == nil {
		t.Error("a 31-byte seed must be refused")
	}
}
