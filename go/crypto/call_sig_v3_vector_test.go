package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// callSigV3Vector mirrors conformance/call_sig_v3_payload_vector.json — the cross-language contract for
// `Authorize` call_sig v3. NO bless mode: a mismatch is a contract break, not a stale fixture.
type callSigV3Vector struct {
	Domain string `json:"domain"`
	Cases  []struct {
		Name            string      `json:"name"`
		Why             string      `json:"why"`
		TicketHex       string      `json:"ticket_hex"`
		ToolInputDigest string      `json:"tool_input_digest"`
		ToolName        string      `json:"tool_name"`
		AgentID         string      `json:"agent_id"`
		Subject         string      `json:"subject"`
		Subjects        []string    `json:"subjects"`
		ClientRequestID string      `json:"client_request_id"`
		SessionID       string      `json:"session_id"`
		Features        [][2]string `json:"features"`
		PayloadHex      string      `json:"payload_hex"`
	} `json:"cases"`
}

func loadCallSigV3(t *testing.T) callSigV3Vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "call_sig_v3_payload_vector.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v callSigV3Vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("vector is empty; every assertion below would pass vacuously")
	}
	return v
}

func TestCallSigV3PayloadVector(t *testing.T) {
	v := loadCallSigV3(t)
	if v.Domain != CallSigV3Context {
		t.Fatalf("domain = %q, want %q", v.Domain, CallSigV3Context)
	}
	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			ticket, err := hex.DecodeString(tc.TicketHex)
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(tc.PayloadHex)
			if err != nil {
				t.Fatal(err)
			}
			got := CallSigV3Payload(CallSigV3Fields{
				Ticket:          ticket,
				ToolInputDigest: tc.ToolInputDigest,
				ToolName:        tc.ToolName,
				AgentID:         tc.AgentID,
				Subject:         tc.Subject,
				Subjects:        tc.Subjects,
				ClientRequestID: tc.ClientRequestID,
				SessionID:       tc.SessionID,
				Features:        tc.Features,
			})
			if !bytes.Equal(got, want) {
				t.Errorf("payload mismatch (%s)\n got=%x\nwant=%x", tc.Why, got, want)
			}
		})
	}
}

func TestCallSigV3SignVerifyRoundTrip(t *testing.T) {
	seed := bytes.Repeat([]byte{0x07}, ed25519.SeedSize)
	f := CallSigV3Fields{
		Ticket:          []byte{1, 2, 3, 4},
		ToolInputDigest: "sha256:" + hex.EncodeToString(make([]byte, 32)),
		ToolName:        "read_file",
		AgentID:         "billing-agent",
		Subject:         "user-1",
		Subjects:        []string{"user-2", "user-3"},
		ClientRequestID: "req-0001",
		SessionID:       "sess-9",
		Features:        [][2]string{{"region", "eu"}, {"amount_bucket", "high"}},
	}
	sig, err := CallSigV3(seed, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, CallSigV3Payload(f), sig) {
		t.Fatal("signature does not verify over CallSigV3Payload")
	}
	// The caller's feature slice is not reordered by signing.
	if f.Features[0][0] != "region" {
		t.Fatal("CallSigV3Payload mutated the caller's Features slice")
	}
	tampered := f
	tampered.Subjects = []string{"user-3", "user-2"}
	if ed25519.Verify(pub, CallSigV3Payload(tampered), sig) {
		t.Fatal("signature verified over reordered subjects; subject order is not bound")
	}
	if _, err := CallSigV3(seed[:31], f); err == nil {
		t.Fatal("a 31-byte seed must be refused")
	}
}
