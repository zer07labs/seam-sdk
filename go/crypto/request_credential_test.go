package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// requestSigVector mirrors conformance/request_sig_payload_vector.json — the cross-language contract for
// the `seam-request-call-v1` per-request credential (#508). NO bless mode.
type requestSigVector struct {
	Domain string `json:"domain"`
	Cases  []struct {
		Name         string `json:"name"`
		Why          string `json:"why"`
		TicketHex    string `json:"ticket_hex"`
		RPCFullName  string `json:"rpc_full_name"`
		ResourceID   string `json:"resource_id"`
		BodyInputHex string `json:"body_input_hex"`
		BodyDigest   string `json:"body_digest"`
		PayloadHex   string `json:"payload_hex"`
	} `json:"cases"`
}

func TestRequestSigPayloadMatchesVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "request_sig_payload_vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v requestSigVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Domain != RequestSigContext {
		t.Fatalf("domain %q", v.Domain)
	}
	if len(v.Cases) == 0 {
		t.Fatal("vector is empty")
	}
	for _, c := range v.Cases {
		ticket, _ := hex.DecodeString(c.TicketHex)
		got := hex.EncodeToString(RequestSigPayload(ticket, c.RPCFullName, c.ResourceID, c.BodyDigest))
		if got != c.PayloadHex {
			t.Errorf("%s: payload mismatch (%s)", c.Name, c.Why)
		}
		if c.BodyInputHex != "" {
			body, _ := hex.DecodeString(c.BodyInputHex)
			if d := BodyDigest(body); d != c.BodyDigest {
				t.Errorf("%s: body digest %s, want %s", c.Name, d, c.BodyDigest)
			}
		}
	}
}

// ── #202: the bound-agent default ────────────────────────────────────────────────────────────────

const getDecision = "/seam.api.v1.SeamCoordination/GetDecision"

func agentOf(t *testing.T, b byte) *Agent {
	t.Helper()
	a, err := NewAgent(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// ticketsFor issues a distinct ticket per agent and records who asked, so a test can see which agent
// signed.
func ticketsFor(asked *[]string) TicketSource {
	return func(a *Agent) ([]byte, error) {
		*asked = append(*asked, a.AID())
		return []byte("ticket-for-" + a.AID()), nil
	}
}

func verifies(t *testing.T, a *Agent, md map[string][]byte, rpc, resourceID, digest string) bool {
	t.Helper()
	pub := ed25519.NewKeyFromSeed(a.Seed()).Public().(ed25519.PublicKey)
	return ed25519.Verify(pub, RequestSigPayload(md[TicketMetadataKey], rpc, resourceID, digest), md[CallSigMetadataKey])
}

func TestBoundAgentCredentialIsAttachedByDefault(t *testing.T) {
	bound := agentOf(t, 1)
	var asked []string
	rc := RequestCredentials{Agent: bound, Tickets: ticketsFor(&asked)}
	md, err := rc.Metadata(nil, getDecision, "dec:1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(md) != 2 || string(md[TicketMetadataKey]) != "ticket-for-"+bound.AID() {
		t.Fatalf("metadata: %v", md)
	}
	if !verifies(t, bound, md, getDecision, "dec:1", "") {
		t.Fatal("the default credential is not the bound agent's signature")
	}
	if len(asked) != 1 || asked[0] != bound.AID() {
		t.Fatalf("ticket asked for %v", asked)
	}
}

func TestExplicitCredentialWinsOverTheBoundAgent(t *testing.T) {
	bound, explicit := agentOf(t, 1), agentOf(t, 2)
	var asked []string
	rc := RequestCredentials{Agent: bound, Tickets: ticketsFor(&asked)}
	body := []byte{0x0a, 0x01, 0x78}
	md, err := rc.Metadata(explicit, "/seam.api.v1.SeamCoordination/SubmitVote", "", body)
	if err != nil {
		t.Fatal(err)
	}
	if !verifies(t, explicit, md, "/seam.api.v1.SeamCoordination/SubmitVote", "", BodyDigest(body)) {
		t.Fatal("the explicit credential did not sign")
	}
	if verifies(t, bound, md, "/seam.api.v1.SeamCoordination/SubmitVote", "", BodyDigest(body)) {
		t.Fatal("the bound agent signed despite an explicit credential")
	}
	if len(asked) != 1 || asked[0] != explicit.AID() {
		t.Fatalf("ticket asked for %v", asked)
	}
}

func TestNoAgentMeansNoCredential(t *testing.T) {
	var asked []string
	md, err := RequestCredentials{Tickets: ticketsFor(&asked)}.Metadata(nil, getDecision, "dec:1", nil)
	if err != nil || md != nil || len(asked) != 0 {
		t.Fatalf("unbound client sent a credential: md=%v err=%v asked=%v", md, err, asked)
	}
	// An explicit credential still works on an unbound value — opt-in per call, as before #202.
	md, err = RequestCredentials{Tickets: ticketsFor(&asked)}.Metadata(agentOf(t, 3), getDecision, "dec:1", nil)
	if err != nil || len(md) != 2 {
		t.Fatalf("explicit on unbound: md=%v err=%v", md, err)
	}
}

func TestTicketErrorPropagates(t *testing.T) {
	boom := errors.New("admit failed")
	rc := RequestCredentials{Agent: agentOf(t, 1), Tickets: func(*Agent) ([]byte, error) { return nil, boom }}
	if _, err := rc.Metadata(nil, getDecision, "dec:1", nil); !errors.Is(err, boom) {
		t.Fatalf("err %v", err)
	}
	if _, err := (RequestCredentials{Agent: agentOf(t, 1)}).Metadata(nil, getDecision, "dec:1", nil); err == nil {
		t.Fatal("a bound agent with no TicketSource must fail loudly, not send nothing")
	}
}
