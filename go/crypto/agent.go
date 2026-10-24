package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Agent is an agent identity — a 32-byte Ed25519 seed that derives the pinned AID and signs the
// admission PoP, the Authorize call_sig and the per-request credential. Mirrors Python's `Agent`.
//
// The seed is held unexported so it cannot be printed by accident: String, GoString and every fmt verb
// render only the AID, and encoding/json sees no exported field. Seed() hands out a copy for the
// seed-taking functions in this package.
type Agent struct {
	seed []byte
	aid  string
}

// NewAgent wraps an existing 32-byte seed. The slice is copied; the caller's is theirs.
func NewAgent(seed []byte) (*Agent, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("agent seed must be %d bytes", ed25519.SeedSize)
	}
	s := append([]byte(nil), seed...)
	pub := ed25519.NewKeyFromSeed(s).Public().(ed25519.PublicKey)
	return &Agent{seed: s, aid: AIDFromPubkey(pub)}, nil
}

// GenerateAgent is a new agent identity from 32 CSPRNG bytes (crypto/rand) — Python's
// `Agent.generate()`. To persist one, use identity.CreateIdentityFile, which generates and writes in
// one step and never returns the seed.
func GenerateAgent() (*Agent, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("generate agent seed: %w", err)
	}
	return NewAgent(seed)
}

// AID is the agent's `aid:pubkey:ed25519:` identity.
func (a *Agent) AID() string { return a.aid }

// Seed returns a copy of the 32-byte seed, for BuildPresentation, CallSigV3, RequestSig and
// EnrollPopSign. Never log it.
func (a *Agent) Seed() []byte { return append([]byte(nil), a.seed...) }

// String renders the AID only — never the seed.
func (a *Agent) String() string { return "Agent(aid=" + a.aid + ")" }

// GoString is what %#v prints; without it %#v would dump the unexported seed bytes.
func (a *Agent) GoString() string { return a.String() }

// Format routes every fmt verb (%x, %s, %v, %+v, %#v, ...) to String, so no verb can reach the seed.
func (a *Agent) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(a.String())) }

// ── The per-request credential (`seam-request-call-v1`, #508) ─────────────────────────────────────

// RequestSigContext is the domain tag of the per-request credential — deliberately distinct from the
// Authorize call_sig tag, so a captured call_sig is never spendable as a request credential.
const RequestSigContext = "seam-request-call-v1"

// SessionUnavailableReason is the ErrorInfo.reason (domain seam.zer07labs.com) of an UNAVAILABLE (HTTP 503) refusal: another
// runtime replica holds the live session's lease, or the shared session store is unreachable
// (seam-runtime k8s P6). RetryInfo carries the holder's remaining lease (at most the 30s lease TTL), or
// 1s while the store is down; a single-replica runtime never returns it. It is retryable, but the
// runtime has already burned the credential's proof for every credentialed write except ReportOutcome,
// and the signature is deterministic: drop the cached admission ticket, re-admit, and re-sign before
// resending, or the resend is refused UNAUTHENTICATED request_replayed.
const SessionUnavailableReason = "SESSION_UNAVAILABLE"

// RequestSigPayload is the exact byte string RequestSig signs:
//
//	frame(context) | frame(ticket) | frame(rpc_full_name) | frame(resource_id) | frame(body_digest)
//
// with frame(x) = u32le(len_bytes(x)) | x. rpcFullName is the gRPC full method path on both transports
// (e.g. "/seam.api.v1.SeamCoordination/GetDecision"). A bodyless read binds its id as resourceID and an
// empty bodyDigest; a bodied verb over gRPC binds an empty resourceID and BodyDigest of the request
// message's exact serialized bytes. Pinned by conformance/request_sig_payload_vector.json.
func RequestSigPayload(ticket []byte, rpcFullName, resourceID, bodyDigest string) []byte {
	var out []byte
	for _, p := range [][]byte{[]byte(RequestSigContext), ticket, []byte(rpcFullName), []byte(resourceID), []byte(bodyDigest)} {
		out = binary.LittleEndian.AppendUint32(out, uint32(len(p)))
		out = append(out, p...)
	}
	return out
}

// RequestSig is Ed25519 by the agent key over RequestSigPayload: the raw 64-byte `x-seam-call-sig-bin`.
func RequestSig(agentSeed, ticket []byte, rpcFullName, resourceID, bodyDigest string) ([]byte, error) {
	if len(agentSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("agent seed must be %d bytes", ed25519.SeedSize)
	}
	return ed25519.Sign(ed25519.NewKeyFromSeed(agentSeed), RequestSigPayload(ticket, rpcFullName, resourceID, bodyDigest)), nil
}

// BodyDigest is "sha256:" + lowercase hex of SHA-256 over body — the exact wire bytes of the request
// message, never a re-serialization taken after the fact.
func BodyDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Metadata keys the per-request credential travels in over gRPC (binary `-bin` headers).
const (
	TicketMetadataKey  = "x-seam-ticket-bin"
	CallSigMetadataKey = "x-seam-call-sig-bin"
)

// TicketSource returns a live admission ticket for agent. The Go module carries no transport, so the
// caller's own client admits (BuildPresentation → Admit) and caches; RequestCredentials only signs.
type TicketSource func(agent *Agent) ([]byte, error)

// RequestCredentials attaches the `seam-request-call-v1` credential to subject-scoped calls (#202).
//
// The Go module is a crypto shim with no client and no verb methods (see COMPATIBILITY.md §4), so the
// bound-agent default lives here, transport-agnostic, rather than on a client: it is the same rule as
// Python's `SeamClient(channel, agent=...)._signer` and TS's `credential ??= this.agent`. A caller
// building its own client over the generated stubs holds one RequestCredentials and calls Metadata for
// each subject-scoped verb.
type RequestCredentials struct {
	// Agent is the bound agent. Nil leaves the credential opt-in per call, as before #202.
	Agent *Agent
	// Tickets supplies the admission ticket for whichever agent signs.
	Tickets TicketSource
}

// Metadata is the gRPC metadata for one subject-scoped call. An explicit credential wins; otherwise the
// bound Agent is used; with neither it returns nil and no credential is sent. resourceID is the verb's
// id for a bodyless read ("" for a bodied verb); body is the request message's exact serialized bytes
// for a bodied verb, or nil for a bodyless one.
func (r RequestCredentials) Metadata(credential *Agent, rpcFullName, resourceID string, body []byte) (map[string][]byte, error) {
	if credential == nil {
		credential = r.Agent
	}
	if credential == nil {
		return nil, nil
	}
	if r.Tickets == nil {
		return nil, fmt.Errorf("RequestCredentials: no TicketSource to admit %s", credential.AID())
	}
	ticket, err := r.Tickets(credential)
	if err != nil {
		return nil, err
	}
	digest := ""
	if body != nil {
		digest = BodyDigest(body)
	}
	sig, err := RequestSig(credential.seed, ticket, rpcFullName, resourceID, digest)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{TicketMetadataKey: ticket, CallSigMetadataKey: sig}, nil
}
