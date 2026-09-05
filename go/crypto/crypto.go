// Package crypto is the client-side crypto for the Seam Go SDK — pure Go stdlib (Ed25519 + SHA-256),
// no AITP binding. The admission proof-of-possession is Ed25519 over SHA-256 of a documented,
// domain-separated canonical byte layout (RFC-AITP-0002 §3); the seed never leaves the client. The
// cross-language conformance vectors in conformance/vectors.json (generated from the Rust reference) pin
// the exact bytes — this shim mirrors the Python/TypeScript reference byte-for-byte.
package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

var proofDomain = []byte("aitp-pinned-key-v1\x00")

func b64urlNoPad(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// AIDFromPubkey is the agent's `aid:pubkey:ed25519:` identity for a 32-byte Ed25519 public key.
func AIDFromPubkey(pub []byte) string { return "aid:pubkey:ed25519:" + b64urlNoPad(pub) }

// aidToPubkey recovers the 32-byte Ed25519 public key embedded in an `aid:pubkey:[ed25519:]<43-b64url>`.
func aidToPubkey(aid string) ([]byte, error) {
	for _, p := range []string{"aid:pubkey:ed25519:", "aid:pubkey:"} {
		if strings.HasPrefix(aid, p) {
			return b64urlDecode(aid[len(p):])
		}
	}
	return nil, fmt.Errorf("unsupported AID form: %q", aid)
}

// popMessageID is the deterministic (no-RNG) message id: the first 16 bytes of
// SHA-256("seam-pop-mid" || pop_nonce), formatted as a hyphenated UUID (raw bytes, no version munging).
func popMessageID(popNonce string) string {
	sum := sha256.Sum256(append([]byte("seam-pop-mid"), []byte(popNonce)...))
	b := sum[:16]
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Descriptor is the pinned-key credential inside a presentation.
type Descriptor struct {
	Type      string `json:"type"`
	Subject   string `json:"subject"`
	Proof     string `json:"proof"`
	PublicKey string `json:"public_key"`
}

// Presentation is the pinned-key admission presentation the Seam server verifies.
type Presentation struct {
	SenderAID  string     `json:"sender_aid"`
	Descriptor Descriptor `json:"descriptor"`
	MessageID  string     `json:"message_id"`
	Timestamp  int64      `json:"timestamp"`
	PopNonce   string     `json:"pop_nonce"`
}

// Commitment is the sealed-decision commitment whose rooted TCT is verified.
type Commitment struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	Authority  string `json:"authority"`
	Supersedes string `json:"supersedes"`
	AuthMethod string `json:"auth_method"`
	TrustBasis string `json:"trust_basis"`
}

// BuildPresentation builds the pinned-key admission presentation.
//
//	proof = base64url(Ed25519_sign( SHA256( domain || sender_aid \0 || receiver_aid \0 ||
//	        message_id \0 || timestamp_be_i64 \0 || b64url_decode(pop_nonce) ) ))
func BuildPresentation(agentSeed []byte, receiverAID, popNonce string, nowMs int64) (Presentation, error) {
	if len(agentSeed) != ed25519.SeedSize {
		return Presentation{}, fmt.Errorf("agent seed must be %d bytes", ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(agentSeed)
	pub := priv.Public().(ed25519.PublicKey)
	senderAID := AIDFromPubkey(pub)
	mid := popMessageID(popNonce)
	timestamp := nowMs / 1000

	nonceBytes, err := b64urlDecode(popNonce)
	if err != nil {
		return Presentation{}, fmt.Errorf("pop_nonce is not base64url: %w", err)
	}
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(timestamp))

	var in []byte
	in = append(in, proofDomain...)
	in = append(in, []byte(senderAID)...)
	in = append(in, 0)
	in = append(in, []byte(receiverAID)...)
	in = append(in, 0)
	in = append(in, []byte(mid)...)
	in = append(in, 0)
	in = append(in, ts[:]...)
	in = append(in, 0)
	in = append(in, nonceBytes...)

	digest := sha256.Sum256(in)
	proof := b64urlNoPad(ed25519.Sign(priv, digest[:]))

	return Presentation{
		SenderAID: senderAID,
		Descriptor: Descriptor{
			Type:      "pinned_key",
			Subject:   senderAID,
			Proof:     proof,
			PublicKey: b64urlNoPad(pub),
		},
		MessageID: mid,
		Timestamp: timestamp,
		PopNonce:  popNonce,
	}, nil
}

// seamCommitmentDigest is SHA-256 (hex) over a length-prefixed framing of a domain tag + the commitment
// fields — each field prefixed with its 8-byte big-endian length so the digest is injective over the
// field tuple (a `\0` separator would let boundary-shifted fields collide). Mirrors the runtime.
func seamCommitmentDigest(c Commitment) string {
	h := sha256.New()
	for _, f := range [][]byte{
		[]byte("seam-commitment-digest:v1"),
		[]byte(c.ID),
		[]byte(c.Action),
		[]byte(c.Authority),
		[]byte(c.Supersedes),
		[]byte(c.AuthMethod),
		[]byte(c.TrustBasis),
	} {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(f)))
		h.Write(l[:])
		h.Write(f)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyTCT independently verifies a sealed commitment's rooted TCT — zero server trust, stock crypto.
// It verifies the EdDSA JWS against the issuer's key (recovered from its AID), checks the self-issued
// claims (`typ`, `iss==sub==aud==issuer_aid`, `exp`), and that the bound `seam-commitment-digest` grant
// matches this exact commitment. Any malformed/forged input fails closed (returns false), never panics.
func VerifyTCT(issuerAID, tctJWS string, c Commitment, nowS int64) bool {
	parts := strings.Split(tctJWS, ".")
	if len(parts) != 3 {
		return false
	}
	pub, err := aidToPubkey(issuerAID)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := b64urlDecode(parts[2])
	if err != nil {
		return false
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(parts[0]+"."+parts[1]), sig) {
		return false
	}
	headerBytes, err := b64urlDecode(parts[0])
	if err != nil {
		return false
	}
	payloadBytes, err := b64urlDecode(parts[1])
	if err != nil {
		return false
	}
	var header, payload map[string]any
	if json.Unmarshal(headerBytes, &header) != nil || json.Unmarshal(payloadBytes, &payload) != nil {
		return false
	}
	if header["alg"] != "EdDSA" || header["typ"] != "aitp-tct+jwt" {
		return false
	}
	iss, _ := payload["iss"].(string)
	sub, _ := payload["sub"].(string)
	aud, _ := payload["aud"].(string)
	if !(iss == sub && sub == aud && aud == issuerAID) {
		return false
	}
	// This type assertion is the NORMATIVE `exp` rule for all five SDKs — `exp` must be a JSON
	// number, so a string, a bool, null, absent, an object or an array all refuse the token. It was
	// adopted (rather than Python's or TypeScript's looser reading) because Java and Kotlin already
	// matched it, making it the standing 3-of-5 majority, and because it is the strictest of the
	// three shapes that were in the tree — the safe direction for a token verifier. Python and
	// TypeScript were brought here; conformance/tct_exp_extended.json is what holds them here.
	exp, ok := payload["exp"].(float64)
	if !ok {
		return false
	}
	// The rule has to be TOTAL, and `int64(exp)` is not: the Go spec leaves the conversion
	// implementation-defined when the value does not fit. Measured, this arm64 build saturates
	// (`int64(1e300)` is `MaxInt64`, so the token verifies); amd64's CVTTSD2SQ yields INT64_MIN, so
	// the same token is REFUSED there. A normative rule whose answer depends on the architecture of
	// whoever is checking is not a rule, and it would have made CI's own machine the arbiter.
	// Bounded explicitly instead — 2^63 is exactly representable as a float64, so this comparison is
	// itself exact — and Python and TypeScript carry the same bound so all five still agree.
	if exp >= 9223372036854775808.0 || exp < -9223372036854775808.0 {
		return false
	}
	// Reject at/after expiry (RFC 7519), TRUNCATING toward zero to whole seconds first: for
	// exp = N + 0.5, nowS = N is already expired. A float-precise compare would accept it and drift
	// from the shims; flooring would differ from all four of them on a negative exp.
	if nowS >= int64(exp) {
		return false
	}
	want := "seam-commitment-digest:" + seamCommitmentDigest(c)
	grants, ok := payload["grants"].([]any)
	if !ok {
		return false
	}
	for _, g := range grants {
		if s, ok := g.(string); ok && s == want {
			return true
		}
	}
	return false
}
