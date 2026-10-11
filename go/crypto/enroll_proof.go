package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"
)

// EnrollProof is the agent-side enrolment proof-of-possession (seam-runtime #1157 / #1164, SDK #214): the
// parts of `EnrollTenantRequest.pop` (`EnrollPop`), produced by the AGENT being enrolled and handed to
// the operator who enrols it. Signature is the RAW 64-byte Ed25519 signature, as the gRPC `bytes` field
// carries it; ToREST gives the `POST /v1/tenants` form, where it is unpadded base64url. The runtime
// accepts a proof at most 5 minutes old and at most 60 s in the future, so produce it just before the
// enrolment call. Mirrors Python's `EnrollProof` and TypeScript's `EnrollProof`.
type EnrollProof struct {
	IssuedAtMs uint64 // Unix epoch MILLISECONDS
	Nonce      string // 1..=128 chars of [A-Za-z0-9_-]
	Signature  []byte // raw 64 bytes
}

// EnrollProofREST is the REST body's `pop` object: `{"issued_at_ms", "nonce", "signature"}`, the
// signature as unpadded base64url. It marshals with encoding/json to exactly the shape Python's
// `EnrollProof.to_rest()` and TypeScript's `enrollProofToRest` produce.
type EnrollProofREST struct {
	IssuedAtMs uint64 `json:"issued_at_ms"`
	Nonce      string `json:"nonce"`
	Signature  string `json:"signature"`
}

// SignatureB64URL is the signature as unpadded base64url — the REST form.
func (p EnrollProof) SignatureB64URL() string { return b64urlNoPad(p.Signature) }

// ToREST is the REST body's `pop` object.
func (p EnrollProof) ToREST() EnrollProofREST {
	return EnrollProofREST{IssuedAtMs: p.IssuedAtMs, Nonce: p.Nonce, Signature: p.SignatureB64URL()}
}

// NewEnrollPopNonce is a fresh nonce: 16 random bytes as unpadded base64url — 22 characters, inside the
// contract.
func NewEnrollPopNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("enrol pop nonce: %w", err)
	}
	return b64urlNoPad(b), nil
}

// EnrollPop signs an enrolment proof with the agent's own key (32-byte seed) at an explicit time and
// nonce. The subject AID is DERIVED from the seed — a proof can only ever speak for the key that signs it
// — and the nonce is validated first, since a proof the runtime will refuse is not worth producing.
// Prefer EnrolmentProof, which defaults issuedAtMs to now and the nonce to a fresh random one.
func EnrollPop(agentSeed []byte, tenant, namespace string, issuedAtMs uint64, nonce string) (EnrollProof, error) {
	if len(agentSeed) != ed25519.SeedSize {
		return EnrollProof{}, fmt.Errorf("agent seed must be %d bytes", ed25519.SeedSize)
	}
	subject := AIDFromPubkey(ed25519.NewKeyFromSeed(agentSeed).Public().(ed25519.PublicKey))
	sig, err := EnrollPopSign(agentSeed, EnrollPopFields{
		SubjectAID: subject,
		Tenant:     tenant,
		Namespace:  namespace,
		IssuedAtMs: issuedAtMs,
		Nonce:      nonce,
	})
	if err != nil {
		return EnrollProof{}, err
	}
	return EnrollProof{IssuedAtMs: issuedAtMs, Nonce: nonce, Signature: sig}, nil
}

// EnrolmentProof is this agent's consent to being enrolled under tenant/namespace: the `pop` an operator
// sends with `EnrollTenant` (gRPC: the raw fields; REST: ToREST). Required for enrolment by a
// tenant-scoped operator token. issuedAtMs is now and the nonce is 16 fresh random bytes as 22 base64url
// characters; use EnrollPop to pin either. The Go counterpart of Python's `Agent.enrolment_proof` and
// TypeScript's `Agent.enrolmentProof`.
func EnrolmentProof(agentSeed []byte, tenant, namespace string) (EnrollProof, error) {
	nonce, err := NewEnrollPopNonce()
	if err != nil {
		return EnrollProof{}, err
	}
	return EnrollPop(agentSeed, tenant, namespace, uint64(time.Now().UnixMilli()), nonce)
}
