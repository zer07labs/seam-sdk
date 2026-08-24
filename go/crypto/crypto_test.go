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

// signTCT builds a minimally-valid TCT JWS over the given commitment with the given exp claim, signed
// by the issuer seed — a local fixture generator for boundary cases the published vector cannot pin.
func signTCT(t *testing.T, seedHex string, c Commitment, exp float64) (issuerAID, jws string) {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	issuerAID = AIDFromPubkey(priv.Public().(ed25519.PublicKey))
	header, _ := json.Marshal(map[string]any{"alg": "EdDSA", "typ": "aitp-tct+jwt"})
	payload, _ := json.Marshal(map[string]any{
		"iss": issuerAID, "sub": issuerAID, "aud": issuerAID,
		"exp":    exp,
		"grants": []string{"seam-commitment-digest:" + seamCommitmentDigest(c)},
	})
	signing := b64urlNoPad(header) + "." + b64urlNoPad(payload)
	sig := ed25519.Sign(priv, []byte(signing))
	return issuerAID, signing + "." + b64urlNoPad(sig)
}

// TestTCTExpFractionalBoundary pins the reference truncation semantics shared by every shim: exp is
// truncated to whole seconds BEFORE the `nowS >= exp` comparison (Python: `int(payload["exp"])`), so
// for exp = N + 0.5 the token is already expired at nowS = N. A float-precise compare (Go's previous
// behavior) would still accept it there and drift from Python/Java/Kotlin.
func TestTCTExpFractionalBoundary(t *testing.T) {
	v := load(t)
	c := v.TCT.Inputs.Commitment
	const n = int64(1_700_000_000)
	iss, jws := signTCT(t, v.TCT.Inputs.IssuerSeedHex, c, float64(n)+0.5)
	if VerifyTCT(iss, jws, c, n) {
		t.Fatal("exp = N + 0.5 must already be expired at nowS = N (truncation semantics)")
	}
	if !VerifyTCT(iss, jws, c, n-1) {
		t.Fatal("exp = N + 0.5 must still verify at nowS = N - 1")
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

// ── Commitment-digest framing coverage (W5.4 / G4) ────────────────────────────────────────────────
//
// `seamCommitmentDigest` is implemented byte-for-byte in ALL FIVE SDK languages and is the framing
// with the widest fan-out in this repo — but it has no vector section of its own in
// `conformance/vectors.json`, and it cannot get one here: `seam-runtime`'s `sdk-digest-parity` job
// byte-diffs that whole file against its own emitter, so a block added on this side turns the
// runtime's CI red. A vector for it has to originate there.
//
// What IS available is stronger than it looks. `VerifyTCT` recomputes the digest and compares it to
// the `seam-commitment-digest:` grant inside the runtime-signed JWS, so the vector already carries a
// runtime-produced expected value for one commitment. The gap was never coverage of the digest — it
// was coverage of the FIELD TUPLE: the only pre-existing test tampered `Action`, so exactly one of
// the seven framing inputs was proven bound. The other five commitment fields and the length-prefix
// property were unproven in every language.
//
// These two tests close that using only the committed vector.

// Every field the commitment digest binds must actually be bound. A field dropped from the preimage
// — or reordered — lets an artifact verify under another's signature, which is the whole reason the
// digest exists (it attests WHO committed and HOW they authed, not just the decision).
func TestCommitmentDigestBindsEveryField(t *testing.T) {
	v := load(t)
	base := v.TCT.Inputs.Commitment
	const now = 1_700_000_001

	if !VerifyTCT(v.TCT.IssuerAID, v.TCT.SignedArtifactJWS, base, now) {
		t.Fatal("the unmodified vector commitment must verify — nothing below means anything otherwise")
	}

	for _, tc := range []struct {
		field  string
		mutate func(*Commitment)
	}{
		{"id", func(c *Commitment) { c.ID += "-x" }},
		{"action", func(c *Commitment) { c.Action = "ALLOW" }},
		{"authority", func(c *Commitment) { c.Authority += "-x" }},
		// The vector's commitment omits `supersedes`, so absent is the branch already exercised.
		// This pins the PRESENT branch, which nothing covered: absent and present must differ, or
		// a supersession could be stripped from a sealed record undetected.
		{"supersedes (absent -> present)", func(c *Commitment) { c.Supersedes = "k-previous" }},
		{"auth_method", func(c *Commitment) { c.AuthMethod += "-x" }},
		{"trust_basis", func(c *Commitment) { c.TrustBasis += "-x" }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			mutated := base
			tc.mutate(&mutated)
			if VerifyTCT(v.TCT.IssuerAID, v.TCT.SignedArtifactJWS, mutated, now) {
				t.Fatalf("changing %s did not change the commitment digest — that field is not bound", tc.field)
			}
		})
	}
}

// The length prefixes are load-bearing, and this is the test that notices if someone "simplifies"
// them away. Both `seam-store` and `seam-trust-aitp` record the reason in their own source: without
// an 8-byte big-endian length before each field, ("a\0b","c") and ("a","b\0c") produce identical
// preimages — letting one Commitment verify under another's TCT. The fields are arbitrary text that
// may itself contain NUL (UTF-8 permits U+0000, and it survives the JSON/prost decision path), so
// this is reachable, not theoretical.
//
// A separator-joined implementation passes every other test in this file and fails this one.
func TestCommitmentDigestIsInjectiveAcrossFieldBoundaries(t *testing.T) {
	v := load(t)
	base := v.TCT.Inputs.Commitment
	const now = 1_700_000_001

	// Shift the boundary between `id` and `action` by folding a NUL into `id`. Under a NUL-joined
	// framing this collides with the real commitment; under length-prefixing it cannot.
	shifted := base
	shifted.ID = base.ID + "\x00" + base.Action
	shifted.Action = ""

	if VerifyTCT(v.TCT.IssuerAID, v.TCT.SignedArtifactJWS, shifted, now) {
		t.Fatal("a boundary-shifted commitment verified — the framing is separator-joined, not " +
			"length-prefixed, and one artifact can now verify under another's signature")
	}
}
