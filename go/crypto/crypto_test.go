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
		ExplanationDigestHex string `json:"explanation_digest_hex"`
		CommitmentDigestHex  string `json:"commitment_digest_hex"`
		IssuerAID            string `json:"issuer_aid"`
		SignedArtifactJWS    string `json:"signed_artifact_jws"`
	} `json:"tct"`
	DerivedUUID map[string]json.RawMessage `json:"derived_uuid"`
}

type derivedUUIDCase struct {
	Tag      string `json:"tag"`
	InputHex string `json:"input_hex"`
	UUID     string `json:"uuid"`
}

func derivedCase(t *testing.T, v vectors, name string) derivedUUIDCase {
	t.Helper()
	raw, ok := v.DerivedUUID[name]
	if !ok {
		t.Fatalf("vectors.json derived_uuid block has no %q", name)
	}
	var c derivedUUIDCase
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// The AITP known answer, the PoP message_id, and the TCT jti all come from ONE primitive.
func TestDerivedUUIDVectors(t *testing.T) {
	v := load(t)
	want := map[string]string{
		"kat_derived_uuid_001": "27b131ae-bcc6-4466-ab32-1d0f896453b1",
		"pop_message_id":       "786ec92e-a43a-40b5-98d8-848ff365ea78",
		"tct_jti":              "c7321ce4-62f1-4e38-ac23-212dc9e0055b",
	}
	for name, literal := range want {
		t.Run(name, func(t *testing.T) {
			c := derivedCase(t, v, name)
			if c.UUID != literal {
				t.Fatalf("vector drifted from the pinned literal: %s", c.UUID)
			}
			in, err := hex.DecodeString(c.InputHex)
			if err != nil {
				t.Fatal(err)
			}
			if got := DerivedUUID(c.Tag, in); got != c.UUID {
				t.Fatalf("DerivedUUID(%q): got %s want %s", c.Tag, got, c.UUID)
			}
		})
	}
}

func TestPopMessageIDMatchesRuntimeVectors(t *testing.T) {
	v := load(t)
	c := derivedCase(t, v, "pop_message_id")
	if c.Tag != PopMessageIDTag {
		t.Fatalf("tag drifted: %q", c.Tag)
	}
	in, _ := hex.DecodeString(c.InputHex)
	if string(in) != v.Admission.Inputs.PopNonce {
		t.Fatal("the pop_message_id input must be the admission nonce's ASCII text")
	}
	if got := PopMessageID(v.Admission.Inputs.PopNonce); got != c.UUID || got != v.Admission.Presentation.MessageID {
		t.Fatalf("PopMessageID: got %s want %s / %s", got, c.UUID, v.Admission.Presentation.MessageID)
	}
}

// The presentation carries exactly five fields (the runtime decodes it with deny_unknown_fields).
func TestPresentationHasExactlyFiveFields(t *testing.T) {
	v := load(t)
	seed, _ := hex.DecodeString(v.Admission.Inputs.AgentSeedHex)
	p, err := BuildPresentation(seed, v.Admission.Inputs.ReceiverAID, v.Admission.Inputs.PopNonce, v.Admission.Inputs.NowMs)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(p)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for k := range m {
		keys = append(keys, k)
	}
	if len(m) != 5 {
		t.Fatalf("presentation has %d fields: %v", len(m), keys)
	}
	for _, k := range []string{"sender_aid", "descriptor", "message_id", "timestamp", "pop_nonce"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("presentation lacks %q: %v", k, keys)
		}
	}
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

// The vector pins both digests explicitly, not only through the signed grant.
func TestTCTVectorDigests(t *testing.T) {
	v := load(t)
	c := v.TCT.Inputs.Commitment
	ed, err := ExplanationDigest(c.Explanation)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(ed[:]); got != v.TCT.ExplanationDigestHex {
		t.Fatalf("explanation digest: got %s want %s", got, v.TCT.ExplanationDigestHex)
	}
	got, err := seamCommitmentDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	if got != v.TCT.CommitmentDigestHex {
		t.Fatalf("commitment digest: got %s want %s", got, v.TCT.CommitmentDigestHex)
	}
	// Holding only the published digest (no entries) verifies the same grant.
	pub := c
	pub.Explanation = nil
	pub.ExplanationDigest = ed[:]
	if !VerifyTCT(v.TCT.IssuerAID, v.TCT.SignedArtifactJWS, pub, 1_700_000_001) {
		t.Fatal("the published explanation_digest alone must verify")
	}
}

func cloneEntries(in []ExplanationEntry) []ExplanationEntry {
	return append([]ExplanationEntry(nil), in...)
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
	issuerAID = issuerFromSeed(t, seedHex)
	payload := attestationPayload(t, issuerAID, c)
	payload["exp"] = exp
	raw, _ := json.Marshal(payload)
	return issuerAID, signRawTCT(t, seedHex, raw)
}

func issuerFromSeed(t *testing.T, seedHex string) string {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatal(err)
	}
	return AIDFromPubkey(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
}

// attestationPayload is the self-attestation TCT payload the runtime seals a commitment as.
func attestationPayload(t *testing.T, issuerAID string, c Commitment) map[string]any {
	t.Helper()
	digest, err := seamCommitmentDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"iss": issuerAID, "sub": issuerAID, "aud": issuerAID,
		"exp":    4853600000,
		"grants": []string{AttestationGrant},
		"ext": map[string]any{CommitmentExtNamespace: map[string]any{
			"type": CommitmentStatement, "commitment_digest": digest,
		}},
	}
}

// signRawTCT signs exactly the given payload bytes, so a test can hand-write JSON (e.g. a repeated key).
func signRawTCT(t *testing.T, seedHex string, payload []byte) string {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	header, _ := json.Marshal(map[string]any{"alg": "EdDSA", "typ": "aitp-tct+jwt"})
	signing := b64urlNoPad(header) + "." + b64urlNoPad(payload)
	return signing + "." + b64urlNoPad(ed25519.Sign(priv, []byte(signing)))
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
// the framing inputs was proven bound. The other five commitment fields and the length-prefix
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
		{"supersedes (absent -> present)", func(c *Commitment) { s := "k-previous"; c.Supersedes = &s }},
		{"supersedes (absent -> present empty)", func(c *Commitment) { s := ""; c.Supersedes = &s }},
		{"auth_method", func(c *Commitment) { c.AuthMethod += "-x" }},
		{"trust_basis", func(c *Commitment) { c.TrustBasis += "-x" }},
		{"committer", func(c *Commitment) { c.Committer += "-x" }},
		{"explanation reason", func(c *Commitment) {
			c.Explanation = cloneEntries(c.Explanation)
			c.Explanation[0].Reason += "-x"
		}},
		{"explanation order", func(c *Commitment) {
			c.Explanation = cloneEntries(c.Explanation)
			c.Explanation[0], c.Explanation[1] = c.Explanation[1], c.Explanation[0]
		}},
		{"explanation dropped (entries -> empty)", func(c *Commitment) { c.Explanation = []ExplanationEntry{} }},
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
