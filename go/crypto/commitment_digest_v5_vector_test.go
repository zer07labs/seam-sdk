package crypto

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// conformance/commitment_digest_v5_signed_vector.json is the runtime's reference vector for
// `seam-commitment-digest:v5` + `seam-explanation-digest:v2` (seam-runtime #1711, #1687). A port is conforming iff it
// reproduces every digest in it and verifies its signed_artifact against issuer_aid. The commitments are the
// REST projection: byte fields (governing_doc_sha256 included) as JSON number arrays, absent
// confidence/rationale_ref/supersedes/voter_verification/governing_doc_sha256 as null. The slot-9/10
// digests sit beside the commitment as hex (null = absent).
type v5Vector struct {
	CommitmentDigestDomain  string `json:"commitment_digest_domain"`
	ExplanationDigestDomain string `json:"explanation_digest_domain"`
	IssuerAID               string `json:"issuer_aid"`
	Cases                   []struct {
		Name       string `json:"name"`
		Commitment struct {
			ID                 string             `json:"id"`
			Action             string             `json:"action"`
			Authority          string             `json:"authority"`
			Supersedes         *string            `json:"supersedes"`
			AuthMethod         string             `json:"auth_method"`
			TrustBasis         string             `json:"trust_basis"`
			Committer          string             `json:"committer"`
			SignedArtifact     []int              `json:"signed_artifact"`
			ExplanationDigest  []int              `json:"explanation_digest"`
			Explanation        []ExplanationEntry `json:"explanation"`
			GoverningDocSha256 []int              `json:"governing_doc_sha256"`
		} `json:"commitment"`
		SelectionDigest   *string `json:"selection_digest"`
		CertificateDigest *string `json:"certificate_digest"`
		ExplanationDigest string  `json:"explanation_digest"`
		CommitmentDigest  string  `json:"commitment_digest"`
	} `json:"cases"`
}

func intsToBytes(t *testing.T, in []int) []byte {
	t.Helper()
	out := make([]byte, len(in))
	for i, b := range in {
		if b < 0 || b > 255 {
			t.Fatalf("byte out of range: %d", b)
		}
		out[i] = byte(b)
	}
	return out
}

func optHex(t *testing.T, s *string) []byte {
	t.Helper()
	if s == nil {
		return nil
	}
	b, err := hex.DecodeString(*s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// optInts is a JSON number array that may be null (absent).
func optInts(t *testing.T, in []int) []byte {
	t.Helper()
	if in == nil {
		return nil
	}
	return intsToBytes(t, in)
}

func loadV5(t *testing.T) v5Vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "commitment_digest_v5_signed_vector.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v v5Vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("vector is empty")
	}
	return v
}

func TestCommitmentDigestV5Vector(t *testing.T) {
	v := loadV5(t)
	if v.CommitmentDigestDomain != CommitmentDigestDomain || v.ExplanationDigestDomain != ExplanationDomain {
		t.Fatalf("domain tags drifted: %q / %q", v.CommitmentDigestDomain, v.ExplanationDigestDomain)
	}
	signed := 0
	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			vc := tc.Commitment
			if vc.Explanation == nil {
				vc.Explanation = []ExplanationEntry{}
			}
			ed, err := ExplanationDigest(vc.Explanation)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(ed[:]); got != tc.ExplanationDigest {
				t.Fatalf("explanation digest: got %s want %s", got, tc.ExplanationDigest)
			}
			published := intsToBytes(t, vc.ExplanationDigest)
			if hex.EncodeToString(published) != tc.ExplanationDigest {
				t.Fatalf("the vector's published explanation_digest disagrees with its own hex")
			}
			c := Commitment{
				ID: vc.ID, Action: vc.Action, Authority: vc.Authority, AuthMethod: vc.AuthMethod,
				TrustBasis: vc.TrustBasis, Committer: vc.Committer,
				ExplanationDigest: published, Explanation: vc.Explanation, Supersedes: vc.Supersedes,
				SelectionDigest: optHex(t, tc.SelectionDigest), CertificateDigest: optHex(t, tc.CertificateDigest),
				GoverningDocSha256: optInts(t, vc.GoverningDocSha256),
			}
			// All three field-8 resolutions must agree: entries + published, entries only, published only.
			only := c
			only.ExplanationDigest = nil
			pubOnly := c
			pubOnly.Explanation = nil
			for name, cc := range map[string]Commitment{"entries+published": c, "entries": only, "published": pubOnly} {
				got, err := seamCommitmentDigest(cc)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if got != tc.CommitmentDigest {
					t.Fatalf("%s: commitment digest got %s want %s", name, got, tc.CommitmentDigest)
				}
			}
			if len(vc.SignedArtifact) > 0 {
				signed++
				jws := string(intsToBytes(t, vc.SignedArtifact))
				if !VerifyTCT(v.IssuerAID, jws, c, 0) {
					t.Fatal("signed_artifact must verify against issuer_aid")
				}
				tampered := c
				tampered.Explanation = cloneEntries(c.Explanation)
				tampered.Explanation[0].Reason += "-x"
				tampered.ExplanationDigest = nil
				if VerifyTCT(v.IssuerAID, jws, tampered, 0) {
					t.Fatal("a tampered explanation must not verify")
				}
			}
		})
	}
	if signed == 0 {
		t.Fatal("no case carries a signed_artifact; the signature path is untested")
	}
	voters := 0
	for _, tc := range v.Cases {
		for _, e := range tc.Commitment.Explanation {
			if e.VoterVerification != nil {
				voters++
			}
		}
	}
	if voters == 0 {
		t.Fatal("no entry carries a voter_verification; the VV framing is untested")
	}
	governed := 0
	for _, tc := range v.Cases {
		if tc.Commitment.GoverningDocSha256 != nil && len(tc.Commitment.SignedArtifact) > 0 {
			governed++
		}
	}
	if governed == 0 {
		t.Fatal("no signed case carries governing_doc_sha256; field 11 is untested under a signature")
	}
}

// conformance/commitment_digest_v5_vector.json: the slot vector, generated independently of the
// runtime (scripts/commitment_digest_v5_vectors.py). Commitments carry only the published
// explanation_digest (a number array); the slot-9/10/11 digests sit beside them as hex (null = absent).
// Its `governing_trailer_refusals` are not exercised here: they pin the runtime's 0x06 trailer
// decoder, and this SDK never decodes sealed trailers — field 11 reaches it as the proto field.
func TestCommitmentDigestV5SlotVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "commitment_digest_v5_vector.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v struct {
		CommitmentDigestDomain string `json:"commitment_digest_domain"`
		Cases                  []struct {
			Name       string `json:"name"`
			Commitment struct {
				ID                string  `json:"id"`
				Action            string  `json:"action"`
				Authority         string  `json:"authority"`
				AuthMethod        string  `json:"auth_method"`
				TrustBasis        string  `json:"trust_basis"`
				Supersedes        *string `json:"supersedes"`
				Committer         string  `json:"committer"`
				ExplanationDigest []int   `json:"explanation_digest"`
			} `json:"commitment"`
			SelectionDigest    *string `json:"selection_digest"`
			CertificateDigest  *string `json:"certificate_digest"`
			GoverningDocSha256 *string `json:"governing_doc_sha256"`
			CommitmentDigest   string  `json:"commitment_digest"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if v.CommitmentDigestDomain != CommitmentDigestDomain {
		t.Fatalf("domain tag drifted: %q", v.CommitmentDigestDomain)
	}
	if len(v.Cases) < 7 {
		t.Fatalf("expected at least 7 cases, got %d", len(v.Cases))
	}
	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			vc := tc.Commitment
			got, err := seamCommitmentDigest(Commitment{
				ID: vc.ID, Action: vc.Action, Authority: vc.Authority, AuthMethod: vc.AuthMethod,
				TrustBasis: vc.TrustBasis, Supersedes: vc.Supersedes, Committer: vc.Committer,
				ExplanationDigest:  intsToBytes(t, vc.ExplanationDigest),
				SelectionDigest:    optHex(t, tc.SelectionDigest),
				CertificateDigest:  optHex(t, tc.CertificateDigest),
				GoverningDocSha256: optHex(t, tc.GoverningDocSha256),
			})
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.CommitmentDigest {
				t.Fatalf("commitment digest got %s want %s", got, tc.CommitmentDigest)
			}
		})
	}
}

// Fields 9, 10 and 11: a present digest must be exactly 32 bytes, and presence is a different preimage from
// absence (no all-zero sentinel).
func TestCommitmentSlotsRefuseBadLengthAndBindPresence(t *testing.T) {
	absent, err := seamCommitmentDigest(Commitment{})
	if err != nil {
		t.Fatal(err)
	}
	zero := make([]byte, 32)
	for name, c := range map[string]Commitment{"selection": {SelectionDigest: zero}, "certificate": {CertificateDigest: zero}, "governing": {GoverningDocSha256: zero}} {
		got, err := seamCommitmentDigest(c)
		if err != nil || got == absent {
			t.Fatalf("%s: a present all-zero digest must differ from absent (%v)", name, err)
		}
	}
	for name, c := range map[string]Commitment{
		"selection 31":   {SelectionDigest: zero[:31]},
		"selection 0":    {SelectionDigest: []byte{}},
		"certificate 33": {CertificateDigest: append(append([]byte{}, zero...), 0)},
		"governing 31":   {GoverningDocSha256: zero[:31]},
		"governing 0":    {GoverningDocSha256: []byte{}},
		"governing 33":   {GoverningDocSha256: append(append([]byte{}, zero...), 0)},
	} {
		if _, err := seamCommitmentDigest(c); err == nil {
			t.Fatalf("%s must be refused, not hashed", name)
		}
	}
}

func voterEntry() ExplanationEntry {
	return ExplanationEntry{Kind: "vote", Participant: "risk", ProposalID: "p1", Value: "APPROVE",
		VoterVerification: &VoterVerification{Method: VoterMethodPop, ContentDigest: make([]byte, 32), Signature: make([]byte, 64)}}
}

func TestExplanationVoterRecordRefusals(t *testing.T) {
	plain := voterEntry()
	plain.VoterVerification = nil
	a, err := ExplanationDigest([]ExplanationEntry{plain})
	if err != nil {
		t.Fatal(err)
	}
	b, err := ExplanationDigest([]ExplanationEntry{voterEntry()})
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("a voter record must change the entry's preimage")
	}
	for name, mutate := range map[string]func(*VoterVerification){
		"unspecified method": func(v *VoterVerification) { v.Method = "" },
		"enum name":          func(v *VoterVerification) { v.Method = "VOTER_VERIFICATION_POP" },
		"uppercase":          func(v *VoterVerification) { v.Method = "POP" },
		"short digest":       func(v *VoterVerification) { v.ContentDigest = v.ContentDigest[:31] },
	} {
		e := voterEntry()
		mutate(e.VoterVerification)
		if _, err := ExplanationDigest([]ExplanationEntry{e}); err == nil {
			t.Fatalf("%s must be refused, not hashed", name)
		}
	}
	cp := voterEntry()
	cp.VoterVerification.Method = VoterMethodCpSigned
	if _, err := ExplanationDigest([]ExplanationEntry{cp}); err != nil {
		t.Fatalf("cp_signed is a framed word: %v", err)
	}
	for n, want := range map[int32]string{1: "pop", 2: "cp_signed"} {
		if got, err := VoterMethodFromProto(n); err != nil || got != want {
			t.Fatalf("VoterMethodFromProto(%d) = %q, %v", n, got, err)
		}
	}
	for _, n := range []int32{0, 3, -1} {
		if _, err := VoterMethodFromProto(n); err == nil {
			t.Fatalf("VoterMethodFromProto(%d) must be refused", n)
		}
	}
}

func TestExplanationDigestEmptyMatchesSpec(t *testing.T) {
	const want = "cabe83af912ea38ef4525f5a7d8580b4c4e217417edc0c93f936d2c18c4fd8f5"
	for name, entries := range map[string][]ExplanationEntry{"nil": nil, "empty": {}} {
		d, err := ExplanationDigest(entries)
		if err != nil || hex.EncodeToString(d[:]) != want {
			t.Fatalf("%s: got %x, %v; want %s", name, d, err, want)
		}
	}
	// The spec's worked example: all fields empty, no explanation held.
	got, err := seamCommitmentDigest(Commitment{})
	if err != nil || got != "f31f8081790860a42529c30c4b75626213c6ad36b7c797ba172a2246eab41207" {
		t.Fatalf("all-empty worked example: got %s, %v", got, err)
	}
}

func f64(f float64) *float64 { return &f }

func evalEntry(conf *float64) ExplanationEntry {
	return ExplanationEntry{Kind: "evaluation", Participant: "p", ProposalID: "p1", Value: "BLOCK", Confidence: conf}
}

// Absent is not zero: CONF = 0x00 and CONF = 0x01 ‖ be64(0) are different preimages.
func TestExplanationAbsentConfidenceIsNotZero(t *testing.T) {
	absent, err := ExplanationDigest([]ExplanationEntry{evalEntry(nil)})
	if err != nil {
		t.Fatal(err)
	}
	zero, err := ExplanationDigest([]ExplanationEntry{evalEntry(f64(0))})
	if err != nil {
		t.Fatal(err)
	}
	if absent == zero {
		t.Fatal("an absent confidence and a stated 0.0 must give different digests")
	}
	ref := ""
	withRef := evalEntry(nil)
	withRef.RationaleRef = &ref
	r, err := ExplanationDigest([]ExplanationEntry{withRef})
	if err != nil {
		t.Fatal(err)
	}
	if r == absent {
		t.Fatal("an absent rationale_ref and a stated empty one must give different digests")
	}
}

func TestExplanationRefusesNonCanonical(t *testing.T) {
	for name, e := range map[string]ExplanationEntry{
		"negative zero": evalEntry(f64(math.Copysign(0, -1))),
		"NaN":           evalEntry(f64(math.NaN())),
		"+Inf":          evalEntry(f64(math.Inf(1))),
		"-Inf":          evalEntry(f64(math.Inf(-1))),
		"above one":     evalEntry(f64(1.5)),
		"below zero":    evalEntry(f64(-0.1)),
		"unknown kind":  {Kind: "comment"},
		"enum name":     {Kind: "EXPLANATION_KIND_VOTE"},
		"uppercase":     {Kind: "Vote"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ExplanationDigest([]ExplanationEntry{e}); err == nil {
				t.Fatal("must be refused, not hashed")
			}
		})
	}
	for _, ok := range []float64{0, 0.5, 1} {
		if _, err := ExplanationDigest([]ExplanationEntry{evalEntry(f64(ok))}); err != nil {
			t.Fatalf("confidence %v must be accepted: %v", ok, err)
		}
	}
}

// VerifyTCT fails closed (false, no panic) when the held entries disagree with the published digest,
// or when an entry is malformed — even though the signature itself is valid.
func TestVerifyTCTRefusesInconsistentExplanation(t *testing.T) {
	v := load(t)
	c := v.TCT.Inputs.Commitment
	const now = 1_700_000_001
	ed, err := ExplanationDigest(c.Explanation)
	if err != nil {
		t.Fatal(err)
	}

	consistent := c
	consistent.ExplanationDigest = ed[:]
	if !VerifyTCT(v.TCT.IssuerAID, v.TCT.SignedArtifactJWS, consistent, now) {
		t.Fatal("entries + matching published digest must verify")
	}

	disagree := consistent
	disagree.Explanation = cloneEntries(c.Explanation)
	disagree.Explanation[1].Reason = "edited after sealing"
	if VerifyTCT(v.TCT.IssuerAID, v.TCT.SignedArtifactJWS, disagree, now) {
		t.Fatal("entries disagreeing with the published digest must not verify")
	}

	wrongLen := c
	wrongLen.Explanation = nil
	wrongLen.ExplanationDigest = ed[:31]
	if VerifyTCT(v.TCT.IssuerAID, v.TCT.SignedArtifactJWS, wrongLen, now) {
		t.Fatal("a truncated published digest must not verify")
	}

	for name, mutate := range map[string]func(*ExplanationEntry){
		"unknown kind":   func(e *ExplanationEntry) { e.Kind = "comment" },
		"-0.0":           func(e *ExplanationEntry) { e.Confidence = f64(math.Copysign(0, -1)) },
		"NaN confidence": func(e *ExplanationEntry) { e.Confidence = f64(math.NaN()) },
	} {
		bad := c
		bad.Explanation = cloneEntries(c.Explanation)
		mutate(&bad.Explanation[0])
		if VerifyTCT(v.TCT.IssuerAID, v.TCT.SignedArtifactJWS, bad, now) {
			t.Fatalf("%s must fail closed", name)
		}
	}
}

// Unchanged since v3: `supersedes` carries a presence byte, so absent and present-empty
// are different digests (the vector's all_empty / empty_supersedes cases, reproduced directly).
func TestEmptyVsAbsentSupersedesDiffer(t *testing.T) {
	empty := ""
	absent, err := seamCommitmentDigest(Commitment{})
	if err != nil {
		t.Fatal(err)
	}
	present, err := seamCommitmentDigest(Commitment{Supersedes: &empty})
	if err != nil {
		t.Fatal(err)
	}
	if absent == present {
		t.Fatal("absent and present-empty supersedes must give different digests")
	}
	if present != "9bf7e384a2d8b003c1cb5669b8198dcd5784401797d0897586baa87afeba4ce3" {
		t.Fatalf("present-empty supersedes: got %s", present)
	}
}

// The statement rides in ext["com.zer07labs.seam"]; a locally signed token of exactly that shape
// verifies, which is what makes every refusal below about the shape and nothing else.
func TestCommitmentTCTStatementInExt(t *testing.T) {
	v := load(t)
	c := v.TCT.Inputs.Commitment
	iss := issuerFromSeed(t, v.TCT.Inputs.IssuerSeedHex)
	raw, _ := json.Marshal(attestationPayload(t, iss, c))
	if !VerifyTCT(iss, signRawTCT(t, v.TCT.Inputs.IssuerSeedHex, raw), c, 1_700_000_001) {
		t.Fatal("a well-formed self-attestation must verify")
	}
}

func TestCommitmentTCTShapeRefusals(t *testing.T) {
	v := load(t)
	c := v.TCT.Inputs.Commitment
	seed := v.TCT.Inputs.IssuerSeedHex
	iss := issuerFromSeed(t, seed)
	digest, err := seamCommitmentDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	stmt := func() map[string]any {
		return map[string]any{"type": CommitmentStatement, "commitment_digest": digest}
	}
	withStmt := func(p map[string]any, s map[string]any) {
		p["ext"] = map[string]any{CommitmentExtNamespace: s}
	}
	for name, mutate := range map[string]func(map[string]any){
		"statement in grants (v2 shape)": func(p map[string]any) {
			delete(p, "ext")
			p["grants"] = []string{"seam:commitment", "seam-commitment-digest:" + digest}
		},
		"extra grant": func(p map[string]any) {
			p["grants"] = []string{AttestationGrant, "seam-commitment-digest:" + digest}
		},
		"no grants":  func(p map[string]any) { delete(p, "grants") },
		"iss != aud": func(p map[string]any) { p["aud"] = "aid:pubkey:ed25519:" + repeat("B", 43) },
		"sub != iss": func(p map[string]any) { p["sub"] = "aid:pubkey:ed25519:" + repeat("B", 43) },
		"ext absent": func(p map[string]any) { delete(p, "ext") },
		"wrong type": func(p map[string]any) { s := stmt(); s["type"] = "seam:other"; withStmt(p, s) },
		"extra statement field": func(p map[string]any) {
			s := stmt()
			s["x"] = "y"
			withStmt(p, s)
		},
		"extra ext key": func(p map[string]any) {
			p["ext"] = map[string]any{CommitmentExtNamespace: stmt(), "com.example": map[string]any{}}
		},
		"uppercase digest": func(p map[string]any) {
			s := stmt()
			s["commitment_digest"] = strings.ToUpper(digest)
			withStmt(p, s)
		},
		"wrong digest": func(p map[string]any) {
			s := stmt()
			s["commitment_digest"] = repeat("0", 64)
			withStmt(p, s)
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := attestationPayload(t, iss, c)
			mutate(p)
			raw, _ := json.Marshal(p)
			if VerifyTCT(iss, signRawTCT(t, seed, raw), c, 1_700_000_001) {
				t.Fatalf("%s must be refused", name)
			}
		})
	}
}

// encoding/json keeps the LAST of two equal keys; a token whose JSON repeats a key must be refused
// rather than read one way here and another way by a different parser.
func TestCommitmentTCTDuplicateKeyRefused(t *testing.T) {
	v := load(t)
	c := v.TCT.Inputs.Commitment
	seed := v.TCT.Inputs.IssuerSeedHex
	iss := issuerFromSeed(t, seed)
	digest, err := seamCommitmentDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	head := `{"iss":"` + iss + `","sub":"` + iss + `","aud":"` + iss + `","exp":4853600000,"grants":["aitp.attestation"],`
	good := `"ext":{"com.zer07labs.seam":{"type":"seam:commitment","commitment_digest":"` + digest + `"}}}`
	if !VerifyTCT(iss, signRawTCT(t, seed, []byte(head+good)), c, 1_700_000_001) {
		t.Fatal("the hand-written control payload must verify")
	}
	decoy := `{"type":"seam:commitment","commitment_digest":"` + repeat("0", 64) + `"}`
	for name, body := range map[string]string{
		"duplicate namespace key": `"ext":{"com.zer07labs.seam":` + decoy + `,"com.zer07labs.seam":{"type":"seam:commitment","commitment_digest":"` + digest + `"}}}`,
		"duplicate statement key": `"ext":{"com.zer07labs.seam":{"type":"seam:commitment","commitment_digest":"` + repeat("0", 64) + `","commitment_digest":"` + digest + `"}}}`,
		"duplicate ext":           `"ext":{"com.zer07labs.seam":` + decoy + `},` + good,
	} {
		t.Run(name, func(t *testing.T) {
			if VerifyTCT(iss, signRawTCT(t, seed, []byte(head+body)), c, 1_700_000_001) {
				t.Fatalf("%s must be refused", name)
			}
		})
	}
}
