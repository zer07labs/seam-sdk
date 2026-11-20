package crypto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// conformance/selection_rule_v1_vectors.json is seam-runtime's option-selection fixture (runtime 0.90.0,
// docs/specs/selection-rule.v1.md), vendored verbatim. This port frames the selection block's digest
// (v5 field 9) and the `proposal` explanation word; the winner recompute (`rule_cases`, `sealed_cases`)
// is driven in selection_decide_test.go.

type selBlockJSON struct {
	SelectionBlock
	RulesDigestHex string `json:"rules_digest"`
}

func (b selBlockJSON) block(t *testing.T) SelectionBlock {
	t.Helper()
	rd, err := hex.DecodeString(b.RulesDigestHex)
	if err != nil {
		t.Fatal(err)
	}
	out := b.SelectionBlock
	out.RulesDigest = rd
	return out
}

type selVector struct {
	Codec struct {
		Block           selBlockJSON `json:"block"`
		Body            string       `json:"body"`
		SelectionDigest string       `json:"selection_digest"`
		Field9          string       `json:"field_9"`
	} `json:"codec"`
	SealedCases []struct {
		Name    string            `json:"name"`
		Entries []json.RawMessage `json:"entries"`
	} `json:"sealed_cases"`
	CommitmentDigestV5 struct {
		Cases []struct {
			Name       string `json:"name"`
			Commitment struct {
				ID         string  `json:"id"`
				Action     string  `json:"action"`
				Authority  string  `json:"authority"`
				Supersedes *string `json:"supersedes"`
				AuthMethod string  `json:"auth_method"`
				TrustBasis string  `json:"trust_basis"`
				Committer  string  `json:"committer"`
			} `json:"commitment"`
			ExplanationDigest  string  `json:"explanation_digest"`
			SelectionDigest    *string `json:"selection_digest"`
			CertificateDigest  *string `json:"certificate_digest"`
			GoverningDocSha256 *string `json:"governing_doc_sha256"`
			CommitmentDigest   string  `json:"commitment_digest"`
		} `json:"cases"`
	} `json:"commitment_digest_v5"`
}

func loadSelVector(t *testing.T) selVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "selection_rule_v1_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v selVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// selEntries reads a sealed case's entries. The fixture spells a voter record's byte fields as hex
// strings under their record names; VoterVerification reads hex under `*_hex`, so they are renamed.
func selEntries(t *testing.T, raws []json.RawMessage) []ExplanationEntry {
	t.Helper()
	out := make([]ExplanationEntry, len(raws))
	for i, r := range raws {
		var m map[string]any
		if err := json.Unmarshal(r, &m); err != nil {
			t.Fatal(err)
		}
		if vv, ok := m["voter_verification"].(map[string]any); ok {
			for _, k := range []string{"content_digest", "signature", "signer_certificate"} {
				vv[k+"_hex"] = vv[k]
				delete(vv, k)
			}
		}
		b, _ := json.Marshal(m)
		if err := json.Unmarshal(b, &out[i]); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestSelectionCodecVector(t *testing.T) {
	v := loadSelVector(t)
	body, err := SelectionBody(v.Codec.Block.block(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(body); got != v.Codec.Body {
		t.Fatalf("body\n got %s\nwant %s", got, v.Codec.Body)
	}
	if len(body) != 422 {
		t.Fatalf("body is %d bytes, want 422", len(body))
	}
	d := SelectionDigest(body)
	if got := hex.EncodeToString(d[:]); got != v.Codec.SelectionDigest {
		t.Fatalf("selection_digest %s, want %s", got, v.Codec.SelectionDigest)
	}
	if got := "01" + "0000000000000020" + hex.EncodeToString(d[:]); got != v.Codec.Field9 {
		t.Fatalf("field_9 %s, want %s", got, v.Codec.Field9)
	}
}

func TestSelectionProposalWordExplanationDigest(t *testing.T) {
	v := loadSelVector(t)
	for _, c := range v.SealedCases {
		if c.Name != "verified" {
			continue
		}
		d, err := ExplanationDigest(selEntries(t, c.Entries))
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(d[:]); got != "40a4e742ffce841dcb2deb0ee6912c590a7268068117dd593bbd11bb4f76e34c" {
			t.Fatalf("explanation digest %s", got)
		}
		return
	}
	t.Fatal("no verified sealed case")
}

func TestSelectionCommitmentDigestV5Cases(t *testing.T) {
	v := loadSelVector(t)
	block := v.Codec.Block.block(t)
	unhex := func(s *string) []byte {
		if s == nil {
			return nil
		}
		b, err := hex.DecodeString(*s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, k := range v.CommitmentDigestV5.Cases {
		ed, _ := hex.DecodeString(k.ExplanationDigest)
		c := Commitment{
			ID: k.Commitment.ID, Action: k.Commitment.Action, Authority: k.Commitment.Authority,
			Supersedes: k.Commitment.Supersedes, AuthMethod: k.Commitment.AuthMethod,
			TrustBasis: k.Commitment.TrustBasis, Committer: k.Commitment.Committer,
			ExplanationDigest: ed, SelectionDigest: unhex(k.SelectionDigest),
			CertificateDigest: unhex(k.CertificateDigest), GoverningDocSha256: unhex(k.GoverningDocSha256),
		}
		got, err := seamCommitmentDigest(c)
		if err != nil || got != k.CommitmentDigest {
			t.Fatalf("%s: %s %v, want %s", k.Name, got, err, k.CommitmentDigest)
		}
		if k.SelectionDigest == nil {
			continue
		}
		both := c
		both.Selection = &block
		if _, err := seamCommitmentDigest(both); err == nil {
			t.Fatalf("%s: Selection and SelectionDigest together must be refused", k.Name)
		}
		c.SelectionDigest = nil
		c.Selection = &block
		if got, err := seamCommitmentDigest(c); err != nil || got != k.CommitmentDigest {
			t.Fatalf("%s (block): %s %v, want %s", k.Name, got, err, k.CommitmentDigest)
		}
	}
}

func TestSelectionBodyRefusesWhatCannotBeSealed(t *testing.T) {
	base := loadSelVector(t).Codec.Block.block(t)
	cases := map[string]func(b *SelectionBlock){
		"weights descending": func(b *SelectionBlock) {
			b.Weights = []SelectionWeight{{"carol", 1}, {"bob", 2}}
		},
		"weights duplicate":     func(b *SelectionBlock) { b.Weights = []SelectionWeight{{"bob", 1}, {"bob", 2}} },
		"rules_digest 31 bytes": func(b *SelectionBlock) { b.RulesDigest = b.RulesDigest[1:] },
		"empty winner":          func(b *SelectionBlock) { b.WinnerProposalID = "" },
	}
	for name, mut := range cases {
		b := base
		mut(&b)
		if _, err := SelectionBody(b); err == nil {
			t.Fatalf("%s: encoded", name)
		}
	}
	// Ascending is by UTF-8 bytes: "Z" < "a" < "é".
	b := base
	b.Weights = []SelectionWeight{{"Z", 1}, {"a", 1}, {"é", 1}}
	if _, err := SelectionBody(b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(SelectionDigestDomain, "v1") {
		t.Fatal(SelectionDigestDomain)
	}
}
