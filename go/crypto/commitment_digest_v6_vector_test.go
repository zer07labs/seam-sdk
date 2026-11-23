package crypto

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

// The three v6 vector files in conformance/ (byte-pinned to seam-runtime's by sdk-digest-parity):
// commitment_digest_v6_vector.json, commitment_digest_v6_signed_vector.json and gate_block_vector.json. Every
// row of every section is asserted, except the gate file's outage_classification and writer_refusals: those
// pin the WRITER (which HTTP outcome may be sealed as which reason), and this SDK is a reader only.
//
// Refusal rows assert refusal only. The rule name is advisory (spec §Refusal rules), so a test never fails
// because a different applicable rule was reported.

func readConformance(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
}

func assertRefused(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a refusal, got acceptance")
	}
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("expected a *Refusal, got %T: %v", err, err)
	}
}

type v6Commitment struct {
	ID                 string             `json:"id"`
	Action             string             `json:"action"`
	Authority          string             `json:"authority"`
	AuthMethod         string             `json:"auth_method"`
	TrustBasis         string             `json:"trust_basis"`
	Supersedes         *string            `json:"supersedes"`
	Committer          string             `json:"committer"`
	ExplanationDigest  []int              `json:"explanation_digest"`
	Explanation        []ExplanationEntry `json:"explanation"`
	GoverningDocSha256 []int              `json:"governing_doc_sha256"`
}

func (vc v6Commitment) toCommitment(t *testing.T) Commitment {
	t.Helper()
	return Commitment{
		ID: vc.ID, Action: vc.Action, Authority: vc.Authority, AuthMethod: vc.AuthMethod,
		TrustBasis: vc.TrustBasis, Supersedes: vc.Supersedes, Committer: vc.Committer,
		ExplanationDigest: optInts(t, vc.ExplanationDigest), Explanation: vc.Explanation,
	}
}

type v6Case struct {
	Name               string       `json:"name"`
	DigestOnly         bool         `json:"digest_only"`
	Commitment         v6Commitment `json:"commitment"`
	SelectionDigest    *string      `json:"selection_digest"`
	GateDigest         *string      `json:"gate_digest"`
	GateBlockCase      *string      `json:"gate_block_case"`
	GoverningDocSha256 *string      `json:"governing_doc_sha256"`
	Env                *string      `json:"env"`
	Trailers           *string      `json:"trailers"`
	Field10            string       `json:"field_10"`
	Field11            string       `json:"field_11"`
	Field12            string       `json:"field_12"`
	CommitmentDigest   string       `json:"commitment_digest"`
	V5CommitmentDigest *string      `json:"v5_commitment_digest"`
}

type v6Refusal struct {
	Name     string            `json:"name"`
	Scheme   *string           `json:"scheme"`
	BaseCase string            `json:"base_case"`
	Override map[string]string `json:"override"`
	Env      *string           `json:"env"`
	Trailers *string           `json:"trailers"`
	Expect   json.RawMessage   `json:"expect"`
	Rule     string            `json:"rule"`
}

type v6Vector struct {
	CommitmentDigestDomain string      `json:"commitment_digest_domain"`
	GateDigestDomain       string      `json:"gate_digest_domain"`
	Cases                  []v6Case    `json:"cases"`
	DigestInputRefusals    []v6Refusal `json:"digest_input_refusals"`
	GoverningRefusals      []v6Refusal `json:"governing_trailer_refusals"`
	V5Refusals             []v6Refusal `json:"v5_refusals"`
	SchemeFree             []v6Refusal `json:"scheme_free"`
	StatementSelection     []struct {
		Name      string  `json:"name"`
		Statement *string `json:"statement"`
		Ext       *string `json:"ext"`
		Expect    string  `json:"expect"`
	} `json:"statement_selection"`
}

func loadV6(t *testing.T) v6Vector {
	t.Helper()
	var v v6Vector
	readConformance(t, "commitment_digest_v6_vector.json", &v)
	if v.CommitmentDigestDomain != CommitmentDigestDomainV6 || v.GateDigestDomain != GateDigestDomain {
		t.Fatalf("domain tags drifted: %q / %q", v.CommitmentDigestDomain, v.GateDigestDomain)
	}
	for name, n := range map[string]int{
		"cases": len(v.Cases), "digest_input_refusals": len(v.DigestInputRefusals),
		"governing_trailer_refusals": len(v.GoverningRefusals), "v5_refusals": len(v.V5Refusals),
		"scheme_free": len(v.SchemeFree), "statement_selection": len(v.StatementSelection),
	} {
		if n == 0 {
			t.Fatalf("section %s is empty", name)
		}
	}
	return v
}

func schemeOf(t *testing.T, s *string) TrailerScheme {
	t.Helper()
	switch {
	case s == nil:
		return SchemeFree
	case *s == "v5":
		return SchemeV5
	case *s == "v6":
		return SchemeV6
	}
	t.Fatalf("unknown scheme %q", *s)
	return 0
}

func (c v6Case) digestFields(t *testing.T) CommitmentDigestFields {
	t.Helper()
	return CommitmentDigestFields{
		SelectionDigest: optHex(t, c.SelectionDigest), GateDigest: optHex(t, c.GateDigest),
		GoverningDocSha256: optHex(t, c.GoverningDocSha256), Env: c.Env,
	}
}

func gateDigestOfCase(t *testing.T, name string) string {
	t.Helper()
	g := loadGate(t)
	for _, c := range g.Cases {
		if c.Name == name {
			return c.GateDigest
		}
	}
	t.Fatalf("no gate case %q", name)
	return ""
}

func TestCommitmentDigestV6Cases(t *testing.T) {
	v := loadV6(t)
	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			c := tc.Commitment.toCommitment(t)
			var f CommitmentDigestFields
			if tc.DigestOnly {
				// Fields 9-12 are digest inputs only; there are no trailers to derive them from.
				if tc.Trailers != nil {
					t.Fatal("a digest_only case must carry trailers: null")
				}
				f = tc.digestFields(t)
			} else {
				if tc.Trailers == nil {
					t.Fatal("a non-digest_only case must carry trailers")
				}
				tr, err := DecodeCommitmentTrailers(mustHex(t, *tc.Trailers), SchemeV6)
				if err != nil {
					t.Fatalf("decode trailers: %v", err)
				}
				// Derived from the bytes, and agreeing with what the vector states beside them.
				want := tc.digestFields(t)
				if !reflect.DeepEqual(tr.GateDigest, want.GateDigest) ||
					!reflect.DeepEqual(tr.GoverningDocSha256, want.GoverningDocSha256) ||
					!reflect.DeepEqual(tr.Env, want.Env) {
					t.Fatalf("derived fields disagree: gate %x doc %x env %v", tr.GateDigest, tr.GoverningDocSha256, tr.Env)
				}
				if tc.GateBlockCase != nil && hex.EncodeToString(tr.GateDigest) != gateDigestOfCase(t, *tc.GateBlockCase) {
					t.Fatalf("gate digest is not gate case %s's", *tc.GateBlockCase)
				}
				f = CommitmentDigestFields{
					SelectionDigest: optHex(t, tc.SelectionDigest), GateDigest: tr.GateDigest,
					GoverningDocSha256: tr.GoverningDocSha256, Env: tr.Env,
				}
				for name, got := range map[string][]byte{"field_10": tr.Field10, "field_11": tr.Field11, "field_12": tr.Field12} {
					if want := map[string]string{"field_10": tc.Field10, "field_11": tc.Field11, "field_12": tc.Field12}[name]; hex.EncodeToString(got) != want {
						t.Fatalf("decoded %s: got %x want %s", name, got, want)
					}
				}
			}
			for name, got := range map[string][]byte{
				"field_10": slotEncoding(f.GateDigest), "field_11": slotEncoding(f.GoverningDocSha256), "field_12": envEncoding(f.Env),
			} {
				if want := map[string]string{"field_10": tc.Field10, "field_11": tc.Field11, "field_12": tc.Field12}[name]; hex.EncodeToString(got) != want {
					t.Fatalf("%s: got %x want %s", name, got, want)
				}
			}
			got, err := CommitmentDigestV6(c, f)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.CommitmentDigest {
				t.Fatalf("v6 digest: got %s want %s", got, tc.CommitmentDigest)
			}
			if tc.V5CommitmentDigest != nil {
				// The re-cut cases: the same inputs under v5 reproduce v5's file, through both v5 paths.
				g5, err := CommitmentDigest(CommitmentV5, c, f)
				if err != nil {
					t.Fatal(err)
				}
				cc := c
				cc.SelectionDigest, cc.CertificateDigest, cc.GoverningDocSha256 = f.SelectionDigest, f.GateDigest, f.GoverningDocSha256
				legacy, err := seamCommitmentDigest(cc)
				if err != nil {
					t.Fatal(err)
				}
				if g5 != *tc.V5CommitmentDigest || legacy != *tc.V5CommitmentDigest {
					t.Fatalf("v5 digest: got %s / %s want %s", g5, legacy, *tc.V5CommitmentDigest)
				}
			}
		})
	}
}

func caseByName(t *testing.T, v v6Vector, name string) v6Case {
	t.Helper()
	for _, c := range v.Cases {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no case %q", name)
	return v6Case{}
}

// digestRefusal replays a base_case + override/env row through the digest function of its scheme.
func digestRefusal(t *testing.T, v v6Vector, r v6Refusal) error {
	t.Helper()
	base := caseByName(t, v, r.BaseCase)
	f := base.digestFields(t)
	for k, val := range r.Override {
		b := mustHex(t, val)
		switch k {
		case "selection_digest":
			f.SelectionDigest = b
		case "gate_digest":
			f.GateDigest = b
		case "governing_doc_sha256":
			f.GoverningDocSha256 = b
		default:
			t.Fatalf("unknown override %q", k)
		}
	}
	if r.Env != nil {
		f.Env = r.Env
	}
	version := CommitmentV6
	if schemeOf(t, r.Scheme) == SchemeV5 {
		version = CommitmentV5
	}
	_, err := CommitmentDigest(version, base.Commitment.toCommitment(t), f)
	return err
}

// #420: a served Gate block or env has no v5 meaning; under v5 both refuse by name.
func TestServedProjectionUnderV5Refuses(t *testing.T) {
	live := "live"
	for want, c := range map[string]Commitment{
		"v5_refuses_gate_block": {GateBody: []byte{1}},
		"v5_refuses_env":        {Env: &live},
	} {
		_, err := expectedCommitmentDigest(CommitmentV5, c)
		var r *Refusal
		if !errors.As(err, &r) || r.Rule != want {
			t.Fatalf("want %s, got %v", want, err)
		}
	}
}

func TestCommitmentDigestV6Refusals(t *testing.T) {
	v := loadV6(t)
	sections := map[string][]v6Refusal{
		"digest_input_refusals":      v.DigestInputRefusals,
		"governing_trailer_refusals": v.GoverningRefusals,
		"v5_refusals":                v.V5Refusals,
	}
	for section, rows := range sections {
		for _, r := range rows {
			t.Run(section+"/"+r.Name, func(t *testing.T) {
				if r.Trailers != nil {
					_, err := DecodeCommitmentTrailers(mustHex(t, *r.Trailers), schemeOf(t, r.Scheme))
					assertRefused(t, err)
					return
				}
				if r.BaseCase == "" {
					t.Fatal("a refusal row needs trailers or a base_case")
				}
				assertRefused(t, digestRefusal(t, v, r))
			})
		}
	}
}

func TestCommitmentTrailersSchemeFree(t *testing.T) {
	v := loadV6(t)
	for _, r := range v.SchemeFree {
		t.Run(r.Name, func(t *testing.T) {
			if r.Scheme != nil {
				t.Fatal("scheme_free rows carry scheme: null")
			}
			got, err := DecodeCommitmentTrailers(mustHex(t, *r.Trailers), SchemeFree)
			var refused string
			if json.Unmarshal(r.Expect, &refused) == nil {
				if refused != "refused" {
					t.Fatalf("unknown expect %q", refused)
				}
				assertRefused(t, err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var want map[string]any
			if err := json.Unmarshal(r.Expect, &want); err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got.Field10) != want["field_10"] || hex.EncodeToString(got.Field11) != want["field_11"] {
				t.Fatalf("fields 10/11: got %x / %x", got.Field10, got.Field11)
			}
			if f12, ok := want["field_12"]; ok {
				if hex.EncodeToString(got.Field12) != f12 {
					t.Fatalf("field_12: got %x want %v", got.Field12, f12)
				}
			} else if got.Field12 != nil {
				t.Fatalf("field_12 must be absent, got %x", got.Field12)
			}
			wantVer := 0
			if n, ok := want["governing_body_version"].(float64); ok {
				wantVer = int(n)
			}
			if got.GoverningBodyVersion != wantVer {
				t.Fatalf("governing_body_version: got %d want %d", got.GoverningBodyVersion, wantVer)
			}
		})
	}
}

func TestCommitmentStatementSelection(t *testing.T) {
	v := loadV6(t)
	for _, r := range v.StatementSelection {
		t.Run(r.Name, func(t *testing.T) {
			var got CommitmentVersion
			var err error
			switch {
			case r.Statement != nil && r.Ext == nil:
				got, err = SelectCommitmentVersionFromStatement([]byte(*r.Statement))
			case r.Ext != nil && r.Statement == nil:
				got, err = SelectCommitmentVersion([]byte(*r.Ext))
			default:
				t.Fatal("a row carries exactly one of statement / ext")
			}
			switch r.Expect {
			case "refused":
				assertRefused(t, err)
			case "v5", "v6":
				if err != nil {
					t.Fatalf("expected %s, refused: %v", r.Expect, err)
				}
				if got.String() != r.Expect {
					t.Fatalf("selected %s, want %s", got, r.Expect)
				}
			default:
				t.Fatalf("unknown expect %q", r.Expect)
			}
		})
	}
}

type v6SignedVector struct {
	CommitmentDigestDomain string `json:"commitment_digest_domain"`
	IssuerAID              string `json:"issuer_aid"`
	SealMs                 int64  `json:"seal_ms"`
	Cases                  []struct {
		Name             string       `json:"name"`
		Commitment       v6Commitment `json:"commitment"`
		Trailers         string       `json:"trailers"`
		Field10          string       `json:"field_10"`
		Field11          string       `json:"field_11"`
		Field12          string       `json:"field_12"`
		CommitmentDigest string       `json:"commitment_digest"`
		Ext              string       `json:"ext"`
		SignedArtifact   string       `json:"signed_artifact"`
		Expect           string       `json:"expect"`
	} `json:"cases"`
	Negatives []struct {
		Name           string `json:"name"`
		Over           string `json:"over"`
		Ext            string `json:"ext"`
		SignedArtifact string `json:"signed_artifact"`
		Expect         string `json:"expect"`
	} `json:"negatives"`
}

func TestCommitmentDigestV6SignedVector(t *testing.T) {
	var v v6SignedVector
	readConformance(t, "commitment_digest_v6_signed_vector.json", &v)
	if v.CommitmentDigestDomain != CommitmentDigestDomainV6 || len(v.Cases) == 0 || len(v.Negatives) == 0 {
		t.Fatal("signed vector drifted or is empty")
	}
	now := v.SealMs / 1000
	commitments := map[string]Commitment{}
	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Expect != "v6" {
				t.Fatalf("unknown expect %q", tc.Expect)
			}
			c := tc.Commitment.toCommitment(t)
			doc := optInts(t, tc.Commitment.GoverningDocSha256)
			c.Trailers = mustHex(t, tc.Trailers)
			tr, err := DecodeCommitmentTrailers(c.Trailers, SchemeV6)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(tr.Field10) != tc.Field10 || hex.EncodeToString(tr.Field11) != tc.Field11 || hex.EncodeToString(tr.Field12) != tc.Field12 {
				t.Fatalf("decoded fields: %x / %x / %x", tr.Field10, tr.Field11, tr.Field12)
			}
			if !reflect.DeepEqual(tr.GoverningDocSha256, doc) {
				t.Fatalf("trailer doc %x disagrees with the record's %x", tr.GoverningDocSha256, doc)
			}
			got, err := expectedCommitmentDigest(CommitmentV6, c)
			if err != nil || got != tc.CommitmentDigest {
				t.Fatalf("v6 digest: got %s (%v) want %s", got, err, tc.CommitmentDigest)
			}
			if sel, err := SelectCommitmentVersion([]byte(tc.Ext)); err != nil || sel != CommitmentV6 {
				t.Fatalf("ext selects %v (%v), want v6", sel, err)
			}
			// Trailers alone, and trailers with the agreeing doc carried beside them, both verify.
			if !VerifyTCT(v.IssuerAID, tc.SignedArtifact, c, now) {
				t.Fatal("the signed v6 TCT must verify (trailers only)")
			}
			withDoc := c
			withDoc.GoverningDocSha256 = doc
			if !VerifyTCT(v.IssuerAID, tc.SignedArtifact, withDoc, now) {
				t.Fatal("the signed v6 TCT must verify (trailers + agreeing doc)")
			}
			// Tamper: an env flipped in the trailer, the trailers dropped, a disagreeing doc beside them.
			if len(c.Trailers) > 0 {
				noTrailers := c
				noTrailers.Trailers = []byte{}
				if VerifyTCT(v.IssuerAID, tc.SignedArtifact, noTrailers, now) {
					t.Fatal("dropping the trailers must not verify")
				}
				wrongDoc := c
				wrongDoc.GoverningDocSha256 = make([]byte, 32)
				if VerifyTCT(v.IssuerAID, tc.SignedArtifact, wrongDoc, now) {
					t.Fatal("a doc disagreeing with the trailer must not verify")
				}
			}
			// #420: nil Trailers is a served commitment; its projection (GateBody, GoverningDocSha256, Env)
			// rebuilds the trailer run byte for byte, and verifies. Without the projection only the
			// ungoverned case verifies.
			served := c
			served.Trailers = nil
			if len(c.Trailers) > 0 && c.Trailers[0] == gateTrailerMarker {
				n := binary.LittleEndian.Uint32(c.Trailers[1:5])
				served.GateBody = c.Trailers[5 : 5+n]
			}
			served.GoverningDocSha256, served.Env = tr.GoverningDocSha256, tr.Env
			rebuilt, err := ServedCommitmentTrailers(served.GateBody, served.GoverningDocSha256, served.Env)
			if err != nil || !bytes.Equal(rebuilt, c.Trailers) {
				t.Fatalf("served projection rebuilds %x (%v), want %x", rebuilt, err, c.Trailers)
			}
			if !VerifyTCT(v.IssuerAID, tc.SignedArtifact, served, now) {
				t.Fatal("a served commitment must verify (#420)")
			}
			bare := served
			bare.GateBody, bare.GoverningDocSha256, bare.Env = nil, nil, nil
			if got := VerifyTCT(v.IssuerAID, tc.SignedArtifact, bare, now); got != (len(c.Trailers) == 0) {
				t.Fatalf("nil trailers with no projection: verified=%v", got)
			}
			if served.GoverningDocSha256 != nil {
				flipped := "live"
				if served.Env != nil && *served.Env == "live" {
					flipped = "sandbox"
				}
				wrongEnv := served
				wrongEnv.Env = &flipped
				if VerifyTCT(v.IssuerAID, tc.SignedArtifact, wrongEnv, now) {
					t.Fatal("a served env that disagrees with the signed digest must not verify")
				}
				if served.GateBody != nil {
					noGate := served
					noGate.GateBody = nil
					gd := GateDigest(served.GateBody)
					noGate.CertificateDigest = gd[:]
					if VerifyTCT(v.IssuerAID, tc.SignedArtifact, noGate, now) {
						t.Fatal("a Gate digest beside, without the body, must not verify")
					}
				}
			}
			both := c
			both.Env = served.Env
			both.GateBody = []byte{}
			if VerifyTCT(v.IssuerAID, tc.SignedArtifact, both, now) {
				t.Fatal("a served projection beside raw trailers must be refused")
			}
			if VerifyTCT(v.IssuerAID, tc.SignedArtifact, c, 4920825600) {
				t.Fatal("an expired TCT must not verify")
			}
			commitments[tc.Name] = c
		})
	}
	for _, n := range v.Negatives {
		t.Run("negative/"+n.Name, func(t *testing.T) {
			if n.Expect != "refused" {
				t.Fatalf("unknown expect %q", n.Expect)
			}
			c, ok := commitments[n.Over]
			if !ok {
				t.Fatalf("no signed case %q", n.Over)
			}
			if VerifyTCT(v.IssuerAID, n.SignedArtifact, c, now) {
				t.Fatalf("%s must be refused", n.Name)
			}
		})
	}
}

type gateVector struct {
	GateDigestDomain string `json:"gate_digest_domain"`
	Cases            []struct {
		Name                     string         `json:"name"`
		Block                    map[string]any `json:"block"`
		GateBody                 string         `json:"gate_body"`
		Trailer                  string         `json:"trailer"`
		GateDigestPreimagePrefix string         `json:"gate_digest_preimage_prefix"`
		GateDigest               string         `json:"gate_digest"`
		Field10                  string         `json:"field_10"`
	} `json:"cases"`
	PresenceStates []struct {
		Name    string  `json:"name"`
		Case    string  `json:"case"`
		Trailer *string `json:"trailer"`
		Field10 string  `json:"field_10"`
	} `json:"presence_states"`
	BodyRefusals []struct {
		Name     string `json:"name"`
		GateBody string `json:"gate_body"`
		Expect   string `json:"expect"`
	} `json:"body_refusals"`
	Sequences []v6Refusal `json:"sequences"`
	// outage_classification and writer_refusals: writer-side, not ported (see the file comment).
}

func loadGate(t *testing.T) gateVector {
	t.Helper()
	var g gateVector
	readConformance(t, "gate_block_vector.json", &g)
	if g.GateDigestDomain != GateDigestDomain || len(g.Cases) == 0 || len(g.PresenceStates) == 0 ||
		len(g.BodyRefusals) == 0 || len(g.Sequences) == 0 {
		t.Fatal("gate vector drifted or a section is empty")
	}
	return g
}

func gateBlockJSON(b GateBlock) map[string]any {
	m := map[string]any{
		"status": b.Status, "attempt_id": b.AttemptID, "domain": b.Domain, "flow_id": b.FlowID, "env": b.Env,
		"timeout_ms": strconv.FormatUint(b.TimeoutMs, 10), "on_outage": b.OnOutage,
		"requested_at_ms": strconv.FormatUint(b.RequestedAtMs, 10),
	}
	if b.Status == "answered" {
		m["receipt_jcs"], m["key_id"], m["signature"] = b.ReceiptJCS, b.KeyID, hex.EncodeToString(b.Signature)
		if b.CertificateJCS == nil {
			m["certificate_jcs"] = nil
		} else {
			m["certificate_jcs"] = *b.CertificateJCS
		}
	} else {
		m["reason"], m["given_up_at_ms"] = b.Reason, strconv.FormatUint(b.GivenUpAtMs, 10)
	}
	return m
}

func TestGateBlockCases(t *testing.T) {
	g := loadGate(t)
	for _, tc := range g.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			body := mustHex(t, tc.GateBody)
			blk, err := DecodeGateBody(body)
			if err != nil {
				t.Fatal(err)
			}
			if got := gateBlockJSON(blk); !reflect.DeepEqual(got, tc.Block) {
				t.Fatalf("decoded block:\n got %v\nwant %v", got, tc.Block)
			}
			trailer := binary.LittleEndian.AppendUint32([]byte{0x05}, uint32(len(body)))
			if hex.EncodeToString(append(trailer, body...)) != tc.Trailer {
				t.Fatal("trailer framing differs")
			}
			if hex.EncodeToString(be64Frame(nil, []byte(GateDigestDomain))) != tc.GateDigestPreimagePrefix {
				t.Fatal("preimage prefix differs")
			}
			d := GateDigest(body)
			if hex.EncodeToString(d[:]) != tc.GateDigest {
				t.Fatalf("gate digest: got %x want %s", d, tc.GateDigest)
			}
			if hex.EncodeToString(slotEncoding(d[:])) != tc.Field10 {
				t.Fatal("field_10 differs")
			}
		})
	}
}

func TestGateBlockPresenceStates(t *testing.T) {
	g := loadGate(t)
	for _, ps := range g.PresenceStates {
		t.Run(ps.Name, func(t *testing.T) {
			if ps.Trailer == nil {
				tr, err := DecodeCommitmentTrailers(nil, SchemeV6)
				if err != nil || hex.EncodeToString(tr.Field10) != ps.Field10 {
					t.Fatalf("absent: field_10 %x (%v), want %s", tr.Field10, err, ps.Field10)
				}
				return
			}
			// A lone 0x05 has no 0x06 env to bind to, so it is read here as a single trailer.
			raw := mustHex(t, *ps.Trailer)
			if raw[0] != 0x05 {
				t.Fatalf("marker %#x", raw[0])
			}
			body, end, err := readTrailer(raw, 0, "gate_trailer_truncated")
			if err != nil || end != len(raw) {
				t.Fatalf("trailer framing: %v", err)
			}
			if _, err := DecodeGateBody(body); err != nil {
				t.Fatal(err)
			}
			d := GateDigest(body)
			if hex.EncodeToString(slotEncoding(d[:])) != ps.Field10 {
				t.Fatalf("field_10 differs for %s", ps.Name)
			}
			if gateDigestOfCase(t, ps.Case) != hex.EncodeToString(d[:]) {
				t.Fatalf("not gate case %s", ps.Case)
			}
		})
	}
}

func TestGateBlockBodyRefusals(t *testing.T) {
	g := loadGate(t)
	for _, r := range g.BodyRefusals {
		t.Run(r.Name, func(t *testing.T) {
			if r.Expect != "refused" {
				t.Fatalf("unknown expect %q", r.Expect)
			}
			_, err := DecodeGateBody(mustHex(t, r.GateBody))
			assertRefused(t, err)
		})
	}
}

func TestGateBlockSequences(t *testing.T) {
	g := loadGate(t)
	for _, r := range g.Sequences {
		t.Run(r.Name, func(t *testing.T) {
			got, err := DecodeCommitmentTrailers(mustHex(t, *r.Trailers), schemeOf(t, r.Scheme))
			var refused string
			if json.Unmarshal(r.Expect, &refused) == nil {
				if refused != "refused" {
					t.Fatalf("unknown expect %q", refused)
				}
				assertRefused(t, err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var want map[string]string
			if err := json.Unmarshal(r.Expect, &want); err != nil {
				t.Fatal(err)
			}
			gotm := map[string]string{
				"field_10": hex.EncodeToString(got.Field10), "field_11": hex.EncodeToString(got.Field11),
				"field_12": hex.EncodeToString(got.Field12),
			}
			if !reflect.DeepEqual(gotm, want) {
				t.Fatalf("fields:\n got %v\nwant %v", gotm, want)
			}
		})
	}
}
