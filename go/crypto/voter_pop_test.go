package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// voterPopVector mirrors conformance/voter_pop_v1_payload_vector.json, the cross-language contract for the
// voter proof-of-possession (#1687, seam-sdk#359). NO bless mode: a mismatch is a contract break.
type voterPopVector struct {
	Domain        string         `json:"domain"`
	ContentDomain string         `json:"content_domain"`
	Cases         []voterPopCase `json:"cases"`
}

type voterPopCase struct {
	Name     string `json:"name"`
	SeedHex  string `json:"seed_hex"`
	VoterAID string `json:"voter_aid"`
	Target   struct {
		Issuer         string `json:"issuer"`
		Audience       string `json:"audience"`
		Tenant         string `json:"tenant"`
		Namespace      string `json:"namespace"`
		SessionID      string `json:"session_id"`
		OpenedAtMillis uint64 `json:"opened_at_millis"`
	} `json:"target"`
	Content struct {
		Mode         string   `json:"mode"`
		ProposalID   string   `json:"proposal_id"`
		Content      string   `json:"content"`
		Participants []string `json:"participants"`
		OnBehalfOf   []string `json:"on_behalf_of"`
		Context      []struct {
			CtxRef      string `json:"ctx_ref"`
			ContentHash string `json:"content_hash"`
		} `json:"context"`
		Features [][2]string `json:"features"`
		Policy   *struct {
			PolicyVersion  string `json:"policy_version"`
			RulesDigestHex string `json:"rules_digest_hex"`
		} `json:"policy"`
	} `json:"content"`
	ContentDigestHex string `json:"content_digest_hex"`
	Entry            struct {
		Kind         string   `json:"kind"`
		Participant  string   `json:"participant"`
		ProposalID   string   `json:"proposal_id"`
		Value        string   `json:"value"`
		Reason       string   `json:"reason"`
		Confidence   *float64 `json:"confidence"`
		RationaleRef *string  `json:"rationale_ref"`
	} `json:"entry"`
	EntryBytesHex string `json:"entry_bytes_hex"`
	IssuedAtMs    uint64 `json:"issued_at_ms"`
	ExpiresAtMs   uint64 `json:"expires_at_ms"`
	PayloadHex    string `json:"payload_hex"`
	SignatureHex  string `json:"signature_hex"`
}

func loadVoterPop(t *testing.T) voterPopVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "voter_pop_v1_payload_vector.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v voterPopVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("the vector has no cases")
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func (c voterPopCase) target() VoterPopTarget {
	return VoterPopTarget{
		Issuer: c.Target.Issuer, Tenant: c.Target.Tenant, Namespace: c.Target.Namespace,
		SessionID: c.Target.SessionID, OpenedAtMillis: c.Target.OpenedAtMillis, Audience: c.Target.Audience,
	}
}

func (c voterPopCase) content(t *testing.T) VoteContent {
	vc := VoteContent{
		Mode: c.Content.Mode, ProposalID: c.Content.ProposalID, Content: c.Content.Content,
		Participants: c.Content.Participants, OnBehalfOf: c.Content.OnBehalfOf, Features: c.Content.Features,
	}
	for _, x := range c.Content.Context {
		vc.Context = append(vc.Context, VoteContext{CtxRef: x.CtxRef, ContentHash: x.ContentHash})
	}
	if p := c.Content.Policy; p != nil {
		vc.Policy = &VotePolicyRef{PolicyVersion: p.PolicyVersion, RulesDigest: mustHex(t, p.RulesDigestHex)}
	}
	return vc
}

func (c voterPopCase) entry() VoteEntry {
	return VoteEntry{
		Kind: c.Entry.Kind, Participant: c.Entry.Participant, ProposalID: c.Entry.ProposalID,
		Value: c.Entry.Value, Reason: c.Entry.Reason, Confidence: c.Entry.Confidence, RationaleRef: c.Entry.RationaleRef,
	}
}

func TestVoterPopVectorDomains(t *testing.T) {
	v := loadVoterPop(t)
	if v.Domain != VoterPopV1Domain || v.ContentDomain != VoteContentV1Domain {
		t.Fatalf("domains: got %q/%q", v.Domain, v.ContentDomain)
	}
}

// Every byte matches the independent generator: content digest, entry bytes, payload, AID and signature.
// The signature equality is the cross-port gate: Python and TS assert the same bytes.
func TestVoterPopVectorEveryByte(t *testing.T) {
	for _, c := range loadVoterPop(t).Cases {
		t.Run(c.Name, func(t *testing.T) {
			cd, err := VoteContentDigest(c.content(t))
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(cd[:]); got != c.ContentDigestHex {
				t.Fatalf("content digest: got %s want %s", got, c.ContentDigestHex)
			}
			eb, err := VoteEntryBytes(c.entry())
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(eb); got != c.EntryBytesHex {
				t.Fatalf("entry bytes: got %s want %s", got, c.EntryBytesHex)
			}
			payload, err := VoterPopPayload(c.target(), c.VoterAID, cd[:], c.IssuedAtMs, c.ExpiresAtMs, eb)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(payload); got != c.PayloadHex {
				t.Fatalf("payload: got %s want %s", got, c.PayloadHex)
			}
			p, err := SignVoterPopAt(mustHex(t, c.SeedHex), c.target(), cd[:], c.entry(), c.IssuedAtMs, c.ExpiresAtMs)
			if err != nil {
				t.Fatal(err)
			}
			if p.VoterAID != c.VoterAID {
				t.Fatalf("voter aid: got %s want %s", p.VoterAID, c.VoterAID)
			}
			if got := hex.EncodeToString(p.Signature); got != c.SignatureHex {
				t.Fatalf("signature: got %s want %s", got, c.SignatureHex)
			}
			if !VerifyVoterPop(c.target(), c.VoterAID, cd[:], c.IssuedAtMs, c.ExpiresAtMs, c.entry(), mustHex(t, c.SignatureHex)) {
				t.Fatal("the vector signature must verify")
			}
		})
	}
}

func TestVoterPopOtherCasesDifferFromBasic(t *testing.T) {
	v := loadVoterPop(t)
	by := map[string]voterPopCase{}
	for _, c := range v.Cases {
		by[c.Name] = c
	}
	basic := by["basic"]
	n := 0
	for name, c := range by {
		if !strings.HasPrefix(name, "other-") {
			continue
		}
		n++
		if c.PayloadHex == basic.PayloadHex || c.SignatureHex == basic.SignatureHex {
			t.Fatalf("%s must differ from basic", name)
		}
	}
	if n == 0 {
		t.Fatal("no other-* cases")
	}
	if a, b := by["features-order-a"], by["features-order-b"]; a.SignatureHex != b.SignatureHex || a.ContentDigestHex != b.ContentDigestHex {
		t.Fatal("the same feature set in another caller order must sign identically")
	}
}

func TestVoterPopDoesNotVerifyForAnotherTarget(t *testing.T) {
	c := loadVoterPop(t).Cases[0]
	cd := mustHex(t, c.ContentDigestHex)
	sig := mustHex(t, c.SignatureHex)
	other := c.target()
	other.SessionID += "-x"
	if VerifyVoterPop(other, c.VoterAID, cd, c.IssuedAtMs, c.ExpiresAtMs, c.entry(), sig) {
		t.Fatal("a proof must not verify for another session")
	}
	e := c.entry()
	e.Value = "REJECT"
	if VerifyVoterPop(c.target(), c.VoterAID, cd, c.IssuedAtMs, c.ExpiresAtMs, e, sig) {
		t.Fatal("a proof must not verify for another value")
	}
	if VerifyVoterPop(c.target(), "not-an-aid", cd, c.IssuedAtMs, c.ExpiresAtMs, c.entry(), sig) {
		t.Fatal("a malformed AID is false, not a panic")
	}
	if VerifyVoterPop(c.target(), c.VoterAID, cd[:31], c.IssuedAtMs, c.ExpiresAtMs, c.entry(), sig) {
		t.Fatal("a short content digest is false")
	}
}

func TestVoteEntryBytesFoldsNegativeZeroAndRefuses(t *testing.T) {
	neg, pos := math.Copysign(0, -1), 0.0
	a, err := VoteEntryBytes(VoteEntry{Kind: "vote", Confidence: &neg})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := VoteEntryBytes(VoteEntry{Kind: "vote", Confidence: &pos})
	if !bytes.Equal(a, b) {
		t.Fatal("-0 confidence must fold to +0")
	}
	nan := math.NaN()
	inf := math.Inf(1)
	for name, e := range map[string]VoteEntry{
		"unknown kind":   {Kind: "VOTE"},
		"NaN confidence": {Kind: "vote", Confidence: &nan},
		"Inf confidence": {Kind: "vote", Confidence: &inf},
	} {
		if _, err := VoteEntryBytes(e); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
}

func TestSignVoterPopRefusesAWindowTheRuntimeRefuses(t *testing.T) {
	c := loadVoterPop(t).Cases[0]
	seed, cd := mustHex(t, c.SeedHex), mustHex(t, c.ContentDigestHex)
	for _, w := range [][2]uint64{{2000, 1000}, {0, VoterPopMaxLifetimeMs + 1}} {
		if _, err := SignVoterPopAt(seed, c.target(), cd, c.entry(), w[0], w[1]); err == nil {
			t.Fatalf("window %v must be refused", w)
		}
	}
	if _, err := SignVoterPopAt(seed, c.target(), cd, c.entry(), 0, VoterPopMaxLifetimeMs); err != nil {
		t.Fatalf("exactly 15 minutes is allowed: %v", err)
	}
	if _, err := SignVoterPopAt(seed[:31], c.target(), cd, c.entry(), 0, 1); err == nil {
		t.Fatal("a short seed must be refused")
	}
}

func TestSignVoterPopDefaultWindow(t *testing.T) {
	c := loadVoterPop(t).Cases[0]
	before := uint64(time.Now().UnixMilli())
	p, err := SignVoterPop(mustHex(t, c.SeedHex), c.target(), mustHex(t, c.ContentDigestHex), c.entry())
	if err != nil {
		t.Fatal(err)
	}
	after := uint64(time.Now().UnixMilli())
	if p.IssuedAtMs < before || p.IssuedAtMs > after || p.ExpiresAtMs-p.IssuedAtMs != VoterPopDefaultLifetimeMs {
		t.Fatalf("default window: [%d, %d]", p.IssuedAtMs, p.ExpiresAtMs)
	}
	if !VerifyVoterPop(c.target(), p.VoterAID, mustHex(t, c.ContentDigestHex), p.IssuedAtMs, p.ExpiresAtMs, c.entry(), p.Signature) {
		t.Fatal("a fresh proof must verify")
	}
}

func TestVoterPopREST(t *testing.T) {
	c := loadVoterPop(t).Cases[0]
	p := VoterPopProof{VoterAID: c.VoterAID, IssuedAtMs: c.IssuedAtMs, ExpiresAtMs: c.ExpiresAtMs, Signature: mustHex(t, c.SignatureHex)}
	r, err := p.ToREST()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	var back map[string]map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	pop := back["pop"]
	if pop["voter_aid"] != c.VoterAID || pop["issued_at_ms"] != float64(c.IssuedAtMs) || pop["expires_at_ms"] != float64(c.ExpiresAtMs) {
		t.Fatalf("REST form: %s", raw)
	}
	sig, _ := pop["signature"].(string)
	if strings.ContainsAny(sig, "=+/") || sig != b64urlNoPad(p.Signature) {
		t.Fatalf("signature must be unpadded base64url: %q", sig)
	}
	p.ExpiresAtMs = 1 << 53
	if _, err := p.ToREST(); err == nil {
		t.Fatal("a window past 2^53 must be refused")
	}
}

func TestVoteContentFeaturesAndPolicy(t *testing.T) {
	base := VoteContent{Mode: "m", ProposalID: "p", Content: "c"}
	dup := base
	dup.Features = [][2]string{{"a", "1"}, {"b", "2"}, {"a", "3"}}
	if _, err := VoteContentDigest(dup); err == nil {
		t.Fatal("a repeated feature key must be refused")
	}
	short := base
	short.Policy = &VotePolicyRef{PolicyVersion: "v", RulesDigest: make([]byte, 31)}
	if _, err := VoteContentDigest(short); err == nil {
		t.Fatal("a rules digest that is not 32 bytes must be refused")
	}
	in := [][2]string{{"z", "1"}, {"a", "2"}}
	ordered := base
	ordered.Features = in
	if _, err := VoteContentDigest(ordered); err != nil {
		t.Fatal(err)
	}
	if in[0][0] != "z" {
		t.Fatal("the caller's feature slice must not be reordered")
	}
}

// ── the sealed record re-check ──────────────────────────────────────────────────────────────────────

func tctVote(t *testing.T) (vectors, int) {
	v := load(t)
	for i, e := range v.TCT.Inputs.Commitment.Explanation {
		if e.Kind == "vote" {
			return v, i
		}
	}
	t.Fatal("the conformance TCT has no vote")
	return v, -1
}

func TestConformanceVoteRecordReverifies(t *testing.T) {
	v, i := tctVote(t)
	entries := v.TCT.Inputs.Commitment.Explanation
	vote := entries[i]
	if vote.VoterVerification == nil {
		t.Fatal("the conformance vote carries no record")
	}
	if !VerifyVoterRecord(vote) {
		t.Fatal("the sealed record must re-verify")
	}
	if !VerifyCommitmentVoters(entries, v.TCT.IssuerAID, nil) {
		t.Fatal("the commitment voter check must pass")
	}
	d := &VoterDecision{Tenant: vote.VoterVerification.Tenant, SessionID: vote.VoterVerification.SessionID}
	if !VerifyCommitmentVoters(entries, v.TCT.IssuerAID, d) {
		t.Fatal("the commitment voter check must pass for its own decision")
	}
}

func TestCommitmentVotersFailClosed(t *testing.T) {
	v, i := tctVote(t)
	entries := v.TCT.Inputs.Commitment.Explanation
	iss := v.TCT.IssuerAID
	vv := *entries[i].VoterVerification
	swap := func(f func(e *ExplanationEntry)) []ExplanationEntry {
		out := cloneEntries(entries)
		f(&out[i])
		return out
	}
	withVV := func(f func(r *VoterVerification)) []ExplanationEntry {
		return swap(func(e *ExplanationEntry) { r := vv; f(&r); e.VoterVerification = &r })
	}
	cases := []struct {
		name     string
		entries  []ExplanationEntry
		issuer   string
		decision *VoterDecision
	}{
		{"another pinned issuer", entries, "aid:pubkey:ed25519:" + strings.Repeat("A", 43), nil},
		{"another decision's session", entries, iss, &VoterDecision{Tenant: vv.Tenant, SessionID: "s-other"}},
		{"a vote without its record", swap(func(e *ExplanationEntry) { e.VoterVerification = nil }), iss, nil},
		{"a tampered reason", swap(func(e *ExplanationEntry) { e.Reason += "!" }), iss, nil},
		{"an evaluation with a record", func() []ExplanationEntry {
			out := cloneEntries(entries)
			for j := range out {
				if out[j].Kind == "evaluation" {
					r := vv
					out[j].VoterVerification = &r
				}
			}
			return out
		}(), iss, nil},
		{"a record outside its window", withVV(func(r *VoterVerification) { r.AcceptedAtMs = r.ExpiresAtMs + 1 }), iss, nil},
		{"a non-pop method", withVV(func(r *VoterVerification) { r.Method = VoterMethodCpSigned }), iss, nil},
		{"a signer certificate on pop", withVV(func(r *VoterVerification) { r.SignerCertificate = []byte{1} }), iss, nil},
		{"another audience", withVV(func(r *VoterVerification) { r.Audience = "seam-runtime-partner" }), iss, nil},
	}
	hasEval := false
	for _, e := range entries {
		hasEval = hasEval || e.Kind == "evaluation"
	}
	for _, c := range cases {
		if c.name == "an evaluation with a record" && !hasEval {
			continue
		}
		if VerifyCommitmentVoters(c.entries, c.issuer, c.decision) {
			t.Fatalf("%s: must fail closed", c.name)
		}
	}
}
