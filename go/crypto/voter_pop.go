package crypto

// The voter proof-of-possession `seam-voter-pop-v1` (seam-runtime #1687,
// docs/specs/voter-verification.v1.md, seam-sdk#359): a vote, ballot or objection signed by the voter's
// OWN enrolled `voter` key. Runtime 0.87.0+ refuses one without it (`voter_proof_required`).
//
// Byte-exact against conformance/voter_pop_v1_payload_vector.json. The twins are Python's
// `seam_sdk.crypto` voter section and TypeScript's `signVoterPop` & co.
//
// This module has no transport. A caller sends the vote through its own generated stubs and sets the
// proof there: `VoterProof{Pop: &VoterPop{VoterAid, IssuedAtMs, ExpiresAtMs, Signature}}` on
// `VoteRequest.proof`, `BallotRequest.proof`, `ObjectionRequest.proof` or a one-shot `Vote.proof`, field
// for field from VoterPopProof. The REST body takes VoterPopProof.ToREST().

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"time"
)

// Domain tags. Bump them only in lockstep with the runtime.
const (
	VoterPopV1Domain    = "seam-voter-pop-v1"
	VoteContentV1Domain = "seam-vote-content-v1"
)

// The window the runtime enforces: `expires - issued <= 15 min`, `issued <= now + 60 s`, `now <= expires`.
// A freshly signed proof defaults to a 5-minute lifetime.
const (
	VoterPopMaxLifetimeMs     uint64 = 15 * 60 * 1000
	VoterPopMaxSkewMs         uint64 = 60 * 1000
	VoterPopDefaultLifetimeMs uint64 = 5 * 60 * 1000
)

// VoterVerifiedKinds are the explanation kinds a voter must sign. Every one of them carries a sealed voter
// record, and an evaluation never does.
var VoterVerifiedKinds = []string{"vote", "ballot", "objection"}

// VoterPopTarget is where a vote is cast: the runtime (Issuer AID and Audience; "" means "seam-runtime")
// and the session's Tenant/Namespace and open identity (SessionID, OpenedAtMillis =
// `SessionStep.opened_at_millis` from the open; 0 on the one-shot `RunDecision` path).
type VoterPopTarget struct {
	Issuer         string
	Tenant         string
	Namespace      string
	SessionID      string
	OpenedAtMillis uint64
	Audience       string // "" is the default "seam-runtime"
}

func (t VoterPopTarget) audience() string {
	if t.Audience == "" {
		return "seam-runtime"
	}
	return t.Audience
}

// VoterPopProof is a signed voter proof: the parts of `VoterProof.pop` (`VoterPop`). Signature is the raw
// 64 bytes, as the gRPC `bytes` field carries it.
type VoterPopProof struct {
	VoterAID    string
	IssuedAtMs  uint64
	ExpiresAtMs uint64
	Signature   []byte
}

// VoterPopREST is the REST `proof.pop` object, with the signature as unpadded base64url.
type VoterPopREST struct {
	VoterAID    string `json:"voter_aid"`
	IssuedAtMs  uint64 `json:"issued_at_ms"`
	ExpiresAtMs uint64 `json:"expires_at_ms"`
	Signature   string `json:"signature"`
}

// VoterProofREST is the REST body's `proof` object: `{"pop": {...}}`. It marshals with encoding/json to
// exactly the shape Python's `VoterPop.to_rest()` and TypeScript's `voterPopToRest` produce.
type VoterProofREST struct {
	Pop VoterPopREST `json:"pop"`
}

// ToREST is the REST body's `proof` object. The window is a JSON number, so a value past 2^53 is refused
// rather than rounded by a JSON reader.
func (p VoterPopProof) ToREST() (VoterProofREST, error) {
	const maxSafe = 1<<53 - 1
	if p.IssuedAtMs > maxSafe || p.ExpiresAtMs > maxSafe {
		return VoterProofREST{}, fmt.Errorf("voter proof window exceeds 2^53 and cannot be carried as a JSON number")
	}
	return VoterProofREST{Pop: VoterPopREST{
		VoterAID:    p.VoterAID,
		IssuedAtMs:  p.IssuedAtMs,
		ExpiresAtMs: p.ExpiresAtMs,
		Signature:   b64urlNoPad(p.Signature),
	}}, nil
}

// VoteEntry is the entry the runtime will seal, as the voter signs it. Kind is "vote", "ballot" or
// "objection"; ProposalID is the ballot's request id for a ballot; Value is the vote value, ballot choice
// or objection severity ("" when omitted). A nil Confidence / RationaleRef is ABSENT, which is a different
// preimage from a stated 0.0 / "".
type VoteEntry struct {
	Kind         string
	Participant  string
	ProposalID   string
	Value        string
	Reason       string
	Confidence   *float64
	RationaleRef *string
}

// VoteContext is one sealed context binding the content digest frames. ContentHash is "" when the
// binding carries none.
type VoteContext struct {
	CtxRef      string
	ContentHash string
}

// VotePolicyRef is the session's `SessionStep.vote_policy` from open: the policy version and its 32-byte
// rules digest.
type VotePolicyRef struct {
	PolicyVersion string
	RulesDigest   []byte
}

// VoteContent is what a vote is about, the input of VoteContentDigest. Content is the accepted proposal's
// option (vote, objection), the approval request's action (ballot), or votes[0].value (one-shot).
// Participants and OnBehalfOf are as opened, in request order; Context is the sealed provenance in sealed
// order. Features is the one-shot `RunDecisionRequest.features` as (key, value) pairs in any order: they
// are framed sorted by key bytes, and a repeated key is refused, never deduplicated. A session vote has
// none. Policy is the session's bound vote policy; nil frames 0x00 (the one-shot, server-resolved).
type VoteContent struct {
	Mode         string
	ProposalID   string
	Content      string
	Participants []string
	OnBehalfOf   []string
	Context      []VoteContext
	Features     [][2]string
	Policy       *VotePolicyRef
}

// frameLE appends framed(x) = u32le(len(x)) ‖ x.
func frameLE(out, x []byte) []byte {
	out = binary.LittleEndian.AppendUint32(out, uint32(len(x)))
	return append(out, x...)
}

func countFrameLE(out []byte, n int) []byte {
	return frameLE(out, binary.LittleEndian.AppendUint32(nil, uint32(n)))
}

// VoteContentDigest is `seam-vote-content-v1` (32 raw bytes):
//
//	SHA-256( framed(domain) ‖ framed(mode) ‖ framed(proposal_id) ‖ framed(content) ‖
//	         framed(u32le(n)) ‖ framed(participant_i)… ‖ framed(u32le(m)) ‖ framed(on_behalf_of_i)… ‖
//	         framed(u32le(k)) ‖ (framed(ctx_ref_i) ‖ framed(content_hash_i))… ‖
//	         framed(u32le(f)) ‖ (framed(key_j) ‖ framed(value_j))… ‖ POLICY )
//	POLICY = 0x00 | 0x01 ‖ framed(policy_version) ‖ framed(rules_digest[32])
//
// It refuses a repeated feature key and a rules digest that is not 32 bytes.
func VoteContentDigest(c VoteContent) ([32]byte, error) {
	var out []byte
	out = frameLE(out, []byte(VoteContentV1Domain))
	out = frameLE(out, []byte(c.Mode))
	out = frameLE(out, []byte(c.ProposalID))
	out = frameLE(out, []byte(c.Content))
	out = countFrameLE(out, len(c.Participants))
	for _, p := range c.Participants {
		out = frameLE(out, []byte(p))
	}
	out = countFrameLE(out, len(c.OnBehalfOf))
	for _, o := range c.OnBehalfOf {
		out = frameLE(out, []byte(o))
	}
	out = countFrameLE(out, len(c.Context))
	for _, x := range c.Context {
		out = frameLE(out, []byte(x.CtxRef))
		out = frameLE(out, []byte(x.ContentHash))
	}
	// Go's string `<` is bytewise over the UTF-8, which is the contract's order. Sort a copy: the
	// caller's slice is theirs.
	feats := append([][2]string(nil), c.Features...)
	sort.SliceStable(feats, func(i, j int) bool { return feats[i][0] < feats[j][0] })
	for i := 1; i < len(feats); i++ {
		if feats[i][0] == feats[i-1][0] {
			return [32]byte{}, fmt.Errorf("feature key %q is given twice (refused, never deduplicated)", feats[i][0])
		}
	}
	out = countFrameLE(out, len(feats))
	for _, kv := range feats {
		out = frameLE(out, []byte(kv[0]))
		out = frameLE(out, []byte(kv[1]))
	}
	if c.Policy == nil {
		out = append(out, 0x00)
	} else {
		if len(c.Policy.RulesDigest) != 32 {
			return [32]byte{}, fmt.Errorf("rules digest must be 32 bytes, got %d", len(c.Policy.RulesDigest))
		}
		out = append(out, 0x01)
		out = frameLE(out, []byte(c.Policy.PolicyVersion))
		out = frameLE(out, c.Policy.RulesDigest)
	}
	return sha256.Sum256(out), nil
}

// VoteEntryBytes is the frozen `entry_bytes` a voter signs (F(x) = be64(len(x)) ‖ x):
//
//	F(kind) ‖ F(participant) ‖ F(proposal_id) ‖ F(value) ‖ F(reason) ‖ CONF ‖ REF
//	CONF = 0x00 | 0x01 ‖ be64(binary64 bits)      REF = 0x00 | 0x01 ‖ F(rationale_ref)
//
// A stated -0.0 confidence folds to +0.0. It refuses an unknown kind and a non-finite confidence.
// Frozen: an explanation-digest bump never changes it.
func VoteEntryBytes(e VoteEntry) ([]byte, error) {
	known := false
	for _, k := range ExplanationKinds {
		if e.Kind == k {
			known = true
			break
		}
	}
	if !known {
		return nil, fmt.Errorf("unknown explanation kind %q", e.Kind)
	}
	var out []byte
	out = be64Frame(out, []byte(e.Kind))
	out = be64Frame(out, []byte(e.Participant))
	out = be64Frame(out, []byte(e.ProposalID))
	out = be64Frame(out, []byte(e.Value))
	out = be64Frame(out, []byte(e.Reason))
	if e.Confidence == nil {
		out = append(out, 0x00)
	} else {
		c := *e.Confidence
		if math.IsNaN(c) || math.IsInf(c, 0) {
			return nil, fmt.Errorf("non-finite confidence %v", c)
		}
		if c == 0 {
			c = 0 // folds -0.0 to +0.0
		}
		out = append(out, 0x01)
		out = binary.BigEndian.AppendUint64(out, math.Float64bits(c))
	}
	if e.RationaleRef == nil {
		out = append(out, 0x00)
	} else {
		out = append(out, 0x01)
		out = be64Frame(out, []byte(*e.RationaleRef))
	}
	return out, nil
}

// VoterPopPayload is the exact byte string a voter proof signs (framed(x) = u32le(len(x)) ‖ x):
//
//	framed(domain) ‖ framed(issuer) ‖ framed(audience) ‖ framed(tenant) ‖ framed(namespace) ‖
//	framed(session_id) ‖ framed(u64le(opened_at_millis)) ‖ framed(voter_aid) ‖ framed(content_digest) ‖
//	framed(u64le(issued_at_ms)) ‖ framed(u64le(expires_at_ms)) ‖ framed(entry_bytes)
//
// It refuses a content digest that is not 32 bytes.
func VoterPopPayload(t VoterPopTarget, voterAID string, contentDigest []byte, issuedAtMs, expiresAtMs uint64, entryBytes []byte) ([]byte, error) {
	return voterPopPayload(t, t.audience(), voterAID, contentDigest, issuedAtMs, expiresAtMs, entryBytes)
}

// voterPopPayload frames audience as given: a sealed record's audience is re-checked as recorded, never
// defaulted.
func voterPopPayload(t VoterPopTarget, audience, voterAID string, contentDigest []byte, issuedAtMs, expiresAtMs uint64, entryBytes []byte) ([]byte, error) {
	if len(contentDigest) != 32 {
		return nil, fmt.Errorf("content digest must be 32 bytes, got %d", len(contentDigest))
	}
	var out []byte
	out = frameLE(out, []byte(VoterPopV1Domain))
	out = frameLE(out, []byte(t.Issuer))
	out = frameLE(out, []byte(audience))
	out = frameLE(out, []byte(t.Tenant))
	out = frameLE(out, []byte(t.Namespace))
	out = frameLE(out, []byte(t.SessionID))
	out = frameLE(out, binary.LittleEndian.AppendUint64(nil, t.OpenedAtMillis))
	out = frameLE(out, []byte(voterAID))
	out = frameLE(out, contentDigest)
	out = frameLE(out, binary.LittleEndian.AppendUint64(nil, issuedAtMs))
	out = frameLE(out, binary.LittleEndian.AppendUint64(nil, expiresAtMs))
	out = frameLE(out, entryBytes)
	return out, nil
}

// SignVoterPopAt signs a `seam-voter-pop-v1` proof with the voter's OWN enrolled `voter` key (32-byte
// Ed25519 seed) over an explicit window. The voter AID is DERIVED from the seed. A window the runtime must
// refuse (issued > expires, or longer than 15 minutes) is never signed. Prefer SignVoterPop, which signs
// now for five minutes.
func SignVoterPopAt(voterSeed []byte, t VoterPopTarget, contentDigest []byte, entry VoteEntry, issuedAtMs, expiresAtMs uint64) (VoterPopProof, error) {
	eb, err := VoteEntryBytes(entry)
	if err != nil {
		return VoterPopProof{}, err
	}
	return SignVoterPopEntryBytes(voterSeed, t, contentDigest, eb, issuedAtMs, expiresAtMs)
}

// SignVoterPop is SignVoterPopAt over [now, now + 5 min].
func SignVoterPop(voterSeed []byte, t VoterPopTarget, contentDigest []byte, entry VoteEntry) (VoterPopProof, error) {
	now := uint64(time.Now().UnixMilli())
	return SignVoterPopAt(voterSeed, t, contentDigest, entry, now, now+VoterPopDefaultLifetimeMs)
}

// SignVoterPopEntryBytes is SignVoterPopAt over entry bytes already framed by VoteEntryBytes.
func SignVoterPopEntryBytes(voterSeed []byte, t VoterPopTarget, contentDigest, entryBytes []byte, issuedAtMs, expiresAtMs uint64) (VoterPopProof, error) {
	if len(voterSeed) != ed25519.SeedSize {
		return VoterPopProof{}, fmt.Errorf("voter seed must be %d bytes", ed25519.SeedSize)
	}
	if issuedAtMs > expiresAtMs || expiresAtMs-issuedAtMs > VoterPopMaxLifetimeMs {
		return VoterPopProof{}, fmt.Errorf("voter proof window must satisfy issuedAtMs <= expiresAtMs <= issuedAtMs + 15 min")
	}
	key := ed25519.NewKeyFromSeed(voterSeed)
	aid := AIDFromPubkey(key.Public().(ed25519.PublicKey))
	payload, err := VoterPopPayload(t, aid, contentDigest, issuedAtMs, expiresAtMs, entryBytes)
	if err != nil {
		return VoterPopProof{}, err
	}
	return VoterPopProof{VoterAID: aid, IssuedAtMs: issuedAtMs, ExpiresAtMs: expiresAtMs, Signature: ed25519.Sign(key, payload)}, nil
}

// VerifyVoterPop reports whether signature is voterAID's Ed25519 signature over VoterPopPayload. The
// binding only: the window is the runtime's (and a re-verifier's) to check. Any malformed input is false.
func VerifyVoterPop(t VoterPopTarget, voterAID string, contentDigest []byte, issuedAtMs, expiresAtMs uint64, entry VoteEntry, signature []byte) bool {
	eb, err := VoteEntryBytes(entry)
	if err != nil {
		return false
	}
	return verifyVoterPopBytes(t, t.audience(), voterAID, contentDigest, issuedAtMs, expiresAtMs, eb, signature)
}

func verifyVoterPopBytes(t VoterPopTarget, audience, voterAID string, contentDigest []byte, issuedAtMs, expiresAtMs uint64, entryBytes, signature []byte) bool {
	pub, err := aidToPubkey(voterAID)
	if err != nil || len(pub) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	payload, err := voterPopPayload(t, audience, voterAID, contentDigest, issuedAtMs, expiresAtMs, entryBytes)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), payload, signature)
}

// VerifyVoterRecord re-checks one sealed entry's voter record offline, from the record alone: it rebuilds
// the signed input from the record's own addressing fields and the entry's frozen entry bytes, checks the
// window at AcceptedAtMs, and verifies the signature with the key Principal embeds. False for a missing
// record, a non-"pop" method, a signer certificate, or anything that does not verify. Twin of Python
// `verify_voter_record` and TypeScript `verifyVoterRecord`.
func VerifyVoterRecord(e ExplanationEntry) bool {
	vv := e.VoterVerification
	if vv == nil || vv.Method != VoterMethodPop || len(vv.SignerCertificate) != 0 {
		return false
	}
	issued, expires, accepted := vv.IssuedAtMs, vv.ExpiresAtMs, vv.AcceptedAtMs
	if !(issued <= expires && expires-issued <= VoterPopMaxLifetimeMs && accepted <= expires) {
		return false
	}
	// issued <= accepted + skew, without overflowing near 2^64.
	if accepted <= math.MaxUint64-VoterPopMaxSkewMs && issued > accepted+VoterPopMaxSkewMs {
		return false
	}
	eb, err := VoteEntryBytes(VoteEntry{
		Kind:         e.Kind,
		Participant:  e.Participant,
		ProposalID:   e.ProposalID,
		Value:        e.Value,
		Reason:       e.Reason,
		Confidence:   e.Confidence,
		RationaleRef: e.RationaleRef,
	})
	if err != nil {
		return false
	}
	t := VoterPopTarget{
		Issuer:         vv.Issuer,
		Tenant:         vv.Tenant,
		Namespace:      vv.Namespace,
		SessionID:      vv.SessionID,
		OpenedAtMillis: vv.OpenedAtMillis,
	}
	return verifyVoterPopBytes(t, vv.Audience, vv.Principal, vv.ContentDigest, issued, expires, eb, vv.Signature)
}

// VoterDecision names the decision a commitment's voter records must belong to.
type VoterDecision struct {
	Tenant    string
	SessionID string
}

// VerifyCommitmentVoters is the commitment-level voter check (voter-verification.v1.md §"The sealed
// record"). It is true iff every vote, ballot and objection carries a record and no evaluation does; every
// record's issuer is issuer (the one the verifier pinned); all records share one (tenant, namespace,
// session_id, opened_at_millis, audience); when decision is non-nil, that is the records' own; and each
// record re-checks (VerifyVoterRecord). An explanation with no voter-kind entries passes. The content
// digest is not re-derived: what it covers is not in the commitment. Twin of Python
// `verify_commitment_voters` and TypeScript `verifyCommitmentVoters`.
func VerifyCommitmentVoters(entries []ExplanationEntry, issuer string, decision *VoterDecision) bool {
	type addressing struct {
		tenant, namespace, sessionID string
		openedAt                     uint64
		audience                     string
	}
	var first *addressing
	for _, e := range entries {
		vv := e.VoterVerification
		voterKind := false
		for _, k := range VoterVerifiedKinds {
			if e.Kind == k {
				voterKind = true
				break
			}
		}
		if !voterKind {
			if vv != nil {
				return false
			}
			continue
		}
		if vv == nil || vv.Issuer != issuer {
			return false
		}
		a := addressing{vv.Tenant, vv.Namespace, vv.SessionID, vv.OpenedAtMillis, vv.Audience}
		if first == nil {
			first = &a
		} else if a != *first {
			return false
		}
		if decision != nil && (vv.Tenant != decision.Tenant || vv.SessionID != decision.SessionID) {
			return false
		}
		if !VerifyVoterRecord(e) {
			return false
		}
	}
	return true
}
