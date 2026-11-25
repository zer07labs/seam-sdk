// Package crypto is the client-side crypto for the Seam Go SDK — pure Go stdlib (Ed25519 + SHA-256),
// no AITP binding. The admission proof-of-possession is Ed25519 over SHA-256 of a documented,
// domain-separated canonical byte layout (RFC-AITP-0002 §3); the seed never leaves the client. The
// cross-language conformance vectors in conformance/vectors.json (generated from the Rust reference) pin
// the exact bytes — this shim mirrors the Python/TypeScript reference byte-for-byte.
package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
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

// DerivedUUID is the runtime's derived-UUID rule (seam-runtime docs/specs/authorize.v1.md, P9):
//
//	h  = SHA-256(tag || 0x00 || input)
//	id = h[0..16] with h[6] = (h[6] & 0x0f) | 0x40 and h[8] = (h[8] & 0x3f) | 0x80
//
// returned in the lowercase hyphenated form the wire carries. One primitive serves every derived id —
// the PoP message_id and the commitment TCT jti. Pinned by conformance/vectors.json's derived_uuid
// block.
func DerivedUUID(tag string, input []byte) string {
	buf := make([]byte, 0, len(tag)+1+len(input))
	buf = append(buf, tag...)
	buf = append(buf, 0)
	buf = append(buf, input...)
	sum := sha256.Sum256(buf)
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// PopMessageIDTag is the domain tag of the PoP message_id derivation (P9).
const PopMessageIDTag = "seam-pop-mid-v1"

// PopMessageID is the admission message_id: DerivedUUID("seam-pop-mid-v1", pop_nonce_ascii). The input
// is the nonce's base64url text exactly as sent, not its decoded bytes.
func PopMessageID(popNonce string) string { return DerivedUUID(PopMessageIDTag, []byte(popNonce)) }

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
//
// Committer, and the Explanation entries and/or the published ExplanationDigest, are bound by
// `seam-commitment-digest:v5` (see seamCommitmentDigest). A nil Explanation means the entries are not
// held (only the published digest, if any, is used); a non-nil empty slice is the empty explanation.
// A nil Supersedes is ABSENT, which v5 frames differently from a present empty string. A nil
// SelectionDigest / CertificateDigest (fields 9 and 10) is ABSENT — every record runtime 0.88.0 seals;
// present, each MUST be exactly 32 bytes. GoverningDocSha256 (field 11, #1711) is the SHA-256 of the
// tenant governing document the decision was sealed under (`Commitment.governing_doc_sha256` on the
// wire): nil for an ungoverned decision, else exactly 32 bytes.
type Commitment struct {
	ID                 string             `json:"id"`
	Action             string             `json:"action"`
	Authority          string             `json:"authority"`
	Supersedes         *string            `json:"supersedes"`
	AuthMethod         string             `json:"auth_method"`
	TrustBasis         string             `json:"trust_basis"`
	Committer          string             `json:"committer"`
	ExplanationDigest  []byte             `json:"explanation_digest,omitempty"`
	Explanation        []ExplanationEntry `json:"explanation,omitempty"`
	SelectionDigest    []byte             `json:"-"`
	CertificateDigest  []byte             `json:"-"`
	GoverningDocSha256 []byte             `json:"-"`
	// Selection is the sealed option-selection block (runtime 0.90.0, `Commitment.selection`): when set,
	// field 9 is SelectionDigest(SelectionBody(*Selection)). nil = "not a selection decision". Setting both
	// it and SelectionDigest is refused. When set, VerifyTCT also recomputes the winner from Explanation
	// (VerifySelection) and fails closed when Explanation is nil.
	Selection *SelectionBlock `json:"-"`
	// Trailers is the raw `0x05` (Gate block) / `0x06` (governing) trailer bytes the sealed commitment
	// appends (seam-commitment-digest.v6.md; "" when it has neither). nil = not held, and VerifyTCT then
	// behaves exactly as before. When set, VerifyTCT derives fields 10-12 from these bytes only, under the
	// scheme the TCT statement selects (DecodeCommitmentTrailers); a GoverningDocSha256 / CertificateDigest
	// set beside them must agree with them.
	Trailers []byte `json:"-"`
	// GateBody and Env are the served projection (#420): `seam.api.v1.Commitment` carries no raw trailers,
	// only `gate = 13` (GateRecord.body, the exact `0x05` body) beside GoverningDocSha256 and `env = 14`.
	// With nil Trailers, VerifyTCT under v6 rebuilds the trailer run from GateBody, GoverningDocSha256 and
	// Env (ServedCommitmentTrailers) and decodes it under every v6 rule, so field 10 is still its own Gate
	// digest over the body. v5 refuses either. nil = absent. Setting either beside Trailers is refused.
	GateBody []byte  `json:"-"`
	Env      *string `json:"-"`
}

// ExplanationEntry is one sealed explanation entry, in the order the runtime accepted it. Kind is the
// lowercase word (see ExplanationKinds), never the proto enum name. A nil Confidence / RationaleRef is
// ABSENT, which is a different preimage from a stated 0.0 / "".
type ExplanationEntry struct {
	Kind         string   `json:"kind"`
	Participant  string   `json:"participant"`
	ProposalID   string   `json:"proposal_id"`
	Value        string   `json:"value"`
	Reason       string   `json:"reason"`
	Confidence   *float64 `json:"confidence"`
	RationaleRef *string  `json:"rationale_ref"`
	// VoterVerification is the sealed voter proof record (seam-runtime #1687): present on every vote,
	// ballot and objection runtime 0.87.0+ seals, absent (nil) on evaluations.
	VoterVerification *VoterVerification `json:"voter_verification"`
}

// VoterVerification is a sealed `VoterVerificationRecord` (seam-runtime docs/specs/voter-verification.v1.md),
// field for field. Method is the lowercase word VoterMethodPop or VoterMethodCpSigned — never the proto
// enum name; VoterMethodFromProto maps the enum. ContentDigest is the 32 raw bytes of
// `seam-vote-content-v1`; SignerCertificate is empty for `pop`.
type VoterVerification struct {
	Method            string
	Principal         string
	ContentDigest     []byte
	IssuedAtMs        uint64
	ExpiresAtMs       uint64
	Signature         []byte
	SignerCertificate []byte
	Tenant            string
	Namespace         string
	SessionID         string
	OpenedAtMillis    uint64
	Issuer            string
	Audience          string
	AcceptedAtMs      uint64
}

// The closed voter-verification method words the explanation digest frames.
const (
	VoterMethodPop      = "pop"
	VoterMethodCpSigned = "cp_signed"
)

// VoterMethodFromProto maps the `seam.api.v1.VoterVerification` enum number to its digest word:
// 1 (POP) → "pop", 2 (CP_SIGNED) → "cp_signed". UNSPECIFIED (0) and any unknown value are refused —
// the runtime never seals one.
func VoterMethodFromProto(n int32) (string, error) {
	switch n {
	case 1:
		return VoterMethodPop, nil
	case 2:
		return VoterMethodCpSigned, nil
	}
	return "", fmt.Errorf("voter verification method %d is not sealable", n)
}

// UnmarshalJSON reads a voter record in either vector projection: the seam-client conformance form
// (`content_digest_hex`, `signature_hex`, `signer_certificate_hex`) or the REST form (byte fields as
// JSON number arrays).
func (v *VoterVerification) UnmarshalJSON(raw []byte) error {
	var w struct {
		Method               string  `json:"method"`
		Principal            string  `json:"principal"`
		ContentDigest        []int   `json:"content_digest"`
		ContentDigestHex     *string `json:"content_digest_hex"`
		IssuedAtMs           uint64  `json:"issued_at_ms"`
		ExpiresAtMs          uint64  `json:"expires_at_ms"`
		Signature            []int   `json:"signature"`
		SignatureHex         *string `json:"signature_hex"`
		SignerCertificate    []int   `json:"signer_certificate"`
		SignerCertificateHex *string `json:"signer_certificate_hex"`
		Tenant               string  `json:"tenant"`
		Namespace            string  `json:"namespace"`
		SessionID            string  `json:"session_id"`
		OpenedAtMillis       uint64  `json:"opened_at_millis"`
		Issuer               string  `json:"issuer"`
		Audience             string  `json:"audience"`
		AcceptedAtMs         uint64  `json:"accepted_at_ms"`
	}
	if err := json.Unmarshal(raw, &w); err != nil {
		return err
	}
	pick := func(name string, ints []int, hx *string) ([]byte, error) {
		if hx != nil {
			return hex.DecodeString(*hx)
		}
		out := make([]byte, len(ints))
		for i, b := range ints {
			if b < 0 || b > 255 {
				return nil, fmt.Errorf("%s: byte out of range: %d", name, b)
			}
			out[i] = byte(b)
		}
		return out, nil
	}
	cd, err := pick("content_digest", w.ContentDigest, w.ContentDigestHex)
	if err != nil {
		return err
	}
	sig, err := pick("signature", w.Signature, w.SignatureHex)
	if err != nil {
		return err
	}
	cert, err := pick("signer_certificate", w.SignerCertificate, w.SignerCertificateHex)
	if err != nil {
		return err
	}
	*v = VoterVerification{
		Method: w.Method, Principal: w.Principal, ContentDigest: cd, IssuedAtMs: w.IssuedAtMs,
		ExpiresAtMs: w.ExpiresAtMs, Signature: sig, SignerCertificate: cert, Tenant: w.Tenant,
		Namespace: w.Namespace, SessionID: w.SessionID, OpenedAtMillis: w.OpenedAtMillis,
		Issuer: w.Issuer, Audience: w.Audience, AcceptedAtMs: w.AcceptedAtMs,
	}
	return nil
}

// BuildPresentation builds the pinned-key admission presentation.
//
//	proof = base64url(Ed25519_sign( SHA256( domain || sender_aid \0 || receiver_aid \0 ||
//	        message_id \0 || timestamp_ascii_decimal \0 || b64url_decode(pop_nonce) ) ))
func BuildPresentation(agentSeed []byte, receiverAID, popNonce string, nowMs int64) (Presentation, error) {
	if len(agentSeed) != ed25519.SeedSize {
		return Presentation{}, fmt.Errorf("agent seed must be %d bytes", ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(agentSeed)
	pub := priv.Public().(ed25519.PublicKey)
	senderAID := AIDFromPubkey(pub)
	mid := PopMessageID(popNonce)
	timestamp := nowMs / 1000

	nonceBytes, err := b64urlDecode(popNonce)
	if err != nil {
		return Presentation{}, fmt.Errorf("pop_nonce is not base64url: %w", err)
	}
	// ASCII-decimal, matching message_id's text encoding (FormatInt: the signed i64, not FormatUint)
	ts := []byte(strconv.FormatInt(timestamp, 10))

	var in []byte
	in = append(in, proofDomain...)
	in = append(in, []byte(senderAID)...)
	in = append(in, 0)
	in = append(in, []byte(receiverAID)...)
	in = append(in, 0)
	in = append(in, []byte(mid)...)
	in = append(in, 0)
	in = append(in, ts...)
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

// ExplanationKinds are the `kind` words the explanation digest frames — lowercase ASCII, exactly.
// "proposal" (runtime 0.90.0, option selection) is one accepted option of a selection session; it never
// carries a voter record.
var ExplanationKinds = []string{"vote", "evaluation", "objection", "ballot", "proposal"}

// ExplanationDomain and CommitmentDigestDomain are the two domain tags of the commitment binding.
// Normative: seam-runtime docs/specs/seam-commitment-digest.v5.md.
const (
	ExplanationDomain      = "seam-explanation-digest:v2"
	CommitmentDigestDomain = "seam-commitment-digest:v5"
)

// The self-attestation TCT statement (RFC-AITP-0005) a Seam commitment is sealed as: the only grant,
// the ext namespace that carries the statement, and the statement's type.
const (
	AttestationGrant       = "aitp.attestation"
	CommitmentExtNamespace = "com.zer07labs.seam"
	CommitmentStatement    = "seam:commitment"
)

// be64Frame appends F(x) = be64(len(x)) ‖ x.
func be64Frame(out, x []byte) []byte {
	out = binary.BigEndian.AppendUint64(out, uint64(len(x)))
	return append(out, x...)
}

// ExplanationDigest is `seam-explanation-digest:v2` over a sealed explanation (32 raw bytes):
//
//	SHA-256( F("seam-explanation-digest:v2") ‖ be64(count) ‖ Σ ENTRY )
//	ENTRY = F(kind) ‖ F(participant) ‖ F(proposal_id) ‖ F(value) ‖ F(reason) ‖ CONF ‖ REF ‖ VV
//	CONF  = 0x00 | 0x01 ‖ be64(IEEE-754 bits)      REF = 0x00 | 0x01 ‖ F(rationale_ref)
//	VV    = 0x00 | 0x01 ‖ F(method) ‖ F(principal) ‖ F(content_digest) ‖ be64(issued_at_ms) ‖
//	        be64(expires_at_ms) ‖ F(signature) ‖ F(signer_certificate) ‖ F(tenant) ‖ F(namespace) ‖
//	        F(session_id) ‖ be64(opened_at_millis) ‖ F(issuer) ‖ F(audience) ‖ be64(accepted_at_ms)
//
// Entries are hashed in the given order, never sorted or de-duplicated. It refuses (returns an error)
// an unknown kind, a non-canonical confidence — NaN, ±Inf, outside [0, 1], or -0.0 — or a voter record
// with an unknown method word or a content digest that is not 32 bytes, rather than hash it.
func ExplanationDigest(entries []ExplanationEntry) ([32]byte, error) {
	out := be64Frame(nil, []byte(ExplanationDomain))
	out = binary.BigEndian.AppendUint64(out, uint64(len(entries)))
	for i, e := range entries {
		known := false
		for _, k := range ExplanationKinds {
			if e.Kind == k {
				known = true
				break
			}
		}
		if !known {
			return [32]byte{}, fmt.Errorf("explanation entry %d: unknown kind %q", i, e.Kind)
		}
		for _, f := range []string{e.Kind, e.Participant, e.ProposalID, e.Value, e.Reason} {
			out = be64Frame(out, []byte(f))
		}
		if e.Confidence == nil {
			out = append(out, 0x00)
		} else {
			c := *e.Confidence
			// NaN fails both range comparisons; ±Inf fails one; -0.0 passes them, hence Signbit.
			if !(c >= 0 && c <= 1) || math.Signbit(c) {
				return [32]byte{}, fmt.Errorf("explanation entry %d: non-canonical confidence %v", i, c)
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
		if vv := e.VoterVerification; vv == nil {
			out = append(out, 0x00)
		} else {
			if vv.Method != VoterMethodPop && vv.Method != VoterMethodCpSigned {
				return [32]byte{}, fmt.Errorf("explanation entry %d: unknown voter method %q", i, vv.Method)
			}
			if len(vv.ContentDigest) != sha256.Size {
				return [32]byte{}, fmt.Errorf("explanation entry %d: voter content_digest must be %d bytes, got %d", i, sha256.Size, len(vv.ContentDigest))
			}
			out = append(out, 0x01)
			out = be64Frame(out, []byte(vv.Method))
			out = be64Frame(out, []byte(vv.Principal))
			out = be64Frame(out, vv.ContentDigest)
			out = binary.BigEndian.AppendUint64(out, vv.IssuedAtMs)
			out = binary.BigEndian.AppendUint64(out, vv.ExpiresAtMs)
			out = be64Frame(out, vv.Signature)
			out = be64Frame(out, vv.SignerCertificate)
			out = be64Frame(out, []byte(vv.Tenant))
			out = be64Frame(out, []byte(vv.Namespace))
			out = be64Frame(out, []byte(vv.SessionID))
			out = binary.BigEndian.AppendUint64(out, vv.OpenedAtMillis)
			out = be64Frame(out, []byte(vv.Issuer))
			out = be64Frame(out, []byte(vv.Audience))
			out = binary.BigEndian.AppendUint64(out, vv.AcceptedAtMs)
		}
	}
	return sha256.Sum256(out), nil
}

// commitmentExplanationDigest resolves field 8: with Explanation entries, recomputed from them — and
// if ExplanationDigest is ALSO published the two must agree (spec §Verification step 1), else an
// error. With only the published digest: used as published (verifies who and what, not why). With
// neither: the digest of the empty explanation.
func commitmentExplanationDigest(c Commitment) ([]byte, error) {
	if c.ExplanationDigest != nil && len(c.ExplanationDigest) != sha256.Size {
		return nil, fmt.Errorf("explanation_digest must be %d bytes, got %d", sha256.Size, len(c.ExplanationDigest))
	}
	if c.Explanation == nil {
		if c.ExplanationDigest != nil {
			return c.ExplanationDigest, nil
		}
		d, err := ExplanationDigest(nil)
		return d[:], err
	}
	d, err := ExplanationDigest(c.Explanation)
	if err != nil {
		return nil, err
	}
	if c.ExplanationDigest != nil && !bytes.Equal(c.ExplanationDigest, d[:]) {
		return nil, fmt.Errorf("explanation_digest does not match the explanation entries")
	}
	return d[:], nil
}

// seamCommitmentDigest is `seam-commitment-digest:v5` (hex): SHA-256 over
//
//	F(domain) ‖ F(id) ‖ F(action) ‖ F(authority) ‖ SUP ‖ F(auth_method) ‖ F(trust_basis) ‖
//	F(committer) ‖ F(explanation_digest) ‖ SEL ‖ CERT ‖ DOC
//	SUP  = 0x00 (supersedes absent) | 0x01 ‖ F(supersedes) (present)
//	SEL  = 0x00 (no selection) | 0x01 ‖ be64(32) ‖ selection_digest
//	CERT = 0x00 (no Gate certificate) | 0x01 ‖ be64(32) ‖ certificate_digest
//	DOC  = 0x00 (ungoverned) | 0x01 ‖ be64(32) ‖ governing_doc_sha256 (field 11, #1711)
//
// with F(x) = be64(len(x)) ‖ x, so the digest is injective over the tuple (a `\0` separator would let
// boundary-shifted fields collide). Field 8 is the 32 RAW bytes of the explanation digest (see
// commitmentExplanationDigest). A present slot-9/10/11 digest that is not 32 bytes is refused, not
// hashed. v1-v4 are deleted, not dual-verified. Mirrors the runtime
// byte-for-byte.
func seamCommitmentDigest(c Commitment) (string, error) {
	ed, err := commitmentExplanationDigest(c)
	if err != nil {
		return "", err
	}
	var out []byte
	for _, f := range []string{CommitmentDigestDomain, c.ID, c.Action, c.Authority} {
		out = be64Frame(out, []byte(f))
	}
	if c.Supersedes == nil {
		out = append(out, 0x00)
	} else {
		out = append(out, 0x01)
		out = be64Frame(out, []byte(*c.Supersedes))
	}
	for _, f := range [][]byte{[]byte(c.AuthMethod), []byte(c.TrustBasis), []byte(c.Committer), ed} {
		out = be64Frame(out, f)
	}
	sel, err := selectionSlot(c)
	if err != nil {
		return "", err
	}
	for _, slot := range []struct {
		name string
		d    []byte
	}{{"selection_digest", sel}, {"certificate_digest", c.CertificateDigest}, {"governing_doc_sha256", c.GoverningDocSha256}} {
		if slot.d == nil {
			out = append(out, 0x00)
			continue
		}
		if len(slot.d) != sha256.Size {
			return "", fmt.Errorf("%s must be %d bytes, got %d", slot.name, sha256.Size, len(slot.d))
		}
		out = append(out, 0x01)
		out = be64Frame(out, slot.d)
	}
	sum := sha256.Sum256(out)
	return hex.EncodeToString(sum[:]), nil
}

// hasDuplicateKey reports whether any JSON object anywhere in raw repeats a key, or raw is not exactly
// one well-formed JSON value. encoding/json keeps the LAST of two equal keys, so a token could carry a
// statement another parser reads differently; the verifier refuses it instead of picking one.
func hasDuplicateKey(raw []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func() bool // false on a duplicate or malformed input
	walk = func() bool {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return false
				}
				k, ok := kt.(string)
				if !ok || seen[k] {
					return false
				}
				seen[k] = true
				if !walk() {
					return false
				}
			}
			_, err = dec.Token() // '}'
			return err == nil
		case json.Delim('['):
			for dec.More() {
				if !walk() {
					return false
				}
			}
			_, err = dec.Token() // ']'
			return err == nil
		}
		return true
	}
	if !walk() {
		return true
	}
	_, err := dec.Token()
	return err == nil // trailing content after the value
}

// VerifyTCT independently verifies a sealed commitment's rooted TCT against the PINNED issuer AID — zero
// server trust, stock crypto.
//
// Deep-cleanup S-4 (seam-runtime #2031, runtime 0.123.0): the TCT is a self-attestation by a short-lived
// SEAL key that the pinned issuer certifies (seal_key.go). Steps, each fail-closed:
//
//  1. read `ext["com.zer07labs.seam.seal-key-cert"]` from the (not yet verified) payload: exactly
//     {cert, sig}, both strict base64url;
//  2. parse the certificate and verify it under the pinned issuer, which it must name (VerifySealKeyCert;
//     strict Ed25519 over sha256(cert));
//  3. verify the JWS under the seal key, with iss == sub == aud == the seal key's untagged AID and
//     `cnf.jkt` its thumbprint; the verified `ext` must carry the same certificate member;
//  4. `iat` must be an integer with not_before_ms ≤ iat·1000 ≤ not_after_ms, no grace;
//  5. the statement and digest checks below, unchanged.
//
// No backward compatibility: a TCT signed directly by the issuer (every TCT before 0.123.0) is refused.
// This proves a key the pinned issuer certified signed the statement, claiming an `iat` inside the
// window; it does not prove when the token was made. Evidence-grade verification binds `iat` to the
// chained `sealed_at`: VerifyTCTSealedAt.
//
// Then the RFC-AITP-0005 self-attestation shape: `alg`/`typ`, `exp`, `grants` is exactly
// ["aitp.attestation"], and `ext` is exactly the statement plus the certificate member, where the
// statement is {"type": "seam:commitment", "commitment_digest": "<64 lowercase hex>"}, whose digest must
// equal `seam-commitment-digest:v5` of this exact commitment — the decided content, the committer, and
// the sealed explanation. A statement that also carries
// "commitment_digest_domain": "seam-commitment-digest:v6" selects v6 instead (SelectCommitmentVersion),
// and the digest is recomputed under v6 only, with fields 10-12 from c.Trailers. A repeated JSON key anywhere in the header or payload
// refuses the token, and a digest carried in `grants` (the retired v2 shape) does not verify.
// Explanation entries that disagree with a published ExplanationDigest, an unknown kind, or a
// non-canonical confidence verify false. When c.Selection is set, the winner is recomputed from
// c.Explanation (VerifySelection) and must verify; a block with nil Explanation fails closed. Any
// malformed/forged input fails closed (returns false), never panics.
func VerifyTCT(issuerAID, tctJWS string, c Commitment, nowS int64) bool {
	return verifyTCT(issuerAID, tctJWS, c, nowS, nil)
}

// VerifyTCTSealedAt is VerifyTCT bound to the record's chained seal time — the evidence-grade check
// (seam-commitment-digest.v6 §Seal key step 6, evidence-bundle.v1 §Verifying step 4). Additionally
// sealedAtMs must be at most math.MaxInt64 and the TCT's `iat` must equal floor(sealedAtMs / 1000).
//
// `iat` is self-asserted, so VerifyTCT alone proves a certified seal key signed the statement, not when:
// a leaked seal key can backdate a token anywhere in its certificate window. sealedAtMs must be the
// `sealed_at` of the record's CHAINED DECISION_SEALED link (record-digest bound), never a value from the
// token and never a served DecisionRecordView.SealedAt. Same rule as seam-verify `verify_tct_sealed_at`
// and the runtime's `verify_commitment_sealed_at` (seam-runtime #2031); pinned by
// conformance/tct_sealed_at_vector.json.
func VerifyTCTSealedAt(issuerAID, tctJWS string, c Commitment, nowS int64, sealedAtMs uint64) bool {
	return verifyTCT(issuerAID, tctJWS, c, nowS, &sealedAtMs)
}

func verifyTCT(issuerAID, tctJWS string, c Commitment, nowS int64, sealedAtMs *uint64) bool {
	parts := strings.Split(tctJWS, ".")
	if len(parts) != 3 {
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
	sig, err := b64urlDecode(parts[2])
	if err != nil {
		return false
	}
	if hasDuplicateKey(headerBytes) || hasDuplicateKey(payloadBytes) {
		return false
	}
	var header, payload map[string]any
	if json.Unmarshal(headerBytes, &header) != nil || json.Unmarshal(payloadBytes, &payload) != nil {
		return false
	}
	// (1) + (2) The seal-key certificate, read before the signature is checked (the token's signer is
	// only known once the certificate names it), verified under the PINNED issuer.
	peekedExt, _ := payload["ext"].(map[string]any)
	peeked, ok := peekedExt[SealKeyCertExtKey]
	if !ok {
		return false
	}
	certBytes, certSig, ok := sealKeyCertMember(peeked)
	if !ok {
		return false
	}
	cert, ok := VerifySealKeyCert(issuerAID, certBytes, certSig)
	if !ok {
		return false
	}
	// (3) The token is a self-attestation by the certified seal key.
	if !ed25519.Verify(ed25519.PublicKey(cert.SealPK[:]), []byte(parts[0]+"."+parts[1]), sig) {
		return false
	}
	sealAID := cert.SealAID()
	iss, _ := payload["iss"].(string)
	sub, _ := payload["sub"].(string)
	aud, _ := payload["aud"].(string)
	if !(iss == sub && sub == aud && aud == sealAID) {
		return false
	}
	cnf, _ := payload["cnf"].(map[string]any)
	if jkt, _ := cnf["jkt"].(string); jkt != jwkThumbprint(cert.SealPK[:]) {
		return false
	}
	verifiedExt, _ := payload["ext"].(map[string]any)
	if !reflect.DeepEqual(verifiedExt[SealKeyCertExtKey], peeked) {
		return false
	}
	// (4) iat, an integer literal (never a float spelling), inside the certificate window, no grace.
	var rawClaims map[string]json.RawMessage
	if json.Unmarshal(payloadBytes, &rawClaims) != nil {
		return false
	}
	iat, ok := jsonInt64(rawClaims["iat"])
	if !ok || !cert.Covers(iat) {
		return false
	}
	// Evidence grade (S-4): iat is the chained seal second.
	if sealedAtMs != nil && (*sealedAtMs > math.MaxInt64 || iat != int64(*sealedAtMs/1000)) {
		return false
	}
	if header["alg"] != "EdDSA" || header["typ"] != "aitp-tct+jwt" {
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
	grants, ok := payload["grants"].([]any)
	if !ok || len(grants) != 1 || grants[0] != AttestationGrant {
		return false
	}
	// Exactly the statement and the certificate member: no other namespace.
	ext, ok := payload["ext"].(map[string]any)
	if !ok || len(ext) != 2 {
		return false
	}
	if _, ok := ext[CommitmentExtNamespace]; !ok {
		return false
	}
	// v5 or v6 is chosen by the statement's exact member set, read from the raw ext text
	// (SelectCommitmentVersion), and the digest is recomputed under that version only: never both, never
	// a fallback. A 2-member statement is v5, exactly as before; Trailers (if held) are checked under that
	// version's scheme rules.
	version, got, err := selectFromExt(rawClaims["ext"])
	if err != nil {
		return false
	}
	digest, err := expectedCommitmentDigest(version, c)
	if err != nil || got != digest {
		return false
	}
	// Option selection (runtime 0.90.0, selection-rule.v1 §5 steps 6-9). No block means "not a selection
	// decision" and nothing more. A block without the entries cannot be checked, so it fails closed
	// rather than passing as if the winner had been recomputed.
	if c.Selection != nil {
		if c.Explanation == nil {
			return false
		}
		return VerifySelection(*c.Selection, c.Explanation, c.Action).OK()
	}
	return true
}

// CallSigV3Context is the domain tag of the `Authorize` per-call proof-of-possession, v3 (#197). v3
// grew the signed payload from v2's ticket/digest/tool_name/agent_id to the full attribution set; the
// distinct tag means a v2 signature can NEVER verify as a v3 one, so a version skew between SDK and
// runtime is a clean rejection rather than a parse ambiguity. Bump it only in lockstep with the runtime.
const CallSigV3Context = "seam-authorize-call-v3"

// CallSigV3Fields are the inputs CallSigV3Payload frames. Every string is signed as its UTF-8 bytes;
// an absent optional field is the empty string (the zero value), signed verbatim rather than skipped.
type CallSigV3Fields struct {
	Ticket          []byte // the admission ticket's RAW bytes
	ToolInputDigest string // "sha256:<hex>"
	ToolName        string
	AgentID         string
	Subject         string
	Subjects        []string // signed in the order SENT — never deduped, never sorted
	ClientRequestID string
	SessionID       string
	Features        [][2]string // (key, value) pairs, any order; signed sorted by (key bytes, value bytes)
}

// CallSigV3Payload is the exact byte string CallSigV3 signs:
//
//	frame(context) | frame(ticket) | frame(tool_input_digest) | frame(tool_name) | frame(agent_id) |
//	frame(subject) | frame(u32le(n_subjects)) | frame(subject_i)... | frame(client_request_id) |
//	frame(session_id) | frame(u32le(n_features)) | (frame(key) | frame(value))...
//
// with frame(x) = u32le(len_bytes(x)) | x — the counts are themselves framed. Length prefixing is
// load-bearing: raw concatenation would let bytes shift across a field boundary undetected.
//
// Pinned by conformance/call_sig_v3_payload_vector.json. Exported so a caller can reproduce or verify
// the binding without re-deriving it from prose.
func CallSigV3Payload(f CallSigV3Fields) []byte {
	var out []byte
	frame := func(b []byte) {
		out = binary.LittleEndian.AppendUint32(out, uint32(len(b)))
		out = append(out, b...)
	}
	count := func(n int) { frame(binary.LittleEndian.AppendUint32(nil, uint32(n))) }

	frame([]byte(CallSigV3Context))
	frame(f.Ticket)
	frame([]byte(f.ToolInputDigest))
	frame([]byte(f.ToolName))
	frame([]byte(f.AgentID))
	frame([]byte(f.Subject))
	count(len(f.Subjects))
	for _, s := range f.Subjects {
		frame([]byte(s))
	}
	frame([]byte(f.ClientRequestID))
	frame([]byte(f.SessionID))

	// Go's string `<` is bytewise over the UTF-8, which is exactly the contract's order. Sort a copy:
	// the caller's slice is theirs.
	features := append([][2]string(nil), f.Features...)
	sort.Slice(features, func(i, j int) bool {
		if features[i][0] != features[j][0] {
			return features[i][0] < features[j][0]
		}
		return features[i][1] < features[j][1]
	})
	count(len(features))
	for _, kv := range features {
		frame([]byte(kv[0]))
		frame([]byte(kv[1]))
	}
	return out
}

// CallSigV3 is the per-call proof-of-possession for `Authorize`: Ed25519 by the agent key over
// CallSigV3Payload, returned as the raw 64-byte signature (the `call_sig` bytes field), as Python's
// call_sig does.
func CallSigV3(agentSeed []byte, f CallSigV3Fields) ([]byte, error) {
	if len(agentSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("agent seed must be %d bytes", ed25519.SeedSize)
	}
	return ed25519.Sign(ed25519.NewKeyFromSeed(agentSeed), CallSigV3Payload(f)), nil
}

// EnrollPopV2Context is the domain tag of the enrolment proof-of-possession (seam-runtime #1157, #1687):
// the subject AID's own consent, by the key it embeds, to ONE `EnrollTenant` binding — including the
// participant a `voter` enrolment binds. v1 is deleted (runtime 0.87.0 refuses it). Bump it only in
// lockstep with the runtime.
const EnrollPopV2Context = "seam-enroll-pop-v2"

// EnrollPopFields are the inputs EnrollPopPayload frames, each exactly as sent on the wire. Strings are
// signed as their UTF-8 bytes.
type EnrollPopFields struct {
	SubjectAID string // `aid:pubkey:ed25519:<b64url>` — the AID being enrolled
	Tenant     string
	Namespace  string
	// ParticipantID is the participant a `voter` enrolment binds; "" for every other kind. It must equal
	// the `participant_id` sent beside the proof.
	ParticipantID string
	IssuedAtMs    uint64 // Unix epoch MILLISECONDS
	Nonce         string // 1..=128 chars of [A-Za-z0-9_-]
}

// EnrollPopPayload is the exact byte string EnrollPopSign signs:
//
//	frame(context) | frame(subject_aid) | frame(tenant) | frame(namespace) | frame(participant_id) |
//	frame(u64le(issued_at_ms)) | frame(nonce)
//
// with frame(x) = u32le(len_bytes(x)) | x. issued_at_ms is 8 raw little-endian bytes, not ASCII decimal.
//
// Pinned by conformance/enroll_pop_v2_payload_vector.json. Exported so a caller can reproduce or verify
// the binding without re-deriving it from prose.
func EnrollPopPayload(f EnrollPopFields) []byte {
	var out []byte
	frame := func(b []byte) {
		out = binary.LittleEndian.AppendUint32(out, uint32(len(b)))
		out = append(out, b...)
	}
	frame([]byte(EnrollPopV2Context))
	frame([]byte(f.SubjectAID))
	frame([]byte(f.Tenant))
	frame([]byte(f.Namespace))
	frame([]byte(f.ParticipantID))
	frame(binary.LittleEndian.AppendUint64(nil, f.IssuedAtMs))
	frame([]byte(f.Nonce))
	return out
}

// ValidateEnrollPopNonce refuses a nonce the runtime would refuse: 1..=128 characters of [A-Za-z0-9_-].
func ValidateEnrollPopNonce(nonce string) error {
	if len(nonce) < 1 || len(nonce) > 128 {
		return fmt.Errorf("enrol pop nonce must be 1..=128 characters, got %d", len(nonce))
	}
	for i := 0; i < len(nonce); i++ {
		c := nonce[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return fmt.Errorf("enrol pop nonce must use only [A-Za-z0-9_-]")
		}
	}
	return nil
}

// EnrollPopSign is the enrolment proof-of-possession: Ed25519 by the agent key over EnrollPopPayload,
// returned as the raw 64-byte signature (the `EnrollPop.signature` bytes field; the REST body carries it
// as unpadded base64url). It refuses a SubjectAID that is not the seed's own AID — a proof can only speak
// for the key that signs it — and a nonce the runtime would refuse.
func EnrollPopSign(agentSeed []byte, f EnrollPopFields) ([]byte, error) {
	if len(agentSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("agent seed must be %d bytes", ed25519.SeedSize)
	}
	if err := ValidateEnrollPopNonce(f.Nonce); err != nil {
		return nil, err
	}
	key := ed25519.NewKeyFromSeed(agentSeed)
	if own := AIDFromPubkey(key.Public().(ed25519.PublicKey)); f.SubjectAID != own {
		return nil, fmt.Errorf("SubjectAID %q is not this seed's AID %q", f.SubjectAID, own)
	}
	return ed25519.Sign(key, EnrollPopPayload(f)), nil
}
