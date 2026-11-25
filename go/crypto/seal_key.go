package crypto

// Deep-cleanup S-4 (seam-runtime #2031, runtime 0.123.0): the commitment TCT is signed by a short-lived
// **seal key** that the pinned issuer certifies, not by the issuer itself. Spec: seam-runtime
// docs/specs/seam-commitment-digest.v6.md §Seal key; reference: crates/seam-trust-aitp/src/seal_key.rs.
//
//	cert := framed("seam.seal-key-cert.v1") ‖ framed(seal_pk[32]) ‖ le64(not_before_ms) ‖ le64(not_after_ms)
//	        ‖ framed(issuer_aid)                       framed(x) = u32le(len(x)) ‖ x
//	sig  := Ed25519(issuer, sha256(cert))
//	ext["com.zer07labs.seam.seal-key-cert"] = {"cert": b64url(cert), "sig": b64url(sig)}
//
// No backward compatibility: a TCT signed directly by the issuer (every TCT before 0.123.0) carries no
// certificate and is refused.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math"
	"strconv"
	"unicode/utf8"
)

// SealKeyCertExtKey is the TCT `ext` member that carries the seal-key certificate, beside the commitment
// statement under CommitmentExtNamespace.
const SealKeyCertExtKey = "com.zer07labs.seam.seal-key-cert"

// SealKeyCertDomain is the certificate's domain tag (its first frame).
const SealKeyCertDomain = "seam.seal-key-cert.v1"

// SealKeyMaxWindowMs is the widest certificate window a verifier accepts, not_after − not_before: one
// hour plus the runtime's 30 s backdate skew. A wider certificate does not parse.
const SealKeyMaxWindowMs uint64 = 3_600_000 + 30_000

// sealKeyIssuerAIDMax is the longest issuer AID a certificate carries (the tagged Ed25519 form).
const sealKeyIssuerAIDMax = 62

// SealKeyCert is a parsed seal-key certificate.
type SealKeyCert struct {
	SealPK      [32]byte
	NotBeforeMs uint64
	NotAfterMs  uint64
	IssuerAID   string
}

// SealAID is the seal key's untagged `aid:pubkey:<b64url>` AID: the commitment TCT's iss == sub == aud.
func (c SealKeyCert) SealAID() string { return "aid:pubkey:" + b64urlNoPad(c.SealPK[:]) }

// Covers reports not_before_ms ≤ iat·1000 ≤ not_after_ms, with no grace; an iat whose ms value overflows
// int64 is not covered.
func (c SealKeyCert) Covers(iatSecs int64) bool {
	if iatSecs > math.MaxInt64/1000 || iatSecs < math.MinInt64/1000 {
		return false
	}
	t := iatSecs * 1000
	if t < 0 {
		return false // not_before_ms is unsigned, so a negative instant is never covered
	}
	return c.NotBeforeMs <= uint64(t) && uint64(t) <= c.NotAfterMs
}

// SealKeyCertPreimage encodes a certificate (seam_types::chain::seal_key_cert_preimage).
func SealKeyCertPreimage(sealPK [32]byte, notBeforeMs, notAfterMs uint64, issuerAID string) []byte {
	out := framed(nil, []byte(SealKeyCertDomain))
	out = framed(out, sealPK[:])
	out = binary.LittleEndian.AppendUint64(out, notBeforeMs)
	out = binary.LittleEndian.AppendUint64(out, notAfterMs)
	return framed(out, []byte(issuerAID))
}

// framed appends the runtime's chain framing primitive, u32le(len(x)) ‖ x.
func framed(out, x []byte) []byte {
	out = binary.LittleEndian.AppendUint32(out, uint32(len(x)))
	return append(out, x...)
}

// ParseSealKeyCert parses a certificate. Total on hostile input: refuses a wrong tag, a key that is not
// 32 bytes, trailing bytes, an inverted window, a window wider than SealKeyMaxWindowMs, a time beyond
// math.MaxInt64 ms, and an issuer AID that is not UTF-8 or longer than 62 bytes.
func ParseSealKeyCert(b []byte) (SealKeyCert, bool) {
	var c SealKeyCert
	pos := 0
	get := func() ([]byte, bool) {
		if len(b)-pos < 4 {
			return nil, false
		}
		n := uint64(binary.LittleEndian.Uint32(b[pos:]))
		pos += 4
		if uint64(len(b)-pos) < n {
			return nil, false
		}
		x := b[pos : pos+int(n)]
		pos += int(n)
		return x, true
	}
	le64 := func() (uint64, bool) {
		if len(b)-pos < 8 {
			return 0, false
		}
		v := binary.LittleEndian.Uint64(b[pos:])
		pos += 8
		return v, true
	}
	tag, ok := get()
	if !ok || string(tag) != SealKeyCertDomain {
		return c, false
	}
	pk, ok := get()
	if !ok || len(pk) != 32 {
		return c, false
	}
	copy(c.SealPK[:], pk)
	if c.NotBeforeMs, ok = le64(); !ok {
		return c, false
	}
	if c.NotAfterMs, ok = le64(); !ok {
		return c, false
	}
	aid, ok := get()
	if !ok || pos != len(b) || len(aid) > sealKeyIssuerAIDMax || !utf8.Valid(aid) {
		return c, false
	}
	if !(c.NotBeforeMs <= c.NotAfterMs && c.NotAfterMs <= math.MaxInt64 &&
		c.NotAfterMs-c.NotBeforeMs <= SealKeyMaxWindowMs) {
		return c, false
	}
	c.IssuerAID = string(aid)
	return c, true
}

// VerifySealKeyCert verifies a certificate under the PINNED issuer AID: it must name exactly that AID, and
// the issuer's strict Ed25519 signature over sha256(cert) must hold. The pin compare is load-bearing:
// without it a forger certifies their own key under their own AID.
func VerifySealKeyCert(pinnedIssuerAID string, cert, sig []byte) (SealKeyCert, bool) {
	c, ok := ParseSealKeyCert(cert)
	if !ok || c.IssuerAID != pinnedIssuerAID {
		return SealKeyCert{}, false
	}
	pub, err := aidToPubkey(pinnedIssuerAID)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return SealKeyCert{}, false
	}
	digest := sha256.Sum256(cert)
	if !ed25519VerifyStrict(pub, digest[:], sig) {
		return SealKeyCert{}, false
	}
	return c, true
}

// smallOrderEncodings are the 14 32-byte strings that decode to an Ed25519 point of small order (the 8
// torsion points, their non-canonical y+p aliases and sign-bit variants).
var smallOrderEncodings = func() map[string]bool {
	m := map[string]bool{}
	for _, h := range []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000080",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	} {
		b, _ := hex.DecodeString(h)
		m[string(b)] = true
	}
	return m
}()

// ed25519VerifyStrict mirrors ed25519-dalek's verify_strict, which the runtime uses for the certificate:
// crypto/ed25519 already refuses a non-canonical S and compares R by its encoding; on top of that a
// small-order public key or a small-order R is refused.
func ed25519VerifyStrict(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	if smallOrderEncodings[string(pub)] || smallOrderEncodings[string(sig[:32])] {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// b64urlStrict decodes unpadded base64url strictly: only [A-Za-z0-9_-], no padding, canonical trailing
// bits (the re-encoding must equal the input).
func b64urlStrict(s string) ([]byte, bool) {
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return nil, false
		}
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, false
	}
	return b, true
}

// sealKeyCertMember reads the `{cert, sig}` member: exactly those two keys, both strict base64url strings.
func sealKeyCertMember(v any) (cert, sig []byte, ok bool) {
	obj, isObj := v.(map[string]any)
	if !isObj || len(obj) != 2 {
		return nil, nil, false
	}
	cs, ok1 := obj["cert"].(string)
	ss, ok2 := obj["sig"].(string)
	if !ok1 || !ok2 {
		return nil, nil, false
	}
	if cert, ok1 = b64urlStrict(cs); !ok1 {
		return nil, nil, false
	}
	if sig, ok2 = b64urlStrict(ss); !ok2 {
		return nil, nil, false
	}
	return cert, sig, true
}

// jwkThumbprint is the RFC 7638 thumbprint of an Ed25519 key, the AITP `cnf.jkt`.
func jwkThumbprint(pk []byte) string {
	sum := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + b64urlNoPad(pk) + `"}`))
	return b64urlNoPad(sum[:])
}

// jsonInt64 reads a raw JSON value as an integer literal only: a float spelling (`1.0`, `1e3`), a
// string, a bool, null or an absent member refuses.
func jsonInt64(raw []byte) (int64, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return 0, false
	}
	for i, ch := range raw {
		if !(ch >= '0' && ch <= '9' || (ch == '-' && i == 0)) {
			return 0, false
		}
	}
	digits := raw
	if raw[0] == '-' {
		digits = raw[1:]
	}
	if len(digits) == 0 || (len(digits) > 1 && digits[0] == '0') {
		return 0, false // JSON forbids leading zeros
	}
	v, err := strconv.ParseInt(string(raw), 10, 64)
	return v, err == nil
}
