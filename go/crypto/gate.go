package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"unicode/utf8"
)

// GateDigestDomain is the domain tag of the Gate block digest that frames v6 field 10.
// Normative: seam-runtime docs/specs/seam-gate-block.v1.md.
const GateDigestDomain = "seam-gate-digest:v1"

// Refusal is the error every v6 / Gate decoder and digest returns when it refuses its input. Rule names
// one rule of the spec's refusal table. Only the refusal is normative: the rule is advisory, and where an
// input breaks several rules any of them may be reported.
type Refusal struct{ Rule string }

func (r *Refusal) Error() string { return "refused: " + r.Rule }

func refuse(rule string) error { return &Refusal{Rule: rule} }

// GateBlock is a decoded `0x05` Gate body v1. Text fields are the UTF-8 the body frames; every be64 is a
// uint64 (the full 0..2^64-1 range is legal bytes). Answered blocks set ReceiptJCS, KeyID, Signature (64 raw
// bytes) and CertificateJCS (nil iff the certificate frame is empty, i.e. a route answer); unavailable blocks
// set Reason and GivenUpAtMs.
type GateBlock struct {
	Status         string // "answered" | "unavailable"
	AttemptID      string
	Domain         string
	FlowID         string
	Env            string // "sandbox" | "live"
	TimeoutMs      uint64
	OnOutage       string // "refuse_seal" | "seal_gate_unavailable"
	RequestedAtMs  uint64
	ReceiptJCS     string
	KeyID          string
	Signature      []byte
	CertificateJCS *string
	Reason         string // "timeout" | "connect" | "http_5xx" | "circuit_open" | "token_mint"
	GivenUpAtMs    uint64
}

var (
	gateStatus   = map[byte]string{1: "answered", 2: "unavailable"}
	gateOnOutage = map[byte]string{1: "refuse_seal", 2: "seal_gate_unavailable"}
	// 4 (invalid_response) is reserved and refused: an unverifiable answer is never sealed.
	gateReason = map[byte]string{1: "timeout", 2: "connect", 3: "http_5xx", 5: "circuit_open", 6: "token_mint"}
)

// byteReader is a strict cursor: any read past the end refuses with its truncation rule.
type byteReader struct {
	b         []byte
	p         int
	truncated string
}

func (r *byteReader) take(n uint64) ([]byte, error) {
	// Compared in uint64 so a frame length of 2^64-1 refuses as truncated instead of wrapping.
	if n > uint64(len(r.b)-r.p) {
		return nil, refuse(r.truncated)
	}
	out := r.b[r.p : r.p+int(n)]
	r.p += int(n)
	return out, nil
}

func (r *byteReader) u8() (byte, error) {
	b, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *byteReader) be64() (uint64, error) {
	b, err := r.take(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

func (r *byteReader) framed() ([]byte, error) {
	n, err := r.be64()
	if err != nil {
		return nil, err
	}
	return r.take(n)
}

// text reads a Gate text field: framed, valid UTF-8, non-empty.
func (r *byteReader) text() (string, error) {
	raw, err := r.framed()
	if err != nil {
		return "", err
	}
	if !utf8.Valid(raw) {
		return "", refuse("gate_text_not_utf8")
	}
	if len(raw) == 0 {
		return "", refuse("gate_text_empty")
	}
	return string(raw), nil
}

func (r *byteReader) done(rule string) error {
	if r.p != len(r.b) {
		return refuse(rule)
	}
	return nil
}

// envOf is the env rule on raw bytes: exactly "sandbox" or "live", compared byte for byte (a non-ASCII or
// non-UTF-8 value fails the same rule; there is no text decode).
func envOf(raw []byte) (string, error) {
	s := string(raw)
	if s != "sandbox" && s != "live" {
		return "", refuse("env_not_sandbox_or_live")
	}
	return s, nil
}

// DecodeGateBody is the strict decoder of a `0x05` Gate body v1 (the trailer's body, after
// `marker ‖ u32le(len)`). It refuses (a *Refusal) every body the spec's refusal table names: an unknown
// version, status, on_outage or reason (4 is reserved), an unavailable body under refuse_seal, an env other
// than the bytes "sandbox"/"live", a non-UTF-8 or empty text field, a signature that is not 64 raw bytes, a
// truncated frame, and trailing bytes. It never parses the receipt or certificate content.
func DecodeGateBody(body []byte) (GateBlock, error) {
	var blk GateBlock
	if len(body) == 0 {
		return blk, refuse("gate_body_empty")
	}
	r := &byteReader{b: body, truncated: "gate_body_truncated"}
	v, err := r.u8()
	if err != nil {
		return blk, err
	}
	if v != 0x01 {
		return blk, refuse("gate_body_unknown_version")
	}
	st, err := r.u8()
	if err != nil {
		return blk, err
	}
	status, ok := gateStatus[st]
	if !ok {
		return blk, refuse("gate_status_invalid")
	}
	blk.Status = status
	for _, dst := range []*string{&blk.AttemptID, &blk.Domain, &blk.FlowID} {
		if *dst, err = r.text(); err != nil {
			return blk, err
		}
	}
	envRaw, err := r.framed()
	if err != nil {
		return blk, err
	}
	if blk.Env, err = envOf(envRaw); err != nil {
		return blk, err
	}
	if blk.TimeoutMs, err = r.be64(); err != nil {
		return blk, err
	}
	oo, err := r.u8()
	if err != nil {
		return blk, err
	}
	onOutage, ok := gateOnOutage[oo]
	if !ok {
		return blk, refuse("gate_on_outage_invalid")
	}
	blk.OnOutage = onOutage
	if blk.RequestedAtMs, err = r.be64(); err != nil {
		return blk, err
	}
	if st == 1 {
		if blk.ReceiptJCS, err = r.text(); err != nil {
			return blk, err
		}
		if blk.KeyID, err = r.text(); err != nil {
			return blk, err
		}
		sig, err := r.framed()
		if err != nil {
			return blk, err
		}
		if len(sig) != 64 {
			return blk, refuse("gate_signature_length")
		}
		blk.Signature = append([]byte(nil), sig...)
		cert, err := r.framed()
		if err != nil {
			return blk, err
		}
		if !utf8.Valid(cert) {
			return blk, refuse("gate_text_not_utf8")
		}
		if len(cert) > 0 {
			s := string(cert)
			blk.CertificateJCS = &s
		}
	} else {
		if oo == 1 {
			return blk, refuse("gate_unavailable_under_refuse_seal")
		}
		rs, err := r.u8()
		if err != nil {
			return blk, err
		}
		if rs == 4 {
			return blk, refuse("gate_reason_reserved")
		}
		reason, ok := gateReason[rs]
		if !ok {
			return blk, refuse("gate_reason_invalid")
		}
		blk.Reason = reason
		if blk.GivenUpAtMs, err = r.be64(); err != nil {
			return blk, err
		}
	}
	return blk, r.done("gate_body_trailing_bytes")
}

// GateDigest is `seam-gate-digest:v1` over a Gate body, whole (its version byte included; the trailer marker
// and u32le length are not hashed):
//
//	SHA-256( be64(19) ‖ "seam-gate-digest:v1" ‖ gate_body )
//
// It hashes the bytes it is given; call DecodeGateBody first to refuse a malformed body.
func GateDigest(body []byte) [32]byte {
	return sha256.Sum256(append(be64Frame(nil, []byte(GateDigestDomain)), body...))
}
