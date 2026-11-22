package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
)

// CommitmentDigestDomainV6 is the domain tag of `seam-commitment-digest:v6` (field 0).
// Normative: seam-runtime docs/specs/seam-commitment-digest.v6.md. v5 (CommitmentDigestDomain) is unchanged
// beside it until W9.
const CommitmentDigestDomainV6 = "seam-commitment-digest:v6"

// CommitmentVersion is the commitment digest a TCT statement selects.
type CommitmentVersion int

const (
	CommitmentV5 CommitmentVersion = 5
	CommitmentV6 CommitmentVersion = 6
)

func (v CommitmentVersion) String() string {
	switch v {
	case CommitmentV5:
		return "v5"
	case CommitmentV6:
		return "v6"
	}
	return "unknown"
}

// TrailerScheme is the scheme a trailer decode applies. The bytes never say v5 or v6: a verifier takes it from
// statement selection, the runtime from the database's chain_scheme. SchemeFree accepts both `0x06` body
// versions and applies only the scheme-independent rules; its caller applies the scheme's rules later.
type TrailerScheme int

const (
	SchemeFree TrailerScheme = iota
	SchemeV5
	SchemeV6
)

// CommitmentDigestFields are the inputs of fields 9-12 given directly (the digest-only path). A nil slot is
// absent (0x00); a present one MUST be exactly 32 bytes. A nil Env is absent; a present one MUST be exactly
// "sandbox" or "live" and needs GoverningDocSha256.
type CommitmentDigestFields struct {
	SelectionDigest    []byte  // field 9
	GateDigest         []byte  // field 10 (v5: the opaque certificate slot)
	GoverningDocSha256 []byte  // field 11
	Env                *string // field 12 (v6 only)
}

// CommitmentDigest is the commitment digest (lowercase hex) under the given version, with fields 0-8 from c
// (field 8 resolved as v5 does, from Explanation and/or ExplanationDigest) and fields 9-12 from f only: c's
// SelectionDigest, Selection, CertificateDigest, GoverningDocSha256 and Trailers are NOT read here.
//
//	ENC(9|10|11) = 0x00 | 0x01 ‖ be64(32) ‖ 32 bytes      ENC(12) = 0x00 | 0x01 ‖ F(env)   (v6 only)
//
// It refuses (a *Refusal) before hashing: a present slot not 32 bytes (slot_length_not_32), an env other than
// "sandbox"/"live" (env_not_sandbox_or_live), an env without a doc under v6 (env_without_governing_doc), and
// any env under v5 (v5_refuses_env). Under v5 with no env it reproduces v5 exactly.
func CommitmentDigest(version CommitmentVersion, c Commitment, f CommitmentDigestFields) (string, error) {
	var domain string
	switch version {
	case CommitmentV5:
		domain = CommitmentDigestDomain
		if f.Env != nil {
			return "", refuse("v5_refuses_env")
		}
	case CommitmentV6:
		domain = CommitmentDigestDomainV6
		if f.Env != nil {
			if _, err := envOf([]byte(*f.Env)); err != nil {
				return "", err
			}
			if f.GoverningDocSha256 == nil {
				return "", refuse("env_without_governing_doc")
			}
		}
	default:
		return "", refuse("unknown_commitment_version")
	}
	for _, d := range [][]byte{f.SelectionDigest, f.GateDigest, f.GoverningDocSha256} {
		if d != nil && len(d) != sha256.Size {
			return "", refuse("slot_length_not_32")
		}
	}
	ed, err := commitmentExplanationDigest(c)
	if err != nil {
		return "", err
	}
	var out []byte
	for _, s := range []string{domain, c.ID, c.Action, c.Authority} {
		out = be64Frame(out, []byte(s))
	}
	if c.Supersedes == nil {
		out = append(out, 0x00)
	} else {
		out = append(out, 0x01)
		out = be64Frame(out, []byte(*c.Supersedes))
	}
	for _, b := range [][]byte{[]byte(c.AuthMethod), []byte(c.TrustBasis), []byte(c.Committer), ed} {
		out = be64Frame(out, b)
	}
	out = append(out, slotEncoding(f.SelectionDigest)...)
	out = append(out, slotEncoding(f.GateDigest)...)
	out = append(out, slotEncoding(f.GoverningDocSha256)...)
	if version == CommitmentV6 {
		out = append(out, envEncoding(f.Env)...)
	}
	sum := sha256.Sum256(out)
	return hex.EncodeToString(sum[:]), nil
}

// CommitmentDigestV6 is CommitmentDigest(CommitmentV6, c, f).
func CommitmentDigestV6(c Commitment, f CommitmentDigestFields) (string, error) {
	return CommitmentDigest(CommitmentV6, c, f)
}

func slotEncoding(d []byte) []byte {
	if d == nil {
		return []byte{0x00}
	}
	return be64Frame([]byte{0x01}, d)
}

func envEncoding(env *string) []byte {
	if env == nil {
		return []byte{0x00}
	}
	return be64Frame([]byte{0x01}, []byte(*env))
}

// CommitmentTrailers is a decoded `0x05` / `0x06` trailer run: fields 10-12 as raw values and as their exact
// digest encodings. GoverningBodyVersion is 0 when there is no `0x06` trailer, else 1 or 2. Field12 is nil
// when the decode has no field 12 to frame (v5, or a scheme-free decode of a v1 body / no `0x06`).
type CommitmentTrailers struct {
	Gate                 *GateBlock
	GateDigest           []byte // nil (no 0x05) or SHA-256 per GateDigest over the 0x05 body
	GoverningDocSha256   []byte // nil (no 0x06) or 32 bytes
	Env                  *string
	GoverningBodyVersion int
	Field10              []byte
	Field11              []byte
	Field12              []byte
}

const (
	gateTrailerMarker      = 0x05
	governingTrailerMarker = 0x06
)

// readTrailer reads `marker ‖ u32le(len) ‖ body` at pos.
func readTrailer(tail []byte, pos int, truncated string) ([]byte, int, error) {
	if len(tail)-pos < 5 {
		return nil, 0, refuse(truncated)
	}
	n := uint64(binary.LittleEndian.Uint32(tail[pos+1 : pos+5]))
	if n > uint64(len(tail)-pos-5) {
		return nil, 0, refuse(truncated)
	}
	end := pos + 5 + int(n)
	return tail[pos+5 : end], end, nil
}

// decodeGoverningBody decodes a `0x06` body of either version under scheme, returning (version, doc, env).
func decodeGoverningBody(body []byte, scheme TrailerScheme) (int, []byte, *string, error) {
	if len(body) == 0 {
		return 0, nil, nil, refuse("governing_body_empty")
	}
	version := body[0]
	if version != 0x01 && version != 0x02 {
		return 0, nil, nil, refuse("governing_body_unknown_version")
	}
	if scheme == SchemeV5 && version == 0x02 {
		return 0, nil, nil, refuse("v5_refuses_governing_body_v2")
	}
	if scheme == SchemeV6 && version == 0x01 {
		return 0, nil, nil, refuse("v6_refuses_governing_body_v1")
	}
	if version == 0x01 {
		if len(body) != 33 {
			return 0, nil, nil, refuse("governing_body_length")
		}
		return 1, append([]byte(nil), body[1:]...), nil, nil
	}
	r := &byteReader{b: body[1:], truncated: "governing_body_truncated"}
	doc, err := r.take(sha256.Size)
	if err != nil {
		return 0, nil, nil, err
	}
	if r.p == len(r.b) {
		return 0, nil, nil, refuse("env_presence_missing")
	}
	presence, _ := r.u8()
	var env *string
	switch presence {
	case 0x00:
	case 0x01:
		raw, err := r.framed()
		if err != nil {
			return 0, nil, nil, err
		}
		e, err := envOf(raw)
		if err != nil {
			return 0, nil, nil, err
		}
		env = &e
	default:
		return 0, nil, nil, refuse("env_presence_invalid")
	}
	if err := r.done("governing_body_trailing_bytes"); err != nil {
		return 0, nil, nil, err
	}
	return 2, append([]byte(nil), doc...), env, nil
}

// DecodeCommitmentTrailers decodes the raw `0x05` / `0x06` trailer bytes a commitment appends ("" when it has
// neither) into fields 10-12. Fields 10-12 come only from these bytes, never from a value carried beside them.
//
// Rules applied by every scheme: markers strictly increase (a second `0x05`, or `0x05` after `0x06`, refuses:
// marker_order); a marker outside 0x01-0x07 refuses (unknown_marker); nothing may follow the last trailer;
// the `0x05` body is decoded strictly (DecodeGateBody) and field 10 is 0x01 ‖ F(GateDigest(body)); the `0x06`
// body is v1 (exactly 33 bytes) or v2 (doc ‖ env slot, the env exactly "sandbox"/"live"); and a `0x05` is
// legal only beside a `0x06` v2 whose env equals the Gate body's env (gate_env_binding).
//
// Scheme rules on top: SchemeV5 refuses any `0x05` (v5_refuses_gate_block) and a v2 body
// (v5_refuses_governing_body_v2); SchemeV6 refuses a v1 body (v6_refuses_governing_body_v1); SchemeFree
// accepts both body versions and reports GoverningBodyVersion. The selection (`0x04`) and other in-range
// trailers are not carried by this input (the selection block travels as Commitment.Selection /
// SelectionDigest, as in v5), so their markers refuse here rather than being skipped.
func DecodeCommitmentTrailers(trailers []byte, scheme TrailerScheme) (CommitmentTrailers, error) {
	var out CommitmentTrailers
	var gateBody []byte
	havePos := false
	pos, last := 0, 0
	for pos < len(trailers) {
		marker := int(trailers[pos])
		if marker < 0x01 || marker > 0x07 {
			return out, refuse("unknown_marker")
		}
		if marker <= last {
			return out, refuse("marker_order")
		}
		last = marker
		switch marker {
		case gateTrailerMarker:
			if scheme == SchemeV5 {
				return out, refuse("v5_refuses_gate_block")
			}
			body, next, err := readTrailer(trailers, pos, "gate_trailer_truncated")
			if err != nil {
				return out, err
			}
			blk, err := DecodeGateBody(body)
			if err != nil {
				return out, err
			}
			gateBody, out.Gate, pos = body, &blk, next
		case governingTrailerMarker:
			body, next, err := readTrailer(trailers, pos, "governing_trailer_truncated")
			if err != nil {
				return out, err
			}
			v, doc, env, err := decodeGoverningBody(body, scheme)
			if err != nil {
				return out, err
			}
			out.GoverningBodyVersion, out.GoverningDocSha256, out.Env, pos = v, doc, env, next
			havePos = true
		default:
			return out, refuse("trailer_not_carried")
		}
	}
	if out.Gate != nil {
		if !havePos || out.Env == nil || *out.Env != out.Gate.Env {
			return out, refuse("gate_env_binding")
		}
		d := GateDigest(gateBody)
		out.GateDigest = d[:]
	}
	out.Field10 = slotEncoding(out.GateDigest)
	out.Field11 = slotEncoding(out.GoverningDocSha256)
	if scheme == SchemeV6 || (scheme == SchemeFree && out.GoverningBodyVersion == 2) {
		out.Field12 = envEncoding(out.Env)
	}
	return out, nil
}

// jsonDupWalk walks exactly one JSON value with a json.Decoder token stream, refusing a repeated member name
// in ANY object at any depth. Names are compared as the decoder returns them, i.e. after JSON unescaping, so
// "type" and "type" collide. encoding/json's map decode would silently keep the last duplicate.
func jsonDupWalk(raw []byte) error {
	if !json.Valid(raw) {
		return refuse("statement_not_json")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return refuse("statement_not_json")
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return refuse("statement_not_json")
				}
				k, ok := kt.(string)
				if !ok {
					return refuse("statement_not_json")
				}
				if seen[k] {
					return refuse("statement_duplicate_member")
				}
				seen[k] = true
				if err := walk(); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return refuse("statement_not_json")
			}
		case json.Delim('['):
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return refuse("statement_not_json")
			}
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := dec.Token(); err == nil {
		return refuse("statement_not_json")
	}
	return nil
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// selectFromObject applies the exact-member-set rule to an already duplicate-checked statement value.
func selectFromObject(raw json.RawMessage) (CommitmentVersion, string, error) {
	var obj map[string]json.RawMessage
	if t := bytes.TrimLeft(raw, " \t\r\n"); len(t) == 0 || t[0] != '{' || json.Unmarshal(raw, &obj) != nil {
		return 0, "", refuse("statement_not_object")
	}
	_, hasType := obj["type"]
	_, hasDigest := obj["commitment_digest"]
	domRaw, hasDomain := obj["commitment_digest_domain"]
	var version CommitmentVersion
	switch {
	case len(obj) == 2 && hasType && hasDigest:
		version = CommitmentV5
	case len(obj) == 3 && hasType && hasDigest && hasDomain:
		var dom string
		if json.Unmarshal(domRaw, &dom) != nil || dom != CommitmentDigestDomainV6 {
			return 0, "", refuse("statement_domain_not_v6")
		}
		version = CommitmentV6
	default:
		return 0, "", refuse("statement_member_set")
	}
	var typ string
	if json.Unmarshal(obj["type"], &typ) != nil || typ != CommitmentStatement {
		return 0, "", refuse("statement_type")
	}
	var digest string
	if json.Unmarshal(obj["commitment_digest"], &digest) != nil || !isLowerHex64(digest) {
		return 0, "", refuse("statement_digest_not_lowercase_hex")
	}
	return version, digest, nil
}

// SelectCommitmentVersionFromStatement applies the v6 statement-selection rule to the raw text of the
// `com.zer07labs.seam` statement object: members exactly {type, commitment_digest} select v5; exactly
// {type, commitment_digest, commitment_digest_domain} with the domain the string
// "seam-commitment-digest:v6" select v6. It refuses (a *Refusal) non-JSON, a non-object, a duplicate member
// name at any depth (on the raw text, after unescaping), any other member set or domain value, a type other
// than "seam:commitment", and a digest that is not exactly 64 lowercase hex characters.
func SelectCommitmentVersionFromStatement(statementRaw []byte) (CommitmentVersion, error) {
	if err := jsonDupWalk(statementRaw); err != nil {
		return 0, err
	}
	v, _, err := selectFromObject(statementRaw)
	return v, err
}

// SelectCommitmentVersion is the same rule entered from the raw TCT `ext` object text: the duplicate-member
// guard covers the whole ext (a repeated namespace, a repeated statement member, or a repeat inside another
// namespace's object all refuse), an ext without a `com.zer07labs.seam` member refuses (statement_missing),
// and other namespaces beside it are allowed here (VerifyTCT itself keeps v5's single-namespace shape).
func SelectCommitmentVersion(extRaw []byte) (CommitmentVersion, error) {
	v, _, err := selectFromExt(extRaw)
	return v, err
}

func selectFromExt(extRaw []byte) (CommitmentVersion, string, error) {
	if err := jsonDupWalk(extRaw); err != nil {
		return 0, "", err
	}
	var ext map[string]json.RawMessage
	if t := bytes.TrimLeft(extRaw, " \t\r\n"); len(t) == 0 || t[0] != '{' || json.Unmarshal(extRaw, &ext) != nil {
		return 0, "", refuse("statement_not_object")
	}
	stmt, ok := ext[CommitmentExtNamespace]
	if !ok {
		return 0, "", refuse("statement_missing")
	}
	return selectFromObject(stmt)
}

// expectedCommitmentDigest recomputes the digest of c under the selected version ONLY (never both, never a
// fallback), applying that scheme's trailer rules. c.Trailers, when non-nil, is the only source of fields
// 10-12; a CertificateDigest / GoverningDocSha256 carried beside it must agree with it or the commitment is
// refused. With nil Trailers, v5 is exactly seamCommitmentDigest(c), and v6 reads it as a record with
// neither trailer (fields 10-12 0x00), so a GoverningDocSha256 or CertificateDigest beside it is refused:
// under v6 those fields only ever come from the trailers.
func expectedCommitmentDigest(version CommitmentVersion, c Commitment) (string, error) {
	switch version {
	case CommitmentV5:
		if c.Trailers == nil {
			return seamCommitmentDigest(c)
		}
		t, err := DecodeCommitmentTrailers(c.Trailers, SchemeV5)
		if err != nil {
			return "", err
		}
		if c.GoverningDocSha256 != nil && !bytes.Equal(c.GoverningDocSha256, t.GoverningDocSha256) {
			return "", refuse("governing_doc_disagrees_with_trailer")
		}
		cc := c
		cc.GoverningDocSha256 = t.GoverningDocSha256
		return seamCommitmentDigest(cc)
	case CommitmentV6:
		sel, err := selectionSlot(c)
		if err != nil {
			return "", err
		}
		f := CommitmentDigestFields{SelectionDigest: sel, GoverningDocSha256: c.GoverningDocSha256}
		// nil Trailers is a record with neither trailer: fields 10-12 come from the trailers only.
		t, err := DecodeCommitmentTrailers(c.Trailers, SchemeV6)
		if err != nil {
			return "", err
		}
		if c.GoverningDocSha256 != nil && !bytes.Equal(c.GoverningDocSha256, t.GoverningDocSha256) {
			return "", refuse("governing_doc_disagrees_with_trailer")
		}
		if c.CertificateDigest != nil && !bytes.Equal(c.CertificateDigest, t.GateDigest) {
			return "", refuse("gate_digest_disagrees_with_trailer")
		}
		f.GateDigest, f.GoverningDocSha256, f.Env = t.GateDigest, t.GoverningDocSha256, t.Env
		return CommitmentDigest(CommitmentV6, c, f)
	}
	return "", refuse("unknown_commitment_version")
}
