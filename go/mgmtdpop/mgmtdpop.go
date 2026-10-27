// Package mgmtdpop signs management-plane DPoP proofs for a DPoP-bound operator token (seam-sdk#290).
//
// An operator token minted with a key binding (`cnf.jkt`) is refused as Bearer: every management call
// must carry `authorization: DPoP <token>` plus a fresh RFC 9449 proof — a compact JWS signed by the
// Ed25519 key the management console revealed once, next to the token. The proof binds the call
// (htm/htu), the token (ath) and the exact request bytes (seam_bd), and the runtime burns each proof on
// first use, so every attempt is signed anew.
//
// The grammar is docs/specs/mgmt-dpop.md (a pinned copy of the runtime's); conformance/mgmt_dpop_vector.json
// pins the bytes. Every string reaching a signed JSON object is printable ASCII, and the encoder runs with
// HTML escaping off, so the JSON here is byte-identical to every other SDK's.
package mgmtdpop

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultOperatorAud is the runtime's operator audience when SEAM_RUNTIME_AUD is unset — the
	// authority of every gRPC htu.
	DefaultOperatorAud = "seam-runtime"
	// MaxProofBytes: the runtime refuses a larger proof.
	MaxProofBytes = 8 * 1024
	// MaxBodyBytes: the runtime binds at most this much request body (HTTP) or message (gRPC).
	MaxBodyBytes = 1024 * 1024
	// MaxJTIBytes: the runtime refuses a longer jti.
	MaxJTIBytes = 256
	// MaxIAT is the largest iat every SDK accepts: 2^53 - 1, the largest integer a JavaScript number
	// holds exactly.
	MaxIAT = 1<<53 - 1
)

var (
	// ErrDpop is wrapped by every local refusal: an input the runtime would refuse, refused before any
	// network call. Never returned for a wire error.
	ErrDpop = errors.New("mgmtdpop")
	// ErrKey is wrapped (alongside ErrDpop) when the key, or the token it is meant to be bound to,
	// cannot work: a malformed JWK, an x that is not d's public key, or a cnf.jkt naming another key.
	ErrKey = fmt.Errorf("%w: key", ErrDpop)
)

func dpopErr(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrDpop}, a...)...)
}

func keyErr(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrKey}, a...)...)
}

var (
	b64        = base64.RawURLEncoding
	b64urlRe   = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
	tokenChars = regexp.MustCompile(`^[\x21-\x7e]+$`) // visible ASCII: a header value, no space
	printable  = regexp.MustCompile(`^[\x20-\x7e]+$`)
	methodRe   = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$") // RFC 9110 token
	digits15   = regexp.MustCompile(`^[0-9]{1,5}$`)
)

// compactJSON encodes v with no HTML escaping and no trailing newline.
func compactJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err) // only fixed structs of strings and integers reach here
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

func sha256b64(data []byte) string {
	sum := sha256.Sum256(data)
	return b64.EncodeToString(sum[:])
}

// PublicJWK is the public half, in the member order a proof header carries it.
type PublicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// Key is the Ed25519 key an operator token is bound to. Its private half is unexported and never
// formatted: String, GoString and fmt's %v/%+v/%#v print only the thumbprint.
type Key struct {
	priv ed25519.PrivateKey
	x    string
	jkt  string
}

// KeyFromSeed builds a Key from the raw 32-byte Ed25519 seed (the JWK's d, decoded). The bytes are copied.
func KeyFromSeed(seed []byte) (*Key, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, keyErr("an Ed25519 seed must be exactly 32 bytes")
	}
	priv := ed25519.NewKeyFromSeed(bytes.Clone(seed))
	x := b64.EncodeToString(priv.Public().(ed25519.PublicKey))
	// RFC 7638: SHA-256 over the required members in lexicographic order, no whitespace.
	jkt := sha256b64(compactJSON(struct {
		Crv string `json:"crv"`
		Kty string `json:"kty"`
		X   string `json:"x"`
	}{"Ed25519", "OKP", x}))
	return &Key{priv: priv, x: x, jkt: jkt}, nil
}

func b64url32(name string, v any) ([]byte, error) {
	s, ok := v.(string)
	if !ok {
		return nil, keyErr("JWK member %q must be a string", name)
	}
	if !b64urlRe.MatchString(s) || len(s)%4 == 1 {
		return nil, keyErr("JWK member %q must be unpadded base64url", name)
	}
	raw, err := b64.DecodeString(s)
	if err != nil {
		return nil, keyErr("JWK member %q must be unpadded base64url", name)
	}
	if len(raw) != 32 {
		return nil, keyErr("JWK member %q must decode to 32 bytes, got %d", name, len(raw))
	}
	// Stray low bits in the last character decode to the same bytes but a different thumbprint.
	if b64.EncodeToString(raw) != s {
		return nil, keyErr("JWK member %q is not canonical base64url", name)
	}
	return raw, nil
}

// ParseJWK loads a private OKP/Ed25519 JWK — the one the management console reveals once, next to the
// token. x is checked against the public key derived from d, so a reveal pasted with a typo fails here,
// by name. kid and other members that do not contradict an Ed25519 signing key are ignored.
func ParseJWK(data []byte) (*Key, error) {
	parsed, err := decodeJSON(data)
	if err != nil {
		return nil, keyErr("JWK is not valid JSON: %v", err)
	}
	m, ok := parsed.(map[string]any)
	if !ok {
		return nil, keyErr("JWK must be a JSON object")
	}
	if m["kty"] != "OKP" {
		return nil, keyErr(`JWK "kty" must be "OKP"`)
	}
	if m["crv"] != "Ed25519" {
		return nil, keyErr(`JWK "crv" must be "Ed25519"`)
	}
	if alg, has := m["alg"]; has && alg != "EdDSA" && alg != "Ed25519" {
		return nil, keyErr(`JWK "alg", when present, must be "EdDSA" or "Ed25519"`)
	}
	if use, has := m["use"]; has && use != "sig" {
		return nil, keyErr(`JWK "use", when present, must be "sig"`)
	}
	d, has := m["d"]
	if !has {
		return nil, keyErr(`JWK has no "d": a public JWK cannot sign proofs`)
	}
	x, has := m["x"]
	if !has {
		return nil, keyErr(`JWK has no "x"`)
	}
	seed, err := b64url32("d", d)
	if err != nil {
		return nil, err
	}
	if _, err := b64url32("x", x); err != nil {
		return nil, err
	}
	key, err := KeyFromSeed(seed)
	if err != nil {
		return nil, err
	}
	if key.x != x {
		return nil, keyErr(`JWK "x" is not the public key of its "d"`)
	}
	return key, nil
}

// X is the public key, unpadded base64url — the JWK's x.
func (k *Key) X() string { return k.x }

// JKT is the RFC 7638 thumbprint the runtime compares against the token's cnf.jkt.
func (k *Key) JKT() string { return k.jkt }

// PublicJWK returns the public JWK.
func (k *Key) PublicJWK() PublicJWK { return PublicJWK{"OKP", "Ed25519", k.x} }

// The formatting methods have value receivers, so a Key printed by value (*k, or a struct field of type
// Key) is covered as well as a *Key.

// String prints only the thumbprint.
func (k Key) String() string { return fmt.Sprintf("mgmtdpop.Key(jkt=%q)", k.jkt) }

// GoString prints only the thumbprint (fmt's %#v).
func (k Key) GoString() string { return k.String() }

// Format makes every fmt verb print only the thumbprint, so %+v cannot reach the private key.
func (k Key) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(k.String())) }

// MarshalJSON exposes only the thumbprint.
func (k Key) MarshalJSON() ([]byte, error) {
	return compactJSON(struct {
		JKT string `json:"jkt"`
	}{k.jkt}), nil
}

// NewJTI returns a fresh proof id: 16 random bytes as unpadded base64url (22 characters).
func NewJTI() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return b64.EncodeToString(b[:])
}

type proofOpts struct {
	iat    *int64
	jti    *string
	header PublicJWK
}

// Option overrides a proof default. Pass them only to reproduce a vector.
type Option func(*proofOpts)

// WithIAT sets iat (seconds). Default: now.
func WithIAT(iat int64) Option { return func(o *proofOpts) { o.iat = &iat } }

// WithJTI sets jti. Default: NewJTI().
func WithJTI(jti string) Option { return func(o *proofOpts) { o.jti = &jti } }

func checkToken(token string) error {
	if token == "" {
		return dpopErr("the operator token must be a non-empty string")
	}
	if !tokenChars.MatchString(token) {
		return dpopErr("the operator token must be printable ASCII with no spaces")
	}
	return nil
}

// Proof returns the compact-JWS proof for one management call. htm is the HTTP method ("POST" for every
// gRPC call); htu is the call's target as the runtime compares it (GRPCHTU or HTTPHTU); body is the exact
// HTTP body, or the protobuf-encoded request message without its 5-byte frame. Each proof is burned on
// first use: sign every attempt, retries included.
func Proof(key *Key, token, htm, htu string, body []byte, opts ...Option) (string, error) {
	if key == nil {
		return "", dpopErr("key must be a *mgmtdpop.Key")
	}
	if err := checkToken(token); err != nil {
		return "", err
	}
	if !methodRe.MatchString(htm) {
		return "", dpopErr("htm must be an HTTP method token")
	}
	if !printable.MatchString(htu) {
		return "", dpopErr("htu must be a non-empty printable-ASCII string")
	}
	if len(body) > MaxBodyBytes {
		return "", dpopErr("the request body is %d bytes; the runtime binds at most %d and refuses a larger one", len(body), MaxBodyBytes)
	}
	var o proofOpts
	for _, opt := range opts {
		opt(&o)
	}
	iat := time.Now().Unix()
	if o.iat != nil {
		iat = *o.iat
	}
	if iat < 0 || iat > MaxIAT {
		return "", dpopErr("iat must be a non-negative integer number of seconds")
	}
	jti := NewJTI()
	if o.jti != nil {
		jti = *o.jti
	}
	if !printable.MatchString(jti) {
		return "", dpopErr("jti must be a non-empty printable-ASCII string")
	}
	if len(jti) > MaxJTIBytes {
		return "", dpopErr("jti must be at most %d bytes", MaxJTIBytes)
	}

	header := compactJSON(struct {
		Typ string    `json:"typ"`
		Alg string    `json:"alg"`
		JWK PublicJWK `json:"jwk"`
	}{"dpop+jwt", "EdDSA", key.PublicJWK()})
	claims := compactJSON(struct {
		JTI    string `json:"jti"`
		HTM    string `json:"htm"`
		HTU    string `json:"htu"`
		IAT    int64  `json:"iat"`
		ATH    string `json:"ath"`
		SeamBD string `json:"seam_bd"`
	}{jti, htm, htu, iat, sha256b64([]byte(token)), sha256b64(body)})
	signingInput := b64.EncodeToString(header) + "." + b64.EncodeToString(claims)
	proof := signingInput + "." + b64.EncodeToString(ed25519.Sign(key.priv, []byte(signingInput)))
	if len(proof) > MaxProofBytes {
		return "", dpopErr("the proof is %d bytes; the runtime refuses one over %d", len(proof), MaxProofBytes)
	}
	return proof, nil
}

// GRPCHTU returns grpc://<aud><full method>, e.g. grpc://seam-runtime/seam.api.v1.SeamAdmin/EnrollTenant.
// aud is the runtime's operator audience, not the dialled address.
func GRPCHTU(method, aud string) (string, error) {
	if !strings.HasPrefix(method, "/") || !printable.MatchString(method) {
		return "", dpopErr(`method must be a full gRPC method path such as "/pkg.Service/Method"`)
	}
	if !tokenChars.MatchString(aud) || strings.Contains(aud, "/") {
		return "", dpopErr("aud must be a non-empty printable-ASCII string with no spaces or '/'")
	}
	return "grpc://" + aud + method, nil
}

// HTTPHTU returns the htu the runtime compares an HTTP management call against: https://<authority><path>.
//
// The scheme becomes https, the host is lower-cased, a default port (:443 for https, :80 for http) is
// dropped, and the query and fragment are dropped. The path is kept exactly; an empty one becomes "/".
// A URL carrying userinfo is refused. This is an explicit grammar, not net/url (which normalises), so
// every SDK derives the same htu from the same string: scheme "://" authority [path] ["?" query]
// ["#" fragment], authority = host [":" port], host a reg-name or a bracketed IPv6 literal, port 1-5
// digits. Send the request to exactly this URL: a client that rewrites the path (dot-segments,
// percent-encoding) sends a path the htu does not name, and the runtime refuses the proof.
func HTTPHTU(rawURL string) (string, error) {
	if !tokenChars.MatchString(rawURL) {
		return "", dpopErr("url must be a non-empty visible-ASCII string (no spaces)")
	}
	scheme, rest, found := strings.Cut(rawURL, "://")
	scheme = strings.ToLower(scheme)
	if !found || (scheme != "http" && scheme != "https") {
		return "", dpopErr("url must be an absolute http:// or https:// URL")
	}
	cut := len(rest)
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		cut = i
	}
	authority, tail := rest[:cut], rest[cut:]
	path := tail
	if i := strings.IndexAny(tail, "?#"); i >= 0 {
		path = tail[:i]
	}
	if strings.Contains(authority, "@") {
		return "", dpopErr("url must not carry userinfo")
	}
	var host, portText string
	if strings.HasPrefix(authority, "[") {
		closeAt := strings.Index(authority, "]")
		if closeAt < 2 {
			return "", dpopErr("url has a malformed IPv6 literal")
		}
		host = authority[:closeAt+1]
		after := authority[closeAt+1:]
		if after != "" && !strings.HasPrefix(after, ":") {
			return "", dpopErr("url has a malformed IPv6 literal")
		}
		if after != "" {
			portText = after[1:]
		}
	} else {
		var hasColon bool
		host, portText, hasColon = strings.Cut(authority, ":")
		if hasColon && strings.Contains(portText, ":") {
			return "", dpopErr("url has more than one ':' in its authority; bracket an IPv6 literal")
		}
	}
	if host == "" {
		return "", dpopErr("url has no host")
	}
	host = strings.ToLower(host)
	auth := host
	if portText != "" {
		if !digits15.MatchString(portText) {
			return "", dpopErr("url has an invalid port")
		}
		port, _ := strconv.Atoi(portText)
		if port > 65535 {
			return "", dpopErr("url has an invalid port")
		}
		def := 80
		if scheme == "https" {
			def = 443
		}
		if port != def {
			auth = host + ":" + strconv.Itoa(port)
		}
	}
	if path == "" {
		path = "/"
	}
	return "https://" + auth + path, nil
}

// HTTPHeaders returns the two headers for one call to the HTTP management plane: Authorization
// ("DPoP <token>") and DPoP (the proof). Send exactly body as the request body (empty for a GET), to
// exactly rawURL. Call this once per request — never reuse the headers for a retry.
func HTTPHeaders(key *Key, token, method, rawURL string, body []byte, opts ...Option) (map[string]string, error) {
	htu, err := HTTPHTU(rawURL)
	if err != nil {
		return nil, err
	}
	proof, err := Proof(key, token, method, htu, body, opts...)
	if err != nil {
		return nil, err
	}
	return map[string]string{"Authorization": "DPoP " + token, "DPoP": proof}, nil
}

// peekTokenClaims decodes the operator token's claims WITHOUT verifying it — local diagnostics only;
// the runtime is the verifier.
func peekTokenClaims(token string) (map[string]any, error) {
	if err := checkToken(token); err != nil {
		return nil, err
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || !b64urlRe.MatchString(parts[1]) || len(parts[1])%4 == 1 {
		return nil, keyErr("the operator token is not a compact JWS")
	}
	raw, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, keyErr("the operator token is not a compact JWS")
	}
	payload, err := decodeJSON(raw)
	if err != nil {
		return nil, keyErr("the operator token's payload is not JSON")
	}
	m, ok := payload.(map[string]any)
	if !ok {
		return nil, keyErr("the operator token's payload is not a JSON object")
	}
	return m, nil
}

// decodeJSON reads exactly one JSON value. Numbers stay json.Number, so 1e400 is accepted as Python and TS
// accept it.
func decodeJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the JSON value")
	}
	return v, nil
}

// tokenCnfJkt returns cnf.jkt, "" with ok=false when the token is unbound.
func tokenCnfJkt(claims map[string]any) (string, bool, error) {
	cnf, has := claims["cnf"]
	if !has || cnf == nil {
		return "", false, nil
	}
	m, ok := cnf.(map[string]any)
	if !ok {
		return "", false, keyErr("the operator token's cnf claim is malformed")
	}
	jkt, ok := m["jkt"].(string)
	if !ok {
		return "", false, keyErr("the operator token's cnf claim is malformed")
	}
	return jkt, true, nil
}
