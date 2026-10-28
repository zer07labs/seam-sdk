package mgmtdpop

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mgmtDpopVector mirrors conformance/mgmt_dpop_vector.json — the cross-language contract every SDK's
// signer reproduces byte for byte.
type mgmtDpopVector struct {
	Golden struct {
		SeedHex    string          `json:"seed_hex"`
		JWK        json.RawMessage `json:"jwk"`
		HTM        string          `json:"htm"`
		Method     string          `json:"method"`
		Aud        string          `json:"aud"`
		HTU        string          `json:"htu"`
		Token      string          `json:"token"`
		MessageHex string          `json:"message_hex"`
		IAT        int64           `json:"iat"`
		JTI        string          `json:"jti"`
		JKT        string          `json:"jkt"`
		X          string          `json:"x"`
		ATH        string          `json:"ath"`
		SeamBD     string          `json:"seam_bd"`
		HeaderJSON string          `json:"header_json"`
		ClaimsJSON string          `json:"claims_json"`
		Proof      string          `json:"proof"`
	} `json:"golden"`
	Derived []struct {
		Name       string `json:"name"`
		URL        string `json:"url"`
		HTM        string `json:"htm"`
		HTU        string `json:"htu"`
		MessageHex string `json:"message_hex"`
		IAT        int64  `json:"iat"`
		JTI        string `json:"jti"`
		SeamBD     string `json:"seam_bd"`
		Proof      string `json:"proof"`
	} `json:"derived"`
	GRPCHTU []struct {
		Method string `json:"method"`
		Aud    string `json:"aud"`
		HTU    string `json:"htu"`
	} `json:"grpc_htu"`
	HTTPHTU []struct {
		URL string `json:"url"`
		HTU string `json:"htu"`
	} `json:"http_htu"`
	HTTPHTURejects []struct {
		URL    string `json:"url"`
		Reason string `json:"reason"`
	} `json:"http_htu_rejects"`
	JWKRejects []struct {
		Reason string          `json:"reason"`
		JWK    json.RawMessage `json:"jwk"`
	} `json:"jwk_rejects"`
	JWKAccepts []struct {
		Reason string          `json:"reason"`
		JWK    json.RawMessage `json:"jwk"`
	} `json:"jwk_accepts"`
	IATMax int64 `json:"iat_max"`
}

func loadVector(t *testing.T) mgmtDpopVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "mgmt_dpop_vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v mgmtDpopVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Derived) < 5 || len(v.JWKRejects) < 10 || len(v.HTTPHTU) < 5 || len(v.HTTPHTURejects) < 3 {
		t.Fatal("vector is truncated")
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func goldenKey(t *testing.T, v mgmtDpopVector) *Key {
	t.Helper()
	k, err := KeyFromSeed(mustHex(t, v.Golden.SeedHex))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func segment(t *testing.T, proof string, i int) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(proof, ".")[i])
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// ── the golden vector ──────────────────────────────────────────────────────────────────────────

func TestGoldenKeyAndThumbprint(t *testing.T) {
	v := loadVector(t)
	k := goldenKey(t, v)
	if k.X() != v.Golden.X || k.JKT() != v.Golden.JKT {
		t.Fatalf("x=%s jkt=%s", k.X(), k.JKT())
	}
	fromJWK, err := ParseJWK(v.Golden.JWK)
	if err != nil || fromJWK.JKT() != v.Golden.JKT {
		t.Fatalf("ParseJWK: %v", err)
	}
}

func TestGoldenProofIsByteExact(t *testing.T) {
	v := loadVector(t)
	g := v.Golden
	htu, err := GRPCHTU(g.Method, g.Aud)
	if err != nil || htu != g.HTU {
		t.Fatalf("htu %q: %v", htu, err)
	}
	proof, err := Proof(goldenKey(t, v), g.Token, g.HTM, htu, mustHex(t, g.MessageHex), WithIAT(g.IAT), WithJTI(g.JTI))
	if err != nil {
		t.Fatal(err)
	}
	if proof != g.Proof {
		t.Fatalf("proof differs:\n got %s\nwant %s", proof, g.Proof)
	}
	if segment(t, proof, 0) != g.HeaderJSON || segment(t, proof, 1) != g.ClaimsJSON {
		t.Fatal("header or claims JSON differs")
	}
	var claims map[string]any
	_ = json.Unmarshal([]byte(g.ClaimsJSON), &claims)
	if claims["ath"] != g.ATH || claims["seam_bd"] != g.SeamBD {
		t.Fatal("ath or seam_bd differs")
	}
}

func TestSeedIsCopied(t *testing.T) {
	v := loadVector(t)
	seed := mustHex(t, v.Golden.SeedHex)
	k, _ := KeyFromSeed(seed)
	seed[0] ^= 1
	g := v.Golden
	proof, _ := Proof(k, g.Token, g.HTM, g.HTU, mustHex(t, g.MessageHex), WithIAT(g.IAT), WithJTI(g.JTI))
	if proof != g.Proof {
		t.Fatal("mutating the caller's seed changed the key")
	}
}

func TestDerivedProofs(t *testing.T) {
	v := loadVector(t)
	k := goldenKey(t, v)
	for _, c := range v.Derived {
		t.Run(c.Name, func(t *testing.T) {
			body := mustHex(t, c.MessageHex)
			var proof string
			if c.URL != "" {
				htu, err := HTTPHTU(c.URL)
				if err != nil || htu != c.HTU {
					t.Fatalf("htu %q: %v", htu, err)
				}
				h, err := HTTPHeaders(k, v.Golden.Token, c.HTM, c.URL, body, WithIAT(c.IAT), WithJTI(c.JTI))
				if err != nil {
					t.Fatal(err)
				}
				if h["Authorization"] != "DPoP "+v.Golden.Token {
					t.Fatal(h["Authorization"])
				}
				proof = h["DPoP"]
			} else {
				var err error
				proof, err = Proof(k, v.Golden.Token, c.HTM, c.HTU, body, WithIAT(c.IAT), WithJTI(c.JTI))
				if err != nil {
					t.Fatal(err)
				}
			}
			if proof != c.Proof {
				t.Fatalf("proof differs:\n got %s\nwant %s", proof, c.Proof)
			}
		})
	}
}

func TestGRPCHTUCases(t *testing.T) {
	for _, c := range loadVector(t).GRPCHTU {
		if got, err := GRPCHTU(c.Method, c.Aud); err != nil || got != c.HTU {
			t.Errorf("GRPCHTU(%q, %q) = %q, %v; want %q", c.Method, c.Aud, got, err, c.HTU)
		}
	}
}

func TestHTTPHTUCases(t *testing.T) {
	v := loadVector(t)
	for _, c := range v.HTTPHTU {
		if got, err := HTTPHTU(c.URL); err != nil || got != c.HTU {
			t.Errorf("HTTPHTU(%q) = %q, %v; want %q", c.URL, got, err, c.HTU)
		}
	}
	for _, c := range v.HTTPHTURejects {
		_, err := HTTPHTU(c.URL)
		if !errors.Is(err, ErrDpop) {
			t.Errorf("HTTPHTU(%.80q) [%s]: want ErrDpop, got %v", c.URL, c.Reason, err)
		}
	}
}

func TestJWKRejectsAndAccepts(t *testing.T) {
	v := loadVector(t)
	for _, c := range v.JWKRejects {
		if _, err := ParseJWK(c.JWK); !errors.Is(err, ErrKey) {
			t.Errorf("[%s] want ErrKey, got %v", c.Reason, err)
		}
	}
	for _, c := range v.JWKAccepts {
		k, err := ParseJWK(c.JWK)
		if err != nil || k.JKT() != v.Golden.JKT {
			t.Errorf("[%s] %v", c.Reason, err)
		}
	}
	for _, text := range []string{"{kty: OKP", "[]", "null", `"s"`} {
		if _, err := ParseJWK([]byte(text)); !errors.Is(err, ErrKey) {
			t.Errorf("%q: want ErrKey, got %v", text, err)
		}
	}
}

// ── local refusals: an input the runtime would refuse never reaches the wire ───────────────────────

func TestProofRefusals(t *testing.T) {
	v := loadVector(t)
	k := goldenKey(t, v)
	ok := func(opts ...Option) error {
		_, err := Proof(k, "a.b.c", "POST", "grpc://seam-runtime/m", nil, opts...)
		return err
	}
	if err := ok(WithIAT(v.IATMax)); err != nil || v.IATMax != MaxIAT {
		t.Fatalf("iat_max: %v", err)
	}
	if err := ok(WithJTI(strings.Repeat("j", MaxJTIBytes))); err != nil {
		t.Fatal(err)
	}
	cases := map[string]error{
		"nil key":         func() error { _, e := Proof(nil, "a.b.c", "POST", "grpc://a/m", nil); return e }(),
		"empty token":     func() error { _, e := Proof(k, "", "POST", "grpc://a/m", nil); return e }(),
		"token space":     func() error { _, e := Proof(k, "a b", "POST", "grpc://a/m", nil); return e }(),
		"token non-ascii": func() error { _, e := Proof(k, "a.é.c", "POST", "grpc://a/m", nil); return e }(),
		"htm":             func() error { _, e := Proof(k, "a.b.c", "PO ST", "grpc://a/m", nil); return e }(),
		"htm empty":       func() error { _, e := Proof(k, "a.b.c", "", "grpc://a/m", nil); return e }(),
		"htu empty":       func() error { _, e := Proof(k, "a.b.c", "POST", "", nil); return e }(),
		"htu control":     func() error { _, e := Proof(k, "a.b.c", "POST", "grpc://a/m\n", nil); return e }(),
		"body":            func() error { _, e := Proof(k, "a.b.c", "POST", "grpc://a/m", make([]byte, MaxBodyBytes+1)); return e }(),
		"iat negative":    ok(WithIAT(-1)),
		"iat over":        ok(WithIAT(MaxIAT + 1)),
		"jti empty":       ok(WithJTI("")),
		"jti long":        ok(WithJTI(strings.Repeat("j", MaxJTIBytes+1))),
		"jti non-ascii":   ok(WithJTI("é")),
		"proof size": func() error {
			_, e := Proof(k, "a.b.c", "POST", "grpc://a/"+strings.Repeat("m", MaxProofBytes), nil)
			return e
		}(),
		"grpc method":    func() error { _, e := GRPCHTU("noslash", "seam-runtime"); return e }(),
		"grpc aud":       func() error { _, e := GRPCHTU("/m", "a/b"); return e }(),
		"grpc aud empty": func() error { _, e := GRPCHTU("/m", ""); return e }(),
	}
	for name, err := range cases {
		if !errors.Is(err, ErrDpop) {
			t.Errorf("%s: want ErrDpop, got %v", name, err)
		}
		if errors.Is(err, ErrKey) {
			t.Errorf("%s: a bad argument is not a key error", name)
		}
	}
	if err := ok(WithIAT(0)); err != nil {
		t.Fatal(err)
	}
	if _, err := KeyFromSeed(make([]byte, 31)); !errors.Is(err, ErrKey) {
		t.Fatal(err)
	}
	if _, err := Proof(k, "a.b.c", "POST", "grpc://a/m", make([]byte, MaxBodyBytes)); err != nil {
		t.Fatal(err)
	}
}

func TestFreshProofsVerify(t *testing.T) {
	k := goldenKey(t, loadVector(t))
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		p, err := Proof(k, "a.b.c", "POST", "grpc://seam-runtime/m", []byte{1})
		if err != nil {
			t.Fatal(err)
		}
		at := strings.LastIndex(p, ".")
		sig, _ := base64.RawURLEncoding.DecodeString(p[at+1:])
		pub, _ := base64.RawURLEncoding.DecodeString(k.X())
		if !ed25519.Verify(pub, []byte(p[:at]), sig) {
			t.Fatal("signature does not verify")
		}
		var claims struct{ JTI string }
		_ = json.Unmarshal([]byte(segment(t, p, 1)), &claims)
		if len(claims.JTI) != 22 || seen[claims.JTI] {
			t.Fatalf("jti %q", claims.JTI)
		}
		seen[claims.JTI] = true
	}
}

// ── the private half is never formatted ────────────────────────────────────────────────────────

func TestKeyNeverFormatsItsPrivateHalf(t *testing.T) {
	v := loadVector(t)
	k := goldenKey(t, v)
	seed := mustHex(t, v.Golden.SeedHex)
	j, _ := json.Marshal(k)
	outs := []string{
		fmt.Sprint(k), fmt.Sprintf("%v %+v %#v %s %q %x", k, k, k, k, k, k), k.String(), k.GoString(), string(j),
		fmt.Sprintf("%v", struct{ K *Key }{k}), fmt.Sprintf("%+v", []*Key{k}),
		fmt.Sprintf("%v %+v %#v", *k, *k, *k), fmt.Sprintf("%+v %#v", struct{ K Key }{*k}, struct{ K Key }{*k}),
		fmt.Sprintf("%v", []Key{*k}),
	}
	dB64 := base64.RawURLEncoding.EncodeToString(seed)
	for _, out := range outs {
		if strings.Contains(out, dB64) || strings.Contains(out, hex.EncodeToString(seed)) ||
			bytes.Contains([]byte(out), seed) || strings.Contains(out, "4242") {
			t.Fatalf("formatted output leaks the seed: %s", out)
		}
		if !strings.Contains(out, k.JKT()) {
			t.Fatalf("formatted output lost the thumbprint: %s", out)
		}
	}
}
