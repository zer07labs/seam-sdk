package crypto

// Deep-cleanup S-4 (seam-runtime #2031): the seal-key certificate vector and the regression guards for
// VerifyTCT's seal-key steps.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type sealKeyCertVector struct {
	Domain        string `json:"domain"`
	IssuerSeedHex string `json:"issuer_seed_hex"`
	IssuerAID     string `json:"issuer_aid"`
	SealSeedHex   string `json:"seal_seed_hex"`
	SealPKHex     string `json:"seal_pk_hex"`
	SealAID       string `json:"seal_aid"`
	NotBeforeMs   uint64 `json:"not_before_ms"`
	NotAfterMs    uint64 `json:"not_after_ms"`
	CertHex       string `json:"cert_hex"`
	CertDigestHex string `json:"cert_digest_hex"`
	SigHex        string `json:"sig_hex"`
	ExtMember     struct {
		Cert string `json:"cert"`
		Sig  string `json:"sig"`
	} `json:"ext_member"`
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSealKeyCertVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "seal_key_cert_vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v sealKeyCertVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Domain != SealKeyCertDomain {
		t.Fatalf("domain %q", v.Domain)
	}
	var pk [32]byte
	copy(pk[:], unhex(t, v.SealPKHex))
	if got := ed25519.NewKeyFromSeed(unhex(t, v.SealSeedHex)).Public().(ed25519.PublicKey); hex.EncodeToString(got) != v.SealPKHex {
		t.Fatal("seal_pk is not the seal seed's key")
	}
	issuerPub := ed25519.NewKeyFromSeed(unhex(t, v.IssuerSeedHex)).Public().(ed25519.PublicKey)
	if "aid:pubkey:"+b64urlNoPad(issuerPub) != v.IssuerAID {
		t.Fatal("issuer_aid is not the issuer seed's untagged AID")
	}
	cert := SealKeyCertPreimage(pk, v.NotBeforeMs, v.NotAfterMs, v.IssuerAID)
	if hex.EncodeToString(cert) != v.CertHex {
		t.Fatalf("cert bytes drifted:\n got %x\nwant %s", cert, v.CertHex)
	}
	d := sha256.Sum256(cert)
	if hex.EncodeToString(d[:]) != v.CertDigestHex {
		t.Fatal("cert digest")
	}
	sig := unhex(t, v.SigHex)
	if !ed25519VerifyStrict(issuerPub, d[:], sig) {
		t.Fatal("the issuer signature over sha256(cert) must verify")
	}
	if v.ExtMember.Cert != b64urlNoPad(cert) || v.ExtMember.Sig != b64urlNoPad(sig) {
		t.Fatal("ext_member is not the base64url of cert/sig")
	}
	f, ok := VerifySealKeyCert(v.IssuerAID, cert, sig)
	if !ok {
		t.Fatal("the vector must verify under its pinned issuer")
	}
	if f.SealPK != pk || f.NotBeforeMs != v.NotBeforeMs || f.NotAfterMs != v.NotAfterMs || f.IssuerAID != v.IssuerAID {
		t.Fatalf("parsed fields %+v", f)
	}
	if f.SealAID() != v.SealAID {
		t.Fatalf("seal AID %s, want %s", f.SealAID(), v.SealAID)
	}
	other := "aid:pubkey:" + b64urlNoPad(ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey))
	if _, ok := VerifySealKeyCert(other, cert, sig); ok {
		t.Fatal("another pinned issuer must refuse it")
	}
	for i := range cert {
		bad := append([]byte(nil), cert...)
		bad[i] ^= 1
		if _, ok := VerifySealKeyCert(v.IssuerAID, bad, sig); ok {
			t.Fatalf("flipped cert byte %d verified", i)
		}
	}
	for i := range sig {
		bad := append([]byte(nil), sig...)
		bad[i] ^= 1
		if _, ok := VerifySealKeyCert(v.IssuerAID, cert, bad); ok {
			t.Fatalf("flipped sig byte %d verified", i)
		}
	}
}

func TestSealKeyCertParseRefusals(t *testing.T) {
	var pk [32]byte
	pk[0] = 7
	c := SealKeyCertPreimage(pk, 10, 20, "aid:pubkey:x")
	if f, ok := ParseSealKeyCert(c); !ok || f.NotBeforeMs != 10 || f.NotAfterMs != 20 || f.IssuerAID != "aid:pubkey:x" {
		t.Fatal("round trip")
	}
	for cut := 0; cut < len(c); cut++ {
		if _, ok := ParseSealKeyCert(c[:cut]); ok {
			t.Fatalf("prefix %d parsed", cut)
		}
	}
	if _, ok := ParseSealKeyCert(append(append([]byte(nil), c...), 0)); ok {
		t.Fatal("trailing byte parsed")
	}
	for name, b := range map[string][]byte{
		"inverted":            SealKeyCertPreimage(pk, 21, 20, "a"),
		"beyond i64 max":      SealKeyCertPreimage(pk, 0, ^uint64(0), "a"),
		"one ms over the cap": SealKeyCertPreimage(pk, 1_700_000_000_000, 1_700_000_000_000+SealKeyMaxWindowMs+1, "a"),
		"aid over 62 bytes":   SealKeyCertPreimage(pk, 0, 1, "aid:pubkey:"+repeat("A", 52)),
		"aid not utf-8":       SealKeyCertPreimage(pk, 0, 1, "\xff"),
		"ticket intermediate": append(framed(nil, []byte("seam.ticket-intermediate.v1")), c[4+len(SealKeyCertDomain):]...),
	} {
		if _, ok := ParseSealKeyCert(b); ok {
			t.Fatalf("%s parsed", name)
		}
	}
	if _, ok := ParseSealKeyCert(SealKeyCertPreimage(pk, 1_700_000_000_000, 1_700_000_000_000+SealKeyMaxWindowMs, "aid:pubkey:"+repeat("A", 51))); !ok {
		t.Fatal("exactly the cap with a 62-byte AID must parse")
	}
	short := framed(nil, []byte(SealKeyCertDomain))
	short = framed(short, pk[:31])
	if _, ok := ParseSealKeyCert(short); ok {
		t.Fatal("a 31-byte key parsed")
	}
}

// sealOpts drive sealToken: the defaults mint a token VerifyTCT accepts at now = testIat + 1.
type sealOpts struct {
	nb, na        uint64
	iat           any
	certIssuerAID string
	certTrailing  bool
	issuerSeedHex string            // who signs the certificate
	certSealPub   ed25519.PublicKey // whom the certificate certifies
	signer        ed25519.PrivateKey
	member        func(m map[string]any)
	payload       func(p map[string]any)
}

const sealTestSeed = "0707070707070707070707070707070707070707070707070707070707070707"

func sealToken(t *testing.T, c Commitment, edit func(o *sealOpts)) (pinned, jws string) {
	t.Helper()
	seal := sealKeyFor(t, sealTestSeed)
	o := sealOpts{
		nb: testNotBeforeMs, na: testNotAfterMs, iat: testIat,
		certIssuerAID: issuerFromSeed(t, sealTestSeed), issuerSeedHex: sealTestSeed,
		certSealPub: seal.Public().(ed25519.PublicKey), signer: seal,
	}
	if edit != nil {
		edit(&o)
	}
	var pk [32]byte
	copy(pk[:], o.certSealPub)
	cert := SealKeyCertPreimage(pk, o.nb, o.na, o.certIssuerAID)
	if o.certTrailing {
		cert = append(cert, 0)
	}
	d := sha256.Sum256(cert)
	member := map[string]any{
		"cert": b64urlNoPad(cert),
		"sig":  b64urlNoPad(ed25519.Sign(ed25519.NewKeyFromSeed(seedBytes(t, o.issuerSeedHex)), d[:])),
	}
	if o.member != nil {
		o.member(member)
	}
	p := attestationPayload(t, sealTestSeed, c)
	signerPub := o.signer.Public().(ed25519.PublicKey)
	signerAID := "aid:pubkey:" + b64urlNoPad(signerPub)
	p["iss"], p["sub"], p["aud"] = signerAID, signerAID, signerAID
	p["cnf"] = map[string]any{"jkt": jwkThumbprint(signerPub)}
	p["iat"] = o.iat
	p["ext"].(map[string]any)[SealKeyCertExtKey] = member
	if o.payload != nil {
		o.payload(p)
	}
	raw, _ := json.Marshal(p)
	return issuerFromSeed(t, sealTestSeed), signRawWith(o.signer, raw)
}

func TestVerifyTCTSealKeyRules(t *testing.T) {
	c := load(t).TCT.Inputs.Commitment
	now := testIat + 1
	pinned, ok := sealToken(t, c, nil)
	if !VerifyTCT(pinned, ok, c, now) {
		t.Fatal("the control seal-key token must verify")
	}
	issuerKey := ed25519.NewKeyFromSeed(seedBytes(t, sealTestSeed))
	otherSeed := "0808080808080808080808080808080808080808080808080808080808080808"
	accept := map[string]func(o *sealOpts){
		"iat at not_before": func(o *sealOpts) { o.nb = uint64(testIat) * 1000; o.na = o.nb + 900_000 },
		"iat at not_after":  func(o *sealOpts) { o.na = uint64(testIat) * 1000; o.nb = o.na - 900_000 },
		"window exactly the cap": func(o *sealOpts) {
			o.nb = uint64(testIat) * 1000
			o.na = o.nb + SealKeyMaxWindowMs
		},
	}
	for name, edit := range accept {
		t.Run("accept/"+name, func(t *testing.T) {
			p, jws := sealToken(t, c, edit)
			if !VerifyTCT(p, jws, c, now) {
				t.Fatalf("%s must verify", name)
			}
		})
	}
	refuse := map[string]func(o *sealOpts){
		"window one ms over the cap": func(o *sealOpts) {
			o.nb = uint64(testIat) * 1000
			o.na = o.nb + SealKeyMaxWindowMs + 1
		},
		"iat one second before the window": func(o *sealOpts) { o.nb = uint64(testIat+1) * 1000; o.na = o.nb + 900_000 },
		"iat one second after the window":  func(o *sealOpts) { o.na = uint64(testIat-1) * 1000; o.nb = o.na - 900_000 },
		"iat a float spelling":             func(o *sealOpts) { o.iat = float64(testIat) + 0.5 },
		"iat a string":                     func(o *sealOpts) { o.iat = "1700000000" },
		"iat absent":                       func(o *sealOpts) { o.payload = func(p map[string]any) { delete(p, "iat") } },
		"iat overflows ms":                 func(o *sealOpts) { o.iat = int64(9_223_372_036_854_776) },
		"cert names another issuer (signed by it)": func(o *sealOpts) {
			o.issuerSeedHex = otherSeed
			o.certIssuerAID = issuerFromSeed(t, otherSeed)
		},
		"cert names the pinned issuer, signed by another": func(o *sealOpts) { o.issuerSeedHex = otherSeed },
		"cert names another issuer, signed by the pinned one": func(o *sealOpts) {
			o.certIssuerAID = issuerFromSeed(t, otherSeed)
		},
		"cert names the untagged form of the tagged pin": func(o *sealOpts) {
			o.certIssuerAID = "aid:pubkey:" + b64urlNoPad(issuerKey.Public().(ed25519.PublicKey))
		},
		"trailing cert bytes": func(o *sealOpts) { o.certTrailing = true },
		"cert for another seal key than the signer": func(o *sealOpts) {
			o.certSealPub = sealKeyFor(t, otherSeed).Public().(ed25519.PublicKey)
		},
		"member has a third key": func(o *sealOpts) { o.member = func(m map[string]any) { m["x"] = "y" } },
		"member lacks sig":       func(o *sealOpts) { o.member = func(m map[string]any) { delete(m, "sig") } },
		"member cert padded":     func(o *sealOpts) { o.member = func(m map[string]any) { m["cert"] = m["cert"].(string) + "=" } },
		"member sig std base64":  func(o *sealOpts) { o.member = func(m map[string]any) { m["sig"] = "+" + m["sig"].(string)[1:] } },
		"member cert not string": func(o *sealOpts) { o.member = func(m map[string]any) { m["cert"] = 1 } },
		"cert member absent": func(o *sealOpts) {
			o.payload = func(p map[string]any) { delete(p["ext"].(map[string]any), SealKeyCertExtKey) }
		},
		"an extra ext namespace": func(o *sealOpts) {
			o.payload = func(p map[string]any) { p["ext"].(map[string]any)["com.example"] = map[string]any{} }
		},
		"cnf is not the seal key": func(o *sealOpts) {
			o.payload = func(p map[string]any) { p["cnf"] = map[string]any{"jkt": jwkThumbprint(make([]byte, 32))} }
		},
		"cnf absent": func(o *sealOpts) { o.payload = func(p map[string]any) { delete(p, "cnf") } },
		"iss is the pinned issuer": func(o *sealOpts) {
			o.payload = func(p map[string]any) {
				pin := issuerFromSeed(t, sealTestSeed)
				p["iss"], p["sub"], p["aud"] = pin, pin, pin
			}
		},
		"signed by the issuer key, not the seal key": func(o *sealOpts) {
			o.signer = issuerKey
			o.certSealPub = sealKeyFor(t, sealTestSeed).Public().(ed25519.PublicKey)
		},
	}
	for name, edit := range refuse {
		t.Run("refuse/"+name, func(t *testing.T) {
			p, jws := sealToken(t, c, edit)
			if VerifyTCT(p, jws, c, now) {
				t.Fatalf("%s must be refused", name)
			}
		})
	}
}

// Every TCT minted before S-4 is a self-attestation by the issuer itself, with no certificate: refused
// (no backward compatibility).
func TestVerifyTCTRefusesAnIssuerSignedToken(t *testing.T) {
	c := load(t).TCT.Inputs.Commitment
	digest, err := seamCommitmentDigest(c)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seedBytes(t, sealTestSeed))
	pub := key.Public().(ed25519.PublicKey)
	for _, pin := range []string{"aid:pubkey:" + b64urlNoPad(pub), AIDFromPubkey(pub)} {
		p := map[string]any{
			"ver": "aitp/0.3", "iss": pin, "sub": pin, "aud": pin,
			"cnf": map[string]any{"jkt": jwkThumbprint(pub)}, "iat": testIat, "exp": 4853600000,
			"grants": []string{AttestationGrant},
			"ext": map[string]any{CommitmentExtNamespace: map[string]any{
				"type": CommitmentStatement, "commitment_digest": digest,
			}},
		}
		raw, _ := json.Marshal(p)
		if VerifyTCT(pin, signRawWith(key, raw), c, testIat+1) {
			t.Fatalf("an issuer-signed (pre-S-4) TCT verified under %s", pin)
		}
	}
}

// The certificate signature is checked like ed25519-dalek's verify_strict: a small-order R (or key)
// refuses even where crypto/ed25519 alone would accept.
func TestSealKeyCertSmallOrderRefused(t *testing.T) {
	if len(smallOrderEncodings) != 14 {
		t.Fatalf("%d small-order encodings", len(smallOrderEncodings))
	}
	// The identity point as R with S = 0 verifies under crypto/ed25519 for the identity key: R = [0]B +
	// [k]A = identity. verify_strict refuses it; so must we.
	identity := unhex(t, "0100000000000000000000000000000000000000000000000000000000000000")
	sig := append(append([]byte(nil), identity...), make([]byte, 32)...)
	msg := []byte("m")
	if !ed25519.Verify(ed25519.PublicKey(identity), msg, sig) {
		t.Skip("crypto/ed25519 already refuses the small-order forgery")
	}
	if ed25519VerifyStrict(identity, msg, sig) {
		t.Fatal("a small-order key and R must be refused")
	}
	// A real signature whose R is replaced by a small-order point is refused by the R check alone.
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	good := ed25519.Sign(key, msg)
	bad := append(append([]byte(nil), identity...), good[32:]...)
	if ed25519VerifyStrict(key.Public().(ed25519.PublicKey), msg, bad) {
		t.Fatal("a small-order R must be refused")
	}
	// A certificate under a small-order pinned key is refused end to end.
	var pk [32]byte
	cert := SealKeyCertPreimage(pk, 0, 1, "aid:pubkey:"+b64urlNoPad(identity))
	if _, ok := VerifySealKeyCert("aid:pubkey:"+b64urlNoPad(identity), cert, sig); ok {
		t.Fatal("a certificate under a small-order key with a small-order R must be refused")
	}
}
