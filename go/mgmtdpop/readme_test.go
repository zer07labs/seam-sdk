package mgmtdpop_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/zer07labs/seam-sdk/go/mgmtdpop"
)

// readmeDial holds the README's Go snippet verbatim, between the markers, so it compiles with every test
// run; python/tests/test_readme_dpop_snippets.py checks both READMEs still quote exactly these lines.
func readmeDial(target string, creds credentials.TransportCredentials) error {
	// README:dpop:begin
	key, err := mgmtdpop.ParseJWK([]byte(os.Getenv("SEAM_OPERATOR_DPOP_JWK")))
	if err != nil {
		return err
	}
	opts, err := mgmtdpop.DialOptions(key, os.Getenv("SEAM_OPERATOR_TOKEN"), "")
	if err != nil {
		return err
	}
	cc, err := grpc.NewClient(target, append(opts, grpc.WithTransportCredentials(creds))...)
	// README:dpop:end
	if err != nil {
		return err
	}
	return cc.Close()
}

func TestReadmeSnippetRuns(t *testing.T) {
	key, err := mgmtdpop.KeyFromSeed(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	jwk := `{"kty":"OKP","crv":"Ed25519","x":"` + key.X() + `","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`
	t.Setenv("SEAM_OPERATOR_DPOP_JWK", jwk)
	t.Setenv("SEAM_OPERATOR_TOKEN", boundToken(t, key.JKT()))
	if err := readmeDial("passthrough:///unused", insecure.NewCredentials()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SEAM_OPERATOR_TOKEN", boundToken(t, "another-key"))
	if err := readmeDial("passthrough:///unused", insecure.NewCredentials()); err == nil {
		t.Fatal("a token bound to another key must fail before any call")
	}
}

func boundToken(t *testing.T, jkt string) string {
	t.Helper()
	claims, err := json.Marshal(map[string]any{"aud": "seam-runtime", "cnf": map[string]any{"jkt": jkt}})
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	return b64([]byte(`{"alg":"EdDSA","typ":"JWT"}`)) + "." + b64(claims) + ".c2ln"
}
