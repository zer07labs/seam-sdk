package identity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zer07labs/seam-sdk/go/crypto"
)

// Mirrors python/tests/test_identity_file.py (seam-sdk#201).

const (
	agentID  = "ap-clerk"
	tenant   = "acme"
	endpoint = "seam.example:443"
)

func mustCreate(t *testing.T, path string) (string, string) {
	t.Helper()
	p, aid, err := CreateIdentityFile(path, agentID, tenant, endpoint)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return p, aid
}

func asIdentityErr(t *testing.T, err error, want string) {
	t.Helper()
	var ie *IdentityFileError
	if !errors.As(err, &ie) {
		t.Fatalf("want *IdentityFileError, got %T: %v", err, err)
	}
	if !strings.Contains(ie.Error(), want) {
		t.Fatalf("error %q does not mention %q", ie.Error(), want)
	}
}

func TestGenerateIs32FreshCSPRNGBytes(t *testing.T) {
	a, _ := crypto.GenerateAgent()
	b, _ := crypto.GenerateAgent()
	if len(a.Seed()) != 32 || bytes.Equal(a.Seed(), b.Seed()) || a.AID() == b.AID() {
		t.Fatal("two generated agents must be distinct 32-byte seeds")
	}
}

func TestRoundTripAIDEquality(t *testing.T) {
	path, aid := mustCreate(t, filepath.Join(t.TempDir(), "id.json"))
	loaded, err := LoadIdentityFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AID() != aid || loaded.Agent.AID() != aid {
		t.Fatalf("aid mismatch: %s vs %s", loaded.AID(), aid)
	}
	if loaded.AgentID != agentID || loaded.Tenant != tenant || loaded.Endpoint != endpoint {
		t.Fatalf("fields: %+v", loaded)
	}
}

func TestCreateNeverReturnsTheSeed(t *testing.T) {
	path, aid := mustCreate(t, filepath.Join(t.TempDir(), "id.json"))
	var data map[string]any
	raw, _ := os.ReadFile(path)
	_ = json.Unmarshal(raw, &data)
	seedHex := data["seed_hex"].(string)
	if strings.Contains(path, seedHex) || strings.Contains(aid, seedHex) {
		t.Fatal("the seed leaked into a return value")
	}
}

func TestPrintingNeverShowsTheSeed(t *testing.T) {
	path, _ := mustCreate(t, filepath.Join(t.TempDir(), "id.json"))
	loaded, _ := LoadIdentityFile(path)
	seedHex := hex.EncodeToString(loaded.Agent.Seed())
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
		for _, v := range []any{loaded, loaded.Agent, *loaded} {
			out := fmt.Sprintf(verb, v)
			if strings.Contains(strings.ToLower(out), seedHex) {
				t.Fatalf("%s of %T printed the seed: %s", verb, v, out)
			}
		}
	}
	if j, _ := json.Marshal(loaded.Agent); strings.Contains(string(j), seedHex) {
		t.Fatalf("json of Agent printed the seed: %s", j)
	}
}

func TestFileIsSchemaV1WithTheAdaptersFieldNames(t *testing.T) {
	path, _ := mustCreate(t, filepath.Join(t.TempDir(), "id.json"))
	raw, _ := os.ReadFile(path)
	dec := json.NewDecoder(bytes.NewReader(raw))
	_, _ = dec.Token()
	var keys []string
	for dec.More() {
		k, _ := dec.Token()
		keys = append(keys, k.(string))
		var skip any
		_ = dec.Decode(&skip)
	}
	if strings.Join(keys, ",") != "version,seed_hex,agent_id,tenant,endpoint,aid" {
		t.Fatalf("keys: %v", keys)
	}
	var data map[string]any
	_ = json.Unmarshal(raw, &data)
	if data["version"].(float64) != 1 || len(data["seed_hex"].(string)) != 64 {
		t.Fatalf("data: %v", data)
	}
}

func TestSecondCreateRefusesAndLeavesBytesUnchanged(t *testing.T) {
	path, _ := mustCreate(t, filepath.Join(t.TempDir(), "id.json"))
	before, _ := os.ReadFile(path)
	_, _, err := CreateIdentityFile(path, agentID, tenant, endpoint)
	asIdentityErr(t, err, "refusing to overwrite")
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("existing file was modified")
	}
}

func TestSymlinkAtTheTargetIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	for _, dangling := range []bool{false, true} {
		dir := t.TempDir()
		target := filepath.Join(dir, "elsewhere.json")
		if !dangling {
			_ = os.WriteFile(target, []byte("untouched"), 0o644)
		}
		link := filepath.Join(dir, "id.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		_, _, err := CreateIdentityFile(link, agentID, tenant, endpoint)
		asIdentityErr(t, err, "refusing to overwrite")
		if st, _ := os.Lstat(link); st.Mode()&os.ModeSymlink == 0 {
			t.Fatal("symlink replaced")
		}
		got, err := os.ReadFile(target)
		if dangling && err == nil {
			t.Fatal("dangling symlink target was created")
		}
		if !dangling && string(got) != "untouched" {
			t.Fatal("symlink target was written through")
		}
	}
}

func TestNoTempFileIsLeftBehind(t *testing.T) {
	dir := t.TempDir()
	path, _ := mustCreate(t, filepath.Join(dir, "id.json"))
	_, _, err := CreateIdentityFile(path, agentID, tenant, endpoint)
	asIdentityErr(t, err, "refusing")
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "id.json" {
		t.Fatalf("dir: %v", entries)
	}
}

func TestEmptyFieldIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	for _, field := range []string{"agent_id", "tenant", "endpoint"} {
		dir := t.TempDir()
		a, tn, e := agentID, tenant, endpoint
		switch field {
		case "agent_id":
			a = ""
		case "tenant":
			tn = ""
		case "endpoint":
			e = ""
		}
		_, _, err := CreateIdentityFile(filepath.Join(dir, "id.json"), a, tn, e)
		asIdentityErr(t, err, field)
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Fatalf("%s: wrote %v", field, entries)
		}
	}
}

func TestAnExistingAdaptersFileStillLoads(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	p := filepath.Join(t.TempDir(), "partner.json")
	raw := fmt.Sprintf(`{"version": 1, "seed_hex": %q, "agent_id": "qa-confirm", "tenant": "t1", "endpoint": "localhost:50051", "comment": "extra keys are ignored"}`, hex.EncodeToString(seed))
	_ = os.WriteFile(p, []byte(raw), 0o600)
	loaded, err := LoadIdentityFile(p)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := crypto.NewAgent(seed)
	if !bytes.Equal(loaded.Agent.Seed(), seed) || loaded.AID() != want.AID() {
		t.Fatal("adapters-shaped file did not load to the same agent")
	}
}

func TestEnvPointerIsReadWhenNoPathIsGiven(t *testing.T) {
	path, aid := mustCreate(t, filepath.Join(t.TempDir(), "id.json"))
	t.Setenv(EnvPointer, path)
	loaded, err := LoadIdentityFile("")
	if err != nil || loaded.AID() != aid {
		t.Fatalf("env load: %v", err)
	}
	t.Setenv(EnvPointer, "")
	_, err = LoadIdentityFile("")
	asIdentityErr(t, err, EnvPointer)
}

func TestMalformedFilesAreLoud(t *testing.T) {
	for _, c := range []struct{ body, want string }{
		{`{"version": 2}`, "version"},
		{`{"version": 1, "seed_hex": "ab"}`, "64 hex"},
		{`{"version": 1, "seed_hex": "` + strings.Repeat("zz", 32) + `"}`, "not valid hex"},
		{`{"version": 1, "seed_hex": "` + strings.Repeat("ab", 32) + `", "agent_id": "a", "tenant": "t"}`, "endpoint"},
		{`[1, 2]`, "JSON object"},
		{`{not json`, "not valid JSON"},
	} {
		p := filepath.Join(t.TempDir(), "bad.json")
		_ = os.WriteFile(p, []byte(c.body), 0o600)
		_, err := LoadIdentityFile(p)
		asIdentityErr(t, err, c.want)
	}
}

func TestMissingFileIsLoud(t *testing.T) {
	_, err := LoadIdentityFile(filepath.Join(t.TempDir(), "nope.json"))
	asIdentityErr(t, err, "not found")
}

// seam-sdk#274 (D-AID-RECORD): a created file records its AID; a recorded aid is verified on load.

const (
	fixtureSeedHex = "ddc1524b29efe5bc1b9e9ea141b2a4740ba3e4d52f781afa3c1ffb3a3970580c"
	fixtureAID     = "aid:pubkey:ed25519:9x_uM2PCzXE8pt6di2RwwKCkod7W5kctdLdoIVtKep4"
)

func TestCreatedFileRecordsTheReturnedAID(t *testing.T) {
	path, aid := mustCreate(t, filepath.Join(t.TempDir(), "id.json"))
	raw, _ := os.ReadFile(path)
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(data["seed_hex"].(string))
	derived, _ := crypto.NewAgent(seed)
	if data["aid"] != aid || derived.AID() != aid {
		t.Fatalf("recorded aid %v, returned %s, derived %s", data["aid"], aid, derived.AID())
	}
}

func writeWithAID(t *testing.T, aid any) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"version": 1, "seed_hex": fixtureSeedHex, "agent_id": "a", "tenant": "t", "endpoint": "e:1", "aid": aid,
	})
	p := filepath.Join(t.TempDir(), "id.json")
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestABadRecordedAIDIsRefused(t *testing.T) {
	other := make([]byte, 32)
	for i := range other {
		other[i] = byte(i)
	}
	otherAgent, _ := crypto.NewAgent(other)
	for _, c := range []struct {
		name string
		aid  any
		want string
	}{
		{"mismatch", otherAgent.AID(), "recorded aid does not match seed_hex"},
		{"short", fixtureAID[:len(fixtureAID)-1], "aid is malformed"},
		{"long", fixtureAID + "A", "aid is malformed"},
		{"wrong-alg", strings.Replace(fixtureAID, "ed25519", "ed448", 1), "aid is malformed"},
		{"non-b64url", fixtureAID[:len(fixtureAID)-1] + "=", "aid is malformed"},
		{"empty", "", "aid is malformed"},
		{"null", nil, "aid is malformed"},
		{"number", 42, "aid is malformed"},
		{"list", []string{fixtureAID}, "aid is malformed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadIdentityFile(writeWithAID(t, c.aid))
			var ie *IdentityFileError
			if !errors.As(err, &ie) || ie.Error() != c.want {
				t.Fatalf("want IdentityFileError %q, got %T: %v", c.want, err, err)
			}
		})
	}
}

func TestAMatchingRecordedAIDLoads(t *testing.T) {
	loaded, err := LoadIdentityFile(writeWithAID(t, fixtureAID))
	if err != nil || loaded.AID() != fixtureAID {
		t.Fatalf("load: %v", err)
	}
}

func TestTheSharedAIDFixtureLoadsWithItsRecordedAID(t *testing.T) {
	// Written by Python's create_identity_file (seam-sdk#274); the TS suite pins its bytes.
	p := filepath.Join("..", "..", "ts", "tests", "fixtures", "identity_v1_aid_python.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil || data["aid"] != fixtureAID {
		t.Fatalf("fixture aid: %v %v", data["aid"], err)
	}
	loaded, err := LoadIdentityFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.AID() != fixtureAID || hex.EncodeToString(loaded.Agent.Seed()) != fixtureSeedHex {
		t.Fatalf("aid %s", loaded.AID())
	}
	if loaded.AgentID != "ap-clerk" || loaded.Tenant != "acm\u00e9" || loaded.Endpoint != "seam.example:443" {
		t.Fatalf("fields: %+v", loaded)
	}
}

func TestALegacyFileWithoutAIDLoadsUnchanged(t *testing.T) {
	p := filepath.Join(t.TempDir(), "legacy.json")
	raw := `{"version": 1, "seed_hex": "` + fixtureSeedHex + `", "agent_id": "ap-clerk", "tenant": "acme", "endpoint": "seam.example:443"}`
	_ = os.WriteFile(p, []byte(raw), 0o600)
	loaded, err := LoadIdentityFile(p)
	if err != nil || loaded.AID() != fixtureAID {
		t.Fatalf("legacy load: %v", err)
	}
}
