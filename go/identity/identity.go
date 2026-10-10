// Package identity is identity custody for the Seam Go SDK (seam-sdk#201): create and load the
// schema-v1 bootstrap file. It mirrors Python's `seam_sdk/identity.py`, which owns the schema:
//
//	{"version": 1, "seed_hex": "<64 hex>", "agent_id": "...", "tenant": "...", "endpoint": "host:port"}
//
// Unknown extra keys are ignored on load. One JSON file plus one env pointer (SEAM_BOOTSTRAP_FILE).
//
// The seed leaves this package in exactly one direction: from disk into a crypto.Agent on load.
// CreateIdentityFile generates it, writes it, and returns (path, aid) — never the seed.
package identity

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/zer07labs/seam-sdk/go/crypto"
)

// EnvPointer names the bootstrap file when LoadIdentityFile is given no path.
const EnvPointer = "SEAM_BOOTSTRAP_FILE"

// SchemaVersion is the only bootstrap schema this SDK reads and writes.
const SchemaVersion = 1

// IdentityFileError is returned when the bootstrap file is missing, malformed, fails validation, or
// cannot be created. Always loud. Unwrap reaches the underlying OS/JSON error, when there is one.
type IdentityFileError struct {
	Msg string
	Err error
}

func (e *IdentityFileError) Error() string { return e.Msg }
func (e *IdentityFileError) Unwrap() error { return e.Err }

func fail(err error, format string, a ...any) error {
	return &IdentityFileError{Msg: fmt.Sprintf(format, a...), Err: err}
}

// LoadedIdentity is the process identity loaded from a bootstrap file. The seed is held only inside
// Agent, whose String/Format never print it; LoadedIdentity's own String omits it too.
type LoadedIdentity struct {
	Agent    *crypto.Agent
	AgentID  string // registry identity for scope lookup (may equal the AID)
	Tenant   string
	Endpoint string // the data-plane endpoint this process talks to
}

// AID is the loaded agent's AID.
func (l *LoadedIdentity) AID() string { return l.Agent.AID() }

func (l *LoadedIdentity) String() string {
	return fmt.Sprintf("LoadedIdentity(aid=%q, agent_id=%q, tenant=%q, endpoint=%q)", l.AID(), l.AgentID, l.Tenant, l.Endpoint)
}

// GoString keeps %#v from walking into Agent's fields.
func (l *LoadedIdentity) GoString() string { return l.String() }

// LoadIdentityFile loads the process identity from path, or from $SEAM_BOOTSTRAP_FILE when path is "".
func LoadIdentityFile(path string) (*LoadedIdentity, error) {
	resolved := path
	if resolved == "" {
		resolved = os.Getenv(EnvPointer)
	}
	if resolved == "" {
		return nil, fail(nil, "no bootstrap file: pass a path or set $%s (one JSON + env pointer is the custody contract)", EnvPointer)
	}
	raw, err := os.ReadFile(resolved)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fail(err, "bootstrap file not found: %s", resolved)
		}
		return nil, fail(err, "cannot read bootstrap file %s: %v", resolved, err)
	}
	var top any
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fail(err, "bootstrap file is not valid JSON: %s: %v", resolved, err)
	}
	data, ok := top.(map[string]any)
	if !ok {
		return nil, fail(nil, "bootstrap file is not a JSON object: %s", resolved)
	}
	if v, ok := data["version"].(float64); !ok || v != SchemaVersion {
		return nil, fail(nil, "bootstrap schema version %v unsupported (want %d)", data["version"], SchemaVersion)
	}
	seedHex, _ := data["seed_hex"].(string)
	if len(seedHex) != 64 {
		return nil, fail(nil, "seed_hex must be exactly 64 hex chars (a 32-byte Ed25519 seed)")
	}
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, fail(err, "seed_hex is not valid hex")
	}
	fields := map[string]string{}
	var missing []string
	for _, k := range []string{"agent_id", "tenant", "endpoint"} {
		s, ok := data[k].(string)
		if !ok || s == "" {
			missing = append(missing, k)
		}
		fields[k] = s
	}
	if len(missing) > 0 {
		return nil, fail(nil, "bootstrap file missing required field(s): %s", strings.Join(missing, ", "))
	}
	agent, err := crypto.NewAgent(seed)
	if err != nil {
		return nil, fail(err, "%v", err)
	}
	return &LoadedIdentity{Agent: agent, AgentID: fields["agent_id"], Tenant: fields["tenant"], Endpoint: fields["endpoint"]}, nil
}

// CreateIdentityFile generates a new agent identity and writes it to path as a schema-v1 bootstrap
// file. It returns (path, aid); the seed is never returned — load the file with LoadIdentityFile in the
// process that will use it.
//
// The write is atomic and never clobbers. The bytes go to a sibling temp file opened
// O_CREAT|O_EXCL|O_NOFOLLOW with mode 0600 (re-applied with fchmod so the umask cannot widen it), are
// fsync-ed, and are then published with a hard link, which fails if anything — a file, a directory, a
// symlink — already exists at path. The temp name is then unlinked and the directory fsync-ed. A reader
// never sees a partial file, and an existing file is left byte-for-byte unchanged.
func CreateIdentityFile(path, agentID, tenant, endpoint string) (string, string, error) {
	for _, f := range [][2]string{{"agent_id", agentID}, {"tenant", tenant}, {"endpoint", endpoint}} {
		if f[1] == "" {
			return "", "", fail(nil, "%s must be a non-empty string", f[0])
		}
	}
	agent, err := crypto.GenerateAgent()
	if err != nil {
		return "", "", fail(err, "%v", err)
	}
	seed := agent.Seed()
	// A struct, not a map, so the key order is the schema's: version, seed_hex, agent_id, tenant, endpoint.
	body, err := json.MarshalIndent(struct {
		Version  int    `json:"version"`
		SeedHex  string `json:"seed_hex"`
		AgentID  string `json:"agent_id"`
		Tenant   string `json:"tenant"`
		Endpoint string `json:"endpoint"`
	}{SchemaVersion, hex.EncodeToString(seed), agentID, tenant, endpoint}, "", "  ")
	if err != nil {
		return "", "", fail(err, "%v", err)
	}
	body = append(body, '\n')

	abs, err := filepath.Abs(path)
	if err != nil {
		return "", "", fail(err, "cannot resolve %s: %v", path, err)
	}
	dir := filepath.Dir(abs)
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return "", "", fail(err, "%v", err)
	}
	tmp := filepath.Join(dir, "."+filepath.Base(abs)+"."+hex.EncodeToString(nonce)+".tmp")

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
	if err != nil {
		return "", "", fail(err, "cannot create bootstrap file in %s: %v", dir, err)
	}
	defer os.Remove(tmp)
	writeErr := func() error {
		if err := f.Chmod(0o600); err != nil { // fchmod: the umask cannot widen it
			return err
		}
		if _, err := f.Write(body); err != nil {
			return err
		}
		return f.Sync()
	}()
	if cerr := f.Close(); writeErr == nil {
		writeErr = cerr
	}
	if writeErr != nil {
		return "", "", fail(writeErr, "cannot write bootstrap file in %s: %v", dir, writeErr)
	}
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return "", "", fail(err, "refusing to overwrite existing path: %s", path)
		}
		return "", "", fail(err, "cannot publish bootstrap file %s: %v", path, err)
	}
	if err := os.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", "", fail(err, "cannot remove temp file %s: %v", tmp, err)
	}
	if err := fsyncDir(dir); err != nil {
		return "", "", fail(err, "cannot fsync %s: %v", dir, err)
	}
	return path, agent.AID(), nil
}
