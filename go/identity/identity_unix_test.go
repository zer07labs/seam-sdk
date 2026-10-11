//go:build unix

package identity

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestModeIs0600UnderUmask0(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	path, _ := mustCreate(t, filepath.Join(t.TempDir(), "id.json"))
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
}
