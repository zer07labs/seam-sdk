//go:build unix

package identity

import (
	"os"
	"syscall"
)

const oNoFollow = syscall.O_NOFOLLOW

// fsyncDir makes the new directory entry durable.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
