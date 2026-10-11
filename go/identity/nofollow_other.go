//go:build !unix

package identity

// Platform gap: there is no O_NOFOLLOW outside unix. O_EXCL on the random temp name, plus the hard-link
// publish (which never follows a link at the destination), still refuse any existing path.
const oNoFollow = 0

// fsyncDir is a no-op: Windows cannot open a directory to fsync it. Python skips it there too.
func fsyncDir(string) error { return nil }
