module github.com/zer07labs/seam-sdk/go

go 1.21

// go/v0.48.0 was tagged at 0953410, before the protocol pass (seam-sdk#265, #272) merged, and the Go
// checksum database recorded it, so the tag cannot move. go/v0.48.1 is the protocol-pass Go module.
retract v0.48.0
