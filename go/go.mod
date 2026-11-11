module github.com/zer07labs/seam-sdk/go

go 1.25.0

// go/v0.48.0 was tagged at 0953410, before the protocol pass (seam-sdk#265, #272) merged, and the Go
// checksum database recorded it, so the tag cannot move. go/v0.48.1 is the protocol-pass Go module.
retract v0.48.0

require (
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa
	google.golang.org/grpc v1.83.1
	google.golang.org/protobuf v1.36.11
)

require (
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
)
