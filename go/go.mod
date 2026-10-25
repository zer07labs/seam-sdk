module github.com/zer07labs/seam-sdk/go

go 1.21

// go/v0.48.0 was tagged at 0953410, before the protocol pass (seam-sdk#265, #272) merged, and the Go
// checksum database recorded it, so the tag cannot move. go/v0.48.1 is the protocol-pass Go module.
retract v0.48.0

require (
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240604185151-ef581f913117
	google.golang.org/grpc v1.66.3
	google.golang.org/protobuf v1.34.1
)

require (
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	golang.org/x/text v0.16.0 // indirect
)
