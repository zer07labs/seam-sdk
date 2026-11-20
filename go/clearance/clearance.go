// Package clearance sends the caller's decrypt clearance, `x-seam-clearance`, on the decision reads
// (#384). Mirrors Python's `clearance=` and the TypeScript `DecisionReadOptions.clearance`.
//
// seam-runtime applies a namespace's §2.3 decrypt-clearance floor on GetDecision (the seal
// attestation and the experiment allocation on the view), ReplayDecision (runtime 0.101.0+) and
// GetCommitmentProof. It reads the caller's clearance from this header. If the header is absent or
// its value unrecognised, the read is at Public, the lowest clearance.
//
// The clearance is per call, so it rides the call's context rather than a connection-wide
// interceptor:
//
//	ctx, err := clearance.NewContext(ctx, clearance.Financial)
//	if err != nil { ... }
//	view, err := coord.ReplayDecision(ctx, req)
//
// Without NewContext no header is sent, exactly as before.
//
// The value set is closed and exact: the runtime's Classification labels, spelled as it parses them
// (case-sensitive). Anything else is refused with ErrClearance before any call is made. The runtime
// would not refuse an unknown label; it would quietly read at Public, which shows up as an
// unexplained PERMISSION_DENIED (replay, proof) or a CLEARANCE_DENIED view (GetDecision).
//
// Sending it is an assertion, not a grant. The runtime honours the header only on a data plane in
// the `allow` subject-header posture, i.e. behind a trusted gateway. A plane in `deny` posture
// (SEAM_GRPC_SUBJECT_HEADERS=deny) and a peer-cert plane strip it at the edge, so the read there is
// at Public whatever this says. The header is not part of the #508 call signature.
package clearance

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/metadata"
)

// Header is the request header the runtime reads the caller's clearance from.
const Header = "x-seam-clearance"

// Clearance is one of the runtime's Classification labels, in its exact wire spelling.
type Clearance string

// The six labels, in the runtime enum's declaration order (lowest first).
const (
	Public       Clearance = "Public"
	Internal     Clearance = "Internal"
	Confidential Clearance = "Confidential"
	Financial    Clearance = "Financial"
	Pii          Clearance = "Pii"
	Phi          Clearance = "Phi"
)

// All returns the six labels in declaration order. It is a fresh slice each call.
func All() []Clearance {
	return []Clearance{Public, Internal, Confidential, Financial, Pii, Phi}
}

// ErrClearance is returned (wrapped) for any value that is not exactly one of the six labels.
var ErrClearance = errors.New("clearance: not one of the runtime's labels")

func allowed() string {
	names := make([]string, 0, 6)
	for _, c := range All() {
		names = append(names, string(c))
	}
	return strings.Join(names, ", ")
}

// Valid reports whether c is exactly one of the six labels.
func (c Clearance) Valid() bool {
	for _, k := range All() {
		if c == k {
			return true
		}
	}
	return false
}

// Parse returns s as a Clearance, or an error wrapping ErrClearance when s is not exactly one of the
// six labels (case-sensitive: "PUBLIC" and "public" are refused).
func Parse(s string) (Clearance, error) {
	c := Clearance(s)
	if !c.Valid() {
		return "", fmt.Errorf("%w: %q is not one of %s (exact, case-sensitive; omit it to send no %s)", ErrClearance, s, allowed(), Header)
	}
	return c, nil
}

// NewContext returns ctx carrying `x-seam-clearance: c` in its outgoing metadata, for the decision
// reads made with it. It replaces any value an earlier NewContext set, so the call carries exactly
// one, and keeps every other outgoing key (x-seam-tenant, credential headers). An invalid c returns
// ctx unchanged and an error wrapping ErrClearance.
//
// A later raw metadata.AppendToOutgoingContext of the same key would still add a second value; the
// runtime reads the first. Use NewContext again instead.
func NewContext(ctx context.Context, c Clearance) (context.Context, error) {
	if !c.Valid() {
		_, err := Parse(string(c))
		return ctx, err
	}
	md, ok := metadata.FromOutgoingContext(ctx)
	if ok {
		md = md.Copy()
	} else {
		md = metadata.MD{}
	}
	md.Set(Header, string(c))
	return metadata.NewOutgoingContext(ctx, md), nil
}
