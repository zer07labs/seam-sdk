package clearance

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	replay = "/seam.api.v1.SeamCoordination/ReplayDecision"
	proof  = "/seam.api.v1.SeamCoordination/GetCommitmentProof"
)

type call struct {
	method    string
	clearance []string
	tenant    []string
}

type seen struct {
	mu    sync.Mutex
	calls []call
}

// serve answers every method with an empty message and records the headers it received, so the test
// needs no generated stub (they are outside this module): what matters is what reaches the wire.
func serve(t *testing.T) (string, *seen) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &seen{}
	srv := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		md, _ := metadata.FromIncomingContext(stream.Context())
		method, _ := grpc.MethodFromServerStream(stream)
		s.mu.Lock()
		s.calls = append(s.calls, call{method, md.Get(Header), md.Get("x-seam-tenant")})
		s.mu.Unlock()
		if err := stream.RecvMsg(&emptypb.Empty{}); err != nil {
			return err
		}
		return stream.SendMsg(&emptypb.Empty{})
	}))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String(), s
}

func dial(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func invoke(t *testing.T, ctx context.Context, conn *grpc.ClientConn, method string) {
	t.Helper()
	if err := conn.Invoke(ctx, method, &emptypb.Empty{}, &emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
}

func (s *seen) last() call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[len(s.calls)-1]
}

func TestEachLabelIsSentExactlyOnceOnBothDecisionReads(t *testing.T) {
	addr, s := serve(t)
	conn := dial(t, addr)
	for _, c := range All() {
		ctx, err := NewContext(context.Background(), c)
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		for _, m := range []string{replay, proof} {
			invoke(t, ctx, conn, m)
			got := s.last()
			if got.method != m || !reflect.DeepEqual(got.clearance, []string{string(c)}) {
				t.Fatalf("%s %s: server saw %+v", m, c, got)
			}
		}
	}
}

func TestWithoutNewContextNoHeaderIsSent(t *testing.T) {
	addr, s := serve(t)
	conn := dial(t, addr)
	for _, m := range []string{replay, proof} {
		invoke(t, context.Background(), conn, m)
		if got := s.last().clearance; len(got) != 0 {
			t.Fatalf("%s: unexpected %s %v", m, Header, got)
		}
	}
}

func TestASecondNewContextReplacesRatherThanAppends(t *testing.T) {
	addr, s := serve(t)
	conn := dial(t, addr)
	// An earlier raw append of the key is replaced too: NewContext leaves exactly one value.
	ctx := metadata.AppendToOutgoingContext(context.Background(), Header, "Internal")
	ctx, err := NewContext(ctx, Confidential)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = NewContext(ctx, Phi)
	if err != nil {
		t.Fatal(err)
	}
	invoke(t, ctx, conn, replay)
	if got := s.last().clearance; !reflect.DeepEqual(got, []string{"Phi"}) {
		t.Fatalf("want exactly [Phi], got %v", got)
	}
}

func TestOtherOutgoingMetadataIsKeptAndTheParentIsUntouched(t *testing.T) {
	addr, s := serve(t)
	conn := dial(t, addr)
	parent := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-seam-tenant", "acme"))
	parent = metadata.AppendToOutgoingContext(parent, "x-seam-tenant-extra", "1")
	ctx, err := NewContext(parent, Financial)
	if err != nil {
		t.Fatal(err)
	}
	invoke(t, ctx, conn, proof)
	got := s.last()
	if !reflect.DeepEqual(got.tenant, []string{"acme"}) || !reflect.DeepEqual(got.clearance, []string{"Financial"}) {
		t.Fatalf("server saw %+v", got)
	}
	// The parent context's metadata was copied, not mutated.
	md, _ := metadata.FromOutgoingContext(parent)
	if v := md.Get(Header); len(v) != 0 {
		t.Fatalf("parent context gained %s: %v", Header, v)
	}
	invoke(t, parent, conn, proof)
	if v := s.last().clearance; len(v) != 0 {
		t.Fatalf("parent call sent %s: %v", Header, v)
	}
}

func TestAContextWithNoOutgoingMetadataDoesNotPanic(t *testing.T) {
	ctx, err := NewContext(context.Background(), Pii)
	if err != nil {
		t.Fatal(err)
	}
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok || !reflect.DeepEqual(md.Get(Header), []string{"Pii"}) {
		t.Fatalf("got %v %v", ok, md)
	}
}

var bad = []string{"PUBLIC", "public", "", " Public", "Public ", "Restricted", "PII", "phi"}

func TestAnInvalidValueIsRefusedAndTheContextIsUnchanged(t *testing.T) {
	addr, s := serve(t)
	conn := dial(t, addr)
	for _, b := range bad {
		ctx, err := NewContext(context.Background(), Clearance(b))
		if !errors.Is(err, ErrClearance) {
			t.Fatalf("%q: want ErrClearance, got %v", b, err)
		}
		if ctx != context.Background() {
			t.Fatalf("%q: the context was changed", b)
		}
		if _, err := Parse(b); !errors.Is(err, ErrClearance) {
			t.Fatalf("Parse(%q): want ErrClearance, got %v", b, err)
		}
		invoke(t, ctx, conn, replay)
		if v := s.last().clearance; len(v) != 0 {
			t.Fatalf("%q: the refused value still reached the wire: %v", b, v)
		}
	}
}

func TestParseRoundTripsTheSixLabels(t *testing.T) {
	want := []string{"Public", "Internal", "Confidential", "Financial", "Pii", "Phi"}
	for i, c := range All() {
		if string(c) != want[i] {
			t.Fatalf("label %d: %q", i, c)
		}
		got, err := Parse(want[i])
		if err != nil || got != c || !got.Valid() {
			t.Fatalf("Parse(%q) = %q, %v", want[i], got, err)
		}
	}
	all := All()
	all[0] = "mutated"
	if All()[0] != Public {
		t.Fatal("All() must return a fresh slice")
	}
}
