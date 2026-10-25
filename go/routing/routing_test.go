package routing

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type seen struct {
	mu    sync.Mutex
	calls [][]string
}

// serve answers every method with an empty message and records the x-seam-tenant values it received,
// so the test needs no generated stub: what matters is what reaches the wire.
func serve(t *testing.T) (string, *seen) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &seen{}
	srv := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		md, _ := metadata.FromIncomingContext(stream.Context())
		s.mu.Lock()
		s.calls = append(s.calls, md.Get(TenantHeader))
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

func dial(t *testing.T, addr string, opts ...grpc.DialOption) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func callBoth(t *testing.T, ctx context.Context, conn *grpc.ClientConn) {
	t.Helper()
	if err := conn.Invoke(ctx, "/seam.api.v1.SeamAdmission/IssueChallenge", &emptypb.Empty{}, &emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
	st, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, "/seam.api.v1.SeamEvents/StreamEvents")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SendMsg(&emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
	_ = st.CloseSend()
	if err := st.RecvMsg(&emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
}

func TestWithTenantSendsTheHeaderOnUnaryAndStreamingCalls(t *testing.T) {
	addr, s := serve(t)
	opts, err := WithTenant("acme")
	if err != nil {
		t.Fatal(err)
	}
	callBoth(t, context.Background(), dial(t, addr, opts...))
	if want := [][]string{{"acme"}, {"acme"}}; !reflect.DeepEqual(s.calls, want) {
		t.Fatalf("got %v, want %v", s.calls, want)
	}
}

func TestNoInterceptorSendsNoHeader(t *testing.T) {
	addr, s := serve(t)
	callBoth(t, context.Background(), dial(t, addr))
	if len(s.calls) != 2 || len(s.calls[0]) != 0 || len(s.calls[1]) != 0 {
		t.Fatalf("got %v, want no header on either call", s.calls)
	}
}

func TestAHeaderTheCallAlreadyNamesIsKept(t *testing.T) {
	addr, s := serve(t)
	opts, _ := WithTenant("acme")
	ctx := metadata.AppendToOutgoingContext(context.Background(), TenantHeader, "explicit")
	callBoth(t, ctx, dial(t, addr, opts...))
	if want := [][]string{{"explicit"}, {"explicit"}}; !reflect.DeepEqual(s.calls, want) {
		t.Fatalf("got %v, want %v", s.calls, want)
	}
}

func TestAnEmptyTenantIsRefused(t *testing.T) {
	if _, err := WithTenant(""); !errors.Is(err, ErrEmptyTenant) {
		t.Fatalf("got %v", err)
	}
	if _, err := UnaryInterceptor(""); !errors.Is(err, ErrEmptyTenant) {
		t.Fatalf("got %v", err)
	}
	if _, err := StreamInterceptor(""); !errors.Is(err, ErrEmptyTenant) {
		t.Fatalf("got %v", err)
	}
}

func refusal(t *testing.T, code codes.Code, reason, domain string, md map[string]string) error {
	t.Helper()
	st, err := status.New(code, "refused").WithDetails(&errdetails.ErrorInfo{Reason: reason, Domain: domain, Metadata: md})
	if err != nil {
		t.Fatal(err)
	}
	return st.Err()
}

func TestWrongCellIsRecognisedAndItsMetadataRead(t *testing.T) {
	md := map[string]string{"cell": "aws-stg-b", "root_snapshot_id": "snap-41", "root_generated_at": "2026-10-25T12:00:00Z"}
	err := refusal(t, codes.FailedPrecondition, WrongCellReason, SeamErrorDomain, md)
	if !IsWrongCell(err) {
		t.Fatal("WRONG_CELL not recognised")
	}
	if got := SeamErrorInfo(err).GetMetadata(); !reflect.DeepEqual(got, md) {
		t.Fatalf("metadata %v", got)
	}
}

func TestOnlyASeamDomainFailedPreconditionWrongCellCounts(t *testing.T) {
	for name, err := range map[string]error{
		"other reason": refusal(t, codes.FailedPrecondition, "stream_id_mismatch", SeamErrorDomain, nil),
		"other domain": refusal(t, codes.FailedPrecondition, WrongCellReason, "example.com", nil),
		"other code":   refusal(t, codes.Unavailable, WrongCellReason, SeamErrorDomain, nil),
		"no detail":    status.Error(codes.FailedPrecondition, "refused"),
		"not a status": errors.New("boom"),
	} {
		if IsWrongCell(err) {
			t.Errorf("%s: read as WRONG_CELL", name)
		}
	}
	if SeamErrorInfo(errors.New("boom")) != nil {
		t.Error("a non-status error has no ErrorInfo")
	}
}
