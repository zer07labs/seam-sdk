package mgmtdpop

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/zer07labs/seam-sdk/go/routing"
)

// rawCodec hands the server each message's bytes exactly as they arrived, so every assertion below is
// made against the received bytes, never a re-serialised decode.
type rawCodec struct{}

func (rawCodec) Marshal(v any) ([]byte, error) { return *(v.(*[]byte)), nil }
func (rawCodec) Unmarshal(data []byte, v any) error {
	*(v.(*[]byte)) = append([]byte(nil), data...)
	return nil
}
func (rawCodec) Name() string { return "proto" }

type received struct {
	method string
	md     metadata.MD
	body   []byte
}

type tapServer struct {
	mu    sync.Mutex
	calls []received
}

func (s *tapServer) handle(_ any, stream grpc.ServerStream) error {
	method, _ := grpc.MethodFromServerStream(stream)
	md, _ := metadata.FromIncomingContext(stream.Context())
	var body []byte
	if err := stream.RecvMsg(&body); err != nil {
		return err
	}
	s.mu.Lock()
	s.calls = append(s.calls, received{method, md, body})
	s.mu.Unlock()
	reply := []byte{}
	if strings.HasSuffix(method, "/StreamEvents") {
		// Two empty frames: the client drains both, then io.EOF.
		if err := stream.SendMsg(&reply); err != nil {
			return err
		}
	}
	return stream.SendMsg(&reply)
}

func (s *tapServer) all() []received {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]received(nil), s.calls...)
}

// dial starts a bufconn tap server and returns a client connection built with extra dial options.
func dial(t *testing.T, opts ...grpc.DialOption) (*grpc.ClientConn, *tapServer) {
	t.Helper()
	tap := &tapServer{}
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.UnknownServiceHandler(tap.handle), grpc.ForceServerCodec(rawCodec{}))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	opts = append(opts,
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	cc, err := grpc.NewClient("passthrough:///bufnet", opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return cc, tap
}

var (
	testKey   = mustKey(0x42)
	otherKey  = mustKey(0x07)
	boundTest = makeToken(map[string]any{"aud": "seam-runtime", "cnf": map[string]any{"jkt": testKey.JKT()}})
)

func mustKey(b byte) *Key {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = b
	}
	k, err := KeyFromSeed(seed)
	if err != nil {
		panic(err)
	}
	return k
}

func makeToken(claims map[string]any) string {
	claims["sub"] = "op"
	h, _ := json.Marshal(map[string]any{"alg": "EdDSA", "typ": "JWT"})
	c, _ := json.Marshal(claims)
	return b64.EncodeToString(h) + "." + b64.EncodeToString(c) + ".c2ln"
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return b64.EncodeToString(sum[:])
}

// checkProof verifies one received call's DPoP headers against the bytes the server received.
func checkProof(t *testing.T, r received, token, aud string) map[string]any {
	t.Helper()
	if got := r.md.Get("authorization"); len(got) != 1 || got[0] != "DPoP "+token {
		t.Fatalf("authorization = %v", got)
	}
	proofs := r.md.Get("dpop")
	if len(proofs) != 1 {
		t.Fatalf("dpop = %v", proofs)
	}
	proof := proofs[0]
	at := strings.LastIndex(proof, ".")
	sig, _ := b64.DecodeString(proof[at+1:])
	pub, _ := b64.DecodeString(testKey.X())
	if !ed25519.Verify(pub, []byte(proof[:at]), sig) {
		t.Fatal("proof signature does not verify")
	}
	raw, _ := b64.DecodeString(strings.Split(proof, ".")[1])
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["htm"] != "POST" || claims["htu"] != "grpc://"+aud+r.method {
		t.Fatalf("htm/htu = %v %v", claims["htm"], claims["htu"])
	}
	if claims["seam_bd"] != digest(r.body) {
		t.Fatalf("seam_bd does not cover the received bytes")
	}
	if claims["ath"] != digest([]byte(token)) {
		t.Fatal("ath")
	}
	return claims
}

func signedConn(t *testing.T, token, aud string, opts ...InterceptorOption) (*grpc.ClientConn, *tapServer) {
	t.Helper()
	dialOpts, err := DialOptions(testKey, token, aud, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return dial(t, dialOpts...)
}

const enroll = "/seam.api.v1.SeamAdmin/EnrollTenant"
const streamEvents = "/seam.api.v1.SeamEvents/StreamEvents"

// ── the proof binds the bytes the server received ───────────────────────────────────────────────

func TestUnaryProofBindsReceivedBytes(t *testing.T) {
	cc, tap := signedConn(t, boundTest, "")
	if err := cc.Invoke(context.Background(), enroll, wrapperspb.String("acme"), &emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
	calls := tap.all()
	if len(calls) != 1 || len(calls[0].body) == 0 {
		t.Fatalf("calls = %+v", calls)
	}
	checkProof(t, calls[0], boundTest, "seam-runtime")
}

func TestEmptyMessage(t *testing.T) {
	cc, tap := signedConn(t, boundTest, "")
	if err := cc.Invoke(context.Background(), "/seam.api.v1.SeamAdmin/ListTenants", &emptypb.Empty{}, &emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
	r := tap.all()[0]
	if len(r.body) != 0 {
		t.Fatal("expected an empty message")
	}
	if checkProof(t, r, boundTest, "seam-runtime")["htu"] != "grpc://seam-runtime/seam.api.v1.SeamAdmin/ListTenants" {
		t.Fatal("htu")
	}
}

func openStream(t *testing.T, cc *grpc.ClientConn, ctx context.Context) grpc.ClientStream {
	t.Helper()
	cs, err := cc.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, streamEvents)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func TestServerStreamSignsTheOneRequest(t *testing.T) {
	cc, tap := signedConn(t, boundTest, "")
	cs := openStream(t, cc, context.Background())
	if err := cs.SendMsg(wrapperspb.String("stream-1")); err != nil {
		t.Fatal(err)
	}
	if err := cs.CloseSend(); err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		err := cs.RecvMsg(&emptypb.Empty{})
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 2 {
		t.Fatalf("received %d messages", n)
	}
	r := tap.all()[0]
	if r.method != streamEvents || len(r.body) == 0 {
		t.Fatalf("%+v", r)
	}
	checkProof(t, r, boundTest, "seam-runtime")
}

func TestLazyStreamBeforeSendMsg(t *testing.T) {
	cc, tap := signedConn(t, boundTest, "")
	ctx := context.WithValue(context.Background(), struct{}{}, "marker")
	cs := openStream(t, cc, ctx)
	if cs.Context().Value(struct{}{}) != "marker" {
		t.Fatal("Context() before SendMsg must return the captured context")
	}
	for name, err := range map[string]error{
		"RecvMsg":   cs.RecvMsg(&emptypb.Empty{}),
		"CloseSend": cs.CloseSend(),
		"Header":    func() error { _, e := cs.Header(); return e }(),
	} {
		if !errors.Is(err, ErrStreamNotStarted) {
			t.Errorf("%s: want ErrStreamNotStarted, got %v", name, err)
		}
	}
	if cs.Trailer() != nil {
		t.Error("Trailer() before SendMsg must be nil")
	}
	if len(tap.all()) != 0 {
		t.Fatal("nothing may reach the server before SendMsg")
	}
}

func TestLazyStreamSecondSendMsgIsRefused(t *testing.T) {
	cc, _ := signedConn(t, boundTest, "")
	cs := openStream(t, cc, context.Background())
	if err := cs.SendMsg(wrapperspb.String("a")); err != nil {
		t.Fatal(err)
	}
	if err := cs.SendMsg(wrapperspb.String("b")); !errors.Is(err, ErrDpop) {
		t.Fatalf("second SendMsg: %v", err)
	}
}

func TestLazyStreamCancelledBeforeSendMsg(t *testing.T) {
	cc, tap := signedConn(t, boundTest, "")
	ctx, cancel := context.WithCancel(context.Background())
	cs := openStream(t, cc, ctx)
	cancel()
	if err := cs.SendMsg(wrapperspb.String("a")); status.Code(err) != codes.Canceled {
		t.Fatalf("SendMsg after cancel: %v", err)
	}
	if err := cs.RecvMsg(&emptypb.Empty{}); status.Code(err) != codes.Canceled {
		t.Fatalf("a failed open must stick: %v", err)
	}
	if len(tap.all()) != 0 {
		t.Fatal("a cancelled stream must not reach the server")
	}
}

func TestClientStreamingIsRefused(t *testing.T) {
	cc, _ := signedConn(t, boundTest, "")
	_, err := cc.NewStream(context.Background(), &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, "/x.Y/Z")
	if !errors.Is(err, ErrDpop) {
		t.Fatalf("want ErrDpop, got %v", err)
	}
}

// prefixCodec puts different bytes on the wire than the proto codec would, so a signer that ignored a
// forced codec would sign the wrong bytes.
type prefixCodec struct{}

func (prefixCodec) Marshal(v any) ([]byte, error) {
	b, err := encoding.GetCodecV2("proto").Marshal(v)
	if err != nil {
		return nil, err
	}
	return append([]byte("PFX"), b.Materialize()...), nil
}
func (prefixCodec) Unmarshal(data []byte, v any) error { return nil }
func (prefixCodec) Name() string                       { return "prefix" }

func TestAForcedCodecIsTheOneSigned(t *testing.T) {
	cc, tap := signedConn(t, boundTest, "")
	err := cc.Invoke(context.Background(), enroll, wrapperspb.String("acme"), &emptypb.Empty{}, grpc.ForceCodec(prefixCodec{}))
	if err != nil {
		t.Fatal(err)
	}
	r := tap.all()[0]
	if !strings.HasPrefix(string(r.body), "PFX") {
		t.Fatalf("the forced codec did not reach the wire: %q", r.body)
	}
	checkProof(t, r, boundTest, "seam-runtime")

	cs, err := cc.NewStream(context.Background(), &grpc.StreamDesc{ServerStreams: true}, streamEvents, grpc.ForceCodec(prefixCodec{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.SendMsg(wrapperspb.String("s")); err != nil {
		t.Fatal(err)
	}
	_ = cs.CloseSend()
	for cs.RecvMsg(&emptypb.Empty{}) == nil {
	}
	checkProof(t, tap.all()[1], boundTest, "seam-runtime")
}

func TestAnUnknownContentSubtypeIsRefusedLocally(t *testing.T) {
	cc, tap := signedConn(t, boundTest, "")
	err := cc.Invoke(context.Background(), enroll, &emptypb.Empty{}, &emptypb.Empty{}, grpc.CallContentSubtype("nope"))
	if !errors.Is(err, ErrDpop) {
		t.Fatalf("want ErrDpop, got %v", err)
	}
	if len(tap.all()) != 0 {
		t.Fatal("nothing may reach the server")
	}
}

// ── aud, clock and freshness ─────────────────────────────────────────────────────────────────────

func TestAudResolution(t *testing.T) {
	jkt := map[string]any{"jkt": testKey.JKT()}
	cases := []struct {
		claims map[string]any
		aud    string
		want   string
	}{
		{map[string]any{"aud": "ops.internal", "cnf": jkt}, "", "ops.internal"},
		{map[string]any{"aud": "seam-runtime", "cnf": jkt}, "cell-7", "cell-7"},
		{map[string]any{"cnf": jkt}, "", DefaultOperatorAud},
		{map[string]any{"aud": []string{"a", "b"}, "cnf": jkt}, "cell-7", "cell-7"},
	}
	for _, c := range cases {
		tok := makeToken(c.claims)
		cc, tap := signedConn(t, tok, c.aud)
		if err := cc.Invoke(context.Background(), enroll, &emptypb.Empty{}, &emptypb.Empty{}); err != nil {
			t.Fatal(err)
		}
		checkProof(t, tap.all()[0], tok, c.want)
	}
}

func TestClockSetsIAT(t *testing.T) {
	cc, tap := signedConn(t, boundTest, "", WithClock(func() int64 { return 1234 }))
	if err := cc.Invoke(context.Background(), enroll, &emptypb.Empty{}, &emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
	if checkProof(t, tap.all()[0], boundTest, "seam-runtime")["iat"] != float64(1234) {
		t.Fatal("iat")
	}
}

func TestConcurrentCallsCarryDistinctProofs(t *testing.T) {
	cc, tap := signedConn(t, boundTest, "", WithClock(func() int64 { return 1 }))
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cc.Invoke(context.Background(), enroll, wrapperspb.String("x"), &emptypb.Empty{}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	jtis := map[any]bool{}
	for _, r := range tap.all() {
		jtis[checkProof(t, r, boundTest, "seam-runtime")["jti"]] = true
	}
	if len(jtis) != 32 {
		t.Fatalf("%d distinct jti over 32 calls", len(jtis))
	}
}

func TestTenantHeaderRidesAlongside(t *testing.T) {
	dpop, err := DialOptions(testKey, boundTest, "")
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := routing.WithTenant("acme")
	if err != nil {
		t.Fatal(err)
	}
	cc, tap := dial(t, append(tenant, dpop...)...)
	if err := cc.Invoke(context.Background(), enroll, &emptypb.Empty{}, &emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
	r := tap.all()[0]
	if got := r.md.Get(routing.TenantHeader); len(got) != 1 || got[0] != "acme" {
		t.Fatalf("tenant = %v", got)
	}
	checkProof(t, r, boundTest, "seam-runtime")
}

// ── guaranteed-to-fail pairings are refused before any call ──────────────────────────────────────

func TestConstructionRefusals(t *testing.T) {
	jkt := map[string]any{"jkt": testKey.JKT()}
	keyCases := []struct {
		name  string
		key   *Key
		token string
		aud   string
		match string
	}{
		{"no token", testKey, "", "", "needs token"},
		{"unbound", testKey, makeToken(map[string]any{"aud": "seam-runtime"}), "", "not DPoP-bound"},
		{"other key", otherKey, boundTest, "", "bound to key"},
		{"list aud", testKey, makeToken(map[string]any{"aud": []string{"a", "b"}, "cnf": jkt}), "", "not a single string"},
		{"not a JWS", testKey, "not-a-jws", "", "compact JWS"},
		{"cnf not object", testKey, makeToken(map[string]any{"cnf": "x"}), "", "malformed"},
		{"jkt not string", testKey, makeToken(map[string]any{"cnf": map[string]any{"jkt": 7}}), "", "malformed"},
		{"payload not JSON", testKey, "a." + b64.EncodeToString([]byte("{")) + ".c", "", "not JSON"},
		{"trailing data", testKey, "a." + b64.EncodeToString([]byte(`{"cnf":{"jkt":"x"}} {}`)) + ".c", "", "not JSON"},
		{"payload null", testKey, "a." + b64.EncodeToString([]byte("null")) + ".c", "", "not a JSON object"},
		{"aud null", testKey, makeToken(map[string]any{"aud": nil, "cnf": jkt}), "", "not a single string"},
		{"aud number", testKey, makeToken(map[string]any{"aud": 7, "cnf": jkt}), "", "not a single string"},
	}
	for _, c := range keyCases {
		_, err := DialOptions(c.key, c.token, c.aud)
		if !errors.Is(err, ErrKey) || !strings.Contains(err.Error(), c.match) {
			t.Errorf("%s: want ErrKey matching %q, got %v", c.name, c.match, err)
		}
	}
	argCases := map[string]error{
		"nil key":        func() error { _, e := DialOptions(nil, boundTest, ""); return e }(),
		"explicit aud /": func() error { _, e := DialOptions(testKey, boundTest, "a/b"); return e }(),
		"token aud space": func() error {
			_, e := DialOptions(testKey, makeToken(map[string]any{"aud": "has space", "cnf": jkt}), "")
			return e
		}(),
		"nil clock": func() error { _, e := DialOptions(testKey, boundTest, "", WithClock(nil)); return e }(),
		"negative clock": func() error {
			_, e := DialOptions(testKey, boundTest, "", WithClock(func() int64 { return -1 }))
			return e
		}(),
		"token space": func() error { _, e := UnaryInterceptor(testKey, "a b", ""); return e }(),
	}
	for name, err := range argCases {
		if !errors.Is(err, ErrDpop) || errors.Is(err, ErrKey) {
			t.Errorf("%s: want ErrDpop (not ErrKey), got %v", name, err)
		}
	}
	big := "a." + b64.EncodeToString([]byte(`{"n":1e400,"cnf":{"jkt":"`+testKey.JKT()+`"}}`)) + ".c"
	if _, err := DialOptions(testKey, big, ""); err != nil {
		t.Errorf("a valid JSON number in the token must not be refused: %v", err)
	}
	if _, err := StreamInterceptor(testKey, "", ""); !errors.Is(err, ErrKey) {
		t.Errorf("StreamInterceptor applies the same checks: %v", err)
	}
}
