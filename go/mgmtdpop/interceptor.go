package mgmtdpop

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type interceptorOpts struct {
	clock func() int64
}

// InterceptorOption configures UnaryInterceptor, StreamInterceptor and DialOptions.
type InterceptorOption func(*interceptorOpts)

// WithClock sets the source of each proof's iat (seconds). Default: the wall clock.
func WithClock(clock func() int64) InterceptorOption {
	return func(o *interceptorOpts) { o.clock = clock }
}

// signer holds what every call needs; it is immutable, so one interceptor serves concurrent calls.
type signer struct {
	key   *Key
	token string
	aud   string
	clock func() int64
}

// newSigner refuses, before any call, every pairing the runtime is guaranteed to refuse: a token that is
// not DPoP-bound, a cnf.jkt naming another key, or a list aud with no explicit override.
func newSigner(key *Key, token, aud string, opts []InterceptorOption) (*signer, error) {
	if key == nil {
		return nil, dpopErr("key must be a *mgmtdpop.Key")
	}
	if token == "" {
		return nil, keyErr("a DPoP key needs token: the bound operator token minted with it")
	}
	claims, err := peekTokenClaims(token)
	if err != nil {
		return nil, err
	}
	jkt, bound, err := tokenCnfJkt(claims)
	if err != nil {
		return nil, err
	}
	if !bound {
		return nil, keyErr("the operator token is not DPoP-bound (no cnf.jkt); send it as Bearer without this interceptor")
	}
	if jkt != key.JKT() {
		return nil, keyErr("the operator token is bound to key %q, not this key (%q)", jkt, key.JKT())
	}
	if aud == "" {
		tokAud, has := claims["aud"]
		if !has {
			aud = DefaultOperatorAud
		} else if s, ok := tokAud.(string); ok {
			aud = s
		} else { // a list, a number or null: as Python and TS
			return nil, keyErr("the operator token's aud is not a single string; pass aud explicitly")
		}
	}
	if _, err := GRPCHTU("/m", aud); err != nil {
		return nil, err
	}
	o := interceptorOpts{clock: func() int64 { return time.Now().Unix() }}
	for _, opt := range opts {
		opt(&o)
	}
	if o.clock == nil {
		return nil, dpopErr("clock must be a function")
	}
	if iat := o.clock(); iat < 0 || iat > MaxIAT {
		return nil, dpopErr("clock must return a non-negative integer number of seconds")
	}
	return &signer{key: key, token: token, aud: aud, clock: o.clock}, nil
}

// marshalFor encodes msg with the codec grpc-go will put on the wire for a call made with opts. It
// mirrors grpc-go's setCallInfoCodec/getCodec: the last ForceCodec/ForceCodecV2 wins; otherwise the
// content subtype (default "proto") names the codec, a V1 registration before a V2 one.
func marshalFor(msg any, opts []grpc.CallOption) ([]byte, error) {
	var forced func(any) ([]byte, error)
	subtype := ""
	for _, o := range opts {
		switch o := o.(type) {
		case grpc.ForceCodecCallOption:
			forced = o.Codec.Marshal
		case grpc.ForceCodecV2CallOption:
			forced = marshalV2(o.CodecV2)
		case grpc.ContentSubtypeCallOption:
			subtype = strings.ToLower(o.ContentSubtype)
		case grpc.CustomCodecCallOption:
			return nil, dpopErr("the deprecated grpc.CallCustomCodec is not supported; use grpc.ForceCodecV2")
		}
	}
	if forced != nil {
		return forced(msg)
	}
	if subtype == "" {
		subtype = "proto"
	}
	if c := encoding.GetCodec(subtype); c != nil {
		return c.Marshal(msg)
	}
	if c := encoding.GetCodecV2(subtype); c != nil {
		return marshalV2(c)(msg)
	}
	return nil, dpopErr("no codec registered for content-subtype %q", subtype)
}

func marshalV2(c encoding.CodecV2) func(any) ([]byte, error) {
	return func(msg any) ([]byte, error) {
		buf, err := c.Marshal(msg)
		if err != nil {
			return nil, err
		}
		defer buf.Free()
		return buf.Materialize(), nil // a fresh copy, safe past Free
	}
}

// sign returns ctx carrying both headers for one call. msg is encoded with the codec grpc-go puts on the
// wire for this call, so seam_bd covers exactly the bytes the server receives.
func (s *signer) sign(ctx context.Context, method string, msg any, opts []grpc.CallOption) (context.Context, error) {
	body, err := marshalFor(msg, opts)
	if err != nil {
		if errors.Is(err, ErrDpop) {
			return nil, err
		}
		return nil, dpopErr("cannot encode the request message: %v", err)
	}
	htu, err := GRPCHTU(method, s.aud)
	if err != nil {
		return nil, err
	}
	proof, err := Proof(s.key, s.token, "POST", htu, body, WithIAT(s.clock()))
	if err != nil {
		return nil, err
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "DPoP "+s.token, "dpop", proof), nil
}

// UnaryInterceptor signs every unary call with a fresh proof. aud "" takes the token's aud, else
// DefaultOperatorAud. Each attempt is signed once: do not combine it with a retry policy that resends a
// call's metadata, because the runtime burns a proof on first use.
func UnaryInterceptor(key *Key, token, aud string, opts ...InterceptorOption) (grpc.UnaryClientInterceptor, error) {
	s, err := newSigner(key, token, aud, opts)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, callOpts ...grpc.CallOption) error {
		signed, err := s.sign(ctx, method, req, callOpts)
		if err != nil {
			return err
		}
		return invoker(signed, method, req, reply, cc, callOpts...)
	}, nil
}

// StreamInterceptor signs server-streaming calls. grpc-go sends headers when a stream opens, before its
// request is known, so the real stream is opened lazily by the first SendMsg, which signs that message.
// A management stream carries exactly one request message; a second SendMsg is refused. Until that
// SendMsg has been called, RecvMsg, Header and CloseSend return ErrStreamNotStarted rather than wait
// for it; a call that races the opening SendMsg waits for it to finish and then uses the real stream.
// Call them after SendMsg, as the generated server-streaming stubs do.
func StreamInterceptor(key *Key, token, aud string, opts ...InterceptorOption) (grpc.StreamClientInterceptor, error) {
	s, err := newSigner(key, token, aud, opts)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, callOpts ...grpc.CallOption) (grpc.ClientStream, error) {
		if desc.ClientStreams {
			return nil, dpopErr("%s streams requests; a DPoP proof binds exactly one request message", method)
		}
		return &lazyStream{ctx: ctx, s: s, desc: desc, cc: cc, method: method, streamer: streamer, opts: callOpts}, nil
	}, nil
}

// DialOptions returns the dial options that install both interceptors. aud "" takes the token's aud,
// else DefaultOperatorAud (the other SDKs mean "not given" by null and refuse an empty aud).
func DialOptions(key *Key, token, aud string, opts ...InterceptorOption) ([]grpc.DialOption, error) {
	unary, err := UnaryInterceptor(key, token, aud, opts...)
	if err != nil {
		return nil, err
	}
	stream, _ := StreamInterceptor(key, token, aud, opts...)
	return []grpc.DialOption{grpc.WithChainUnaryInterceptor(unary), grpc.WithChainStreamInterceptor(stream)}, nil
}

// ErrStreamNotStarted is returned by a lazy stream's methods that need the real stream before the first
// SendMsg has opened it.
var ErrStreamNotStarted = errors.New("mgmtdpop: the stream opens on its first SendMsg (the proof signs that message)")

type lazyStream struct {
	ctx      context.Context
	s        *signer
	desc     *grpc.StreamDesc
	cc       *grpc.ClientConn
	method   string
	streamer grpc.Streamer
	opts     []grpc.CallOption

	mu   sync.Mutex
	real grpc.ClientStream
	err  error // a failed open, returned from every later call
}

func (l *lazyStream) started() (grpc.ClientStream, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return nil, l.err
	}
	if l.real == nil {
		return nil, ErrStreamNotStarted
	}
	return l.real, nil
}

func (l *lazyStream) SendMsg(m any) error {
	l.mu.Lock()
	if l.err != nil {
		l.mu.Unlock()
		return l.err
	}
	if l.real != nil {
		l.mu.Unlock()
		return dpopErr("%s: a DPoP proof binds exactly one request message", l.method)
	}
	if err := l.ctx.Err(); err != nil {
		err = status.FromContextError(err).Err() // codes.Canceled / DeadlineExceeded, as a real stream reports
		l.err = err
		l.mu.Unlock()
		return err
	}
	signed, err := l.s.sign(l.ctx, l.method, m, l.opts)
	if err == nil {
		l.real, err = l.streamer(signed, l.desc, l.cc, l.method, l.opts...)
	}
	if err != nil {
		l.err = err
		l.mu.Unlock()
		return err
	}
	real := l.real
	l.mu.Unlock()
	return real.SendMsg(m)
}

func (l *lazyStream) RecvMsg(m any) error {
	real, err := l.started()
	if err != nil {
		return err
	}
	return real.RecvMsg(m)
}

func (l *lazyStream) Header() (metadata.MD, error) {
	real, err := l.started()
	if err != nil {
		return nil, err
	}
	return real.Header()
}

func (l *lazyStream) Trailer() metadata.MD {
	real, err := l.started()
	if err != nil {
		return nil
	}
	return real.Trailer()
}

func (l *lazyStream) CloseSend() error {
	real, err := l.started()
	if err != nil {
		return err
	}
	return real.CloseSend()
}

func (l *lazyStream) Context() context.Context {
	real, err := l.started()
	if err != nil {
		return l.ctx
	}
	return real.Context()
}

var _ grpc.ClientStream = (*lazyStream)(nil)
