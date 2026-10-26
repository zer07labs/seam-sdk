// Package routing carries the `x-seam-tenant` routing hint on every seam.api.v1 call and reads the
// runtime's WRONG_CELL refusal (seam-runtime k8s P15, D123). Mirrors Python's `seam_sdk.tenant` and
// the TypeScript `tenantHeaderInterceptor`.
//
// seam-cell-router routes each call to the cell where the caller's tenant lives. IssueChallenge,
// Admit and RunDecision carry no tenant before authentication, so the router reads it from this
// header, on every call. It is a routing hint, never authority: the cell still derives the tenant
// from identity and refuses a misrouted call FAILED_PRECONDITION reason WRONG_CELL.
//
// Install it on the connection that the generated stubs run over:
//
//	opts, err := routing.WithTenant("acme")
//	conn, err := grpc.NewClient(target, append(opts, creds)...)
//
// A connection straight to its cell (no router in front) needs none of this.
package routing

import (
	"context"
	"errors"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TenantHeader is the request header seam-cell-router routes on (D123). Legal-hold's placer-named
// tenant on the management plane (runtime #1037) uses the same name, per call.
const TenantHeader = "x-seam-tenant"

// SeamErrorDomain is the ErrorInfo domain every Seam refusal carries.
const SeamErrorDomain = "seam.zer07labs.com"

// WrongCellReason is the ErrorInfo reason of a FAILED_PRECONDITION refusal: the call reached a cell
// that does not hold the caller's tenant (runtime 0.58.0). Its metadata names the `cell` that
// answered and the fleet root it routed by (`root_snapshot_id`, `root_generated_at`). Never
// retryable: the same call to the same endpoint reaches the same cell; the remedy is the routing.
const WrongCellReason = "WRONG_CELL"

// TenantMovingReason is the ErrorInfo reason of a FAILED_PRECONDITION refusal with RetryInfo: the
// caller's tenant is moving between cells (runtime 0.59.0, k8s P16). Its metadata names the `move_id`
// and the `target_cell`. Retryable after the RetryInfo delay: the refusal lands before any write.
// Once the tenant flips, the source cell answers WRONG_CELL instead.
const TenantMovingReason = "TENANT_MOVING"

// ErrEmptyTenant is returned for an empty tenant, which is refused rather than sent: the router
// refuses a missing or malformed value uniformly.
var ErrEmptyTenant = errors.New("routing: tenant must be this caller's enrolled tenant id (non-empty); omit the interceptor to send no x-seam-tenant header")

func withTenant(ctx context.Context, tenant string) context.Context {
	// A call that already names the header keeps its own value: fill a gap, never rewrite.
	if md, ok := metadata.FromOutgoingContext(ctx); ok && len(md.Get(TenantHeader)) > 0 {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, TenantHeader, tenant)
}

// UnaryInterceptor attaches `x-seam-tenant: tenant` to every unary call.
func UnaryInterceptor(tenant string) (grpc.UnaryClientInterceptor, error) {
	if tenant == "" {
		return nil, ErrEmptyTenant
	}
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoker(withTenant(ctx, tenant), method, req, reply, cc, opts...)
	}, nil
}

// StreamInterceptor attaches `x-seam-tenant: tenant` to every streaming call.
func StreamInterceptor(tenant string) (grpc.StreamClientInterceptor, error) {
	if tenant == "" {
		return nil, ErrEmptyTenant
	}
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		return streamer(withTenant(ctx, tenant), desc, cc, method, opts...)
	}, nil
}

// WithTenant returns the dial options that install both interceptors.
func WithTenant(tenant string) ([]grpc.DialOption, error) {
	unary, err := UnaryInterceptor(tenant)
	if err != nil {
		return nil, err
	}
	stream, _ := StreamInterceptor(tenant)
	return []grpc.DialOption{grpc.WithChainUnaryInterceptor(unary), grpc.WithChainStreamInterceptor(stream)}, nil
}

// SeamErrorInfo returns the Seam-domain ErrorInfo on err's status, or nil when there is none. Its
// Metadata holds the refusal's structured facts, unfiltered.
func SeamErrorInfo(err error) *errdetails.ErrorInfo {
	st, ok := status.FromError(err)
	if !ok {
		return nil
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetDomain() == SeamErrorDomain {
			return info
		}
	}
	return nil
}

// IsWrongCell reports whether err is the runtime's WRONG_CELL refusal. Never retry it.
func IsWrongCell(err error) bool {
	if status.Code(err) != codes.FailedPrecondition {
		return false
	}
	info := SeamErrorInfo(err)
	return info != nil && info.GetReason() == WrongCellReason
}

// IsTenantMoving reports whether err is the runtime's TENANT_MOVING refusal. Retry it after the
// RetryInfo delay.
func IsTenantMoving(err error) bool {
	if status.Code(err) != codes.FailedPrecondition {
		return false
	}
	info := SeamErrorInfo(err)
	return info != nil && info.GetReason() == TenantMovingReason
}
