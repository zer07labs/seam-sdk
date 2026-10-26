package com.zer07labs.seam;

import com.google.protobuf.Any;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.rpc.ErrorInfo;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ForwardingClientCall;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import io.grpc.protobuf.StatusProto;
import java.util.Optional;

/**
 * The {@code x-seam-tenant} routing hint on every seam.api.v1 call, and the runtime's WRONG_CELL
 * refusal (seam-runtime k8s P15, D123). Mirrors Python's {@code seam_sdk.tenant}.
 *
 * <p>seam-cell-router routes each call to the cell where the caller's tenant lives. IssueChallenge,
 * Admit and RunDecision carry no tenant before authentication, so the router reads it from this
 * header, on every call. It is a routing hint, never authority: the cell still derives the tenant
 * from identity and refuses a misrouted call FAILED_PRECONDITION reason WRONG_CELL. Install it on the
 * channel the generated stubs run over:
 *
 * <pre>{@code
 * Channel routed = ClientInterceptors.intercept(channel, TenantRouting.interceptor("acme"));
 * }</pre>
 *
 * A channel straight to its cell (no router in front) needs none of this.
 */
public final class TenantRouting {
    private TenantRouting() {}

    /** The request header seam-cell-router routes on (D123). */
    public static final String TENANT_HEADER = "x-seam-tenant";

    /** The ErrorInfo domain every Seam refusal carries. */
    public static final String SEAM_ERROR_DOMAIN = "seam.zer07labs.com";

    /**
     * ErrorInfo reason of a FAILED_PRECONDITION refusal: the call reached a cell that does not hold
     * the caller's tenant (runtime 0.58.0). Its metadata names the {@code cell} that answered and the
     * fleet root it routed by ({@code root_snapshot_id}, {@code root_generated_at}). Never retryable:
     * the same call to the same endpoint reaches the same cell; the remedy is the routing.
     */
    public static final String WRONG_CELL_REASON = "WRONG_CELL";

    /**
     * The ErrorInfo reason of a FAILED_PRECONDITION refusal with RetryInfo: the caller's tenant is moving
     * between cells (runtime 0.59.0, k8s P16). Its metadata names the {@code move_id} and the
     * {@code target_cell}. Retryable after the RetryInfo delay: the refusal lands before any write. Once
     * the tenant flips, the source cell answers WRONG_CELL instead.
     */
    public static final String TENANT_MOVING_REASON = "TENANT_MOVING";

    private static final Metadata.Key<String> KEY =
            Metadata.Key.of(TENANT_HEADER, Metadata.ASCII_STRING_MARSHALLER);

    /**
     * An interceptor that attaches {@code x-seam-tenant: tenant} to every call, unary and streaming. A
     * call that already names the header keeps its own value.
     *
     * @throws IllegalArgumentException for a null or empty tenant, which is refused rather than sent
     */
    public static ClientInterceptor interceptor(String tenant) {
        if (tenant == null || tenant.isEmpty()) {
            throw new IllegalArgumentException(
                    "tenant must be this caller's enrolled tenant id (non-empty); omit the interceptor"
                            + " to send no x-seam-tenant header");
        }
        return new ClientInterceptor() {
            @Override
            public <Q, R> ClientCall<Q, R> interceptCall(
                    MethodDescriptor<Q, R> method, CallOptions options, Channel next) {
                return new ForwardingClientCall.SimpleForwardingClientCall<>(
                        next.newCall(method, options)) {
                    @Override
                    public void start(Listener<R> listener, Metadata headers) {
                        if (!headers.containsKey(KEY)) headers.put(KEY, tenant);
                        super.start(listener, headers);
                    }
                };
            }
        };
    }

    /**
     * The Seam-domain ErrorInfo on {@code t}'s status, if any. Its metadata holds the refusal's
     * structured facts, unfiltered. A malformed detail reads as absent.
     */
    public static Optional<ErrorInfo> errorInfo(Throwable t) {
        com.google.rpc.Status st = StatusProto.fromThrowable(t);
        if (st == null) return Optional.empty();
        for (Any d : st.getDetailsList()) {
            if (!d.is(ErrorInfo.class)) continue;
            try {
                ErrorInfo info = d.unpack(ErrorInfo.class);
                if (SEAM_ERROR_DOMAIN.equals(info.getDomain())) return Optional.of(info);
            } catch (InvalidProtocolBufferException e) {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    /** Whether {@code t} is the runtime's WRONG_CELL refusal. Never retry it. */
    public static boolean isWrongCell(Throwable t) {
        return Status.fromThrowable(t).getCode() == Status.Code.FAILED_PRECONDITION
                && errorInfo(t).map(i -> WRONG_CELL_REASON.equals(i.getReason())).orElse(false);
    }

    /** Whether {@code t} is the runtime's TENANT_MOVING refusal. Retry it after the RetryInfo delay. */
    public static boolean isTenantMoving(Throwable t) {
        return Status.fromThrowable(t).getCode() == Status.Code.FAILED_PRECONDITION
                && errorInfo(t).map(i -> TENANT_MOVING_REASON.equals(i.getReason())).orElse(false);
    }
}
