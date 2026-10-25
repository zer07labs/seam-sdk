package com.zer07labs.seam

import com.google.protobuf.InvalidProtocolBufferException
import com.google.rpc.ErrorInfo
import io.grpc.CallOptions
import io.grpc.Channel
import io.grpc.ClientCall
import io.grpc.ClientInterceptor
import io.grpc.ForwardingClientCall
import io.grpc.Metadata
import io.grpc.MethodDescriptor
import io.grpc.Status
import io.grpc.protobuf.StatusProto

/**
 * The `x-seam-tenant` routing hint on every seam.api.v1 call, and the runtime's WRONG_CELL refusal
 * (seam-runtime k8s P15, D123). Mirrors Python's `seam_sdk.tenant`.
 *
 * seam-cell-router routes each call to the cell where the caller's tenant lives. IssueChallenge, Admit
 * and RunDecision carry no tenant before authentication, so the router reads it from this header, on
 * every call. It is a routing hint, never authority: the cell still derives the tenant from identity and
 * refuses a misrouted call FAILED_PRECONDITION reason WRONG_CELL. Install it on the channel the generated
 * stubs run over: `ClientInterceptors.intercept(channel, TenantRouting.interceptor("acme"))`. A channel
 * straight to its cell (no router in front) needs none of this.
 */
object TenantRouting {
    /** The request header seam-cell-router routes on (D123). */
    const val TENANT_HEADER = "x-seam-tenant"

    /** The ErrorInfo domain every Seam refusal carries. */
    const val SEAM_ERROR_DOMAIN = "seam.zer07labs.com"

    /**
     * ErrorInfo reason of a FAILED_PRECONDITION refusal: the call reached a cell that does not hold the
     * caller's tenant (runtime 0.58.0). Its metadata names the `cell` that answered and the fleet root it
     * routed by (`root_snapshot_id`, `root_generated_at`). Never retryable: the same call to the same
     * endpoint reaches the same cell; the remedy is the routing.
     */
    const val WRONG_CELL_REASON = "WRONG_CELL"

    private val KEY: Metadata.Key<String> = Metadata.Key.of(TENANT_HEADER, Metadata.ASCII_STRING_MARSHALLER)

    /**
     * An interceptor that attaches `x-seam-tenant: tenant` to every call, unary and streaming. A call that
     * already names the header keeps its own value.
     *
     * @throws IllegalArgumentException for an empty tenant, which is refused rather than sent
     */
    fun interceptor(tenant: String): ClientInterceptor {
        require(tenant.isNotEmpty()) {
            "tenant must be this caller's enrolled tenant id (non-empty); omit the interceptor to send no " +
                "x-seam-tenant header"
        }
        return object : ClientInterceptor {
            override fun <Q, R> interceptCall(
                method: MethodDescriptor<Q, R>,
                options: CallOptions,
                next: Channel,
            ): ClientCall<Q, R> =
                object : ForwardingClientCall.SimpleForwardingClientCall<Q, R>(next.newCall(method, options)) {
                    override fun start(listener: Listener<R>, headers: Metadata) {
                        if (!headers.containsKey(KEY)) headers.put(KEY, tenant)
                        super.start(listener, headers)
                    }
                }
        }
    }

    /**
     * The Seam-domain ErrorInfo on [t]'s status, or `null`. Its metadata holds the refusal's structured
     * facts, unfiltered. A malformed detail reads as absent.
     */
    fun errorInfo(t: Throwable): ErrorInfo? {
        val st = StatusProto.fromThrowable(t) ?: return null
        for (d in st.detailsList) {
            if (!d.`is`(ErrorInfo::class.java)) continue
            val info =
                try {
                    d.unpack(ErrorInfo::class.java)
                } catch (e: InvalidProtocolBufferException) {
                    return null
                }
            if (info.domain == SEAM_ERROR_DOMAIN) return info
        }
        return null
    }

    /** Whether [t] is the runtime's WRONG_CELL refusal. Never retry it. */
    fun isWrongCell(t: Throwable): Boolean =
        Status.fromThrowable(t).code == Status.Code.FAILED_PRECONDITION &&
            errorInfo(t)?.reason == WRONG_CELL_REASON
}
