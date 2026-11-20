package com.zer07labs.seam

import io.grpc.CallOptions
import io.grpc.Channel
import io.grpc.ClientCall
import io.grpc.ClientInterceptor
import io.grpc.ForwardingClientCall
import io.grpc.Metadata
import io.grpc.MethodDescriptor

/**
 * The caller's decrypt clearance, `x-seam-clearance`, on the decision reads (#384). Mirrors Python's
 * `clearance=` and the TypeScript `DecisionReadOptions.clearance`.
 *
 * seam-runtime applies a namespace's §2.3 decrypt-clearance floor on GetDecision (the seal attestation
 * and the experiment allocation on the view), ReplayDecision (runtime 0.101.0+) and GetCommitmentProof.
 * It reads the caller's clearance from this header. If the header is absent or its value unrecognised,
 * the read is at `Public`, the lowest clearance. It is per call, so install it on the stub for the
 * decision read rather than on the whole channel:
 * `coord.withInterceptors(Clearance.CONFIDENTIAL.interceptor()).replayDecision(req)`. Without the
 * interceptor, no header is sent, exactly as before.
 *
 * The value set is closed and exact: the runtime's Classification labels, spelled as it parses them
 * (case-sensitive). [parse] accepts only that spelling, never the constant names. The runtime would not
 * refuse an unknown label; it would quietly read at Public, which shows up as an unexplained
 * PERMISSION_DENIED (replay, proof) or a CLEARANCE_DENIED view (GetDecision).
 *
 * Sending it is an assertion, not a grant. The runtime honours the header only on a data plane in the
 * `allow` subject-header posture, i.e. behind a trusted gateway. A plane in `deny` posture
 * (`SEAM_GRPC_SUBJECT_HEADERS=deny`) and a peer-cert plane strip it at the edge, so the read there is at
 * Public whatever this says. The header is not part of the #508 call signature.
 */
enum class Clearance(
    /** The exact label sent on the wire, e.g. `"Pii"`. */
    val wireValue: String,
) {
    PUBLIC("Public"),
    INTERNAL("Internal"),
    CONFIDENTIAL("Confidential"),
    FINANCIAL("Financial"),
    PII("Pii"),
    PHI("Phi"),
    ;

    override fun toString(): String = wireValue

    /**
     * An interceptor that sets `x-seam-clearance` to this label on each call it sees. It replaces any
     * value already in the headers, so a call carries exactly one.
     */
    fun interceptor(): ClientInterceptor {
        val value = wireValue
        return object : ClientInterceptor {
            override fun <Q, R> interceptCall(
                method: MethodDescriptor<Q, R>,
                options: CallOptions,
                next: Channel,
            ): ClientCall<Q, R> =
                object : ForwardingClientCall.SimpleForwardingClientCall<Q, R>(next.newCall(method, options)) {
                    override fun start(listener: Listener<R>, headers: Metadata) {
                        headers.removeAll(KEY)
                        headers.put(KEY, value)
                        super.start(listener, headers)
                    }
                }
        }
    }

    companion object {
        /** The request header the runtime reads the caller's clearance from. */
        const val HEADER = "x-seam-clearance"

        /** [HEADER] as a gRPC metadata key. */
        @JvmField
        val KEY: Metadata.Key<String> = Metadata.Key.of(HEADER, Metadata.ASCII_STRING_MARSHALLER)

        /**
         * The clearance whose wire label is exactly [value].
         *
         * @throws IllegalArgumentException for anything else, including `""`, other casings and the
         *     constant names (`"PUBLIC"`)
         */
        @JvmStatic
        fun parse(value: String): Clearance =
            entries.firstOrNull { it.wireValue == value }
                ?: throw IllegalArgumentException(
                    "clearance \"$value\" is not one of ${entries.joinToString(", ") { it.wireValue }} " +
                        "(exact, case-sensitive; omit the interceptor to send no $HEADER)",
                )
    }
}
