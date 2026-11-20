package com.zer07labs.seam;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ForwardingClientCall;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import java.util.Arrays;
import java.util.stream.Collectors;

/**
 * The caller's decrypt clearance, {@code x-seam-clearance}, on the decision reads (#384). Mirrors
 * Python's {@code clearance=} and the TypeScript {@code DecisionReadOptions.clearance}.
 *
 * <p>seam-runtime applies a namespace's §2.3 decrypt-clearance floor on GetDecision (the seal
 * attestation and the experiment allocation on the view), ReplayDecision (runtime 0.101.0+) and
 * GetCommitmentProof. It reads the caller's clearance from this header. If the header is absent or
 * its value unrecognised, the read is at {@code Public}, the lowest clearance. It is per call, so
 * install it on the stub for the decision read rather than on the whole channel:
 *
 * <pre>{@code
 * ReplayView v = coord.withInterceptors(Clearance.CONFIDENTIAL.interceptor()).replayDecision(req);
 * }</pre>
 *
 * Without the interceptor, no header is sent, exactly as before.
 *
 * <p>The value set is closed and exact: the runtime's Classification labels, spelled as it parses
 * them (case-sensitive). {@link #parse} accepts only that spelling, never the constant names. The
 * runtime would not refuse an unknown label; it would quietly read at Public, which shows up as an
 * unexplained PERMISSION_DENIED (replay, proof) or a CLEARANCE_DENIED view (GetDecision).
 *
 * <p>Sending it is an assertion, not a grant. The runtime honours the header only on a data plane in
 * the {@code allow} subject-header posture, i.e. behind a trusted gateway. A plane in {@code deny}
 * posture ({@code SEAM_GRPC_SUBJECT_HEADERS=deny}) and a peer-cert plane strip it at the edge, so the
 * read there is at Public whatever this says. The header is not part of the #508 call signature.
 */
public enum Clearance {
    PUBLIC("Public"),
    INTERNAL("Internal"),
    CONFIDENTIAL("Confidential"),
    FINANCIAL("Financial"),
    PII("Pii"),
    PHI("Phi");

    /** The request header the runtime reads the caller's clearance from. */
    public static final String HEADER = "x-seam-clearance";

    /** {@link #HEADER} as a gRPC metadata key. */
    public static final Metadata.Key<String> KEY =
            Metadata.Key.of(HEADER, Metadata.ASCII_STRING_MARSHALLER);

    private final String wire;

    Clearance(String wire) {
        this.wire = wire;
    }

    /** The exact label sent on the wire, e.g. {@code "Pii"}. */
    public String wireValue() {
        return wire;
    }

    @Override
    public String toString() {
        return wire;
    }

    /**
     * The clearance whose wire label is exactly {@code value}.
     *
     * @throws IllegalArgumentException for anything else, including {@code null}, {@code ""}, other
     *     casings and the constant names ({@code "PUBLIC"})
     */
    public static Clearance parse(String value) {
        for (Clearance c : values()) {
            if (c.wire.equals(value)) return c;
        }
        String allowed = Arrays.stream(values()).map(Clearance::wireValue).collect(Collectors.joining(", "));
        throw new IllegalArgumentException(
                "clearance "
                        + (value == null ? "null" : "\"" + value + "\"")
                        + " is not one of "
                        + allowed
                        + " (exact, case-sensitive; omit the interceptor to send no "
                        + HEADER
                        + ")");
    }

    /**
     * An interceptor that sets {@code x-seam-clearance} to this label on each call it sees. It
     * replaces any value already in the headers, so a call carries exactly one.
     */
    public ClientInterceptor interceptor() {
        final String value = wire;
        return new ClientInterceptor() {
            @Override
            public <Q, R> ClientCall<Q, R> interceptCall(
                    MethodDescriptor<Q, R> method, CallOptions options, Channel next) {
                return new ForwardingClientCall.SimpleForwardingClientCall<>(
                        next.newCall(method, options)) {
                    @Override
                    public void start(Listener<R> listener, Metadata headers) {
                        headers.removeAll(KEY);
                        headers.put(KEY, value);
                        super.start(listener, headers);
                    }
                };
            }
        };
    }
}
