package com.zer07labs.seam;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ClientInterceptors;
import io.grpc.ForwardingClientCall;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerInterceptors;
import io.grpc.ServerServiceDefinition;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.ClientCalls;
import io.grpc.stub.ServerCalls;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** x-seam-clearance reaches the wire once, on the decision reads; parse accepts only the wire label. */
class ClearanceTest {
    private static final MethodDescriptor.Marshaller<byte[]> BYTES =
            new MethodDescriptor.Marshaller<>() {
                @Override
                public InputStream stream(byte[] v) {
                    return new ByteArrayInputStream(v);
                }

                @Override
                public byte[] parse(InputStream in) {
                    try {
                        return in.readAllBytes();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            };

    private static MethodDescriptor<byte[], byte[]> unary(String name) {
        return MethodDescriptor.newBuilder(BYTES, BYTES)
                .setType(MethodDescriptor.MethodType.UNARY)
                .setFullMethodName("seam.api.v1.SeamCoordination/" + name)
                .build();
    }

    private static final MethodDescriptor<byte[], byte[]> REPLAY = unary("ReplayDecision");
    private static final MethodDescriptor<byte[], byte[]> PROOF = unary("GetCommitmentProof");

    private final List<String> seen = Collections.synchronizedList(new ArrayList<>());
    private Server server;
    private ManagedChannel channel;

    @BeforeEach
    void start() throws IOException {
        String name = InProcessServerBuilder.generateName();
        ServerInterceptor record =
                new ServerInterceptor() {
                    @Override
                    public <Q, R> ServerCall.Listener<Q> interceptCall(
                            ServerCall<Q, R> call, Metadata headers, ServerCallHandler<Q, R> next) {
                        Iterable<String> values = headers.getAll(Clearance.KEY);
                        List<String> all = new ArrayList<>();
                        if (values != null) values.forEach(all::add);
                        seen.add(call.getMethodDescriptor().getBareMethodName() + all);
                        return next.startCall(call, headers);
                    }
                };
        ServerServiceDefinition coord =
                ServerServiceDefinition.builder("seam.api.v1.SeamCoordination")
                        .addMethod(REPLAY, ServerCalls.asyncUnaryCall((req, out) -> {
                            out.onNext(new byte[0]);
                            out.onCompleted();
                        }))
                        .addMethod(PROOF, ServerCalls.asyncUnaryCall((req, out) -> {
                            out.onNext(new byte[0]);
                            out.onCompleted();
                        }))
                        .build();
        server = InProcessServerBuilder.forName(name)
                .addService(ServerInterceptors.intercept(coord, record))
                .build()
                .start();
        channel = InProcessChannelBuilder.forName(name).build();
    }

    @AfterEach
    void stop() {
        channel.shutdownNow();
        server.shutdownNow();
    }

    private void callBoth(Channel ch) {
        ClientCalls.blockingUnaryCall(ch, REPLAY, CallOptions.DEFAULT, new byte[0]);
        ClientCalls.blockingUnaryCall(ch, PROOF, CallOptions.DEFAULT, new byte[0]);
    }

    @Test
    void eachLabelIsSentExactlyOnceOnBothDecisionReads() {
        for (Clearance c : Clearance.values()) {
            seen.clear();
            callBoth(ClientInterceptors.intercept(channel, c.interceptor()));
            String v = c.wireValue();
            assertEquals(List.of("ReplayDecision[" + v + "]", "GetCommitmentProof[" + v + "]"), seen);
        }
    }

    @Test
    void noInterceptorSendsNoHeader() {
        callBoth(channel);
        assertEquals(List.of("ReplayDecision[]", "GetCommitmentProof[]"), seen);
    }

    @Test
    void theInterceptorReplacesAnEarlierValueRatherThanAppending() {
        // An inner interceptor that adds a stale value first; then two clearances stacked.
        ClientInterceptor stale =
                new ClientInterceptor() {
                    @Override
                    public <Q, R> ClientCall<Q, R> interceptCall(
                            MethodDescriptor<Q, R> method, CallOptions options, Channel next) {
                        return new ForwardingClientCall.SimpleForwardingClientCall<>(
                                next.newCall(method, options)) {
                            @Override
                            public void start(Listener<R> listener, Metadata headers) {
                                headers.put(Clearance.KEY, "Internal");
                                super.start(listener, headers);
                            }
                        };
                    }
                };
        // ClientInterceptors.intercept runs the LAST interceptor's start first.
        callBoth(ClientInterceptors.intercept(
                channel, Clearance.PHI.interceptor(), Clearance.CONFIDENTIAL.interceptor(), stale));
        assertEquals(List.of("ReplayDecision[Phi]", "GetCommitmentProof[Phi]"), seen);
    }

    @Test
    void parseRoundTripsTheSixWireLabels() {
        String[] wire = {"Public", "Internal", "Confidential", "Financial", "Pii", "Phi"};
        Clearance[] all = Clearance.values();
        assertEquals(wire.length, all.length);
        for (int i = 0; i < wire.length; i++) {
            assertEquals(wire[i], all[i].wireValue());
            assertEquals(wire[i], all[i].toString());
            assertSame(all[i], Clearance.parse(wire[i]));
        }
        assertEquals("x-seam-clearance", Clearance.HEADER);
        assertEquals("x-seam-clearance", Clearance.KEY.name());
    }

    @Test
    void parseRefusesAnythingElse() {
        for (String bad : new String[] {"public", "PUBLIC", "", "Restricted", "PII", " Public", "Public ", null}) {
            IllegalArgumentException e =
                    assertThrows(IllegalArgumentException.class, () -> Clearance.parse(bad), String.valueOf(bad));
            assertEquals(true, e.getMessage().contains("clearance"));
        }
    }
}
