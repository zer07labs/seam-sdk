package com.zer07labs.seam;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.protobuf.Any;
import com.google.rpc.ErrorInfo;
import io.grpc.Channel;
import io.grpc.ClientInterceptors;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Server;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.ServerInterceptors;
import io.grpc.ServerServiceDefinition;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.protobuf.StatusProto;
import io.grpc.stub.ClientCalls;
import io.grpc.stub.ServerCalls;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** x-seam-tenant reaches the wire on unary and streaming calls; WRONG_CELL reads off ErrorInfo. */
class TenantRoutingTest {
    private static final Metadata.Key<String> KEY =
            Metadata.Key.of(TenantRouting.TENANT_HEADER, Metadata.ASCII_STRING_MARSHALLER);

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

    private static final MethodDescriptor<byte[], byte[]> UNARY =
            MethodDescriptor.newBuilder(BYTES, BYTES)
                    .setType(MethodDescriptor.MethodType.UNARY)
                    .setFullMethodName("seam.api.v1.SeamAdmission/IssueChallenge")
                    .build();
    private static final MethodDescriptor<byte[], byte[]> STREAM =
            MethodDescriptor.newBuilder(BYTES, BYTES)
                    .setType(MethodDescriptor.MethodType.SERVER_STREAMING)
                    .setFullMethodName("seam.api.v1.SeamEvents/StreamEvents")
                    .build();

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
                        Iterable<String> values = headers.getAll(KEY);
                        List<String> all = new ArrayList<>();
                        if (values != null) values.forEach(all::add);
                        seen.add(String.valueOf(all));
                        return next.startCall(call, headers);
                    }
                };
        ServerServiceDefinition admission =
                ServerServiceDefinition.builder("seam.api.v1.SeamAdmission")
                        .addMethod(UNARY, ServerCalls.asyncUnaryCall((req, out) -> {
                            out.onNext(new byte[0]);
                            out.onCompleted();
                        }))
                        .build();
        ServerServiceDefinition events =
                ServerServiceDefinition.builder("seam.api.v1.SeamEvents")
                        .addMethod(STREAM, ServerCalls.asyncServerStreamingCall((req, out) -> {
                            out.onNext(new byte[0]);
                            out.onCompleted();
                        }))
                        .build();
        server = InProcessServerBuilder.forName(name)
                .addService(ServerInterceptors.intercept(admission, record))
                .addService(ServerInterceptors.intercept(events, record))
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
        ClientCalls.blockingUnaryCall(ch, UNARY, io.grpc.CallOptions.DEFAULT, new byte[0]);
        Iterator<byte[]> it =
                ClientCalls.blockingServerStreamingCall(ch, STREAM, io.grpc.CallOptions.DEFAULT, new byte[0]);
        while (it.hasNext()) it.next();
    }

    @Test
    void theInterceptorSendsTheTenantOnUnaryAndStreamingCalls() {
        callBoth(ClientInterceptors.intercept(channel, TenantRouting.interceptor("acme")));
        assertEquals(List.of("[acme]", "[acme]"), seen);
    }

    @Test
    void noInterceptorSendsNoHeader() {
        callBoth(channel);
        assertEquals(List.of("[]", "[]"), seen);
    }

    @Test
    void anEmptyTenantIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> TenantRouting.interceptor(""));
        assertThrows(IllegalArgumentException.class, () -> TenantRouting.interceptor(null));
    }

    private static StatusRuntimeException refusal(int code, String reason, String domain, Map<String, String> md) {
        com.google.rpc.Status st = com.google.rpc.Status.newBuilder()
                .setCode(code)
                .setMessage("refused")
                .addDetails(Any.pack(ErrorInfo.newBuilder().setReason(reason).setDomain(domain).putAllMetadata(md).build()))
                .build();
        return StatusProto.toStatusRuntimeException(st);
    }

    @Test
    void wrongCellIsRecognisedAndItsMetadataRead() {
        Map<String, String> md = Map.of("cell", "aws-stg-b", "root_snapshot_id", "snap-41", "root_generated_at", "2026-10-25T12:00:00Z");
        StatusRuntimeException e = refusal(Status.Code.FAILED_PRECONDITION.value(), TenantRouting.WRONG_CELL_REASON, TenantRouting.SEAM_ERROR_DOMAIN, md);
        assertTrue(TenantRouting.isWrongCell(e));
        assertEquals(md, TenantRouting.errorInfo(e).orElseThrow().getMetadataMap());
    }

    @Test
    void onlyASeamDomainFailedPreconditionWrongCellCounts() {
        int fp = Status.Code.FAILED_PRECONDITION.value();
        assertFalse(TenantRouting.isWrongCell(refusal(fp, "stream_id_mismatch", TenantRouting.SEAM_ERROR_DOMAIN, Map.of())));
        assertFalse(TenantRouting.isWrongCell(refusal(fp, "WRONG_CELL", "example.com", Map.of())));
        assertFalse(TenantRouting.isWrongCell(refusal(Status.Code.UNAVAILABLE.value(), "WRONG_CELL", TenantRouting.SEAM_ERROR_DOMAIN, Map.of())));
        assertFalse(TenantRouting.isWrongCell(Status.FAILED_PRECONDITION.asRuntimeException()));
        assertFalse(TenantRouting.isWrongCell(new RuntimeException("boom")));
        assertTrue(TenantRouting.errorInfo(new RuntimeException("boom")).isEmpty());
    }
}
