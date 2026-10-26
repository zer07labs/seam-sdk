package com.zer07labs.seam

import com.google.protobuf.Any
import com.google.rpc.ErrorInfo
import io.grpc.CallOptions
import io.grpc.Channel
import io.grpc.ClientInterceptors
import io.grpc.ManagedChannel
import io.grpc.Metadata
import io.grpc.MethodDescriptor
import io.grpc.Server
import io.grpc.ServerCall
import io.grpc.ServerCallHandler
import io.grpc.ServerInterceptor
import io.grpc.ServerInterceptors
import io.grpc.ServerServiceDefinition
import io.grpc.Status
import io.grpc.StatusRuntimeException
import io.grpc.inprocess.InProcessChannelBuilder
import io.grpc.inprocess.InProcessServerBuilder
import io.grpc.protobuf.StatusProto
import io.grpc.stub.ClientCalls
import io.grpc.stub.ServerCalls
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.util.Collections
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/** x-seam-tenant reaches the wire on unary and streaming calls; WRONG_CELL reads off ErrorInfo. */
class TenantRoutingTest {
    private val key = Metadata.Key.of(TenantRouting.TENANT_HEADER, Metadata.ASCII_STRING_MARSHALLER)
    private val bytes =
        object : MethodDescriptor.Marshaller<ByteArray> {
            override fun stream(value: ByteArray): InputStream = ByteArrayInputStream(value)

            override fun parse(stream: InputStream): ByteArray = stream.readAllBytes()
        }
    private val unary =
        MethodDescriptor.newBuilder(bytes, bytes)
            .setType(MethodDescriptor.MethodType.UNARY)
            .setFullMethodName("seam.api.v1.SeamAdmission/IssueChallenge")
            .build()
    private val stream =
        MethodDescriptor.newBuilder(bytes, bytes)
            .setType(MethodDescriptor.MethodType.SERVER_STREAMING)
            .setFullMethodName("seam.api.v1.SeamEvents/StreamEvents")
            .build()

    private val seen: MutableList<List<String>> = Collections.synchronizedList(mutableListOf())
    private lateinit var server: Server
    private lateinit var channel: ManagedChannel

    @BeforeEach
    fun start() {
        val name = InProcessServerBuilder.generateName()
        val record =
            object : ServerInterceptor {
                override fun <Q, R> interceptCall(
                    call: ServerCall<Q, R>,
                    headers: Metadata,
                    next: ServerCallHandler<Q, R>,
                ): ServerCall.Listener<Q> {
                    seen.add(headers.getAll(key)?.toList() ?: emptyList())
                    return next.startCall(call, headers)
                }
            }
        val admission =
            ServerServiceDefinition.builder("seam.api.v1.SeamAdmission")
                .addMethod(unary, ServerCalls.asyncUnaryCall { _, out -> out.onNext(ByteArray(0)); out.onCompleted() })
                .build()
        val events =
            ServerServiceDefinition.builder("seam.api.v1.SeamEvents")
                .addMethod(stream, ServerCalls.asyncServerStreamingCall { _, out -> out.onNext(ByteArray(0)); out.onCompleted() })
                .build()
        server =
            InProcessServerBuilder.forName(name)
                .addService(ServerInterceptors.intercept(admission, record))
                .addService(ServerInterceptors.intercept(events, record))
                .build()
                .start()
        channel = InProcessChannelBuilder.forName(name).build()
    }

    @AfterEach
    fun stop() {
        channel.shutdownNow()
        server.shutdownNow()
    }

    private fun callBoth(ch: Channel) {
        ClientCalls.blockingUnaryCall(ch, unary, CallOptions.DEFAULT, ByteArray(0))
        ClientCalls.blockingServerStreamingCall(ch, stream, CallOptions.DEFAULT, ByteArray(0)).forEach { _ -> }
    }

    @Test
    fun `the interceptor sends the tenant on unary and streaming calls`() {
        callBoth(ClientInterceptors.intercept(channel, TenantRouting.interceptor("acme")))
        assertEquals(listOf(listOf("acme"), listOf("acme")), seen)
    }

    @Test
    fun `no interceptor sends no header`() {
        callBoth(channel)
        assertEquals(listOf(emptyList<String>(), emptyList()), seen)
    }

    @Test
    fun `an empty tenant is refused`() {
        assertThrows(IllegalArgumentException::class.java) { TenantRouting.interceptor("") }
    }

    private fun refusal(code: Status.Code, reason: String, domain: String, md: Map<String, String>): StatusRuntimeException =
        StatusProto.toStatusRuntimeException(
            com.google.rpc.Status.newBuilder()
                .setCode(code.value())
                .setMessage("refused")
                .addDetails(Any.pack(ErrorInfo.newBuilder().setReason(reason).setDomain(domain).putAllMetadata(md).build()))
                .build(),
        )

    @Test
    fun `WRONG_CELL is recognised and its metadata read`() {
        val md = mapOf("cell" to "aws-stg-b", "root_snapshot_id" to "snap-41", "root_generated_at" to "2026-10-25T12:00:00Z")
        val e = refusal(Status.Code.FAILED_PRECONDITION, TenantRouting.WRONG_CELL_REASON, TenantRouting.SEAM_ERROR_DOMAIN, md)
        assertTrue(TenantRouting.isWrongCell(e))
        assertEquals(md, TenantRouting.errorInfo(e)!!.metadataMap)
    }

    @Test
    fun `only a Seam-domain FAILED_PRECONDITION WRONG_CELL counts`() {
        val fp = Status.Code.FAILED_PRECONDITION
        val d = TenantRouting.SEAM_ERROR_DOMAIN
        assertFalse(TenantRouting.isWrongCell(refusal(fp, "stream_id_mismatch", d, emptyMap())))
        assertFalse(TenantRouting.isWrongCell(refusal(fp, "WRONG_CELL", "example.com", emptyMap())))
        assertFalse(TenantRouting.isWrongCell(refusal(Status.Code.UNAVAILABLE, "WRONG_CELL", d, emptyMap())))
        assertFalse(TenantRouting.isWrongCell(Status.FAILED_PRECONDITION.asRuntimeException()))
        assertFalse(TenantRouting.isWrongCell(RuntimeException("boom")))
        assertNull(TenantRouting.errorInfo(RuntimeException("boom")))
    }

    @Test
    fun `TENANT_MOVING is recognised and is not WRONG_CELL`() {
        val fp = Status.Code.FAILED_PRECONDITION
        val d = TenantRouting.SEAM_ERROR_DOMAIN
        val md = mapOf("move_id" to "mv-1", "target_cell" to "aws-stg-b")
        val e = refusal(fp, TenantRouting.TENANT_MOVING_REASON, d, md)
        assertTrue(TenantRouting.isTenantMoving(e))
        assertFalse(TenantRouting.isWrongCell(e))
        assertEquals(md, TenantRouting.errorInfo(e)!!.metadataMap)
        assertFalse(TenantRouting.isTenantMoving(refusal(fp, "WRONG_CELL", d, emptyMap())))
        assertFalse(TenantRouting.isTenantMoving(refusal(Status.Code.UNAVAILABLE, "TENANT_MOVING", d, emptyMap())))
    }
}
