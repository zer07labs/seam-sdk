package com.zer07labs.seam

import io.grpc.CallOptions
import io.grpc.Channel
import io.grpc.ClientCall
import io.grpc.ClientInterceptor
import io.grpc.ClientInterceptors
import io.grpc.ForwardingClientCall
import io.grpc.ManagedChannel
import io.grpc.Metadata
import io.grpc.MethodDescriptor
import io.grpc.Server
import io.grpc.ServerCall
import io.grpc.ServerCallHandler
import io.grpc.ServerInterceptor
import io.grpc.ServerInterceptors
import io.grpc.ServerServiceDefinition
import io.grpc.inprocess.InProcessChannelBuilder
import io.grpc.inprocess.InProcessServerBuilder
import io.grpc.stub.ClientCalls
import io.grpc.stub.ServerCalls
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.util.Collections
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/** x-seam-clearance reaches the wire once, on the decision reads; parse accepts only the wire label. */
class ClearanceTest {
    private val bytes =
        object : MethodDescriptor.Marshaller<ByteArray> {
            override fun stream(value: ByteArray): InputStream = ByteArrayInputStream(value)

            override fun parse(stream: InputStream): ByteArray = stream.readAllBytes()
        }

    private fun unary(name: String) =
        MethodDescriptor.newBuilder(bytes, bytes)
            .setType(MethodDescriptor.MethodType.UNARY)
            .setFullMethodName("seam.api.v1.SeamCoordination/$name")
            .build()

    private val replay = unary("ReplayDecision")
    private val proof = unary("GetCommitmentProof")

    private val seen: MutableList<String> = Collections.synchronizedList(mutableListOf())
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
                    val values = headers.getAll(Clearance.KEY)?.toList() ?: emptyList()
                    seen.add("${call.methodDescriptor.bareMethodName}$values")
                    return next.startCall(call, headers)
                }
            }
        val coord =
            ServerServiceDefinition.builder("seam.api.v1.SeamCoordination")
                .addMethod(replay, ServerCalls.asyncUnaryCall { _, out -> out.onNext(ByteArray(0)); out.onCompleted() })
                .addMethod(proof, ServerCalls.asyncUnaryCall { _, out -> out.onNext(ByteArray(0)); out.onCompleted() })
                .build()
        server =
            InProcessServerBuilder.forName(name)
                .addService(ServerInterceptors.intercept(coord, record))
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
        ClientCalls.blockingUnaryCall(ch, replay, CallOptions.DEFAULT, ByteArray(0))
        ClientCalls.blockingUnaryCall(ch, proof, CallOptions.DEFAULT, ByteArray(0))
    }

    @Test
    fun eachLabelIsSentExactlyOnceOnBothDecisionReads() {
        for (c in Clearance.entries) {
            seen.clear()
            callBoth(ClientInterceptors.intercept(channel, c.interceptor()))
            val v = c.wireValue
            assertEquals(listOf("ReplayDecision[$v]", "GetCommitmentProof[$v]"), seen.toList())
        }
    }

    @Test
    fun noInterceptorSendsNoHeader() {
        callBoth(channel)
        assertEquals(listOf("ReplayDecision[]", "GetCommitmentProof[]"), seen.toList())
    }

    @Test
    fun theInterceptorReplacesAnEarlierValueRatherThanAppending() {
        val stale =
            object : ClientInterceptor {
                override fun <Q, R> interceptCall(
                    method: MethodDescriptor<Q, R>,
                    options: CallOptions,
                    next: Channel,
                ): ClientCall<Q, R> =
                    object : ForwardingClientCall.SimpleForwardingClientCall<Q, R>(next.newCall(method, options)) {
                        override fun start(listener: Listener<R>, headers: Metadata) {
                            headers.put(Clearance.KEY, "Internal")
                            super.start(listener, headers)
                        }
                    }
            }
        // ClientInterceptors.intercept runs the LAST interceptor's start first.
        callBoth(
            ClientInterceptors.intercept(channel, Clearance.PHI.interceptor(), Clearance.CONFIDENTIAL.interceptor(), stale),
        )
        assertEquals(listOf("ReplayDecision[Phi]", "GetCommitmentProof[Phi]"), seen.toList())
    }

    @Test
    fun parseRoundTripsTheSixWireLabels() {
        val wire = listOf("Public", "Internal", "Confidential", "Financial", "Pii", "Phi")
        assertEquals(wire, Clearance.entries.map { it.wireValue })
        assertEquals(wire, Clearance.entries.map { it.toString() })
        for ((i, w) in wire.withIndex()) assertSame(Clearance.entries[i], Clearance.parse(w))
        assertEquals("x-seam-clearance", Clearance.HEADER)
        assertEquals("x-seam-clearance", Clearance.KEY.name())
    }

    @Test
    fun parseRefusesAnythingElse() {
        for (bad in listOf("public", "PUBLIC", "", "Restricted", "PII", " Public", "Public ")) {
            val e = assertThrows(IllegalArgumentException::class.java, { Clearance.parse(bad) }, bad)
            assertTrue(e.message!!.contains("clearance"))
        }
    }
}
