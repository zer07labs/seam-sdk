package com.zer07labs.seam

import com.google.gson.Gson
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import io.grpc.CallOptions
import io.grpc.Channel
import io.grpc.ClientCall
import io.grpc.ClientInterceptors
import io.grpc.Context
import io.grpc.Contexts
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
import io.grpc.inprocess.InProcessChannelBuilder
import io.grpc.inprocess.InProcessServerBuilder
import io.grpc.stub.ClientCalls
import io.grpc.stub.ServerCalls
import io.grpc.stub.StreamObserver
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Base64
import java.util.Collections
import java.util.HexFormat
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

/**
 * The management-plane DPoP signer (seam-sdk#290). conformance/mgmt_dpop_vector.json is the cross-language
 * contract, and an in-process server with a raw-bytes marshaller checks that seam_bd covers exactly the
 * bytes it received.
 */
class MgmtDpopTest {
    private val b64 = Base64.getUrlEncoder().withoutPadding()
    private val b64d = Base64.getUrlDecoder()
    private val hex = HexFormat.of()

    private fun vector(): JsonObject {
        val v = JsonParser.parseString(Files.readString(Path.of("..", "conformance", "mgmt_dpop_vector.json"))).asJsonObject
        assertTrue(v.getAsJsonArray("derived").size() >= 5 && v.getAsJsonArray("jwk_rejects").size() >= 10)
        return v
    }

    private fun JsonObject.s(k: String): String = get(k).asString
    private fun golden(v: JsonObject) = v.getAsJsonObject("golden")
    private fun goldenKey(v: JsonObject) = MgmtDpop.Key.fromSeed(hex.parseHex(golden(v).s("seed_hex")))
    private fun segment(proof: String, i: Int) = String(b64d.decode(proof.split(".")[i]), Charsets.UTF_8)
    private fun sha(b: ByteArray): String = b64.encodeToString(MessageDigest.getInstance("SHA-256").digest(b))

    // ── the golden vector ──────────────────────────────────────────────────────────────────────

    @Test
    fun goldenKeyAndThumbprint() {
        val v = vector()
        val g = golden(v)
        val k = goldenKey(v)
        assertEquals(g.s("x"), k.x)
        assertEquals(g.s("jkt"), k.jkt)
        assertEquals(g.s("jkt"), MgmtDpop.Key.fromJwk(g.get("jwk").toString()).jkt)
    }

    @Test
    fun goldenProofIsByteExact() {
        val v = vector()
        val g = golden(v)
        val htu = MgmtDpop.grpcHtu(g.s("method"), g.s("aud"))
        assertEquals(g.s("htu"), htu)
        val proof = MgmtDpop.proof(goldenKey(v), g.s("token"), g.s("htm"), htu, hex.parseHex(g.s("message_hex")),
            g.get("iat").asLong, g.s("jti"))
        assertEquals(g.s("proof"), proof)
        assertEquals(g.s("header_json"), segment(proof, 0))
        assertEquals(g.s("claims_json"), segment(proof, 1))
        val claims = JsonParser.parseString(g.s("claims_json")).asJsonObject
        assertEquals(g.s("ath"), claims.s("ath"))
        assertEquals(g.s("seam_bd"), claims.s("seam_bd"))
    }

    @Test
    fun theSeedIsCopied() {
        val v = vector()
        val g = golden(v)
        val seed = hex.parseHex(g.s("seed_hex"))
        val k = MgmtDpop.Key.fromSeed(seed)
        seed[0] = (seed[0].toInt() xor 1).toByte()
        assertEquals(g.s("proof"), MgmtDpop.proof(k, g.s("token"), g.s("htm"), g.s("htu"),
            hex.parseHex(g.s("message_hex")), g.get("iat").asLong, g.s("jti")))
    }

    @Test
    fun derivedProofs() {
        val v = vector()
        val k = goldenKey(v)
        val token = golden(v).s("token")
        for (e in v.getAsJsonArray("derived")) {
            val c = e.asJsonObject
            val body = hex.parseHex(c.s("message_hex"))
            val iat = c.get("iat").asLong
            val proof = if (c.has("url")) {
                assertEquals(c.s("htu"), MgmtDpop.httpHtu(c.s("url")), c.s("name"))
                val h = MgmtDpop.httpHeaders(k, token, c.s("htm"), c.s("url"), body, iat, c.s("jti"))
                assertEquals("DPoP $token", h["Authorization"])
                h.getValue("DPoP")
            } else {
                MgmtDpop.proof(k, token, c.s("htm"), c.s("htu"), body, iat, c.s("jti"))
            }
            assertEquals(c.s("proof"), proof, c.s("name"))
        }
    }

    @Test
    fun htuCases() {
        val v = vector()
        for (e in v.getAsJsonArray("grpc_htu")) {
            val c = e.asJsonObject
            assertEquals(c.s("htu"), MgmtDpop.grpcHtu(c.s("method"), c.s("aud")))
        }
        for (e in v.getAsJsonArray("http_htu")) {
            val c = e.asJsonObject
            assertEquals(c.s("htu"), MgmtDpop.httpHtu(c.s("url")), c.s("url"))
        }
        for (e in v.getAsJsonArray("http_htu_rejects")) {
            val c = e.asJsonObject
            assertThrows(MgmtDpop.DpopException::class.java, { MgmtDpop.httpHtu(c.s("url")) }, c.s("reason"))
        }
    }

    @Test
    fun jwkRejectsAndAccepts() {
        val v = vector()
        for (e in v.getAsJsonArray("jwk_rejects")) {
            val c = e.asJsonObject
            assertThrows(MgmtDpop.DpopKeyException::class.java, { MgmtDpop.Key.fromJwk(c.get("jwk").toString()) }, c.s("reason"))
        }
        for (e in v.getAsJsonArray("jwk_accepts")) {
            assertEquals(golden(v).s("jkt"), MgmtDpop.Key.fromJwk(e.asJsonObject.get("jwk").toString()).jkt)
        }
        // Strict JSON only: Gson's lenient defaults would accept each of these.
        val jwk = golden(v).get("jwk").toString()
        for (text in listOf("{kty: OKP", "[]", "null", "\"s\"", jwk.replace('"', '\''), "$jwk {}", "// c\n$jwk", "", "\uFEFF$jwk")) {
            assertThrows(MgmtDpop.DpopKeyException::class.java, { MgmtDpop.Key.fromJwk(text) }, text)
        }
        assertThrows(MgmtDpop.DpopKeyException::class.java) { MgmtDpop.Key.fromSeed(ByteArray(31)) }
    }

    // ── local refusals ─────────────────────────────────────────────────────────────────────────

    @Test
    fun localRefusals() {
        val v = vector()
        val k = goldenKey(v)
        assertEquals(v.get("iat_max").asLong, MgmtDpop.MAX_IAT)
        MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m", ByteArray(0), MgmtDpop.MAX_IAT)
        MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m", ByteArray(0), 0L, "j".repeat(MgmtDpop.MAX_JTI_BYTES))
        MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m", ByteArray(MgmtDpop.MAX_BODY_BYTES))
        val cases: List<() -> Unit> = listOf(
            { MgmtDpop.proof(k, "", "POST", "grpc://a/m") },
            { MgmtDpop.proof(k, "a b", "POST", "grpc://a/m") },
            { MgmtDpop.proof(k, "a.é.c", "POST", "grpc://a/m") },
            { MgmtDpop.proof(k, "a.b.c", "PO ST", "grpc://a/m") },
            { MgmtDpop.proof(k, "a.b.c", "", "grpc://a/m") },
            { MgmtDpop.proof(k, "a.b.c", "POST", "") },
            { MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m\n") },
            { MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m", ByteArray(MgmtDpop.MAX_BODY_BYTES + 1)) },
            { MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m", ByteArray(0), -1L) },
            { MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m", ByteArray(0), MgmtDpop.MAX_IAT + 1) },
            { MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m", ByteArray(0), 0L, "") },
            { MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m", ByteArray(0), 0L, "é") },
            { MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m", ByteArray(0), 0L, "j".repeat(MgmtDpop.MAX_JTI_BYTES + 1)) },
            { MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/" + "m".repeat(MgmtDpop.MAX_PROOF_BYTES)) },
            { MgmtDpop.grpcHtu("noslash") },
            { MgmtDpop.grpcHtu("/m", "a/b") },
            { MgmtDpop.grpcHtu("/m", "") },
        )
        cases.forEachIndexed { i, case ->
            val e = assertThrows(MgmtDpop.DpopException::class.java, { case() }, "case $i")
            assertFalse(e is MgmtDpop.DpopKeyException, "case $i is a bad argument, not a key error")
        }
    }

    @Test
    fun freshProofsVerifyAndCarryDistinctJtis() {
        val k = goldenKey(vector())
        val jtis = mutableSetOf<String>()
        repeat(50) {
            val p = MgmtDpop.proof(k, "a.b.c", "POST", "grpc://seam-runtime/m", byteArrayOf(1))
            assertTrue(verifies(k, p))
            val jti = JsonParser.parseString(segment(p, 1)).asJsonObject.s("jti")
            assertEquals(22, jti.length)
            assertTrue(jtis.add(jti))
        }
    }

    @Test
    fun theKeyNeverFormatsItsPrivateHalf() {
        val v = vector()
        val k = goldenKey(v)
        val seedHex = golden(v).s("seed_hex")
        val seedB64 = b64.encodeToString(hex.parseHex(seedHex))
        for (out in listOf(k.toString(), "$k", listOf(k).toString(), mapOf("k" to k).toString())) {
            assertFalse(out.contains(seedHex) || out.contains(seedB64), out)
            assertTrue(out.contains(k.jkt), out)
        }
    }

    // ── the interceptor, against an in-process server that records the raw bytes ───────────────

    private val bytes = object : MethodDescriptor.Marshaller<ByteArray> {
        override fun stream(value: ByteArray): InputStream = ByteArrayInputStream(value)
        override fun parse(stream: InputStream): ByteArray = stream.readAllBytes()
    }

    private fun method(name: String, type: MethodDescriptor.MethodType): MethodDescriptor<ByteArray, ByteArray> =
        MethodDescriptor.newBuilder(bytes, bytes).setType(type).setFullMethodName(name).build()

    private val enroll = method("seam.api.v1.SeamAdmin/EnrollTenant", MethodDescriptor.MethodType.UNARY)
    private val stream = method("seam.api.v1.SeamEvents/StreamEvents", MethodDescriptor.MethodType.SERVER_STREAMING)

    private val authKey = Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER)
    private val dpopKey = Metadata.Key.of("dpop", Metadata.ASCII_STRING_MARSHALLER)
    private val tenantKey = Metadata.Key.of(TenantRouting.TENANT_HEADER, Metadata.ASCII_STRING_MARSHALLER)
    private val headersKey: Context.Key<Metadata> = Context.key("headers")

    private data class Received(val method: String, val headers: Metadata, val body: ByteArray)

    private val received: MutableList<Received> = Collections.synchronizedList(mutableListOf())
    private lateinit var server: Server
    private lateinit var channel: ManagedChannel
    private val key = MgmtDpop.Key.fromSeed(ByteArray(32) { 0x42 })
    private val other = MgmtDpop.Key.fromSeed(ByteArray(32) { 0x07 })
    private val bound = token(mapOf("aud" to "seam-runtime", "cnf" to mapOf("jkt" to key.jkt)))

    private fun token(claims: Map<String, Any?>): String =
        b64.encodeToString("""{"alg":"EdDSA","typ":"JWT"}""".toByteArray()) + "." +
            b64.encodeToString(Gson().newBuilder().serializeNulls().create().toJson(claims).toByteArray()) + ".c2ln"

    @BeforeEach
    fun start() {
        val name = InProcessServerBuilder.generateName()
        // Each call's headers ride its own gRPC Context, so concurrent calls cannot see each other's.
        val capture = object : ServerInterceptor {
            override fun <Q, R> interceptCall(call: ServerCall<Q, R>, headers: Metadata, next: ServerCallHandler<Q, R>) =
                Contexts.interceptCall(Context.current().withValue(headersKey, headers), call, headers, next)
        }
        val admin = ServerServiceDefinition.builder("seam.api.v1.SeamAdmin")
            .addMethod(enroll, ServerCalls.asyncUnaryCall { req, out ->
                received.add(Received(enroll.fullMethodName, headersKey.get(), req))
                out.onNext(ByteArray(0))
                out.onCompleted()
            })
            .build()
        val events = ServerServiceDefinition.builder("seam.api.v1.SeamEvents")
            .addMethod(stream, ServerCalls.asyncServerStreamingCall { req, out ->
                received.add(Received(stream.fullMethodName, headersKey.get(), req))
                out.onNext(ByteArray(0))
                out.onNext(ByteArray(0))
                out.onCompleted()
            })
            .build()
        server = InProcessServerBuilder.forName(name).directExecutor()
            .addService(ServerInterceptors.intercept(admin, capture))
            .addService(ServerInterceptors.intercept(events, capture))
            .build()
            .start()
        channel = InProcessChannelBuilder.forName(name).directExecutor().build()
    }

    @AfterEach
    fun stop() {
        channel.shutdownNow()
        server.shutdownNow()
    }

    private fun signed(token: String, aud: String? = null): Channel =
        ClientInterceptors.intercept(channel, MgmtDpop.interceptor(key, token, aud))

    private fun verifies(k: MgmtDpop.Key, proof: String): Boolean {
        val at = proof.lastIndexOf('.')
        val v = Ed25519Signer()
        v.init(false, Ed25519PublicKeyParameters(b64d.decode(k.x), 0))
        val msg = proof.substring(0, at).toByteArray(Charsets.US_ASCII)
        v.update(msg, 0, msg.size)
        return v.verifySignature(b64d.decode(proof.substring(at + 1)))
    }

    /** Checks one received call's DPoP headers against the bytes the server received; returns its claims. */
    private fun checkProof(r: Received, token: String, aud: String): JsonObject {
        assertEquals("DPoP $token", r.headers.get(authKey))
        val proof = r.headers.get(dpopKey)
        assertNotNull(proof)
        assertTrue(verifies(key, proof!!), "the proof signature verifies")
        val claims = JsonParser.parseString(segment(proof, 1)).asJsonObject
        assertEquals("POST", claims.s("htm"))
        assertEquals("grpc://$aud/${r.method}", claims.s("htu"))
        assertEquals(sha(r.body), claims.s("seam_bd"), "seam_bd covers the received bytes")
        assertEquals(sha(token.toByteArray(Charsets.US_ASCII)), claims.s("ath"))
        return claims
    }

    @Test
    fun aUnaryProofBindsTheReceivedBytes() {
        val body = byteArrayOf(0x0a, 0x04) + "acme".toByteArray()
        ClientCalls.blockingUnaryCall(signed(bound), enroll, CallOptions.DEFAULT, body)
        assertEquals(1, received.size)
        assertEquals(hex.formatHex(body), hex.formatHex(received[0].body))
        checkProof(received[0], bound, "seam-runtime")
    }

    @Test
    fun anEmptyMessageIsSigned() {
        ClientCalls.blockingUnaryCall(signed(bound), enroll, CallOptions.DEFAULT, ByteArray(0))
        checkProof(received[0], bound, "seam-runtime")
    }

    @Test
    fun aBlockingServerStreamSignsItsOneRequest() {
        val it = ClientCalls.blockingServerStreamingCall(signed(bound), stream, CallOptions.DEFAULT, byteArrayOf(0x0a, 0x02, 0x73, 0x31))
        var n = 0
        while (it.hasNext()) {
            it.next()
            n++
        }
        assertEquals(2, n)
        checkProof(received[0], bound, "seam-runtime")
    }

    @Test
    fun anAsyncServerStreamRequestsBeforeSendingAndStillGetsEverything() {
        // asyncServerStreamingCall calls request(n) before sendMessage: the delayed call must queue it.
        val done = CompletableFuture<Int>()
        ClientCalls.asyncServerStreamingCall(signed(bound).newCall(stream, CallOptions.DEFAULT), byteArrayOf(1),
            object : StreamObserver<ByteArray> {
                var n = 0
                override fun onNext(value: ByteArray) {
                    n++
                }
                override fun onError(t: Throwable) {
                    done.completeExceptionally(t)
                }
                override fun onCompleted() {
                    done.complete(n)
                }
            })
        assertEquals(2, done.get(5, TimeUnit.SECONDS))
        checkProof(received[0], bound, "seam-runtime")
    }

    /** A listener that records how the call closed. */
    private class Closing : ClientCall.Listener<ByteArray>() {
        val status = CompletableFuture<Status>()
        override fun onClose(s: Status, trailers: Metadata) {
            status.complete(s)
        }
    }

    @Test
    fun cancelBeforeSendMessageNeverReachesTheServer() {
        val call = signed(bound).newCall(enroll, CallOptions.DEFAULT)
        val l = Closing()
        call.start(l, Metadata())
        call.request(1)
        call.cancel("caller gave up", null)
        assertEquals(Status.Code.CANCELLED, l.status.get(5, TimeUnit.SECONDS).code)
        call.sendMessage(byteArrayOf(1)) // after cancel: a no-op, as on any cancelled call
        call.halfClose()
        assertTrue(received.isEmpty())
        assertFalse(call.isReady)
    }

    @Test
    fun halfCloseWithNoMessageIsRefusedLocally() {
        val call = signed(bound).newCall(enroll, CallOptions.DEFAULT)
        val l = Closing()
        call.start(l, Metadata())
        call.halfClose()
        val s = l.status.get(5, TimeUnit.SECONDS)
        assertEquals(Status.Code.INTERNAL, s.code)
        assertTrue(s.description!!.contains("exactly one request message"))
        assertTrue(received.isEmpty())
    }

    @Test
    fun aSecondMessageIsRefused() {
        val call = signed(bound).newCall(stream, CallOptions.DEFAULT)
        call.start(Closing(), Metadata())
        call.sendMessage(byteArrayOf(1))
        assertThrows(IllegalStateException::class.java) { call.sendMessage(byteArrayOf(2)) }
        call.cancel("done", null)
    }

    @Test
    fun sendMessageBeforeStartIsRefused() {
        val call = signed(bound).newCall(enroll, CallOptions.DEFAULT)
        assertThrows(IllegalStateException::class.java) { call.sendMessage(byteArrayOf(1)) }
    }

    @Test
    fun anOversizedMessageIsRefusedBeforeTheWire() {
        val ch = signed(bound)
        assertThrows(RuntimeException::class.java) {
            ClientCalls.blockingUnaryCall(ch, enroll, CallOptions.DEFAULT, ByteArray(MgmtDpop.MAX_BODY_BYTES + 1))
        }
        assertTrue(received.isEmpty())
    }

    @Test
    fun clientStreamingMethodsAreRefused() {
        val bidi = method("x.Y/Z", MethodDescriptor.MethodType.BIDI_STREAMING)
        assertThrows(IllegalStateException::class.java) { signed(bound).newCall(bidi, CallOptions.DEFAULT) }
    }

    @Test
    fun audResolution() {
        val jkt = mapOf("jkt" to key.jkt)
        val cases = listOf(
            Triple(mapOf("aud" to "ops.internal", "cnf" to jkt), null, "ops.internal"),
            Triple(mapOf("aud" to "seam-runtime", "cnf" to jkt), "cell-7", "cell-7"),
            Triple(mapOf("cnf" to jkt), null, "seam-runtime"),
            Triple(mapOf("aud" to listOf("a", "b"), "cnf" to jkt), "cell-7", "cell-7"),
        )
        for ((claims, aud, want) in cases) {
            received.clear()
            val tok = token(claims)
            ClientCalls.blockingUnaryCall(signed(tok, aud), enroll, CallOptions.DEFAULT, ByteArray(0))
            checkProof(received[0], tok, want)
        }
    }

    @Test
    fun theClockSetsIat() {
        val ch = ClientInterceptors.intercept(channel, MgmtDpop.interceptor(key, bound, null) { 1234L })
        ClientCalls.blockingUnaryCall(ch, enroll, CallOptions.DEFAULT, ByteArray(0))
        assertEquals(1234L, checkProof(received[0], bound, "seam-runtime").get("iat").asLong)
    }

    @Test
    fun concurrentCallsCarryDistinctProofs() {
        val ch = ClientInterceptors.intercept(channel, MgmtDpop.interceptor(key, bound, null) { 1L })
        val pool = Executors.newFixedThreadPool(8)
        val go = CountDownLatch(1)
        val all = (1..32).map {
            CompletableFuture.runAsync({
                go.await()
                ClientCalls.blockingUnaryCall(ch, enroll, CallOptions.DEFAULT, byteArrayOf(7))
            }, pool)
        }
        go.countDown()
        CompletableFuture.allOf(*all.toTypedArray()).get(10, TimeUnit.SECONDS)
        pool.shutdown()
        val jtis = synchronized(received) { received.map { checkProof(it, bound, "seam-runtime").s("jti") }.toSet() }
        assertEquals(32, jtis.size)
    }

    @Test
    fun theTenantHeaderRidesAlongside() {
        val ch = ClientInterceptors.intercept(signed(bound), TenantRouting.interceptor("acme"))
        ClientCalls.blockingUnaryCall(ch, enroll, CallOptions.DEFAULT, ByteArray(0))
        assertEquals("acme", received[0].headers.get(tenantKey))
        checkProof(received[0], bound, "seam-runtime")
    }

    // ── guaranteed-to-fail pairings are refused before any call ────────────────────────────────

    @Test
    fun constructionRefusals() {
        val jkt = mapOf("jkt" to key.jkt)
        val keyCases = listOf(
            Triple(key, "", "needs token"),
            Triple(key, token(mapOf("aud" to "seam-runtime")), "not DPoP-bound"),
            Triple(other, bound, "bound to key"),
            Triple(key, token(mapOf("aud" to listOf("a", "b"), "cnf" to jkt)), "not a single string"),
            Triple(key, token(mapOf("aud" to null, "cnf" to jkt)), "not a single string"),
            Triple(key, token(mapOf("aud" to 7, "cnf" to jkt)), "not a single string"),
            Triple(key, "not-a-jws", "compact JWS"),
            Triple(key, token(mapOf("cnf" to "x")), "malformed"),
            Triple(key, token(mapOf("cnf" to mapOf("jkt" to 7))), "malformed"),
            Triple(key, "a." + b64.encodeToString("{".toByteArray()) + ".c", "not JSON"),
            Triple(key, "a." + b64.encodeToString("[".repeat(5000).toByteArray()) + ".c", "not JSON"),
        )
        for ((k, tok, match) in keyCases) {
            val e = assertThrows(MgmtDpop.DpopKeyException::class.java, { MgmtDpop.interceptor(k, tok) }, match)
            assertTrue(e.message!!.contains(match), e.message)
        }
        val argCases: List<() -> Unit> = listOf(
            { MgmtDpop.interceptor(key, bound, "a/b") },
            { MgmtDpop.interceptor(key, bound, "") },
            { MgmtDpop.interceptor(key, token(mapOf("aud" to "has space", "cnf" to jkt))) },
            { MgmtDpop.interceptor(key, bound, null) { -1L } },
            { MgmtDpop.interceptor(key, "a b") },
        )
        argCases.forEachIndexed { i, case ->
            val e = assertThrows(MgmtDpop.DpopException::class.java, { case() }, "case $i")
            assertFalse(e is MgmtDpop.DpopKeyException, "case $i")
        }
        // A bad clock is named before the token is read, as in Python: even an unbound token reports the clock.
        val e = assertThrows(MgmtDpop.DpopException::class.java) { MgmtDpop.interceptor(key, "not-a-jws", null) { -1L } }
        assertTrue(e.message!!.contains("clock"), e.message)
    }

    @Test
    fun halfCloseBeforeStartIsRefused() {
        val call = signed(bound).newCall(enroll, CallOptions.DEFAULT)
        assertThrows(IllegalStateException::class.java) { call.halfClose() }
    }

    /** The README's Kotlin snippet, verbatim between the markers (python/tests/test_readme_dpop_snippets.py). */
    private fun readmeSnippet(channel: Channel): Channel {
        // README:dpop:begin
        val key = MgmtDpop.Key.fromJwk(System.getenv("SEAM_OPERATOR_DPOP_JWK"))
        val signed = ClientInterceptors.intercept(channel, MgmtDpop.interceptor(key, System.getenv("SEAM_OPERATOR_TOKEN")))
        // README:dpop:end
        return signed
    }

    @Test
    fun theReadmeSnippetSigns() {
        ClientCalls.blockingUnaryCall(readmeSnippet(channel), enroll, CallOptions.DEFAULT, byteArrayOf(1))
        checkProof(received[0], System.getenv("SEAM_OPERATOR_TOKEN"), "seam-runtime")
    }

    @Test
    fun gsonNeverSerialisesTheSeed() {
        val json = Gson().toJson(goldenKey(vector()))
        assertFalse(json.contains("seed"), json)
        assertFalse(json.contains("66,66"), json)
    }
}
