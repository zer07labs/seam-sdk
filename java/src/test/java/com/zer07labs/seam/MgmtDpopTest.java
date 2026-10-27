package com.zer07labs.seam;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptors;
import io.grpc.Context;
import io.grpc.Contexts;
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
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.ClientCalls;
import io.grpc.stub.ServerCalls;
import io.grpc.stub.StreamObserver;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The management-plane DPoP signer (seam-sdk#290). conformance/mgmt_dpop_vector.json is the
 * cross-language contract, and an in-process server with a raw-bytes marshaller checks that seam_bd
 * covers exactly the bytes it received.
 */
class MgmtDpopTest {
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();
    private static final HexFormat HEX = HexFormat.of();

    private static JsonObject vector() throws IOException {
        JsonObject v = JsonParser.parseString(
                        Files.readString(Path.of("..", "conformance", "mgmt_dpop_vector.json")))
                .getAsJsonObject();
        assertTrue(v.getAsJsonArray("derived").size() >= 5 && v.getAsJsonArray("jwk_rejects").size() >= 10);
        return v;
    }

    private static MgmtDpop.Key goldenKey(JsonObject v) {
        return MgmtDpop.Key.fromSeed(HEX.parseHex(v.getAsJsonObject("golden").get("seed_hex").getAsString()));
    }

    private static String str(JsonObject o, String k) {
        return o.get(k).getAsString();
    }

    private static String segment(String proof, int i) {
        return new String(B64D.decode(proof.split("\\.")[i]), StandardCharsets.UTF_8);
    }

    private static String sha(byte[] b) throws Exception {
        return B64.encodeToString(MessageDigest.getInstance("SHA-256").digest(b));
    }

    // ── the golden vector ──────────────────────────────────────────────────────────────────────

    @Test
    void goldenKeyAndThumbprint() throws IOException {
        JsonObject v = vector();
        JsonObject g = v.getAsJsonObject("golden");
        MgmtDpop.Key k = goldenKey(v);
        assertEquals(str(g, "x"), k.x());
        assertEquals(str(g, "jkt"), k.jkt());
        assertEquals(str(g, "jkt"), MgmtDpop.Key.fromJwk(g.get("jwk").toString()).jkt());
    }

    @Test
    void goldenProofIsByteExact() throws IOException {
        JsonObject v = vector();
        JsonObject g = v.getAsJsonObject("golden");
        String htu = MgmtDpop.grpcHtu(str(g, "method"), str(g, "aud"));
        assertEquals(str(g, "htu"), htu);
        String proof = MgmtDpop.proof(goldenKey(v), str(g, "token"), str(g, "htm"), htu,
                HEX.parseHex(str(g, "message_hex")), g.get("iat").getAsLong(), str(g, "jti"));
        assertEquals(str(g, "proof"), proof);
        assertEquals(str(g, "header_json"), segment(proof, 0));
        assertEquals(str(g, "claims_json"), segment(proof, 1));
        JsonObject claims = JsonParser.parseString(str(g, "claims_json")).getAsJsonObject();
        assertEquals(str(g, "ath"), str(claims, "ath"));
        assertEquals(str(g, "seam_bd"), str(claims, "seam_bd"));
    }

    @Test
    void theSeedIsCopied() throws IOException {
        JsonObject v = vector();
        JsonObject g = v.getAsJsonObject("golden");
        byte[] seed = HEX.parseHex(str(g, "seed_hex"));
        MgmtDpop.Key k = MgmtDpop.Key.fromSeed(seed);
        seed[0] ^= 1;
        assertEquals(str(g, "proof"), MgmtDpop.proof(k, str(g, "token"), str(g, "htm"), str(g, "htu"),
                HEX.parseHex(str(g, "message_hex")), g.get("iat").getAsLong(), str(g, "jti")));
    }

    @Test
    void derivedProofs() throws IOException {
        JsonObject v = vector();
        MgmtDpop.Key k = goldenKey(v);
        String token = str(v.getAsJsonObject("golden"), "token");
        for (JsonElement e : v.getAsJsonArray("derived")) {
            JsonObject c = e.getAsJsonObject();
            byte[] body = HEX.parseHex(str(c, "message_hex"));
            long iat = c.get("iat").getAsLong();
            String proof;
            if (c.has("url")) {
                assertEquals(str(c, "htu"), MgmtDpop.httpHtu(str(c, "url")), str(c, "name"));
                Map<String, String> h =
                        MgmtDpop.httpHeaders(k, token, str(c, "htm"), str(c, "url"), body, iat, str(c, "jti"));
                assertEquals("DPoP " + token, h.get("Authorization"));
                proof = h.get("DPoP");
            } else {
                proof = MgmtDpop.proof(k, token, str(c, "htm"), str(c, "htu"), body, iat, str(c, "jti"));
            }
            assertEquals(str(c, "proof"), proof, str(c, "name"));
        }
    }

    @Test
    void htuCases() throws IOException {
        JsonObject v = vector();
        for (JsonElement e : v.getAsJsonArray("grpc_htu")) {
            JsonObject c = e.getAsJsonObject();
            assertEquals(str(c, "htu"), MgmtDpop.grpcHtu(str(c, "method"), str(c, "aud")));
        }
        for (JsonElement e : v.getAsJsonArray("http_htu")) {
            JsonObject c = e.getAsJsonObject();
            assertEquals(str(c, "htu"), MgmtDpop.httpHtu(str(c, "url")), str(c, "url"));
        }
        for (JsonElement e : v.getAsJsonArray("http_htu_rejects")) {
            JsonObject c = e.getAsJsonObject();
            assertThrows(MgmtDpop.DpopException.class, () -> MgmtDpop.httpHtu(str(c, "url")), str(c, "reason"));
        }
    }

    @Test
    void jwkRejectsAndAccepts() throws IOException {
        JsonObject v = vector();
        for (JsonElement e : v.getAsJsonArray("jwk_rejects")) {
            JsonObject c = e.getAsJsonObject();
            assertThrows(MgmtDpop.DpopKeyException.class, () -> MgmtDpop.Key.fromJwk(c.get("jwk").toString()),
                    str(c, "reason"));
        }
        for (JsonElement e : v.getAsJsonArray("jwk_accepts")) {
            JsonObject c = e.getAsJsonObject();
            assertEquals(str(v.getAsJsonObject("golden"), "jkt"),
                    MgmtDpop.Key.fromJwk(c.get("jwk").toString()).jkt());
        }
        // Strict JSON only: Gson's lenient defaults would accept each of these.
        String jwk = v.getAsJsonObject("golden").get("jwk").toString();
        for (String text : List.of("{kty: OKP", "[]", "null", "\"s\"", jwk.replace('"', '\''), jwk + " {}",
                "// c\n" + jwk, "", "\uFEFF" + jwk)) {
            assertThrows(MgmtDpop.DpopKeyException.class, () -> MgmtDpop.Key.fromJwk(text), text);
        }
        assertThrows(MgmtDpop.DpopKeyException.class, () -> MgmtDpop.Key.fromJwk(null));
        assertThrows(MgmtDpop.DpopKeyException.class, () -> MgmtDpop.Key.fromSeed(new byte[31]));
    }

    // ── local refusals ─────────────────────────────────────────────────────────────────────────

    @Test
    void localRefusals() throws IOException {
        JsonObject v = vector();
        MgmtDpop.Key k = goldenKey(v);
        assertEquals(v.get("iat_max").getAsLong(), MgmtDpop.MAX_IAT);
        MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m", null, MgmtDpop.MAX_IAT, null);
        MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m", null, 0L, "j".repeat(MgmtDpop.MAX_JTI_BYTES));
        MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m", new byte[MgmtDpop.MAX_BODY_BYTES]);
        List<Runnable> cases = List.of(
                () -> MgmtDpop.proof(null, "a.b.c", "POST", "grpc://a/m", null),
                () -> MgmtDpop.proof(k, "", "POST", "grpc://a/m", null),
                () -> MgmtDpop.proof(k, null, "POST", "grpc://a/m", null),
                () -> MgmtDpop.proof(k, "a b", "POST", "grpc://a/m", null),
                () -> MgmtDpop.proof(k, "a.é.c", "POST", "grpc://a/m", null),
                () -> MgmtDpop.proof(k, "a.b.c", "PO ST", "grpc://a/m", null),
                () -> MgmtDpop.proof(k, "a.b.c", "", "grpc://a/m", null),
                () -> MgmtDpop.proof(k, "a.b.c", "POST", "", null),
                () -> MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m\n", null),
                () -> MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m", new byte[MgmtDpop.MAX_BODY_BYTES + 1]),
                () -> MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m", null, -1L, null),
                () -> MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m", null, MgmtDpop.MAX_IAT + 1, null),
                () -> MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m", null, 0L, ""),
                () -> MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m", null, 0L, "é"),
                () -> MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/m", null, 0L,
                        "j".repeat(MgmtDpop.MAX_JTI_BYTES + 1)),
                () -> MgmtDpop.proof(k, "a.b.c", "POST", "grpc://a/" + "m".repeat(MgmtDpop.MAX_PROOF_BYTES), null),
                () -> MgmtDpop.grpcHtu("noslash", null),
                () -> MgmtDpop.grpcHtu("/m", "a/b"),
                () -> MgmtDpop.grpcHtu("/m", ""),
                () -> MgmtDpop.httpHtu(null));
        for (int i = 0; i < cases.size(); i++) {
            MgmtDpop.DpopException e = assertThrows(MgmtDpop.DpopException.class, cases.get(i)::run, "case " + i);
            assertFalse(e instanceof MgmtDpop.DpopKeyException, "case " + i + " is a bad argument, not a key error");
        }
    }

    @Test
    void freshProofsVerifyAndCarryDistinctJtis() throws Exception {
        MgmtDpop.Key k = goldenKey(vector());
        Set<String> jtis = new HashSet<>();
        for (int i = 0; i < 50; i++) {
            String p = MgmtDpop.proof(k, "a.b.c", "POST", "grpc://seam-runtime/m", new byte[] {1});
            assertTrue(verifies(k, p));
            String jti = str(JsonParser.parseString(segment(p, 1)).getAsJsonObject(), "jti");
            assertEquals(22, jti.length());
            assertTrue(jtis.add(jti));
        }
    }

    @Test
    void theKeyNeverFormatsItsPrivateHalf() throws IOException {
        JsonObject v = vector();
        MgmtDpop.Key k = goldenKey(v);
        String seedHex = str(v.getAsJsonObject("golden"), "seed_hex");
        String seedB64 = B64.encodeToString(HEX.parseHex(seedHex));
        for (String out : List.of(k.toString(), String.valueOf(k), "" + List.of(k))) {
            assertFalse(out.contains(seedHex) || out.contains(seedB64), out);
            assertTrue(out.contains(k.jkt()), out);
        }
    }

    // ── the interceptor, against an in-process server that records the raw bytes ───────────────

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

    private static MethodDescriptor<byte[], byte[]> method(String name, MethodDescriptor.MethodType type) {
        return MethodDescriptor.newBuilder(BYTES, BYTES).setType(type).setFullMethodName(name).build();
    }

    private static final MethodDescriptor<byte[], byte[]> ENROLL =
            method("seam.api.v1.SeamAdmin/EnrollTenant", MethodDescriptor.MethodType.UNARY);
    private static final MethodDescriptor<byte[], byte[]> STREAM =
            method("seam.api.v1.SeamEvents/StreamEvents", MethodDescriptor.MethodType.SERVER_STREAMING);

    private static final Metadata.Key<String> AUTH = Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
    private static final Metadata.Key<String> DPOP = Metadata.Key.of("dpop", Metadata.ASCII_STRING_MARSHALLER);
    private static final Metadata.Key<String> TENANT =
            Metadata.Key.of(TenantRouting.TENANT_HEADER, Metadata.ASCII_STRING_MARSHALLER);

    private static final Context.Key<Metadata> HEADERS = Context.key("headers");

    private record Received(String method, Metadata headers, byte[] body) {}

    private final List<Received> received = Collections.synchronizedList(new ArrayList<>());
    private Server server;
    private ManagedChannel channel;
    private final MgmtDpop.Key key = MgmtDpop.Key.fromSeed(filled(0x42));
    private final MgmtDpop.Key other = MgmtDpop.Key.fromSeed(filled(0x07));
    private final String bound = token(Map.of("aud", "seam-runtime", "cnf", Map.of("jkt", key.jkt())));

    private static byte[] filled(int b) {
        byte[] s = new byte[32];
        java.util.Arrays.fill(s, (byte) b);
        return s;
    }

    private static String token(Map<String, Object> claims) {
        Gson gson = new Gson();
        return B64.encodeToString("{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + B64.encodeToString(gson.toJson(claims).getBytes(StandardCharsets.UTF_8)) + ".c2ln";
    }

    /** A bound token whose aud is JSON null (Map.of refuses null values). */
    private String nullAud() {
        return B64.encodeToString("{}".getBytes(StandardCharsets.UTF_8)) + "."
                + B64.encodeToString(("{\"aud\":null,\"cnf\":{\"jkt\":\"" + key.jkt() + "\"}}")
                        .getBytes(StandardCharsets.UTF_8))
                + ".c2ln";
    }

    @BeforeEach
    void start() throws IOException {
        String name = InProcessServerBuilder.generateName();
        // Each call's headers ride its own gRPC Context, so concurrent calls cannot see each other's.
        ServerInterceptor capture = new ServerInterceptor() {
            @Override
            public <Q, R> ServerCall.Listener<Q> interceptCall(
                    ServerCall<Q, R> call, Metadata headers, ServerCallHandler<Q, R> next) {
                return Contexts.interceptCall(Context.current().withValue(HEADERS, headers), call, headers, next);
            }
        };
        ServerCalls.UnaryMethod<byte[], byte[]> unary = (req, out) -> {
            received.add(new Received(ENROLL.getFullMethodName(), HEADERS.get(), req));
            out.onNext(new byte[0]);
            out.onCompleted();
        };
        ServerCalls.ServerStreamingMethod<byte[], byte[]> stream = (req, out) -> {
            received.add(new Received(STREAM.getFullMethodName(), HEADERS.get(), req));
            out.onNext(new byte[0]);
            out.onNext(new byte[0]);
            out.onCompleted();
        };
        ServerServiceDefinition admin = ServerServiceDefinition.builder("seam.api.v1.SeamAdmin")
                .addMethod(ENROLL, ServerCalls.asyncUnaryCall(unary))
                .build();
        ServerServiceDefinition events = ServerServiceDefinition.builder("seam.api.v1.SeamEvents")
                .addMethod(STREAM, ServerCalls.asyncServerStreamingCall(stream))
                .build();
        server = InProcessServerBuilder.forName(name)
                .directExecutor()
                .addService(ServerInterceptors.intercept(admin, capture))
                .addService(ServerInterceptors.intercept(events, capture))
                .build()
                .start();
        channel = InProcessChannelBuilder.forName(name).directExecutor().build();
    }

    @AfterEach
    void stop() {
        channel.shutdownNow();
        server.shutdownNow();
    }

    private Channel signed(String token, String aud) {
        return ClientInterceptors.intercept(channel, MgmtDpop.interceptor(key, token, aud));
    }

    private static boolean verifies(MgmtDpop.Key k, String proof) {
        int at = proof.lastIndexOf('.');
        Ed25519Signer v = new Ed25519Signer();
        v.init(false, new Ed25519PublicKeyParameters(B64D.decode(k.x()), 0));
        byte[] msg = proof.substring(0, at).getBytes(StandardCharsets.US_ASCII);
        v.update(msg, 0, msg.length);
        return v.verifySignature(B64D.decode(proof.substring(at + 1)));
    }

    /** Checks one received call's DPoP headers against the bytes the server received; returns its claims. */
    private JsonObject checkProof(Received r, String token, String aud) throws Exception {
        assertEquals("DPoP " + token, r.headers().get(AUTH));
        String proof = r.headers().get(DPOP);
        assertNotNull(proof);
        assertTrue(verifies(key, proof), "the proof signature verifies");
        JsonObject claims = JsonParser.parseString(segment(proof, 1)).getAsJsonObject();
        assertEquals("POST", str(claims, "htm"));
        assertEquals("grpc://" + aud + "/" + r.method(), str(claims, "htu"));
        assertEquals(sha(r.body()), str(claims, "seam_bd"), "seam_bd covers the received bytes");
        assertEquals(sha(token.getBytes(StandardCharsets.US_ASCII)), str(claims, "ath"));
        return claims;
    }

    @Test
    void aUnaryProofBindsTheReceivedBytes() throws Exception {
        byte[] body = {0x0a, 0x04, 'a', 'c', 'm', 'e'};
        ClientCalls.blockingUnaryCall(signed(bound, null), ENROLL, CallOptions.DEFAULT, body);
        assertEquals(1, received.size());
        assertEquals(HEX.formatHex(body), HEX.formatHex(received.get(0).body()));
        checkProof(received.get(0), bound, "seam-runtime");
    }

    @Test
    void anEmptyMessageIsSigned() throws Exception {
        ClientCalls.blockingUnaryCall(signed(bound, null), ENROLL, CallOptions.DEFAULT, new byte[0]);
        checkProof(received.get(0), bound, "seam-runtime");
    }

    @Test
    void aBlockingServerStreamSignsItsOneRequest() throws Exception {
        Iterator<byte[]> it = ClientCalls.blockingServerStreamingCall(
                signed(bound, null), STREAM, CallOptions.DEFAULT, new byte[] {0x0a, 0x02, 's', '1'});
        int n = 0;
        while (it.hasNext()) {
            it.next();
            n++;
        }
        assertEquals(2, n);
        checkProof(received.get(0), bound, "seam-runtime");
    }

    @Test
    void anAsyncServerStreamRequestsBeforeSendingAndStillGetsEverything() throws Exception {
        // asyncServerStreamingCall calls request(n) before sendMessage: the delayed call must queue it.
        CompletableFuture<Integer> done = new CompletableFuture<>();
        ClientCalls.asyncServerStreamingCall(
                signed(bound, null).newCall(STREAM, CallOptions.DEFAULT), new byte[] {1},
                new StreamObserver<>() {
                    int n;

                    @Override
                    public void onNext(byte[] value) {
                        n++;
                    }

                    @Override
                    public void onError(Throwable t) {
                        done.completeExceptionally(t);
                    }

                    @Override
                    public void onCompleted() {
                        done.complete(n);
                    }
                });
        assertEquals(2, done.get(5, TimeUnit.SECONDS));
        checkProof(received.get(0), bound, "seam-runtime");
    }

    /** A listener that records how the call closed. */
    private static final class Closing extends ClientCall.Listener<byte[]> {
        final CompletableFuture<Status> status = new CompletableFuture<>();

        @Override
        public void onClose(Status s, Metadata trailers) {
            status.complete(s);
        }
    }

    @Test
    void cancelBeforeSendMessageNeverReachesTheServer() throws Exception {
        ClientCall<byte[], byte[]> call = signed(bound, null).newCall(ENROLL, CallOptions.DEFAULT);
        Closing l = new Closing();
        call.start(l, new Metadata());
        call.request(1);
        call.cancel("caller gave up", null);
        assertEquals(Status.Code.CANCELLED, l.status.get(5, TimeUnit.SECONDS).getCode());
        call.sendMessage(new byte[] {1}); // after cancel: a no-op, as on any cancelled call
        call.halfClose();
        assertTrue(received.isEmpty());
        assertFalse(call.isReady());
    }

    @Test
    void halfCloseWithNoMessageIsRefusedLocally() throws Exception {
        ClientCall<byte[], byte[]> call = signed(bound, null).newCall(ENROLL, CallOptions.DEFAULT);
        Closing l = new Closing();
        call.start(l, new Metadata());
        call.halfClose();
        Status s = l.status.get(5, TimeUnit.SECONDS);
        assertEquals(Status.Code.INTERNAL, s.getCode());
        assertTrue(s.getDescription().contains("exactly one request message"));
        assertTrue(received.isEmpty());
    }

    @Test
    void aSecondMessageIsRefused() {
        ClientCall<byte[], byte[]> call = signed(bound, null).newCall(STREAM, CallOptions.DEFAULT);
        call.start(new Closing(), new Metadata());
        call.sendMessage(new byte[] {1});
        assertThrows(IllegalStateException.class, () -> call.sendMessage(new byte[] {2}));
        call.cancel("done", null);
    }

    @Test
    void sendMessageBeforeStartIsRefused() {
        ClientCall<byte[], byte[]> call = signed(bound, null).newCall(ENROLL, CallOptions.DEFAULT);
        assertThrows(IllegalStateException.class, () -> call.sendMessage(new byte[] {1}));
    }

    @Test
    void anOversizedMessageIsRefusedBeforeTheWire() {
        Channel ch = signed(bound, null);
        assertThrows(RuntimeException.class, () -> ClientCalls.blockingUnaryCall(
                ch, ENROLL, CallOptions.DEFAULT, new byte[MgmtDpop.MAX_BODY_BYTES + 1]));
        assertTrue(received.isEmpty());
    }

    @Test
    void clientStreamingMethodsAreRefused() {
        MethodDescriptor<byte[], byte[]> bidi =
                method("x.Y/Z", MethodDescriptor.MethodType.BIDI_STREAMING);
        assertThrows(IllegalStateException.class, () -> signed(bound, null).newCall(bidi, CallOptions.DEFAULT));
    }

    @Test
    void audResolution() throws Exception {
        Map<String, Object> jkt = Map.of("jkt", key.jkt());
        Object[][] cases = {
            {Map.of("aud", "ops.internal", "cnf", jkt), null, "ops.internal"},
            {Map.of("aud", "seam-runtime", "cnf", jkt), "cell-7", "cell-7"},
            {Map.of("cnf", jkt), null, "seam-runtime"},
            {Map.of("aud", List.of("a", "b"), "cnf", jkt), "cell-7", "cell-7"},
        };
        for (Object[] c : cases) {
            received.clear();
            @SuppressWarnings("unchecked")
            String tok = token((Map<String, Object>) c[0]);
            ClientCalls.blockingUnaryCall(signed(tok, (String) c[1]), ENROLL, CallOptions.DEFAULT, new byte[0]);
            checkProof(received.get(0), tok, (String) c[2]);
        }
    }

    @Test
    void theClockSetsIat() throws Exception {
        Channel ch = ClientInterceptors.intercept(channel, MgmtDpop.interceptor(key, bound, null, () -> 1234));
        ClientCalls.blockingUnaryCall(ch, ENROLL, CallOptions.DEFAULT, new byte[0]);
        assertEquals(1234, checkProof(received.get(0), bound, "seam-runtime").get("iat").getAsLong());
    }

    @Test
    void concurrentCallsCarryDistinctProofs() throws Exception {
        Channel ch = ClientInterceptors.intercept(channel, MgmtDpop.interceptor(key, bound, null, () -> 1));
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch go = new CountDownLatch(1);
        List<CompletableFuture<Void>> all = new ArrayList<>();
        for (int i = 0; i < 32; i++) {
            all.add(CompletableFuture.runAsync(() -> {
                try {
                    go.await();
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                ClientCalls.blockingUnaryCall(ch, ENROLL, CallOptions.DEFAULT, new byte[] {7});
            }, pool));
        }
        go.countDown();
        CompletableFuture.allOf(all.toArray(new CompletableFuture[0])).get(10, TimeUnit.SECONDS);
        pool.shutdown();
        Set<String> jtis = new HashSet<>();
        synchronized (received) {
            for (Received r : received) {
                jtis.add(str(checkProof(r, bound, "seam-runtime"), "jti"));
            }
        }
        assertEquals(32, jtis.size());
    }

    @Test
    void theTenantHeaderRidesAlongside() throws Exception {
        Channel ch = ClientInterceptors.intercept(signed(bound, null), TenantRouting.interceptor("acme"));
        ClientCalls.blockingUnaryCall(ch, ENROLL, CallOptions.DEFAULT, new byte[0]);
        assertEquals("acme", received.get(0).headers().get(TENANT));
        checkProof(received.get(0), bound, "seam-runtime");
    }

    // ── guaranteed-to-fail pairings are refused before any call ────────────────────────────────

    @Test
    void constructionRefusals() {
        Map<String, Object> jkt = Map.of("jkt", key.jkt());
        Object[][] keyCases = {
            {key, null, "needs token"},
            {key, "", "needs token"},
            {key, token(Map.of("aud", "seam-runtime")), "not DPoP-bound"},
            {other, bound, "bound to key"},
            {key, token(Map.of("aud", List.of("a", "b"), "cnf", jkt)), "not a single string"},
            {key, "not-a-jws", "compact JWS"},
            {key, token(Map.of("cnf", "x")), "malformed"},
            {key, nullAud(), "not a single string"},
            {key, token(Map.of("aud", 7, "cnf", jkt)), "not a single string"},
            {key, token(Map.of("cnf", Map.of("jkt", 7))), "malformed"},
            {key, "a." + B64.encodeToString("{".getBytes(StandardCharsets.UTF_8)) + ".c", "not JSON"},
            {key, "a." + B64.encodeToString("[".repeat(5000).getBytes(StandardCharsets.UTF_8)) + ".c", "not JSON"},
        };
        for (Object[] c : keyCases) {
            MgmtDpop.DpopKeyException e = assertThrows(MgmtDpop.DpopKeyException.class,
                    () -> MgmtDpop.interceptor((MgmtDpop.Key) c[0], (String) c[1], null), String.valueOf(c[2]));
            assertTrue(e.getMessage().contains((String) c[2]), e.getMessage());
        }
        List<Runnable> argCases = List.of(
                () -> MgmtDpop.interceptor(null, bound, null),
                () -> MgmtDpop.interceptor(key, bound, "a/b"),
                () -> MgmtDpop.interceptor(key, bound, ""),
                () -> MgmtDpop.interceptor(key, token(Map.of("aud", "has space", "cnf", jkt)), null),
                () -> MgmtDpop.interceptor(key, bound, null, () -> -1),
                () -> MgmtDpop.interceptor(key, "a b", null));
        for (int i = 0; i < argCases.size(); i++) {
            MgmtDpop.DpopException e = assertThrows(MgmtDpop.DpopException.class, argCases.get(i)::run, "case " + i);
            assertFalse(e instanceof MgmtDpop.DpopKeyException, "case " + i);
        }
        assertInstanceOf(IllegalArgumentException.class, new MgmtDpop.DpopException("x"));
        // A bad clock is named before the token is read, as in Python: even an unbound token reports the clock.
        MgmtDpop.DpopException e = assertThrows(MgmtDpop.DpopException.class,
                () -> MgmtDpop.interceptor(key, "not-a-jws", null, () -> -1));
        assertTrue(e.getMessage().contains("clock"), e.getMessage());
    }

    @Test
    void halfCloseBeforeStartIsRefused() {
        ClientCall<byte[], byte[]> call = signed(bound, null).newCall(ENROLL, CallOptions.DEFAULT);
        assertThrows(IllegalStateException.class, call::halfClose);
    }

    /** The README's Java snippet, verbatim between the markers (python/tests/test_readme_dpop_snippets.py). */
    private static Channel readmeSnippet(Channel channel) {
        // README:dpop:begin
        MgmtDpop.Key key = MgmtDpop.Key.fromJwk(System.getenv("SEAM_OPERATOR_DPOP_JWK"));
        Channel signed = ClientInterceptors.intercept(
                channel, MgmtDpop.interceptor(key, System.getenv("SEAM_OPERATOR_TOKEN"), null));
        // README:dpop:end
        return signed;
    }

    @Test
    void theReadmeSnippetSigns() throws Exception {
        ClientCalls.blockingUnaryCall(readmeSnippet(channel), ENROLL, CallOptions.DEFAULT, new byte[] {1});
        checkProof(received.get(0), System.getenv("SEAM_OPERATOR_TOKEN"), "seam-runtime");
    }

    @Test
    void gsonNeverSerialisesTheSeed() throws Exception {
        String json = new Gson().toJson(goldenKey(vector()));
        assertFalse(json.contains("seed"), json);
        assertFalse(json.contains("66,66"), json);
    }
}
