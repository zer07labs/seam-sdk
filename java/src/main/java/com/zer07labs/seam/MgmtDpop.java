package com.zer07labs.seam;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import io.grpc.Attributes;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/**
 * Management-plane DPoP proofs for a DPoP-bound operator token (seam-sdk#290). Mirrors Python's
 * {@code seam_sdk.dpop}.
 *
 * <p>An operator token minted with a key binding ({@code cnf.jkt}) is refused as Bearer. Every
 * management call must carry {@code authorization: DPoP <token>} plus a fresh RFC 9449 proof: a compact
 * JWS signed by the Ed25519 key the management console revealed once, next to the token. The proof binds
 * the call (htm/htu), the token (ath) and the exact request bytes (seam_bd). The runtime burns each proof
 * on first use, so every attempt is signed anew. Install the interceptor on the management channel:
 *
 * <pre>{@code
 * // The console's one-time reveal: the private JWK, exactly as shown, from your secret store.
 * MgmtDpop.Key key = MgmtDpop.Key.fromJwk(System.getenv("SEAM_OPERATOR_DPOP_JWK"));
 * Channel signed = ClientInterceptors.intercept(channel,
 *     MgmtDpop.interceptor(key, System.getenv("SEAM_OPERATOR_TOKEN"), null));
 * }</pre>
 *
 * <p>The grammar is {@code docs/specs/mgmt-dpop.md}, a pinned copy of the runtime's, and
 * {@code conformance/mgmt_dpop_vector.json} pins the bytes. Every string in a signed JSON object is
 * printable ASCII, and Gson runs with HTML escaping off, so this JSON is byte-identical to every other
 * SDK's.
 */
public final class MgmtDpop {
    private MgmtDpop() {}

    /** The runtime's operator audience when SEAM_RUNTIME_AUD is unset: the authority of every gRPC htu. */
    public static final String DEFAULT_OPERATOR_AUD = "seam-runtime";
    /** The runtime refuses a larger proof. */
    public static final int MAX_PROOF_BYTES = 8 * 1024;
    /** The runtime binds at most this much request body (HTTP) or message (gRPC). */
    public static final int MAX_BODY_BYTES = 1024 * 1024;
    /** The runtime refuses a longer jti. */
    public static final int MAX_JTI_BYTES = 256;
    /** The largest iat every SDK accepts: 2^53 - 1, the largest integer a JavaScript number holds exactly. */
    public static final long MAX_IAT = (1L << 53) - 1;

    /**
     * A local refusal: an input the runtime would refuse, refused before any network call. Never thrown
     * for a wire error.
     */
    public static class DpopException extends IllegalArgumentException {
        public DpopException(String message) {
            super(message);
        }
    }

    /**
     * The key, or the token it is meant to be bound to, cannot work: a malformed JWK, an x that is not d's
     * public key, or a cnf.jkt naming another key.
     */
    public static final class DpopKeyException extends DpopException {
        public DpopKeyException(String message) {
            super(message);
        }
    }

    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Pattern B64URL = Pattern.compile("[A-Za-z0-9_-]*");
    private static final Pattern TOKEN_CHARS = Pattern.compile("[\\x21-\\x7e]+"); // visible ASCII, no space
    private static final Pattern PRINTABLE = Pattern.compile("[\\x20-\\x7e]+");
    private static final Pattern METHOD = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+"); // RFC 9110 token
    private static final Pattern PORT = Pattern.compile("[0-9]{1,5}");

    private static String b64(byte[] b) {
        return B64.encodeToString(b);
    }

    private static String sha256b64(byte[] data) {
        try {
            return b64(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    /** Parses JSON strictly (no comments, unquoted names or trailing data), like every other SDK's parser. */
    private static JsonElement parseStrict(String text) throws IOException {
        // JsonReader silently skips a leading byte-order mark; RFC 8259 parsers (Python's, Go's) refuse it.
        if (text.startsWith("\uFEFF")) {
            throw new IOException("a byte-order mark is not JSON");
        }
        JsonReader reader = new JsonReader(new StringReader(text));
        reader.setStrictness(Strictness.STRICT);
        JsonElement el = GSON.getAdapter(JsonElement.class).read(reader);
        if (reader.peek() != JsonToken.END_DOCUMENT) {
            throw new IOException("trailing data");
        }
        return el;
    }

    // ── the key ─────────────────────────────────────────────────────────────────────────────────

    /**
     * The Ed25519 key an operator token is bound to. The private half is never formatted:
     * {@link #toString} prints only the thumbprint.
     */
    public static final class Key {
        private final byte[] seed;
        private final String x;
        private final String jkt;

        private Key(byte[] seed) {
            this.seed = seed;
            this.x = b64(new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded());
            // RFC 7638: SHA-256 over the required members in lexicographic order, no whitespace.
            Map<String, String> members = new LinkedHashMap<>();
            members.put("crv", "Ed25519");
            members.put("kty", "OKP");
            members.put("x", x);
            this.jkt = sha256b64(ascii(GSON.toJson(members)));
        }

        /** Builds a key from the raw 32-byte Ed25519 seed (the JWK's d, decoded). The bytes are copied. */
        public static Key fromSeed(byte[] seed) {
            if (seed == null || seed.length != 32) {
                throw new DpopKeyException("an Ed25519 seed must be exactly 32 bytes");
            }
            return new Key(seed.clone());
        }

        /**
         * Loads a private OKP/Ed25519 JWK: the one the management console reveals once, next to the token.
         * x is checked against the public key derived from d, so a reveal pasted with a typo fails here, by
         * name. kid, and any other member that does not contradict an Ed25519 signing key, is ignored.
         */
        public static Key fromJwk(String json) {
            if (json == null) {
                throw new DpopKeyException("JWK must be a JSON object");
            }
            JsonElement parsed;
            try {
                parsed = parseStrict(json);
            } catch (IOException | JsonParseException | IllegalStateException e) {
                throw new DpopKeyException("JWK is not valid JSON: " + e.getMessage());
            }
            if (!parsed.isJsonObject()) {
                throw new DpopKeyException("JWK must be a JSON object");
            }
            JsonObject m = parsed.getAsJsonObject();
            if (!"OKP".equals(stringMember(m, "kty"))) {
                throw new DpopKeyException("JWK \"kty\" must be \"OKP\"");
            }
            if (!"Ed25519".equals(stringMember(m, "crv"))) {
                throw new DpopKeyException("JWK \"crv\" must be \"Ed25519\"");
            }
            if (m.has("alg")) {
                String alg = stringMember(m, "alg");
                if (!"EdDSA".equals(alg) && !"Ed25519".equals(alg)) {
                    throw new DpopKeyException("JWK \"alg\", when present, must be \"EdDSA\" or \"Ed25519\"");
                }
            }
            if (m.has("use") && !"sig".equals(stringMember(m, "use"))) {
                throw new DpopKeyException("JWK \"use\", when present, must be \"sig\"");
            }
            if (!m.has("d")) {
                throw new DpopKeyException("JWK has no \"d\": a public JWK cannot sign proofs");
            }
            if (!m.has("x")) {
                throw new DpopKeyException("JWK has no \"x\"");
            }
            byte[] seed = b64url32(m, "d");
            b64url32(m, "x");
            Key key = new Key(seed);
            if (!key.x.equals(stringMember(m, "x"))) {
                throw new DpopKeyException("JWK \"x\" is not the public key of its \"d\"");
            }
            return key;
        }

        /** The public key, unpadded base64url: the JWK's x. */
        public String x() {
            return x;
        }

        /** The RFC 7638 thumbprint the runtime compares against the token's cnf.jkt. */
        public String jkt() {
            return jkt;
        }

        /** The public JWK, in the member order a proof header carries it. */
        public Map<String, String> publicJwk() {
            Map<String, String> jwk = new LinkedHashMap<>();
            jwk.put("kty", "OKP");
            jwk.put("crv", "Ed25519");
            jwk.put("x", x);
            return jwk;
        }

        byte[] sign(byte[] msg) {
            Ed25519Signer signer = new Ed25519Signer();
            signer.init(true, new Ed25519PrivateKeyParameters(seed, 0));
            signer.update(msg, 0, msg.length);
            return signer.generateSignature();
        }

        @Override
        public String toString() {
            return "MgmtDpop.Key(jkt=" + jkt + ")";
        }
    }

    /** The member's string value, or null when it is absent or not a JSON string. */
    private static String stringMember(JsonObject m, String name) {
        JsonElement v = m.get(name);
        return v != null && v.isJsonPrimitive() && v.getAsJsonPrimitive().isString() ? v.getAsString() : null;
    }

    private static byte[] b64url32(JsonObject m, String name) {
        String s = stringMember(m, name);
        if (s == null) {
            throw new DpopKeyException("JWK member \"" + name + "\" must be a string");
        }
        if (!B64URL.matcher(s).matches() || s.length() % 4 == 1) {
            throw new DpopKeyException("JWK member \"" + name + "\" must be unpadded base64url");
        }
        byte[] raw = B64D.decode(s);
        if (raw.length != 32) {
            throw new DpopKeyException(
                    "JWK member \"" + name + "\" must decode to 32 bytes, got " + raw.length);
        }
        // Stray low bits in the last character decode to the same bytes but a different thumbprint.
        if (!b64(raw).equals(s)) {
            throw new DpopKeyException("JWK member \"" + name + "\" is not canonical base64url");
        }
        return raw;
    }

    // ── the proof ───────────────────────────────────────────────────────────────────────────────

    /** A fresh proof id: 16 random bytes as unpadded base64url (22 characters). */
    public static String newJti() {
        byte[] b = new byte[16];
        RANDOM.nextBytes(b);
        return b64(b);
    }

    private static void checkToken(String token) {
        if (token == null || token.isEmpty()) {
            throw new DpopException("the operator token must be a non-empty string");
        }
        if (!TOKEN_CHARS.matcher(token).matches()) {
            throw new DpopException("the operator token must be printable ASCII with no spaces");
        }
    }

    /** {@link #proof(Key, String, String, String, byte[], Long, String)} with iat now and a fresh jti. */
    public static String proof(Key key, String token, String htm, String htu, byte[] body) {
        return proof(key, token, htm, htu, body, null, null);
    }

    /**
     * The compact-JWS proof for one management call. htm is the HTTP method ("POST" for every gRPC call);
     * htu is the call's target as the runtime compares it ({@link #grpcHtu} or {@link #httpHtu}); body is
     * the exact HTTP body, or the protobuf-encoded request message without its 5-byte frame. iat (seconds)
     * and jti default to now and {@link #newJti()} when null; pass them only to reproduce a vector. Each
     * proof is burned on first use: sign every attempt, retries included.
     */
    public static String proof(
            Key key, String token, String htm, String htu, byte[] body, Long iat, String jti) {
        if (key == null) {
            throw new DpopException("key must be a MgmtDpop.Key");
        }
        checkToken(token);
        if (htm == null || !METHOD.matcher(htm).matches()) {
            throw new DpopException("htm must be an HTTP method token");
        }
        if (htu == null || !PRINTABLE.matcher(htu).matches()) {
            throw new DpopException("htu must be a non-empty printable-ASCII string");
        }
        if (body == null) {
            body = new byte[0];
        }
        if (body.length > MAX_BODY_BYTES) {
            throw new DpopException(
                    "the request body is " + body.length + " bytes; the runtime binds at most "
                            + MAX_BODY_BYTES + " and refuses a larger one");
        }
        long t = iat == null ? System.currentTimeMillis() / 1000 : iat;
        if (t < 0 || t > MAX_IAT) {
            throw new DpopException("iat must be a non-negative integer number of seconds");
        }
        String id = jti == null ? newJti() : jti;
        if (id.isEmpty() || !PRINTABLE.matcher(id).matches()) {
            throw new DpopException("jti must be a non-empty printable-ASCII string");
        }
        if (id.length() > MAX_JTI_BYTES) {
            throw new DpopException("jti must be at most " + MAX_JTI_BYTES + " bytes");
        }

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", "dpop+jwt");
        header.put("alg", "EdDSA");
        header.put("jwk", key.publicJwk());
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("jti", id);
        claims.put("htm", htm);
        claims.put("htu", htu);
        claims.put("iat", t);
        claims.put("ath", sha256b64(ascii(token)));
        claims.put("seam_bd", sha256b64(body));
        String signingInput = b64(ascii(GSON.toJson(header))) + "." + b64(ascii(GSON.toJson(claims)));
        String proof = signingInput + "." + b64(key.sign(ascii(signingInput)));
        if (proof.length() > MAX_PROOF_BYTES) {
            throw new DpopException(
                    "the proof is " + proof.length() + " bytes; the runtime refuses one over " + MAX_PROOF_BYTES);
        }
        return proof;
    }

    /**
     * {@code grpc://<aud><full method>}, e.g. {@code grpc://seam-runtime/seam.api.v1.SeamAdmin/EnrollTenant}.
     * aud is the runtime's operator audience, not the dialled address; null means
     * {@link #DEFAULT_OPERATOR_AUD}.
     */
    public static String grpcHtu(String method, String aud) {
        if (method == null || !method.startsWith("/") || !PRINTABLE.matcher(method).matches()) {
            throw new DpopException("method must be a full gRPC method path such as \"/pkg.Service/Method\"");
        }
        String a = aud == null ? DEFAULT_OPERATOR_AUD : aud;
        if (!TOKEN_CHARS.matcher(a).matches() || a.contains("/")) {
            throw new DpopException("aud must be a non-empty printable-ASCII string with no spaces or '/'");
        }
        return "grpc://" + a + method;
    }

    private static int firstOf(String s, String chars) {
        for (int i = 0; i < s.length(); i++) {
            if (chars.indexOf(s.charAt(i)) >= 0) {
                return i;
            }
        }
        return -1;
    }

    /**
     * The htu the runtime compares an HTTP management call against: {@code https://<authority><path>}.
     *
     * <p>The scheme becomes https, the host is lower-cased, a default port (:443 for https, :80 for http)
     * is dropped, and the query and fragment are dropped. The path is kept exactly; an empty one becomes
     * "/". A URL carrying userinfo is refused. This is an explicit grammar, not java.net.URI (which
     * normalises), so every SDK derives the same htu from the same string: scheme "://" authority [path]
     * ["?" query] ["#" fragment], authority = host [":" port], host a reg-name or a bracketed IPv6
     * literal, port 1-5 digits. Send the request to exactly this URL: a client that rewrites the path
     * (dot-segments, percent-encoding) sends a path the htu does not name, and the runtime refuses it.
     */
    public static String httpHtu(String url) {
        if (url == null || !TOKEN_CHARS.matcher(url).matches()) {
            throw new DpopException("url must be a non-empty visible-ASCII string (no spaces)");
        }
        int sep = url.indexOf("://");
        String scheme = sep < 0 ? "" : url.substring(0, sep).toLowerCase(Locale.ROOT);
        if (sep < 0 || (!scheme.equals("http") && !scheme.equals("https"))) {
            throw new DpopException("url must be an absolute http:// or https:// URL");
        }
        String rest = url.substring(sep + 3);
        int cut = firstOf(rest, "/?#");
        String authority = cut < 0 ? rest : rest.substring(0, cut);
        String tail = cut < 0 ? "" : rest.substring(cut);
        int q = firstOf(tail, "?#");
        String path = q < 0 ? tail : tail.substring(0, q);
        if (authority.contains("@")) {
            throw new DpopException("url must not carry userinfo");
        }
        String host;
        String portText = "";
        if (authority.startsWith("[")) {
            int close = authority.indexOf(']');
            if (close < 2) {
                throw new DpopException("url has a malformed IPv6 literal");
            }
            host = authority.substring(0, close + 1);
            String after = authority.substring(close + 1);
            if (!after.isEmpty() && !after.startsWith(":")) {
                throw new DpopException("url has a malformed IPv6 literal");
            }
            if (!after.isEmpty()) {
                portText = after.substring(1);
            }
        } else {
            int colon = authority.indexOf(':');
            host = colon < 0 ? authority : authority.substring(0, colon);
            if (colon >= 0) {
                portText = authority.substring(colon + 1);
                if (portText.indexOf(':') >= 0) {
                    throw new DpopException("url has more than one ':' in its authority; bracket an IPv6 literal");
                }
            }
        }
        if (host.isEmpty()) {
            throw new DpopException("url has no host");
        }
        host = host.toLowerCase(Locale.ROOT);
        String auth = host;
        if (!portText.isEmpty()) {
            if (!PORT.matcher(portText).matches() || Integer.parseInt(portText) > 65535) {
                throw new DpopException("url has an invalid port");
            }
            int port = Integer.parseInt(portText);
            if (port != (scheme.equals("https") ? 443 : 80)) {
                auth = host + ":" + port;
            }
        }
        return "https://" + auth + (path.isEmpty() ? "/" : path);
    }

    /** {@link #httpHeaders(Key, String, String, String, byte[], Long, String)} with iat now and a fresh jti. */
    public static Map<String, String> httpHeaders(Key key, String token, String method, String url, byte[] body) {
        return httpHeaders(key, token, method, url, body, null, null);
    }

    /**
     * Both headers for one call to the HTTP management plane: {@code Authorization} ("DPoP <token>") and
     * {@code DPoP} (the proof). Send exactly body as the request body (empty for a GET), to exactly url.
     * Call this once per request; never reuse the headers for a retry.
     */
    public static Map<String, String> httpHeaders(
            Key key, String token, String method, String url, byte[] body, Long iat, String jti) {
        String htu = httpHtu(url);
        String proof = proof(key, token, method, htu, body, iat, jti);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", "DPoP " + token);
        headers.put("DPoP", proof);
        return headers;
    }

    // ── the token, peeked (never verified: the runtime is the verifier) ─────────────────────────

    static JsonObject peekTokenClaims(String token) {
        checkToken(token);
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || !B64URL.matcher(parts[1]).matches() || parts[1].length() % 4 == 1) {
            throw new DpopKeyException("the operator token is not a compact JWS");
        }
        JsonElement payload;
        try {
            payload = parseStrict(new String(B64D.decode(parts[1]), StandardCharsets.UTF_8));
        } catch (IOException | JsonParseException | IllegalStateException e) {
            throw new DpopKeyException("the operator token's payload is not JSON");
        }
        if (!payload.isJsonObject()) {
            throw new DpopKeyException("the operator token's payload is not a JSON object");
        }
        return payload.getAsJsonObject();
    }

    /** cnf.jkt, or null when the token is unbound. */
    static String tokenCnfJkt(JsonObject claims) {
        JsonElement cnf = claims.get("cnf");
        if (cnf == null || cnf.isJsonNull()) {
            return null;
        }
        String jkt = cnf.isJsonObject() ? stringMember(cnf.getAsJsonObject(), "jkt") : null;
        if (jkt == null) {
            throw new DpopKeyException("the operator token's cnf claim is malformed");
        }
        return jkt;
    }

    // ── the gRPC interceptor ────────────────────────────────────────────────────────────────────

    private static final Metadata.Key<String> AUTHORIZATION =
            Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
    private static final Metadata.Key<String> DPOP = Metadata.Key.of("dpop", Metadata.ASCII_STRING_MARSHALLER);

    /** {@link #interceptor(Key, String, String, LongSupplier)} on the wall clock. */
    public static ClientInterceptor interceptor(Key key, String token, String aud) {
        return interceptor(key, token, aud, null);
    }

    /**
     * Signs every unary and server-streaming call with a fresh proof over its one request message. aud
     * null takes the token's own aud, else {@link #DEFAULT_OPERATOR_AUD}. clock (seconds) defaults to
     * the wall clock. Every pairing the runtime is guaranteed to refuse throws here, before any call:
     * a token that is not DPoP-bound, a cnf.jkt naming another key, or a list aud with no override. Each
     * attempt is signed once, so never combine it with a retry policy that resends a call's metadata.
     */
    public static ClientInterceptor interceptor(Key key, String token, String aud, LongSupplier clock) {
        if (key == null) {
            throw new DpopException("key must be a MgmtDpop.Key");
        }
        if (token == null || token.isEmpty()) {
            throw new DpopKeyException("a DPoP key needs token: the bound operator token minted with it");
        }
        // The clock is probed before the token is read, in Python's order, so a bad clock is named first.
        LongSupplier c = clock != null ? clock : () -> System.currentTimeMillis() / 1000;
        long sample = c.getAsLong();
        if (sample < 0 || sample > MAX_IAT) {
            throw new DpopException("clock must return a non-negative integer number of seconds");
        }
        JsonObject claims = peekTokenClaims(token);
        String jkt = tokenCnfJkt(claims);
        if (jkt == null) {
            throw new DpopKeyException(
                    "the operator token is not DPoP-bound (no cnf.jkt); send it as Bearer without this interceptor");
        }
        if (!jkt.equals(key.jkt())) {
            throw new DpopKeyException(
                    "the operator token is bound to key " + jkt + ", not this key (" + key.jkt() + ")");
        }
        String resolved = aud;
        if (resolved == null) {
            JsonElement tokAud = claims.get("aud");
            if (tokAud == null) { // absent; a JSON null is refused below, as in Python and TS
                resolved = DEFAULT_OPERATOR_AUD;
            } else if (tokAud.isJsonPrimitive() && tokAud.getAsJsonPrimitive().isString()) {
                resolved = tokAud.getAsString();
            } else {
                throw new DpopKeyException("the operator token's aud is not a single string; pass aud explicitly");
            }
        }
        grpcHtu("/m", resolved); // refuses an aud that cannot form an htu
        return new DpopInterceptor(key, token, resolved, c);
    }

    private static final class DpopInterceptor implements ClientInterceptor {
        private final Key key;
        private final String token;
        private final String aud;
        private final LongSupplier clock;

        DpopInterceptor(Key key, String token, String aud, LongSupplier clock) {
            this.key = key;
            this.token = token;
            this.aud = aud;
            this.clock = clock;
        }

        @Override
        public <Q, R> ClientCall<Q, R> interceptCall(MethodDescriptor<Q, R> method, CallOptions options, Channel next) {
            if (!method.getType().clientSendsOneMessage()) {
                throw new IllegalStateException(
                        method.getFullMethodName() + " streams requests; a DPoP proof binds exactly one request message");
            }
            return new DelayedSignedCall<>(this, method, options, next);
        }

        String sign(String fullMethodName, byte[] body) {
            return proof(key, token, "POST", grpcHtu("/" + fullMethodName, aud), body, clock.getAsLong(), null);
        }
    }

    /**
     * A call whose real start waits for its one request message, because the proof signs that message's
     * bytes and travels in the headers. Until then, {@code request}, {@code setMessageCompression} and
     * {@code halfClose} are queued and replayed in order; {@code cancel} closes the listener without ever
     * opening the real call.
     */
    private static final class DelayedSignedCall<Q, R> extends ClientCall<Q, R> {
        private final DpopInterceptor signer;
        private final MethodDescriptor<Q, R> method;
        private final CallOptions options;
        private final Channel next;

        private Listener<R> listener;
        private Metadata headers;
        private ClientCall<Q, R> real;
        private boolean closed;
        private final List<Consumer<ClientCall<Q, R>>> pending = new ArrayList<>();

        DelayedSignedCall(DpopInterceptor signer, MethodDescriptor<Q, R> method, CallOptions options, Channel next) {
            this.signer = signer;
            this.method = method;
            this.options = options;
            this.next = next;
        }

        @Override
        public synchronized void start(Listener<R> listener, Metadata headers) {
            if (this.listener != null) {
                throw new IllegalStateException("already started");
            }
            this.listener = listener;
            this.headers = headers;
        }

        @Override
        public synchronized void request(int numMessages) {
            if (real != null) {
                real.request(numMessages);
            } else if (!closed) {
                pending.add(c -> c.request(numMessages));
            }
        }

        @Override
        public synchronized void setMessageCompression(boolean enabled) {
            if (real != null) {
                real.setMessageCompression(enabled);
            } else if (!closed) {
                pending.add(c -> c.setMessageCompression(enabled));
            }
        }

        @Override
        public void sendMessage(Q message) {
            ClientCall<Q, R> started;
            synchronized (this) {
                if (listener == null) {
                    throw new IllegalStateException("sendMessage before start");
                }
                if (closed) {
                    return; // cancelled before its message: nothing is sent, as with any cancelled call
                }
                if (real != null) {
                    throw new IllegalStateException(
                            method.getFullMethodName() + ": a DPoP proof binds exactly one request message");
                }
                byte[] body;
                try (InputStream in = method.streamRequest(message)) {
                    body = in.readAllBytes();
                } catch (IOException e) {
                    throw new DpopException("cannot encode the request message: " + e.getMessage());
                }
                // A refusal (an oversized message) throws here, before anything reaches the wire.
                String proof = signer.sign(method.getFullMethodName(), body);
                headers.put(AUTHORIZATION, "DPoP " + signer.token);
                headers.put(DPOP, proof);
                real = next.newCall(method, options);
                real.start(listener, headers);
                for (Consumer<ClientCall<Q, R>> op : pending) {
                    op.accept(real);
                }
                pending.clear();
                started = real;
            }
            started.sendMessage(message);
        }

        @Override
        public synchronized void halfClose() {
            if (listener == null) {
                throw new IllegalStateException("halfClose before start");
            }
            if (real != null) {
                real.halfClose();
                return;
            }
            if (closed) {
                return;
            }
            closed = true;
            pending.clear();
            listener.onClose(
                    Status.INTERNAL.withDescription("a management call must carry exactly one request message (got none)"),
                    new Metadata());
        }

        @Override
        public synchronized void cancel(String message, Throwable cause) {
            if (real != null) {
                real.cancel(message, cause);
                return;
            }
            if (closed) {
                return;
            }
            closed = true;
            pending.clear();
            if (listener != null) {
                Status status = Status.CANCELLED;
                if (message != null) {
                    status = status.withDescription(message);
                }
                if (cause != null) {
                    status = status.withCause(cause);
                }
                listener.onClose(status, new Metadata());
            }
        }

        @Override
        public synchronized boolean isReady() {
            return real != null && real.isReady();
        }

        @Override
        public synchronized Attributes getAttributes() {
            return real != null ? real.getAttributes() : Attributes.EMPTY;
        }
    }
}
