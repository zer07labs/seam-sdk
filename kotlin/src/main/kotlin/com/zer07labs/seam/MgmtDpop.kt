package com.zer07labs.seam

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParseException
import com.google.gson.Strictness
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import io.grpc.Attributes
import io.grpc.CallOptions
import io.grpc.Channel
import io.grpc.ClientCall
import io.grpc.ClientInterceptor
import io.grpc.Metadata
import io.grpc.MethodDescriptor
import io.grpc.Status
import java.io.IOException
import java.io.StringReader
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.Locale
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * Management-plane DPoP proofs for a DPoP-bound operator token (seam-sdk#290). Mirrors Python's
 * `seam_sdk.dpop`.
 *
 * An operator token minted with a key binding (`cnf.jkt`) is refused as Bearer. Every management call
 * must carry `authorization: DPoP <token>` plus a fresh RFC 9449 proof: a compact JWS signed by the
 * Ed25519 key the management console revealed once, next to the token. The proof binds the call
 * (htm/htu), the token (ath) and the exact request bytes (seam_bd). The runtime burns each proof on first
 * use, so every attempt is signed anew. Install the interceptor on the management channel:
 *
 * ```
 * // The console's one-time reveal: the private JWK, exactly as shown, from your secret store.
 * val key = MgmtDpop.Key.fromJwk(System.getenv("SEAM_OPERATOR_DPOP_JWK"))
 * val signed = ClientInterceptors.intercept(channel, MgmtDpop.interceptor(key, System.getenv("SEAM_OPERATOR_TOKEN")))
 * ```
 *
 * The grammar is `docs/specs/mgmt-dpop.md`, a pinned copy of the runtime's, and
 * `conformance/mgmt_dpop_vector.json` pins the bytes. Every string in a signed JSON object is printable
 * ASCII, and Gson runs with HTML escaping off, so this JSON is byte-identical to every other SDK's.
 */
object MgmtDpop {
    /** The runtime's operator audience when SEAM_RUNTIME_AUD is unset: the authority of every gRPC htu. */
    const val DEFAULT_OPERATOR_AUD = "seam-runtime"

    /** The runtime refuses a larger proof. */
    const val MAX_PROOF_BYTES = 8 * 1024

    /** The runtime binds at most this much request body (HTTP) or message (gRPC). */
    const val MAX_BODY_BYTES = 1024 * 1024

    /** The runtime refuses a longer jti. */
    const val MAX_JTI_BYTES = 256

    /** The largest iat every SDK accepts: 2^53 - 1, the largest integer a JavaScript number holds exactly. */
    const val MAX_IAT: Long = (1L shl 53) - 1

    /** A local refusal: an input the runtime would refuse, refused before any network call. */
    open class DpopException(message: String) : IllegalArgumentException(message)

    /**
     * The key, or the token it is meant to be bound to, cannot work: a malformed JWK, an x that is not d's
     * public key, or a cnf.jkt naming another key.
     */
    class DpopKeyException(message: String) : DpopException(message)

    private val gson: Gson = GsonBuilder().disableHtmlEscaping().create()
    private val b64enc = Base64.getUrlEncoder().withoutPadding()
    private val b64dec = Base64.getUrlDecoder()
    private val random = SecureRandom()

    private val b64url = Regex("[A-Za-z0-9_-]*")
    private val tokenChars = Regex("""[\x21-\x7e]+""") // visible ASCII, no space
    private val printable = Regex("""[\x20-\x7e]+""")
    private val methodToken = Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+") // RFC 9110 token
    private val portDigits = Regex("[0-9]{1,5}")

    private fun b64(b: ByteArray): String = b64enc.encodeToString(b)

    private fun sha256b64(data: ByteArray): String = b64(MessageDigest.getInstance("SHA-256").digest(data))

    private fun ascii(s: String): ByteArray = s.toByteArray(Charsets.US_ASCII)

    /** Parses JSON strictly (no comments, unquoted names or trailing data), like every other SDK's parser. */
    private fun parseStrict(text: String): JsonElement {
        // JsonReader silently skips a leading byte-order mark; RFC 8259 parsers (Python's, Go's) refuse it.
        if (text.startsWith("\uFEFF")) throw IOException("a byte-order mark is not JSON")
        val reader = JsonReader(StringReader(text))
        reader.strictness = Strictness.STRICT
        val el = gson.getAdapter(JsonElement::class.java).read(reader)
        if (reader.peek() != JsonToken.END_DOCUMENT) throw IOException("trailing data")
        return el
    }

    /** The member's string value, or null when it is absent or not a JSON string. */
    private fun JsonObject.stringMember(name: String): String? {
        val v = get(name)
        return if (v != null && v.isJsonPrimitive && v.asJsonPrimitive.isString) v.asString else null
    }

    // ── the key ─────────────────────────────────────────────────────────────────────────────────

    /** The Ed25519 key an operator token is bound to. [toString] prints only the thumbprint. */
    class Key private constructor(private val seed: ByteArray) {
        /** The public key, unpadded base64url: the JWK's x. */
        val x: String = b64(Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded)

        /** The RFC 7638 thumbprint the runtime compares against the token's cnf.jkt. */
        val jkt: String = sha256b64(ascii(gson.toJson(linkedMapOf("crv" to "Ed25519", "kty" to "OKP", "x" to x))))

        /** The public JWK, in the member order a proof header carries it. */
        fun publicJwk(): Map<String, String> = linkedMapOf("kty" to "OKP", "crv" to "Ed25519", "x" to x)

        // @JvmSynthetic: `internal` alone compiles to a public method Java code could call to sign arbitrary bytes.
        @JvmSynthetic
        internal fun sign(msg: ByteArray): ByteArray {
            val signer = Ed25519Signer()
            signer.init(true, Ed25519PrivateKeyParameters(seed, 0))
            signer.update(msg, 0, msg.size)
            return signer.generateSignature()
        }

        override fun toString(): String = "MgmtDpop.Key(jkt=$jkt)"

        companion object {
            /** Builds a key from the raw 32-byte Ed25519 seed (the JWK's d, decoded). The bytes are copied. */
            @JvmStatic
            fun fromSeed(seed: ByteArray): Key {
                if (seed.size != 32) throw DpopKeyException("an Ed25519 seed must be exactly 32 bytes")
                return Key(seed.copyOf())
            }

            /**
             * Loads a private OKP/Ed25519 JWK: the one the management console reveals once, next to the
             * token. x is checked against the public key derived from d, so a reveal pasted with a typo fails
             * here, by name. kid, and any other member that does not contradict an Ed25519 signing key, is
             * ignored.
             */
            @JvmStatic
            fun fromJwk(json: String): Key {
                val parsed = try {
                    parseStrict(json)
                } catch (e: IOException) {
                    throw DpopKeyException("JWK is not valid JSON: ${e.message}")
                } catch (e: JsonParseException) {
                    throw DpopKeyException("JWK is not valid JSON: ${e.message}")
                } catch (e: IllegalStateException) {
                    throw DpopKeyException("JWK is not valid JSON: ${e.message}")
                }
                if (!parsed.isJsonObject) throw DpopKeyException("JWK must be a JSON object")
                val m = parsed.asJsonObject
                if (m.stringMember("kty") != "OKP") throw DpopKeyException("JWK \"kty\" must be \"OKP\"")
                if (m.stringMember("crv") != "Ed25519") throw DpopKeyException("JWK \"crv\" must be \"Ed25519\"")
                if (m.has("alg") && m.stringMember("alg") !in setOf("EdDSA", "Ed25519")) {
                    throw DpopKeyException("JWK \"alg\", when present, must be \"EdDSA\" or \"Ed25519\"")
                }
                if (m.has("use") && m.stringMember("use") != "sig") {
                    throw DpopKeyException("JWK \"use\", when present, must be \"sig\"")
                }
                if (!m.has("d")) throw DpopKeyException("JWK has no \"d\": a public JWK cannot sign proofs")
                if (!m.has("x")) throw DpopKeyException("JWK has no \"x\"")
                val seed = b64url32(m, "d")
                b64url32(m, "x")
                val key = Key(seed)
                if (key.x != m.stringMember("x")) throw DpopKeyException("JWK \"x\" is not the public key of its \"d\"")
                return key
            }
        }
    }

    private fun b64url32(m: JsonObject, name: String): ByteArray {
        val s = m.stringMember(name) ?: throw DpopKeyException("JWK member \"$name\" must be a string")
        if (!b64url.matches(s) || s.length % 4 == 1) {
            throw DpopKeyException("JWK member \"$name\" must be unpadded base64url")
        }
        val raw = b64dec.decode(s)
        if (raw.size != 32) throw DpopKeyException("JWK member \"$name\" must decode to 32 bytes, got ${raw.size}")
        // Stray low bits in the last character decode to the same bytes but a different thumbprint.
        if (b64(raw) != s) throw DpopKeyException("JWK member \"$name\" is not canonical base64url")
        return raw
    }

    // ── the proof ───────────────────────────────────────────────────────────────────────────────

    /** A fresh proof id: 16 random bytes as unpadded base64url (22 characters). */
    @JvmStatic
    fun newJti(): String = b64(ByteArray(16).also { random.nextBytes(it) })

    private fun checkToken(token: String?) {
        if (token.isNullOrEmpty()) throw DpopException("the operator token must be a non-empty string")
        if (!tokenChars.matches(token)) throw DpopException("the operator token must be printable ASCII with no spaces")
    }

    /**
     * The compact-JWS proof for one management call. htm is the HTTP method ("POST" for every gRPC call);
     * htu is the call's target as the runtime compares it ([grpcHtu] or [httpHtu]); body is the exact HTTP
     * body, or the protobuf-encoded request message without its 5-byte frame. iat (seconds) and jti default
     * to now and [newJti]; pass them only to reproduce a vector. Each proof is burned on first use: sign
     * every attempt, retries included.
     */
    @JvmStatic
    @JvmOverloads
    fun proof(
        key: Key,
        token: String,
        htm: String,
        htu: String,
        body: ByteArray = ByteArray(0),
        iat: Long? = null,
        jti: String? = null,
    ): String {
        checkToken(token)
        if (!methodToken.matches(htm)) throw DpopException("htm must be an HTTP method token")
        if (!printable.matches(htu)) throw DpopException("htu must be a non-empty printable-ASCII string")
        if (body.size > MAX_BODY_BYTES) {
            throw DpopException(
                "the request body is ${body.size} bytes; the runtime binds at most $MAX_BODY_BYTES and refuses a larger one",
            )
        }
        val t = iat ?: (System.currentTimeMillis() / 1000)
        if (t < 0 || t > MAX_IAT) throw DpopException("iat must be a non-negative integer number of seconds")
        val id = jti ?: newJti()
        if (!printable.matches(id)) throw DpopException("jti must be a non-empty printable-ASCII string")
        if (id.length > MAX_JTI_BYTES) throw DpopException("jti must be at most $MAX_JTI_BYTES bytes")

        val header = linkedMapOf<String, Any>("typ" to "dpop+jwt", "alg" to "EdDSA", "jwk" to key.publicJwk())
        val claims = linkedMapOf<String, Any>(
            "jti" to id,
            "htm" to htm,
            "htu" to htu,
            "iat" to t,
            "ath" to sha256b64(ascii(token)),
            "seam_bd" to sha256b64(body),
        )
        val signingInput = b64(ascii(gson.toJson(header))) + "." + b64(ascii(gson.toJson(claims)))
        val proof = signingInput + "." + b64(key.sign(ascii(signingInput)))
        if (proof.length > MAX_PROOF_BYTES) {
            throw DpopException("the proof is ${proof.length} bytes; the runtime refuses one over $MAX_PROOF_BYTES")
        }
        return proof
    }

    /**
     * `grpc://<aud><full method>`, e.g. `grpc://seam-runtime/seam.api.v1.SeamAdmin/EnrollTenant`. aud is the
     * runtime's operator audience, not the dialled address.
     */
    @JvmStatic
    @JvmOverloads
    fun grpcHtu(method: String, aud: String = DEFAULT_OPERATOR_AUD): String {
        if (!method.startsWith("/") || !printable.matches(method)) {
            throw DpopException("method must be a full gRPC method path such as \"/pkg.Service/Method\"")
        }
        if (!tokenChars.matches(aud) || aud.contains('/')) {
            throw DpopException("aud must be a non-empty printable-ASCII string with no spaces or '/'")
        }
        return "grpc://$aud$method"
    }

    private fun String.firstOf(chars: String): Int = indexOfFirst { it in chars }

    /**
     * The htu the runtime compares an HTTP management call against: `https://<authority><path>`.
     *
     * The scheme becomes https, the host is lower-cased, a default port (:443 for https, :80 for http) is
     * dropped, and the query and fragment are dropped. The path is kept exactly; an empty one becomes "/".
     * A URL carrying userinfo is refused. This is an explicit grammar, not java.net.URI (which
     * normalises), so every SDK derives the same htu from the same string: scheme "://" authority [path]
     * ["?" query] ["#" fragment], authority = host [":" port], host a reg-name or a bracketed IPv6 literal,
     * port 1-5 digits. Send the request to exactly this URL: a client that rewrites the path (dot-segments,
     * percent-encoding) sends a path the htu does not name, and the runtime refuses it.
     */
    @JvmStatic
    fun httpHtu(url: String): String {
        if (!tokenChars.matches(url)) throw DpopException("url must be a non-empty visible-ASCII string (no spaces)")
        val sep = url.indexOf("://")
        val scheme = if (sep < 0) "" else url.substring(0, sep).lowercase(Locale.ROOT)
        if (sep < 0 || (scheme != "http" && scheme != "https")) {
            throw DpopException("url must be an absolute http:// or https:// URL")
        }
        val rest = url.substring(sep + 3)
        val cut = rest.firstOf("/?#")
        val authority = if (cut < 0) rest else rest.substring(0, cut)
        val tail = if (cut < 0) "" else rest.substring(cut)
        val q = tail.firstOf("?#")
        val path = if (q < 0) tail else tail.substring(0, q)
        if ('@' in authority) throw DpopException("url must not carry userinfo")
        var host: String
        var portText = ""
        if (authority.startsWith("[")) {
            val close = authority.indexOf(']')
            if (close < 2) throw DpopException("url has a malformed IPv6 literal")
            host = authority.substring(0, close + 1)
            val after = authority.substring(close + 1)
            if (after.isNotEmpty() && !after.startsWith(":")) throw DpopException("url has a malformed IPv6 literal")
            if (after.isNotEmpty()) portText = after.substring(1)
        } else {
            val colon = authority.indexOf(':')
            host = if (colon < 0) authority else authority.substring(0, colon)
            if (colon >= 0) {
                portText = authority.substring(colon + 1)
                if (':' in portText) {
                    throw DpopException("url has more than one ':' in its authority; bracket an IPv6 literal")
                }
            }
        }
        if (host.isEmpty()) throw DpopException("url has no host")
        host = host.lowercase(Locale.ROOT)
        var auth = host
        if (portText.isNotEmpty()) {
            if (!portDigits.matches(portText) || portText.toInt() > 65535) throw DpopException("url has an invalid port")
            val port = portText.toInt()
            if (port != (if (scheme == "https") 443 else 80)) auth = "$host:$port"
        }
        return "https://" + auth + path.ifEmpty { "/" }
    }

    /**
     * Both headers for one call to the HTTP management plane: `Authorization` ("DPoP <token>") and `DPoP`
     * (the proof). Send exactly body as the request body (empty for a GET), to exactly url. Call this once
     * per request; never reuse the headers for a retry.
     */
    @JvmStatic
    @JvmOverloads
    fun httpHeaders(
        key: Key,
        token: String,
        method: String,
        url: String,
        body: ByteArray = ByteArray(0),
        iat: Long? = null,
        jti: String? = null,
    ): Map<String, String> {
        val proof = proof(key, token, method, httpHtu(url), body, iat, jti)
        return linkedMapOf("Authorization" to "DPoP $token", "DPoP" to proof)
    }

    // ── the token, peeked (never verified: the runtime is the verifier) ─────────────────────────

    internal fun peekTokenClaims(token: String): JsonObject {
        checkToken(token)
        val parts = token.split(".")
        if (parts.size != 3 || !b64url.matches(parts[1]) || parts[1].length % 4 == 1) {
            throw DpopKeyException("the operator token is not a compact JWS")
        }
        val payload = try {
            parseStrict(String(b64dec.decode(parts[1]), Charsets.UTF_8))
        } catch (e: IOException) {
            throw DpopKeyException("the operator token's payload is not JSON")
        } catch (e: JsonParseException) {
            throw DpopKeyException("the operator token's payload is not JSON")
        } catch (e: IllegalStateException) {
            throw DpopKeyException("the operator token's payload is not JSON")
        }
        if (!payload.isJsonObject) throw DpopKeyException("the operator token's payload is not a JSON object")
        return payload.asJsonObject
    }

    /** cnf.jkt, or null when the token is unbound. */
    internal fun tokenCnfJkt(claims: JsonObject): String? {
        val cnf = claims.get("cnf")
        if (cnf == null || cnf.isJsonNull) return null
        return (if (cnf.isJsonObject) cnf.asJsonObject.stringMember("jkt") else null)
            ?: throw DpopKeyException("the operator token's cnf claim is malformed")
    }

    // ── the gRPC interceptor ────────────────────────────────────────────────────────────────────

    private val authorizationKey: Metadata.Key<String> =
        Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER)
    private val dpopKey: Metadata.Key<String> = Metadata.Key.of("dpop", Metadata.ASCII_STRING_MARSHALLER)

    /**
     * Signs every unary and server-streaming call with a fresh proof over its one request message. aud null
     * takes the token's own aud, else [DEFAULT_OPERATOR_AUD]. clock (seconds) defaults to the wall clock.
     * Every pairing the runtime is guaranteed to refuse throws here, before any call: a token that is not
     * DPoP-bound, a cnf.jkt naming another key, or a list aud with no override. Each attempt is signed once,
     * so never combine it with a retry policy that resends a call's metadata.
     */
    @JvmStatic
    @JvmOverloads
    fun interceptor(key: Key, token: String, aud: String? = null, clock: (() -> Long)? = null): ClientInterceptor {
        if (token.isEmpty()) throw DpopKeyException("a DPoP key needs token: the bound operator token minted with it")
        // The clock is probed before the token is read, in Python's order, so a bad clock is named first.
        val c = clock ?: { System.currentTimeMillis() / 1000 }
        val sample = c()
        if (sample < 0 || sample > MAX_IAT) throw DpopException("clock must return a non-negative integer number of seconds")
        val claims = peekTokenClaims(token)
        val jkt = tokenCnfJkt(claims) ?: throw DpopKeyException(
            "the operator token is not DPoP-bound (no cnf.jkt); send it as Bearer without this interceptor",
        )
        if (jkt != key.jkt) throw DpopKeyException("the operator token is bound to key $jkt, not this key (${key.jkt})")
        val resolved = aud ?: run {
            val tokAud = claims.get("aud")
            when {
                tokAud == null -> DEFAULT_OPERATOR_AUD // absent; a JSON null is refused below, as in Python and TS
                tokAud.isJsonPrimitive && tokAud.asJsonPrimitive.isString -> tokAud.asString
                else -> throw DpopKeyException("the operator token's aud is not a single string; pass aud explicitly")
            }
        }
        grpcHtu("/m", resolved) // refuses an aud that cannot form an htu
        return DpopInterceptor(key, token, resolved, c)
    }

    private class DpopInterceptor(
        val key: Key,
        val token: String,
        val aud: String,
        val clock: () -> Long,
    ) : ClientInterceptor {
        override fun <Q, R> interceptCall(
            method: MethodDescriptor<Q, R>,
            options: CallOptions,
            next: Channel,
        ): ClientCall<Q, R> {
            check(method.type.clientSendsOneMessage()) {
                "${method.fullMethodName} streams requests; a DPoP proof binds exactly one request message"
            }
            return DelayedSignedCall(this, method, options, next)
        }

        fun sign(fullMethodName: String, body: ByteArray): String =
            proof(key, token, "POST", grpcHtu("/$fullMethodName", aud), body, clock(), null)
    }

    /**
     * A call whose real start waits for its one request message, because the proof signs that message's
     * bytes and travels in the headers. Until then, `request`, `setMessageCompression` and `halfClose` are
     * queued and replayed in order; `cancel` closes the listener without ever opening the real call.
     */
    private class DelayedSignedCall<Q, R>(
        private val signer: DpopInterceptor,
        private val method: MethodDescriptor<Q, R>,
        private val options: CallOptions,
        private val next: Channel,
    ) : ClientCall<Q, R>() {
        private var listener: Listener<R>? = null
        private var headers: Metadata? = null
        private var real: ClientCall<Q, R>? = null
        private var closed = false
        private val pending = mutableListOf<(ClientCall<Q, R>) -> Unit>()

        @Synchronized
        override fun start(responseListener: Listener<R>, headers: Metadata) {
            check(listener == null) { "already started" }
            listener = responseListener
            this.headers = headers
        }

        @Synchronized
        override fun request(numMessages: Int) {
            real?.request(numMessages) ?: run { if (!closed) pending.add { it.request(numMessages) } }
        }

        @Synchronized
        override fun setMessageCompression(enabled: Boolean) {
            real?.setMessageCompression(enabled) ?: run { if (!closed) pending.add { it.setMessageCompression(enabled) } }
        }

        override fun sendMessage(message: Q) {
            val started: ClientCall<Q, R>
            synchronized(this) {
                val l = checkNotNull(listener) { "sendMessage before start" }
                if (closed) return // cancelled before its message: nothing is sent, as with any cancelled call
                check(real == null) { "${method.fullMethodName}: a DPoP proof binds exactly one request message" }
                val body = try {
                    method.streamRequest(message).use { it.readAllBytes() }
                } catch (e: IOException) {
                    throw DpopException("cannot encode the request message: ${e.message}")
                }
                // A refusal (an oversized message) throws here, before anything reaches the wire.
                val proof = signer.sign(method.fullMethodName, body)
                val h = headers!!
                h.put(authorizationKey, "DPoP ${signer.token}")
                h.put(dpopKey, proof)
                val call = next.newCall(method, options)
                real = call
                call.start(l, h)
                pending.forEach { it(call) }
                pending.clear()
                started = call
            }
            started.sendMessage(message)
        }

        @Synchronized
        override fun halfClose() {
            checkNotNull(listener) { "halfClose before start" }
            real?.let {
                it.halfClose()
                return
            }
            if (closed) return
            closed = true
            pending.clear()
            listener?.onClose(
                Status.INTERNAL.withDescription("a management call must carry exactly one request message (got none)"),
                Metadata(),
            )
        }

        @Synchronized
        override fun cancel(message: String?, cause: Throwable?) {
            real?.let {
                it.cancel(message, cause)
                return
            }
            if (closed) return
            closed = true
            pending.clear()
            var status = Status.CANCELLED
            if (message != null) status = status.withDescription(message)
            if (cause != null) status = status.withCause(cause)
            listener?.onClose(status, Metadata())
        }

        @Synchronized
        override fun isReady(): Boolean = real?.isReady ?: false

        @Synchronized
        override fun getAttributes(): Attributes = real?.attributes ?: Attributes.EMPTY
    }
}
