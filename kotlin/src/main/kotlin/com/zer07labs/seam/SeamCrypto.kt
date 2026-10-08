package com.zer07labs.seam

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.Arrays
import java.util.Base64
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * Client-side crypto for the Seam Kotlin SDK — stock primitives (Ed25519 via Bouncy Castle + SHA-256),
 * no AITP binding. Mirrors the Python/Go/Java/TS reference byte-for-byte; pinned by
 * `conformance/vectors.json`. The admission proof-of-possession is Ed25519 over SHA-256 of a documented,
 * domain-separated canonical byte layout; the seed never leaves the client.
 */
data class Descriptor(val type: String, val subject: String, val proof: String, val publicKey: String)

data class Presentation(
    val senderAid: String,
    val descriptor: Descriptor,
    val messageId: String,
    val timestamp: Long,
    val popNonce: String,
)

data class Commitment(
    val id: String,
    val action: String,
    val authority: String,
    val supersedes: String?,
    val authMethod: String,
    val trustBasis: String,
)

/**
 * The inputs [SeamCrypto.callSigV3Payload] frames. Every string is signed as its UTF-8 bytes; an
 * absent optional field is the empty string (the default), signed verbatim rather than skipped.
 * [ticket] is the admission ticket's RAW bytes. [subjects] are signed in the order given — never
 * deduped, never sorted. [features] are (key, value) pairs in any order; they are signed sorted by
 * (key bytes, value bytes).
 *
 * The v2 fields carry no defaults on purpose, as in Python: a forgotten `toolName`/`agentId` should
 * fail to compile, not produce a signature the runtime rejects.
 */
data class CallSigV3Fields(
    val ticket: ByteArray,
    val toolInputDigest: String,
    val toolName: String,
    val agentId: String,
    val subject: String = "",
    val subjects: List<String> = emptyList(),
    val clientRequestId: String = "",
    val sessionId: String = "",
    val features: List<Pair<String, String>> = emptyList(),
)

object SeamCrypto {
    /**
     * Domain tag of the `Authorize` per-call proof-of-possession, v3 (#197). The distinct tag means a
     * v2 signature can NEVER verify as a v3 one, so SDK/runtime version skew is a clean rejection
     * rather than a parse ambiguity. Bump it only in lockstep with the runtime.
     */
    const val CALL_SIG_V3_CONTEXT = "seam-authorize-call-v3"

    private val PROOF_DOMAIN = "aitp-pinned-key-v1".toByteArray(Charsets.UTF_8) + byteArrayOf(0)
    private val gson = Gson()
    private val mapType = object : TypeToken<Map<String, Any?>>() {}.type

    private fun b64urlNoPad(b: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    private fun b64urlDecode(s: String): ByteArray {
        val pad = (4 - s.length % 4) % 4
        return Base64.getUrlDecoder().decode(s + "=".repeat(pad))
    }

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    private fun ed25519Pub(seed: ByteArray): ByteArray =
        Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded

    private fun ed25519Sign(seed: ByteArray, msg: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(seed, 0))
        signer.update(msg, 0, msg.size)
        return signer.generateSignature()
    }

    private fun ed25519Verify(pub: ByteArray, msg: ByteArray, sig: ByteArray): Boolean =
        try {
            val verifier = Ed25519Signer()
            verifier.init(false, Ed25519PublicKeyParameters(pub, 0))
            verifier.update(msg, 0, msg.size)
            verifier.verifySignature(sig)
        } catch (e: RuntimeException) {
            false
        }

    /** The agent's `aid:pubkey:ed25519:` identity for a 32-byte Ed25519 public key. */
    fun aidFromPubkey(pub: ByteArray): String = "aid:pubkey:ed25519:" + b64urlNoPad(pub)

    private fun aidToPubkey(aid: String): ByteArray {
        for (p in listOf("aid:pubkey:ed25519:", "aid:pubkey:")) {
            if (aid.startsWith(p)) return b64urlDecode(aid.substring(p.length))
        }
        throw IllegalArgumentException("unsupported AID form: $aid")
    }

    private fun popMessageId(popNonce: String): String {
        val h = sha256("seam-pop-mid".toByteArray(Charsets.UTF_8) + popNonce.toByteArray(Charsets.US_ASCII))
        val sb = StringBuilder(36)
        for (i in 0 until 16) {
            if (i == 4 || i == 6 || i == 8 || i == 10) sb.append('-')
            sb.append("%02x".format(h[i].toInt() and 0xff))
        }
        return sb.toString()
    }

    /** Build the pinned-key admission presentation the Seam server verifies. */
    fun buildPresentation(agentSeed: ByteArray, receiverAid: String, popNonce: String, nowMs: Long): Presentation {
        val pub = ed25519Pub(agentSeed)
        val senderAid = aidFromPubkey(pub)
        val mid = popMessageId(popNonce)
        val timestamp = nowMs / 1000

        val buf = ByteArrayOutputStream()
        buf.writeBytes(PROOF_DOMAIN)
        buf.writeBytes(senderAid.toByteArray(Charsets.UTF_8)); buf.write(0)
        buf.writeBytes(receiverAid.toByteArray(Charsets.UTF_8)); buf.write(0)
        buf.writeBytes(mid.toByteArray(Charsets.UTF_8)); buf.write(0)
        buf.writeBytes(timestamp.toString().toByteArray(Charsets.US_ASCII)); buf.write(0)
        buf.writeBytes(b64urlDecode(popNonce))

        val proof = ed25519Sign(agentSeed, sha256(buf.toByteArray()))
        return Presentation(
            senderAid,
            Descriptor("pinned_key", senderAid, b64urlNoPad(proof), b64urlNoPad(pub)),
            mid,
            timestamp,
            popNonce,
        )
    }

    /**
     * SHA-256 (hex) over a **length-prefixed** framing of a domain tag plus the commitment fields —
     * each field preceded by its 8-byte big-endian length. Mirrors the runtime byte-for-byte, and
     * mirrors the Go/Java/Python/TypeScript shims.
     *
     * **The length prefixes are not decoration and must never be "simplified" to a separator.** The
     * fields are arbitrary text that may itself contain NUL — UTF-8 permits U+0000, and it survives
     * the JSON/prost decision path — so with a `\u0000` separator the tuples `("a\u0000b","c")` and
     * `("a","b\u0000c")` produce IDENTICAL preimages, and therefore identical digests. That would
     * let one Commitment verify under another's TCT: an attacker who controls a field boundary could
     * shift bytes across it and reuse a signature that was never issued for their artifact.
     * Length-prefixing makes the digest injective over the field tuple regardless of content.
     *
     * The same rationale is recorded at `seam-trust-aitp/src/lib.rs:350-354` in the runtime. It is
     * written out here because this comment is the only thing standing between a future maintainer
     * and a "cleanup" that silently breaks artifact binding — and Kotlin and Java were the two shims
     * that carried no rationale at all while Go, Python and TypeScript did.
     *
     * Field order is also load-bearing and must match the runtime exactly: domain, id, action,
     * authority, supersedes, auth_method, trust_basis. Binding `authMethod`/`trustBasis` is what
     * makes the artifact attest *who* committed it and *how* they authed, not just the decision.
     * `ConformanceTest` asserts every one of these is bound.
     */
    private fun seamCommitmentDigest(c: Commitment): String {
        val h = ByteArrayOutputStream()
        val fields = listOf(
            "seam-commitment-digest:v1".toByteArray(Charsets.UTF_8),
            c.id.toByteArray(Charsets.UTF_8),
            c.action.toByteArray(Charsets.UTF_8),
            c.authority.toByteArray(Charsets.UTF_8),
            (c.supersedes ?: "").toByteArray(Charsets.UTF_8),
            c.authMethod.toByteArray(Charsets.UTF_8),
            c.trustBasis.toByteArray(Charsets.UTF_8),
        )
        for (f in fields) {
            h.writeBytes(ByteBuffer.allocate(8).putLong(f.size.toLong()).array())
            h.writeBytes(f)
        }
        return sha256(h.toByteArray()).joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    /**
     * Independently verify a sealed commitment's rooted TCT — zero server trust, stock crypto only. Any
     * malformed/forged input fails closed (returns false), never throws.
     */
    fun verifyTct(issuerAid: String, tctJws: String, commitment: Commitment, nowS: Long): Boolean {
        return try {
            val parts = tctJws.split(".")
            if (parts.size != 3) return false
            val pub = try {
                aidToPubkey(issuerAid)
            } catch (e: RuntimeException) {
                return false
            }
            if (pub.size != 32) return false
            if (!ed25519Verify(pub, "${parts[0]}.${parts[1]}".toByteArray(Charsets.US_ASCII), b64urlDecode(parts[2]))) {
                return false
            }
            val header: Map<String, Any?> = gson.fromJson(String(b64urlDecode(parts[0]), Charsets.UTF_8), mapType)
            val payload: Map<String, Any?> = gson.fromJson(String(b64urlDecode(parts[1]), Charsets.UTF_8), mapType)
            if (header["alg"] != "EdDSA" || header["typ"] != "aitp-tct+jwt") return false
            if (!(payload["iss"] == issuerAid && payload["sub"] == issuerAid && payload["aud"] == issuerAid)) {
                return false
            }
            val exp = payload["exp"] as? Number ?: return false
            if (nowS >= exp.toLong()) return false // RFC 7519: reject at/after expiry
            val want = "seam-commitment-digest:" + seamCommitmentDigest(commitment)
            val grants = payload["grants"] as? List<*> ?: return false
            grants.any { it == want }
        } catch (e: RuntimeException) {
            false
        }
    }

    /**
     * The exact bytes [callSigV3] signs: `frame(context) | frame(ticket) | frame(tool_input_digest) |
     * frame(tool_name) | frame(agent_id) | frame(subject) | frame(u32le(n_subjects)) |
     * frame(subject_i)... | frame(client_request_id) | frame(session_id) | frame(u32le(n_features)) |
     * (frame(key) | frame(value))...`, with `frame(x) = u32le(len_bytes(x)) | x` — the counts are
     * themselves framed.
     *
     * Features are sorted by their UTF-8 **bytes**, compared unsigned. `String.compareTo` would be
     * wrong here: it orders by UTF-16 code unit, which disagrees with byte order for
     * supplementary-plane vs. high-BMP characters.
     *
     * Pinned by `conformance/call_sig_v3_payload_vector.json`. Public so a caller can reproduce or
     * verify the binding without re-deriving it from prose.
     */
    fun callSigV3Payload(f: CallSigV3Fields): ByteArray {
        val out = ByteArrayOutputStream()
        fun frame(b: ByteArray) {
            out.writeBytes(u32le(b.size))
            out.writeBytes(b)
        }
        frame(CALL_SIG_V3_CONTEXT.toByteArray(Charsets.UTF_8))
        frame(f.ticket)
        frame(f.toolInputDigest.toByteArray(Charsets.UTF_8))
        frame(f.toolName.toByteArray(Charsets.UTF_8))
        frame(f.agentId.toByteArray(Charsets.UTF_8))
        frame(f.subject.toByteArray(Charsets.UTF_8))
        frame(u32le(f.subjects.size))
        for (s in f.subjects) frame(s.toByteArray(Charsets.UTF_8))
        frame(f.clientRequestId.toByteArray(Charsets.UTF_8))
        frame(f.sessionId.toByteArray(Charsets.UTF_8))

        val features = f.features
            .map { (k, v) -> k.toByteArray(Charsets.UTF_8) to v.toByteArray(Charsets.UTF_8) }
            .sortedWith { a, b ->
                val c = Arrays.compareUnsigned(a.first, b.first)
                if (c != 0) c else Arrays.compareUnsigned(a.second, b.second)
            }
        frame(u32le(features.size))
        for ((k, v) in features) {
            frame(k)
            frame(v)
        }
        return out.toByteArray()
    }

    /**
     * The per-call proof-of-possession for `Authorize`: Ed25519 by the agent key (32-byte seed) over
     * [callSigV3Payload], returned as the raw 64-byte signature (the `call_sig` bytes field), as
     * Python's `call_sig` does.
     */
    fun callSigV3(agentSeed: ByteArray, f: CallSigV3Fields): ByteArray {
        require(agentSeed.size == 32) { "agent seed must be 32 bytes" }
        return ed25519Sign(agentSeed, callSigV3Payload(f))
    }

    private fun u32le(n: Int): ByteArray =
        ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(n).array()
}
