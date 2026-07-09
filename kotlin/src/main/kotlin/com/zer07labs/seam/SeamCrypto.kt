package com.zer07labs.seam

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
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

object SeamCrypto {
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
        buf.writeBytes(ByteBuffer.allocate(8).putLong(timestamp).array()); buf.write(0)
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
}
