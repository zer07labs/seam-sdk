package com.zer07labs.seam

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.Base64
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * Test support: mint a commitment TCT in the S-4 seal-key shape (seam-runtime #2031). The pinned
 * issuer certifies a seal key over a window; the seal key signs the token. Built by hand here, never
 * through [SeamCrypto], so a test is not checking the verifier against itself.
 */
internal object SealKeyTokens {
    /** The seal key the tests sign with (any fixed seed). */
    val SEAL_SEED = ByteArray(32) { 0x5e }

    /** A window every helper token falls in: 1_700_000_000 s, 15 minutes wide. */
    const val NOT_BEFORE_MS = 1_700_000_000_000L
    const val NOT_AFTER_MS = NOT_BEFORE_MS + 900_000L
    const val IAT = NOT_BEFORE_MS / 1000

    fun b64(b: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    fun pub(seed: ByteArray): ByteArray = Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded

    fun sign(seed: ByteArray, msg: ByteArray): ByteArray {
        val s = Ed25519Signer()
        s.init(true, Ed25519PrivateKeyParameters(seed, 0))
        s.update(msg, 0, msg.size)
        return s.generateSignature()
    }

    fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    fun sealAid(sealSeed: ByteArray): String = "aid:pubkey:" + b64(pub(sealSeed))

    fun jkt(pk: ByteArray): String =
        b64(sha256("""{"crv":"Ed25519","kty":"OKP","x":"${b64(pk)}"}""".toByteArray(Charsets.US_ASCII)))

    private fun framed(out: ByteArrayOutputStream, b: ByteArray) {
        out.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(b.size).array())
        out.write(b)
    }

    /** `framed(tag) ‖ framed(pk) ‖ le64 nb ‖ le64 na ‖ framed(issuer_aid)`. */
    fun cert(sealPk: ByteArray, nb: Long, na: Long, issuerAid: String): ByteArray {
        val out = ByteArrayOutputStream()
        framed(out, "seam.seal-key-cert.v1".toByteArray(Charsets.US_ASCII))
        framed(out, sealPk)
        out.write(ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN).putLong(nb).putLong(na).array())
        framed(out, issuerAid.toByteArray(Charsets.UTF_8))
        return out.toByteArray()
    }

    /** The `{cert, sig}` ext member over raw certificate bytes, signed by [issuerSeed]. */
    fun member(issuerSeed: ByteArray, cert: ByteArray): MutableMap<String, Any?> =
        linkedMapOf("cert" to b64(cert), "sig" to b64(sign(issuerSeed, sha256(cert))))

    /** The default member: [SEAL_SEED] certified by [issuerSeed] under [issuerAid]. */
    fun member(issuerSeed: ByteArray, issuerAid: String): MutableMap<String, Any?> =
        member(issuerSeed, cert(pub(SEAL_SEED), NOT_BEFORE_MS, NOT_AFTER_MS, issuerAid))

    /** The seal-key claims (`ver`, `iss/sub/aud`, `cnf`, `iat`) for [sealSeed]. */
    fun claims(sealSeed: ByteArray, iat: Long): MutableMap<String, Any?> {
        val aid = sealAid(sealSeed)
        return linkedMapOf(
            "ver" to "aitp/0.3",
            "iss" to aid,
            "sub" to aid,
            "aud" to aid,
            "cnf" to mapOf("jkt" to jkt(pub(sealSeed))),
            "iat" to iat,
        )
    }

    /** Compact JWS of [payloadJson] signed by [sealSeed]. */
    fun jws(sealSeed: ByteArray, payloadJson: String): String {
        val input = b64("""{"alg":"EdDSA","typ":"aitp-tct+jwt"}""".toByteArray()) + "." + b64(payloadJson.toByteArray())
        return input + "." + b64(sign(sealSeed, input.toByteArray(Charsets.US_ASCII)))
    }
}
