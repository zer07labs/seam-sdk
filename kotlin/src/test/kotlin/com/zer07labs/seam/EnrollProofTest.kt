package com.zer07labs.seam

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.File
import java.math.BigInteger
import java.util.Base64
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The agent-side enrolment proof and its REST form (#214), against the same shared vector as the raw
 * signer (conformance/enroll_pop_v1_payload_vector.json). The REST `pop` object must match the
 * vector's fields byte for byte once serialized. NO bless mode.
 */
class EnrollProofTest {
    @Test
    @Suppress("UNCHECKED_CAST")
    fun enrolmentProofAndRestFormMatchVector() {
        val v: Map<String, Any?> =
            Gson().fromJson(
                File("../conformance/enroll_pop_v1_payload_vector.json").readText(),
                object : TypeToken<Map<String, Any?>>() {}.type,
            )
        val cases = v["cases"] as List<Map<String, Any?>>
        assertTrue(cases.size >= 6, "the vector lost cases; it pins a wire contract")
        for (c in cases) {
            val label = "${c["name"]}: ${c["why"]}"
            val seed = hexToBytes(c["seed_hex"] as String)
            val pub = Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
            val issuedAtMs = (c["issued_at_ms"] as Number).toLong()
            val nonce = c["nonce"] as String
            val signature = c["signature"] as String
            assertEquals(c["subject_aid"], SeamCrypto.aidFromPubkey(pub), label)

            val proof =
                SeamCrypto.enrolmentProof(
                    seed,
                    c["tenant"] as String,
                    c["namespace"] as String,
                    issuedAtMs = issuedAtMs.toULong(),
                    nonce = nonce,
                )
            // RAW 64 bytes — the gRPC form.
            assertEquals(64, proof.signature.size, label)
            assertArrayEquals(Base64.getUrlDecoder().decode(signature), proof.signature, label)
            assertEquals(issuedAtMs.toULong(), proof.issuedAtMs, label)
            assertEquals(nonce, proof.nonce, label)
            // Unpadded base64url — the REST form.
            assertEquals(signature, proof.signatureB64url, label)
            assertEquals(
                linkedMapOf<String, Any>("issued_at_ms" to issuedAtMs, "nonce" to nonce, "signature" to signature),
                proof.toRest(),
                label,
            )
            assertEquals(
                """{"issued_at_ms":$issuedAtMs,"nonce":"$nonce","signature":"$signature"}""",
                Gson().toJson(proof.toRest()),
                label,
            )
            // It verifies over the vector's payload.
            assertTrue(verify(pub, hexToBytes(c["payload_hex"] as String), proof.signature), label)
        }
    }

    @Test
    fun enrolmentProofDefaultsToNowAndAFresh22CharNonce() {
        val seed = ByteArray(32) { it.toByte() }
        val pub = Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
        val before = System.currentTimeMillis().toULong()
        val a = SeamCrypto.enrolmentProof(seed, "acme", "fraud")
        val b = SeamCrypto.enrolmentProof(seed, "acme", "fraud")
        val after = System.currentTimeMillis().toULong()
        assertTrue(a.issuedAtMs in before..after)
        assertEquals(22, a.nonce.length)
        SeamCrypto.validateEnrollPopNonce(a.nonce)
        assertNotEquals(a.nonce, b.nonce, "the default nonce must be random per proof")
        val f = EnrollPopFields(SeamCrypto.aidFromPubkey(pub), "acme", "fraud", a.issuedAtMs, a.nonce)
        assertTrue(verify(pub, SeamCrypto.enrollPopPayload(f), a.signature))
    }

    @Test
    fun restFormCarriesAnUnsignedIssuedAtAndTheProofIsAValue() {
        val sig = ByteArray(64) { 1 }
        val p = EnrollProof(ULong.MAX_VALUE, "n", sig)
        assertEquals(BigInteger("18446744073709551615"), p.toRest()["issued_at_ms"])
        assertEquals(EnrollProof(ULong.MAX_VALUE, "n", sig.copyOf()), p)
        sig[0] = 2 // the proof copied its signature
        assertEquals(1.toByte(), p.signature[0])
    }

    @Test
    fun enrolmentProofRefusesBadNoncesAndShortSeeds() {
        val seed = ByteArray(32) { 7 }
        for (n in listOf("", "x".repeat(129), "has space", "pad=", "a+b", "a/b", "é", "a.b", "ok\n")) {
            assertThrows(
                IllegalArgumentException::class.java,
                { SeamCrypto.enrolmentProof(seed, "acme", "fraud", issuedAtMs = 1uL, nonce = n) },
                "nonce $n",
            )
        }
        assertThrows(IllegalArgumentException::class.java) { SeamCrypto.enrolmentProof(ByteArray(31), "acme", "fraud") }
    }

    private fun verify(pub: ByteArray, msg: ByteArray, sig: ByteArray): Boolean {
        val v = Ed25519Signer()
        v.init(false, Ed25519PublicKeyParameters(pub, 0))
        v.update(msg, 0, msg.size)
        return v.verifySignature(sig)
    }

    private fun hexToBytes(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
