package com.zer07labs.seam

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.File
import java.util.Base64
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The enrolment proof-of-possession (#205). conformance/enroll_pop_v1_payload_vector.json is the
 * cross-language contract. NO bless mode: a mismatch is a contract break (a v2 domain tag), not a
 * stale fixture.
 */
class EnrollPopTest {
    @Test
    @Suppress("UNCHECKED_CAST")
    fun enrollPopMatchesVector() {
        val v: Map<String, Any?> =
            Gson().fromJson(
                File("../conformance/enroll_pop_v1_payload_vector.json").readText(),
                object : TypeToken<Map<String, Any?>>() {}.type,
            )
        assertEquals(SeamCrypto.ENROLL_POP_V1_CONTEXT, v["domain"])
        val cases = v["cases"] as List<Map<String, Any?>>
        assertFalse(cases.isEmpty(), "vector is empty; every assertion below would pass vacuously")
        for (c in cases) {
            val label = "${c["name"]}: ${c["why"]}"
            val f =
                EnrollPopFields(
                    subjectAid = c["subject_aid"] as String,
                    tenant = c["tenant"] as String,
                    namespace = c["namespace"] as String,
                    issuedAtMs = (c["issued_at_ms"] as Number).toLong().toULong(),
                    nonce = c["nonce"] as String,
                )
            assertEquals(c["payload_hex"], hex(SeamCrypto.enrollPopPayload(f)), label)

            val sig = SeamCrypto.enrollPop(hexToBytes(c["seed_hex"] as String), f)
            // RAW 64 bytes — the gRPC form.
            assertArrayEquals(Base64.getUrlDecoder().decode(c["signature"] as String), sig, label)
            // Unpadded base64url — the REST form.
            assertEquals(c["signature"], Base64.getUrlEncoder().withoutPadding().encodeToString(sig), label)
        }
    }

    @Test
    fun aProofForOneTenantAndNamespaceDoesNotVerifyForAnother() {
        val seed = ByteArray(32) { 7 }
        val pub = Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
        val f = EnrollPopFields(SeamCrypto.aidFromPubkey(pub), "tenant-a", "ns-x", 1_760_000_000_000uL, "n0")
        val sig = SeamCrypto.enrollPop(seed, f)
        assertEquals(64, sig.size)
        assertTrue(verify(pub, SeamCrypto.enrollPopPayload(f), sig), "signature must verify")
        for ((t, n) in listOf("tenant-b" to "ns-x", "tenant-a" to "ns-y", "tenant-b" to "ns-y")) {
            assertFalse(
                verify(pub, SeamCrypto.enrollPopPayload(f.copy(tenant = t, namespace = n)), sig),
                "a tenant-a/ns-x proof verified for $t/$n",
            )
        }
    }

    @Test
    fun signerRefusesBadNoncesForeignAidsAndShortSeeds() {
        val seed = ByteArray(32) { 7 }
        val aid = SeamCrypto.aidFromPubkey(Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded)
        val ok = EnrollPopFields(aid, "acme", "fraud", 1uL, "ok")
        for (n in listOf("", "x".repeat(129), "has space", "pad=", "a+b", "a/b", "é", "a.b")) {
            assertThrows(IllegalArgumentException::class.java, { SeamCrypto.enrollPop(seed, ok.copy(nonce = n)) }, "nonce $n")
        }
        assertDoesNotThrow { SeamCrypto.validateEnrollPopNonce("x".repeat(128)) }
        assertThrows(IllegalArgumentException::class.java) {
            SeamCrypto.enrollPop(seed, ok.copy(subjectAid = "aid:pubkey:ed25519:11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"))
        }
        assertThrows(IllegalArgumentException::class.java) { SeamCrypto.enrollPop(ByteArray(31), ok) }
    }

    private fun verify(pub: ByteArray, msg: ByteArray, sig: ByteArray): Boolean {
        val v = Ed25519Signer()
        v.init(false, Ed25519PublicKeyParameters(pub, 0))
        v.update(msg, 0, msg.size)
        return v.verifySignature(sig)
    }

    private fun hexToBytes(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
