package com.zer07labs.seam

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.File
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** The Kotlin crypto shim must reproduce the Rust reference bytes exactly (conformance/vectors.json). */
class ConformanceTest {
    private val vectors: Map<String, Any?> =
        Gson().fromJson(
            File("../conformance/vectors.json").readText(),
            object : TypeToken<Map<String, Any?>>() {}.type,
        )

    @Suppress("UNCHECKED_CAST")
    private fun m(p: Map<String, Any?>, k: String) = p[k] as Map<String, Any?>

    private fun hexToBytes(s: String) =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun commitment(c: Map<String, Any?>) =
        Commitment(
            c["id"] as String,
            c["action"] as String,
            c["authority"] as String,
            c["supersedes"] as String?,
            c["auth_method"] as String,
            c["trust_basis"] as String,
        )

    @Test
    fun pinnedKeyPresentationIsByteExact() {
        val adm = m(vectors, "admission")
        val inp = m(adm, "inputs")
        val got =
            SeamCrypto.buildPresentation(
                hexToBytes(inp["agent_seed_hex"] as String),
                inp["receiver_aid"] as String,
                inp["pop_nonce"] as String,
                (inp["now_ms"] as Number).toLong(),
            )
        val want = m(adm, "presentation")
        val wd = m(want, "descriptor")
        assertEquals(want["sender_aid"], got.senderAid)
        assertEquals(wd["type"], got.descriptor.type)
        assertEquals(wd["subject"], got.descriptor.subject)
        assertEquals(wd["proof"], got.descriptor.proof)
        assertEquals(wd["public_key"], got.descriptor.publicKey)
        assertEquals(want["message_id"], got.messageId)
        assertEquals((want["timestamp"] as Number).toLong(), got.timestamp)
        assertEquals(want["pop_nonce"], got.popNonce)
    }

    @Test
    fun aidDerivationMatches() {
        val adm = m(vectors, "admission")
        val got =
            SeamCrypto.buildPresentation(
                hexToBytes(m(adm, "inputs")["agent_seed_hex"] as String),
                "aid:x",
                "AAAA",
                0,
            )
        assertEquals(m(adm, "derived")["sender_aid"], got.senderAid)
    }

    @Test
    fun tctVerifyValidAndTampered() {
        val t = m(vectors, "tct")
        val c = commitment(m(m(t, "inputs"), "commitment"))
        val iss = t["issuer_aid"] as String
        val jws = t["signed_artifact_jws"] as String
        assertTrue(SeamCrypto.verifyTct(iss, jws, c, 1_700_000_001), "valid TCT must verify")
        assertFalse(
            SeamCrypto.verifyTct(iss, jws, c.copy(action = "ALLOW"), 1_700_000_001),
            "a tampered commitment must not verify",
        )
    }

    @Test
    fun tctVerifyFailsClosed() {
        val t = m(vectors, "tct")
        val c = commitment(m(m(t, "inputs"), "commitment"))
        val iss = t["issuer_aid"] as String
        val jws = t["signed_artifact_jws"] as String
        val cases =
            listOf(
                Triple(iss, jws, 9_999_999_999L),
                Triple(iss, "not.a", 1_700_000_001L),
                Triple("aid:pubkey:ed25519:" + "A".repeat(43), jws, 1_700_000_001L),
                Triple("did:web:example.com", jws, 1_700_000_001L),
                Triple(iss, jws.substring(0, jws.length - 4) + "AAAA", 1_700_000_001L),
            )
        for ((issuer, token, now) in cases) {
            assertFalse(SeamCrypto.verifyTct(issuer, token, c, now), "must fail closed")
        }
    }
}
