package com.zer07labs.seam

import java.math.BigInteger
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Evidence grade: [SeamCrypto.verifyTctSealedAt] requires `iat == floor(sealedAtMs / 1000)` (S-4) and
 * `jti == tctJti(decisionId, sealedAtMs)` (seam-runtime 0.127.0 P4). Pinned by
 * `conformance/tct_sealed_at_vector.json` (emitted by `scripts/emit_tct_sealed_at_vector.py` over the
 * runtime's byte-identical `commitment_digest_v6_signed_vector.json`), the vector every SDK verifier
 * answers. Same rule as seam-verify `verify_tct_sealed_at` and the runtime's `check_commitment_sealed_for`.
 */
class TctSealedAtVectorTest {
    @Suppress("UNCHECKED_CAST")
    @Test
    fun everyCaseAnswersItsExpect() {
        val v = loadVector("tct_sealed_at_vector.json")
        assertEquals("conformance/commitment_digest_v6_signed_vector.json", v["source"])
        val s = loadVector("commitment_digest_v6_signed_vector.json")
        val k = vectorRows(s, "cases").named(v["over"] as String)
        val issuer = s["issuer_aid"] as String
        val jws = k["signed_artifact"] as String
        val c = commitmentFromJson(k["commitment"] as Map<String, Any?>).copy(trailers = unhex(k["trailers"]))
        assertTrue(SeamCrypto.verifyTct(issuer, jws, c, 0), "control")

        val rows = vectorRows(v, "cases")
        val names = rows.map { it["name"] as String }.toSet()
        for (n in listOf(
            "exact_second_boundary",
            "last_ms_of_the_second",
            "iat_plus_1s_at_boundary",
            "iat_minus_1s_at_boundary",
            "replayed_onto_another_record",
            "commitment_id_is_not_the_record_id",
        )) {
            assertTrue(n in names, n)
        }
        val longMax = BigInteger.valueOf(Long.MAX_VALUE)
        for (row in rows) {
            val ms = BigInteger(row["sealed_at_ms"] as String)
            // A uint64 beyond Long.MAX_VALUE arrives as its two's-complement (negative) reading, which the
            // verifier refuses: that is the runtime's beyond-i64 refusal.
            val arg = if (ms > longMax) ms.toLong() else ms.longValueExact()
            assertEquals(
                row["expect"] == "verified",
                SeamCrypto.verifyTctSealedAt(issuer, jws, c, 0, row["decision_id"] as String, arg),
                row["name"] as String,
            )
        }
        val id = v["decision_id"] as String
        assertFalse(SeamCrypto.verifyTctSealedAt(issuer, jws, c, 0, id, -1L))
        val ok = (s["seal_ms"] as Number).toLong()
        assertTrue(SeamCrypto.verifyTctSealedAt(issuer, jws, c, 0, id, ok), "the verified row")
    }

    @Suppress("UNCHECKED_CAST")
    @Test
    fun theJtiDerivationMatchesTheRuntimeKnownAnswerAndTheToken() {
        val v = loadVector("tct_sealed_at_vector.json")
        val kat = v["jti_kat"] as Map<String, Any?>
        assertEquals(
            kat["jti"],
            SeamCrypto.tctJti(kat["decision_id"] as String, (kat["sealed_at_ms"] as String).toLong()),
        )
        val s = loadVector("commitment_digest_v6_signed_vector.json")
        assertEquals(v["jti"], SeamCrypto.tctJti(v["decision_id"] as String, (s["seal_ms"] as Number).toLong()))
    }
}
