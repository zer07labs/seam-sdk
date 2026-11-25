package com.zer07labs.seam

import java.math.BigInteger
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * S-4 evidence grade: [SeamCrypto.verifyTctSealedAt] requires `iat == floor(sealedAtMs / 1000)`. Pinned by
 * `conformance/tct_sealed_at_vector.json` (emitted by `scripts/emit_tct_sealed_at_vector.py` over the
 * runtime's byte-identical `commitment_digest_v6_signed_vector.json`), the vector every SDK verifier
 * answers. Same rule as seam-verify `verify_tct_sealed_at` and the runtime's `verify_commitment_sealed_at`
 * (seam-runtime #2031).
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
        for (n in listOf("exact_second_boundary", "iat_plus_1s_at_boundary", "iat_minus_1s_at_boundary")) {
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
                SeamCrypto.verifyTctSealedAt(issuer, jws, c, 0, arg),
                row["name"] as String,
            )
        }
        assertFalse(SeamCrypto.verifyTctSealedAt(issuer, jws, c, 0, -1L))
    }
}
