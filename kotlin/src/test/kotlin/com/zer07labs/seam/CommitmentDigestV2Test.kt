package com.zer07labs.seam

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.File
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Build a [Commitment] from the REST projection used by the vectors: byte fields as JSON number
 * arrays (or hex strings), absent `confidence` / `rationale_ref` / `supersedes` as `null`.
 */
@Suppress("UNCHECKED_CAST")
internal fun commitmentFromJson(c: Map<String, Any?>): Commitment {
    val explanation = (c["explanation"] as List<Map<String, Any?>>?)?.map { e ->
        ExplanationEntry(
            kind = e["kind"] as String,
            participant = e["participant"] as String,
            proposalId = e["proposal_id"] as String,
            value = e["value"] as String,
            reason = e["reason"] as String,
            confidence = (e["confidence"] as Number?)?.toDouble(),
            rationaleRef = e["rationale_ref"] as String?,
        )
    }
    val published = when (val d = c["explanation_digest"]) {
        null -> null
        is String -> ByteArray(d.length / 2) { d.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        else -> (d as List<Number>).map { it.toInt().toByte() }.toByteArray()
    }
    return Commitment(
        id = c["id"] as String,
        action = c["action"] as String,
        authority = c["authority"] as String,
        supersedes = c["supersedes"] as String?,
        authMethod = c["auth_method"] as String,
        trustBasis = c["trust_basis"] as String,
        committer = (c["committer"] as String?) ?: "",
        explanation = explanation,
        explanationDigest = published,
    )
}

/** `seam-commitment-digest:v2` + `seam-explanation-digest:v1` against conformance/commitment_digest_v2_vector.json. */
class CommitmentDigestV2Test {
    private val vector: Map<String, Any?> =
        Gson().fromJson(
            File("../conformance/commitment_digest_v2_vector.json").readText(),
            object : TypeToken<Map<String, Any?>>() {}.type,
        )

    @Suppress("UNCHECKED_CAST")
    private val cases = vector["cases"] as List<Map<String, Any?>>

    @Suppress("UNCHECKED_CAST")
    private fun case(name: String) = cases.single { it["name"] == name }

    @Suppress("UNCHECKED_CAST")
    private fun commitmentOf(c: Map<String, Any?>) = commitmentFromJson(c["commitment"] as Map<String, Any?>)

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private val issuer get() = vector["issuer_aid"] as String

    @Suppress("UNCHECKED_CAST")
    private fun signedArtifact(c: Map<String, Any?>): String =
        String(
            ((c["commitment"] as Map<String, Any?>)["signed_artifact"] as List<Number>).map { it.toInt().toByte() }.toByteArray(),
            Charsets.US_ASCII,
        )

    private fun entry(confidence: Double? = null, kind: String = "evaluation") =
        ExplanationEntry(kind, "p", "p1", "v", "r", confidence, null)

    @Test
    fun domainsMatch() {
        assertEquals("seam-commitment-digest:v2", vector["commitment_digest_domain"])
        assertEquals("seam-explanation-digest:v1", vector["explanation_digest_domain"])
    }

    @Test
    fun reproducesEveryDigest() {
        assertFalse(cases.isEmpty(), "vector is empty; every assertion below would pass vacuously")
        for (c in cases) {
            val cm = commitmentOf(c)
            val name = c["name"]
            assertEquals(c["explanation_digest"], hex(SeamCrypto.explanationDigest(cm.explanation!!)), "$name explanation_digest")
            // Entries + published digest (agreeing), entries only, and published only all give the same digest.
            assertEquals(c["commitment_digest"], SeamCrypto.seamCommitmentDigest(cm), "$name commitment_digest")
            assertEquals(c["commitment_digest"], SeamCrypto.seamCommitmentDigest(cm.copy(explanationDigest = null)), "$name entries only")
            assertEquals(c["commitment_digest"], SeamCrypto.seamCommitmentDigest(cm.copy(explanation = null)), "$name published only")
        }
    }

    @Test
    fun emptyExplanationDigestIsPinned() {
        assertEquals(
            "eb7853dc086ef5385db8408cf35c9c984e845ccc03d269102f942eed7806ce40",
            hex(SeamCrypto.explanationDigest(emptyList())),
        )
        // Neither entries nor a published digest: field 8 is the empty explanation's digest.
        val bare = Commitment("", "", "", null, "", "")
        assertEquals("78edca52ba1e88f13a78e5569742bfce0b51474ca840bf38a8dde414d5515784", SeamCrypto.seamCommitmentDigest(bare))
    }

    @Test
    fun populatedSignedVerifies() {
        val c = case("populated_signed")
        val cm = commitmentOf(c)
        val jws = signedArtifact(c)
        assertTrue(SeamCrypto.verifyTct(issuer, jws, cm, NOW_S), "populated_signed must verify")
        assertTrue(SeamCrypto.verifyTct(issuer, jws, cm.copy(explanation = null), NOW_S), "published digest alone must verify")
        assertFalse(SeamCrypto.verifyTct(issuer, jws, cm.copy(committer = ""), NOW_S), "committer must be bound")
        assertFalse(
            SeamCrypto.verifyTct(issuer, jws, cm.copy(action = "approuvé — limit raised"), NOW_S),
            "a normalizing (NFC) port must not verify",
        )
    }

    @Test
    fun absentConfidenceDiffersFromStatedZero() {
        assertNotEquals(
            hex(SeamCrypto.explanationDigest(listOf(entry(null)))),
            hex(SeamCrypto.explanationDigest(listOf(entry(0.0)))),
        )
    }

    @Test
    fun nonCanonicalConfidenceAndUnknownKindRefused() {
        for (bad in listOf(-0.0, Double.NaN, 1.5, -0.1, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY)) {
            assertThrows(IllegalArgumentException::class.java, { SeamCrypto.explanationDigest(listOf(entry(bad))) }, "confidence $bad")
        }
        for (k in listOf("EVALUATION", "EXPLANATION_KIND_VOTE", "veto", "")) {
            assertThrows(IllegalArgumentException::class.java, { SeamCrypto.explanationDigest(listOf(entry(kind = k))) }, "kind $k")
        }
        // Boundaries are canonical.
        SeamCrypto.explanationDigest(listOf(entry(0.0), entry(1.0), entry(kind = "ballot"), entry(kind = "objection"), entry(kind = "vote")))
    }

    @Test
    fun verifyFailsClosedOnMalformedExplanation() {
        val c = case("populated_signed")
        val cm = commitmentOf(c)
        val jws = signedArtifact(c)
        val first = cm.explanation!![0]
        val variants = listOf(
            "entries disagree with published digest" to
                cm.copy(explanation = cm.explanation!!.drop(1)),
            "published digest disagrees with entries" to
                cm.copy(explanationDigest = ByteArray(32)),
            "-0.0 confidence" to cm.copy(explanation = listOf(first.copy(confidence = -0.0)) + cm.explanation!!.drop(1)),
            "NaN confidence" to cm.copy(explanation = listOf(first.copy(confidence = Double.NaN)) + cm.explanation!!.drop(1)),
            "1.5 confidence" to cm.copy(explanation = listOf(first.copy(confidence = 1.5)) + cm.explanation!!.drop(1)),
            "unknown kind" to cm.copy(explanation = listOf(first.copy(kind = "veto")) + cm.explanation!!.drop(1)),
        )
        for ((why, v) in variants) {
            assertFalse(SeamCrypto.verifyTct(issuer, jws, v, NOW_S), why)
        }
        // Same disagreement with no published digest is a mere digest mismatch: still false, never a throw.
        assertFalse(SeamCrypto.verifyTct(issuer, jws, cm.copy(explanationDigest = null, explanation = cm.explanation!!.drop(1)), NOW_S))
    }

    private companion object {
        const val NOW_S = 1_760_000_001L
    }
}
