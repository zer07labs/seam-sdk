package com.zer07labs.seam

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.File
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/**
 * Option selection (runtime 0.90.0, seam-runtime `docs/specs/selection-rule.v1.md`) against the
 * runtime's vendored fixture `conformance/selection_rule_v1_vectors.json`: the selection block codec,
 * the v5 field 9 it frames, and the `proposal` explanation word. This port frames the digest only; the
 * winner recompute (`rule_cases`, `sealed_cases`) is the Rust verifier's and the Python SDK's.
 */
class SelectionV1Test {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private fun unhex(d: String) = ByteArray(d.length / 2) { d.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private val vector: Map<String, Any?> = Gson().fromJson(
        File("../conformance/selection_rule_v1_vectors.json").readText(),
        object : TypeToken<Map<String, Any?>>() {}.type,
    )

    @Suppress("UNCHECKED_CAST")
    private fun block(b: Map<String, Any?>): SelectionBlock {
        fun u(k: String) = (b[k] as Number).toLong().toUInt()
        return SelectionBlock(
            rule = b["rule"] as String,
            ruleVersion = u("rule_version"),
            defaultWeight = u("default_weight"),
            weights = (b["weights"] as List<Map<String, Any?>>).map {
                SelectionWeight(it["participant"] as String, (it["weight"] as Number).toLong().toUInt())
            },
            tie = b["tie"] as String,
            abstention = b["abstention"] as String,
            minBallots = u("min_ballots"),
            policyVersion = b["policy_version"] as String,
            rulesDigest = unhex(b["rules_digest"] as String),
            participants = b["participants"] as List<String>,
            onBehalfOf = b["on_behalf_of"] as List<String>,
            context = (b["context"] as List<Map<String, Any?>>).map {
                SelectionContext(it["ctx_ref"] as String, it["content_hash"] as String)
            },
            winnerProposalId = b["winner_proposal_id"] as String,
        )
    }

    @Suppress("UNCHECKED_CAST")
    private val codec get() = vector["codec"] as Map<String, Any?>

    @Suppress("UNCHECKED_CAST")
    private val codecBlock get() = block(codec["block"] as Map<String, Any?>)

    @Test
    fun `the codec block encodes to the vector body, digest and field 9`() {
        val body = SeamCrypto.selectionBody(codecBlock)
        assertEquals(codec["body"], hex(body))
        assertEquals(422, body.size)
        val d = SeamCrypto.selectionDigest(body)
        assertEquals(codec["selection_digest"], hex(d))
        assertEquals(codec["field_9"], "01" + "0000000000000020" + hex(d))
    }

    @Test
    @Suppress("UNCHECKED_CAST")
    fun `the proposal word frames the verified case's explanation digest`() {
        val verified = (vector["sealed_cases"] as List<Map<String, Any?>>).first { it["name"] == "verified" }
        val c = commitmentFromJson(
            mapOf(
                "id" to "", "action" to "", "authority" to "", "supersedes" to null,
                "auth_method" to "", "trust_basis" to "", "explanation" to verified["entries"],
            ),
        )
        assertEquals(
            "40a4e742ffce841dcb2deb0ee6912c590a7268068117dd593bbd11bb4f76e34c",
            hex(SeamCrypto.explanationDigest(c.explanation!!)),
        )
    }

    @Test
    @Suppress("UNCHECKED_CAST")
    fun `every commitment_digest_v5 case with field 9 from the block`() {
        val fromBlock = SeamCrypto.selectionDigest(SeamCrypto.selectionBody(codecBlock))
        val cases = (vector["commitment_digest_v5"] as Map<String, Any?>)["cases"] as List<Map<String, Any?>>
        assertEquals(3, cases.size)
        for (k in cases) {
            val cm = (k["commitment"] as Map<String, Any?>) + ("explanation_digest" to k["explanation_digest"])
            val sel = vectorBytes(k, "selection_digest")
            if (sel != null) assertEquals(hex(sel), hex(fromBlock))
            val c = commitmentFromJson(cm).copy(
                selectionDigest = if (sel == null) null else fromBlock,
                certificateDigest = vectorBytes(k, "certificate_digest"),
                governingDocSha256 = vectorBytes(k, "governing_doc_sha256"),
            )
            assertEquals(k["commitment_digest"], SeamCrypto.seamCommitmentDigest(c), k["name"] as String)
        }
    }

    @Test
    fun `a block the runtime could not have sealed is refused`() {
        val b = codecBlock
        listOf(
            b.copy(weights = listOf(SelectionWeight("carol", 1u), SelectionWeight("bob", 2u))),
            b.copy(weights = listOf(SelectionWeight("bob", 1u), SelectionWeight("bob", 2u))),
            b.copy(rulesDigest = ByteArray(31)),
            b.copy(winnerProposalId = ""),
        ).forEach { x -> assertThrows(IllegalArgumentException::class.java) { SeamCrypto.selectionBody(x) } }
        // Ascending is by UTF-8 bytes: "Z" < "a" < "é".
        SeamCrypto.selectionBody(
            b.copy(weights = listOf(SelectionWeight("Z", 1u), SelectionWeight("a", 1u), SelectionWeight("é", 1u))),
        )
    }
}
