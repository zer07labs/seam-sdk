package com.zer07labs.seam

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.File
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Option selection (runtime 0.90.0, seam-runtime `docs/specs/selection-rule.v1.md`) against the
 * runtime's vendored fixture `conformance/selection_rule_v1_vectors.json`: the selection block codec,
 * the v5 field 9 it frames, the `proposal` explanation word, `decide()` over every `rule_cases` entry
 * and the verifier's selection steps (§5 steps 6-9) over every `sealed_cases` entry, by name.
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
            // rule_cases records carry no winner: decide() ignores it.
            winnerProposalId = (b["winner_proposal_id"] as String?) ?: "",
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

    /** Defaults for a partial voter record (`malformed_proposal_with_voter_record` seals only a few fields). */
    private val partialRecord: Map<String, Any?> = mapOf(
        "issued_at_ms" to 0, "expires_at_ms" to 0, "signature" to "", "signer_certificate" to "",
        "tenant" to "", "namespace" to "", "session_id" to "", "opened_at_millis" to 0,
        "issuer" to "", "audience" to "", "accepted_at_ms" to 0,
    )

    @Suppress("UNCHECKED_CAST")
    private fun entries(raw: Any?): List<ExplanationEntry> =
        commitmentFromJson(
            mapOf(
                "id" to "", "action" to "", "authority" to "", "supersedes" to null,
                "auth_method" to "", "trust_basis" to "",
                "explanation" to (raw as List<Map<String, Any?>>).map { e ->
                    val vv = e["voter_verification"] as Map<String, Any?>?
                    if (vv == null) e else e + ("voter_verification" to partialRecord + vv)
                },
            ),
        ).explanation!!

    private fun intOrNull(v: Any?): Int? = (v as Number?)?.toInt()

    @Test
    @Suppress("UNCHECKED_CAST")
    fun `every rule case through decide`() {
        val cases = vector["rule_cases"] as List<Map<String, Any?>>
        assertEquals(30, cases.size)
        for (k in cases) {
            val name = k["name"] as String
            val got = SeamCrypto.decide(block(k["record"] as Map<String, Any?>), entries(k["entries"]))
            val want = k["expect"] as Map<String, Any?>
            assertEquals(want["result"], got.result, name)
            for ((key, v) in want) {
                when (key) {
                    "result" -> Unit
                    "winner_proposal_id" -> assertEquals(v, got.winnerProposalId, name)
                    "option" -> assertEquals(v, got.option, name)
                    "reason" -> assertEquals(v, got.reason, name)
                    "at" -> assertEquals(intOrNull(v), got.at, name)
                    "ballots" -> assertEquals(intOrNull(v), got.ballots, name)
                    "scores" -> assertEquals(
                        (v as List<Map<String, Any?>>).map {
                            SelectionScore(it["proposal_id"] as String, (it["score"] as Number).toLong())
                        },
                        got.scores,
                        name,
                    )
                    else -> error("$name: unexpected expect key $key")
                }
            }
        }
    }

    @Test
    @Suppress("UNCHECKED_CAST")
    fun `every sealed case through verifySelection by name`() {
        val cases = vector["sealed_cases"] as List<Map<String, Any?>>
        assertEquals(13, cases.size)
        for (k in cases) {
            val name = k["name"] as String
            val got = SeamCrypto.verifySelection(
                block(k["block"] as Map<String, Any?>),
                entries(k["entries"]),
                k["action"] as String,
            )
            val want = k["expect"] as Map<String, Any?>
            assertEquals(want["result"], got.result, name)
            if ("at" in want) assertEquals(intOrNull(want["at"]), got.at, name)
            if ("recomputed" in want) assertEquals(want["recomputed"], got.recomputed, name)
            if (want["result"] == "verified") {
                assertTrue(got.ok, name)
                assertEquals(want["winner_proposal_id"], got.winnerProposalId, name)
                assertEquals(intOrNull(want["votes_linked"]), got.votesLinked, name)
            } else {
                assertFalse(got.ok, name)
            }
        }
    }

    // ── end to end through verifyTct ──────────────────────────────────────────────────────────────

    private val seed = ByteArray(32) { it.toByte() }

    private fun issuer(): String {
        val pub = org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
        return SeamCrypto.aidFromPubkey(pub)
    }

    /** A seal-key TCT (S-4): signed by the test seal key, which [seed] (the pinned issuer) certifies. */
    private fun tct(issuer: String, digest: String): String {
        val p = SealKeyTokens.claims(SealKeyTokens.SEAL_SEED, SealKeyTokens.IAT)
        p["exp"] = 4_000_000_000L
        p["grants"] = listOf("aitp.attestation")
        p["ext"] = linkedMapOf(
            "com.zer07labs.seam" to mapOf("type" to "seam:commitment", "commitment_digest" to digest),
            SeamCrypto.SEAL_KEY_CERT_EXT_KEY to SealKeyTokens.member(seed, issuer),
        )
        return SealKeyTokens.jws(SealKeyTokens.SEAL_SEED, com.google.gson.Gson().toJson(p))
    }

    @Suppress("UNCHECKED_CAST")
    private fun selectionCommitment(): Commitment {
        val verified = (vector["sealed_cases"] as List<Map<String, Any?>>).first { it["name"] == "verified" }
        val case = ((vector["commitment_digest_v5"] as Map<String, Any?>)["cases"] as List<Map<String, Any?>>)
            .first { it["name"] == "populated_selection_governed" }
        return commitmentFromJson(case["commitment"] as Map<String, Any?>).copy(
            explanation = entries(verified["entries"]),
            governingDocSha256 = vectorBytes(case, "governing_doc_sha256"),
            selection = block(verified["block"] as Map<String, Any?>),
        )
    }

    @Test
    @Suppress("UNCHECKED_CAST")
    fun `a selection commitment frames field 9 from its block`() {
        val case = ((vector["commitment_digest_v5"] as Map<String, Any?>)["cases"] as List<Map<String, Any?>>)
            .first { it["name"] == "populated_selection_governed" }
        val c = selectionCommitment()
        assertEquals(case["commitment_digest"], SeamCrypto.seamCommitmentDigest(c))
        assertThrows(IllegalArgumentException::class.java) {
            SeamCrypto.seamCommitmentDigest(c.copy(selectionDigest = ByteArray(32)))
        }
    }

    @Test
    fun `verifyTct recomputes the winner of a selection commitment`() {
        val iss = issuer()
        val c = selectionCommitment()
        val jws = tct(iss, SeamCrypto.seamCommitmentDigest(c))
        assertTrue(SeamCrypto.verifyTct(iss, jws, c, 0))
        // A losing action under a valid TCT fails the winner recompute, not the signature.
        val losing = c.copy(action = "rate 5%")
        assertFalse(SeamCrypto.verifyTct(iss, tct(iss, SeamCrypto.seamCommitmentDigest(losing)), losing, 0))
        // A stripped or edited block fails the TCT.
        assertFalse(SeamCrypto.verifyTct(iss, jws, c.copy(selection = null), 0))
        val blk = c.selection!!
        val edited = blk.copy(weights = listOf(SelectionWeight("bob", 3u)))
        assertFalse(SeamCrypto.verifyTct(iss, jws, c.copy(selection = edited), 0))
    }

    @Test
    fun `a selection block without entries fails closed`() {
        val iss = issuer()
        val c = selectionCommitment()
        val jws = tct(iss, SeamCrypto.seamCommitmentDigest(c))
        val noEntries = c.copy(explanation = null, explanationDigest = SeamCrypto.explanationDigest(c.explanation!!))
        // The digest still matches (the published explanation digest stands in for the entries)…
        assertEquals(SeamCrypto.seamCommitmentDigest(c), SeamCrypto.seamCommitmentDigest(noEntries))
        // …but the winner cannot be recomputed, so the TCT does not verify.
        assertFalse(SeamCrypto.verifyTct(iss, jws, noEntries, 0))
        assertNull(noEntries.explanation)
    }
}
