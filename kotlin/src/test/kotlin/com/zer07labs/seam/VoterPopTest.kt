package com.zer07labs.seam

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.File
import java.util.Base64
import java.util.HexFormat
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * `seam-voter-pop-v1` (seam-sdk#359): every case of `conformance/voter_pop_v1_payload_vector.json` byte
 * for byte — the same bytes the independent Python generator, the Python SDK and the TypeScript SDK
 * assert — plus the sealed-record re-check against the `vectors.json` TCT's vote.
 */
@Suppress("UNCHECKED_CAST")
class VoterPopTest {
    private val hex = HexFormat.of()
    private val mapType = object : TypeToken<Map<String, Any?>>() {}.type
    private val vector: Map<String, Any?> =
        Gson().fromJson(File("../conformance/voter_pop_v1_payload_vector.json").readText(), mapType)
    private val cases = vector["cases"] as List<Map<String, Any?>>

    private fun byName(n: String) = cases.first { it["name"] == n }

    private fun m(p: Map<String, Any?>, k: String) = p[k] as Map<String, Any?>

    private fun u(o: Any?): ULong = (o as Number).toLong().toULong()

    private fun target(c: Map<String, Any?>): VoterPopTarget {
        val t = m(c, "target")
        return VoterPopTarget(
            issuer = t["issuer"] as String,
            tenant = t["tenant"] as String,
            namespace = t["namespace"] as String,
            sessionId = t["session_id"] as String,
            openedAtMillis = u(t["opened_at_millis"]),
            audience = t["audience"] as String,
        )
    }

    private fun contentDigest(c: Map<String, Any?>): ByteArray {
        val k = m(c, "content")
        val policy = k["policy"] as Map<String, Any?>?
        return SeamCrypto.voteContentDigest(
            mode = k["mode"] as String,
            proposalId = k["proposal_id"] as String,
            content = k["content"] as String,
            participants = k["participants"] as List<String>,
            onBehalfOf = k["on_behalf_of"] as List<String>,
            context = (k["context"] as List<Map<String, Any?>>).map {
                VoteContext(it["ctx_ref"] as String, it["content_hash"] as String)
            },
            features = (k["features"] as List<List<String>>).map { it[0] to it[1] },
            policy = policy?.let {
                VotePolicyRef(it["policy_version"] as String, hex.parseHex(it["rules_digest_hex"] as String))
            },
        )
    }

    private fun entry(c: Map<String, Any?>): VoteEntry {
        val e = m(c, "entry")
        return VoteEntry(
            kind = e["kind"] as String,
            participant = e["participant"] as String,
            proposalId = e["proposal_id"] as String,
            value = e["value"] as String,
            reason = e["reason"] as String,
            confidence = (e["confidence"] as Number?)?.toDouble(),
            rationaleRef = e["rationale_ref"] as String?,
        )
    }

    private fun seed(c: Map<String, Any?>) = hex.parseHex(c["seed_hex"] as String)

    @Test
    fun theVectorIsPopulatedAndTheDomainsMatch() {
        assertEquals(SeamCrypto.VOTER_POP_V1_DOMAIN, vector["domain"])
        assertEquals(SeamCrypto.VOTE_CONTENT_V1_DOMAIN, vector["content_domain"])
        assertTrue(cases.size >= 10)
    }

    @Test
    fun everyByteMatchesTheVector() {
        for (c in cases) {
            val n = c["name"] as String
            val digest = contentDigest(c)
            assertEquals(c["content_digest_hex"], hex.formatHex(digest), "$n: content digest")
            val eb = SeamCrypto.voteEntryBytes(entry(c))
            assertEquals(c["entry_bytes_hex"], hex.formatHex(eb), "$n: entry bytes")
            val issued = u(c["issued_at_ms"])
            val expires = u(c["expires_at_ms"])
            val payload = SeamCrypto.voterPopPayload(target(c), c["voter_aid"] as String, digest, issued, expires, eb)
            assertEquals(c["payload_hex"], hex.formatHex(payload), "$n: payload")
            // The cross-port gate: the bytes signed here equal the independent Python generator's.
            val p = SeamCrypto.signVoterPop(seed(c), target(c), digest, entry(c), issued, expires)
            assertEquals(c["voter_aid"], p.voterAid, "$n: voter AID")
            assertEquals(c["signature_hex"], hex.formatHex(p.signature), "$n: signature")
            assertEquals(issued, p.issuedAtMs)
            assertEquals(expires, p.expiresAtMs)
            assertTrue(SeamCrypto.verifyVoterPop(target(c), p.voterAid, digest, issued, expires, entry(c), p.signature), n)
            assertTrue(
                SeamCrypto.verifyVoterPop(
                    target(c), p.voterAid, digest, issued, expires, eb, hex.parseHex(c["signature_hex"] as String),
                ),
                "$n: the vector's signature verifies",
            )
        }
    }

    @Test
    fun theCrossPortBasicSignatureIsThePythonGeneratorsBytes() {
        val c = byName("basic")
        val p = SeamCrypto.signVoterPop(
            seed(c),
            target(c),
            hex.parseHex(c["content_digest_hex"] as String),
            hex.parseHex(c["entry_bytes_hex"] as String),
            u(c["issued_at_ms"]),
            u(c["expires_at_ms"]),
        )
        assertArrayEquals(hex.parseHex(c["signature_hex"] as String), p.signature)
    }

    @Test
    fun theOtherCasesDifferFromBasic() {
        val basic = byName("basic")
        for (c in cases.filter { (it["name"] as String).startsWith("other-") }) {
            assertNotEquals(basic["payload_hex"], c["payload_hex"], c["name"] as String)
            assertNotEquals(basic["signature_hex"], c["signature_hex"], c["name"] as String)
        }
        assertEquals(byName("features-order-a")["signature_hex"], byName("features-order-b")["signature_hex"])
    }

    @Test
    fun aSignatureDoesNotVerifyForAnotherTarget() {
        val c = byName("basic")
        val t = target(c)
        val sig = hex.parseHex(c["signature_hex"] as String)
        val digest = hex.parseHex(c["content_digest_hex"] as String)
        val i = u(c["issued_at_ms"])
        val x = u(c["expires_at_ms"])
        val aid = c["voter_aid"] as String
        assertTrue(SeamCrypto.verifyVoterPop(t, aid, digest, i, x, entry(c), sig))
        assertFalse(SeamCrypto.verifyVoterPop(t.copy(sessionId = "s-other"), aid, digest, i, x, entry(c), sig))
        assertFalse(SeamCrypto.verifyVoterPop(t, aid, digest, i, x + 1uL, entry(c), sig))
        assertFalse(SeamCrypto.verifyVoterPop(t, "not-an-aid", digest, i, x, entry(c), sig))
        assertFalse(SeamCrypto.verifyVoterPop(t, aid, ByteArray(31), i, x, entry(c), sig))
        assertFalse(SeamCrypto.verifyVoterPop(t, aid, digest, i, x, entry(c), ByteArray(63)))
    }

    @Test
    fun negativeZeroConfidenceFoldsToPositiveZero() {
        val neg = SeamCrypto.voteEntryBytes(VoteEntry("vote", "risk", "p", "v", "", -0.0))
        val pos = SeamCrypto.voteEntryBytes(VoteEntry("vote", "risk", "p", "v", "", 0.0))
        assertArrayEquals(pos, neg)
        assertThrows(IllegalArgumentException::class.java) {
            SeamCrypto.voteEntryBytes(VoteEntry("vote", "risk", "p", "v", "", Double.NaN))
        }
        assertThrows(IllegalArgumentException::class.java) {
            SeamCrypto.voteEntryBytes(VoteEntry("Vote", "risk", "p", "v"))
        }
    }

    @Test
    fun aWindowTheRuntimeMustRefuseIsNeverSigned() {
        val c = byName("basic")
        val digest = hex.parseHex(c["content_digest_hex"] as String)
        val max = SeamCrypto.VOTER_POP_MAX_LIFETIME_MS.toULong()
        for ((i, x) in listOf(1_000uL to 999uL, 0uL to max + 1uL, ULong.MAX_VALUE to 0uL)) {
            assertThrows(IllegalArgumentException::class.java, { SeamCrypto.signVoterPop(seed(c), target(c), digest, entry(c), i, x) }, "$i..$x")
        }
        SeamCrypto.signVoterPop(seed(c), target(c), digest, entry(c), 0uL, max)
        assertThrows(IllegalArgumentException::class.java) {
            SeamCrypto.signVoterPop(ByteArray(31), target(c), digest, entry(c), 0uL, 1uL)
        }
    }

    @Test
    fun theDefaultWindowIsNowPlusFiveMinutes() {
        val c = byName("basic")
        val before = System.currentTimeMillis().toULong()
        val p = SeamCrypto.signVoterPop(seed(c), target(c), hex.parseHex(c["content_digest_hex"] as String), entry(c))
        val after = System.currentTimeMillis().toULong()
        assertTrue(p.issuedAtMs in before..after)
        assertEquals(SeamCrypto.VOTER_POP_DEFAULT_LIFETIME_MS.toULong(), p.expiresAtMs - p.issuedAtMs)
    }

    @Test
    fun theRestFormIsUnpaddedBase64urlWithANumericWindow() {
        val c = byName("basic")
        val sig = hex.parseHex(c["signature_hex"] as String)
        val p = VoterPopProof(c["voter_aid"] as String, u(c["issued_at_ms"]), u(c["expires_at_ms"]), sig)
        val pop = SeamCrypto.voterPopToRest(p)["pop"] as Map<String, Any>
        assertEquals(listOf("voter_aid", "issued_at_ms", "expires_at_ms", "signature"), pop.keys.toList())
        assertEquals(c["voter_aid"], pop["voter_aid"])
        assertEquals((c["issued_at_ms"] as Number).toLong(), pop["issued_at_ms"])
        assertEquals((c["expires_at_ms"] as Number).toLong(), pop["expires_at_ms"])
        assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(sig), pop["signature"])
        assertThrows(IllegalArgumentException::class.java) { VoterPopProof("a", 1uL shl 53, 1uL shl 53, sig).toRest() }
        // The proof defends its signature bytes.
        p.signature[0] = (p.signature[0].toInt() xor 1).toByte()
        assertArrayEquals(sig, p.signature)
    }

    @Test
    fun featuresFrameSortedARepeatedKeyIsRefusedAndThePolicySlotNeeds32Bytes() {
        assertEquals(byName("features-order-a")["content_digest_hex"], hex.formatHex(contentDigest(byName("features-order-b"))))
        assertThrows(IllegalArgumentException::class.java) {
            SeamCrypto.voteContentDigest("m", "p", "c", features = listOf("k" to "1", "k" to "2"))
        }
        assertThrows(IllegalArgumentException::class.java) {
            SeamCrypto.voteContentDigest("m", "p", "c", policy = VotePolicyRef("pol", ByteArray(31)))
        }
        // Unsigned byte order: "é" (0xC3…) sorts after "z".
        assertArrayEquals(
            SeamCrypto.voteContentDigest("m", "p", "c", features = listOf("é" to "1", "z" to "2")),
            SeamCrypto.voteContentDigest("m", "p", "c", features = listOf("z" to "2", "é" to "1")),
        )
    }

    // ── the sealed record re-check (verifyVoterRecord / verifyCommitmentVoters) ────────────────────

    private val tct: Map<String, Any?> =
        (Gson().fromJson<Map<String, Any?>>(File("../conformance/vectors.json").readText(), mapType))["tct"] as Map<String, Any?>
    private val issuer = tct["issuer_aid"] as String
    private val entries: List<ExplanationEntry> = commitmentFromJson(m(m(tct, "inputs"), "commitment")).explanation!!
    private val vote = entries.first { it.kind == "vote" }

    private fun swapVote(e: ExplanationEntry) = entries.map { if (it === vote) e else it }

    @Test
    fun theConformanceVotesSealedRecordReVerifiesAndTheCommitmentCheckPasses() {
        val vv = vote.voterVerification!!
        assertTrue(SeamCrypto.verifyVoterRecord(vote))
        assertTrue(SeamCrypto.verifyCommitmentVoters(entries, issuer))
        assertTrue(SeamCrypto.verifyCommitmentVoters(entries, issuer, VoterDecisionRef(vv.tenant, vv.sessionId)))
    }

    @Test
    fun theCommitmentLevelVoterCheckFailsClosed() {
        val vv = vote.voterVerification!!
        assertTrue(entries.any { it.kind == "evaluation" }, "the vector must carry an evaluation")
        val cases: List<Triple<String, List<ExplanationEntry>, Pair<String, VoterDecisionRef?>>> = listOf(
            Triple("another pinned issuer", entries, ("aid:pubkey:ed25519:" + "A".repeat(43)) to null),
            Triple("another decision's session", entries, issuer to VoterDecisionRef(vv.tenant, "s-other")),
            Triple("a vote without its record", swapVote(vote.copy(voterVerification = null)), issuer to null),
            Triple("a tampered reason", swapVote(vote.copy(reason = vote.reason + "!")), issuer to null),
            Triple(
                "an evaluation with a record",
                entries.map { if (it.kind == "evaluation") it.copy(voterVerification = vv) else it },
                issuer to null,
            ),
            Triple(
                "a record outside its window",
                swapVote(vote.copy(voterVerification = vv.copy(acceptedAtMs = vv.expiresAtMs + 1uL))),
                issuer to null,
            ),
            Triple("a non-pop method", swapVote(vote.copy(voterVerification = vv.copy(method = "cp_signed"))), issuer to null),
        )
        for ((name, es, pinned) in cases) {
            assertFalse(SeamCrypto.verifyCommitmentVoters(es, pinned.first, pinned.second), name)
        }
    }
}
