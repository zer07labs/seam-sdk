package com.zer07labs.seam

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.File
import java.util.Base64
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
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
/** Bytes from a vector: a `<name>_hex` string, or `<name>` as a hex string or a list of byte values. */
@Suppress("UNCHECKED_CAST")
internal fun vectorBytes(m: Map<String, Any?>, name: String): ByteArray? {
    fun unhex(d: String) = ByteArray(d.length / 2) { d.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    (m[name + "_hex"] as String?)?.let { return unhex(it) }
    return when (val d = m[name]) {
        null -> null
        is String -> unhex(d)
        else -> (d as List<Number>).map { it.toInt().toByte() }.toByteArray()
    }
}

/** A sealed voter verification record from a vector's JSON projection (`null` when absent). */
internal fun voterVerificationFromJson(v: Map<String, Any?>?): VoterVerification? {
    if (v == null) return null
    fun u(k: String) = (v[k] as Number).toLong().toULong()
    return VoterVerification(
        method = v["method"] as String,
        principal = v["principal"] as String,
        contentDigest = vectorBytes(v, "content_digest")!!,
        issuedAtMs = u("issued_at_ms"),
        expiresAtMs = u("expires_at_ms"),
        signature = vectorBytes(v, "signature")!!,
        signerCertificate = vectorBytes(v, "signer_certificate") ?: ByteArray(0),
        tenant = v["tenant"] as String,
        namespace = v["namespace"] as String,
        sessionId = v["session_id"] as String,
        openedAtMillis = u("opened_at_millis"),
        issuer = v["issuer"] as String,
        audience = v["audience"] as String,
        acceptedAtMs = u("accepted_at_ms"),
    )
}

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
            voterVerification = voterVerificationFromJson(e["voter_verification"] as Map<String, Any?>?),
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

/**
 * `seam-commitment-digest:v4` + `seam-explanation-digest:v2` against
 * conformance/commitment_digest_v4_vector.json, plus the self-attestation TCT shape `verifyTct`
 * accepts — and nothing beside it.
 */
class CommitmentDigestV4Test {
    private val vector: Map<String, Any?> =
        Gson().fromJson(
            File("../conformance/commitment_digest_v4_vector.json").readText(),
            object : TypeToken<Map<String, Any?>>() {}.type,
        )

    @Suppress("UNCHECKED_CAST")
    private val cases = vector["cases"] as List<Map<String, Any?>>

    @Suppress("UNCHECKED_CAST")
    private fun case(name: String) = cases.single { it["name"] == name }

    @Suppress("UNCHECKED_CAST")
    private fun commitmentOf(c: Map<String, Any?>) =
        commitmentFromJson(c["commitment"] as Map<String, Any?>).copy(
            selectionDigest = vectorBytes(c, "selection_digest"),
            certificateDigest = vectorBytes(c, "certificate_digest"),
        )

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
        assertEquals(SeamCrypto.COMMITMENT_DIGEST_DOMAIN, vector["commitment_digest_domain"])
        assertEquals(SeamCrypto.EXPLANATION_DIGEST_DOMAIN, vector["explanation_digest_domain"])
        assertEquals("seam-commitment-digest:v4", SeamCrypto.COMMITMENT_DIGEST_DOMAIN)
        assertEquals("seam-explanation-digest:v2", SeamCrypto.EXPLANATION_DIGEST_DOMAIN)
    }

    @Test
    fun reproducesEveryDigest() {
        assertEquals(listOf(
                "all_empty", "empty_supersedes", "populated_signed",
                "selection_present", "certificate_present", "both_present",
            ), cases.map { it["name"] })
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
            "cabe83af912ea38ef4525f5a7d8580b4c4e217417edc0c93f936d2c18c4fd8f5",
            hex(SeamCrypto.explanationDigest(emptyList())),
        )
        // Neither entries nor a published digest: field 8 is the empty explanation's digest.
        val bare = Commitment("", "", "", null, "", "")
        assertEquals("6e3a11bbef5f552f78e6d9114c13b7e48bb0a30de82d38a603981d6d1ca7281a", SeamCrypto.seamCommitmentDigest(bare))
    }

    /** The supersedes presence byte: absent supersedes and present-empty supersedes are different digests. */
    @Test
    fun emptyAndAbsentSupersedesDiffer() {
        val absent = commitmentOf(case("all_empty"))
        val empty = commitmentOf(case("empty_supersedes"))
        assertEquals(null, absent.supersedes)
        assertEquals("", empty.supersedes)
        assertNotEquals(SeamCrypto.seamCommitmentDigest(absent), SeamCrypto.seamCommitmentDigest(empty))
        assertEquals(
            "a495c011cd353de108bb7c0e2a3bcb90051d59b135696a10848c3a087e5fed50",
            SeamCrypto.seamCommitmentDigest(empty),
        )
    }

    /** Fields 9/10: each slot is bound, the two are not interchangeable, and a bad length is refused. */
    @Test
    fun selectionAndCertificateSlots() {
        val none = commitmentOf(case("all_empty"))
        val sel = commitmentOf(case("selection_present"))
        val cert = commitmentOf(case("certificate_present"))
        val both = commitmentOf(case("both_present"))
        assertEquals(null, none.selectionDigest)
        assertEquals(4, listOf(none, sel, cert, both).map { SeamCrypto.seamCommitmentDigest(it) }.toSet().size)
        assertNotEquals(
            SeamCrypto.seamCommitmentDigest(sel),
            SeamCrypto.seamCommitmentDigest(sel.copy(selectionDigest = null, certificateDigest = sel.selectionDigest)),
        )
        for (len in listOf(0, 31, 33)) {
            assertThrows(IllegalArgumentException::class.java, { SeamCrypto.seamCommitmentDigest(none.copy(selectionDigest = ByteArray(len))) }, "selection $len")
            assertThrows(IllegalArgumentException::class.java, { SeamCrypto.seamCommitmentDigest(none.copy(certificateDigest = ByteArray(len))) }, "certificate $len")
        }
    }

    /** A voter record with an unknown method, or a content digest that is not 32 bytes, is refused. */
    @Test
    fun malformedVoterRecordRefused() {
        val e = commitmentOf(case("populated_signed")).explanation!![3]
        val v = e.voterVerification!!
        assertEquals("pop", v.method)
        for (m in listOf("POP", "VOTER_VERIFICATION_POP", "unspecified", "")) {
            assertThrows(IllegalArgumentException::class.java, {
                SeamCrypto.explanationDigest(listOf(e.copy(voterVerification = v.copy(method = m))))
            }, "method $m")
        }
        for (len in listOf(0, 31, 33)) {
            assertThrows(IllegalArgumentException::class.java, {
                SeamCrypto.explanationDigest(listOf(e.copy(voterVerification = v.copy(contentDigest = ByteArray(len)))))
            }, "content digest $len")
        }
        // cp_signed is a known word (declared, not served): it frames, and differs from pop.
        assertNotEquals(
            hex(SeamCrypto.explanationDigest(listOf(e))),
            hex(SeamCrypto.explanationDigest(listOf(e.copy(voterVerification = v.copy(method = "cp_signed"))))),
        )
        // The record is bound: stripping it or moving accepted_at_ms changes the digest.
        assertNotEquals(hex(SeamCrypto.explanationDigest(listOf(e))), hex(SeamCrypto.explanationDigest(listOf(e.copy(voterVerification = null)))))
        assertNotEquals(
            hex(SeamCrypto.explanationDigest(listOf(e))),
            hex(SeamCrypto.explanationDigest(listOf(e.copy(voterVerification = v.copy(acceptedAtMs = v.acceptedAtMs + 1uL))))),
        )
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
        const val TCT_NOW_S = 1_700_000_001L
    }

    // -- The self-attestation shape ---------------------------------------------------------
    //
    // Tokens re-signed locally with the `tct` block's issuer seed, so a refusal below can only be
    // about the claim it changes: the well-formed control verifies with the same key and commitment.

    @Suppress("UNCHECKED_CAST")
    private val tct: Map<String, Any?> =
        (
            Gson().fromJson<Map<String, Any?>>(
                File("../conformance/vectors.json").readText(),
                object : TypeToken<Map<String, Any?>>() {}.type,
            )["tct"] as Map<String, Any?>
        )

    @Suppress("UNCHECKED_CAST")
    private val tctInputs get() = tct["inputs"] as Map<String, Any?>

    @Suppress("UNCHECKED_CAST")
    private val tctCommitment get() = commitmentFromJson(tctInputs["commitment"] as Map<String, Any?>)

    private val tctIssuer get() = tct["issuer_aid"] as String

    private fun b64(b: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    private fun sign(payloadJson: String): String {
        val seedHex = tctInputs["issuer_seed_hex"] as String
        val seed = ByteArray(seedHex.length / 2) { seedHex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        val input = b64("""{"alg":"EdDSA","typ":"aitp-tct+jwt"}""".toByteArray()) + "." + b64(payloadJson.toByteArray())
        val msg = input.toByteArray(Charsets.US_ASCII)
        val s = Ed25519Signer()
        s.init(true, Ed25519PrivateKeyParameters(seed, 0))
        s.update(msg, 0, msg.size)
        return input + "." + b64(s.generateSignature())
    }

    private fun statement(digest: String) =
        mutableMapOf<String, Any?>("type" to SeamCrypto.COMMITMENT_STATEMENT, "commitment_digest" to digest)

    private fun payload(digest: String) = mutableMapOf<String, Any?>(
        "iss" to tctIssuer,
        "sub" to tctIssuer,
        "aud" to tctIssuer,
        "exp" to 4_853_600_000L,
        "grants" to listOf(SeamCrypto.ATTESTATION_GRANT),
        "ext" to mapOf(SeamCrypto.COMMITMENT_EXT_NAMESPACE to statement(digest)),
    )

    @Test
    fun wellFormedSelfAttestationVerifies() {
        val c = tctCommitment
        val p = payload(SeamCrypto.seamCommitmentDigest(c))
        assertTrue(SeamCrypto.verifyTct(tctIssuer, sign(Gson().toJson(p)), c, TCT_NOW_S))
    }

    @Test
    fun attestationShapeRefusals() {
        val c = tctCommitment
        val digest = SeamCrypto.seamCommitmentDigest(c)
        val other = "aid:pubkey:ed25519:" + "B".repeat(43)
        val ns = SeamCrypto.COMMITMENT_EXT_NAMESPACE
        val mutations: List<Pair<String, (MutableMap<String, Any?>) -> Unit>> = listOf(
            "statement in grants (v2 shape)" to { p ->
                p.remove("ext")
                p["grants"] = listOf("seam:commitment", "seam-commitment-digest:$digest")
            },
            "extra grant" to { p -> p["grants"] = listOf(SeamCrypto.ATTESTATION_GRANT, "seam-commitment-digest:$digest") },
            "no grants" to { p -> p.remove("grants") },
            "iss != aud" to { p -> p["aud"] = other },
            "sub != iss" to { p -> p["sub"] = other },
            "ext absent" to { p -> p.remove("ext") },
            "extra ext key" to { p -> p["ext"] = mapOf(ns to statement(digest), "com.example" to emptyMap<String, Any>()) },
            "wrong type" to { p -> p["ext"] = mapOf(ns to statement(digest).also { it["type"] = "seam:other" }) },
            "extra statement field" to { p -> p["ext"] = mapOf(ns to statement(digest).also { it["x"] = "y" }) },
            "uppercase digest" to { p -> p["ext"] = mapOf(ns to statement(digest.uppercase())) },
            "wrong digest" to { p -> p["ext"] = mapOf(ns to statement("0".repeat(64))) },
        )
        for ((why, mutate) in mutations) {
            val p = payload(digest)
            mutate(p)
            assertFalse(SeamCrypto.verifyTct(tctIssuer, sign(Gson().toJson(p)), c, TCT_NOW_S), "$why must be refused")
        }
    }

    /**
     * A payload whose JSON repeats a key is refused: Gson keeps one of the two, and a different
     * parser might keep the other, so the same signed bytes would mean two things.
     */
    @Test
    fun duplicateKeyIsRefused() {
        val c = tctCommitment
        val digest = SeamCrypto.seamCommitmentDigest(c)
        val iss = tctIssuer
        val head = """{"iss":"$iss","sub":"$iss","aud":"$iss","exp":4853600000,"grants":["aitp.attestation"],"""
        val good = """"ext":{"com.zer07labs.seam":{"type":"seam:commitment","commitment_digest":"$digest"}}}"""
        assertTrue(SeamCrypto.verifyTct(iss, sign(head + good), c, TCT_NOW_S), "the hand-written control payload must verify")
        val zeros = "0".repeat(64)
        val decoy = """{"type":"seam:commitment","commitment_digest":"$zeros"}"""
        val bodies = mapOf(
            "duplicate namespace key" to
                """"ext":{"com.zer07labs.seam":$decoy,"com.zer07labs.seam":{"type":"seam:commitment","commitment_digest":"$digest"}}}""",
            "duplicate statement key" to
                """"ext":{"com.zer07labs.seam":{"type":"seam:commitment","commitment_digest":"$zeros","commitment_digest":"$digest"}}}""",
            "duplicate ext" to """"ext":{"com.zer07labs.seam":$decoy},$good""",
        )
        for ((why, body) in bodies) {
            assertFalse(SeamCrypto.verifyTct(iss, sign(head + body), c, TCT_NOW_S), "$why must be refused")
        }
    }
}
