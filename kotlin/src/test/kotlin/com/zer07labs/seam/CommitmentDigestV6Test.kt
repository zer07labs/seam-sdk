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

@Suppress("UNCHECKED_CAST")
internal fun loadVector(file: String): Map<String, Any?> =
    Gson().fromJson(File("../conformance/$file").readText(), object : TypeToken<Map<String, Any?>>() {}.type)

@Suppress("UNCHECKED_CAST")
internal fun vectorRows(v: Map<String, Any?>, section: String): List<Map<String, Any?>> {
    val out = v[section] as List<Map<String, Any?>>?
    assertFalse(out.isNullOrEmpty(), "section $section is empty")
    return out!!
}

internal fun unhex(s: Any?): ByteArray? =
    (s as String?)?.let { d -> ByteArray(d.length / 2) { d.substring(it * 2, it * 2 + 2).toInt(16).toByte() } }

internal fun hexOf(b: ByteArray?): String? = b?.joinToString("") { "%02x".format(it.toInt() and 0xff) }

internal fun List<Map<String, Any?>>.named(name: String): Map<String, Any?> =
    firstOrNull { it["name"] == name } ?: throw AssertionError("no row $name")

/**
 * `seam-commitment-digest:v6` against the runtime's vectors (`conformance/commitment_digest_v6_vector.json`
 * and `conformance/commitment_digest_v6_signed_vector.json`): every row of every section. Refusal rows
 * assert the refusal only, never the rule name (the name is advisory, spec §Refusal rules). NO bless mode.
 */
@Suppress("UNCHECKED_CAST")
class CommitmentDigestV6Test {
    private val nowS = 1_767_225_601L
    private val v6 get() = loadVector("commitment_digest_v6_vector.json")
    private val signed get() = loadVector("commitment_digest_v6_signed_vector.json")

    private fun base(k: Map<String, Any?>) = commitmentFromJson(k["commitment"] as Map<String, Any?>)

    /** The case-level field inputs of a `digest_only` case. */
    private fun fields(k: Map<String, Any?>) = CommitmentDigestFields(
        selectionDigest = unhex(k["selection_digest"]),
        gateDigest = unhex(k["gate_digest"]),
        governingDocSha256 = unhex(k["governing_doc_sha256"]),
        env = k["env"] as String?,
    )

    @Test
    fun everyCaseReproduces() {
        val v = v6
        assertEquals(SeamCrypto.COMMITMENT_DIGEST_DOMAIN_V6, v["commitment_digest_domain"])
        assertEquals(SeamCrypto.GATE_DIGEST_DOMAIN, v["gate_digest_domain"])
        val cases = vectorRows(v, "cases")
        assertEquals(15, cases.size)
        for (k in cases) {
            val name = k["name"] as String
            val c = base(k)
            val f = if (k["digest_only"] == true) {
                // Fields 9-12 are digest-function inputs only; there are no trailers to derive them from.
                assertNull(k["trailers"], name)
                fields(k).also { f ->
                    k["v5_commitment_digest"]?.let {
                        assertEquals(it, SeamCrypto.commitmentDigest(CommitmentVersion.V5, c, f), "$name v5")
                    }
                }
            } else {
                val t = SeamCrypto.decodeCommitmentTrailers(unhex(k["trailers"])!!, CommitmentVersion.V6)
                assertEquals(k["field_10"], hexOf(t.field10), name)
                assertEquals(k["field_11"], hexOf(t.field11), name)
                assertEquals(k["field_12"], hexOf(t.field12), name)
                assertEquals(k["gate_digest"], hexOf(t.gateDigest), name)
                assertEquals(k["governing_doc_sha256"], hexOf(t.governingDocSha256), name)
                assertEquals(k["env"], t.env, name)
                CommitmentDigestFields(unhex(k["selection_digest"]), t.gateDigest, t.governingDocSha256, t.env)
            }
            assertEquals(k["commitment_digest"], SeamCrypto.commitmentDigest(CommitmentVersion.V6, c, f), name)
        }
    }

    @Test
    fun digestInputRefusals() {
        val v = v6
        val cases = vectorRows(v, "cases")
        val refusals = vectorRows(v, "digest_input_refusals")
        assertEquals(10, refusals.size)
        for (r in refusals) {
            assertEquals("v6", r["scheme"])
            val k = cases.named(r["base_case"] as String)
            val b = fields(k)
            val o = (r["override"] as Map<String, Any?>?) ?: emptyMap()
            val f = CommitmentDigestFields(
                selectionDigest = if ("selection_digest" in o) unhex(o["selection_digest"]) else b.selectionDigest,
                gateDigest = if ("gate_digest" in o) unhex(o["gate_digest"]) else b.gateDigest,
                governingDocSha256 =
                if ("governing_doc_sha256" in o) unhex(o["governing_doc_sha256"]) else b.governingDocSha256,
                env = if ("env" in r) r["env"] as String? else b.env,
            )
            assertThrows(IllegalArgumentException::class.java, {
                SeamCrypto.commitmentDigest(CommitmentVersion.V6, base(k), f)
            }, r["name"] as String)
        }
    }

    @Test
    fun governingTrailerRefusalsUnderV6() {
        val refusals = vectorRows(v6, "governing_trailer_refusals")
        assertEquals(17, refusals.size)
        for (r in refusals) {
            assertEquals("v6", r["scheme"])
            assertThrows(IllegalArgumentException::class.java, {
                SeamCrypto.decodeCommitmentTrailers(unhex(r["trailers"])!!, CommitmentVersion.V6)
            }, r["name"] as String)
        }
    }

    @Test
    fun frameLengthOfMaxBe64RefusesAsTruncated() {
        val r = vectorRows(v6, "governing_trailer_refusals").named("env_frame_length_max_be64")
        val e = assertThrows(CommitmentRefusal::class.java) {
            SeamCrypto.decodeCommitmentTrailers(unhex(r["trailers"])!!, CommitmentVersion.V6)
        }
        // Pinned here because a signed read of 2^64-1 is -1, and the classic bug is to wrap rather than
        // refuse; the rule is the only applicable one for this input.
        assertEquals("governing_body_truncated", e.rule)
    }

    @Test
    fun v5Refusals() {
        val v = v6
        val cases = vectorRows(v, "cases")
        val refusals = vectorRows(v, "v5_refusals")
        assertEquals(6, refusals.size)
        for (r in refusals) {
            assertEquals("v5", r["scheme"])
            val name = r["name"] as String
            val trailers = unhex(r["trailers"])
            if (trailers != null) {
                assertThrows(IllegalArgumentException::class.java, {
                    SeamCrypto.decodeCommitmentTrailers(trailers, CommitmentVersion.V5)
                }, name)
            } else {
                val k = cases.named(r["base_case"] as String)
                val f = fields(k).copy(env = r["env"] as String?)
                assertThrows(IllegalArgumentException::class.java, {
                    SeamCrypto.commitmentDigest(CommitmentVersion.V5, base(k), f)
                }, name)
            }
        }
    }

    @Test
    fun schemeFreeDecode() {
        val rows = vectorRows(v6, "scheme_free")
        assertEquals(7, rows.size)
        for (r in rows) {
            assertNull(r["scheme"])
            val name = r["name"] as String
            val t = unhex(r["trailers"])!!
            if (r["expect"] == "refused") {
                assertThrows(IllegalArgumentException::class.java, {
                    SeamCrypto.decodeCommitmentTrailers(t, null)
                }, name)
                continue
            }
            val e = r["expect"] as Map<String, Any?>
            val d = SeamCrypto.decodeCommitmentTrailers(t, null)
            assertEquals(e["field_10"], hexOf(d.field10), name)
            assertEquals(e["field_11"], hexOf(d.field11), name)
            if ("field_12" in e) assertEquals(e["field_12"], hexOf(d.field12), name)
            assertEquals((e["governing_body_version"] as Number?)?.toInt(), d.governingBodyVersion, name)
        }
    }

    @Test
    fun statementSelection() {
        val rows = vectorRows(v6, "statement_selection")
        assertEquals(29, rows.size)
        for (r in rows) {
            val name = r["name"] as String
            val viaExt = "ext" in r
            val raw = (if (viaExt) r["ext"] else r["statement"]) as String
            val select = {
                if (viaExt) SeamCrypto.selectCommitmentVersion(raw) else SeamCrypto.selectStatementVersion(raw)
            }
            if (r["expect"] == "refused") {
                assertThrows(CommitmentRefusal::class.java, { select() }, name)
            } else {
                assertEquals(r["expect"], select().name.lowercase(), name)
            }
        }
    }

    private fun signedCommitment(k: Map<String, Any?>) =
        commitmentFromJson(k["commitment"] as Map<String, Any?>).copy(trailers = unhex(k["trailers"]))

    @Test
    fun signedCasesVerify() {
        val v = signed
        val issuer = v["issuer_aid"] as String
        val cases = vectorRows(v, "cases")
        assertEquals(3, cases.size)
        for (k in cases) {
            val name = k["name"] as String
            assertEquals("v6", k["expect"], name)
            assertEquals(CommitmentVersion.V6, SeamCrypto.selectCommitmentVersion(k["ext"] as String), name)
            val c = signedCommitment(k)
            val t = SeamCrypto.decodeCommitmentTrailers(c.trailers!!, CommitmentVersion.V6)
            assertEquals(k["field_10"], hexOf(t.field10), name)
            assertEquals(k["field_11"], hexOf(t.field11), name)
            assertEquals(k["field_12"], hexOf(t.field12), name)
            assertEquals(
                k["commitment_digest"],
                SeamCrypto.commitmentDigest(
                    CommitmentVersion.V6, c,
                    CommitmentDigestFields(null, t.gateDigest, t.governingDocSha256, t.env),
                ),
                name,
            )
            val tct = k["signed_artifact"] as String
            assertTrue(SeamCrypto.verifyTct(issuer, tct, c, nowS), name)
            // The same TCT over the commitment without its trailers recomputes a different v6 digest.
            if ((k["trailers"] as String).isNotEmpty()) {
                assertFalse(SeamCrypto.verifyTct(issuer, tct, c.copy(trailers = null), nowS), name)
            }
        }
    }

    @Test
    fun signedNegativesAreRefused() {
        val v = signed
        val issuer = v["issuer_aid"] as String
        val cases = vectorRows(v, "cases")
        val negatives = vectorRows(v, "negatives")
        assertEquals(5, negatives.size)
        for (n in negatives) {
            assertEquals("refused", n["expect"])
            val c = signedCommitment(cases.named(n["over"] as String))
            assertFalse(SeamCrypto.verifyTct(issuer, n["signed_artifact"] as String, c, nowS), n["name"] as String)
        }
    }

    @Test
    fun v5StatementOverEnvCommitmentNeverRetriesUnderV6() {
        val v = signed
        val n = vectorRows(v, "negatives").named("v5_statement_over_env_commitment")
        assertEquals(CommitmentVersion.V5, SeamCrypto.selectCommitmentVersion(n["ext"] as String))
        val over = vectorRows(v, "cases").named(n["over"] as String)
        assertThrows(CommitmentRefusal::class.java) {
            SeamCrypto.decodeCommitmentTrailers(unhex(over["trailers"])!!, CommitmentVersion.V5)
        }
    }

    @Test
    fun v5CommitmentDigestIsUnchangedThroughTheVersionedEntry() {
        for (k in vectorRows(v6, "cases")) {
            if (k["digest_only"] != true) continue
            val f = fields(k)
            val b = base(k)
            val slotted = b.copy(
                selectionDigest = f.selectionDigest,
                certificateDigest = f.gateDigest,
                governingDocSha256 = f.governingDocSha256,
            )
            assertEquals(
                SeamCrypto.seamCommitmentDigest(slotted),
                SeamCrypto.commitmentDigest(CommitmentVersion.V5, b, f),
                k["name"] as String,
            )
        }
    }

    @Test
    fun otherTrailerMarkersAreNotDigestInputs() {
        assertEquals("00", hexOf(SeamCrypto.decodeCommitmentTrailers(ByteArray(0), CommitmentVersion.V6).field10))
        assertThrows(IllegalArgumentException::class.java) {
            SeamCrypto.decodeCommitmentTrailers(unhex("0400000000")!!, CommitmentVersion.V6)
        }
    }
}
