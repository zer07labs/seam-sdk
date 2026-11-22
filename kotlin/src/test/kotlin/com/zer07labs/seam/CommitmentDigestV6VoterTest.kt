package com.zer07labs.seam

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * `seam-commitment-digest:v6` with sealed voter records: every row of
 * `conformance/commitment_digest_v6_voter_vector.json` (copied byte for byte from seam-runtime, seamd
 * 0.113.0). Specs: seam-runtime `docs/specs/seam-commitment-digest.v6.md` and
 * `docs/specs/voter-verification.v1.md`. Twin of Python `test_commitment_digest_v6_voters.py`.
 *
 * A case passes under v6 AND `verifyCommitmentVoters(entries, issuer, decision)` with `voters_verified`
 * records. A negative is refused by at least one of the two. `rule` is advisory, so no test compares it.
 * NO bless mode.
 */
@Suppress("UNCHECKED_CAST")
class CommitmentDigestV6VoterTest {
    private val v get() = loadVector("commitment_digest_v6_voter_vector.json")

    private fun issuer(v: Map<String, Any?>) = v["issuer_aid"] as String

    private fun decision(v: Map<String, Any?>): VoterDecisionRef {
        val d = v["decision"] as List<String>
        assertEquals(2, d.size)
        return VoterDecisionRef(d[0], d[1])
    }

    /** The row as `verifyTct` reads it: the full commitment WITH its entries, plus the raw trailers. */
    private fun commitment(row: Map<String, Any?>) =
        commitmentFromJson(row["commitment"] as Map<String, Any?>).copy(trailers = unhex(row["trailers"]))

    private fun records(entries: List<ExplanationEntry>) = entries.count { it.voterVerification != null }

    @Test
    fun theVectorFileIsTheV6VoterSpec() {
        val v = v
        assertEquals(SeamCrypto.COMMITMENT_DIGEST_DOMAIN_V6, v["commitment_digest_domain"])
        assertEquals("seam-commitment-digest:v6", v["commitment_digest_domain"])
        assertEquals("seam-explanation-digest:v2", v["explanation_digest_domain"])
        assertEquals(SeamCrypto.GATE_DIGEST_DOMAIN, v["gate_digest_domain"])
        assertEquals("seam-gate-digest:v1", v["gate_digest_domain"])
        decision(v)
        assertEquals(setOf("decision", "cases", "negatives"), v.filterValues { it is List<*> }.keys)
        assertEquals(2, vectorRows(v, "cases").size)
        assertEquals(8, vectorRows(v, "negatives").size)
    }

    @Test
    fun everyCaseVerifiesWithItsVoterRecords() {
        val v = v
        val issuer = issuer(v)
        val decision = decision(v)
        val votersVerified = (v["voters_verified"] as Number).toInt()
        for (k in vectorRows(v, "cases")) {
            val name = k["name"] as String
            assertEquals("v6", k["expect"], name)
            assertEquals(CommitmentVersion.V6, SeamCrypto.selectCommitmentVersion(k["ext"] as String), name)
            val c = commitment(k)
            val entries = c.explanation!!
            assertArrayEquals(c.explanationDigest, SeamCrypto.explanationDigest(entries), name)
            val t = SeamCrypto.decodeCommitmentTrailers(c.trailers!!, CommitmentVersion.V6)
            assertEquals(
                k["commitment_digest"],
                SeamCrypto.commitmentDigest(
                    CommitmentVersion.V6, c,
                    CommitmentDigestFields(null, t.gateDigest, t.governingDocSha256, t.env),
                ),
                name,
            )
            assertTrue(SeamCrypto.verifyTct(issuer, k["signed_artifact"] as String, c, 0), name)
            assertTrue(SeamCrypto.verifyCommitmentVoters(entries, issuer, decision), name)
            assertEquals(votersVerified, records(entries), name)
        }
    }

    @Test
    fun everyNegativeIsRefused() {
        val v = v
        val issuer = issuer(v)
        val decision = decision(v)
        val cases = vectorRows(v, "cases").map { it["name"] as String }.toSet()
        for (n in vectorRows(v, "negatives")) {
            val name = n["name"] as String
            assertEquals("refused", n["expect"], name)
            assertTrue(n["over"] in cases, name)
            val c = commitment(n)
            val tctOk = SeamCrypto.verifyTct(issuer, n["signed_artifact"] as String, c, 0)
            val votersOk = SeamCrypto.verifyCommitmentVoters(c.explanation!!, issuer, decision)
            assertFalse(tctOk && votersOk, name)
        }
    }

    /**
     * `wrong_decision` is a well-signed TCT whose records name another decision: only the decision the
     * verifier knows can refuse it, so dropping that argument must let it through.
     */
    @Test
    fun theDecisionBindingIsWhatRefusesWrongDecision() {
        val v = v
        val issuer = issuer(v)
        val n = vectorRows(v, "negatives").named("wrong_decision")
        val c = commitment(n)
        assertTrue(SeamCrypto.verifyTct(issuer, n["signed_artifact"] as String, c, 0))
        assertTrue(SeamCrypto.verifyCommitmentVoters(c.explanation!!, issuer))
        assertFalse(SeamCrypto.verifyCommitmentVoters(c.explanation!!, issuer, decision(v)))
    }

    /**
     * The entries and their digest were rewritten together and the old TCT kept: the records still
     * re-check, so it is the commitment digest under the signature that refuses it.
     */
    @Test
    fun aTamperedPublishedEntryBreaksTheSignedDigest() {
        val v = v
        val issuer = issuer(v)
        val n = vectorRows(v, "negatives").named("tampered_published_entry")
        val c = commitment(n)
        assertTrue(SeamCrypto.verifyCommitmentVoters(c.explanation!!, issuer, decision(v)))
        assertFalse(SeamCrypto.verifyTct(issuer, n["signed_artifact"] as String, c, 0))
    }
}
