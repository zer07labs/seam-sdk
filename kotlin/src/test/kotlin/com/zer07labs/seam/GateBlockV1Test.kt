package com.zer07labs.seam

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/**
 * The Gate block v1 (`0x05`) and `seam-gate-digest:v1` against `conformance/gate_block_vector.json`:
 * `cases`, `presence_states`, `body_refusals` and `sequences`, every row. Refusal rows assert the refusal
 * only.
 *
 * `outage_classification` and `writer_refusals` are NOT tested here: they pin what the runtime WRITES for
 * an observed Gate outcome (which HTTP status seals as which reason, or refuses), and this SDK is a reader
 * only. A reader cannot see the HTTP status, so those rows have nothing to assert against a decoder (Flows
 * W2 plan, cross-port contract item 3).
 */
@Suppress("UNCHECKED_CAST")
class GateBlockV1Test {
    private val vector get() = loadVector("gate_block_vector.json")

    private fun u32le(n: Int) = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(n).array()

    private fun be64(n: Long) = ByteBuffer.allocate(8).putLong(n).array()

    /** `0x06 ‖ u32le(len) ‖ 0x02 ‖ doc ‖ 0x01 ‖ F(env)`: the binding a `0x05` needs. */
    private fun governingV2(env: String): ByteArray {
        val e = env.toByteArray(Charsets.US_ASCII)
        val body = ByteArrayOutputStream().apply {
            write(0x02)
            writeBytes(MessageDigest.getInstance("SHA-256").digest("seam-governing-doc:test-vector".toByteArray()))
            write(0x01)
            writeBytes(be64(e.size.toLong()))
            writeBytes(e)
        }.toByteArray()
        return byteArrayOf(0x06) + u32le(body.size) + body
    }

    @Test
    fun everyCaseDecodesAndDigests() {
        val v = vector
        assertEquals(SeamCrypto.GATE_DIGEST_DOMAIN, v["gate_digest_domain"])
        val cases = vectorRows(v, "cases")
        assertEquals(8, cases.size)
        for (k in cases) {
            val name = k["name"] as String
            val body = unhex(k["gate_body"])!!
            val want = k["block"] as Map<String, Any?>
            val b = SeamCrypto.decodeGateBody(body)
            assertEquals(want["status"], b.status, name)
            assertEquals(want["attempt_id"], b.attemptId, name)
            assertEquals(want["domain"], b.domain, name)
            assertEquals(want["flow_id"], b.flowId, name)
            assertEquals(want["env"], b.env, name)
            assertEquals(want["timeout_ms"], b.timeoutMs.toString(), name)
            assertEquals(want["on_outage"], b.onOutage, name)
            assertEquals(want["requested_at_ms"], b.requestedAtMs.toString(), name)
            if (b.status == "answered") {
                assertEquals(want["receipt_jcs"], b.receiptJcs, name)
                assertEquals(want["key_id"], b.keyId, name)
                assertEquals(want["signature"], hexOf(b.signature), name)
                assertEquals(want["certificate_jcs"], b.certificateJcs, name)
                assertNull(b.reason, name)
                assertNull(b.givenUpAtMs, name)
            } else {
                assertEquals(want["reason"], b.reason, name)
                assertEquals(want["given_up_at_ms"], b.givenUpAtMs.toString(), name)
                assertNull(b.receiptJcs, name)
                assertNull(b.signature, name)
            }
            assertEquals(k["gate_digest"], hexOf(SeamCrypto.gateDigest(body)), name)
            val tag = SeamCrypto.GATE_DIGEST_DOMAIN.toByteArray(Charsets.US_ASCII)
            assertEquals(k["gate_digest_preimage_prefix"], hexOf(be64(tag.size.toLong()) + tag), name)
            // The trailer frames the body; decoded beside its 0x06 v2 binding, field 10 is the digest.
            val trailer = unhex(k["trailer"])!!
            assertEquals(hexOf(trailer), hexOf(byteArrayOf(0x05) + u32le(body.size) + body), name)
            val t = SeamCrypto.decodeCommitmentTrailers(trailer + governingV2(b.env), CommitmentVersion.V6)
            assertEquals(k["field_10"], hexOf(t.field10), name)
        }
    }

    @Test
    fun presenceStates() {
        val rows = vectorRows(vector, "presence_states")
        assertEquals(3, rows.size)
        for (r in rows) {
            val seq = unhex(r["trailer"])?.let { trailer ->
                val body = trailer.copyOfRange(5, trailer.size)
                trailer + governingV2(SeamCrypto.decodeGateBody(body).env)
            } ?: ByteArray(0)
            val t = SeamCrypto.decodeCommitmentTrailers(seq, CommitmentVersion.V6)
            assertEquals(r["field_10"], hexOf(t.field10), r["name"] as String)
        }
    }

    @Test
    fun bodyRefusals() {
        val rows = vectorRows(vector, "body_refusals")
        assertEquals(36, rows.size)
        for (r in rows) {
            assertEquals("refused", r["expect"])
            val name = r["name"] as String
            val body = unhex(r["gate_body"])!!
            assertThrows(CommitmentRefusal::class.java, { SeamCrypto.decodeGateBody(body) }, name)
            assertThrows(CommitmentRefusal::class.java, { SeamCrypto.gateDigest(body) }, name)
        }
    }

    @Test
    fun frameLengthOfMaxBe64RefusesAsTruncated() {
        val r = vectorRows(vector, "body_refusals").named("frame_length_max_be64")
        val e = assertThrows(CommitmentRefusal::class.java) { SeamCrypto.decodeGateBody(unhex(r["gate_body"])!!) }
        assertEquals("gate_body_truncated", e.rule)
    }

    @Test
    fun sequencesUnderV6() {
        val rows = vectorRows(vector, "sequences")
        assertEquals(13, rows.size)
        for (r in rows) {
            assertEquals("v6", r["scheme"])
            val name = r["name"] as String
            val t = unhex(r["trailers"])!!
            if (r["expect"] == "refused") {
                assertThrows(IllegalArgumentException::class.java, {
                    SeamCrypto.decodeCommitmentTrailers(t, CommitmentVersion.V6)
                }, name)
                continue
            }
            val e = r["expect"] as Map<String, Any?>
            val d = SeamCrypto.decodeCommitmentTrailers(t, CommitmentVersion.V6)
            assertEquals(e["field_10"], hexOf(d.field10), name)
            assertEquals(e["field_11"], hexOf(d.field11), name)
            assertEquals(e["field_12"], hexOf(d.field12), name)
        }
    }
}
