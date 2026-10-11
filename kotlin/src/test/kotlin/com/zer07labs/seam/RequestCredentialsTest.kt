package com.zer07labs.seam

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.nio.file.Files
import java.nio.file.Path
import java.util.HexFormat
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

private const val GET_DECISION = "/seam.api.v1.SeamCoordination/GetDecision"
private const val SUBMIT_VOTE = "/seam.api.v1.SeamCoordination/SubmitVote"

/** The `seam-request-call-v1` credential (#508) and the bound-agent default (#202). */
class RequestCredentialsTest {
    @Test
    fun requestSigPayloadMatchesVector() {
        val v: Map<String, Any?> = Gson().fromJson(
            Files.readString(Path.of("..", "conformance", "request_sig_payload_vector.json")),
            object : TypeToken<Map<String, Any?>>() {}.type,
        )
        assertEquals(SeamCrypto.REQUEST_SIG_CONTEXT, v["domain"])
        @Suppress("UNCHECKED_CAST")
        val cases = v["cases"] as List<Map<String, Any?>>
        assertFalse(cases.isEmpty(), "vector is empty")
        val hex = HexFormat.of()
        for (c in cases) {
            val label = "${c["name"]}: ${c["why"]}"
            val payload = SeamCrypto.requestSigPayload(
                hex.parseHex(c["ticket_hex"] as String),
                c["rpc_full_name"] as String,
                c["resource_id"] as String,
                c["body_digest"] as String,
            )
            assertEquals(c["payload_hex"], hex.formatHex(payload), label)
            (c["body_input_hex"] as String?)?.let {
                assertEquals(c["body_digest"], SeamCrypto.bodyDigest(hex.parseHex(it)), label)
            }
        }
    }

    private fun agentOf(b: Int) = Agent(ByteArray(32) { b.toByte() })

    private fun recording(asked: MutableList<String>) = TicketSource { a ->
        asked += a.aid
        "ticket-for-${a.aid}".toByteArray()
    }

    private fun verifies(a: Agent, md: Map<String, ByteArray>, rpc: String, resourceId: String, digest: String): Boolean {
        val pub = Ed25519PrivateKeyParameters(a.seed(), 0).generatePublicKey().encoded
        val msg = SeamCrypto.requestSigPayload(md.getValue(RequestCredentials.TICKET_KEY), rpc, resourceId, digest)
        val v = Ed25519Signer()
        v.init(false, Ed25519PublicKeyParameters(pub, 0))
        v.update(msg, 0, msg.size)
        return v.verifySignature(md.getValue(RequestCredentials.CALL_SIG_KEY))
    }

    @Test
    fun boundAgentCredentialIsAttachedByDefault() {
        val bound = agentOf(1)
        val asked = mutableListOf<String>()
        val md = RequestCredentials(bound, recording(asked)).metadata(null, GET_DECISION, "dec:1")
        assertEquals(2, md.size)
        assertArrayEquals("ticket-for-${bound.aid}".toByteArray(), md[RequestCredentials.TICKET_KEY])
        assertTrue(verifies(bound, md, GET_DECISION, "dec:1", ""))
        assertEquals(listOf(bound.aid), asked)
    }

    @Test
    fun explicitCredentialWinsOverTheBoundAgent() {
        val bound = agentOf(1)
        val explicit = agentOf(2)
        val asked = mutableListOf<String>()
        val body = byteArrayOf(0x0a, 0x01, 0x78)
        val md = RequestCredentials(bound, recording(asked)).metadata(explicit, SUBMIT_VOTE, "", body)
        val digest = SeamCrypto.bodyDigest(body)
        assertTrue(verifies(explicit, md, SUBMIT_VOTE, "", digest), "explicit credential did not sign")
        assertFalse(verifies(bound, md, SUBMIT_VOTE, "", digest), "bound agent signed instead")
        assertEquals(listOf(explicit.aid), asked)
    }

    @Test
    fun noAgentMeansNoCredential() {
        val asked = mutableListOf<String>()
        val unbound = RequestCredentials(null, recording(asked))
        assertTrue(unbound.metadata(null, GET_DECISION, "dec:1").isEmpty())
        assertTrue(asked.isEmpty(), "an unbound client admitted anyway")
        // Opt-in per call still works on an unbound instance, as before #202.
        assertEquals(2, unbound.metadata(agentOf(3), GET_DECISION, "dec:1").size)
    }
}
