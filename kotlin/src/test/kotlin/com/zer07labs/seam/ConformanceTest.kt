package com.zer07labs.seam

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.File
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** The Kotlin crypto shim must reproduce the Rust reference bytes exactly (conformance/vectors.json). */
class ConformanceTest {
    private val vectors: Map<String, Any?> =
        Gson().fromJson(
            File("../conformance/vectors.json").readText(),
            object : TypeToken<Map<String, Any?>>() {}.type,
        )

    @Suppress("UNCHECKED_CAST")
    private fun m(p: Map<String, Any?>, k: String) = p[k] as Map<String, Any?>

    private fun hexToBytes(s: String) =
        ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun commitment(c: Map<String, Any?>) = commitmentFromJson(c)

    @Test
    fun pinnedKeyPresentationIsByteExact() {
        val adm = m(vectors, "admission")
        val inp = m(adm, "inputs")
        val got =
            SeamCrypto.buildPresentation(
                hexToBytes(inp["agent_seed_hex"] as String),
                inp["receiver_aid"] as String,
                inp["pop_nonce"] as String,
                (inp["now_ms"] as Number).toLong(),
            )
        val want = m(adm, "presentation")
        val wd = m(want, "descriptor")
        assertEquals(want["sender_aid"], got.senderAid)
        assertEquals(wd["type"], got.descriptor.type)
        assertEquals(wd["subject"], got.descriptor.subject)
        assertEquals(wd["proof"], got.descriptor.proof)
        assertEquals(wd["public_key"], got.descriptor.publicKey)
        assertEquals(want["message_id"], got.messageId)
        assertEquals((want["timestamp"] as Number).toLong(), got.timestamp)
        assertEquals(want["pop_nonce"], got.popNonce)
    }

    @Test
    fun aidDerivationMatches() {
        val adm = m(vectors, "admission")
        val got =
            SeamCrypto.buildPresentation(
                hexToBytes(m(adm, "inputs")["agent_seed_hex"] as String),
                "aid:x",
                "AAAA",
                0,
            )
        assertEquals(m(adm, "derived")["sender_aid"], got.senderAid)
    }

    @Test
    fun tctVerifyValidAndTampered() {
        val t = m(vectors, "tct")
        val c = commitment(m(m(t, "inputs"), "commitment"))
        val iss = t["issuer_aid"] as String
        val jws = t["signed_artifact_jws"] as String
        assertTrue(SeamCrypto.verifyTct(iss, jws, c, 1_700_000_001), "valid TCT must verify")
        assertFalse(
            SeamCrypto.verifyTct(iss, jws, c.copy(action = "ALLOW"), 1_700_000_001),
            "a tampered commitment must not verify",
        )
    }

    @Test
    fun tctDigestsMatchVector() {
        val t = m(vectors, "tct")
        val c = commitment(m(m(t, "inputs"), "commitment"))
        assertEquals(t["explanation_digest_hex"], hex(SeamCrypto.explanationDigest(c.explanation!!)))
        assertEquals(t["commitment_digest_hex"], SeamCrypto.seamCommitmentDigest(c))
        // Only the published digest (no entries) must reproduce the same commitment digest.
        val publishedOnly = c.copy(explanation = null, explanationDigest = hexToBytes(t["explanation_digest_hex"] as String))
        assertEquals(t["commitment_digest_hex"], SeamCrypto.seamCommitmentDigest(publishedOnly))
        assertTrue(SeamCrypto.verifyTct(t["issuer_aid"] as String, t["signed_artifact_jws"] as String, publishedOnly, NOW_S))
    }

    @Test
    fun tctVerifyFailsClosed() {
        val t = m(vectors, "tct")
        val c = commitment(m(m(t, "inputs"), "commitment"))
        val iss = t["issuer_aid"] as String
        val jws = t["signed_artifact_jws"] as String
        val cases =
            listOf(
                Triple(iss, jws, 9_999_999_999L),
                Triple(iss, "not.a", 1_700_000_001L),
                Triple("aid:pubkey:ed25519:" + "A".repeat(43), jws, 1_700_000_001L),
                Triple("did:web:example.com", jws, 1_700_000_001L),
                Triple(iss, jws.substring(0, jws.length - 4) + "AAAA", 1_700_000_001L),
            )
        for ((issuer, token, now) in cases) {
            assertFalse(SeamCrypto.verifyTct(issuer, token, c, now), "must fail closed")
        }
    }

    // -- Commitment-digest framing coverage (W5.4 / G4) ----------------------------------------
    //
    // `seam-commitment-digest:v2` is implemented byte-for-byte in ALL FIVE SDK languages -- the
    // widest fan-out of any framing in this repo. Its own reference vector is
    // conformance/commitment_digest_v2_vector.json (see CommitmentDigestV2Test); the `tct` block of
    // conformance/vectors.json carries `explanation_digest_hex` / `commitment_digest_hex` too. Both
    // originate in seam-runtime, whose `sdk-digest-parity` job byte-diffs vectors.json against its
    // own emitter.
    //
    // What IS available is stronger than it looks. `verifyTct` recomputes the digest and compares
    // it to the `seam-commitment-digest:` grant inside the runtime-signed JWS, so the vector
    // already carries a runtime-produced expected value. The gap was never coverage of the digest
    // -- it was coverage of the FIELD TUPLE: the pre-existing tests tampered `action` only, so
    // exactly one of the framing inputs was proven bound.
    //
    // The difference is demonstrable, not theoretical: an implementation that silently drops
    // `supersedes` from the preimage PASSES the pre-existing KAT test (the vector's commitment has
    // no `supersedes`, so the bytes are identical) and FAILS the first test below. Verified in Go
    // and Python, where that mutation could be run directly.

    /**
     * Every field the commitment digest binds must actually be bound. A field dropped from the
     * preimage -- or reordered -- lets one artifact verify under another's signature, which is the
     * whole point of the digest: it attests WHO committed and HOW they authed, not just the
     * decision.
     */
    @Test
    fun commitmentDigestBindsEveryField() {
        val t = m(vectors, "tct")
        val base = commitment(m(m(t, "inputs"), "commitment"))
        val iss = t["issuer_aid"] as String
        val jws = t["signed_artifact_jws"] as String

        assertTrue(
            SeamCrypto.verifyTct(iss, jws, base, NOW_S),
            "the unmodified vector commitment must verify -- nothing below means anything otherwise",
        )

        val mutations =
            listOf(
                "id" to base.copy(id = base.id + "-x"),
                "action" to base.copy(action = "ALLOW"),
                "authority" to base.copy(authority = base.authority + "-x"),
                // The vector's commitment omits `supersedes`, so absent is the branch already
                // exercised. This pins the PRESENT branch, which nothing covered: absent and
                // present must differ, or a supersession could be stripped from a sealed record
                // undetected.
                "supersedes (absent -> present)" to base.copy(supersedes = "k-previous"),
                "auth_method" to base.copy(authMethod = base.authMethod + "-x"),
                "trust_basis" to base.copy(trustBasis = base.trustBasis + "-x"),
                "committer" to base.copy(committer = base.committer + "-x"),
                "explanation (entry reason)" to
                    base.copy(explanation = base.explanation!!.mapIndexed { i, e -> if (i == 0) e.copy(reason = e.reason + "-x") else e }),
                "explanation (entry order)" to base.copy(explanation = base.explanation!!.reversed()),
                "explanation (absent confidence -> stated 0.0)" to
                    base.copy(explanation = base.explanation!!.mapIndexed { i, e -> if (i == 0) e.copy(confidence = 0.0) else e }),
                "explanation (entries dropped)" to base.copy(explanation = null),
            )

        for ((field, mutated) in mutations) {
            assertFalse(
                SeamCrypto.verifyTct(iss, jws, mutated, NOW_S),
                "changing $field did not change the commitment digest -- that field is not bound",
            )
        }
    }

    /**
     * The length prefixes are load-bearing, and this notices if someone "simplifies" them away.
     * Both seam-store and seam-trust-aitp record the reason in their own source: without an 8-byte
     * big-endian length before each field, ("a\u0000b","c") and ("a","b\u0000c") produce identical
     * preimages, letting one Commitment verify under another's TCT. The fields are arbitrary text
     * that may itself contain NUL (UTF-8 permits U+0000, and it survives the JSON/prost decision
     * path), so this is reachable rather than theoretical.
     */
    @Test
    fun commitmentDigestIsInjectiveAcrossFieldBoundaries() {
        val t = m(vectors, "tct")
        val base = commitment(m(m(t, "inputs"), "commitment"))

        // Fold the id/action boundary into `id` with a NUL. Under a NUL-joined framing this
        // collides with the real commitment; under length-prefixing it cannot.
        val shifted = base.copy(id = base.id + "\u0000" + base.action, action = "")

        assertFalse(
            SeamCrypto.verifyTct(
                t["issuer_aid"] as String,
                t["signed_artifact_jws"] as String,
                shifted,
                NOW_S,
            ),
            "a boundary-shifted commitment verified -- the framing is separator-joined, not " +
                "length-prefixed, and one artifact can now verify under another's signature",
        )
    }

    // -- Authorize call_sig v3 (#197) ------------------------------------------------------------
    //
    // conformance/call_sig_v3_payload_vector.json is the cross-language contract. NO bless mode: a
    // mismatch is a contract break (a v4 domain tag), not a stale fixture.

    @Test
    @Suppress("UNCHECKED_CAST")
    fun callSigV3PayloadMatchesVector() {
        val v: Map<String, Any?> =
            Gson().fromJson(
                File("../conformance/call_sig_v3_payload_vector.json").readText(),
                object : TypeToken<Map<String, Any?>>() {}.type,
            )
        assertEquals(SeamCrypto.CALL_SIG_V3_CONTEXT, v["domain"])
        val cases = v["cases"] as List<Map<String, Any?>>
        assertFalse(cases.isEmpty(), "vector is empty; every assertion below would pass vacuously")
        for (c in cases) {
            val got =
                SeamCrypto.callSigV3Payload(
                    CallSigV3Fields(
                        ticket = hexToBytes(c["ticket_hex"] as String),
                        toolInputDigest = c["tool_input_digest"] as String,
                        toolName = c["tool_name"] as String,
                        agentId = c["agent_id"] as String,
                        subject = c["subject"] as String,
                        subjects = c["subjects"] as List<String>,
                        clientRequestId = c["client_request_id"] as String,
                        sessionId = c["session_id"] as String,
                        features = (c["features"] as List<List<String>>).map { it[0] to it[1] },
                    ),
                )
            assertEquals(c["payload_hex"], hex(got), "${c["name"]}: ${c["why"]}")
        }
    }

    /**
     * The vector's non-ascii case has a single feature, so it cannot catch a UTF-16 sort. U+FF61
     * (UTF-8 EF BD A1) sorts BEFORE U+1F600 (F0 9F 98 80) by bytes, but AFTER it by
     * `String.compareTo` (0xFF61 > 0xD83D). The payload must follow byte order.
     */
    @Test
    fun callSigV3SortsFeaturesByUtf8Bytes() {
        val f =
            CallSigV3Fields(
                ticket = byteArrayOf(1),
                toolInputDigest = "d",
                toolName = "t",
                agentId = "",
                features = listOf("😀" to "a", "｡" to "b"),
            )
        val p = hex(SeamCrypto.callSigV3Payload(f))
        assertTrue(p.indexOf("efbda1") < p.indexOf("f09f9880"), "features sorted by UTF-16 code unit, not by UTF-8 bytes")
    }

    @Test
    fun callSigV3SignVerifyRoundTrip() {
        val seed = ByteArray(32) { 7 }
        val f =
            CallSigV3Fields(
                ticket = byteArrayOf(1, 2, 3, 4),
                toolInputDigest = "sha256:" + "00".repeat(32),
                toolName = "read_file",
                agentId = "billing-agent",
                subject = "user-1",
                subjects = listOf("user-2", "user-3"),
                clientRequestId = "req-0001",
                sessionId = "sess-9",
                features = listOf("region" to "eu", "amount_bucket" to "high"),
            )
        val sig = SeamCrypto.callSigV3(seed, f)
        assertEquals(64, sig.size)

        val pub = Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
        assertTrue(verify(pub, SeamCrypto.callSigV3Payload(f), sig), "signature must verify")
        assertFalse(
            verify(pub, SeamCrypto.callSigV3Payload(f.copy(subjects = listOf("user-3", "user-2"))), sig),
            "signature verified over reordered subjects -- subject order is not bound",
        )
        assertThrows(IllegalArgumentException::class.java) { SeamCrypto.callSigV3(ByteArray(31), f) }
    }

    private fun verify(pub: ByteArray, msg: ByteArray, sig: ByteArray): Boolean {
        val v = Ed25519Signer()
        v.init(false, Ed25519PublicKeyParameters(pub, 0))
        v.update(msg, 0, msg.size)
        return v.verifySignature(sig)
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private companion object {
        const val NOW_S = 1_700_000_001L
    }
}
