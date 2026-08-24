package com.zer07labs.seam

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.File
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
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

    private fun commitment(c: Map<String, Any?>) =
        Commitment(
            c["id"] as String,
            c["action"] as String,
            c["authority"] as String,
            c["supersedes"] as String?,
            c["auth_method"] as String,
            c["trust_basis"] as String,
        )

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
    // `seam-commitment-digest:v1` is implemented byte-for-byte in ALL FIVE SDK languages -- the
    // widest fan-out of any framing in this repo -- and has no vector section of its own. It cannot
    // get one here either: seam-runtime's `sdk-digest-parity` job byte-diffs the whole of
    // conformance/vectors.json against its own emitter, so a block added on this side turns the
    // runtime's CI red. A vector for it must originate there.
    //
    // What IS available is stronger than it looks. `verifyTct` recomputes the digest and compares
    // it to the `seam-commitment-digest:` grant inside the runtime-signed JWS, so the vector
    // already carries a runtime-produced expected value. The gap was never coverage of the digest
    // -- it was coverage of the FIELD TUPLE: the pre-existing tests tampered `action` only, so
    // exactly one of the seven framing inputs was proven bound.
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

    private companion object {
        const val NOW_S = 1_700_000_001L
    }
}
