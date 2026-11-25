package com.zer07labs.seam

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.io.File
import java.math.BigDecimal
import java.util.Base64
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Deep-cleanup S-4 (seam-runtime #2031, runtime 0.123.0): the commitment TCT is signed by a seal key
 * the pinned issuer certifies. Pinned by `conformance/seal_key_cert_vector.json`; the token cases are
 * minted here by hand ([SealKeyTokens]) so each refusal is about one thing. Twin of Java `SealKeyTest`.
 */
class SealKeyTest {
    private val mapType = object : TypeToken<Map<String, Any?>>() {}.type
    private val nowS = 1_700_000_001L

    private val issuerSeed = ByteArray(32) { 7 }
    private val issuer = "aid:pubkey:" + SealKeyTokens.b64(SealKeyTokens.pub(issuerSeed))
    private val otherSeed = ByteArray(32) { 8 }
    private val other = "aid:pubkey:" + SealKeyTokens.b64(SealKeyTokens.pub(otherSeed))
    private val seal = SealKeyTokens.SEAL_SEED
    private val nb = SealKeyTokens.NOT_BEFORE_MS
    private val na = SealKeyTokens.NOT_AFTER_MS
    private val iat = SealKeyTokens.IAT

    private fun load(name: String): Map<String, Any?> = Gson().fromJson(File("../conformance/$name").readText(), mapType)

    private fun unhex(h: String) = ByteArray(h.length / 2) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun long(v: Any?) = BigDecimal(v.toString()).toBigIntegerExact().toLong()

    // ── the frozen certificate vector ──────────────────────────────────────────────────────────

    @Test
    fun theSealKeyCertVectorRebuildsAndVerifies() {
        val v = load("seal_key_cert_vector.json")
        assertEquals(SeamCrypto.SEAL_KEY_CERT_DOMAIN, v["domain"])
        val cert = unhex(v["cert_hex"] as String)
        val sig = unhex(v["sig_hex"] as String)
        val pk = unhex(v["seal_pk_hex"] as String)
        val vnb = long(v["not_before_ms"])
        val vna = long(v["not_after_ms"])
        val vIssuer = v["issuer_aid"] as String
        assertEquals(issuer, vIssuer, "issuer seed 7x32")
        assertArrayEquals(pk, SealKeyTokens.pub(unhex(v["seal_seed_hex"] as String)))
        assertArrayEquals(cert, SeamCrypto.sealKeyCertPreimage(pk, vnb, vna, vIssuer))
        assertArrayEquals(cert, SealKeyTokens.cert(pk, vnb, vna, vIssuer))
        assertEquals(v["cert_digest_hex"], hex(SealKeyTokens.sha256(cert)))
        @Suppress("UNCHECKED_CAST")
        val member = v["ext_member"] as Map<String, Any?>
        assertEquals(SealKeyTokens.b64(cert), member["cert"])
        assertEquals(SealKeyTokens.b64(sig), member["sig"])

        val f = SeamCrypto.verifySealKeyCert(vIssuer, cert, sig)
        assertNotNull(f, "verifies under the pin")
        assertArrayEquals(pk, f!!.sealPk)
        assertEquals(vnb, f.notBeforeMs)
        assertEquals(vna, f.notAfterMs)
        assertEquals(vIssuer, f.issuerAid)
        assertEquals(v["seal_aid"], f.sealAid)

        assertNull(SeamCrypto.verifySealKeyCert(other, cert, sig), "another pinned issuer")
        for (i in cert.indices) {
            val bad = cert.copyOf()
            bad[i] = (bad[i].toInt() xor 1).toByte()
            assertNull(SeamCrypto.verifySealKeyCert(vIssuer, bad, sig), "flipped cert byte $i")
        }
        for (i in sig.indices) {
            val bad = sig.copyOf()
            bad[i] = (bad[i].toInt() xor 1).toByte()
            assertNull(SeamCrypto.verifySealKeyCert(vIssuer, cert, bad), "flipped sig byte $i")
        }
    }

    @Test
    fun everyPrefixAndATrailingByteIsRefused() {
        val pk = SealKeyTokens.pub(seal)
        val c = SealKeyTokens.cert(pk, nb, na, issuer)
        assertNotNull(SeamCrypto.parseSealKeyCert(c))
        for (cut in 0 until c.size) assertNull(SeamCrypto.parseSealKeyCert(c.copyOf(cut)), "prefix $cut")
        assertNull(SeamCrypto.parseSealKeyCert(c.copyOf(c.size + 1)), "trailing byte")
        assertNull(SeamCrypto.parseSealKeyCert(SealKeyTokens.cert(pk, 21, 20, "a")), "inverted")
        assertNull(SeamCrypto.parseSealKeyCert(SealKeyTokens.cert(pk, 0, -1L, "a")), "not_after beyond i64::MAX (u64::MAX)")
        assertNull(SeamCrypto.parseSealKeyCert(SealKeyTokens.cert(pk, 0, Long.MAX_VALUE, "a")), "wider than the cap")
        assertNull(SeamCrypto.parseSealKeyCert(SealKeyTokens.cert(pk, nb, nb + 1, "a".repeat(63))), "issuer AID over 62 bytes")
        assertNotNull(SeamCrypto.parseSealKeyCert(SealKeyTokens.cert(pk, nb, nb + 1, "a".repeat(62))))
        val badUtf8 = SealKeyTokens.cert(pk, nb, nb + 1, "ab")
        badUtf8[badUtf8.size - 1] = 0xff.toByte()
        assertNull(SeamCrypto.parseSealKeyCert(badUtf8), "issuer AID not UTF-8")
        val wrongTag = c.copyOf()
        wrongTag[4] = (wrongTag[4].toInt() xor 1).toByte()
        assertNull(SeamCrypto.parseSealKeyCert(wrongTag), "wrong domain tag")
    }

    // ── token-level verification ───────────────────────────────────────────────────────────────

    @Suppress("UNCHECKED_CAST")
    private fun commitment(): Commitment {
        val t = load("vectors.json")["tct"] as Map<String, Any?>
        return commitmentFromJson((t["inputs"] as Map<String, Any?>)["commitment"] as Map<String, Any?>)
    }

    /** A token whose parts the case controls: who signs it, its claims, iat literal and ext member. */
    private fun token(signer: ByteArray, claimsSeal: ByteArray, iatLiteral: String?, member: Any?, extra: String): String {
        val claims = SealKeyTokens.claims(claimsSeal, 0)
        claims.remove("iat")
        val head = Gson().toJson(claims)
        val stmt = """{"type":"seam:commitment","commitment_digest":"${SeamCrypto.seamCommitmentDigest(commitment())}"}"""
        val ext = """{"com.zer07labs.seam":$stmt""" +
            (if (member == null) "" else ""","${SeamCrypto.SEAL_KEY_CERT_EXT_KEY}":${Gson().toJson(member)}""") +
            extra + "}"
        val payload = head.dropLast(1) + (if (iatLiteral == null) "" else ""","iat":$iatLiteral""") +
            ""","exp":4853600000,"grants":["aitp.attestation"],"ext":$ext}"""
        return SealKeyTokens.jws(signer, payload)
    }

    private fun verify(jws: String) = SeamCrypto.verifyTct(issuer, jws, commitment(), nowS)

    private fun member(nb: Long, na: Long) =
        SealKeyTokens.member(issuerSeed, SealKeyTokens.cert(SealKeyTokens.pub(seal), nb, na, issuer))

    private fun ok(iat: Long, member: Any?) = token(seal, seal, iat.toString(), member, "")

    @Test
    @Suppress("UNCHECKED_CAST")
    fun theRuntimeVectorTokensVerify() {
        val t = load("vectors.json")["tct"] as Map<String, Any?>
        assertTrue(
            SeamCrypto.verifyTct(t["issuer_aid"] as String, t["signed_artifact_jws"] as String, commitment(), nowS),
            "vectors.json tct, signed through the runtime's seeded seal key",
        )
        assertFalse(SeamCrypto.verifyTct(other, t["signed_artifact_jws"] as String, commitment(), nowS), "another pinned issuer")
        assertTrue(verify(ok(iat, member(nb, na))), "the hand-minted control")
    }

    @Test
    fun anIssuerSignedTctIsRefused() {
        // The pre-S-4 shape: iss == sub == aud == the issuer, signed by the issuer, no certificate.
        assertFalse(verify(token(issuerSeed, issuerSeed, iat.toString(), null, "")))
        assertFalse(verify(token(issuerSeed, issuerSeed, iat.toString(), member(nb, na), "")))
        assertFalse(verify(token(issuerSeed, seal, iat.toString(), member(nb, na), "")))
    }

    @Test
    fun aWindowOverTheCapIsRefusedAndTheCapItselfVerifies() {
        assertTrue(verify(ok(iat, member(nb, nb + SeamCrypto.SEAL_KEY_MAX_WINDOW_MS))))
        assertFalse(verify(ok(iat, member(nb, nb + SeamCrypto.SEAL_KEY_MAX_WINDOW_MS + 1))))
        assertEquals(3_630_000L, SeamCrypto.SEAL_KEY_MAX_WINDOW_MS)
    }

    @Test
    fun iatMustLieInTheWindowWithNoGrace() {
        val m = member(nb, na)
        assertTrue(verify(ok(nb / 1000, m)), "not_before")
        assertTrue(verify(ok(na / 1000, m)), "not_after")
        assertFalse(verify(ok(nb / 1000 - 1, m)), "one second before")
        assertFalse(verify(ok(na / 1000 + 1, m)), "one second after")
        assertFalse(verify(ok(nb / 1000, member(nb + 1, na))), "iat*1000 one ms before not_before")
        for (lit in listOf(null, "\"1700000000\"", "1700000000.0", "1.7e9", "true", "null")) {
            assertFalse(verify(token(seal, seal, lit, m, "")), "iat $lit")
        }
        assertFalse(verify(ok(Long.MAX_VALUE, member(Long.MAX_VALUE - 1000, Long.MAX_VALUE))), "iat*1000 overflows")
    }

    @Test
    fun theCertificateMustNameAndBeSignedByThePinnedIssuer() {
        val pk = SealKeyTokens.pub(seal)
        assertFalse(verify(ok(iat, SealKeyTokens.member(issuerSeed, SealKeyTokens.cert(pk, nb, na, other)))))
        assertFalse(verify(ok(iat, SealKeyTokens.member(otherSeed, SealKeyTokens.cert(pk, nb, na, issuer)))))
        val forged = ok(iat, SealKeyTokens.member(otherSeed, SealKeyTokens.cert(pk, nb, na, other)))
        assertFalse(verify(forged))
        assertTrue(SeamCrypto.verifyTct(other, forged, commitment(), nowS), "control: under its own pin")
        assertFalse(
            SeamCrypto.verifyTct(SeamCrypto.aidFromPubkey(SealKeyTokens.pub(issuerSeed)), ok(iat, member(nb, na)), commitment(), nowS),
        )
    }

    @Test
    fun theCertificateMemberAndExtShapeAreExact() {
        val m = member(nb, na)
        assertFalse(verify(ok(iat, LinkedHashMap(m).also { it["x"] = "y" })), "a third member")
        assertFalse(verify(ok(iat, LinkedHashMap(m).also { it.remove("sig") })), "sig missing")
        val padded = Base64.getUrlEncoder().encodeToString(Base64.getUrlDecoder().decode(m["sig"] as String))
        assertTrue(padded.endsWith("="))
        assertFalse(verify(ok(iat, LinkedHashMap(m).also { it["sig"] = padded })), "padded base64url")
        val std = (m["cert"] as String).replace('-', '+').replace('_', '/')
        if (std != m["cert"]) assertFalse(verify(ok(iat, LinkedHashMap(m).also { it["cert"] = std })), "standard alphabet")
        val sig = m["sig"] as String
        val nonCanonical = sig.dropLast(1) + (sig.last() + 1)
        assertFalse(verify(ok(iat, LinkedHashMap(m).also { it["sig"] = nonCanonical })), "non-canonical trailing bits")
        assertFalse(verify(ok(iat, LinkedHashMap(m).also { it["cert"] = 1 })), "cert not a string")
        val otherSeal = SealKeyTokens.member(issuerSeed, SealKeyTokens.cert(SealKeyTokens.pub(otherSeed), nb, na, issuer))
        assertFalse(verify(ok(iat, otherSeal)), "cert for another seal key")
        assertFalse(verify(token(seal, seal, iat.toString(), m, ""","com.example":{}""")), "extra ext namespace")
        assertFalse(verify(token(seal, seal, iat.toString(), null, "")), "no certificate member")
    }

    @Test
    fun trailingCertificateBytesAreRefused() {
        val c = SealKeyTokens.cert(SealKeyTokens.pub(seal), nb, na, issuer)
        assertFalse(verify(ok(iat, SealKeyTokens.member(issuerSeed, c.copyOf(c.size + 1)))))
    }

    @Test
    fun aSmallOrderRorKeyIsRefused() {
        val identity = ByteArray(32).also { it[0] = 1 }
        val msg = "m".toByteArray()
        val sig = identity.copyOf(64)
        assertFalse(SeamCrypto.ed25519VerifyStrict(identity, msg, sig))
        val c = SealKeyTokens.cert(SealKeyTokens.pub(seal), nb, na, issuer)
        val good = SealKeyTokens.sign(issuerSeed, SealKeyTokens.sha256(c))
        assertNotNull(SeamCrypto.verifySealKeyCert(issuer, c, good))
        val bad = good.copyOf()
        identity.copyInto(bad, 0)
        assertNull(SeamCrypto.verifySealKeyCert(issuer, c, bad))
        val weak = "aid:pubkey:" + SealKeyTokens.b64(identity)
        assertNull(SeamCrypto.verifySealKeyCert(weak, SealKeyTokens.cert(SealKeyTokens.pub(seal), nb, na, weak), sig))
    }
}
