package com.zer07labs.seam

import com.google.gson.Gson
import com.google.gson.Strictness
import com.google.gson.reflect.TypeToken
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.StringReader
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import java.util.Base64
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * Client-side crypto for the Seam Kotlin SDK — stock primitives (Ed25519 via Bouncy Castle + SHA-256),
 * no AITP binding. Mirrors the Python/Go/Java/TS reference byte-for-byte; pinned by
 * `conformance/vectors.json`. The admission proof-of-possession is Ed25519 over SHA-256 of a documented,
 * domain-separated canonical byte layout; the seed never leaves the client.
 */
data class Descriptor(val type: String, val subject: String, val proof: String, val publicKey: String)

data class Presentation(
    val senderAid: String,
    val descriptor: Descriptor,
    val messageId: String,
    val timestamp: Long,
    val popNonce: String,
)

/**
 * A sealed voter verification record (seam-runtime #1687, `voter-verification.v1.md`): the voter's own
 * proof of possession plus where it was cast and when the runtime accepted it. [method] is `pop` or
 * `cp_signed` (never the proto enum name); [contentDigest] is the 32 raw bytes of
 * `seam-vote-content-v1`; [signerCertificate] is empty for `pop`.
 */
data class VoterVerification(
    val method: String,
    val principal: String,
    val contentDigest: ByteArray,
    val issuedAtMs: ULong,
    val expiresAtMs: ULong,
    val signature: ByteArray,
    val signerCertificate: ByteArray = ByteArray(0),
    val tenant: String,
    val namespace: String,
    val sessionId: String,
    val openedAtMillis: ULong,
    val issuer: String,
    val audience: String,
    val acceptedAtMs: ULong,
)

/**
 * One entry of a commitment's sealed explanation, framed by [SeamCrypto.explanationDigest]. [kind] is
 * the lowercase word `vote`, `evaluation`, `objection` or `ballot` (exactly; never the proto enum
 * name). [confidence] and [rationaleRef] are `null` when absent — an absent confidence and a stated
 * `0.0` are different bytes, which is the point of the digest. [voterVerification] is `null` when
 * absent (evaluations); the runtime seals one on every vote, ballot and objection (#1687).
 */
data class ExplanationEntry(
    val kind: String,
    val participant: String,
    val proposalId: String,
    val value: String,
    val reason: String,
    val confidence: Double? = null,
    val rationaleRef: String? = null,
    val voterVerification: VoterVerification? = null,
)

/**
 * The commitment fields `seam-commitment-digest:v4` binds. [committer] is the verified AID that
 * committed (empty when absent). [selectionDigest] (field 9) and [certificateDigest] (field 10) are
 * `null` when absent — every record runtime 0.87.0 seals — and exactly 32 bytes when present.
 * [supersedes] is `null` when ABSENT, which v4 frames as `0x00` — a
 * different digest from a present empty string (`0x01 ‖ F("")`). Field 8 (the explanation digest) is resolved from [explanation] and
 * [explanationDigest] (32 raw bytes) — see [SeamCrypto.verifyTct].
 */
data class Commitment(
    val id: String,
    val action: String,
    val authority: String,
    val supersedes: String?,
    val authMethod: String,
    val trustBasis: String,
    val committer: String = "",
    val explanation: List<ExplanationEntry>? = null,
    val explanationDigest: ByteArray? = null,
    val selectionDigest: ByteArray? = null,
    val certificateDigest: ByteArray? = null,
)

/**
 * The inputs [SeamCrypto.callSigV3Payload] frames. Every string is signed as its UTF-8 bytes; an
 * absent optional field is the empty string (the default), signed verbatim rather than skipped.
 * [ticket] is the admission ticket's RAW bytes. [subjects] are signed in the order given — never
 * deduped, never sorted. [features] are (key, value) pairs in any order; they are signed sorted by
 * (key bytes, value bytes).
 *
 * The v2 fields carry no defaults on purpose, as in Python: a forgotten `toolName`/`agentId` should
 * fail to compile, not produce a signature the runtime rejects.
 */
data class CallSigV3Fields(
    val ticket: ByteArray,
    val toolInputDigest: String,
    val toolName: String,
    val agentId: String,
    val subject: String = "",
    val subjects: List<String> = emptyList(),
    val clientRequestId: String = "",
    val sessionId: String = "",
    val features: List<Pair<String, String>> = emptyList(),
)

object SeamCrypto {
    /**
     * Domain tag of the `Authorize` per-call proof-of-possession, v3 (#197). The distinct tag means a
     * v2 signature can NEVER verify as a v3 one, so SDK/runtime version skew is a clean rejection
     * rather than a parse ambiguity. Bump it only in lockstep with the runtime.
     */
    const val CALL_SIG_V3_CONTEXT = "seam-authorize-call-v3"

    private val PROOF_DOMAIN = "aitp-pinned-key-v1".toByteArray(Charsets.UTF_8) + byteArrayOf(0)
    private val gson = Gson()
    private val mapType = object : TypeToken<Map<String, Any?>>() {}.type

    private fun b64urlNoPad(b: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    private fun b64urlDecode(s: String): ByteArray {
        val pad = (4 - s.length % 4) % 4
        return Base64.getUrlDecoder().decode(s + "=".repeat(pad))
    }

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

    private fun ed25519Pub(seed: ByteArray): ByteArray =
        Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded

    private fun ed25519Sign(seed: ByteArray, msg: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(seed, 0))
        signer.update(msg, 0, msg.size)
        return signer.generateSignature()
    }

    private fun ed25519Verify(pub: ByteArray, msg: ByteArray, sig: ByteArray): Boolean =
        try {
            val verifier = Ed25519Signer()
            verifier.init(false, Ed25519PublicKeyParameters(pub, 0))
            verifier.update(msg, 0, msg.size)
            verifier.verifySignature(sig)
        } catch (e: RuntimeException) {
            false
        }

    /** The agent's `aid:pubkey:ed25519:` identity for a 32-byte Ed25519 public key. */
    fun aidFromPubkey(pub: ByteArray): String = "aid:pubkey:ed25519:" + b64urlNoPad(pub)

    private fun aidToPubkey(aid: String): ByteArray {
        for (p in listOf("aid:pubkey:ed25519:", "aid:pubkey:")) {
            if (aid.startsWith(p)) return b64urlDecode(aid.substring(p.length))
        }
        throw IllegalArgumentException("unsupported AID form: $aid")
    }

    /** Domain tag of the PoP admission `message_id`: `derivedUuid(tag, nonce_ascii)`. */
    const val POP_MESSAGE_ID_TAG = "seam-pop-mid-v1"

    /**
     * Deterministic, v4-shaped UUID: the first 16 bytes of `SHA-256(tag ‖ 0x00 ‖ input)` with the
     * version nibble set to 4 and the variant bits to `10`, lowercase and hyphenated. The `0x00`
     * separates tag from input, so no (tag, input) pair collides with another by shifting bytes
     * across the boundary. Pinned by `derived_uuid` in `conformance/vectors.json`.
     */
    fun derivedUuid(tag: String, input: ByteArray): String {
        val h = sha256(tag.toByteArray(Charsets.UTF_8) + byteArrayOf(0) + input)
        h[6] = ((h[6].toInt() and 0x0f) or 0x40).toByte()
        h[8] = ((h[8].toInt() and 0x3f) or 0x80).toByte()
        val sb = StringBuilder(36)
        for (i in 0 until 16) {
            if (i == 4 || i == 6 || i == 8 || i == 10) sb.append('-')
            sb.append("%02x".format(h[i].toInt() and 0xff))
        }
        return sb.toString()
    }

    /** The admission `message_id`: `derivedUuid("seam-pop-mid-v1", nonce_ascii)`. */
    fun popMessageId(popNonce: String): String =
        derivedUuid(POP_MESSAGE_ID_TAG, popNonce.toByteArray(Charsets.US_ASCII))

    /** Build the pinned-key admission presentation the Seam server verifies. */
    fun buildPresentation(agentSeed: ByteArray, receiverAid: String, popNonce: String, nowMs: Long): Presentation {
        val pub = ed25519Pub(agentSeed)
        val senderAid = aidFromPubkey(pub)
        val mid = popMessageId(popNonce)
        val timestamp = nowMs / 1000

        val buf = ByteArrayOutputStream()
        buf.writeBytes(PROOF_DOMAIN)
        buf.writeBytes(senderAid.toByteArray(Charsets.UTF_8)); buf.write(0)
        buf.writeBytes(receiverAid.toByteArray(Charsets.UTF_8)); buf.write(0)
        buf.writeBytes(mid.toByteArray(Charsets.UTF_8)); buf.write(0)
        buf.writeBytes(timestamp.toString().toByteArray(Charsets.US_ASCII)); buf.write(0)
        buf.writeBytes(b64urlDecode(popNonce))

        val proof = ed25519Sign(agentSeed, sha256(buf.toByteArray()))
        return Presentation(
            senderAid,
            Descriptor("pinned_key", senderAid, b64urlNoPad(proof), b64urlNoPad(pub)),
            mid,
            timestamp,
            popNonce,
        )
    }

    /** The `kind` words the explanation digest frames — lowercase ASCII, exactly; never the proto enum name. */
    val EXPLANATION_KINDS: List<String> = listOf("vote", "evaluation", "objection", "ballot")

    private fun be64(n: Long): ByteArray = ByteBuffer.allocate(8).putLong(n).array()

    /** `F(x) = be64(len(x)) ‖ x`. */
    private fun ByteArrayOutputStream.frame(b: ByteArray) {
        writeBytes(be64(b.size.toLong()))
        writeBytes(b)
    }

    /** The voter-verification `method` words the explanation digest frames — lowercase, exactly. */
    val VOTER_VERIFICATION_METHODS: List<String> = listOf("pop", "cp_signed")

    /** Domain tag of the explanation digest. */
    const val EXPLANATION_DIGEST_DOMAIN = "seam-explanation-digest:v2"

    /**
     * `seam-explanation-digest:v2` over a sealed explanation, in sealed order (32 raw bytes):
     * `SHA-256(F("seam-explanation-digest:v2") ‖ be64(count) ‖ Σ ENTRY)`, with
     * `ENTRY = F(kind) ‖ F(participant) ‖ F(proposal_id) ‖ F(value) ‖ F(reason) ‖ CONF ‖ REF ‖ VV`,
     * `CONF = 0x00 | 0x01 ‖ be64(IEEE-754 bits)`, `REF = 0x00 | 0x01 ‖ F(rationale_ref)`,
     * `VV = 0x00 | 0x01 ‖ F(method) ‖ F(principal) ‖ F(content_digest) ‖ be64(issued_at_ms) ‖
     * be64(expires_at_ms) ‖ F(signature) ‖ F(signer_certificate) ‖ F(tenant) ‖ F(namespace) ‖
     * F(session_id) ‖ be64(opened_at_millis) ‖ F(issuer) ‖ F(audience) ‖ be64(accepted_at_ms)`. Never
     * sorts, never de-duplicates.
     *
     * Throws [IllegalArgumentException] on an unknown kind, a non-canonical confidence (NaN, ±inf,
     * outside `[0.0, 1.0]`, or `-0.0`), an unknown voter-verification method, or a content digest that
     * is not 32 bytes, rather than hashing it. Normative:
     * `seam-runtime/docs/specs/seam-commitment-digest.v4.md`.
     */
    fun explanationDigest(entries: List<ExplanationEntry>): ByteArray {
        val out = ByteArrayOutputStream()
        out.frame(EXPLANATION_DIGEST_DOMAIN.toByteArray(Charsets.UTF_8))
        out.writeBytes(be64(entries.size.toLong()))
        for (e in entries) {
            require(e.kind in EXPLANATION_KINDS) { "unknown explanation kind ${e.kind}" }
            out.frame(e.kind.toByteArray(Charsets.UTF_8))
            out.frame(e.participant.toByteArray(Charsets.UTF_8))
            out.frame(e.proposalId.toByteArray(Charsets.UTF_8))
            out.frame(e.value.toByteArray(Charsets.UTF_8))
            out.frame(e.reason.toByteArray(Charsets.UTF_8))
            val conf = e.confidence
            if (conf == null) {
                out.write(0)
            } else {
                val bits = java.lang.Double.doubleToRawLongBits(conf)
                // `bits < 0` is the sign bit: refuses -0.0 (and any negative), which `conf >= 0.0` admits.
                require(conf.isFinite() && conf >= 0.0 && conf <= 1.0 && bits >= 0L) {
                    "non-canonical confidence $conf"
                }
                out.write(1)
                out.writeBytes(be64(bits))
            }
            val ref = e.rationaleRef
            if (ref == null) {
                out.write(0)
            } else {
                out.write(1)
                out.frame(ref.toByteArray(Charsets.UTF_8))
            }
            val v = e.voterVerification
            if (v == null) {
                out.write(0)
            } else {
                require(v.method in VOTER_VERIFICATION_METHODS) {
                    "unknown voter verification method ${v.method}"
                }
                require(v.contentDigest.size == 32) { "voter verification content_digest must be 32 bytes" }
                out.write(1)
                out.frame(v.method.toByteArray(Charsets.UTF_8))
                out.frame(v.principal.toByteArray(Charsets.UTF_8))
                out.frame(v.contentDigest)
                out.writeBytes(be64(v.issuedAtMs.toLong()))
                out.writeBytes(be64(v.expiresAtMs.toLong()))
                out.frame(v.signature)
                out.frame(v.signerCertificate)
                out.frame(v.tenant.toByteArray(Charsets.UTF_8))
                out.frame(v.namespace.toByteArray(Charsets.UTF_8))
                out.frame(v.sessionId.toByteArray(Charsets.UTF_8))
                out.writeBytes(be64(v.openedAtMillis.toLong()))
                out.frame(v.issuer.toByteArray(Charsets.UTF_8))
                out.frame(v.audience.toByteArray(Charsets.UTF_8))
                out.writeBytes(be64(v.acceptedAtMs.toLong()))
            }
        }
        return sha256(out.toByteArray())
    }

    /**
     * The explanation digest a commitment binds as field 8, checked when the entries are present
     * (spec §Verification step 1). With [Commitment.explanation]: recomputed from the entries, and if
     * [Commitment.explanationDigest] is ALSO given the two must agree — otherwise
     * [IllegalArgumentException]. With only the published digest: used as published (verifies *who*
     * and *what*, not *why*). With neither: the digest of the empty explanation.
     */
    internal fun commitmentExplanationDigest(c: Commitment): ByteArray {
        val published = c.explanationDigest
        val entries = c.explanation ?: return published ?: explanationDigest(emptyList())
        val computed = explanationDigest(entries)
        require(published == null || MessageDigest.isEqual(published, computed)) {
            "explanation_digest does not match the explanation entries"
        }
        return computed
    }

    /** Domain tag of the commitment digest. */
    const val COMMITMENT_DIGEST_DOMAIN = "seam-commitment-digest:v4"

    /** The one grant a commitment self-attestation carries. */
    const val ATTESTATION_GRANT = "aitp.attestation"

    /** The `ext` namespace the commitment statement rides under. */
    const val COMMITMENT_EXT_NAMESPACE = "com.zer07labs.seam"

    /** The statement `type` inside [COMMITMENT_EXT_NAMESPACE]. */
    const val COMMITMENT_STATEMENT = "seam:commitment"

    /**
     * `seam-commitment-digest:v4` (hex): SHA-256 over a **length-prefixed** framing of a domain tag
     * plus the commitment fields — each field preceded by its 8-byte big-endian length. Mirrors the
     * runtime byte-for-byte, and mirrors the Go/Java/Python/TypeScript shims. v3 is deleted, not
     * dual-verified. Normative: `seam-runtime/docs/specs/seam-commitment-digest.v4.md`. `supersedes`
     * carries a presence byte — `0x00` when absent (`null`), `0x01 ‖ F(s)` when present. v4 (#1687)
     * binds the v2 explanation digest as field 8 and appends two always-framed slots: field 9 (selection
     * digest) and field 10 (Gate certificate digest), each `0x00` when absent or `0x01 ‖ be64(32) ‖ 32
     * raw bytes`; a present slot that is not 32 bytes throws [IllegalArgumentException].
     *
     * **The length prefixes are not decoration and must never be "simplified" to a separator.** The
     * fields are arbitrary text that may itself contain NUL — UTF-8 permits U+0000, and it survives
     * the JSON/prost decision path — so with a `\u0000` separator the tuples `("a\u0000b","c")` and
     * `("a","b\u0000c")` produce IDENTICAL preimages, and therefore identical digests. That would
     * let one Commitment verify under another's TCT: an attacker who controls a field boundary could
     * shift bytes across it and reuse a signature that was never issued for their artifact.
     * Length-prefixing makes the digest injective over the field tuple regardless of content.
     *
     * The same rationale is recorded in the runtime's `seam-trust-aitp/src/lib.rs`. It is written out
     * here because this comment is the only thing standing between a future maintainer and a
     * "cleanup" that silently breaks artifact binding.
     *
     * Field order is also load-bearing and must match the runtime exactly: domain, id, action,
     * authority, supersedes, auth_method, trust_basis, committer, explanation_digest (the 32 RAW
     * bytes, not hex — see [commitmentExplanationDigest]). Binding `authMethod`/`trustBasis`/
     * `committer` is what makes the artifact attest *who* committed it and *how* they authed, and the
     * explanation digest binds *why*. `ConformanceTest` asserts every one of these is bound.
     */
    internal fun seamCommitmentDigest(c: Commitment): String {
        require(c.selectionDigest == null || c.selectionDigest.size == 32) {
            "selection_digest must be 32 bytes when present"
        }
        require(c.certificateDigest == null || c.certificateDigest.size == 32) {
            "certificate_digest must be 32 bytes when present"
        }
        val explanation = commitmentExplanationDigest(c)
        val h = ByteArrayOutputStream()
        h.frame(COMMITMENT_DIGEST_DOMAIN.toByteArray(Charsets.UTF_8))
        h.frame(c.id.toByteArray(Charsets.UTF_8))
        h.frame(c.action.toByteArray(Charsets.UTF_8))
        h.frame(c.authority.toByteArray(Charsets.UTF_8))
        val supersedes = c.supersedes
        if (supersedes == null) {
            h.write(0x00)
        } else {
            h.write(0x01)
            h.frame(supersedes.toByteArray(Charsets.UTF_8))
        }
        h.frame(c.authMethod.toByteArray(Charsets.UTF_8))
        h.frame(c.trustBasis.toByteArray(Charsets.UTF_8))
        h.frame(c.committer.toByteArray(Charsets.UTF_8))
        h.frame(explanation)
        for (slot in listOf(c.selectionDigest, c.certificateDigest)) {
            if (slot == null) {
                h.write(0x00)
            } else {
                h.write(0x01)
                h.frame(slot)
            }
        }
        return sha256(h.toByteArray()).joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    /**
     * Independently verify a sealed commitment's rooted TCT — zero server trust, stock crypto only:
     * the EdDSA JWS (`typ` `aitp-tct+jwt`) against the pinned issuer AID's key; the self-issued
     * claims (`iss == sub == aud == issuerAid`); `exp`; that `grants` is exactly
     * `["aitp.attestation"]`; and that `ext` is exactly
     * `{"com.zer07labs.seam":{"type":"seam:commitment","commitment_digest":<hex>}}` with the hex equal
     * to the recomputed `seam-commitment-digest:v4` of this exact commitment (the decided content, the
     * committer, and the sealed explanation). A header or payload whose JSON repeats an object key at
     * any depth is refused: Gson would keep one of the two, and another parser might keep the other. Any malformed/forged input fails closed (returns false),
     * never throws — including explanation entries that disagree with the published
     * `explanationDigest`, an unknown kind, or a non-canonical confidence.
     */
    fun verifyTct(issuerAid: String, tctJws: String, commitment: Commitment, nowS: Long): Boolean {
        return try {
            val parts = tctJws.split(".")
            if (parts.size != 3) return false
            val pub = try {
                aidToPubkey(issuerAid)
            } catch (e: RuntimeException) {
                return false
            }
            if (pub.size != 32) return false
            if (!ed25519Verify(pub, "${parts[0]}.${parts[1]}".toByteArray(Charsets.US_ASCII), b64urlDecode(parts[2]))) {
                return false
            }
            val headerJson = String(b64urlDecode(parts[0]), Charsets.UTF_8)
            val payloadJson = String(b64urlDecode(parts[1]), Charsets.UTF_8)
            if (hasDuplicateKey(headerJson) || hasDuplicateKey(payloadJson)) return false
            val header: Map<String, Any?> = gson.fromJson(headerJson, mapType) ?: return false
            val payload: Map<String, Any?> = gson.fromJson(payloadJson, mapType) ?: return false
            if (header["alg"] != "EdDSA" || header["typ"] != "aitp-tct+jwt") return false
            if (!(payload["iss"] == issuerAid && payload["sub"] == issuerAid && payload["aud"] == issuerAid)) {
                return false
            }
            val exp = payload["exp"] as? Number ?: return false
            if (nowS >= exp.toLong()) return false // RFC 7519: reject at/after expiry
            val grants = payload["grants"] as? List<*> ?: return false
            if (grants.size != 1 || grants[0] != ATTESTATION_GRANT) return false
            val ext = payload["ext"] as? Map<*, *> ?: return false
            if (ext.size != 1) return false
            val stmt = ext[COMMITMENT_EXT_NAMESPACE] as? Map<*, *> ?: return false
            if (stmt.size != 2 || stmt["type"] != COMMITMENT_STATEMENT) return false
            val digest = stmt["commitment_digest"] as? String ?: return false
            digest == seamCommitmentDigest(commitment)
        } catch (e: RuntimeException) {
            false
        }
    }

    /**
     * True when [json] repeats an object key at any depth — or is not a single well-formed JSON
     * value, which fails closed the same way.
     */
    internal fun hasDuplicateKey(json: String): Boolean =
        try {
            JsonReader(StringReader(json)).use { r ->
                r.strictness = Strictness.STRICT
                scanForDuplicate(r) || r.peek() != JsonToken.END_DOCUMENT
            }
        } catch (e: IOException) {
            true
        } catch (e: RuntimeException) {
            true
        }

    private fun scanForDuplicate(r: JsonReader): Boolean {
        when (r.peek()) {
            JsonToken.BEGIN_OBJECT -> {
                r.beginObject()
                val seen = HashSet<String>()
                while (r.hasNext()) {
                    if (!seen.add(r.nextName()) || scanForDuplicate(r)) return true
                }
                r.endObject()
            }
            JsonToken.BEGIN_ARRAY -> {
                r.beginArray()
                while (r.hasNext()) {
                    if (scanForDuplicate(r)) return true
                }
                r.endArray()
            }
            else -> r.skipValue()
        }
        return false
    }

    /**
     * The exact bytes [callSigV3] signs: `frame(context) | frame(ticket) | frame(tool_input_digest) |
     * frame(tool_name) | frame(agent_id) | frame(subject) | frame(u32le(n_subjects)) |
     * frame(subject_i)... | frame(client_request_id) | frame(session_id) | frame(u32le(n_features)) |
     * (frame(key) | frame(value))...`, with `frame(x) = u32le(len_bytes(x)) | x` — the counts are
     * themselves framed.
     *
     * Features are sorted by their UTF-8 **bytes**, compared unsigned. `String.compareTo` would be
     * wrong here: it orders by UTF-16 code unit, which disagrees with byte order for
     * supplementary-plane vs. high-BMP characters.
     *
     * Pinned by `conformance/call_sig_v3_payload_vector.json`. Public so a caller can reproduce or
     * verify the binding without re-deriving it from prose.
     */
    fun callSigV3Payload(f: CallSigV3Fields): ByteArray {
        val out = ByteArrayOutputStream()
        fun frame(b: ByteArray) {
            out.writeBytes(u32le(b.size))
            out.writeBytes(b)
        }
        frame(CALL_SIG_V3_CONTEXT.toByteArray(Charsets.UTF_8))
        frame(f.ticket)
        frame(f.toolInputDigest.toByteArray(Charsets.UTF_8))
        frame(f.toolName.toByteArray(Charsets.UTF_8))
        frame(f.agentId.toByteArray(Charsets.UTF_8))
        frame(f.subject.toByteArray(Charsets.UTF_8))
        frame(u32le(f.subjects.size))
        for (s in f.subjects) frame(s.toByteArray(Charsets.UTF_8))
        frame(f.clientRequestId.toByteArray(Charsets.UTF_8))
        frame(f.sessionId.toByteArray(Charsets.UTF_8))

        val features = f.features
            .map { (k, v) -> k.toByteArray(Charsets.UTF_8) to v.toByteArray(Charsets.UTF_8) }
            .sortedWith { a, b ->
                val c = Arrays.compareUnsigned(a.first, b.first)
                if (c != 0) c else Arrays.compareUnsigned(a.second, b.second)
            }
        frame(u32le(features.size))
        for ((k, v) in features) {
            frame(k)
            frame(v)
        }
        return out.toByteArray()
    }

    /**
     * The per-call proof-of-possession for `Authorize`: Ed25519 by the agent key (32-byte seed) over
     * [callSigV3Payload], returned as the raw 64-byte signature (the `call_sig` bytes field), as
     * Python's `call_sig` does.
     */
    fun callSigV3(agentSeed: ByteArray, f: CallSigV3Fields): ByteArray {
        require(agentSeed.size == 32) { "agent seed must be 32 bytes" }
        return ed25519Sign(agentSeed, callSigV3Payload(f))
    }

    private fun u32le(n: Int): ByteArray =
        ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(n).array()
    // ── Enrolment proof-of-possession (#205) ────────────────────────────────────────────────────

    /**
     * Domain tag of the enrolment proof-of-possession (seam-runtime #1157): the subject AID's own
     * consent, by the key it embeds, to ONE `EnrollTenant` binding. Bump it only in lockstep with the
     * runtime. v2 (#1687) signs the `participant_id` a `voter` enrolment binds (`""` for every other
     * kind); v1 is refused by runtime 0.87.0 and is gone.
     */
    const val ENROLL_POP_V2_CONTEXT = "seam-enroll-pop-v2"

    private val ENROLL_POP_NONCE = Regex("[A-Za-z0-9_-]{1,128}")

    /**
     * The exact bytes [enrollPop] signs: `frame(context) | frame(subject_aid) | frame(tenant) |
     * frame(namespace) | frame(participant_id) | frame(u64le(issued_at_ms)) | frame(nonce)`, with
     * `frame(x) = u32le(len_bytes(x)) | x`. `issued_at_ms` is 8 raw little-endian bytes, not ASCII
     * decimal.
     *
     * Pinned by `conformance/enroll_pop_v2_payload_vector.json`. Public so a caller can reproduce or
     * verify the binding without re-deriving it from prose.
     */
    fun enrollPopPayload(f: EnrollPopFields): ByteArray {
        val out = ByteArrayOutputStream()
        fun frame(b: ByteArray) {
            out.writeBytes(leBytes(b.size.toLong(), 4))
            out.writeBytes(b)
        }
        frame(ENROLL_POP_V2_CONTEXT.toByteArray(Charsets.UTF_8))
        frame(f.subjectAid.toByteArray(Charsets.UTF_8))
        frame(f.tenant.toByteArray(Charsets.UTF_8))
        frame(f.namespace.toByteArray(Charsets.UTF_8))
        frame(f.participantId.toByteArray(Charsets.UTF_8))
        frame(leBytes(f.issuedAtMs.toLong(), 8))
        frame(f.nonce.toByteArray(Charsets.UTF_8))
        return out.toByteArray()
    }

    /** Refuse a nonce the runtime would refuse: 1..=128 characters of `[A-Za-z0-9_-]`. */
    fun validateEnrollPopNonce(nonce: String) {
        require(ENROLL_POP_NONCE.matches(nonce)) {
            "enrol pop nonce must be 1..=128 characters of [A-Za-z0-9_-]"
        }
    }

    /**
     * The enrolment proof-of-possession: Ed25519 by the agent key (32-byte seed) over
     * [enrollPopPayload], returned as the raw 64-byte signature (the `EnrollPop.signature` bytes field;
     * the REST body carries it as unpadded base64url). Refuses a `subjectAid` that is not the seed's
     * own AID — a proof can only speak for the key that signs it — and a nonce the runtime would
     * refuse.
     */
    fun enrollPop(agentSeed: ByteArray, f: EnrollPopFields): ByteArray {
        require(agentSeed.size == 32) { "agent seed must be 32 bytes" }
        validateEnrollPopNonce(f.nonce)
        val own = aidFromPubkey(ed25519Pub(agentSeed))
        require(f.subjectAid == own) { "subjectAid ${f.subjectAid} is not this seed's AID $own" }
        return ed25519Sign(agentSeed, enrollPopPayload(f))
    }

    private fun leBytes(v: Long, n: Int): ByteArray = ByteArray(n) { i -> (v ushr (8 * i)).toByte() }

    // ── Enrolment proof, agent side + REST form (#214) ──────────────────────────────────────────

    private val random = SecureRandom()

    /** A fresh nonce: 16 random bytes as unpadded base64url — 22 characters, inside the contract. */
    fun newEnrollPopNonce(): String = b64urlNoPad(ByteArray(16).also(random::nextBytes))

    /**
     * This agent's consent to being enrolled under [tenant]/[namespace]: the `pop` an operator sends
     * with `EnrollTenant` (gRPC: the raw fields; REST: [EnrollProof.toRest]). Required for enrolment by
     * a tenant-scoped operator token. The subject AID is DERIVED from [agentSeed] — a proof can only
     * ever speak for the key that signs it — and the nonce is validated first.
     *
     * [issuedAtMs] defaults to now and [nonce] to 16 fresh random bytes as 22 base64url characters;
     * both are overridable for tests. The runtime accepts the proof for 5 minutes (and up to 60 s ahead
     * of its clock), so mint it just before the enrolment call. [participantId] is the participant a
     * `voter` enrolment binds (`""`, the default, for every other kind); the operator sends the same
     * value as `EnrollTenantRequest.participant_id`. The counterpart of Python's
     * `Agent.enrolment_proof` and TypeScript's `Agent.enrolmentProof`.
     */
    fun enrolmentProof(
        agentSeed: ByteArray,
        tenant: String,
        namespace: String,
        issuedAtMs: ULong = System.currentTimeMillis().toULong(),
        nonce: String = newEnrollPopNonce(),
        participantId: String = "",
    ): EnrollProof {
        require(agentSeed.size == 32) { "agent seed must be 32 bytes" }
        val subject = aidFromPubkey(ed25519Pub(agentSeed))
        val sig =
            enrollPop(agentSeed, EnrollPopFields(subject, tenant, namespace, issuedAtMs, nonce, participantId))
        return EnrollProof(issuedAtMs, nonce, sig)
    }
    // ── The per-request credential (`seam-request-call-v1`, #508) ──────────────────────────────

    /**
     * Domain tag of the per-request credential — deliberately distinct from the `Authorize` call_sig
     * tag, so a captured call_sig is never spendable as a request credential.
     */
    const val REQUEST_SIG_CONTEXT = "seam-request-call-v1"

    /**
     * The exact bytes [requestSig] signs: `frame(context) | frame(ticket) | frame(rpc_full_name) |
     * frame(resource_id) | frame(body_digest)`, with `frame(x) = u32le(len_bytes(x)) | x`.
     * [rpcFullName] is the gRPC full method path on both transports. A bodyless read binds its id as
     * [resourceId] and an empty [bodyDigest]; a bodied verb over gRPC binds an empty [resourceId] and
     * [bodyDigest] of the request message's exact serialized bytes.
     *
     * Pinned by `conformance/request_sig_payload_vector.json`.
     */
    fun requestSigPayload(ticket: ByteArray, rpcFullName: String, resourceId: String, bodyDigest: String): ByteArray {
        val out = ByteArrayOutputStream()
        for (p in listOf(
            REQUEST_SIG_CONTEXT.toByteArray(Charsets.UTF_8),
            ticket,
            rpcFullName.toByteArray(Charsets.UTF_8),
            resourceId.toByteArray(Charsets.UTF_8),
            bodyDigest.toByteArray(Charsets.UTF_8),
        )) {
            out.writeBytes(u32le(p.size))
            out.writeBytes(p)
        }
        return out.toByteArray()
    }

    /** Ed25519 by the agent key (32-byte seed) over [requestSigPayload]: the raw 64-byte `x-seam-call-sig-bin`. */
    fun requestSig(
        agentSeed: ByteArray,
        ticket: ByteArray,
        rpcFullName: String,
        resourceId: String,
        bodyDigest: String,
    ): ByteArray {
        require(agentSeed.size == 32) { "agent seed must be 32 bytes" }
        return ed25519Sign(agentSeed, requestSigPayload(ticket, rpcFullName, resourceId, bodyDigest))
    }

    /**
     * `"sha256:" + lowercase hex(SHA-256(body))` over the request message's exact wire bytes — never a
     * re-serialization taken after the fact.
     */
    fun bodyDigest(body: ByteArray): String =
        "sha256:" + sha256(body).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    // ── Voter proof-of-possession: seam-voter-pop-v1 (#1687, seam-sdk#359) ─────────────────────
    // A vote, ballot or objection must carry the voter's OWN proof, signed by its enrolled `voter`
    // key (seam-runtime docs/specs/voter-verification.v1.md); runtime 0.87.0 refuses one without
    // (`voter_proof_required`). Byte-exact against conformance/voter_pop_v1_payload_vector.json; the
    // twins are Python `seam_sdk.crypto`, TypeScript `crypto.ts` and Java `SeamCrypto`.

    /** Domain tag of the voter proof's signed payload. */
    const val VOTER_POP_V1_DOMAIN = "seam-voter-pop-v1"

    /** Domain tag of the vote content digest. */
    const val VOTE_CONTENT_V1_DOMAIN = "seam-vote-content-v1"

    /** The longest window the runtime accepts: `expires - issued <= 15 min`. */
    const val VOTER_POP_MAX_LIFETIME_MS: Long = 15L * 60 * 1000

    /** The clock skew the runtime allows: `issued <= accepted + 60 s`. */
    const val VOTER_POP_MAX_SKEW_MS: Long = 60L * 1000

    /** The default lifetime of a freshly signed proof (5 minutes). */
    const val VOTER_POP_DEFAULT_LIFETIME_MS: Long = 5L * 60 * 1000

    /** The audience a voter proof names unless told otherwise. */
    const val VOTER_POP_DEFAULT_AUDIENCE = "seam-runtime"

    /** The explanation kinds a voter must sign: each carries a sealed voter record; an evaluation never does. */
    val VOTER_VERIFIED_KINDS: List<String> = listOf("vote", "ballot", "objection")

    private val MAX_LIFETIME = VOTER_POP_MAX_LIFETIME_MS.toULong()
    private val MAX_SKEW = VOTER_POP_MAX_SKEW_MS.toULong()

    private fun ByteArrayOutputStream.frameLE(b: ByteArray) {
        writeBytes(u32le(b.size))
        writeBytes(b)
    }

    /**
     * `seam-vote-content-v1`: what the vote is about (32 raw bytes). [content] is the accepted
     * proposal's `option` (vote, objection), the approval request's `action` (ballot), or
     * `votes[0].value` (one-shot); [participants] / [onBehalfOf] as opened, in request order; [context]
     * the sealed provenance in sealed order. [features] is the one-shot `RunDecisionRequest.features` in
     * any order — framed sorted by UTF-8 key bytes, and a repeated key is REFUSED, never deduplicated; a
     * session vote has none. [policy] is the session's bound `vote_policy`; `null` frames `0x00` (the
     * one-shot, server-resolved).
     */
    fun voteContentDigest(
        mode: String,
        proposalId: String,
        content: String,
        participants: List<String> = emptyList(),
        onBehalfOf: List<String> = emptyList(),
        context: List<VoteContext> = emptyList(),
        features: List<Pair<String, String>> = emptyList(),
        policy: VotePolicyRef? = null,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.frameLE(VOTE_CONTENT_V1_DOMAIN.toByteArray(Charsets.UTF_8))
        out.frameLE(mode.toByteArray(Charsets.UTF_8))
        out.frameLE(proposalId.toByteArray(Charsets.UTF_8))
        out.frameLE(content.toByteArray(Charsets.UTF_8))
        out.frameLE(u32le(participants.size))
        participants.forEach { out.frameLE(it.toByteArray(Charsets.UTF_8)) }
        out.frameLE(u32le(onBehalfOf.size))
        onBehalfOf.forEach { out.frameLE(it.toByteArray(Charsets.UTF_8)) }
        out.frameLE(u32le(context.size))
        for (c in context) {
            out.frameLE(c.ctxRef.toByteArray(Charsets.UTF_8))
            out.frameLE(c.contentHash.toByteArray(Charsets.UTF_8))
        }
        val feats = features.map { (k, v) -> k.toByteArray(Charsets.UTF_8) to v.toByteArray(Charsets.UTF_8) }
            .sortedWith { a, b -> Arrays.compareUnsigned(a.first, b.first) }
        for (i in 1 until feats.size) {
            require(!feats[i - 1].first.contentEquals(feats[i].first)) {
                "feature key \"${String(feats[i].first, Charsets.UTF_8)}\" is given twice (refused, never deduplicated)"
            }
        }
        out.frameLE(u32le(feats.size))
        for ((k, v) in feats) {
            out.frameLE(k)
            out.frameLE(v)
        }
        if (policy == null) {
            out.write(0)
        } else {
            val rules = policy.rulesDigest
            require(rules.size == 32) { "rulesDigest must be 32 bytes, got ${rules.size}" }
            out.write(1)
            out.frameLE(policy.policyVersion.toByteArray(Charsets.UTF_8))
            out.frameLE(rules)
        }
        return sha256(out.toByteArray())
    }

    /**
     * The frozen `entry_bytes` a voter signs (`F(x) = be64(len) ‖ x`): `F(kind) ‖ F(participant) ‖
     * F(proposal_id) ‖ F(value) ‖ F(reason) ‖ opt_conf ‖ opt_ref`. A stated `-0.0` confidence folds to
     * `+0.0`; a non-finite one is refused. Frozen: an explanation-digest bump never changes it.
     */
    fun voteEntryBytes(e: VoteEntry): ByteArray {
        require(e.kind in EXPLANATION_KINDS) { "unknown explanation kind \"${e.kind}\"" }
        val out = ByteArrayOutputStream()
        out.frame(e.kind.toByteArray(Charsets.UTF_8))
        out.frame(e.participant.toByteArray(Charsets.UTF_8))
        out.frame(e.proposalId.toByteArray(Charsets.UTF_8))
        out.frame(e.value.toByteArray(Charsets.UTF_8))
        out.frame(e.reason.toByteArray(Charsets.UTF_8))
        val c = e.confidence
        if (c == null) {
            out.write(0)
        } else {
            require(c.isFinite()) { "non-finite confidence $c" }
            out.write(1)
            out.writeBytes(be64((c + 0.0).toRawBits())) // -0.0 + 0.0 == +0.0
        }
        val r = e.rationaleRef
        if (r == null) {
            out.write(0)
        } else {
            out.write(1)
            out.frame(r.toByteArray(Charsets.UTF_8))
        }
        return out.toByteArray()
    }

    /**
     * The exact bytes a voter proof signs (`framed(x) = u32le(len) ‖ x`): domain, issuer, audience,
     * tenant, namespace, sessionId, u64le(openedAtMillis), voterAid, contentDigest[32], u64le(issuedAtMs),
     * u64le(expiresAtMs), entryBytes.
     */
    fun voterPopPayload(
        target: VoterPopTarget,
        voterAid: String,
        contentDigest: ByteArray,
        issuedAtMs: ULong,
        expiresAtMs: ULong,
        entryBytes: ByteArray,
    ): ByteArray {
        require(contentDigest.size == 32) { "contentDigest must be 32 bytes, got ${contentDigest.size}" }
        val out = ByteArrayOutputStream()
        out.frameLE(VOTER_POP_V1_DOMAIN.toByteArray(Charsets.UTF_8))
        out.frameLE(target.issuer.toByteArray(Charsets.UTF_8))
        out.frameLE(target.audience.toByteArray(Charsets.UTF_8))
        out.frameLE(target.tenant.toByteArray(Charsets.UTF_8))
        out.frameLE(target.namespace.toByteArray(Charsets.UTF_8))
        out.frameLE(target.sessionId.toByteArray(Charsets.UTF_8))
        out.frameLE(leBytes(target.openedAtMillis.toLong(), 8))
        out.frameLE(voterAid.toByteArray(Charsets.UTF_8))
        out.frameLE(contentDigest)
        out.frameLE(leBytes(issuedAtMs.toLong(), 8))
        out.frameLE(leBytes(expiresAtMs.toLong(), 8))
        out.frameLE(entryBytes)
        return out.toByteArray()
    }

    /**
     * Sign a `seam-voter-pop-v1` proof with the voter's OWN enrolled `voter` key (32-byte Ed25519 seed)
     * over [voterPopPayload]. The voter AID is DERIVED from the seed. A window the runtime must refuse
     * (`issued > expires`, or longer than 15 min) is never signed.
     */
    fun signVoterPop(
        voterSeed: ByteArray,
        target: VoterPopTarget,
        contentDigest: ByteArray,
        entryBytes: ByteArray,
        issuedAtMs: ULong,
        expiresAtMs: ULong,
    ): VoterPopProof {
        require(voterSeed.size == 32) { "voter seed must be 32 bytes" }
        require(issuedAtMs <= expiresAtMs && expiresAtMs - issuedAtMs <= MAX_LIFETIME) {
            "voter proof window must satisfy issuedAtMs <= expiresAtMs <= issuedAtMs + 15 min"
        }
        val voterAid = aidFromPubkey(ed25519Pub(voterSeed))
        val payload = voterPopPayload(target, voterAid, contentDigest, issuedAtMs, expiresAtMs, entryBytes)
        return VoterPopProof(voterAid, issuedAtMs, expiresAtMs, ed25519Sign(voterSeed, payload))
    }

    /**
     * [signVoterPop] over the [voteEntryBytes] of [entry]. [issuedAtMs] defaults to now and
     * [expiresAtMs] to [VOTER_POP_DEFAULT_LIFETIME_MS] (5 minutes) later — sign just before the vote call.
     */
    fun signVoterPop(
        voterSeed: ByteArray,
        target: VoterPopTarget,
        contentDigest: ByteArray,
        entry: VoteEntry,
        issuedAtMs: ULong = System.currentTimeMillis().toULong(),
        expiresAtMs: ULong = issuedAtMs + VOTER_POP_DEFAULT_LIFETIME_MS.toULong(),
    ): VoterPopProof = signVoterPop(voterSeed, target, contentDigest, voteEntryBytes(entry), issuedAtMs, expiresAtMs)

    /**
     * `true` iff [signature] is [voterAid]'s Ed25519 signature over [voterPopPayload]. The binding only;
     * the window is the runtime's (and a re-verifier's) to check. Never throws: anything malformed is
     * `false`.
     */
    fun verifyVoterPop(
        target: VoterPopTarget,
        voterAid: String,
        contentDigest: ByteArray,
        issuedAtMs: ULong,
        expiresAtMs: ULong,
        entryBytes: ByteArray,
        signature: ByteArray,
    ): Boolean =
        try {
            signature.size == 64 &&
                ed25519Verify(
                    aidToPubkey(voterAid),
                    voterPopPayload(target, voterAid, contentDigest, issuedAtMs, expiresAtMs, entryBytes),
                    signature,
                )
        } catch (e: RuntimeException) {
            false
        }

    /** [verifyVoterPop] over the [voteEntryBytes] of [entry]. */
    fun verifyVoterPop(
        target: VoterPopTarget,
        voterAid: String,
        contentDigest: ByteArray,
        issuedAtMs: ULong,
        expiresAtMs: ULong,
        entry: VoteEntry,
        signature: ByteArray,
    ): Boolean =
        try {
            verifyVoterPop(target, voterAid, contentDigest, issuedAtMs, expiresAtMs, voteEntryBytes(entry), signature)
        } catch (e: RuntimeException) {
            false
        }

    /** The REST/JSON `proof` object for [p] — [VoterPopProof.toRest]. */
    fun voterPopToRest(p: VoterPopProof): Map<String, Any> = p.toRest()

    /**
     * Re-check one sealed entry's voter verification record offline, from the record alone: rebuild the
     * signed input from the record's own addressing fields and the entry's frozen `entry_bytes`, check the
     * window at `accepted_at_ms` (`issued <= expires <= issued + 15 min`, `issued <= accepted + 60 s`,
     * `accepted <= expires`), and verify the signature with the key `principal` embeds. `false` for a
     * missing record, a non-`pop` method, a signer certificate, or anything that does not verify. Twin of
     * Python `verify_voter_record`.
     */
    fun verifyVoterRecord(entry: ExplanationEntry): Boolean {
        val vv = entry.voterVerification ?: return false
        if (vv.method != "pop") return false
        return try {
            val issued = vv.issuedAtMs
            val expires = vv.expiresAtMs
            val accepted = vv.acceptedAtMs
            val skewOk = issued < MAX_SKEW || issued - MAX_SKEW <= accepted
            if (!(issued <= expires && expires - issued <= MAX_LIFETIME && skewOk && accepted <= expires)) {
                return false
            }
            if (vv.signerCertificate.isNotEmpty()) return false
            verifyVoterPop(
                VoterPopTarget(vv.issuer, vv.tenant, vv.namespace, vv.sessionId, vv.openedAtMillis, vv.audience),
                vv.principal,
                vv.contentDigest,
                issued,
                expires,
                VoteEntry(
                    entry.kind,
                    entry.participant,
                    entry.proposalId,
                    entry.value,
                    entry.reason,
                    entry.confidence,
                    entry.rationaleRef,
                ),
                vv.signature,
            )
        } catch (e: RuntimeException) {
            false
        }
    }

    /**
     * The commitment-level voter check (`voter-verification.v1.md` §"The sealed record"). `true` iff
     * every `vote`, `ballot` and `objection` carries a record and no `evaluation` does; every record's
     * `issuer` is [issuer] (the one the verifier pinned); all records share one `(tenant, namespace,
     * session_id, opened_at_millis, audience)`; when [decision] is given, that is the records' own; and
     * each record re-checks ([verifyVoterRecord]). An explanation with no voter-kind entries passes.
     * `content_digest` is not re-derived: what it covers is not in the commitment. Twin of Python
     * `verify_commitment_voters`.
     */
    fun verifyCommitmentVoters(
        entries: List<ExplanationEntry>,
        issuer: String,
        decision: VoterDecisionRef? = null,
    ): Boolean {
        var addressing: List<Any>? = null
        for (e in entries) {
            val vv = e.voterVerification
            if (e.kind !in VOTER_VERIFIED_KINDS) {
                if (vv != null) return false
                continue
            }
            if (vv == null || vv.issuer != issuer) return false
            val a = listOf(vv.tenant, vv.namespace, vv.sessionId, vv.openedAtMillis.toString(), vv.audience)
            if (addressing == null) addressing = a else if (a != addressing) return false
            if (decision != null && (vv.tenant != decision.tenant || vv.sessionId != decision.sessionId)) return false
            if (!verifyVoterRecord(e)) return false
        }
        return true
    }
}

/**
 * The inputs [SeamCrypto.enrollPopPayload] frames, each exactly as sent on the wire. Strings are
 * signed as their UTF-8 bytes; [issuedAtMs] is Unix epoch MILLISECONDS (the proto field is `uint64`).
 */
data class EnrollPopFields(
    val subjectAid: String,
    val tenant: String,
    val namespace: String,
    val issuedAtMs: ULong,
    val nonce: String,
    /** The participant a `voter` enrolment binds (#1687); `""` for every other kind. */
    val participantId: String = "",
)

/**
 * The agent-side enrolment proof-of-possession (seam-runtime #1157 / #1164): the parts of
 * `EnrollTenantRequest.pop` (`EnrollPop`), produced by the AGENT being enrolled and handed to the
 * operator who enrols it. [signature] is the RAW 64-byte Ed25519 signature, as the gRPC `bytes` field
 * carries it; [toRest] gives the `POST /v1/tenants` form, where it is unpadded base64url. The runtime
 * accepts a proof at most 5 minutes old and at most 60 s in the future. Mirrors Python's and
 * TypeScript's `EnrollProof`. Not a data class: it holds a byte array, compared by content here.
 */
class EnrollProof(val issuedAtMs: ULong, val nonce: String, signature: ByteArray) {
    private val sig = signature.copyOf()

    /** The raw 64-byte signature (a copy). */
    val signature: ByteArray get() = sig.copyOf()

    /** The signature as unpadded base64url — the REST form. */
    val signatureB64url: String get() = Base64.getUrlEncoder().withoutPadding().encodeToString(sig)

    /**
     * The REST body's `pop` object, `{issued_at_ms, nonce, signature}` in that order, ready for any
     * JSON encoder. `issued_at_ms` is a [Long], or a [BigInteger] past [Long.MAX_VALUE] — never a
     * [ULong], which a reflective encoder such as Gson would not emit as a number.
     */
    fun toRest(): Map<String, Any> =
        linkedMapOf(
            "issued_at_ms" to
                (if (issuedAtMs <= Long.MAX_VALUE.toULong()) issuedAtMs.toLong() else BigInteger(issuedAtMs.toString())),
            "nonce" to nonce,
            "signature" to signatureB64url,
        )

    override fun equals(other: Any?): Boolean =
        other is EnrollProof && other.issuedAtMs == issuedAtMs && other.nonce == nonce && other.sig.contentEquals(sig)

    override fun hashCode(): Int = 31 * (31 * issuedAtMs.hashCode() + nonce.hashCode()) + sig.contentHashCode()

    override fun toString(): String = "EnrollProof(issuedAtMs=$issuedAtMs, nonce=$nonce, signature=$signatureB64url)"
}

/**
 * Where a vote is cast: the runtime ([issuer] AID and [audience], default `seam-runtime`) and the
 * session's tenant/namespace and open identity ([sessionId], [openedAtMillis] =
 * `SessionStep.opened_at_millis` from the open; `0` on the one-shot `RunDecision` path).
 */
data class VoterPopTarget(
    val issuer: String,
    val tenant: String,
    val namespace: String,
    val sessionId: String,
    val openedAtMillis: ULong = 0uL,
    val audience: String = SeamCrypto.VOTER_POP_DEFAULT_AUDIENCE,
)

/**
 * The entry the runtime will seal, as the voter signs it. [kind] is `vote`, `ballot` or `objection`;
 * [proposalId] is the ballot's `request_id` for a ballot; [value] is the vote value, ballot choice, or
 * objection severity (`""` when omitted). [confidence] and [rationaleRef] are `null` when absent (a
 * stated `0.0` is different bytes).
 */
data class VoteEntry(
    val kind: String,
    val participant: String,
    val proposalId: String,
    val value: String,
    val reason: String = "",
    val confidence: Double? = null,
    val rationaleRef: String? = null,
)

/** One sealed context binding the content digest frames; [contentHash] is `""` when none. */
data class VoteContext(val ctxRef: String, val contentHash: String = "")

/**
 * The session's bound vote policy (`SessionStep.vote_policy` from the open): [policyVersion] and the
 * 32-byte [rulesDigest]. Not a data class: it holds a byte array, compared by content here.
 */
class VotePolicyRef(val policyVersion: String, rulesDigest: ByteArray) {
    private val rules = rulesDigest.copyOf()

    /** The 32-byte rules digest (a copy). */
    val rulesDigest: ByteArray get() = rules.copyOf()

    override fun equals(other: Any?): Boolean =
        other is VotePolicyRef && other.policyVersion == policyVersion && other.rules.contentEquals(rules)

    override fun hashCode(): Int = 31 * policyVersion.hashCode() + rules.contentHashCode()

    override fun toString(): String = "VotePolicyRef(policyVersion=$policyVersion)"
}

/** The decision a commitment-level voter check is pinned to: the records' own tenant and session id. */
data class VoterDecisionRef(val tenant: String, val sessionId: String)

/**
 * A signed voter proof: the parts of the generated `VoterProof.pop` (`VoterPop`). Set [voterAid],
 * [issuedAtMs], [expiresAtMs] and the RAW 64-byte [signature] on a `VoterPop`, wrap it in a
 * `VoterProof`, and put it on `VoteRequest.proof`, `BallotRequest.proof`, `ObjectionRequest.proof` or a
 * one-shot `Vote.proof`. [toRest] is the REST/JSON `proof` object. Not a data class: it holds a byte
 * array, compared by content here.
 */
class VoterPopProof(val voterAid: String, val issuedAtMs: ULong, val expiresAtMs: ULong, signature: ByteArray) {
    private val sig = signature.copyOf()

    /** The raw 64-byte signature (a copy). */
    val signature: ByteArray get() = sig.copyOf()

    /** The signature as unpadded base64url — the REST form. */
    val signatureB64url: String get() = Base64.getUrlEncoder().withoutPadding().encodeToString(sig)

    /**
     * The REST/JSON `proof` object: `{"pop": {voter_aid, issued_at_ms, expires_at_ms, signature}}`, the
     * signature as unpadded base64url and the window as [Long]s. The window is a JSON number, so a value
     * past 2^53 is refused rather than rounded.
     */
    fun toRest(): Map<String, Any> {
        val maxSafe = (1uL shl 53) - 1uL
        for (v in listOf(issuedAtMs, expiresAtMs)) {
            require(v <= maxSafe) { "voter proof window value $v exceeds 2^53 and cannot be carried as a JSON number" }
        }
        return linkedMapOf(
            "pop" to
                linkedMapOf<String, Any>(
                    "voter_aid" to voterAid,
                    "issued_at_ms" to issuedAtMs.toLong(),
                    "expires_at_ms" to expiresAtMs.toLong(),
                    "signature" to signatureB64url,
                ),
        )
    }

    override fun equals(other: Any?): Boolean =
        other is VoterPopProof && other.voterAid == voterAid && other.issuedAtMs == issuedAtMs &&
            other.expiresAtMs == expiresAtMs && other.sig.contentEquals(sig)

    override fun hashCode(): Int =
        31 * (31 * (31 * voterAid.hashCode() + issuedAtMs.hashCode()) + expiresAtMs.hashCode()) + sig.contentHashCode()

    override fun toString(): String =
        "VoterPopProof(voterAid=$voterAid, issuedAtMs=$issuedAtMs, expiresAtMs=$expiresAtMs, signature=$signatureB64url)"
}
