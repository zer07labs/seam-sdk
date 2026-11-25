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
 * The commitment fields `seam-commitment-digest:v5` binds. [committer] is the verified AID that
 * committed (empty when absent). [selectionDigest] (field 9) and [certificateDigest] (field 10) are
 * `null` when absent — every record runtime 0.88.0 seals — and exactly 32 bytes when present.
 * [governingDocSha256] (field 11, #1711) is the SHA-256 of the tenant governing document the decision
 * was sealed under (`Commitment.governing_doc_sha256` on the wire): `null` for an ungoverned decision,
 * else exactly 32 bytes.
 * [supersedes] is `null` when ABSENT, which v5 frames as `0x00` — a
 * different digest from a present empty string (`0x01 ‖ F("")`). Field 8 (the explanation digest) is resolved from [explanation] and
 * [explanationDigest] (32 raw bytes) — see [SeamCrypto.verifyTct].
 * [selection] is the sealed option-selection block (`Commitment.selection`, runtime 0.90.0), `null`
 * when the commitment carries none (the default, and today's behaviour). Given, field 9 is framed from
 * this verifier's own [SeamCrypto.selectionDigest] over it (a [selectionDigest] given beside it must
 * agree), and [SeamCrypto.verifyTct] additionally recomputes the winner (selection-rule.v1 §5 steps 6-9).
 * [trailers] (Flows W2) is the raw `0x05` (Gate block) and `0x06` (governing document) trailer bytes the
 * sealed commitment appends, in order and nothing else; `null` when not given. [SeamCrypto.verifyTct]
 * derives fields 10-12 from them under the version the TCT's statement selects
 * ([SeamCrypto.decodeCommitmentTrailers]); with `null` a v5 verification is exactly what it was before.
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
    val governingDocSha256: ByteArray? = null,
    val selection: SelectionBlock? = null,
    val trailers: ByteArray? = null,
    /**
     * The served projection (#420): `seam.api.v1.Commitment` carries no raw trailers, only `gate = 13`
     * (`GateRecord.body`, the exact `0x05` body) beside [governingDocSha256] and `env = 14`. With
     * `trailers == null`, [SeamCrypto.verifyTct] under v6 rebuilds the trailer run from [gateBody],
     * [governingDocSha256] and [env] ([SeamCrypto.servedCommitmentTrailers]) and decodes it under every
     * v6 rule; v5 refuses either. Setting either beside [trailers] is refused.
     */
    val gateBody: ByteArray? = null,
    val env: String? = null,
)

/** One weight override of a [SelectionBlock]. */
data class SelectionWeight(val participant: String, val weight: UInt)

/** One sealed context pair of a [SelectionBlock]; [contentHash] is `""` when the binding carries none. */
data class SelectionContext(val ctxRef: String, val contentHash: String)

/**
 * The sealed `seam.selection.weighted_plurality` block (runtime 0.90.0, seam-runtime
 * `docs/specs/selection-rule.v1.md` §4.2), field for field in `body` order; the generated
 * `SelectionRecord` (`Commitment.selection = 12`) maps onto it one to one. [weights] are strictly
 * ascending by participant UTF-8 bytes, [rulesDigest] is the 32-byte bound `policy_rules_digest`, and
 * [winnerProposalId] is never empty. Field 9 of `seam-commitment-digest:v5` is
 * `SeamCrypto.selectionDigest(SeamCrypto.selectionBody(block))`: pass it as [Commitment.selectionDigest].
 */
data class SelectionBlock(
    val rule: String,
    val ruleVersion: UInt,
    val defaultWeight: UInt,
    val weights: List<SelectionWeight>,
    val tie: String,
    val abstention: String,
    val minBallots: UInt,
    val policyVersion: String,
    val rulesDigest: ByteArray,
    val participants: List<String>,
    val onBehalfOf: List<String>,
    val context: List<SelectionContext>,
    val winnerProposalId: String,
)

/** One proposal's score in a [SelectionDecision], in sealed proposal order. */
data class SelectionScore(val proposalId: String, val score: Long)

/**
 * The outcome of [SeamCrypto.decide]: [result] is `winner` (with [winnerProposalId] and [option]),
 * `no_winner` (with [reason]: `below_min_ballots`, `no_positive_score` or `tie`) or `malformed` (with
 * [reason] and [at], the entry index, `null` for a record-level check). [scores] list every proposal
 * in sealed order and [ballots] counts distinct voters; both are empty / 0 for `malformed`.
 */
data class SelectionDecision(
    val result: String,
    val winnerProposalId: String? = null,
    val option: String? = null,
    val reason: String? = null,
    val at: Int? = null,
    val scores: List<SelectionScore> = emptyList(),
    val ballots: Int = 0,
)

/**
 * The outcome of [SeamCrypto.verifySelection]. [result] is `verified` or one of the spec's verifier
 * result names (`selection_malformed`, `selection_no_winner_sealed`, `selection_winner_mismatch`,
 * `selection_action_mismatch`, `selection_vote_unverified`, `selection_content_link_mismatch`,
 * `selection_principal_not_one_to_one`). [at] is the entry index where the check failed, when the
 * spec names one; [reason] is [SeamCrypto.decide]'s reason for a malformed or no-winner record;
 * [recomputed] is the winner this verifier computed when it disagrees with the sealed one.
 */
data class SelectionResult(
    val result: String,
    val winnerProposalId: String? = null,
    val votesLinked: Int = 0,
    val at: Int? = null,
    val reason: String? = null,
    val recomputed: String? = null,
) {
    val ok: Boolean get() = result == "verified"
}

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

    /**
     * The `kind` words the explanation digest frames — lowercase ASCII, exactly; never the proto enum name.
     * `"proposal"` (runtime 0.90.0, option selection) is one accepted option of a selection session; it
     * never carries a voter record.
     */
    val EXPLANATION_KINDS: List<String> = listOf("vote", "evaluation", "objection", "ballot", "proposal")

    /** Domain tag of the option-selection block digest v5 field 9 binds. */
    const val SELECTION_DIGEST_DOMAIN = "seam-selection-digest:v1"

    /**
     * The canonical selection block `body` (selection-rule.v1 §4.2), framed only with `F(x) =
     * be64(len) ‖ x` and `U(n) = be64(n)`. The winner is recomputed by [decide] and checked by
     * [verifySelection] (selection-rule.v1 §3, §5 steps 6-9), which [verifyTct] runs whenever the
     * commitment carries a [Commitment.selection] block.
     *
     * @throws IllegalArgumentException for a block the runtime could not have sealed: weights not
     *   strictly ascending by participant UTF-8 bytes (duplicates included), a rules digest that is not
     *   32 bytes, or an empty winner — refused rather than hashed.
     */
    fun selectionBody(b: SelectionBlock): ByteArray {
        val keys = b.weights.map { it.participant.toByteArray(Charsets.UTF_8) }
        for (i in 1 until keys.size) {
            require(Arrays.compareUnsigned(keys[i - 1], keys[i]) < 0) {
                "selection weights are not strictly ascending by participant (weights_not_canonical)"
            }
        }
        require(b.rulesDigest.size == 32) { "selection rules_digest must be 32 bytes, got ${b.rulesDigest.size}" }
        require(b.winnerProposalId.isNotEmpty()) { "selection winner_proposal_id is empty (empty_winner)" }
        fun utf8(s: String) = s.toByteArray(Charsets.UTF_8)
        val out = ByteArrayOutputStream()
        out.frame(utf8(b.rule))
        out.writeBytes(be64(b.ruleVersion.toLong()))
        out.writeBytes(be64(b.defaultWeight.toLong()))
        out.writeBytes(be64(b.weights.size.toLong()))
        b.weights.forEachIndexed { i, w ->
            out.frame(keys[i])
            out.writeBytes(be64(w.weight.toLong()))
        }
        out.frame(utf8(b.tie))
        out.frame(utf8(b.abstention))
        out.writeBytes(be64(b.minBallots.toLong()))
        out.frame(utf8(b.policyVersion))
        out.frame(b.rulesDigest)
        out.writeBytes(be64(b.participants.size.toLong()))
        b.participants.forEach { out.frame(utf8(it)) }
        out.writeBytes(be64(b.onBehalfOf.size.toLong()))
        b.onBehalfOf.forEach { out.frame(utf8(it)) }
        out.writeBytes(be64(b.context.size.toLong()))
        b.context.forEach {
            out.frame(utf8(it.ctxRef))
            out.frame(utf8(it.contentHash))
        }
        out.frame(utf8(b.winnerProposalId))
        return out.toByteArray()
    }

    /** The one rule word v1 knows (selection-rule.v1 §2). */
    const val SELECTION_RULE = "seam.selection.weighted_plurality"
    const val SELECTION_RULE_VERSION: UInt = 1u
    const val SELECTION_TIE = "no_winner"
    const val SELECTION_ABSTENTION = "excluded_counts_for_quorum"

    /** The `mode` a selection vote's `seam-vote-content-v1` digest frames. */
    const val SELECTION_MODE = "macp.mode.decision.v1"

    /** The vote values a selection `vote` entry may carry. */
    val VOTE_VALUES: List<String> = listOf("APPROVE", "REJECT", "ABSTAIN")

    private fun recordMalformed(b: SelectionBlock): String? {
        if (b.rule != SELECTION_RULE) return "unknown_rule"
        if (b.ruleVersion != SELECTION_RULE_VERSION) return "unknown_rule_version"
        if (b.tie != SELECTION_TIE) return "unknown_tie"
        if (b.abstention != SELECTION_ABSTENTION) return "unknown_abstention"
        val keys = b.weights.map { it.participant.toByteArray(Charsets.UTF_8) }
        for (i in 1 until keys.size) {
            if (Arrays.compareUnsigned(keys[i - 1], keys[i]) >= 0) return "weights_not_canonical"
        }
        if (b.defaultWeight == 0u && b.weights.all { it.weight == 0u }) return "zero_electorate"
        if (b.minBallots == 0u) return "min_ballots_zero"
        if (b.participants.isEmpty()) return "no_participants"
        if (b.participants.toSet().size != b.participants.size) return "duplicate_participant"
        return null
    }

    private fun utf8Key(s: String): ByteBuffer = ByteBuffer.wrap(s.toByteArray(Charsets.UTF_8))

    /**
     * `decide(record, entries)` (selection-rule.v1 §3): a pure function of the selection block (its
     * [SelectionBlock.winnerProposalId] is ignored) and the sealed explanation entries, in sealed order.
     * [SelectionDecision.at] is the entry index of a malformed entry, `null` for a record-level check.
     * Options compare by UTF-8 bytes, never normalised. Twin of Python `decide`.
     */
    fun decide(block: SelectionBlock, entries: List<ExplanationEntry>): SelectionDecision {
        recordMalformed(block)?.let { return SelectionDecision("malformed", reason = it) }
        val weights = block.weights.associate { it.participant to it.weight }
        val participants = block.participants.toSet()
        val proposals = LinkedHashMap<String, String>()
        val options = HashSet<ByteBuffer>()
        val voted = HashSet<Pair<String, String>>()
        val approvers = HashSet<String>()
        val voters = LinkedHashSet<String>()
        val approvals = ArrayList<Pair<String, String>>()
        var seenVote = false
        entries.forEachIndexed { i, e ->
            fun mal(reason: String) = SelectionDecision("malformed", reason = reason, at = i)
            when (e.kind) {
                "proposal" -> {
                    if (seenVote) return mal("proposal_after_vote")
                    if (e.voterVerification != null) return mal("proposal_has_voter_record")
                    if (e.reason != "" || e.confidence != null || e.rationaleRef != null) {
                        return mal("proposal_has_extra_fields")
                    }
                    if (e.proposalId == "") return mal("empty_proposal_id")
                    if (e.value == "") return mal("empty_option")
                    if (e.proposalId in proposals) return mal("duplicate_proposal_id")
                    if (!options.add(utf8Key(e.value))) return mal("duplicate_option")
                    proposals[e.proposalId] = e.value
                }
                "vote" -> {
                    seenVote = true
                    val who = e.participant
                    val pid = e.proposalId
                    if (pid !in proposals) return mal("vote_unknown_proposal")
                    if (e.value !in VOTE_VALUES) return mal("vote_bad_value")
                    if (who !in participants) return mal("vote_not_participant")
                    if ((who to pid) in voted) return mal("duplicate_vote")
                    if (e.value == "APPROVE") {
                        if (!approvers.add(who)) return mal("double_approve")
                        approvals.add(who to pid)
                    }
                    voted.add(who to pid)
                    voters.add(who)
                }
                "evaluation", "objection" -> Unit // sealed, never scored (v1 admits no objection veto)
                "ballot" -> return mal("ballot_in_selection")
                else -> return mal("unknown_kind")
            }
        }
        if (proposals.isEmpty()) return SelectionDecision("malformed", reason = "no_proposals")
        val scores = LinkedHashMap<String, Long>()
        proposals.keys.forEach { scores[it] = 0L }
        for ((who, pid) in approvals) scores[pid] = scores.getValue(pid) + (weights[who] ?: block.defaultWeight).toLong()
        val tally = scores.map { (p, sc) -> SelectionScore(p, sc) }
        val ballots = voters.size
        val top = scores.values.max()
        val leaders = scores.filterValues { it == top }.keys.toList()
        if (ballots.toLong() < block.minBallots.toLong()) {
            return SelectionDecision("no_winner", reason = "below_min_ballots", scores = tally, ballots = ballots)
        }
        if (top == 0L) return SelectionDecision("no_winner", reason = "no_positive_score", scores = tally, ballots = ballots)
        if (leaders.size > 1) return SelectionDecision("no_winner", reason = "tie", scores = tally, ballots = ballots)
        return SelectionDecision(
            "winner",
            winnerProposalId = leaders[0],
            option = proposals.getValue(leaders[0]),
            scores = tally,
            ballots = ballots,
        )
    }

    /**
     * selection-rule.v1 §5 steps 6-9 over a selection block, the sealed entries and `Commitment.action`.
     * Step 6 recomputes the winner ([decide]) and checks it is the sealed one; step 7 checks the
     * winner's sealed option is [action] byte for byte; step 8 re-derives every vote's
     * `seam-vote-content-v1` digest ([SELECTION_MODE]) from sealed inputs alone and checks it is the one
     * the voter signed (the record's `contentDigest`); step 9 checks participant ↔ principal is
     * one-to-one across the votes. It does not re-check signatures or the TCT: signatures are
     * [verifyCommitmentVoters]'s, the TCT [verifyTct]'s (which calls this when the commitment carries a
     * block). Never throws for a malformed block or entries: they are a non-`verified` result. Twin of
     * Python `verify_selection`.
     */
    fun verifySelection(block: SelectionBlock, entries: List<ExplanationEntry>, action: String): SelectionResult {
        val d = decide(block, entries)
        if (d.result == "malformed") return SelectionResult("selection_malformed", reason = d.reason, at = d.at)
        if (d.result == "no_winner") return SelectionResult("selection_no_winner_sealed", reason = d.reason)
        if (d.winnerProposalId != block.winnerProposalId) {
            return SelectionResult("selection_winner_mismatch", recomputed = d.winnerProposalId)
        }
        if (!d.option!!.toByteArray(Charsets.UTF_8).contentEquals(action.toByteArray(Charsets.UTF_8))) {
            return SelectionResult("selection_action_mismatch")
        }
        val proposals = entries.filter { it.kind == "proposal" }.associate { it.proposalId to it.value }
        // A sealed block always carries a 32-byte rules digest (selectionBody refuses any other).
        if (block.rulesDigest.size != 32) return SelectionResult("selection_malformed", reason = "rules_digest_not_32")
        val policy = VotePolicyRef(block.policyVersion, block.rulesDigest)
        val context = block.context.map { VoteContext(it.ctxRef, it.contentHash) }
        var linked = 0
        entries.forEachIndexed { i, e ->
            if (e.kind != "vote") return@forEachIndexed
            val vv = e.voterVerification ?: return SelectionResult("selection_vote_unverified", at = i)
            val want = voteContentDigest(
                SELECTION_MODE,
                e.proposalId,
                proposals.getValue(e.proposalId),
                block.participants,
                block.onBehalfOf,
                context,
                emptyList(),
                policy,
            )
            if (!vv.contentDigest.contentEquals(want)) return SelectionResult("selection_content_link_mismatch", at = i)
            linked++
        }
        val byParticipant = HashMap<String, String>()
        val byPrincipal = HashMap<String, String>()
        entries.forEachIndexed { i, e ->
            if (e.kind != "vote") return@forEachIndexed
            val p = e.participant
            val a = e.voterVerification!!.principal
            if (byParticipant.getOrPut(p) { a } != a || byPrincipal.getOrPut(a) { p } != p) {
                return SelectionResult("selection_principal_not_one_to_one", at = i)
            }
        }
        return SelectionResult("verified", winnerProposalId = d.winnerProposalId, votesLinked = linked)
    }

    /** `SHA-256(F("seam-selection-digest:v1") ‖ body)`: the 32 bytes v5 field 9 binds. */
    fun selectionDigest(body: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.frame(SELECTION_DIGEST_DOMAIN.toByteArray(Charsets.UTF_8))
        out.writeBytes(body)
        return sha256(out.toByteArray())
    }

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
    const val COMMITMENT_DIGEST_DOMAIN = "seam-commitment-digest:v5"

    /** The one grant a commitment self-attestation carries. */
    const val ATTESTATION_GRANT = "aitp.attestation"

    /** The `ext` namespace the commitment statement rides under. */
    const val COMMITMENT_EXT_NAMESPACE = "com.zer07labs.seam"

    /** The statement `type` inside [COMMITMENT_EXT_NAMESPACE]. */
    const val COMMITMENT_STATEMENT = "seam:commitment"

    /**
     * `seam-commitment-digest:v5` (hex): SHA-256 over a **length-prefixed** framing of a domain tag
     * plus the commitment fields — each field preceded by its 8-byte big-endian length. Mirrors the
     * runtime byte-for-byte, and mirrors the Go/Java/Python/TypeScript shims. v1-v4 are deleted, not
     * dual-verified. Normative: `seam-runtime/docs/specs/seam-commitment-digest.v5.md`. `supersedes`
     * carries a presence byte — `0x00` when absent (`null`), `0x01 ‖ F(s)` when present. v4 (#1687)
     * binds the v2 explanation digest as field 8 and appends two always-framed slots: field 9 (selection
     * digest) and field 10 (Gate certificate digest), each `0x00` when absent or `0x01 ‖ be64(32) ‖ 32
     * raw bytes`. v5 (#1711) appends field 11, the governing document digest, in the same slot
     * encoding. A present slot that is not 32 bytes throws [IllegalArgumentException].
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
        require(c.governingDocSha256 == null || c.governingDocSha256.size == 32) {
            "governing_doc_sha256 must be 32 bytes when present"
        }
        val explanation = commitmentExplanationDigest(c)
        val selectionSlot = c.selection?.let { blk ->
            val d = selectionDigest(selectionBody(blk))
            require(c.selectionDigest == null || c.selectionDigest.contentEquals(d)) {
                "selection_digest does not match the selection block"
            }
            d
        } ?: c.selectionDigest
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
        for (slot in listOf(selectionSlot, c.certificateDigest, c.governingDocSha256)) {
            if (slot == null) {
                h.write(0x00)
            } else {
                h.write(0x01)
                h.frame(slot)
            }
        }
        return sha256(h.toByteArray()).joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    // ── The seal key (seam-runtime #2031, deep-cleanup S-4, runtime 0.123.0) ──────────────────
    //
    // Normative: seam-runtime docs/specs/seam-commitment-digest.v6.md §Seal key. The pinned issuer no
    // longer signs commitment TCTs: it certifies a short-lived in-memory seal key, and the TCT is a
    // self-attestation by that key carrying the certificate in a second ext member. Pinned by
    // conformance/seal_key_cert_vector.json. No backward compatibility: an issuer-signed TCT is refused.

    /** The TCT `ext` member that carries the seal-key certificate. */
    const val SEAL_KEY_CERT_EXT_KEY = "com.zer07labs.seam.seal-key-cert"

    /** Domain tag, the certificate's first frame. */
    const val SEAL_KEY_CERT_DOMAIN = "seam.seal-key-cert.v1"

    /** The widest certificate window accepted, `not_after - not_before`: 1 h plus 30 s skew. */
    const val SEAL_KEY_MAX_WINDOW_MS = 3_630_000L

    private const val SEAL_KEY_ISSUER_AID_MAX = 62

    /** A parsed seal-key certificate. [notBeforeMs]/[notAfterMs] are within [0, Long.MAX_VALUE]. */
    class SealKeyCert(val sealPk: ByteArray, val notBeforeMs: Long, val notAfterMs: Long, val issuerAid: String) {
        /** The seal key's untagged `aid:pubkey:` AID: the commitment TCT's `iss == sub == aud`. */
        val sealAid: String get() = "aid:pubkey:" + b64urlNoPad(sealPk)

        /** `notBeforeMs <= iat*1000 <= notAfterMs`, no grace; an overflowing `iat` is outside. */
        fun covers(iatSecs: Long): Boolean {
            val t = try {
                Math.multiplyExact(iatSecs, 1000L)
            } catch (e: ArithmeticException) {
                return false
            }
            return notBeforeMs <= t && t <= notAfterMs
        }
    }

    /** `framed(x)`: `u32le(len) ‖ x` — the runtime's chain framing primitive. */
    private fun framedPut(out: ByteArrayOutputStream, b: ByteArray) {
        out.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(b.size).array())
        out.write(b)
    }

    /**
     * `framed("seam.seal-key-cert.v1") ‖ framed(seal_pk) ‖ le64(not_before_ms) ‖ le64(not_after_ms) ‖
     * framed(issuer_aid)` — the bytes the issuer signs SHA-256 of.
     */
    fun sealKeyCertPreimage(sealPk: ByteArray, notBeforeMs: Long, notAfterMs: Long, issuerAid: String): ByteArray {
        val out = ByteArrayOutputStream()
        framedPut(out, SEAL_KEY_CERT_DOMAIN.toByteArray(Charsets.US_ASCII))
        framedPut(out, sealPk)
        out.write(ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN).putLong(notBeforeMs).putLong(notAfterMs).array())
        framedPut(out, issuerAid.toByteArray(Charsets.UTF_8))
        return out.toByteArray()
    }

    private fun framedGet(b: ByteArray, pos: IntArray): ByteArray? {
        if (b.size - pos[0] < 4) return null
        val len = Integer.toUnsignedLong(ByteBuffer.wrap(b, pos[0], 4).order(ByteOrder.LITTLE_ENDIAN).int)
        if (len > (b.size - pos[0] - 4).toLong()) return null
        val out = b.copyOfRange(pos[0] + 4, pos[0] + 4 + len.toInt())
        pos[0] += 4 + len.toInt()
        return out
    }

    /**
     * Parse a certificate; `null` on a wrong tag, a key that is not 32 bytes, a short read, trailing
     * bytes, an inverted window, a time beyond `Long.MAX_VALUE` ms, a window wider than
     * [SEAL_KEY_MAX_WINDOW_MS], or an issuer AID that is longer than 62 bytes or not UTF-8.
     */
    fun parseSealKeyCert(b: ByteArray): SealKeyCert? {
        val pos = intArrayOf(0)
        val tag = framedGet(b, pos) ?: return null
        if (!tag.contentEquals(SEAL_KEY_CERT_DOMAIN.toByteArray(Charsets.US_ASCII))) return null
        val pk = framedGet(b, pos) ?: return null
        if (pk.size != 32) return null
        if (b.size - pos[0] < 16) return null
        val le = ByteBuffer.wrap(b, pos[0], 16).order(ByteOrder.LITTLE_ENDIAN)
        val nb = le.long
        val na = le.long
        pos[0] += 16
        val aid = framedGet(b, pos) ?: return null
        if (pos[0] != b.size || aid.size > SEAL_KEY_ISSUER_AID_MAX) return null
        // Unsigned u64 in a signed Long: a negative value is > i64::MAX, refused.
        if (nb < 0 || na < 0 || nb > na || na - nb > SEAL_KEY_MAX_WINDOW_MS) return null
        val issuer = try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(aid))
                .toString()
        } catch (e: java.nio.charset.CharacterCodingException) {
            return null
        }
        return SealKeyCert(pk, nb, na, issuer)
    }

    /**
     * Verify a certificate under the PINNED issuer AID: it must name exactly that AID, and the issuer's
     * strict Ed25519 signature over `sha256(cert)` must hold. `null` on any failure.
     */
    fun verifySealKeyCert(pinnedIssuerAid: String, cert: ByteArray, sig: ByteArray): SealKeyCert? =
        try {
            val f = parseSealKeyCert(cert)
            if (f == null || pinnedIssuerAid != f.issuerAid) {
                null
            } else {
                val pub = aidToPubkey(pinnedIssuerAid)
                if (pub.size != 32 || sig.size != 64 || !ed25519VerifyStrict(pub, sha256(cert), sig)) null else f
            }
        } catch (e: RuntimeException) {
            null
        }

    /**
     * The 32-byte encodings that decode to an Ed25519 point of small order (the 8-torsion), canonical
     * and not. ed25519-dalek's `verify_strict` refuses a small-order public key and a small-order `R`;
     * Bouncy Castle checks neither, so this list closes the gap. Every other strictness (canonical `S`,
     * `R` compared by encoding) is Bouncy Castle's own.
     */
    private val SMALL_ORDER_ENCODINGS = setOf(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )

    private fun smallOrder(enc32: ByteArray): Boolean =
        enc32.joinToString("") { "%02x".format(it.toInt() and 0xff) } in SMALL_ORDER_ENCODINGS

    /** Ed25519 verify with dalek `verify_strict`'s extra refusals (small-order key or R). */
    internal fun ed25519VerifyStrict(pub: ByteArray, msg: ByteArray, sig: ByteArray): Boolean {
        if (pub.size != 32 || sig.size != 64) return false
        if (smallOrder(pub) || smallOrder(sig.copyOfRange(0, 32))) return false
        return ed25519Verify(pub, msg, sig)
    }

    /**
     * Strict unpadded base64url: alphabet `[A-Za-z0-9_-]` only, no `=`, a length that is not 1 mod 4,
     * and canonical trailing bits (re-encoding the bytes gives the input back). `null` when refused.
     */
    internal fun b64urlDecodeStrict(s: String): ByteArray? {
        if (s.length % 4 == 1) return null
        if (!s.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }) return null
        val b = try {
            b64urlDecode(s)
        } catch (e: IllegalArgumentException) {
            return null
        }
        return if (b64urlNoPad(b) == s) b else null
    }

    /** RFC 7638 thumbprint of an Ed25519 key: the AITP `cnf.jkt`. */
    internal fun ed25519Jkt(pk: ByteArray): String {
        val jwk = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + b64urlNoPad(pk) + "\"}"
        return b64urlNoPad(sha256(jwk.toByteArray(Charsets.US_ASCII)))
    }

    private val JSON_INTEGER = Regex("-?(0|[1-9][0-9]*)")

    /** A top-level JSON integer member, or `null` if absent or not a plain integer literal. */
    private fun topLevelInteger(json: String, name: String): Long? =
        try {
            JsonReader(StringReader(json)).use { r ->
                r.strictness = Strictness.STRICT
                r.beginObject()
                var out: Long? = null
                while (r.hasNext()) {
                    if (r.nextName() != name) {
                        r.skipValue()
                        continue
                    }
                    if (r.peek() != JsonToken.NUMBER) return null
                    val lit = r.nextString()
                    // A JSON integer: no fraction, no exponent (serde refuses 1.0 and 1e3 as an i64).
                    if (!JSON_INTEGER.matches(lit)) return null
                    out = lit.toLong()
                    break
                }
                out
            }
        } catch (e: IOException) {
            null
        } catch (e: RuntimeException) {
            null
        }

    /**
     * Independently verify a sealed commitment's rooted TCT — zero server trust, stock crypto only.
     *
     * **Seal key (seam-runtime #2031, S-4; runtime 0.123.0+).** The TCT is signed by a seal key the
     * pinned issuer certifies, never by the issuer itself: (1) `ext["com.zer07labs.seam.seal-key-cert"]`
     * is exactly `{cert, sig}`, strict base64url; (2) the certificate parses ([parseSealKeyCert]), names
     * exactly `issuerAid`, and the issuer's strict Ed25519 signature over `sha256(cert)` holds; (3) the
     * JWS verifies under the seal key, `iss == sub == aud ==` the seal AID and `cnf.jkt` is its
     * thumbprint; (4) `not_before <= iat*1000 <= not_after`, no grace. An issuer-signed TCT (every TCT
     * before S-4) is refused: no backward compatibility. The checks below are otherwise unchanged:
     * `exp`; that `grants` is exactly
     * `["aitp.attestation"]`; and that `ext` is exactly
     * `{"com.zer07labs.seam":{"type":"seam:commitment","commitment_digest":<hex>}}` with the hex equal
     * to the recomputed `seam-commitment-digest:v5` of this exact commitment (the decided content, the
     * committer, and the sealed explanation). Since Flows W2 the statement may instead carry
     * `"commitment_digest_domain":"seam-commitment-digest:v6"`: the exact member set selects the version
     * ([selectCommitmentVersion]), that version's trailer rules apply to [Commitment.trailers], and the
     * digest is recomputed under it alone (v6 spec §Verifiers). A v5 statement with no trailers verifies
     * exactly as before. A header or payload whose JSON repeats an object key at
     * any depth is refused: Gson would keep one of the two, and another parser might keep the other. Any malformed/forged input fails closed (returns false),
     * never throws — including explanation entries that disagree with the published
     * `explanationDigest`, an unknown kind, or a non-canonical confidence.
     */
    fun verifyTct(issuerAid: String, tctJws: String, commitment: Commitment, nowS: Long): Boolean {
        return try {
            val parts = tctJws.split(".")
            if (parts.size != 3) return false
            val headerJson = String(b64urlDecode(parts[0]), Charsets.UTF_8)
            val payloadJson = String(b64urlDecode(parts[1]), Charsets.UTF_8)
            if (hasDuplicateKey(headerJson) || hasDuplicateKey(payloadJson)) return false
            val header: Map<String, Any?> = gson.fromJson(headerJson, mapType) ?: return false
            val payload: Map<String, Any?> = gson.fromJson(payloadJson, mapType) ?: return false
            // S-4 (1) + (2): peek the certificate member from the not-yet-verified payload and verify
            // it under the PINNED issuer; it names the seal key that must have signed the token.
            val peekExt = payload["ext"] as? Map<*, *> ?: return false
            val member = peekExt[SEAL_KEY_CERT_EXT_KEY] as? Map<*, *> ?: return false
            if (member.size != 2) return false
            val certB64 = member["cert"] as? String ?: return false
            val sigB64 = member["sig"] as? String ?: return false
            val certBytes = b64urlDecodeStrict(certB64) ?: return false
            val certSig = b64urlDecodeStrict(sigB64) ?: return false
            val cert = verifySealKeyCert(issuerAid, certBytes, certSig) ?: return false
            val sealAid = cert.sealAid
            // (3) the token is a self-attestation by the certified seal key.
            if (!ed25519Verify(cert.sealPk, "${parts[0]}.${parts[1]}".toByteArray(Charsets.US_ASCII), b64urlDecode(parts[2]))) {
                return false
            }
            if (header["alg"] != "EdDSA" || header["typ"] != "aitp-tct+jwt") return false
            if (!(payload["iss"] == sealAid && payload["sub"] == sealAid && payload["aud"] == sealAid)) {
                return false
            }
            val cnf = payload["cnf"] as? Map<*, *> ?: return false
            if (cnf["jkt"] != ed25519Jkt(cert.sealPk)) return false
            val verifiedExt = payload["ext"] as? Map<*, *> ?: return false
            if (verifiedExt[SEAL_KEY_CERT_EXT_KEY] != member) return false
            // (4) iat is a JSON integer inside the certificate window, no grace.
            val iat = topLevelInteger(payloadJson, "iat") ?: return false
            if (!cert.covers(iat)) return false
            val exp = payload["exp"] as? Number ?: return false
            if (nowS >= exp.toLong()) return false // RFC 7519: reject at/after expiry
            val grants = payload["grants"] as? List<*> ?: return false
            if (grants.size != 1 || grants[0] != ATTESTATION_GRANT) return false
            // ext is exactly the statement and the certificate member, nothing else.
            val ext = payload["ext"] as? Map<*, *> ?: return false
            if (ext.size != 2 || !ext.containsKey(SEAL_KEY_CERT_EXT_KEY)) return false
            // Flows W2: the statement's exact member set selects v5 or v6 (the duplicate-member guard
            // ran over the raw payload above, so it covers every depth of ext). Recompute under that
            // version only: never both, never a fallback.
            val version = selectFromExtObject(ext)
            val digest = (ext[COMMITMENT_EXT_NAMESPACE] as Map<*, *>)["commitment_digest"]
            if (digest != recomputeCommitmentDigest(version, commitment)) return false
            // Option selection (selection-rule.v1 §5 steps 6-9). No block means "not a selection
            // decision" and nothing more. A block without the entries cannot be checked, so it fails
            // closed rather than passing as if the winner had been recomputed.
            val blk = commitment.selection ?: return true
            val entries = commitment.explanation ?: return false
            verifySelection(blk, entries, commitment.action).ok
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

    // ── seam-commitment-digest:v6 + the Gate block v1 (Flows W2, readers only) ──────────────────
    //
    // Normative: seam-runtime docs/specs/seam-commitment-digest.v6.md and seam-gate-block.v1.md.
    // Pinned by conformance/commitment_digest_v6_vector.json, commitment_digest_v6_signed_vector.json
    // and gate_block_vector.json. Every be64 is read as a ULong, never a signed Long.

    /** Domain tag of the v6 commitment digest. v5 ([COMMITMENT_DIGEST_DOMAIN]) is unchanged. */
    const val COMMITMENT_DIGEST_DOMAIN_V6 = "seam-commitment-digest:v6"

    /** Domain tag of the Gate digest v6 field 10 frames: SHA-256(F(tag) ‖ gate_body). */
    const val GATE_DIGEST_DOMAIN = "seam-gate-digest:v1"

    /** The `ext` statement member that selects v6. */
    const val COMMITMENT_DIGEST_DOMAIN_MEMBER = "commitment_digest_domain"

    private const val GATE_TRAILER = 0x05
    private const val GOVERNING_TRAILER = 0x06
    private val ENV_SANDBOX = "sandbox".toByteArray(Charsets.US_ASCII)
    private val ENV_LIVE = "live".toByteArray(Charsets.US_ASCII)
    private val V5_MEMBERS = setOf("type", "commitment_digest")
    private val V6_MEMBERS = setOf("type", "commitment_digest", COMMITMENT_DIGEST_DOMAIN_MEMBER)

    /** A strict reader over one body; every overrun refuses with [truncated]. */
    private class Reader(private val b: ByteArray, private var p: Int, private val truncated: String) {
        /** [n] is unsigned: a be64 length of 2^64-1 refuses as truncated, never wraps. */
        fun take(n: ULong): ByteArray {
            if (n > (b.size - p).toULong()) throw CommitmentRefusal(truncated)
            val out = b.copyOfRange(p, p + n.toInt())
            p += n.toInt()
            return out
        }

        fun u8(): Int = take(1u)[0].toInt() and 0xff

        fun be64(): ULong = ByteBuffer.wrap(take(8u)).long.toULong()

        fun framed(): ByteArray = take(be64())

        val atEnd: Boolean get() = p == b.size

        fun done(rule: String) {
            if (!atEnd) throw CommitmentRefusal(rule)
        }
    }

    private fun strictUtf8(raw: ByteArray, rule: String): String =
        try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(raw))
                .toString()
        } catch (e: java.nio.charset.CharacterCodingException) {
            throw CommitmentRefusal(rule)
        }

    /** A Gate text field: valid UTF-8 and non-empty. */
    private fun gateText(r: Reader): String {
        val out = strictUtf8(r.framed(), "gate_text_not_utf8")
        if (out.isEmpty()) throw CommitmentRefusal("gate_text_empty")
        return out
    }

    /** The env rule on raw bytes: exactly `sandbox` or `live`, compared byte for byte. */
    private fun envOf(raw: ByteArray): String = when {
        raw.contentEquals(ENV_SANDBOX) -> "sandbox"
        raw.contentEquals(ENV_LIVE) -> "live"
        else -> throw CommitmentRefusal("env_not_sandbox_or_live")
    }

    /**
     * Decode a Gate block v1 (`0x05` body, after `marker ‖ u32le(len)`) strictly: every `gate_*` rule of
     * `seam-gate-block.v1.md`. The receipt, key id, signature and certificate are framed bytes and are
     * never parsed. Throws [CommitmentRefusal] on any refusal.
     */
    fun decodeGateBody(body: ByteArray): GateBlock {
        if (body.isEmpty()) throw CommitmentRefusal("gate_body_empty")
        val r = Reader(body, 0, "gate_body_truncated")
        if (r.u8() != 0x01) throw CommitmentRefusal("gate_body_unknown_version")
        val status = r.u8()
        if (status != 1 && status != 2) throw CommitmentRefusal("gate_status_invalid")
        val attemptId = gateText(r)
        val domain = gateText(r)
        val flowId = gateText(r)
        val env = envOf(r.framed())
        val timeoutMs = r.be64()
        val onOutage = r.u8()
        if (onOutage != 1 && onOutage != 2) throw CommitmentRefusal("gate_on_outage_invalid")
        val requestedAtMs = r.be64()
        val outage = if (onOutage == 1) "refuse_seal" else "seal_gate_unavailable"
        val out = if (status == 1) {
            val receipt = gateText(r)
            val keyId = gateText(r)
            val sig = r.framed()
            if (sig.size != 64) throw CommitmentRefusal("gate_signature_length")
            val cert = r.framed()
            GateBlock(
                status = "answered", attemptId = attemptId, domain = domain, flowId = flowId, env = env,
                timeoutMs = timeoutMs, onOutage = outage, requestedAtMs = requestedAtMs,
                receiptJcs = receipt, keyId = keyId, signature = sig,
                certificateJcs = if (cert.isEmpty()) null else strictUtf8(cert, "gate_text_not_utf8"),
            )
        } else {
            if (onOutage == 1) throw CommitmentRefusal("gate_unavailable_under_refuse_seal")
            val reason = when (r.u8()) {
                1 -> "timeout"
                2 -> "connect"
                3 -> "http_5xx"
                4 -> throw CommitmentRefusal("gate_reason_reserved")
                5 -> "circuit_open"
                6 -> "token_mint"
                else -> throw CommitmentRefusal("gate_reason_invalid")
            }
            GateBlock(
                status = "unavailable", attemptId = attemptId, domain = domain, flowId = flowId, env = env,
                timeoutMs = timeoutMs, onOutage = outage, requestedAtMs = requestedAtMs,
                reason = reason, givenUpAtMs = r.be64(),
            )
        }
        r.done("gate_body_trailing_bytes")
        return out
    }

    /**
     * `seam-gate-digest:v1`: SHA-256(`be64(19) ‖ "seam-gate-digest:v1" ‖ gate_body`), the body hashed
     * whole, version byte included. The body is decoded strictly first ([decodeGateBody]), so a body the
     * decoder refuses never yields a digest.
     */
    fun gateDigest(body: ByteArray): ByteArray {
        decodeGateBody(body)
        val h = ByteArrayOutputStream()
        h.frame(GATE_DIGEST_DOMAIN.toByteArray(Charsets.US_ASCII))
        h.writeBytes(body)
        return sha256(h.toByteArray())
    }

    /** `0x00`, or `0x01 ‖ F(d)`. */
    private fun slotBytes(d: ByteArray?): ByteArray {
        val h = ByteArrayOutputStream()
        if (d == null) {
            h.write(0x00)
        } else {
            h.write(0x01)
            h.frame(d)
        }
        return h.toByteArray()
    }

    private fun envSlotBytes(env: String?): ByteArray = slotBytes(env?.toByteArray(Charsets.US_ASCII))

    /**
     * The raw v6 `0x05` / `0x06` trailer run a served `seam.api.v1.Commitment` projects (#420): `gate = 13`
     * (`GateRecord.body`, the exact `0x05` body), `governing_doc_sha256 = 11` and `env = 14`. The
     * projection is lossless under v6 (the `0x06` body v2 is exactly `0x02 ‖ doc ‖ env slot`), so this
     * rebuilds the run (empty when the record has neither trailer) for [decodeCommitmentTrailers] to read
     * under every v6 rule: field 10 is still the reader's own Gate digest over the body (VG1), and a Gate
     * block must match the governing env. Nothing served is trusted: each value is hashed into the digest
     * the TCT signs. v6 only. Throws [CommitmentRefusal]: an env without a doc
     * (`env_without_governing_doc`), an env other than `sandbox`/`live`, a doc that is not 32 bytes
     * (`slot_length_not_32`).
     */
    fun servedCommitmentTrailers(gateBody: ByteArray?, governingDocSha256: ByteArray?, env: String?): ByteArray {
        val out = ByteArrayOutputStream()
        fun run(marker: Int, body: ByteArray) {
            out.write(marker)
            val n = body.size
            for (shift in 0 until 32 step 8) out.write((n ushr shift) and 0xff)
            out.write(body)
        }
        if (gateBody != null) run(GATE_TRAILER, gateBody)
        if (env != null) envOf(env.toByteArray(Charsets.UTF_8))
        if (governingDocSha256 == null) {
            if (env != null) throw CommitmentRefusal("env_without_governing_doc")
            return out.toByteArray()
        }
        if (governingDocSha256.size != 32) throw CommitmentRefusal("slot_length_not_32")
        run(GOVERNING_TRAILER, byteArrayOf(0x02) + governingDocSha256 + envSlotBytes(env))
        return out.toByteArray()
    }

    /**
     * Decode the `0x05` / `0x06` trailers a sealed commitment appends into digest fields 10-12. [scheme]
     * is [CommitmentVersion.V5], [CommitmentVersion.V6], or `null` for the scheme-free decode (both `0x06`
     * body versions accepted, the version reported; the caller applies the scheme rules).
     *
     * Markers strictly increase, an unknown marker refuses, nothing may follow the last trailer. `0x05` is
     * decoded by [decodeGateBody], and field 10 frames this decoder's own [gateDigest] over it (VG1); a
     * `0x05` needs a `0x06` body v2 whose env equals the Gate env (`gate_env_binding`). Under v5 a `0x05`
     * or a body v2 refuses; under v6 a body v1 refuses. [trailers] carries only these two trailers: any
     * other commitment trailer marker (`0x01`-`0x04`, `0x07`) is refused as not a digest input; field 9
     * comes from [Commitment.selectionDigest] or [Commitment.selection], as for v5.
     *
     * Throws [CommitmentRefusal] (or [IllegalArgumentException]) on any refusal.
     */
    fun decodeCommitmentTrailers(trailers: ByteArray, scheme: CommitmentVersion?): CommitmentTrailers {
        var pos = 0
        var last = 0
        var gateBody: ByteArray? = null
        var gate: GateBlock? = null
        var doc: ByteArray? = null
        var env: String? = null
        var version: Int? = null
        while (pos < trailers.size) {
            val marker = trailers[pos].toInt() and 0xff
            if (marker < 0x01 || marker > 0x07) throw CommitmentRefusal("unknown_marker")
            if (marker <= last) throw CommitmentRefusal("marker_order")
            last = marker
            val truncated = when (marker) {
                GATE_TRAILER -> {
                    if (scheme == CommitmentVersion.V5) throw CommitmentRefusal("v5_refuses_gate_block")
                    "gate_trailer_truncated"
                }
                GOVERNING_TRAILER -> "governing_trailer_truncated"
                else -> throw IllegalArgumentException(
                    "trailer marker 0x%02x is not a commitment-digest input: pass only the 0x05/0x06 trailers"
                        .format(marker),
                )
            }
            if (trailers.size - pos < 5) throw CommitmentRefusal(truncated)
            val n = ByteBuffer.wrap(trailers, pos + 1, 4).order(ByteOrder.LITTLE_ENDIAN).int.toUInt().toLong()
            if (n > trailers.size - pos - 5) throw CommitmentRefusal(truncated)
            val body = trailers.copyOfRange(pos + 5, pos + 5 + n.toInt())
            pos += 5 + n.toInt()
            if (marker == GATE_TRAILER) {
                gate = decodeGateBody(body)
                gateBody = body
                continue
            }
            if (body.isEmpty()) throw CommitmentRefusal("governing_body_empty")
            val v = body[0].toInt() and 0xff
            if (v != 0x01 && v != 0x02) throw CommitmentRefusal("governing_body_unknown_version")
            if (scheme == CommitmentVersion.V5 && v == 0x02) throw CommitmentRefusal("v5_refuses_governing_body_v2")
            if (scheme == CommitmentVersion.V6 && v == 0x01) throw CommitmentRefusal("v6_refuses_governing_body_v1")
            version = v
            if (v == 0x01) {
                if (body.size != 33) throw CommitmentRefusal("governing_body_length")
                doc = body.copyOfRange(1, 33)
            } else {
                val r = Reader(body, 1, "governing_body_truncated")
                doc = r.take(32u)
                if (r.atEnd) throw CommitmentRefusal("env_presence_missing")
                when (r.u8()) {
                    0x01 -> env = envOf(r.framed())
                    0x00 -> {}
                    else -> throw CommitmentRefusal("env_presence_invalid")
                }
                r.done("governing_body_trailing_bytes")
            }
        }
        if (gate != null && (doc == null || env == null || env != gate.env)) {
            throw CommitmentRefusal("gate_env_binding")
        }
        val gd = gateBody?.let { gateDigest(it) }
        val hasField12 = scheme == CommitmentVersion.V6 || (scheme == null && version == 2)
        return CommitmentTrailers(
            field10 = slotBytes(gd),
            field11 = slotBytes(doc),
            field12 = if (hasField12) envSlotBytes(env) else null,
            governingBodyVersion = version,
            gateDigest = gd,
            gate = gate,
            governingDocSha256 = doc,
            env = env,
        )
    }

    private fun requireAgree(name: String, beside: ByteArray?, field: ByteArray?) {
        require(beside == null || beside.contentEquals(field)) {
            "$name given on the commitment disagrees with the field"
        }
    }

    /**
     * The commitment digest (hex) under [version]: fields 0-8 from [c], fields 9-12 from [f] (the
     * digest-only path; a field-9/10/11 slot also set on [c], or the digest of its [Commitment.selection],
     * must equal [f]'s). Every refusal is checked before anything is hashed: a present slot that is not 32
     * bytes (`slot_length_not_32`), an env that is not exactly `sandbox`/`live`
     * (`env_not_sandbox_or_live`), an env without the governing doc (`env_without_governing_doc`), and any
     * env under v5 (`v5_refuses_env`). [CommitmentVersion.V5] with no env is byte-for-byte
     * `seam-commitment-digest:v5`; [CommitmentVersion.V6] is `seam-commitment-digest:v6` (v5's framing plus
     * field 12, `0x00` or `0x01 ‖ F(env)`).
     *
     * Throws [IllegalArgumentException] ([CommitmentRefusal] for a spec rule) on any refusal.
     */
    fun commitmentDigest(version: CommitmentVersion, c: Commitment, f: CommitmentDigestFields): String {
        if (listOf(f.selectionDigest, f.gateDigest, f.governingDocSha256).any { it != null && it.size != 32 }) {
            throw CommitmentRefusal("slot_length_not_32")
        }
        if (f.env != null) {
            if (version == CommitmentVersion.V5) throw CommitmentRefusal("v5_refuses_env")
            if (f.env != "sandbox" && f.env != "live") throw CommitmentRefusal("env_not_sandbox_or_live")
            if (f.governingDocSha256 == null) throw CommitmentRefusal("env_without_governing_doc")
        }
        val besideSelection = c.selection?.let { blk ->
            val d = selectionDigest(selectionBody(blk))
            require(c.selectionDigest == null || c.selectionDigest.contentEquals(d)) {
                "selection_digest does not match the selection block"
            }
            d
        } ?: c.selectionDigest
        requireAgree("selection_digest", besideSelection, f.selectionDigest)
        requireAgree("certificate_digest", c.certificateDigest, f.gateDigest)
        requireAgree("governing_doc_sha256", c.governingDocSha256, f.governingDocSha256)
        val framed = c.copy(
            selectionDigest = f.selectionDigest,
            certificateDigest = f.gateDigest,
            governingDocSha256 = f.governingDocSha256,
            selection = null,
            trailers = null,
        )
        if (version == CommitmentVersion.V5) return seamCommitmentDigest(framed)
        val explanation = commitmentExplanationDigest(framed)
        val h = ByteArrayOutputStream()
        h.frame(COMMITMENT_DIGEST_DOMAIN_V6.toByteArray(Charsets.UTF_8))
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
        h.writeBytes(slotBytes(f.selectionDigest))
        h.writeBytes(slotBytes(f.gateDigest))
        h.writeBytes(slotBytes(f.governingDocSha256))
        h.writeBytes(envSlotBytes(f.env))
        return sha256(h.toByteArray()).joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    /**
     * The digest [verifyTct] compares, under the selected version only. v5 with no trailers is exactly
     * [seamCommitmentDigest]. Otherwise fields 10-12 come from this decoder's reading of
     * [Commitment.trailers] under that scheme (v6 field 10 never from a value carried beside it), and a
     * slot also set on the commitment must agree with the trailers.
     */
    private fun recomputeCommitmentDigest(version: CommitmentVersion, c: Commitment): String {
        val selection = c.selection?.let { selectionDigest(selectionBody(it)) } ?: c.selectionDigest
        if (version == CommitmentVersion.V5) {
            if (c.gateBody != null) throw CommitmentRefusal("v5_refuses_gate_block")
            if (c.env != null) throw CommitmentRefusal("v5_refuses_env")
            val raw = c.trailers ?: return seamCommitmentDigest(c)
            val t = decodeCommitmentTrailers(raw, CommitmentVersion.V5)
            return commitmentDigest(
                version, c, CommitmentDigestFields(selection, c.certificateDigest, t.governingDocSha256, null),
            )
        }
        // Fields 10-12 come from the trailers only. No raw trailers is a served commitment: its projection
        // is rebuilt into the trailer run (#420), which is then the only source.
        val raw = if (c.trailers == null) {
            servedCommitmentTrailers(c.gateBody, c.governingDocSha256, c.env)
        } else {
            if (c.gateBody != null || c.env != null) throw CommitmentRefusal("served_projection_beside_trailers")
            c.trailers
        }
        val t = decodeCommitmentTrailers(raw, CommitmentVersion.V6)
        return commitmentDigest(
            version, c, CommitmentDigestFields(selection, t.gateDigest, t.governingDocSha256, t.env),
        )
    }

    /**
     * Statement selection (v6 spec §Verifiers) over the raw `ext` JSON text of a commitment TCT. A
     * duplicate member name at ANY depth of `ext` refuses, found on the raw text with names compared after
     * JSON unescaping (`"type"` and `"type"` are one name). The `com.zer07labs.seam` member must
     * exist; members exactly `{type, commitment_digest}` select v5, exactly
     * `{type, commitment_digest, commitment_digest_domain}` with the domain the string
     * `seam-commitment-digest:v6` select v6; any other set, domain, `type`, or a `commitment_digest` that
     * is not 64 lowercase hex refuses. Member order is not significant. Throws [CommitmentRefusal].
     */
    fun selectCommitmentVersion(extRaw: String): CommitmentVersion {
        val ext = parseStatementJson(extRaw) as? Map<*, *> ?: throw CommitmentRefusal("statement_not_object")
        return selectFromExtObject(ext)
    }

    /**
     * [selectCommitmentVersion] entered from the raw statement object itself (the value of
     * `com.zer07labs.seam`), with the same duplicate-member guard over it. Throws [CommitmentRefusal].
     */
    fun selectStatementVersion(statementRaw: String): CommitmentVersion =
        selectFromStatement(parseStatementJson(statementRaw))

    /** Selection from an `ext` map already cleared of duplicates. */
    private fun selectFromExtObject(ext: Map<*, *>): CommitmentVersion {
        if (!ext.containsKey(COMMITMENT_EXT_NAMESPACE)) throw CommitmentRefusal("statement_missing")
        return selectFromStatement(ext[COMMITMENT_EXT_NAMESPACE])
    }

    private fun selectFromStatement(statement: Any?): CommitmentVersion {
        val stmt = statement as? Map<*, *> ?: throw CommitmentRefusal("statement_not_object")
        val keys = stmt.keys.toSet()
        val version = when (keys) {
            V5_MEMBERS -> CommitmentVersion.V5
            V6_MEMBERS -> {
                if (stmt[COMMITMENT_DIGEST_DOMAIN_MEMBER] != COMMITMENT_DIGEST_DOMAIN_V6) {
                    throw CommitmentRefusal("statement_domain_not_v6")
                }
                CommitmentVersion.V6
            }
            else -> throw CommitmentRefusal("statement_member_set")
        }
        if (stmt["type"] != COMMITMENT_STATEMENT) throw CommitmentRefusal("statement_type")
        val d = stmt["commitment_digest"] as? String
        if (d == null || d.length != 64 || !d.all { it in '0'..'9' || it in 'a'..'f' }) {
            throw CommitmentRefusal("statement_digest_not_lowercase_hex")
        }
        return version
    }

    /**
     * Parse statement JSON strictly: not one well-formed JSON value refuses `statement_not_json`; a
     * repeated member name at any depth refuses `statement_duplicate_member`, detected on the raw text
     * (Gson's streaming reader unescapes each name) before any map parse could keep one of the two.
     */
    private fun parseStatementJson(raw: String): Any? {
        val duplicate = try {
            JsonReader(StringReader(raw)).use { r ->
                r.strictness = Strictness.STRICT
                val dup = scanForDuplicate(r)
                if (!dup && r.peek() != JsonToken.END_DOCUMENT) throw CommitmentRefusal("statement_not_json")
                dup
            }
        } catch (e: CommitmentRefusal) {
            throw e
        } catch (e: IOException) {
            throw CommitmentRefusal("statement_not_json")
        } catch (e: RuntimeException) {
            throw CommitmentRefusal("statement_not_json")
        }
        if (duplicate) throw CommitmentRefusal("statement_duplicate_member")
        return gson.fromJson(raw, Any::class.java)
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

/** The commitment digest version a statement selects, or the scheme a trailer decode applies. */
enum class CommitmentVersion { V5, V6 }

/**
 * A v6 / Gate-block refusal. [rule] names the spec rule. The name is ADVISORY (spec §Refusal rules):
 * where an input breaks more than one rule any applicable one may be named, so a caller must branch on
 * the refusal, never on the name.
 */
class CommitmentRefusal(val rule: String) : IllegalArgumentException(rule)

/**
 * The digest-function inputs for fields 9-12 ([SeamCrypto.commitmentDigest]). Each digest is `null` when
 * absent, else exactly 32 bytes; [env] is `null` when absent, else exactly `"sandbox"` or `"live"`.
 * Under v5 [gateDigest] is v5's opaque field-10 slot.
 */
data class CommitmentDigestFields(
    val selectionDigest: ByteArray? = null,
    val gateDigest: ByteArray? = null,
    val governingDocSha256: ByteArray? = null,
    val env: String? = null,
)

/**
 * A decoded Gate block v1 (`0x05` body). [status] is `answered` or `unavailable`; [onOutage] is
 * `refuse_seal` or `seal_gate_unavailable`. The be64 fields are unsigned ([ULong]). Answered only:
 * [receiptJcs], [keyId], [signature] (64 raw bytes) and [certificateJcs] (`null` for a route answer).
 * Unavailable only: [reason] (`timeout`, `connect`, `http_5xx`, `circuit_open`, `token_mint`) and
 * [givenUpAtMs]. Absent fields are `null`.
 */
data class GateBlock(
    val status: String,
    val attemptId: String,
    val domain: String,
    val flowId: String,
    val env: String,
    val timeoutMs: ULong,
    val onOutage: String,
    val requestedAtMs: ULong,
    val receiptJcs: String? = null,
    val keyId: String? = null,
    val signature: ByteArray? = null,
    val certificateJcs: String? = null,
    val reason: String? = null,
    val givenUpAtMs: ULong? = null,
)

/**
 * The `0x05` / `0x06` trailers decoded ([SeamCrypto.decodeCommitmentTrailers]). [field10]/[field11]/
 * [field12] are the encoded digest fields (`0x00`, or `0x01 ‖ F(x)`); [field12] is `null` when the scheme
 * has no field 12 (v5, or a scheme-free decode without a body v2). [governingBodyVersion] is the `0x06`
 * body version (1 or 2), `null` with no `0x06`. The decoded values beside them are `null` when absent.
 */
data class CommitmentTrailers(
    val field10: ByteArray,
    val field11: ByteArray,
    val field12: ByteArray?,
    val governingBodyVersion: Int?,
    val gateDigest: ByteArray?,
    val gate: GateBlock?,
    val governingDocSha256: ByteArray?,
    val env: String?,
)
