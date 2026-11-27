package com.zer07labs.seam;

import com.google.gson.Gson;
import com.google.gson.Strictness;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.Type;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/**
 * Client-side crypto for the Seam Java SDK — stock primitives (Ed25519 via Bouncy Castle + SHA-256), no
 * AITP binding. The admission proof-of-possession is Ed25519 over SHA-256 of a documented,
 * domain-separated canonical byte layout; the seed never leaves the client. Mirrors the Python/Go/TS
 * reference byte-for-byte — pinned by {@code conformance/vectors.json}.
 */
public final class SeamCrypto {
  private SeamCrypto() {}

  private static final byte[] PROOF_DOMAIN = "aitp-pinned-key-v1\0".getBytes(StandardCharsets.UTF_8);
  private static final Gson GSON = new Gson();
  private static final Type MAP = new TypeToken<Map<String, Object>>() {}.getType();

  public record Descriptor(String type, String subject, String proof, String publicKey) {}

  public record Presentation(
      String senderAid, Descriptor descriptor, String messageId, long timestamp, String popNonce) {}

  /**
   * The {@code kind} words the explanation digest frames — lowercase ASCII, exactly; never the proto
   * enum name ({@code EXPLANATION_KIND_VOTE} → {@code "vote"}). {@code "proposal"} (runtime 0.90.0,
   * option selection) is one accepted option of a selection session; it never carries a voter record.
   */
  public static final List<String> EXPLANATION_KINDS =
      List.of("vote", "evaluation", "objection", "ballot", "proposal");

  /** The voter-verification {@code method} words the explanation digest frames — lowercase, exactly. */
  public static final List<String> VOTER_VERIFICATION_METHODS = List.of("pop", "cp_signed");

  /**
   * A sealed voter verification record (seam-runtime #1687, {@code voter-verification.v1.md}): the
   * voter's own proof of possession plus where it was cast and when the runtime accepted it.
   * {@code method} is {@code "pop"} or {@code "cp_signed"} (never the proto enum name); {@code
   * contentDigest} is the 32 raw bytes of {@code seam-vote-content-v1}; {@code signerCertificate} is
   * empty for {@code pop}. Integers are read as UNSIGNED 64-bit values.
   */
  public record VoterVerification(
      String method,
      String principal,
      byte[] contentDigest,
      long issuedAtMs,
      long expiresAtMs,
      byte[] signature,
      byte[] signerCertificate,
      String tenant,
      String namespace,
      String sessionId,
      long openedAtMillis,
      String issuer,
      String audience,
      long acceptedAtMs) {}

  /**
   * One sealed explanation entry. {@code confidence} and {@code rationaleRef} are {@code null} when
   * absent — an absent confidence and a stated {@code 0.0} are different bytes, which is the point of
   * the explanation digest. {@code voterVerification} is {@code null} when absent (evaluations); the
   * runtime seals one on every vote, ballot and objection (#1687).
   */
  public record ExplanationEntry(
      String kind,
      String participant,
      String proposalId,
      String value,
      String reason,
      Double confidence,
      String rationaleRef,
      VoterVerification voterVerification) {
    /** An entry with no voter verification record (an evaluation). */
    public ExplanationEntry(
        String kind,
        String participant,
        String proposalId,
        String value,
        String reason,
        Double confidence,
        String rationaleRef) {
      this(kind, participant, proposalId, value, reason, confidence, rationaleRef, null);
    }
  }

  /**
   * The commitment fields {@code seam-commitment-digest:v5} binds. {@code committer} may be {@code
   * null} (hashed as empty). {@code supersedes} is {@code null} when ABSENT, which v5 frames as
   * {@code 0x00} — a different digest from a present empty string ({@code 0x01 ‖ F("")}). Field 8 resolves from {@code explanation} (the
   * entries) and/or {@code explanationDigest} (the 32 published bytes) — see {@link #verifyTct}.
   * {@code selectionDigest} (field 9) and {@code certificateDigest} (field 10) are {@code null} when
   * absent — every record runtime 0.88.0 seals — and exactly 32 bytes when present. {@code
   * governingDocSha256} (field 11, #1711) is the SHA-256 of the tenant governing document the decision
   * was sealed under ({@code Commitment.governing_doc_sha256} on the wire): {@code null} for an
   * ungoverned decision, else exactly 32 bytes. {@code trailers} (Flows W2) is the raw {@code 0x05}
   * (Gate block) and {@code 0x06} (governing document) trailer bytes the sealed commitment appends, in
   * order and nothing else; {@code null} when not given. {@link #verifyTct} derives fields 10-12 from
   * them under the version the TCT's statement selects ({@link #decodeCommitmentTrailers}); with
   * {@code null} a v5 verification is exactly what it was before the field existed. {@code gateBody}
   * and {@code env} (#420) are the served projection: {@code seam.api.v1.Commitment} carries no raw
   * trailers, only {@code gate = 13} ({@code GateRecord.body}, the exact {@code 0x05} body) beside
   * {@code governing_doc_sha256} and {@code env = 14}. With {@code trailers == null}, {@link
   * #verifyTct} under v6 rebuilds the trailer run from them ({@link #servedCommitmentTrailers}) and
   * decodes it under every v6 rule; v5 refuses either. Setting either beside {@code trailers} is
   * refused.
   */
  public record Commitment(
      String id,
      String action,
      String authority,
      String supersedes,
      String authMethod,
      String trustBasis,
      String committer,
      byte[] explanationDigest,
      List<ExplanationEntry> explanation,
      byte[] selectionDigest,
      byte[] certificateDigest,
      byte[] governingDocSha256,
      byte[] trailers,
      byte[] gateBody,
      String env) {
    /**
     * A commitment with its raw trailers and no served projection ({@code gateBody} and {@code env}
     * absent): every pre-#420 caller.
     */
    public Commitment(
        String id,
        String action,
        String authority,
        String supersedes,
        String authMethod,
        String trustBasis,
        String committer,
        byte[] explanationDigest,
        List<ExplanationEntry> explanation,
        byte[] selectionDigest,
        byte[] certificateDigest,
        byte[] governingDocSha256,
        byte[] trailers) {
      this(
          id,
          action,
          authority,
          supersedes,
          authMethod,
          trustBasis,
          committer,
          explanationDigest,
          explanation,
          selectionDigest,
          certificateDigest,
          governingDocSha256,
          trailers,
          null,
          null);
    }

    /** A commitment given without its raw trailers (every pre-W2 caller). */
    public Commitment(
        String id,
        String action,
        String authority,
        String supersedes,
        String authMethod,
        String trustBasis,
        String committer,
        byte[] explanationDigest,
        List<ExplanationEntry> explanation,
        byte[] selectionDigest,
        byte[] certificateDigest,
        byte[] governingDocSha256) {
      this(
          id,
          action,
          authority,
          supersedes,
          authMethod,
          trustBasis,
          committer,
          explanationDigest,
          explanation,
          selectionDigest,
          certificateDigest,
          governingDocSha256,
          null);
    }

    /** An ungoverned commitment (field 11 absent) with the given field 9/10 slots. */
    public Commitment(
        String id,
        String action,
        String authority,
        String supersedes,
        String authMethod,
        String trustBasis,
        String committer,
        byte[] explanationDigest,
        List<ExplanationEntry> explanation,
        byte[] selectionDigest,
        byte[] certificateDigest) {
      this(
          id,
          action,
          authority,
          supersedes,
          authMethod,
          trustBasis,
          committer,
          explanationDigest,
          explanation,
          selectionDigest,
          certificateDigest,
          null);
    }

    /**
     * A commitment with neither a selection (field 9) nor a Gate certificate (field 10), and no
     * governing document (field 11).
     */
    public Commitment(
        String id,
        String action,
        String authority,
        String supersedes,
        String authMethod,
        String trustBasis,
        String committer,
        byte[] explanationDigest,
        List<ExplanationEntry> explanation) {
      this(
          id,
          action,
          authority,
          supersedes,
          authMethod,
          trustBasis,
          committer,
          explanationDigest,
          explanation,
          null,
          null,
          null);
    }
  }

  // ── base64url (no padding) ──────────────────────────────────────────────────────────────────
  private static String b64urlNoPad(byte[] b) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  private static byte[] b64urlDecode(String s) {
    int pad = (4 - s.length() % 4) % 4;
    return Base64.getUrlDecoder().decode(s + "=".repeat(pad));
  }

  private static byte[] sha256(byte[] b) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(b);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  // ── Ed25519 (Bouncy Castle) ─────────────────────────────────────────────────────────────────
  private static byte[] ed25519Pub(byte[] seed) {
    return new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded();
  }

  private static byte[] ed25519Sign(byte[] seed, byte[] msg) {
    Ed25519Signer signer = new Ed25519Signer();
    signer.init(true, new Ed25519PrivateKeyParameters(seed, 0));
    signer.update(msg, 0, msg.length);
    return signer.generateSignature();
  }

  private static boolean ed25519Verify(byte[] pub, byte[] msg, byte[] sig) {
    try {
      Ed25519Signer verifier = new Ed25519Signer();
      verifier.init(false, new Ed25519PublicKeyParameters(pub, 0));
      verifier.update(msg, 0, msg.length);
      return verifier.verifySignature(sig);
    } catch (RuntimeException e) {
      return false;
    }
  }

  /** The agent's {@code aid:pubkey:ed25519:} identity for a 32-byte Ed25519 public key. */
  public static String aidFromPubkey(byte[] pub) {
    return "aid:pubkey:ed25519:" + b64urlNoPad(pub);
  }

  private static byte[] aidToPubkey(String aid) {
    for (String p : new String[] {"aid:pubkey:ed25519:", "aid:pubkey:"}) {
      if (aid.startsWith(p)) {
        return b64urlDecode(aid.substring(p.length()));
      }
    }
    throw new IllegalArgumentException("unsupported AID form: " + aid);
  }

  /** Domain tag of the PoP admission {@code message_id}: {@code derivedUuid(tag, nonce_ascii)}. */
  public static final String POP_MESSAGE_ID_TAG = "seam-pop-mid-v1";

  /**
   * Deterministic, v4-shaped UUID: the first 16 bytes of {@code SHA-256(tag ‖ 0x00 ‖ input)} with the
   * version nibble set to 4 and the variant bits to {@code 10}, lowercase and hyphenated. The {@code
   * 0x00} separates tag from input, so no (tag, input) pair collides with another by shifting bytes
   * across the boundary. Pinned by {@code derived_uuid} in {@code conformance/vectors.json}.
   */
  public static String derivedUuid(String tag, byte[] input) {
    return derivedUuidOf(tag, input);
  }

  /** Domain tag of the commitment TCT {@code jti} derivation (AITP registry {@code seam-tct-jti-v1}). */
  public static final String TCT_JTI_TAG = "seam-tct-jti-v1";

  /**
   * The TCT {@code jti} the seal path mints (seam-runtime {@code deterministic_jti}): {@code
   * derivedUuid("seam-tct-jti-v1", be32(len decisionId) ‖ decisionId ‖ be64(sealedAtMs))}. {@code
   * decisionId} is the sealed record's id ({@code DecisionRecord.decision_id}, UTF-8), never {@code
   * Commitment.id}; {@code sealedAtMs} its {@code sealed_at} in ms. Pinned by {@code
   * conformance/tct_sealed_at_vector.json} ({@code jti_kat}).
   */
  public static String tctJti(String decisionId, long sealedAtMs) {
    byte[] id = decisionId.getBytes(StandardCharsets.UTF_8);
    java.nio.ByteBuffer b = java.nio.ByteBuffer.allocate(4 + id.length + 8);
    b.putInt(id.length).put(id).putLong(sealedAtMs);
    return derivedUuidOf(TCT_JTI_TAG, b.array());
  }

  private static String derivedUuidOf(String tag, byte[] input) {
    ByteArrayOutputStream pre = new ByteArrayOutputStream();
    pre.writeBytes(tag.getBytes(StandardCharsets.UTF_8));
    pre.write(0);
    pre.writeBytes(input);
    byte[] h = sha256(pre.toByteArray());
    h[6] = (byte) ((h[6] & 0x0f) | 0x40);
    h[8] = (byte) ((h[8] & 0x3f) | 0x80);
    StringBuilder sb = new StringBuilder(36);
    for (int i = 0; i < 16; i++) {
      if (i == 4 || i == 6 || i == 8 || i == 10) sb.append('-');
      sb.append(String.format("%02x", h[i] & 0xff));
    }
    return sb.toString();
  }

  /** The admission {@code message_id}: {@code derivedUuid("seam-pop-mid-v1", nonce_ascii)}. */
  public static String popMessageId(String popNonce) {
    return derivedUuid(POP_MESSAGE_ID_TAG, popNonce.getBytes(StandardCharsets.US_ASCII));
  }

  /** Build the pinned-key admission presentation the Seam server verifies. */
  public static Presentation buildPresentation(
      byte[] agentSeed, String receiverAid, String popNonce, long nowMs) {
    byte[] pub = ed25519Pub(agentSeed);
    String senderAid = aidFromPubkey(pub);
    String mid = popMessageId(popNonce);
    long timestamp = nowMs / 1000;

    ByteArrayOutputStream in = new ByteArrayOutputStream();
    in.writeBytes(PROOF_DOMAIN);
    in.writeBytes(senderAid.getBytes(StandardCharsets.UTF_8));
    in.write(0);
    in.writeBytes(receiverAid.getBytes(StandardCharsets.UTF_8));
    in.write(0);
    in.writeBytes(mid.getBytes(StandardCharsets.UTF_8));
    in.write(0);
    in.writeBytes(Long.toString(timestamp).getBytes(StandardCharsets.US_ASCII)); // ASCII-decimal
    in.write(0);
    in.writeBytes(b64urlDecode(popNonce));

    byte[] proof = ed25519Sign(agentSeed, sha256(in.toByteArray()));
    return new Presentation(
        senderAid,
        new Descriptor("pinned_key", senderAid, b64urlNoPad(proof), b64urlNoPad(pub)),
        mid,
        timestamp,
        popNonce);
  }

  private static void be64Frame(ByteArrayOutputStream out, byte[] b) {
    out.writeBytes(ByteBuffer.allocate(8).putLong(b.length).array());
    out.writeBytes(b);
  }

  private static void be64(ByteArrayOutputStream out, long v) {
    out.writeBytes(ByteBuffer.allocate(8).putLong(v).array());
  }

  /**
   * Domain tag of the option-selection block digest that {@code seam-commitment-digest:v5} binds as
   * field 9 (runtime 0.90.0, seam-runtime {@code docs/specs/selection-rule.v1.md}).
   */
  public static final String SELECTION_DIGEST_DOMAIN = "seam-selection-digest:v1";

  /** One weight override of a {@link SelectionBlock}; {@code weight} is a u32. */
  public record SelectionWeight(String participant, long weight) {}

  /** One sealed context pair of a {@link SelectionBlock}; {@code contentHash} is "" when none. */
  public record SelectionContext(String ctxRef, String contentHash) {}

  /**
   * The sealed {@code seam.selection.weighted_plurality} block (selection-rule.v1 §4.2), field for
   * field in {@code body} order; the generated {@code SelectionRecord} ({@code Commitment.selection =
   * 12}) maps onto it one to one. Integer fields are u32 carried as {@code long}.
   */
  public record SelectionBlock(
      String rule,
      long ruleVersion,
      long defaultWeight,
      List<SelectionWeight> weights,
      String tie,
      String abstention,
      long minBallots,
      String policyVersion,
      byte[] rulesDigest,
      List<String> participants,
      List<String> onBehalfOf,
      List<SelectionContext> context,
      String winnerProposalId) {}

  private static void u32(ByteArrayOutputStream out, String name, long v) {
    if (v < 0 || v > 0xFFFF_FFFFL) {
      throw new IllegalArgumentException(name + " is " + v + ", outside u32");
    }
    be64(out, v);
  }

  private static byte[] utf8(String s) {
    return nz(s);
  }

  /**
   * The canonical selection block {@code body} (selection-rule.v1 §4.2), framed only with {@code F(x)
   * = be64(len) ‖ x} and {@code U(n) = be64(n)}. Field 9 of {@code seam-commitment-digest:v5} is
   * {@link #selectionDigest}{@code (selectionBody(block))}: pass it as {@link
   * Commitment#selectionDigest()}.
   *
   * <p>Framing the block is not checking it: {@link #verifySelection} recomputes the winner offline
   * (selection-rule.v1 §5 steps 6-9), and {@link #verifyTct(String, String, Commitment, long,
   * SelectionBlock)} runs it whenever a block is supplied.
   *
   * @throws IllegalArgumentException for a block the runtime could not have sealed: weights not
   *     strictly ascending by participant UTF-8 bytes (duplicates included), a rules digest that is
   *     not 32 bytes, an empty winner, or an integer outside u32 — refused rather than hashed.
   */
  public static byte[] selectionBody(SelectionBlock b) {
    List<SelectionWeight> weights = b.weights() == null ? List.of() : b.weights();
    for (int i = 1; i < weights.size(); i++) {
      if (Arrays.compareUnsigned(
              utf8(weights.get(i - 1).participant()), utf8(weights.get(i).participant()))
          >= 0) {
        throw new IllegalArgumentException(
            "selection weights are not strictly ascending by participant (weights_not_canonical)");
      }
    }
    if (b.rulesDigest() == null || b.rulesDigest().length != 32) {
      throw new IllegalArgumentException("selection rules_digest must be 32 bytes");
    }
    if (b.winnerProposalId() == null || b.winnerProposalId().isEmpty()) {
      throw new IllegalArgumentException("selection winner_proposal_id is empty (empty_winner)");
    }
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    be64Frame(out, utf8(b.rule()));
    u32(out, "rule_version", b.ruleVersion());
    u32(out, "default_weight", b.defaultWeight());
    be64(out, weights.size());
    for (SelectionWeight w : weights) {
      be64Frame(out, utf8(w.participant()));
      u32(out, "weight", w.weight());
    }
    be64Frame(out, utf8(b.tie()));
    be64Frame(out, utf8(b.abstention()));
    u32(out, "min_ballots", b.minBallots());
    be64Frame(out, utf8(b.policyVersion()));
    be64Frame(out, b.rulesDigest());
    List<String> participants = b.participants() == null ? List.of() : b.participants();
    be64(out, participants.size());
    for (String p : participants) {
      be64Frame(out, utf8(p));
    }
    List<String> onBehalfOf = b.onBehalfOf() == null ? List.of() : b.onBehalfOf();
    be64(out, onBehalfOf.size());
    for (String o : onBehalfOf) {
      be64Frame(out, utf8(o));
    }
    List<SelectionContext> context = b.context() == null ? List.of() : b.context();
    be64(out, context.size());
    for (SelectionContext c : context) {
      be64Frame(out, utf8(c.ctxRef()));
      be64Frame(out, utf8(c.contentHash()));
    }
    be64Frame(out, utf8(b.winnerProposalId()));
    return out.toByteArray();
  }

  /**
   * {@code SHA-256(F("seam-selection-digest:v1") ‖ body)}: the 32 bytes v5 field 9 binds.
   */
  public static byte[] selectionDigest(byte[] body) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    be64Frame(out, SELECTION_DIGEST_DOMAIN.getBytes(StandardCharsets.UTF_8));
    out.writeBytes(body);
    return sha256(out.toByteArray());
  }

  // ── decide() (selection-rule.v1 §3) and the verifier's selection steps (§5 steps 6-9) ─────────

  /** The one selection rule v1 knows. */
  public static final String SELECTION_RULE = "seam.selection.weighted_plurality";

  /** The one rule version v1 knows. */
  public static final long SELECTION_RULE_VERSION = 1;

  /** The one tie policy v1 knows. */
  public static final String SELECTION_TIE = "no_winner";

  /** The one abstention policy v1 knows. */
  public static final String SELECTION_ABSTENTION = "excluded_counts_for_quorum";

  /** The mode a selection session's votes sign ({@code seam-vote-content-v1}'s {@code mode}). */
  public static final String SELECTION_MODE = "macp.mode.decision.v1";

  /** The vote values a selection vote may carry. */
  public static final List<String> SELECTION_VOTE_VALUES = List.of("APPROVE", "REJECT", "ABSTAIN");

  /** One proposal's tally in a {@link SelectionDecision}, in sealed proposal order. */
  public record SelectionScore(String proposalId, long score) {}

  /**
   * The outcome of {@link #decide}. {@code result} is {@code "winner"}, {@code "no_winner"} or
   * {@code "malformed"}. A winner carries {@code winnerProposalId} and {@code option}; a no-winner
   * carries {@code reason} ({@code below_min_ballots}, {@code no_positive_score}, {@code tie}); both
   * carry {@code scores} (every proposal, sealed order) and {@code ballots}. A malformed record carries
   * {@code reason} and {@code at}: the entry index, {@code null} for a record-level check.
   */
  public record SelectionDecision(
      String result,
      String winnerProposalId,
      String option,
      List<SelectionScore> scores,
      long ballots,
      String reason,
      Integer at) {
    static SelectionDecision malformed(String reason, Integer at) {
      return new SelectionDecision("malformed", null, null, null, 0, reason, at);
    }
  }

  /**
   * The outcome of {@link #verifySelection}. {@code result} is {@code "verified"} or one of the spec's
   * verifier result names ({@code selection_malformed}, {@code selection_no_winner_sealed}, {@code
   * selection_winner_mismatch}, {@code selection_action_mismatch}, {@code selection_vote_unverified},
   * {@code selection_content_link_mismatch}, {@code selection_principal_not_one_to_one}). {@code at}
   * is the entry index where the check failed, when the spec names one; {@code reason} is {@link
   * #decide}'s reason for a malformed or no-winner record; {@code recomputed} is the winner this
   * verifier computed when it disagrees with the sealed one.
   */
  public record SelectionResult(
      String result,
      String winnerProposalId,
      int votesLinked,
      Integer at,
      String reason,
      String recomputed) {
    static SelectionResult of(String result) {
      return new SelectionResult(result, null, 0, null, null, null);
    }

    static SelectionResult at(String result, int at) {
      return new SelectionResult(result, null, 0, at, null, null);
    }

    public boolean ok() {
      return "verified".equals(result);
    }
  }

  private static String recordMalformed(SelectionBlock b) {
    if (!SELECTION_RULE.equals(b.rule())) return "unknown_rule";
    if (b.ruleVersion() != SELECTION_RULE_VERSION) return "unknown_rule_version";
    if (!SELECTION_TIE.equals(b.tie())) return "unknown_tie";
    if (!SELECTION_ABSTENTION.equals(b.abstention())) return "unknown_abstention";
    List<SelectionWeight> weights = b.weights() == null ? List.of() : b.weights();
    for (int i = 1; i < weights.size(); i++) {
      if (Arrays.compareUnsigned(
              utf8(weights.get(i - 1).participant()), utf8(weights.get(i).participant()))
          >= 0) {
        return "weights_not_canonical";
      }
    }
    if (b.defaultWeight() == 0 && weights.stream().allMatch(w -> w.weight() == 0)) {
      return "zero_electorate";
    }
    if (b.minBallots() == 0) return "min_ballots_zero";
    List<String> participants = b.participants() == null ? List.of() : b.participants();
    if (participants.isEmpty()) return "no_participants";
    if (new HashSet<>(participants).size() != participants.size()) return "duplicate_participant";
    return null;
  }

  /**
   * {@code decide(record, entries)} (selection-rule.v1 §3): a pure function of the selection record
   * and the sealed explanation entries. The record's {@code winnerProposalId} is ignored (it may be
   * {@code null}). Options compare by UTF-8 bytes, never normalised. Twin of Python {@code decide}.
   */
  public static SelectionDecision decide(SelectionBlock b, List<ExplanationEntry> entries) {
    String bad = recordMalformed(b);
    if (bad != null) return SelectionDecision.malformed(bad, null);
    Map<String, Long> weights = new java.util.HashMap<>();
    for (SelectionWeight w : b.weights() == null ? List.<SelectionWeight>of() : b.weights()) {
      weights.put(w.participant(), w.weight());
    }
    Set<String> participants = new HashSet<>(b.participants());
    Map<String, String> proposals = new LinkedHashMap<>();
    Set<ByteBuffer> options = new HashSet<>();
    Set<List<String>> voted = new HashSet<>();
    Set<String> approvers = new HashSet<>();
    Set<String> voters = new HashSet<>();
    List<String[]> approvals = new ArrayList<>();
    boolean seenVote = false;
    for (int i = 0; i < entries.size(); i++) {
      ExplanationEntry e = entries.get(i);
      String kind = e.kind();
      if ("proposal".equals(kind)) {
        if (seenVote) return SelectionDecision.malformed("proposal_after_vote", i);
        if (e.voterVerification() != null) {
          return SelectionDecision.malformed("proposal_has_voter_record", i);
        }
        if (!nzs(e.reason()).isEmpty() || e.confidence() != null || e.rationaleRef() != null) {
          return SelectionDecision.malformed("proposal_has_extra_fields", i);
        }
        String pid = nzs(e.proposalId());
        String value = nzs(e.value());
        if (pid.isEmpty()) return SelectionDecision.malformed("empty_proposal_id", i);
        if (value.isEmpty()) return SelectionDecision.malformed("empty_option", i);
        if (proposals.containsKey(pid)) {
          return SelectionDecision.malformed("duplicate_proposal_id", i);
        }
        ByteBuffer opt = ByteBuffer.wrap(utf8(value));
        if (options.contains(opt)) return SelectionDecision.malformed("duplicate_option", i);
        proposals.put(pid, value);
        options.add(opt);
      } else if ("vote".equals(kind)) {
        seenVote = true;
        String who = nzs(e.participant());
        String pid = nzs(e.proposalId());
        if (!proposals.containsKey(pid)) {
          return SelectionDecision.malformed("vote_unknown_proposal", i);
        }
        if (e.value() == null || !SELECTION_VOTE_VALUES.contains(e.value())) {
          return SelectionDecision.malformed("vote_bad_value", i);
        }
        if (!participants.contains(who)) {
          return SelectionDecision.malformed("vote_not_participant", i);
        }
        List<String> key = List.of(who, pid);
        if (voted.contains(key)) return SelectionDecision.malformed("duplicate_vote", i);
        if ("APPROVE".equals(e.value())) {
          if (!approvers.add(who)) return SelectionDecision.malformed("double_approve", i);
          approvals.add(new String[] {who, pid});
        }
        voted.add(key);
        voters.add(who);
      } else if ("evaluation".equals(kind) || "objection".equals(kind)) {
        continue; // sealed, never scored (v1 admits no objection veto)
      } else if ("ballot".equals(kind)) {
        return SelectionDecision.malformed("ballot_in_selection", i);
      } else {
        return SelectionDecision.malformed("unknown_kind", i);
      }
    }
    if (proposals.isEmpty()) return SelectionDecision.malformed("no_proposals", null);
    Map<String, Long> scores = new LinkedHashMap<>();
    for (String pid : proposals.keySet()) scores.put(pid, 0L);
    for (String[] a : approvals) {
      scores.merge(a[1], weights.getOrDefault(a[0], b.defaultWeight()), Long::sum);
    }
    long ballots = voters.size();
    long top = scores.values().stream().mapToLong(Long::longValue).max().orElse(0);
    List<String> leaders = new ArrayList<>();
    List<SelectionScore> tally = new ArrayList<>();
    for (Map.Entry<String, Long> s : scores.entrySet()) {
      tally.add(new SelectionScore(s.getKey(), s.getValue()));
      if (s.getValue() == top) leaders.add(s.getKey());
    }
    String noWinner =
        ballots < b.minBallots()
            ? "below_min_ballots"
            : top == 0 ? "no_positive_score" : leaders.size() > 1 ? "tie" : null;
    if (noWinner != null) {
      return new SelectionDecision("no_winner", null, null, tally, ballots, noWinner, null);
    }
    String w = leaders.get(0);
    return new SelectionDecision("winner", w, proposals.get(w), tally, ballots, null, null);
  }

  private static String nzs(String s) {
    return s == null ? "" : s;
  }

  /**
   * Selection-rule.v1 §5 steps 6-9 over a selection block, the sealed entries and {@code
   * Commitment.action}. Step 6 recomputes the winner ({@link #decide}) and checks it is the sealed
   * one; step 7 checks the winner's sealed option is {@code action} byte for byte; step 8 re-derives
   * every vote's {@code seam-vote-content-v1} digest from sealed inputs alone and checks it is the
   * record's {@code contentDigest}; step 9 checks participant ↔ principal is one-to-one across the
   * votes. Signatures and the TCT are {@link #verifyTct}'s. Twin of Python {@code verify_selection}.
   */
  public static SelectionResult verifySelection(
      SelectionBlock b, List<ExplanationEntry> entries, String action) {
    SelectionDecision d = decide(b, entries);
    if ("malformed".equals(d.result())) {
      return new SelectionResult("selection_malformed", null, 0, d.at(), d.reason(), null);
    }
    if ("no_winner".equals(d.result())) {
      return new SelectionResult("selection_no_winner_sealed", null, 0, null, d.reason(), null);
    }
    if (!d.winnerProposalId().equals(b.winnerProposalId())) {
      return new SelectionResult(
          "selection_winner_mismatch", null, 0, null, null, d.winnerProposalId());
    }
    if (action == null || !Arrays.equals(utf8(d.option()), utf8(action))) {
      return SelectionResult.of("selection_action_mismatch");
    }
    Map<String, String> proposals = new java.util.HashMap<>();
    for (ExplanationEntry e : entries) {
      if ("proposal".equals(e.kind())) proposals.put(e.proposalId(), e.value());
    }
    VotePolicyRef policy = new VotePolicyRef(b.policyVersion(), b.rulesDigest());
    List<VoteContext> ctx = new ArrayList<>();
    for (SelectionContext c : b.context() == null ? List.<SelectionContext>of() : b.context()) {
      ctx.add(new VoteContext(c.ctxRef(), c.contentHash()));
    }
    int linked = 0;
    for (int i = 0; i < entries.size(); i++) {
      ExplanationEntry e = entries.get(i);
      if (!"vote".equals(e.kind())) continue;
      VoterVerification vv = e.voterVerification();
      if (vv == null) return SelectionResult.at("selection_vote_unverified", i);
      byte[] want =
          voteContentDigest(
              SELECTION_MODE,
              e.proposalId(),
              proposals.get(e.proposalId()),
              b.participants(),
              b.onBehalfOf(),
              ctx,
              List.of(),
              policy);
      if (!Arrays.equals(vv.contentDigest(), want)) {
        return SelectionResult.at("selection_content_link_mismatch", i);
      }
      linked++;
    }
    Map<String, String> byParticipant = new java.util.HashMap<>();
    Map<String, String> byPrincipal = new java.util.HashMap<>();
    for (int i = 0; i < entries.size(); i++) {
      ExplanationEntry e = entries.get(i);
      if (!"vote".equals(e.kind())) continue;
      String p = e.participant();
      String a = e.voterVerification().principal();
      String sealedPrincipal = byParticipant.putIfAbsent(p, a);
      String sealedParticipant = byPrincipal.putIfAbsent(a, p);
      if ((sealedPrincipal != null && !sealedPrincipal.equals(a))
          || (sealedParticipant != null && !sealedParticipant.equals(p))) {
        return SelectionResult.at("selection_principal_not_one_to_one", i);
      }
    }
    return new SelectionResult("verified", d.winnerProposalId(), linked, null, null, null);
  }

  /** Domain tag of the explanation digest. */
  public static final String EXPLANATION_DIGEST_DOMAIN = "seam-explanation-digest:v2";

  /**
   * {@code seam-explanation-digest:v2} over a sealed explanation (32 raw bytes), entries in sealed
   * order: {@code SHA-256(F("seam-explanation-digest:v2") ‖ be64(count) ‖ Σ ENTRY)}, with {@code ENTRY
   * = F(kind) ‖ F(participant) ‖ F(proposal_id) ‖ F(value) ‖ F(reason) ‖ CONF ‖ REF ‖ VV}, {@code CONF =
   * 0x00 | 0x01 ‖ be64(IEEE-754 bits)}, {@code REF = 0x00 | 0x01 ‖ F(rationale_ref)}, {@code VV = 0x00
   * | 0x01 ‖ F(method) ‖ F(principal) ‖ F(content_digest) ‖ be64(issued_at_ms) ‖ be64(expires_at_ms) ‖
   * F(signature) ‖ F(signer_certificate) ‖ F(tenant) ‖ F(namespace) ‖ F(session_id) ‖
   * be64(opened_at_millis) ‖ F(issuer) ‖ F(audience) ‖ be64(accepted_at_ms)} and {@code F(x) =
   * be64(len) ‖ x}. Never sorts, never de-duplicates.
   *
   * @throws IllegalArgumentException on an unknown kind, a non-canonical confidence (NaN, ±inf,
   *     outside {@code [0.0, 1.0]}, or {@code -0.0}), an unknown voter-verification method, or a
   *     content digest that is not 32 bytes — refused rather than hashed. Normative: {@code
   *     seam-runtime/docs/specs/seam-commitment-digest.v5.md}.
   */
  public static byte[] explanationDigest(List<ExplanationEntry> entries) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    be64Frame(out, EXPLANATION_DIGEST_DOMAIN.getBytes(StandardCharsets.UTF_8));
    out.writeBytes(ByteBuffer.allocate(8).putLong(entries.size()).array());
    for (ExplanationEntry e : entries) {
      if (e == null || !EXPLANATION_KINDS.contains(e.kind())) {
        throw new IllegalArgumentException(
            "unknown explanation kind " + (e == null ? null : e.kind()));
      }
      be64Frame(out, nz(e.kind()));
      be64Frame(out, nz(e.participant()));
      be64Frame(out, nz(e.proposalId()));
      be64Frame(out, nz(e.value()));
      be64Frame(out, nz(e.reason()));
      Double conf = e.confidence();
      if (conf == null) {
        out.write(0x00);
      } else {
        double d = conf;
        // -0.0 has a set sign bit; `d >= 0.0` alone would admit it (and NaN fails every comparison).
        long bits = Double.doubleToRawLongBits(d);
        if (!(d >= 0.0 && d <= 1.0) || bits < 0) {
          throw new IllegalArgumentException("non-canonical confidence " + d);
        }
        out.write(0x01);
        out.writeBytes(ByteBuffer.allocate(8).putLong(bits).array());
      }
      if (e.rationaleRef() == null) {
        out.write(0x00);
      } else {
        out.write(0x01);
        be64Frame(out, e.rationaleRef().getBytes(StandardCharsets.UTF_8));
      }
      VoterVerification v = e.voterVerification();
      if (v == null) {
        out.write(0x00);
      } else {
        if (v.method() == null || !VOTER_VERIFICATION_METHODS.contains(v.method())) {
          throw new IllegalArgumentException("unknown voter verification method " + v.method());
        }
        if (v.contentDigest() == null || v.contentDigest().length != 32) {
          throw new IllegalArgumentException("voter verification content_digest must be 32 bytes");
        }
        out.write(0x01);
        be64Frame(out, nz(v.method()));
        be64Frame(out, nz(v.principal()));
        be64Frame(out, v.contentDigest());
        be64(out, v.issuedAtMs());
        be64(out, v.expiresAtMs());
        be64Frame(out, v.signature() == null ? new byte[0] : v.signature());
        be64Frame(out, v.signerCertificate() == null ? new byte[0] : v.signerCertificate());
        be64Frame(out, nz(v.tenant()));
        be64Frame(out, nz(v.namespace()));
        be64Frame(out, nz(v.sessionId()));
        be64(out, v.openedAtMillis());
        be64Frame(out, nz(v.issuer()));
        be64Frame(out, nz(v.audience()));
        be64(out, v.acceptedAtMs());
      }
    }
    return sha256(out.toByteArray());
  }

  /**
   * The explanation digest a commitment binds as field 8, checked when the entries are present. With
   * the entries: recomputed from them, and if a published digest is ALSO given the two must agree
   * (spec §Verification step 1). With only the published digest: used as published — verifies
   * <i>who</i> and <i>what</i> but not <i>why</i>. With neither: the empty explanation.
   *
   * @throws IllegalArgumentException on a disagreement, a malformed entry, or a published digest that
   *     is not 32 bytes.
   */
  static byte[] commitmentExplanationDigest(Commitment c) {
    byte[] published = c.explanationDigest();
    if (published != null && published.length != 32) {
      throw new IllegalArgumentException("explanation_digest must be 32 bytes");
    }
    if (c.explanation() == null) {
      return published != null ? published.clone() : explanationDigest(List.of());
    }
    byte[] computed = explanationDigest(c.explanation());
    if (published != null && !MessageDigest.isEqual(published, computed)) {
      throw new IllegalArgumentException(
          "explanation_digest does not match the explanation entries");
    }
    return computed;
  }

  /** Domain tag of the commitment digest. */
  public static final String COMMITMENT_DIGEST_DOMAIN = "seam-commitment-digest:v5";

  /** The one grant a commitment self-attestation carries. */
  public static final String ATTESTATION_GRANT = "aitp.attestation";

  /** The {@code ext} namespace the commitment statement rides under. */
  public static final String COMMITMENT_EXT_NAMESPACE = "com.zer07labs.seam";

  /** The statement {@code type} inside {@link #COMMITMENT_EXT_NAMESPACE}. */
  public static final String COMMITMENT_STATEMENT = "seam:commitment";

  /**
   * {@code seam-commitment-digest:v5} (hex): SHA-256 over a <b>length-prefixed</b> framing of a domain
   * tag plus the commitment fields — each field preceded by its 8-byte big-endian length. Mirrors the
   * runtime byte-for-byte, and mirrors the Go/Kotlin/Python/TypeScript shims. v1-v4 are deleted, not
   * dual-verified. {@code supersedes} carries a presence byte — {@code 0x00} when absent ({@code
   * null}), {@code 0x01 ‖ F(s)} when present. v4 (#1687) binds the v2 explanation digest as field 8 and
   * appends two always-framed slots: field 9 (selection digest) and field 10 (Gate certificate
   * digest), each {@code 0x00} when absent or {@code 0x01 ‖ be64(32) ‖ 32 raw bytes}. v5 (#1711) appends
   * field 11, the governing document digest, in the same slot encoding.
   *
   * <p><b>The length prefixes are not decoration and must never be "simplified" to a separator.</b>
   * The fields are arbitrary text that may itself contain NUL — UTF-8 permits U+0000, and it
   * survives the JSON/prost decision path — so with a {@code \0} separator the tuples
   * {@code ("a\0b","c")} and {@code ("a","b\0c")} produce IDENTICAL preimages, and therefore
   * identical digests. That would let one Commitment verify under another's TCT: an attacker who
   * controls a field boundary could shift bytes across it and reuse a signature that was never
   * issued for their artifact. Length-prefixing makes the digest injective over the field tuple
   * regardless of content.
   *
   * <p>It is written out here because this comment is the only thing standing between a future
   * maintainer and a "cleanup" that silently breaks artifact binding.
   *
   * <p>Field order is also load-bearing and must match the runtime exactly: domain, id, action,
   * authority, supersedes, auth_method, trust_basis, committer, then the 32 RAW bytes (not hex) of the
   * explanation digest ({@link #commitmentExplanationDigest}). Binding {@code committer}/{@code
   * auth_method}/{@code trust_basis} makes the artifact attest <i>who</i> committed it and <i>how</i>
   * they authed; binding the explanation makes it attest <i>why</i>. {@code ConformanceTest} asserts
   * every one of these is bound.
   *
   * @throws IllegalArgumentException when field 8 cannot be resolved (see {@link
   *     #commitmentExplanationDigest}), or a present field 9/10/11 digest is not 32 bytes.
   */
  static String seamCommitmentDigest(Commitment c) {
    checkSlot("selection_digest", c.selectionDigest());
    checkSlot("certificate_digest", c.certificateDigest());
    checkSlot("governing_doc_sha256", c.governingDocSha256());
    byte[] explanation = commitmentExplanationDigest(c);
    ByteArrayOutputStream h = new ByteArrayOutputStream();
    be64Frame(h, COMMITMENT_DIGEST_DOMAIN.getBytes(StandardCharsets.UTF_8));
    be64Frame(h, nz(c.id()));
    be64Frame(h, nz(c.action()));
    be64Frame(h, nz(c.authority()));
    if (c.supersedes() == null) {
      h.write(0x00);
    } else {
      h.write(0x01);
      be64Frame(h, c.supersedes().getBytes(StandardCharsets.UTF_8));
    }
    be64Frame(h, nz(c.authMethod()));
    be64Frame(h, nz(c.trustBasis()));
    be64Frame(h, nz(c.committer()));
    be64Frame(h, explanation);
    optionalDigestSlot(h, c.selectionDigest());
    optionalDigestSlot(h, c.certificateDigest());
    optionalDigestSlot(h, c.governingDocSha256());
    return hex(sha256(h.toByteArray()));
  }

  private static void checkSlot(String name, byte[] d) {
    if (d != null && d.length != 32) {
      throw new IllegalArgumentException(name + " must be 32 bytes when present");
    }
  }

  private static void optionalDigestSlot(ByteArrayOutputStream h, byte[] d) {
    if (d == null) {
      h.write(0x00);
    } else {
      h.write(0x01);
      be64Frame(h, d);
    }
  }

  // ── The seal key (seam-runtime #2031, deep-cleanup S-4, runtime 0.123.0) ──────────────────────
  //
  // Normative: seam-runtime docs/specs/seam-commitment-digest.v6.md §Seal key. The pinned issuer no
  // longer signs commitment TCTs: it certifies a short-lived in-memory seal key, and the TCT is a
  // self-attestation by that key carrying the certificate in a second ext member. Pinned by
  // conformance/seal_key_cert_vector.json. No backward compatibility: an issuer-signed TCT is refused.

  /** The TCT {@code ext} member that carries the seal-key certificate. */
  public static final String SEAL_KEY_CERT_EXT_KEY = "com.zer07labs.seam.seal-key-cert";

  /** Domain tag, the certificate's first frame. */
  public static final String SEAL_KEY_CERT_DOMAIN = "seam.seal-key-cert.v1";

  /** The widest certificate window accepted, {@code not_after - not_before}: 1 h plus 30 s skew. */
  public static final long SEAL_KEY_MAX_WINDOW_MS = 3_630_000L;

  private static final int SEAL_KEY_ISSUER_AID_MAX = 62;

  /** A parsed seal-key certificate. {@code notBeforeMs}/{@code notAfterMs} are within [0, Long.MAX_VALUE]. */
  public record SealKeyCert(byte[] sealPk, long notBeforeMs, long notAfterMs, String issuerAid) {
    /** The seal key's untagged {@code aid:pubkey:} AID: the commitment TCT's {@code iss == sub == aud}. */
    public String sealAid() {
      return "aid:pubkey:" + b64urlNoPad(sealPk);
    }

    /** {@code notBeforeMs <= iat*1000 <= notAfterMs}, no grace; an overflowing {@code iat} is outside. */
    public boolean covers(long iatSecs) {
      long t;
      try {
        t = Math.multiplyExact(iatSecs, 1000L);
      } catch (ArithmeticException e) {
        return false;
      }
      return notBeforeMs <= t && t <= notAfterMs;
    }
  }

  /** {@code framed(x)}: {@code u32le(len) ‖ x} — the runtime's chain framing primitive. */
  private static void framedPut(ByteArrayOutputStream out, byte[] b) {
    out.writeBytes(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(b.length).array());
    out.writeBytes(b);
  }

  /**
   * {@code framed("seam.seal-key-cert.v1") ‖ framed(seal_pk) ‖ le64(not_before_ms) ‖ le64(not_after_ms)
   * ‖ framed(issuer_aid)} — the bytes the issuer signs SHA-256 of.
   */
  public static byte[] sealKeyCertPreimage(
      byte[] sealPk, long notBeforeMs, long notAfterMs, String issuerAid) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    framedPut(out, SEAL_KEY_CERT_DOMAIN.getBytes(StandardCharsets.US_ASCII));
    framedPut(out, sealPk);
    ByteBuffer le = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
    le.putLong(notBeforeMs).putLong(notAfterMs);
    out.writeBytes(le.array());
    framedPut(out, issuerAid.getBytes(StandardCharsets.UTF_8));
    return out.toByteArray();
  }

  /**
   * Parse a certificate; {@code null} on a wrong tag, a key that is not 32 bytes, a short read,
   * trailing bytes, an inverted window, a time beyond {@code Long.MAX_VALUE} ms, a window wider than
   * {@link #SEAL_KEY_MAX_WINDOW_MS}, or an issuer AID that is longer than 62 bytes or not UTF-8.
   */
  public static SealKeyCert parseSealKeyCert(byte[] b) {
    if (b == null) return null;
    int[] pos = {0};
    byte[] tag = framedGet(b, pos);
    if (tag == null || !Arrays.equals(tag, SEAL_KEY_CERT_DOMAIN.getBytes(StandardCharsets.US_ASCII))) {
      return null;
    }
    byte[] pk = framedGet(b, pos);
    if (pk == null || pk.length != 32) return null;
    if (b.length - pos[0] < 16) return null;
    ByteBuffer le = ByteBuffer.wrap(b, pos[0], 16).order(ByteOrder.LITTLE_ENDIAN);
    long nb = le.getLong();
    long na = le.getLong();
    pos[0] += 16;
    byte[] aid = framedGet(b, pos);
    if (aid == null || pos[0] != b.length || aid.length > SEAL_KEY_ISSUER_AID_MAX) return null;
    // Unsigned u64 in a signed long: a negative value is > i64::MAX, refused.
    if (nb < 0 || na < 0 || nb > na || na - nb > SEAL_KEY_MAX_WINDOW_MS) return null;
    String issuer;
    try {
      issuer =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
              .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
              .decode(ByteBuffer.wrap(aid))
              .toString();
    } catch (java.nio.charset.CharacterCodingException e) {
      return null;
    }
    return new SealKeyCert(pk, nb, na, issuer);
  }

  private static byte[] framedGet(byte[] b, int[] pos) {
    if (b.length - pos[0] < 4) return null;
    long len = Integer.toUnsignedLong(
        ByteBuffer.wrap(b, pos[0], 4).order(ByteOrder.LITTLE_ENDIAN).getInt());
    if (len > b.length - pos[0] - 4) return null;
    byte[] out = Arrays.copyOfRange(b, pos[0] + 4, pos[0] + 4 + (int) len);
    pos[0] += 4 + (int) len;
    return out;
  }

  /**
   * Verify a certificate under the PINNED issuer AID: it must name exactly that AID, and the
   * issuer's strict Ed25519 signature over {@code sha256(cert)} must hold. {@code null} on any failure.
   */
  public static SealKeyCert verifySealKeyCert(String pinnedIssuerAid, byte[] cert, byte[] sig) {
    try {
      SealKeyCert f = parseSealKeyCert(cert);
      if (f == null || !pinnedIssuerAid.equals(f.issuerAid())) return null;
      byte[] pub = aidToPubkey(pinnedIssuerAid);
      if (pub.length != 32 || sig == null || sig.length != 64) return null;
      return ed25519VerifyStrict(pub, sha256(cert), sig) ? f : null;
    } catch (RuntimeException e) {
      return null;
    }
  }

  /**
   * The 32-byte encodings that decode to an Ed25519 point of small order (the 8-torsion), canonical
   * and not. ed25519-dalek's {@code verify_strict} refuses a small-order public key and a small-order
   * {@code R}; Bouncy Castle checks neither, so this list closes the gap. Every other strictness
   * (canonical {@code S}, {@code R} compared by encoding) is Bouncy Castle's own.
   */
  private static final String[] SMALL_ORDER_ENCODINGS = {
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
  };

  private static boolean smallOrder(byte[] enc32) {
    String h = hex(enc32);
    for (String s : SMALL_ORDER_ENCODINGS) {
      if (s.equals(h)) return true;
    }
    return false;
  }

  /** Ed25519 verify with dalek {@code verify_strict}'s extra refusals (small-order key or R). */
  static boolean ed25519VerifyStrict(byte[] pub, byte[] msg, byte[] sig) {
    if (pub.length != 32 || sig.length != 64) return false;
    if (smallOrder(pub) || smallOrder(Arrays.copyOfRange(sig, 0, 32))) return false;
    return ed25519Verify(pub, msg, sig);
  }

  /**
   * Strict unpadded base64url: alphabet {@code [A-Za-z0-9_-]} only, no {@code =}, a length that is
   * not 1 mod 4, and canonical trailing bits (re-encoding the bytes gives the input back).
   * {@code null} when refused.
   */
  static byte[] b64urlDecodeStrict(String s) {
    if (s == null || s.length() % 4 == 1) return null;
    for (int i = 0; i < s.length(); i++) {
      char ch = s.charAt(i);
      boolean ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
          || ch == '-' || ch == '_';
      if (!ok) return null;
    }
    byte[] b;
    try {
      b = b64urlDecode(s);
    } catch (IllegalArgumentException e) {
      return null;
    }
    return b64urlNoPad(b).equals(s) ? b : null;
  }

  /** RFC 7638 thumbprint of an Ed25519 key: the AITP {@code cnf.jkt}. */
  static String ed25519Jkt(byte[] pk) {
    String jwk = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + b64urlNoPad(pk) + "\"}";
    return b64urlNoPad(sha256(jwk.getBytes(StandardCharsets.US_ASCII)));
  }

  /** The literal of a top-level JSON integer member, or {@code null} if absent or not a plain integer. */
  private static Long topLevelInteger(String json, String name) {
    try (JsonReader r = new JsonReader(new StringReader(json))) {
      r.setStrictness(Strictness.STRICT);
      r.beginObject();
      while (r.hasNext()) {
        if (!r.nextName().equals(name)) {
          r.skipValue();
          continue;
        }
        if (r.peek() != JsonToken.NUMBER) return null;
        String lit = r.nextString();
        // A JSON integer: no fraction, no exponent (serde refuses 1.0 and 1e3 as an i64).
        if (!lit.matches("-?(0|[1-9][0-9]*)")) return null;
        return Long.parseLong(lit);
      }
      return null;
    } catch (IOException | RuntimeException e) {
      return null;
    }
  }

  /**
   * Independently verify a sealed commitment's rooted TCT — zero server trust, stock crypto only.
   *
   * <p><b>Seal key (seam-runtime #2031, S-4; runtime 0.123.0+).</b> The TCT is signed by a seal key
   * the pinned issuer certifies, never by the issuer itself: (1) {@code
   * ext["com.zer07labs.seam.seal-key-cert"]} is exactly {@code {cert, sig}}, strict base64url; (2) the
   * certificate parses ({@link #parseSealKeyCert}), names exactly {@code issuerAid}, and the issuer's
   * strict Ed25519 signature over {@code sha256(cert)} holds; (3) the JWS verifies under the seal key,
   * {@code iss == sub == aud ==} the seal AID and {@code cnf.jkt} is its thumbprint; (4) {@code
   * not_before <= iat*1000 <= not_after}, no grace. An issuer-signed TCT (every TCT before S-4) is
   * refused: no backward compatibility. The checks below are otherwise unchanged:
   * {@code exp}; that {@code grants} is
   * exactly {@code ["aitp.attestation"]}; and that {@code ext} is exactly {@code
   * {"com.zer07labs.seam":{"type":"seam:commitment","commitment_digest":<hex>}}} (plus the certificate member) with the hex equal to
   * the recomputed {@code seam-commitment-digest:v5} of this exact commitment (decided content,
   * committer, governing document digest, and sealed explanation). Since Flows W2 the statement may
   * instead carry {@code "commitment_digest_domain":"seam-commitment-digest:v6"}: the exact member
   * set selects the version ({@link #selectCommitmentVersion}), that version's trailer rules apply
   * to {@link Commitment#trailers()}, and the digest is recomputed under it alone (v6 spec
   * §Verifiers). A v5 statement with no trailers verifies exactly as before. A header or payload whose JSON repeats an object key at any
   * depth is refused: Gson would keep one of the two, and another parser might keep the other. Any malformed/forged input fails closed (returns {@code false}), never throws
   * — including explanation entries that disagree with the published digest, an unknown kind, or a
   * non-canonical confidence.
   */
  public static boolean verifyTct(String issuerAid, String tctJws, Commitment c, long nowS) {
    return verifyTctAt(issuerAid, tctJws, c, nowS, null);
  }

  /**
   * {@link #verifyTct(String, String, Commitment, long)} <b>bound to the chained record it
   * seals</b> — the evidence-grade check (seam-commitment-digest.v6 §Seal key steps 6 and 7,
   * evidence-bundle.v1 §Verifying step 4): additionally {@code sealedAtMs >= 0}, the TCT's {@code
   * iat == floor(sealedAtMs / 1000)} and its {@code jti == tctJti(decisionId, sealedAtMs)} exactly.
   *
   * <p>{@code iat} is self-asserted, so {@link #verifyTct} alone proves a certified seal key signed
   * the statement, not when: a leaked seal key can backdate a token anywhere in its certificate
   * window. {@code sealedAtMs} must be the {@code sealed_at} of the record's <b>chained</b> {@code
   * DECISION_SEALED} link (record-digest bound), never a value from the token and never a served
   * {@code DecisionRecordView.sealed_at}. A Java {@code long} is the runtime's i64 bound exactly, so
   * a negative value (an unsigned {@code uint64} beyond it) is refused. {@code decisionId} is the
   * {@code decision_id} of that same chained link, never {@code Commitment.id}: the {@code jti} rule
   * (seam-runtime 0.127.0 P4) refuses a genuine seal replayed onto another record, or with its seal
   * time shifted inside its second (same {@code iat}). A null {@code decisionId} is refused. Same
   * rule as seam-verify {@code verify_tct_sealed_at} and the runtime's {@code
   * check_commitment_sealed_for}; pinned by {@code conformance/tct_sealed_at_vector.json}.
   */
  public static boolean verifyTctSealedAt(
      String issuerAid, String tctJws, Commitment c, long nowS, String decisionId, long sealedAtMs) {
    return verifyTctAt(issuerAid, tctJws, c, nowS, new SealedFor(decisionId, sealedAtMs));
  }

  /** The chained record a sealed-at verification binds the token to. */
  private record SealedFor(String decisionId, long sealedAtMs) {}

  /**
   * {@link #verifyTctSealedAt(String, String, Commitment, long, String, long)} for an
   * option-selection decision: {@link #verifyTct(String, String, Commitment, long, SelectionBlock)}
   * with the evidence-grade {@code iat} and {@code jti} binding.
   */
  public static boolean verifyTctSealedAt(
      String issuerAid,
      String tctJws,
      Commitment c,
      long nowS,
      SelectionBlock selection,
      String decisionId,
      long sealedAtMs) {
    return verifyTctSelection(
        issuerAid, tctJws, c, nowS, selection, new SealedFor(decisionId, sealedAtMs));
  }

  private static boolean verifyTctAt(
      String issuerAid, String tctJws, Commitment c, long nowS, SealedFor sealed) {
    try {
      String[] parts = tctJws.split("\\.");
      if (parts.length != 3) return false;
      String headerJson = new String(b64urlDecode(parts[0]), StandardCharsets.UTF_8);
      String payloadJson = new String(b64urlDecode(parts[1]), StandardCharsets.UTF_8);
      if (hasDuplicateKey(headerJson) || hasDuplicateKey(payloadJson)) return false;
      Map<String, Object> header = GSON.fromJson(headerJson, MAP);
      Map<String, Object> payload = GSON.fromJson(payloadJson, MAP);
      if (header == null || payload == null) return false;
      // S-4 (1) + (2): peek the certificate member from the not-yet-verified payload and verify it
      // under the PINNED issuer; it names the seal key that must have signed the token.
      if (!(payload.get("ext") instanceof Map<?, ?> peekExt)
          || !(peekExt.get(SEAL_KEY_CERT_EXT_KEY) instanceof Map<?, ?> member)
          || member.size() != 2
          || !(member.get("cert") instanceof String certB64)
          || !(member.get("sig") instanceof String sigB64)) {
        return false;
      }
      byte[] certBytes = b64urlDecodeStrict(certB64);
      byte[] certSig = b64urlDecodeStrict(sigB64);
      if (certBytes == null || certSig == null) return false;
      SealKeyCert cert = verifySealKeyCert(issuerAid, certBytes, certSig);
      if (cert == null) return false;
      String sealAid = cert.sealAid();
      // (3) the token is a self-attestation by the certified seal key.
      if (!ed25519Verify(cert.sealPk(), (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII),
          b64urlDecode(parts[2]))) {
        return false;
      }
      if (!"EdDSA".equals(header.get("alg")) || !"aitp-tct+jwt".equals(header.get("typ"))) {
        return false;
      }
      if (!(sealAid.equals(payload.get("iss"))
          && sealAid.equals(payload.get("sub"))
          && sealAid.equals(payload.get("aud")))) {
        return false;
      }
      if (!(payload.get("cnf") instanceof Map<?, ?> cnf)
          || !ed25519Jkt(cert.sealPk()).equals(cnf.get("jkt"))) {
        return false;
      }
      if (!(payload.get("ext") instanceof Map<?, ?> verifiedExt)
          || !member.equals(verifiedExt.get(SEAL_KEY_CERT_EXT_KEY))) {
        return false;
      }
      // (4) iat is a JSON integer inside the certificate window, no grace.
      Long iat = topLevelInteger(payloadJson, "iat");
      if (iat == null || !cert.covers(iat)) return false;
      // Evidence grade (S-4 + P4): iat is the chained seal second and jti names the chained record.
      if (sealed != null) {
        if (sealed.sealedAtMs() < 0 || iat != sealed.sealedAtMs() / 1000) return false;
        if (sealed.decisionId() == null
            || !(payload.get("jti") instanceof String jti)
            || !jti.equals(tctJti(sealed.decisionId(), sealed.sealedAtMs()))) return false;
      }
      Object exp = payload.get("exp");
      if (!(exp instanceof Number) || nowS >= ((Number) exp).longValue()) return false;
      if (!(payload.get("grants") instanceof List<?> grants)
          || grants.size() != 1
          || !ATTESTATION_GRANT.equals(grants.get(0))) {
        return false;
      }
      // ext is exactly the statement and the certificate member, nothing else.
      if (!(payload.get("ext") instanceof Map<?, ?> ext)
          || ext.size() != 2
          || !ext.containsKey(SEAL_KEY_CERT_EXT_KEY)) {
        return false;
      }
      // Flows W2: the statement's exact member set selects v5 or v6 (the duplicate-member guard ran
      // over the raw payload above, so it covers every depth of ext). Recompute under that version
      // only: never both, never a fallback.
      CommitmentVersion version = selectFromExtObject(ext);
      Object digest = ((Map<?, ?>) ext.get(COMMITMENT_EXT_NAMESPACE)).get("commitment_digest");
      return digest.equals(recomputeCommitmentDigest(version, c));
    } catch (RuntimeException e) {
      return false;
    }
  }

  /**
   * {@link #verifyTct(String, String, Commitment, long)} for an option-selection decision (runtime
   * 0.90.0, selection-rule.v1 §5 steps 4, 6-9). With {@code selection == null} this is exactly the
   * four-argument form: "not a selection decision". With a block, v5 field 9 is framed from this
   * verifier's own {@link #selectionDigest}{@code (}{@link #selectionBody}{@code (selection))} — a
   * {@link Commitment#selectionDigest()} given beside it must agree — and the winner is recomputed
   * offline ({@link #verifySelection}): the committed action must be the winning option and every
   * vote's signed content must link to it. A block with no {@link Commitment#explanation()} entries
   * cannot be checked, so it fails closed ({@code false}) rather than passing as if it had been.
   */
  public static boolean verifyTct(
      String issuerAid, String tctJws, Commitment c, long nowS, SelectionBlock selection) {
    return verifyTctSelection(issuerAid, tctJws, c, nowS, selection, null);
  }

  private static boolean verifyTctSelection(
      String issuerAid,
      String tctJws,
      Commitment c,
      long nowS,
      SelectionBlock selection,
      SealedFor sealed) {
    if (selection == null) return verifyTctAt(issuerAid, tctJws, c, nowS, sealed);
    try {
      byte[] field9 = selectionDigest(selectionBody(selection));
      if (c.selectionDigest() != null && !Arrays.equals(c.selectionDigest(), field9)) return false;
      Commitment framed =
          new Commitment(
              c.id(), c.action(), c.authority(), c.supersedes(), c.authMethod(), c.trustBasis(),
              c.committer(), c.explanationDigest(), c.explanation(), field9, c.certificateDigest(),
              c.governingDocSha256(), c.trailers(), c.gateBody(), c.env());
      if (!verifyTctAt(issuerAid, tctJws, framed, nowS, sealed)) return false;
      if (c.explanation() == null) return false;
      return verifySelection(selection, c.explanation(), c.action()).ok();
    } catch (RuntimeException e) {
      return false;
    }
  }

  /**
   * True when {@code json} repeats an object key at any depth — or is not a single well-formed JSON
   * value, which fails closed the same way.
   */
  static boolean hasDuplicateKey(String json) {
    try (JsonReader r = new JsonReader(new StringReader(json))) {
      r.setStrictness(Strictness.STRICT);
      return scanForDuplicate(r) || r.peek() != JsonToken.END_DOCUMENT;
    } catch (IOException | RuntimeException e) {
      return true;
    }
  }

  private static boolean scanForDuplicate(JsonReader r) throws IOException {
    switch (r.peek()) {
      case BEGIN_OBJECT -> {
        r.beginObject();
        Set<String> seen = new HashSet<>();
        while (r.hasNext()) {
          if (!seen.add(r.nextName()) || scanForDuplicate(r)) return true;
        }
        r.endObject();
        return false;
      }
      case BEGIN_ARRAY -> {
        r.beginArray();
        while (r.hasNext()) {
          if (scanForDuplicate(r)) return true;
        }
        r.endArray();
        return false;
      }
      default -> {
        r.skipValue();
        return false;
      }
    }
  }

  // ── seam-commitment-digest:v6 + the Gate block v1 (Flows W2, readers only) ──────────────────
  //
  // Normative: seam-runtime docs/specs/seam-commitment-digest.v6.md and seam-gate-block.v1.md.
  // Pinned by conformance/commitment_digest_v6_vector.json, commitment_digest_v6_signed_vector.json
  // and gate_block_vector.json. Every be64 is an UNSIGNED 64-bit value held in a Java long: compared
  // with Long.compareUnsigned and printed with Long.toUnsignedString, never as a signed number.

  /** Domain tag of the v6 commitment digest. v5 ({@link #COMMITMENT_DIGEST_DOMAIN}) is unchanged. */
  public static final String COMMITMENT_DIGEST_DOMAIN_V6 = "seam-commitment-digest:v6";

  /** Domain tag of the Gate digest v6 field 10 frames: SHA-256(F(tag) ‖ gate_body). */
  public static final String GATE_DIGEST_DOMAIN = "seam-gate-digest:v1";

  /** The {@code ext} statement member that selects v6 ({@code commitment_digest_domain}). */
  public static final String COMMITMENT_DIGEST_DOMAIN_MEMBER = "commitment_digest_domain";

  private static final int GATE_TRAILER = 0x05;
  private static final int GOVERNING_TRAILER = 0x06;
  private static final byte[] ENV_SANDBOX = "sandbox".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] ENV_LIVE = "live".getBytes(StandardCharsets.US_ASCII);
  private static final Set<String> V5_MEMBERS = Set.of("type", "commitment_digest");
  private static final Set<String> V6_MEMBERS =
      Set.of("type", "commitment_digest", COMMITMENT_DIGEST_DOMAIN_MEMBER);

  /** The commitment digest version a statement selects, or the scheme a trailer decode applies. */
  public enum CommitmentVersion {
    V5,
    V6
  }

  /**
   * A v6 / Gate-block refusal. {@link #rule()} names the spec rule. The name is ADVISORY (spec
   * §Refusal rules): where an input breaks more than one rule any applicable one may be named, so a
   * caller must branch on the refusal, never on the name.
   */
  public static final class CommitmentRefusal extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;
    private final String rule;

    public CommitmentRefusal(String rule) {
      super(rule);
      this.rule = rule;
    }

    public String rule() {
      return rule;
    }
  }

  /**
   * The digest-function inputs for fields 9-12 ({@link #commitmentDigest}). Each digest is {@code
   * null} when absent, else exactly 32 bytes; {@code env} is {@code null} when absent, else exactly
   * {@code "sandbox"} or {@code "live"}. Under v5 {@code gateDigest} is v5's opaque field-10 slot.
   */
  public record CommitmentDigestFields(
      byte[] selectionDigest, byte[] gateDigest, byte[] governingDocSha256, String env) {}

  /**
   * A decoded Gate block v1 ({@code 0x05} body). {@code status} is {@code answered} or {@code
   * unavailable}; {@code onOutage} is {@code refuse_seal} or {@code seal_gate_unavailable}. {@code
   * timeoutMs}, {@code requestedAtMs} and {@code givenUpAtMs} are UNSIGNED 64-bit values (read them
   * with {@link Long#toUnsignedString(long)}). Answered only: {@code receiptJcs}, {@code keyId},
   * {@code signature} (64 raw bytes) and {@code certificateJcs} ({@code null} for a route answer).
   * Unavailable only: {@code reason} ({@code timeout}, {@code connect}, {@code http_5xx}, {@code
   * circuit_open}, {@code token_mint}) and {@code givenUpAtMs}. Absent fields are {@code null}.
   */
  public record GateBlock(
      String status,
      String attemptId,
      String domain,
      String flowId,
      String env,
      long timeoutMs,
      String onOutage,
      long requestedAtMs,
      String receiptJcs,
      String keyId,
      byte[] signature,
      String certificateJcs,
      String reason,
      Long givenUpAtMs) {}

  /**
   * The {@code 0x05} / {@code 0x06} trailers decoded ({@link #decodeCommitmentTrailers}). {@code
   * field10}/{@code field11}/{@code field12} are the encoded digest fields ({@code 0x00}, or {@code
   * 0x01 ‖ F(x)}); {@code field12} is {@code null} when the scheme has no field 12 (v5, or a
   * scheme-free decode without a body v2). {@code governingBodyVersion} is the {@code 0x06} body
   * version (1 or 2), {@code null} with no {@code 0x06}. The decoded values beside them are {@code
   * null} when absent.
   */
  public record CommitmentTrailers(
      byte[] field10,
      byte[] field11,
      byte[] field12,
      Integer governingBodyVersion,
      byte[] gateDigest,
      GateBlock gate,
      byte[] governingDocSha256,
      String env) {}

  private static CommitmentRefusal refused(String rule) {
    return new CommitmentRefusal(rule);
  }

  /** A strict reader over one body; every overrun refuses with {@code truncated}. */
  private static final class Reader {
    private final byte[] b;
    private final String truncated;
    private int p;

    Reader(byte[] b, int start, String truncated) {
      this.b = b;
      this.p = start;
      this.truncated = truncated;
    }

    /** {@code n} is UNSIGNED: a be64 length of 2^64-1 is -1 here and still refuses as truncated. */
    byte[] take(long n) {
      if (Long.compareUnsigned(n, b.length - p) > 0) throw refused(truncated);
      byte[] out = Arrays.copyOfRange(b, p, p + (int) n);
      p += (int) n;
      return out;
    }

    int u8() {
      return take(1)[0] & 0xff;
    }

    long be64() {
      return ByteBuffer.wrap(take(8)).getLong();
    }

    byte[] framed() {
      return take(be64());
    }

    boolean atEnd() {
      return p == b.length;
    }

    void done(String rule) {
      if (!atEnd()) throw refused(rule);
    }
  }

  private static String strictUtf8(byte[] raw, String rule) {
    try {
      return StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
          .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(raw))
          .toString();
    } catch (java.nio.charset.CharacterCodingException e) {
      throw refused(rule);
    }
  }

  /** A Gate text field: valid UTF-8 and non-empty. */
  private static String gateText(Reader r) {
    String out = strictUtf8(r.framed(), "gate_text_not_utf8");
    if (out.isEmpty()) throw refused("gate_text_empty");
    return out;
  }

  /** The env rule on raw bytes: exactly {@code sandbox} or {@code live}, compared byte for byte. */
  private static String envOf(byte[] raw) {
    if (Arrays.equals(raw, ENV_SANDBOX)) return "sandbox";
    if (Arrays.equals(raw, ENV_LIVE)) return "live";
    throw refused("env_not_sandbox_or_live");
  }

  /**
   * Decode a Gate block v1 ({@code 0x05} body, after {@code marker ‖ u32le(len)}) strictly: every
   * {@code gate_*} rule of {@code seam-gate-block.v1.md}. The receipt, key id, signature and
   * certificate are framed bytes and are never parsed.
   *
   * @throws CommitmentRefusal on any refusal.
   */
  public static GateBlock decodeGateBody(byte[] body) {
    if (body.length == 0) throw refused("gate_body_empty");
    Reader r = new Reader(body, 0, "gate_body_truncated");
    if (r.u8() != 0x01) throw refused("gate_body_unknown_version");
    int status = r.u8();
    if (status != 1 && status != 2) throw refused("gate_status_invalid");
    String attemptId = gateText(r);
    String domain = gateText(r);
    String flowId = gateText(r);
    String env = envOf(r.framed());
    long timeoutMs = r.be64();
    int onOutage = r.u8();
    if (onOutage != 1 && onOutage != 2) throw refused("gate_on_outage_invalid");
    long requestedAtMs = r.be64();
    String outage = onOutage == 1 ? "refuse_seal" : "seal_gate_unavailable";
    GateBlock out;
    if (status == 1) {
      String receipt = gateText(r);
      String keyId = gateText(r);
      byte[] sig = r.framed();
      if (sig.length != 64) throw refused("gate_signature_length");
      byte[] cert = r.framed();
      String certificate = cert.length == 0 ? null : strictUtf8(cert, "gate_text_not_utf8");
      out =
          new GateBlock(
              "answered", attemptId, domain, flowId, env, timeoutMs, outage, requestedAtMs, receipt,
              keyId, sig, certificate, null, null);
    } else {
      if (onOutage == 1) throw refused("gate_unavailable_under_refuse_seal");
      int reason = r.u8();
      String why =
          switch (reason) {
            case 1 -> "timeout";
            case 2 -> "connect";
            case 3 -> "http_5xx";
            case 4 -> throw refused("gate_reason_reserved");
            case 5 -> "circuit_open";
            case 6 -> "token_mint";
            default -> throw refused("gate_reason_invalid");
          };
      long givenUpAtMs = r.be64();
      out =
          new GateBlock(
              "unavailable", attemptId, domain, flowId, env, timeoutMs, outage, requestedAtMs, null,
              null, null, null, why, givenUpAtMs);
    }
    r.done("gate_body_trailing_bytes");
    return out;
  }

  /**
   * {@code seam-gate-digest:v1}: SHA-256({@code be64(19) ‖ "seam-gate-digest:v1" ‖ gate_body}), the
   * body hashed whole, version byte included. The body is decoded strictly first ({@link
   * #decodeGateBody}), so a body the decoder refuses never yields a digest.
   *
   * @throws CommitmentRefusal when the body is refused.
   */
  public static byte[] gateDigest(byte[] body) {
    decodeGateBody(body);
    ByteArrayOutputStream h = new ByteArrayOutputStream();
    be64Frame(h, GATE_DIGEST_DOMAIN.getBytes(StandardCharsets.US_ASCII));
    h.writeBytes(body);
    return sha256(h.toByteArray());
  }

  /** {@code 0x00}, or {@code 0x01 ‖ F(d)}. */
  private static byte[] slotBytes(byte[] d) {
    ByteArrayOutputStream h = new ByteArrayOutputStream();
    optionalDigestSlot(h, d);
    return h.toByteArray();
  }

  private static byte[] envSlotBytes(String env) {
    return slotBytes(env == null ? null : env.getBytes(StandardCharsets.US_ASCII));
  }

  /**
   * The raw v6 {@code 0x05} / {@code 0x06} trailer run a served {@code seam.api.v1.Commitment}
   * projects (#420): {@code gate = 13} ({@code GateRecord.body}, the exact {@code 0x05} body), {@code
   * governing_doc_sha256 = 11} and {@code env = 14}. The projection is lossless under v6 (the {@code
   * 0x06} body v2 is exactly {@code 0x02 ‖ doc ‖ env slot}), so this rebuilds the run (empty when the
   * record has neither trailer) for {@link #decodeCommitmentTrailers} to read under every v6 rule:
   * field 10 is still the reader's own Gate digest over the body (VG1), and a Gate block must match
   * the governing env. Nothing served is trusted: each value is hashed into the digest the TCT signs.
   * v6 only. Throws {@link CommitmentRefusal}: an env without a doc ({@code
   * env_without_governing_doc}), an env other than {@code sandbox}/{@code live}, a doc that is not 32
   * bytes ({@code slot_length_not_32}).
   */
  public static byte[] servedCommitmentTrailers(byte[] gateBody, byte[] governingDocSha256, String env) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    if (gateBody != null) writeTrailer(out, GATE_TRAILER, gateBody);
    if (env != null) envOf(env.getBytes(StandardCharsets.UTF_8));
    if (governingDocSha256 == null) {
      if (env != null) throw refused("env_without_governing_doc");
      return out.toByteArray();
    }
    if (governingDocSha256.length != 32) throw refused("slot_length_not_32");
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    body.write(0x02);
    body.writeBytes(governingDocSha256);
    body.writeBytes(envSlotBytes(env));
    writeTrailer(out, GOVERNING_TRAILER, body.toByteArray());
    return out.toByteArray();
  }

  private static void writeTrailer(ByteArrayOutputStream out, int marker, byte[] body) {
    out.write(marker);
    int n = body.length;
    out.write(n & 0xff);
    out.write((n >>> 8) & 0xff);
    out.write((n >>> 16) & 0xff);
    out.write((n >>> 24) & 0xff);
    out.writeBytes(body);
  }

  /**
   * Decode the {@code 0x05} / {@code 0x06} trailers a sealed commitment appends into digest fields
   * 10-12. {@code scheme} is {@link CommitmentVersion#V5}, {@link CommitmentVersion#V6}, or {@code
   * null} for the scheme-free decode (both {@code 0x06} body versions accepted, the version
   * reported; the caller applies the scheme rules once it knows the scheme).
   *
   * <p>Markers strictly increase, an unknown marker refuses, nothing may follow the last trailer.
   * {@code 0x05} is decoded by {@link #decodeGateBody}, and field 10 frames this decoder's own {@link
   * #gateDigest} over it (VG1); a {@code 0x05} needs a {@code 0x06} body v2 whose env equals the Gate
   * env ({@code gate_env_binding}). Under v5 a {@code 0x05} or a body v2 refuses; under v6 a body v1
   * refuses. {@code trailers} carries only these two trailers: any other commitment trailer marker
   * ({@code 0x01}-{@code 0x04}, {@code 0x07}) is refused as not a digest input; the selection digest
   * (field 9) is given as {@link Commitment#selectionDigest()} or a selection block, as for v5.
   *
   * @throws CommitmentRefusal (or {@link IllegalArgumentException}) on any refusal.
   */
  public static CommitmentTrailers decodeCommitmentTrailers(
      byte[] trailers, CommitmentVersion scheme) {
    int pos = 0;
    int last = 0;
    byte[] gateBody = null;
    GateBlock gate = null;
    byte[] doc = null;
    String env = null;
    Integer version = null;
    while (pos < trailers.length) {
      int marker = trailers[pos] & 0xff;
      if (marker < 0x01 || marker > 0x07) throw refused("unknown_marker");
      if (marker <= last) throw refused("marker_order");
      last = marker;
      String truncated;
      if (marker == GATE_TRAILER) {
        if (scheme == CommitmentVersion.V5) throw refused("v5_refuses_gate_block");
        truncated = "gate_trailer_truncated";
      } else if (marker == GOVERNING_TRAILER) {
        truncated = "governing_trailer_truncated";
      } else {
        throw new IllegalArgumentException(
            String.format(
                "trailer marker 0x%02x is not a commitment-digest input: pass only the 0x05/0x06"
                    + " trailers",
                marker));
      }
      if (trailers.length - pos < 5) throw refused(truncated);
      long n =
          Integer.toUnsignedLong(
              ByteBuffer.wrap(trailers, pos + 1, 4).order(ByteOrder.LITTLE_ENDIAN).getInt());
      if (n > trailers.length - pos - 5) throw refused(truncated);
      byte[] body = Arrays.copyOfRange(trailers, pos + 5, pos + 5 + (int) n);
      pos += 5 + (int) n;
      if (marker == GATE_TRAILER) {
        gate = decodeGateBody(body);
        gateBody = body;
      } else {
        if (body.length == 0) throw refused("governing_body_empty");
        int v = body[0] & 0xff;
        if (v != 0x01 && v != 0x02) throw refused("governing_body_unknown_version");
        if (scheme == CommitmentVersion.V5 && v == 0x02) {
          throw refused("v5_refuses_governing_body_v2");
        }
        if (scheme == CommitmentVersion.V6 && v == 0x01) {
          throw refused("v6_refuses_governing_body_v1");
        }
        version = v;
        if (v == 0x01) {
          if (body.length != 33) throw refused("governing_body_length");
          doc = Arrays.copyOfRange(body, 1, 33);
        } else {
          Reader r = new Reader(body, 1, "governing_body_truncated");
          doc = r.take(32);
          if (r.atEnd()) throw refused("env_presence_missing");
          int presence = r.u8();
          if (presence == 0x01) {
            env = envOf(r.framed());
          } else if (presence != 0x00) {
            throw refused("env_presence_invalid");
          }
          r.done("governing_body_trailing_bytes");
        }
      }
    }
    if (gate != null && (doc == null || env == null || !env.equals(gate.env()))) {
      throw refused("gate_env_binding");
    }
    byte[] gd = gateBody == null ? null : gateDigest(gateBody);
    boolean hasField12 =
        scheme == CommitmentVersion.V6 || (scheme == null && version != null && version == 2);
    return new CommitmentTrailers(
        slotBytes(gd), slotBytes(doc), hasField12 ? envSlotBytes(env) : null, version, gd, gate,
        doc, env);
  }

  private static void requireAgree(String name, byte[] beside, byte[] field) {
    if (beside != null && !Arrays.equals(beside, field)) {
      throw new IllegalArgumentException(name + " given on the commitment disagrees with the field");
    }
  }

  /**
   * The commitment digest (hex) under {@code version}: fields 0-8 from {@code c}, fields 9-12 from
   * {@code f} (the digest-only path; a field-9/10/11 slot also set on {@code c} must equal {@code
   * f}'s). Every refusal is checked before anything is hashed: a present slot that is not 32 bytes
   * ({@code slot_length_not_32}), an env that is not exactly {@code sandbox}/{@code live} ({@code
   * env_not_sandbox_or_live}), an env without the governing doc ({@code env_without_governing_doc}),
   * and any env under v5 ({@code v5_refuses_env}). {@link CommitmentVersion#V5} with no env is
   * byte-for-byte {@code seam-commitment-digest:v5}; {@link CommitmentVersion#V6} is {@code
   * seam-commitment-digest:v6} (v5's framing plus field 12, {@code 0x00} or {@code 0x01 ‖ F(env)}).
   *
   * @throws IllegalArgumentException ({@link CommitmentRefusal} for a spec rule) on any refusal.
   */
  public static String commitmentDigest(
      CommitmentVersion version, Commitment c, CommitmentDigestFields f) {
    if (f.selectionDigest() != null && f.selectionDigest().length != 32
        || f.gateDigest() != null && f.gateDigest().length != 32
        || f.governingDocSha256() != null && f.governingDocSha256().length != 32) {
      throw refused("slot_length_not_32");
    }
    if (f.env() != null) {
      if (version == CommitmentVersion.V5) throw refused("v5_refuses_env");
      if (!"sandbox".equals(f.env()) && !"live".equals(f.env())) {
        throw refused("env_not_sandbox_or_live");
      }
      if (f.governingDocSha256() == null) throw refused("env_without_governing_doc");
    }
    requireAgree("selection_digest", c.selectionDigest(), f.selectionDigest());
    requireAgree("certificate_digest", c.certificateDigest(), f.gateDigest());
    requireAgree("governing_doc_sha256", c.governingDocSha256(), f.governingDocSha256());
    Commitment framed =
        new Commitment(
            c.id(), c.action(), c.authority(), c.supersedes(), c.authMethod(), c.trustBasis(),
            c.committer(), c.explanationDigest(), c.explanation(), f.selectionDigest(),
            f.gateDigest(), f.governingDocSha256());
    if (version == CommitmentVersion.V5) return seamCommitmentDigest(framed);
    byte[] explanation = commitmentExplanationDigest(framed);
    ByteArrayOutputStream h = new ByteArrayOutputStream();
    be64Frame(h, COMMITMENT_DIGEST_DOMAIN_V6.getBytes(StandardCharsets.UTF_8));
    be64Frame(h, nz(c.id()));
    be64Frame(h, nz(c.action()));
    be64Frame(h, nz(c.authority()));
    if (c.supersedes() == null) {
      h.write(0x00);
    } else {
      h.write(0x01);
      be64Frame(h, c.supersedes().getBytes(StandardCharsets.UTF_8));
    }
    be64Frame(h, nz(c.authMethod()));
    be64Frame(h, nz(c.trustBasis()));
    be64Frame(h, nz(c.committer()));
    be64Frame(h, explanation);
    optionalDigestSlot(h, f.selectionDigest());
    optionalDigestSlot(h, f.gateDigest());
    optionalDigestSlot(h, f.governingDocSha256());
    h.writeBytes(envSlotBytes(f.env()));
    return hex(sha256(h.toByteArray()));
  }

  /**
   * The digest {@link #verifyTct} compares, under the selected version only. v5 with no trailers is
   * exactly {@link #seamCommitmentDigest}. Otherwise fields 10-12 come from this decoder's reading of
   * {@link Commitment#trailers()} under that scheme (v6 field 10 never from a value carried beside
   * it), and a slot also set on the commitment must agree with the trailers.
   */
  private static String recomputeCommitmentDigest(CommitmentVersion version, Commitment c) {
    if (version == CommitmentVersion.V5) {
      if (c.gateBody() != null) throw refused("v5_refuses_gate_block");
      if (c.env() != null) throw refused("v5_refuses_env");
      if (c.trailers() == null) return seamCommitmentDigest(c);
      CommitmentTrailers t = decodeCommitmentTrailers(c.trailers(), CommitmentVersion.V5);
      return commitmentDigest(
          version,
          c,
          new CommitmentDigestFields(
              c.selectionDigest(), c.certificateDigest(), t.governingDocSha256(), null));
    }
    // Fields 10-12 come from the trailers only. No raw trailers is a served commitment: its projection
    // is rebuilt into the trailer run (#420), which is then the only source.
    byte[] raw;
    if (c.trailers() == null) {
      raw = servedCommitmentTrailers(c.gateBody(), c.governingDocSha256(), c.env());
    } else {
      if (c.gateBody() != null || c.env() != null)
        throw refused("served_projection_beside_trailers");
      raw = c.trailers();
    }
    CommitmentTrailers t = decodeCommitmentTrailers(raw, CommitmentVersion.V6);
    return commitmentDigest(
        version,
        c,
        new CommitmentDigestFields(
            c.selectionDigest(), t.gateDigest(), t.governingDocSha256(), t.env()));
  }

  /**
   * Statement selection (v6 spec §Verifiers) over the raw {@code ext} JSON text of a commitment TCT.
   * A duplicate member name at ANY depth of {@code ext} refuses, found on the raw text with names
   * compared after JSON unescaping ({@code "type"} and {@code "type"} are one name). The
   * {@code com.zer07labs.seam} member must exist; members exactly {@code {type, commitment_digest}}
   * select v5, exactly {@code {type, commitment_digest, commitment_digest_domain}} with the domain
   * the string {@code seam-commitment-digest:v6} select v6; any other set, domain, {@code type}, or a
   * {@code commitment_digest} that is not 64 lowercase hex refuses. Member order is not significant.
   *
   * @throws CommitmentRefusal on any refusal.
   */
  public static CommitmentVersion selectCommitmentVersion(String extRaw) {
    Object ext = parseStatementJson(extRaw);
    if (!(ext instanceof Map<?, ?> m)) throw refused("statement_not_object");
    return selectFromExtObject(m);
  }

  /**
   * {@link #selectCommitmentVersion} entered from the raw statement object itself (the value of
   * {@code com.zer07labs.seam}), with the same duplicate-member guard over it.
   *
   * @throws CommitmentRefusal on any refusal.
   */
  public static CommitmentVersion selectStatementVersion(String statementRaw) {
    return selectFromStatement(parseStatementJson(statementRaw));
  }

  /** Selection from an {@code ext} map already cleared of duplicates. */
  private static CommitmentVersion selectFromExtObject(Map<?, ?> ext) {
    if (!ext.containsKey(COMMITMENT_EXT_NAMESPACE)) throw refused("statement_missing");
    return selectFromStatement(ext.get(COMMITMENT_EXT_NAMESPACE));
  }

  private static CommitmentVersion selectFromStatement(Object statement) {
    if (!(statement instanceof Map<?, ?> stmt)) throw refused("statement_not_object");
    Set<Object> keys = new HashSet<>(stmt.keySet());
    CommitmentVersion version;
    if (keys.equals(V5_MEMBERS)) {
      version = CommitmentVersion.V5;
    } else if (keys.equals(V6_MEMBERS)) {
      if (!COMMITMENT_DIGEST_DOMAIN_V6.equals(stmt.get(COMMITMENT_DIGEST_DOMAIN_MEMBER))) {
        throw refused("statement_domain_not_v6");
      }
      version = CommitmentVersion.V6;
    } else {
      throw refused("statement_member_set");
    }
    if (!COMMITMENT_STATEMENT.equals(stmt.get("type"))) throw refused("statement_type");
    if (!(stmt.get("commitment_digest") instanceof String d) || !isLowerHex64(d)) {
      throw refused("statement_digest_not_lowercase_hex");
    }
    return version;
  }

  private static boolean isLowerHex64(String d) {
    if (d.length() != 64) return false;
    for (int i = 0; i < 64; i++) {
      char ch = d.charAt(i);
      if (!(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f')) return false;
    }
    return true;
  }

  /**
   * Parse statement JSON strictly: not one well-formed JSON value refuses {@code
   * statement_not_json}; a repeated member name at any depth refuses {@code
   * statement_duplicate_member}, detected on the raw text (Gson's streaming reader unescapes each
   * name) before any map parse could keep one of the two.
   */
  private static Object parseStatementJson(String raw) {
    try (JsonReader r = new JsonReader(new StringReader(raw))) {
      r.setStrictness(Strictness.STRICT);
      if (scanForDuplicate(r)) throw refused("statement_duplicate_member");
      if (r.peek() != JsonToken.END_DOCUMENT) throw refused("statement_not_json");
    } catch (CommitmentRefusal e) {
      throw e;
    } catch (IOException | RuntimeException e) {
      throw refused("statement_not_json");
    }
    return GSON.fromJson(raw, Object.class);
  }

  // ── Authorize call_sig v3 (#197) ────────────────────────────────────────────────────────────

  /**
   * Domain tag of the {@code Authorize} per-call proof-of-possession, v3. The distinct tag means a v2
   * signature can NEVER verify as a v3 one, so SDK/runtime version skew is a clean rejection rather
   * than a parse ambiguity. Bump it only in lockstep with the runtime.
   */
  public static final String CALL_SIG_V3_CONTEXT = "seam-authorize-call-v3";

  /** One attribution feature. Features are signed sorted by (key bytes, value bytes), not as sent. */
  public record Feature(String key, String value) {}

  /**
   * The inputs {@link #callSigV3Payload} frames. Every string is signed as its UTF-8 bytes; an absent
   * optional field is the empty string ({@code null} is read as empty), signed verbatim rather than
   * skipped. {@code ticket} is the admission ticket's RAW bytes. {@code subjects} are signed in the
   * order given — never deduped, never sorted.
   */
  public record CallSigV3Fields(
      byte[] ticket,
      String toolInputDigest,
      String toolName,
      String agentId,
      String subject,
      List<String> subjects,
      String clientRequestId,
      String sessionId,
      List<Feature> features) {}

  /**
   * The exact bytes {@link #callSigV3} signs: {@code frame(context) | frame(ticket) |
   * frame(tool_input_digest) | frame(tool_name) | frame(agent_id) | frame(subject) |
   * frame(u32le(n_subjects)) | frame(subject_i)... | frame(client_request_id) | frame(session_id) |
   * frame(u32le(n_features)) | (frame(key) | frame(value))...}, with {@code frame(x) =
   * u32le(len_bytes(x)) | x} — the counts are themselves framed.
   *
   * <p>Features are sorted by their UTF-8 <b>bytes</b>, compared unsigned. {@link String#compareTo}
   * would be wrong here: it orders by UTF-16 code unit, which disagrees with byte order for
   * supplementary-plane vs. high-BMP characters.
   *
   * <p>Pinned by {@code conformance/call_sig_v3_payload_vector.json}. Public so a caller can
   * reproduce or verify the binding without re-deriving it from prose.
   */
  public static byte[] callSigV3Payload(CallSigV3Fields f) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    frame(out, CALL_SIG_V3_CONTEXT.getBytes(StandardCharsets.UTF_8));
    frame(out, f.ticket() == null ? new byte[0] : f.ticket());
    frame(out, nz(f.toolInputDigest()));
    frame(out, nz(f.toolName()));
    frame(out, nz(f.agentId()));
    frame(out, nz(f.subject()));
    List<String> subjects = f.subjects() == null ? List.of() : f.subjects();
    frame(out, u32le(subjects.size()));
    for (String s : subjects) frame(out, nz(s));
    frame(out, nz(f.clientRequestId()));
    frame(out, nz(f.sessionId()));

    List<byte[][]> features = new ArrayList<>();
    if (f.features() != null) {
      for (Feature kv : f.features()) features.add(new byte[][] {nz(kv.key()), nz(kv.value())});
    }
    features.sort(
        (a, b) -> {
          int c = Arrays.compareUnsigned(a[0], b[0]);
          return c != 0 ? c : Arrays.compareUnsigned(a[1], b[1]);
        });
    frame(out, u32le(features.size()));
    for (byte[][] kv : features) {
      frame(out, kv[0]);
      frame(out, kv[1]);
    }
    return out.toByteArray();
  }

  /**
   * The per-call proof-of-possession for {@code Authorize}: Ed25519 by the agent key (32-byte seed)
   * over {@link #callSigV3Payload}, returned as the raw 64-byte signature (the {@code call_sig}
   * bytes field), as Python's {@code call_sig} does.
   */
  public static byte[] callSigV3(byte[] agentSeed, CallSigV3Fields f) {
    if (agentSeed == null || agentSeed.length != 32) {
      throw new IllegalArgumentException("agent seed must be 32 bytes");
    }
    return ed25519Sign(agentSeed, callSigV3Payload(f));
  }

  private static void frame(ByteArrayOutputStream out, byte[] b) {
    out.writeBytes(u32le(b.length));
    out.writeBytes(b);
  }

  private static byte[] u32le(int n) {
    return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(n).array();
  }

  // ── helpers ─────────────────────────────────────────────────────────────────────────────────
  private static byte[] nz(String s) {
    return (s == null ? "" : s).getBytes(StandardCharsets.UTF_8);
  }

  private static String hex(byte[] b) {
    StringBuilder sb = new StringBuilder(b.length * 2);
    for (byte x : b) sb.append(String.format("%02x", x & 0xff));
    return sb.toString();
  }

  // ── Enrolment proof-of-possession (#205) ────────────────────────────────────────────────────

  /**
   * Domain tag of the enrolment proof-of-possession (seam-runtime #1157): the subject AID's own
   * consent, by the key it embeds, to ONE {@code EnrollTenant} binding. Bump it only in lockstep
   * with the runtime. v2 (#1687) signs the {@code participant_id} a {@code voter} enrolment binds
   * ({@code ""} for every other kind); v1 is refused by runtime 0.87.0 and is gone.
   */
  public static final String ENROLL_POP_V2_CONTEXT = "seam-enroll-pop-v2";

  /**
   * The inputs {@link #enrollPopPayload} frames, each exactly as sent on the wire. Strings are signed
   * as their UTF-8 bytes ({@code null} is read as empty). {@code issuedAtMs} is Unix epoch
   * MILLISECONDS, read as an UNSIGNED 64-bit value (the proto field is {@code uint64}).
   */
  public record EnrollPopFields(
      String subjectAid,
      String tenant,
      String namespace,
      String participantId,
      long issuedAtMs,
      String nonce) {
    /** Fields for a non-voter enrolment: {@code participantId} is {@code ""}. */
    public EnrollPopFields(
        String subjectAid, String tenant, String namespace, long issuedAtMs, String nonce) {
      this(subjectAid, tenant, namespace, "", issuedAtMs, nonce);
    }
  }

  /**
   * The exact bytes {@link #enrollPop} signs: {@code frame(context) | frame(subject_aid) |
   * frame(tenant) | frame(namespace) | frame(participant_id) | frame(u64le(issued_at_ms)) |
   * frame(nonce)}, with {@code
   * frame(x) = u32le(len_bytes(x)) | x}. {@code issued_at_ms} is 8 raw little-endian bytes, not ASCII
   * decimal.
   *
   * <p>Pinned by {@code conformance/enroll_pop_v2_payload_vector.json}. Public so a caller can
   * reproduce or verify the binding without re-deriving it from prose.
   */
  public static byte[] enrollPopPayload(EnrollPopFields f) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    enrollFrame(out, ENROLL_POP_V2_CONTEXT.getBytes(StandardCharsets.UTF_8));
    enrollFrame(out, nz(f.subjectAid()));
    enrollFrame(out, nz(f.tenant()));
    enrollFrame(out, nz(f.namespace()));
    enrollFrame(out, nz(f.participantId()));
    enrollFrame(out, leBytes(f.issuedAtMs(), 8));
    enrollFrame(out, nz(f.nonce()));
    return out.toByteArray();
  }

  /** Refuse a nonce the runtime would refuse: 1..=128 characters of {@code [A-Za-z0-9_-]}. */
  public static void validateEnrollPopNonce(String nonce) {
    if (nonce == null || nonce.isEmpty() || nonce.length() > 128) {
      throw new IllegalArgumentException("enrol pop nonce must be 1..=128 characters");
    }
    if (!nonce.matches("[A-Za-z0-9_-]+")) {
      throw new IllegalArgumentException("enrol pop nonce must use only [A-Za-z0-9_-]");
    }
  }

  /**
   * The enrolment proof-of-possession: Ed25519 by the agent key (32-byte seed) over {@link
   * #enrollPopPayload}, returned as the raw 64-byte signature (the {@code EnrollPop.signature} bytes
   * field; the REST body carries it as unpadded base64url). Refuses a {@code subjectAid} that is not
   * the seed's own AID — a proof can only speak for the key that signs it — and a nonce the runtime
   * would refuse.
   */
  public static byte[] enrollPop(byte[] agentSeed, EnrollPopFields f) {
    if (agentSeed == null || agentSeed.length != 32) {
      throw new IllegalArgumentException("agent seed must be 32 bytes");
    }
    validateEnrollPopNonce(f.nonce());
    String own = aidFromPubkey(ed25519Pub(agentSeed));
    if (!own.equals(f.subjectAid())) {
      throw new IllegalArgumentException(
          "subjectAid " + f.subjectAid() + " is not this seed's AID " + own);
    }
    return ed25519Sign(agentSeed, enrollPopPayload(f));
  }

  private static void enrollFrame(ByteArrayOutputStream out, byte[] b) {
    out.writeBytes(leBytes(b.length, 4));
    out.writeBytes(b);
  }

  private static byte[] leBytes(long v, int n) {
    byte[] out = new byte[n];
    for (int i = 0; i < n; i++) out[i] = (byte) (v >>> (8 * i));
    return out;
  }

  // ── Enrolment proof, agent side + REST form (#214) ──────────────────────────────────────────

  private static final SecureRandom RANDOM = new SecureRandom();

  /**
   * The agent-side enrolment proof-of-possession (seam-runtime #1157 / #1164): the parts of {@code
   * EnrollTenantRequest.pop} ({@code EnrollPop}), produced by the AGENT being enrolled and handed to
   * the operator who enrols it. {@code signature} is the RAW 64-byte Ed25519 signature, as the gRPC
   * {@code bytes} field carries it; {@link #toRest} gives the {@code POST /v1/tenants} form, where it
   * is unpadded base64url. {@code issuedAtMs} is Unix epoch MILLISECONDS, read as UNSIGNED. The
   * runtime accepts a proof at most 5 minutes old and at most 60 s in the future, so produce it just
   * before the enrolment call. Mirrors Python's and TypeScript's {@code EnrollProof}.
   */
  public record EnrollProof(long issuedAtMs, String nonce, byte[] signature) {
    public EnrollProof {
      signature = signature.clone();
    }

    @Override
    public byte[] signature() {
      return signature.clone();
    }

    /** The signature as unpadded base64url — the REST form. */
    public String signatureB64url() {
      return b64urlNoPad(signature);
    }

    /**
     * The REST body's {@code pop} object, {@code {issued_at_ms, nonce, signature}} in that order,
     * ready for any JSON encoder. {@code issued_at_ms} is a {@link Long}, or a {@link BigInteger} for
     * an unsigned value past {@link Long#MAX_VALUE}, so it is never emitted negative.
     */
    public Map<String, Object> toRest() {
      Map<String, Object> m = new LinkedHashMap<>();
      m.put(
          "issued_at_ms",
          issuedAtMs >= 0 ? (Object) issuedAtMs : new BigInteger(Long.toUnsignedString(issuedAtMs)));
      m.put("nonce", nonce);
      m.put("signature", signatureB64url());
      return m;
    }

    @Override
    public boolean equals(Object o) {
      return o instanceof EnrollProof p
          && p.issuedAtMs == issuedAtMs
          && Objects.equals(p.nonce, nonce)
          && Arrays.equals(p.signature, signature);
    }

    @Override
    public int hashCode() {
      return 31 * (31 * Long.hashCode(issuedAtMs) + Objects.hashCode(nonce))
          + Arrays.hashCode(signature);
    }

    @Override
    public String toString() {
      return "EnrollProof[issuedAtMs="
          + Long.toUnsignedString(issuedAtMs)
          + ", nonce="
          + nonce
          + ", signature="
          + signatureB64url()
          + "]";
    }
  }

  /** A fresh nonce: 16 random bytes as unpadded base64url — 22 characters, inside the contract. */
  public static String newEnrollPopNonce() {
    byte[] b = new byte[16];
    RANDOM.nextBytes(b);
    return b64urlNoPad(b);
  }

  /**
   * Sign an enrolment proof with the agent's own key (32-byte seed) at an explicit time and nonce.
   * The subject AID is DERIVED from the seed — a proof can only ever speak for the key that signs it
   * — and the nonce is validated first. {@code participantId} is the participant a {@code voter}
   * enrolment binds ({@code ""} for every other kind); the operator sends the same value as {@code
   * EnrollTenantRequest.participant_id}. Prefer {@link #enrolmentProof(byte[], String, String,
   * String)}, which defaults {@code issuedAtMs} to now and the nonce to a fresh random one.
   */
  public static EnrollProof enrolmentProof(
      byte[] agentSeed,
      String tenant,
      String namespace,
      String participantId,
      long issuedAtMs,
      String nonce) {
    if (agentSeed == null || agentSeed.length != 32) {
      throw new IllegalArgumentException("agent seed must be 32 bytes");
    }
    String subject = aidFromPubkey(ed25519Pub(agentSeed));
    byte[] sig =
        enrollPop(
            agentSeed,
            new EnrollPopFields(subject, tenant, namespace, participantId, issuedAtMs, nonce));
    return new EnrollProof(issuedAtMs, nonce, sig);
  }

  /** {@link #enrolmentProof(byte[], String, String, String, long, String)} with no participant. */
  public static EnrollProof enrolmentProof(
      byte[] agentSeed, String tenant, String namespace, long issuedAtMs, String nonce) {
    return enrolmentProof(agentSeed, tenant, namespace, "", issuedAtMs, nonce);
  }

  /**
   * This agent's consent to being enrolled under {@code tenant}/{@code namespace}: the {@code pop} an
   * operator sends with {@code EnrollTenant} (gRPC: the raw fields; REST: {@link
   * EnrollProof#toRest}). Required for enrolment by a tenant-scoped operator token. {@code issuedAtMs}
   * is now and the nonce is 16 fresh random bytes as 22 base64url characters. The counterpart of
   * Python's {@code Agent.enrolment_proof} and TypeScript's {@code Agent.enrolmentProof}.
   */
  public static EnrollProof enrolmentProof(byte[] agentSeed, String tenant, String namespace) {
    return enrolmentProof(agentSeed, tenant, namespace, "");
  }

  /**
   * {@link #enrolmentProof(byte[], String, String)} for a {@code voter} enrolment bound to {@code
   * participantId} (#1687).
   */
  public static EnrollProof enrolmentProof(
      byte[] agentSeed, String tenant, String namespace, String participantId) {
    return enrolmentProof(
        agentSeed,
        tenant,
        namespace,
        participantId,
        System.currentTimeMillis(),
        newEnrollPopNonce());
  }

  // ── The per-request credential (`seam-request-call-v1`, #508) ──────────────────────────────────

  /**
   * Domain tag of the per-request credential — deliberately distinct from the {@code Authorize}
   * call_sig tag, so a captured call_sig is never spendable as a request credential.
   */
  public static final String REQUEST_SIG_CONTEXT = "seam-request-call-v1";

  /**
   * The exact bytes {@link #requestSig} signs: {@code frame(context) | frame(ticket) |
   * frame(rpc_full_name) | frame(resource_id) | frame(body_digest)}, with {@code frame(x) =
   * u32le(len_bytes(x)) | x}. {@code rpcFullName} is the gRPC full method path on both transports. A
   * bodyless read binds its id as {@code resourceId} and an empty {@code bodyDigest}; a bodied verb
   * over gRPC binds an empty {@code resourceId} and {@link #bodyDigest} of the request message's exact
   * serialized bytes. {@code null} strings are read as empty.
   *
   * <p>Pinned by {@code conformance/request_sig_payload_vector.json}.
   */
  public static byte[] requestSigPayload(
      byte[] ticket, String rpcFullName, String resourceId, String bodyDigest) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    frame(out, REQUEST_SIG_CONTEXT.getBytes(StandardCharsets.UTF_8));
    frame(out, ticket == null ? new byte[0] : ticket);
    frame(out, nz(rpcFullName));
    frame(out, nz(resourceId));
    frame(out, nz(bodyDigest));
    return out.toByteArray();
  }

  /**
   * Ed25519 by the agent key (32-byte seed) over {@link #requestSigPayload}: the raw 64-byte {@code
   * x-seam-call-sig-bin} value.
   */
  public static byte[] requestSig(
      byte[] agentSeed, byte[] ticket, String rpcFullName, String resourceId, String bodyDigest) {
    if (agentSeed == null || agentSeed.length != 32) {
      throw new IllegalArgumentException("agent seed must be 32 bytes");
    }
    return ed25519Sign(agentSeed, requestSigPayload(ticket, rpcFullName, resourceId, bodyDigest));
  }

  /**
   * {@code "sha256:" + lowercase hex(SHA-256(body))} over the request message's exact wire bytes —
   * never a re-serialization taken after the fact.
   */
  public static String bodyDigest(byte[] body) {
    return "sha256:" + hex(sha256(body));
  }

  // ── Voter proof-of-possession: seam-voter-pop-v1 (#1687, seam-sdk#359) ─────────────────────────
  // A vote, ballot or objection must carry the voter's OWN proof, signed by its enrolled `voter` key
  // (seam-runtime docs/specs/voter-verification.v1.md); runtime 0.87.0 refuses one without
  // (`voter_proof_required`). Byte-exact against conformance/voter_pop_v1_payload_vector.json; the
  // twins are Python `seam_sdk.crypto` and TypeScript `crypto.ts`'s voter sections.

  /** Domain tag of the voter proof's signed payload. */
  public static final String VOTER_POP_V1_DOMAIN = "seam-voter-pop-v1";

  /** Domain tag of the vote content digest. */
  public static final String VOTE_CONTENT_V1_DOMAIN = "seam-vote-content-v1";

  /** The longest window the runtime accepts: {@code expires - issued <= 15 min}. */
  public static final long VOTER_POP_MAX_LIFETIME_MS = 15L * 60 * 1000;

  /** The clock skew the runtime allows: {@code issued <= accepted + 60 s}. */
  public static final long VOTER_POP_MAX_SKEW_MS = 60L * 1000;

  /** The default lifetime of a freshly signed proof (5 minutes). */
  public static final long VOTER_POP_DEFAULT_LIFETIME_MS = 5L * 60 * 1000;

  /** The audience a voter proof names unless told otherwise. */
  public static final String VOTER_POP_DEFAULT_AUDIENCE = "seam-runtime";

  /**
   * The explanation kinds a voter must sign: each carries a sealed voter record, and an evaluation
   * never does.
   */
  public static final List<String> VOTER_VERIFIED_KINDS = List.of("vote", "ballot", "objection");

  private static final long MAX_SAFE_JSON_INTEGER = (1L << 53) - 1;

  /**
   * Where a vote is cast: the runtime ({@code issuer} AID and {@code audience}, default {@code
   * seam-runtime}) and the session's tenant/namespace and open identity ({@code sessionId}, {@code
   * openedAtMillis} = {@code SessionStep.opened_at_millis} from the open; {@code 0} on the one-shot
   * {@code RunDecision} path). {@code openedAtMillis} is read as UNSIGNED 64-bit.
   */
  public record VoterPopTarget(
      String issuer,
      String tenant,
      String namespace,
      String sessionId,
      long openedAtMillis,
      String audience) {
    /** A target addressed to the default audience ({@code seam-runtime}). */
    public VoterPopTarget(
        String issuer, String tenant, String namespace, String sessionId, long openedAtMillis) {
      this(issuer, tenant, namespace, sessionId, openedAtMillis, VOTER_POP_DEFAULT_AUDIENCE);
    }
  }

  /**
   * The entry the runtime will seal, as the voter signs it. {@code kind} is {@code vote}, {@code
   * ballot} or {@code objection}; {@code proposalId} is the ballot's {@code request_id} for a ballot;
   * {@code value} is the vote value, ballot choice, or objection severity ({@code ""} when omitted).
   * {@code confidence} and {@code rationaleRef} are {@code null} when absent (a stated {@code 0.0} is
   * different bytes). A {@code null} reason is {@code ""}.
   */
  public record VoteEntry(
      String kind,
      String participant,
      String proposalId,
      String value,
      String reason,
      Double confidence,
      String rationaleRef) {
    /** An entry with no confidence and no rationale reference. */
    public VoteEntry(String kind, String participant, String proposalId, String value, String reason) {
      this(kind, participant, proposalId, value, reason, null, null);
    }
  }

  /** One sealed context binding the content digest frames; {@code contentHash} is {@code ""} when none. */
  public record VoteContext(String ctxRef, String contentHash) {}

  /**
   * The session's bound vote policy ({@code SessionStep.vote_policy} from the open): {@code
   * policyVersion} and the 32-byte {@code rulesDigest}.
   */
  public record VotePolicyRef(String policyVersion, byte[] rulesDigest) {
    public VotePolicyRef {
      rulesDigest = rulesDigest == null ? null : rulesDigest.clone();
    }

    @Override
    public byte[] rulesDigest() {
      return rulesDigest == null ? null : rulesDigest.clone();
    }

    @Override
    public boolean equals(Object o) {
      return o instanceof VotePolicyRef p
          && Objects.equals(p.policyVersion, policyVersion)
          && Arrays.equals(p.rulesDigest, rulesDigest);
    }

    @Override
    public int hashCode() {
      return 31 * Objects.hashCode(policyVersion) + Arrays.hashCode(rulesDigest);
    }
  }

  /**
   * The decision a commitment-level voter check is pinned to, when the verifier knows it: the
   * records' own tenant and session id must equal these.
   */
  public record VoterDecisionRef(String tenant, String sessionId) {}

  /**
   * A signed voter proof: the parts of the generated {@code VoterProof.pop} ({@code VoterPop}). Set
   * {@link #voterAid}, {@link #issuedAtMs}, {@link #expiresAtMs} and the RAW 64-byte {@link
   * #signature} on a {@code VoterPop}, wrap it in a {@code VoterProof}, and put it on {@code
   * VoteRequest.proof}, {@code BallotRequest.proof}, {@code ObjectionRequest.proof} or a one-shot
   * {@code Vote.proof}. {@link #toRest} is the REST/JSON {@code proof} object. Integers are UNSIGNED
   * 64-bit.
   */
  public record VoterPopProof(String voterAid, long issuedAtMs, long expiresAtMs, byte[] signature) {
    public VoterPopProof {
      signature = signature.clone();
    }

    @Override
    public byte[] signature() {
      return signature.clone();
    }

    /** The signature as unpadded base64url — the REST form. */
    public String signatureB64url() {
      return b64urlNoPad(signature);
    }

    /**
     * The REST/JSON {@code proof} object: {@code {"pop": {voter_aid, issued_at_ms, expires_at_ms,
     * signature}}}, the signature as unpadded base64url. The window is a JSON number, so a value past
     * 2^53 is refused rather than rounded.
     */
    public Map<String, Object> toRest() {
      for (long v : new long[] {issuedAtMs, expiresAtMs}) {
        if (Long.compareUnsigned(v, MAX_SAFE_JSON_INTEGER) > 0) {
          throw new IllegalArgumentException(
              "voter proof window value "
                  + Long.toUnsignedString(v)
                  + " exceeds 2^53 and cannot be carried as a JSON number");
        }
      }
      Map<String, Object> pop = new LinkedHashMap<>();
      pop.put("voter_aid", voterAid);
      pop.put("issued_at_ms", issuedAtMs);
      pop.put("expires_at_ms", expiresAtMs);
      pop.put("signature", signatureB64url());
      Map<String, Object> m = new LinkedHashMap<>();
      m.put("pop", pop);
      return m;
    }

    @Override
    public boolean equals(Object o) {
      return o instanceof VoterPopProof p
          && Objects.equals(p.voterAid, voterAid)
          && p.issuedAtMs == issuedAtMs
          && p.expiresAtMs == expiresAtMs
          && Arrays.equals(p.signature, signature);
    }

    @Override
    public int hashCode() {
      return Objects.hash(voterAid, issuedAtMs, expiresAtMs) * 31 + Arrays.hashCode(signature);
    }

    @Override
    public String toString() {
      return "VoterPopProof[voterAid="
          + voterAid
          + ", issuedAtMs="
          + Long.toUnsignedString(issuedAtMs)
          + ", expiresAtMs="
          + Long.toUnsignedString(expiresAtMs)
          + ", signature="
          + signatureB64url()
          + "]";
    }
  }

  /** The REST/JSON {@code proof} object for {@code p} — {@link VoterPopProof#toRest}. */
  public static Map<String, Object> voterPopToRest(VoterPopProof p) {
    return p.toRest();
  }

  private static byte[] utf8(String s, String what) {
    if (s == null) throw new IllegalArgumentException(what + " must not be null");
    return s.getBytes(StandardCharsets.UTF_8);
  }

  private static void countFrame(ByteArrayOutputStream out, int n) {
    frame(out, u32le(n));
  }

  /**
   * {@code seam-vote-content-v1}: what the vote is about (32 raw bytes). {@code content} is the
   * accepted proposal's {@code option} (vote, objection), the approval request's {@code action}
   * (ballot), or {@code votes[0].value} (one-shot); {@code participants} / {@code onBehalfOf} as
   * opened, in request order; {@code context} the sealed provenance in sealed order. {@code features}
   * is the one-shot {@code RunDecisionRequest.features} in any order — framed sorted by UTF-8 key
   * bytes, and a repeated key is REFUSED, never deduplicated; a session vote has none. {@code policy}
   * is the session's bound {@code vote_policy}; {@code null} frames {@code 0x00} (the one-shot,
   * server-resolved).
   */
  public static byte[] voteContentDigest(
      String mode,
      String proposalId,
      String content,
      List<String> participants,
      List<String> onBehalfOf,
      List<VoteContext> context,
      List<Feature> features,
      VotePolicyRef policy) {
    List<String> ps = participants == null ? List.of() : participants;
    List<String> obo = onBehalfOf == null ? List.of() : onBehalfOf;
    List<VoteContext> ctx = context == null ? List.of() : context;
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    frame(out, VOTE_CONTENT_V1_DOMAIN.getBytes(StandardCharsets.UTF_8));
    frame(out, utf8(mode, "mode"));
    frame(out, utf8(proposalId, "proposalId"));
    frame(out, utf8(content, "content"));
    countFrame(out, ps.size());
    for (String p : ps) frame(out, utf8(p, "participant"));
    countFrame(out, obo.size());
    for (String o : obo) frame(out, utf8(o, "onBehalfOf"));
    countFrame(out, ctx.size());
    for (VoteContext c : ctx) {
      frame(out, utf8(c.ctxRef(), "ctxRef"));
      frame(out, nz(c.contentHash()));
    }
    List<byte[][]> feats = canonicalVoteFeatures(features == null ? List.of() : features);
    countFrame(out, feats.size());
    for (byte[][] kv : feats) {
      frame(out, kv[0]);
      frame(out, kv[1]);
    }
    out.writeBytes(votePolicySlot(policy));
    return sha256(out.toByteArray());
  }

  /** {@link #voteContentDigest} for a session vote with no features and no bound policy. */
  public static byte[] voteContentDigest(
      String mode,
      String proposalId,
      String content,
      List<String> participants,
      List<String> onBehalfOf,
      List<VoteContext> context) {
    return voteContentDigest(
        mode, proposalId, content, participants, onBehalfOf, context, List.of(), null);
  }

  private static List<byte[][]> canonicalVoteFeatures(List<Feature> features) {
    List<byte[][]> out = new ArrayList<>(features.size());
    for (Feature f : features) {
      if (f == null || f.key() == null || f.value() == null) {
        throw new IllegalArgumentException("a feature is a (string, string) pair");
      }
      out.add(new byte[][] {utf8(f.key(), "key"), utf8(f.value(), "value")});
    }
    out.sort((a, b) -> Arrays.compareUnsigned(a[0], b[0]));
    for (int i = 1; i < out.size(); i++) {
      if (Arrays.equals(out.get(i - 1)[0], out.get(i)[0])) {
        throw new IllegalArgumentException(
            "feature key \""
                + new String(out.get(i)[0], StandardCharsets.UTF_8)
                + "\" is given twice (refused, never deduplicated)");
      }
    }
    return out;
  }

  private static byte[] votePolicySlot(VotePolicyRef p) {
    if (p == null) return new byte[] {0};
    byte[] rules = p.rulesDigest();
    if (rules == null || rules.length != 32) {
      throw new IllegalArgumentException(
          "rulesDigest must be 32 bytes, got " + (rules == null ? "null" : rules.length));
    }
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(1);
    frame(out, utf8(p.policyVersion(), "policyVersion"));
    frame(out, rules);
    return out.toByteArray();
  }

  /**
   * The frozen {@code entry_bytes} a voter signs ({@code F(x) = be64(len) ‖ x}): {@code F(kind) ‖
   * F(participant) ‖ F(proposal_id) ‖ F(value) ‖ F(reason) ‖ opt_conf ‖ opt_ref}. A stated {@code
   * -0.0} confidence folds to {@code +0.0}; a non-finite one is refused. Frozen: an
   * explanation-digest bump never changes it.
   */
  public static byte[] voteEntryBytes(VoteEntry e) {
    if (e == null || !EXPLANATION_KINDS.contains(e.kind())) {
      throw new IllegalArgumentException(
          "unknown explanation kind " + (e == null ? "null" : "\"" + e.kind() + "\""));
    }
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    be64Frame(out, utf8(e.kind(), "kind"));
    be64Frame(out, utf8(e.participant(), "participant"));
    be64Frame(out, utf8(e.proposalId(), "proposalId"));
    be64Frame(out, utf8(e.value(), "value"));
    be64Frame(out, nz(e.reason()));
    if (e.confidence() == null) {
      out.write(0);
    } else {
      double c = e.confidence();
      if (!Double.isFinite(c)) throw new IllegalArgumentException("non-finite confidence " + c);
      out.write(1);
      be64(out, Double.doubleToRawLongBits(c + 0.0)); // -0.0 + 0.0 == +0.0
    }
    if (e.rationaleRef() == null) {
      out.write(0);
    } else {
      out.write(1);
      be64Frame(out, utf8(e.rationaleRef(), "rationaleRef"));
    }
    return out.toByteArray();
  }

  /**
   * The exact bytes a voter proof signs ({@code framed(x) = u32le(len) ‖ x}): domain, issuer,
   * audience, tenant, namespace, sessionId, u64le(openedAtMillis), voterAid, contentDigest[32],
   * u64le(issuedAtMs), u64le(expiresAtMs), entryBytes. A {@code null} audience is {@code
   * seam-runtime}.
   */
  public static byte[] voterPopPayload(
      VoterPopTarget target,
      String voterAid,
      byte[] contentDigest,
      long issuedAtMs,
      long expiresAtMs,
      byte[] entryBytes) {
    if (contentDigest == null || contentDigest.length != 32) {
      throw new IllegalArgumentException(
          "contentDigest must be 32 bytes, got "
              + (contentDigest == null ? "null" : contentDigest.length));
    }
    if (entryBytes == null) throw new IllegalArgumentException("entryBytes must not be null");
    String audience = target.audience() == null ? VOTER_POP_DEFAULT_AUDIENCE : target.audience();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    frame(out, VOTER_POP_V1_DOMAIN.getBytes(StandardCharsets.UTF_8));
    frame(out, utf8(target.issuer(), "issuer"));
    frame(out, utf8(audience, "audience"));
    frame(out, utf8(target.tenant(), "tenant"));
    frame(out, utf8(target.namespace(), "namespace"));
    frame(out, utf8(target.sessionId(), "sessionId"));
    frame(out, leBytes(target.openedAtMillis(), 8));
    frame(out, utf8(voterAid, "voterAid"));
    frame(out, contentDigest);
    frame(out, leBytes(issuedAtMs, 8));
    frame(out, leBytes(expiresAtMs, 8));
    frame(out, entryBytes);
    return out.toByteArray();
  }

  /**
   * Sign a {@code seam-voter-pop-v1} proof with the voter's OWN enrolled {@code voter} key (32-byte
   * Ed25519 seed) over {@link #voterPopPayload}. The voter AID is DERIVED from the seed. A window the
   * runtime must refuse ({@code issued > expires}, or longer than 15 min; both read UNSIGNED) is never
   * signed.
   */
  public static VoterPopProof signVoterPop(
      byte[] voterSeed,
      VoterPopTarget target,
      byte[] contentDigest,
      byte[] entryBytes,
      long issuedAtMs,
      long expiresAtMs) {
    if (voterSeed == null || voterSeed.length != 32) {
      throw new IllegalArgumentException("voter seed must be 32 bytes");
    }
    if (Long.compareUnsigned(issuedAtMs, expiresAtMs) > 0
        || Long.compareUnsigned(expiresAtMs - issuedAtMs, VOTER_POP_MAX_LIFETIME_MS) > 0) {
      throw new IllegalArgumentException(
          "voter proof window must satisfy issuedAtMs <= expiresAtMs <= issuedAtMs + 15 min");
    }
    String voterAid = aidFromPubkey(ed25519Pub(voterSeed));
    byte[] payload =
        voterPopPayload(target, voterAid, contentDigest, issuedAtMs, expiresAtMs, entryBytes);
    return new VoterPopProof(voterAid, issuedAtMs, expiresAtMs, ed25519Sign(voterSeed, payload));
  }

  /** {@link #signVoterPop} over the {@link #voteEntryBytes} of {@code entry}. */
  public static VoterPopProof signVoterPop(
      byte[] voterSeed,
      VoterPopTarget target,
      byte[] contentDigest,
      VoteEntry entry,
      long issuedAtMs,
      long expiresAtMs) {
    return signVoterPop(
        voterSeed, target, contentDigest, voteEntryBytes(entry), issuedAtMs, expiresAtMs);
  }

  /**
   * {@link #signVoterPop} issued now, expiring {@link #VOTER_POP_DEFAULT_LIFETIME_MS} (5 minutes)
   * later — what a caller signs just before the vote call.
   */
  public static VoterPopProof signVoterPop(
      byte[] voterSeed, VoterPopTarget target, byte[] contentDigest, VoteEntry entry) {
    long now = System.currentTimeMillis();
    return signVoterPop(
        voterSeed, target, contentDigest, entry, now, now + VOTER_POP_DEFAULT_LIFETIME_MS);
  }

  /**
   * {@code true} iff {@code signature} is {@code voterAid}'s Ed25519 signature over {@link
   * #voterPopPayload}. The binding only; the window is the runtime's (and a re-verifier's) to check.
   * Never throws: anything malformed is {@code false}.
   */
  public static boolean verifyVoterPop(
      VoterPopTarget target,
      String voterAid,
      byte[] contentDigest,
      long issuedAtMs,
      long expiresAtMs,
      byte[] entryBytes,
      byte[] signature) {
    try {
      if (signature == null || signature.length != 64) return false;
      return ed25519Verify(
          aidToPubkey(voterAid),
          voterPopPayload(target, voterAid, contentDigest, issuedAtMs, expiresAtMs, entryBytes),
          signature);
    } catch (RuntimeException e) {
      return false;
    }
  }

  /** {@link #verifyVoterPop} over the {@link #voteEntryBytes} of {@code entry}. */
  public static boolean verifyVoterPop(
      VoterPopTarget target,
      String voterAid,
      byte[] contentDigest,
      long issuedAtMs,
      long expiresAtMs,
      VoteEntry entry,
      byte[] signature) {
    try {
      return verifyVoterPop(
          target,
          voterAid,
          contentDigest,
          issuedAtMs,
          expiresAtMs,
          voteEntryBytes(entry),
          signature);
    } catch (RuntimeException e) {
      return false;
    }
  }

  /**
   * Re-check one sealed entry's voter verification record offline, from the record alone: rebuild the
   * signed input from the record's own addressing fields and the entry's frozen {@code entry_bytes},
   * check the window at {@code accepted_at_ms} ({@code issued <= expires <= issued + 15 min}, {@code
   * issued <= accepted + 60 s}, {@code accepted <= expires}), and verify the signature with the key
   * {@code principal} embeds. {@code false} for a missing record, a non-{@code pop} method, a signer
   * certificate, or anything that does not verify. Twin of Python {@code verify_voter_record}.
   */
  public static boolean verifyVoterRecord(ExplanationEntry entry) {
    try {
      VoterVerification vv = entry.voterVerification();
      if (vv == null || !"pop".equals(vv.method())) return false;
      long issued = vv.issuedAtMs();
      long expires = vv.expiresAtMs();
      long accepted = vv.acceptedAtMs();
      boolean skewOk =
          Long.compareUnsigned(issued, VOTER_POP_MAX_SKEW_MS) < 0
              || Long.compareUnsigned(issued - VOTER_POP_MAX_SKEW_MS, accepted) <= 0;
      if (!(Long.compareUnsigned(issued, expires) <= 0
          && Long.compareUnsigned(expires - issued, VOTER_POP_MAX_LIFETIME_MS) <= 0
          && skewOk
          && Long.compareUnsigned(accepted, expires) <= 0)) {
        return false;
      }
      if (vv.signerCertificate() != null && vv.signerCertificate().length != 0) return false;
      VoterPopTarget target =
          new VoterPopTarget(
              vv.issuer(),
              vv.tenant(),
              vv.namespace(),
              vv.sessionId(),
              vv.openedAtMillis(),
              vv.audience());
      VoteEntry signed =
          new VoteEntry(
              entry.kind(),
              entry.participant(),
              entry.proposalId(),
              entry.value(),
              entry.reason(),
              entry.confidence(),
              entry.rationaleRef());
      return verifyVoterPop(
          target, vv.principal(), vv.contentDigest(), issued, expires, signed, vv.signature());
    } catch (RuntimeException e) {
      return false;
    }
  }

  /** {@link #verifyCommitmentVoters(List, String, VoterDecisionRef)} with no pinned decision. */
  public static boolean verifyCommitmentVoters(List<ExplanationEntry> entries, String issuer) {
    return verifyCommitmentVoters(entries, issuer, null);
  }

  /**
   * The commitment-level voter check ({@code voter-verification.v1.md} §"The sealed record"). {@code
   * true} iff every {@code vote}, {@code ballot} and {@code objection} carries a record and no {@code
   * evaluation} does; every record's {@code issuer} is {@code issuer} (the one the verifier pinned);
   * all records share one {@code (tenant, namespace, session_id, opened_at_millis, audience)}; when
   * {@code decision} is given, that is the records' own; and each record re-checks ({@link
   * #verifyVoterRecord}). An explanation with no voter-kind entries passes. {@code content_digest} is
   * not re-derived: what it covers is not in the commitment. Twin of Python {@code
   * verify_commitment_voters}.
   */
  public static boolean verifyCommitmentVoters(
      List<ExplanationEntry> entries, String issuer, VoterDecisionRef decision) {
    if (entries == null || issuer == null) return false;
    List<Object> addressing = null;
    for (ExplanationEntry e : entries) {
      if (e == null) return false;
      VoterVerification vv = e.voterVerification();
      if (!VOTER_VERIFIED_KINDS.contains(e.kind())) {
        if (vv != null) return false;
        continue;
      }
      if (vv == null || !issuer.equals(vv.issuer())) return false;
      List<Object> a =
          Arrays.asList(
              vv.tenant(),
              vv.namespace(),
              vv.sessionId(),
              Long.toUnsignedString(vv.openedAtMillis()),
              vv.audience());
      if (addressing == null) addressing = a;
      else if (!a.equals(addressing)) return false;
      if (decision != null
          && (!Objects.equals(vv.tenant(), decision.tenant())
              || !Objects.equals(vv.sessionId(), decision.sessionId()))) {
        return false;
      }
      if (!verifyVoterRecord(e)) return false;
    }
    return true;
  }
}
