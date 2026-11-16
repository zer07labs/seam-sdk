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
   * enum name ({@code EXPLANATION_KIND_VOTE} → {@code "vote"}).
   */
  public static final List<String> EXPLANATION_KINDS =
      List.of("vote", "evaluation", "objection", "ballot");

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
   * The commitment fields {@code seam-commitment-digest:v4} binds. {@code committer} may be {@code
   * null} (hashed as empty). {@code supersedes} is {@code null} when ABSENT, which v4 frames as
   * {@code 0x00} — a different digest from a present empty string ({@code 0x01 ‖ F("")}). Field 8 resolves from {@code explanation} (the
   * entries) and/or {@code explanationDigest} (the 32 published bytes) — see {@link #verifyTct}.
   * {@code selectionDigest} (field 9) and {@code certificateDigest} (field 10) are {@code null} when
   * absent — every record runtime 0.87.0 seals — and exactly 32 bytes when present.
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
      byte[] certificateDigest) {
    /** A commitment with neither a selection (field 9) nor a Gate certificate (field 10). */
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
   *     seam-runtime/docs/specs/seam-commitment-digest.v4.md}.
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
  public static final String COMMITMENT_DIGEST_DOMAIN = "seam-commitment-digest:v4";

  /** The one grant a commitment self-attestation carries. */
  public static final String ATTESTATION_GRANT = "aitp.attestation";

  /** The {@code ext} namespace the commitment statement rides under. */
  public static final String COMMITMENT_EXT_NAMESPACE = "com.zer07labs.seam";

  /** The statement {@code type} inside {@link #COMMITMENT_EXT_NAMESPACE}. */
  public static final String COMMITMENT_STATEMENT = "seam:commitment";

  /**
   * {@code seam-commitment-digest:v4} (hex): SHA-256 over a <b>length-prefixed</b> framing of a domain
   * tag plus the commitment fields — each field preceded by its 8-byte big-endian length. Mirrors the
   * runtime byte-for-byte, and mirrors the Go/Kotlin/Python/TypeScript shims. v3 is deleted, not
   * dual-verified. {@code supersedes} carries a presence byte — {@code 0x00} when absent ({@code
   * null}), {@code 0x01 ‖ F(s)} when present. v4 (#1687) binds the v2 explanation digest as field 8 and
   * appends two always-framed slots: field 9 (selection digest) and field 10 (Gate certificate
   * digest), each {@code 0x00} when absent or {@code 0x01 ‖ be64(32) ‖ 32 raw bytes}.
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
   *     #commitmentExplanationDigest}), or a present field 9/10 digest is not 32 bytes.
   */
  static String seamCommitmentDigest(Commitment c) {
    checkSlot("selection_digest", c.selectionDigest());
    checkSlot("certificate_digest", c.certificateDigest());
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

  /**
   * Independently verify a sealed commitment's rooted TCT — zero server trust, stock crypto only.
   * Checks the EdDSA JWS ({@code typ} {@code aitp-tct+jwt}) against the pinned issuer AID's key; the
   * self-issued claims ({@code iss == sub == aud == issuerAid}); {@code exp}; that {@code grants} is
   * exactly {@code ["aitp.attestation"]}; and that {@code ext} is exactly {@code
   * {"com.zer07labs.seam":{"type":"seam:commitment","commitment_digest":<hex>}}} with the hex equal to
   * the recomputed {@code seam-commitment-digest:v4} of this exact commitment (decided content,
   * committer, and sealed explanation). A header or payload whose JSON repeats an object key at any
   * depth is refused: Gson would keep one of the two, and another parser might keep the other. Any malformed/forged input fails closed (returns {@code false}), never throws
   * — including explanation entries that disagree with the published digest, an unknown kind, or a
   * non-canonical confidence.
   */
  public static boolean verifyTct(String issuerAid, String tctJws, Commitment c, long nowS) {
    try {
      String[] parts = tctJws.split("\\.");
      if (parts.length != 3) return false;
      byte[] pub;
      try {
        pub = aidToPubkey(issuerAid);
      } catch (RuntimeException e) {
        return false;
      }
      if (pub.length != 32) return false;
      if (!ed25519Verify(pub, (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII),
          b64urlDecode(parts[2]))) {
        return false;
      }
      String headerJson = new String(b64urlDecode(parts[0]), StandardCharsets.UTF_8);
      String payloadJson = new String(b64urlDecode(parts[1]), StandardCharsets.UTF_8);
      if (hasDuplicateKey(headerJson) || hasDuplicateKey(payloadJson)) return false;
      Map<String, Object> header = GSON.fromJson(headerJson, MAP);
      Map<String, Object> payload = GSON.fromJson(payloadJson, MAP);
      if (header == null || payload == null) return false;
      if (!"EdDSA".equals(header.get("alg")) || !"aitp-tct+jwt".equals(header.get("typ"))) {
        return false;
      }
      if (!(issuerAid.equals(payload.get("iss"))
          && issuerAid.equals(payload.get("sub"))
          && issuerAid.equals(payload.get("aud")))) {
        return false;
      }
      Object exp = payload.get("exp");
      if (!(exp instanceof Number) || nowS >= ((Number) exp).longValue()) return false;
      if (!(payload.get("grants") instanceof List<?> grants)
          || grants.size() != 1
          || !ATTESTATION_GRANT.equals(grants.get(0))) {
        return false;
      }
      if (!(payload.get("ext") instanceof Map<?, ?> ext)
          || ext.size() != 1
          || !(ext.get(COMMITMENT_EXT_NAMESPACE) instanceof Map<?, ?> stmt)
          || stmt.size() != 2
          || !COMMITMENT_STATEMENT.equals(stmt.get("type"))
          || !(stmt.get("commitment_digest") instanceof String digest)) {
        return false;
      }
      return digest.equals(seamCommitmentDigest(c));
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
