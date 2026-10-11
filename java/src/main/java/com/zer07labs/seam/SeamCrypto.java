package com.zer07labs.seam;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.io.ByteArrayOutputStream;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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

  /**
   * One sealed explanation entry. {@code confidence} and {@code rationaleRef} are {@code null} when
   * absent — an absent confidence and a stated {@code 0.0} are different bytes, which is the point of
   * the explanation digest.
   */
  public record ExplanationEntry(
      String kind,
      String participant,
      String proposalId,
      String value,
      String reason,
      Double confidence,
      String rationaleRef) {}

  /**
   * The commitment fields {@code seam-commitment-digest:v2} binds. {@code supersedes} and {@code
   * committer} may be {@code null} (hashed as empty). Field 8 resolves from {@code explanation} (the
   * entries) and/or {@code explanationDigest} (the 32 published bytes) — see {@link #verifyTct}.
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
      List<ExplanationEntry> explanation) {}

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

  /** Deterministic (no-RNG) message id: first 16 bytes of SHA-256("seam-pop-mid"||nonce) as a UUID. */
  private static String popMessageId(String popNonce) {
    byte[] h = sha256(concat("seam-pop-mid".getBytes(StandardCharsets.UTF_8),
        popNonce.getBytes(StandardCharsets.US_ASCII)));
    StringBuilder sb = new StringBuilder(36);
    for (int i = 0; i < 16; i++) {
      if (i == 4 || i == 6 || i == 8 || i == 10) sb.append('-');
      sb.append(String.format("%02x", h[i] & 0xff));
    }
    return sb.toString();
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

  /**
   * {@code seam-explanation-digest:v1} over a sealed explanation (32 raw bytes), entries in sealed
   * order: {@code SHA-256(F("seam-explanation-digest:v1") ‖ be64(count) ‖ Σ ENTRY)}, with {@code ENTRY
   * = F(kind) ‖ F(participant) ‖ F(proposal_id) ‖ F(value) ‖ F(reason) ‖ CONF ‖ REF}, {@code CONF =
   * 0x00 | 0x01 ‖ be64(IEEE-754 bits)}, {@code REF = 0x00 | 0x01 ‖ F(rationale_ref)} and {@code F(x) =
   * be64(len) ‖ x}. Never sorts, never de-duplicates.
   *
   * @throws IllegalArgumentException on an unknown kind or a non-canonical confidence (NaN, ±inf,
   *     outside {@code [0.0, 1.0]}, or {@code -0.0}) — refused rather than hashed. Normative: {@code
   *     seam-runtime/docs/specs/seam-commitment-digest.v2.md}.
   */
  public static byte[] explanationDigest(List<ExplanationEntry> entries) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    be64Frame(out, "seam-explanation-digest:v1".getBytes(StandardCharsets.UTF_8));
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

  /**
   * {@code seam-commitment-digest:v2} (hex): SHA-256 over a <b>length-prefixed</b> framing of a domain
   * tag plus the commitment fields — each field preceded by its 8-byte big-endian length. Mirrors the
   * runtime byte-for-byte, and mirrors the Go/Kotlin/Python/TypeScript shims. v1 is deleted, not
   * dual-verified.
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
   *     #commitmentExplanationDigest}).
   */
  static String seamCommitmentDigest(Commitment c) {
    ByteArrayOutputStream h = new ByteArrayOutputStream();
    byte[][] fields = {
      "seam-commitment-digest:v2".getBytes(StandardCharsets.UTF_8),
      nz(c.id()),
      nz(c.action()),
      nz(c.authority()),
      nz(c.supersedes()),
      nz(c.authMethod()),
      nz(c.trustBasis()),
      nz(c.committer()),
      commitmentExplanationDigest(c)
    };
    for (byte[] f : fields) be64Frame(h, f);
    return hex(sha256(h.toByteArray()));
  }

  /**
   * Independently verify a sealed commitment's rooted TCT — zero server trust, stock crypto only.
   * Checks the EdDSA JWS against the issuer AID's key, the self-issued claims, and that the {@code
   * seam-commitment-digest:v2} grant matches this exact commitment (decided content, committer, and
   * sealed explanation). Any malformed/forged input fails closed (returns {@code false}), never throws
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
      Map<String, Object> header =
          GSON.fromJson(new String(b64urlDecode(parts[0]), StandardCharsets.UTF_8), MAP);
      Map<String, Object> payload =
          GSON.fromJson(new String(b64urlDecode(parts[1]), StandardCharsets.UTF_8), MAP);
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
      String want = "seam-commitment-digest:" + seamCommitmentDigest(c);
      Object grants = payload.get("grants");
      if (!(grants instanceof List<?> list)) return false;
      for (Object g : list) {
        if (want.equals(g)) return true;
      }
      return false;
    } catch (RuntimeException e) {
      return false;
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

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] out = new byte[a.length + b.length];
    System.arraycopy(a, 0, out, 0, a.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
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
   * with the runtime.
   */
  public static final String ENROLL_POP_V1_CONTEXT = "seam-enroll-pop-v1";

  /**
   * The inputs {@link #enrollPopPayload} frames, each exactly as sent on the wire. Strings are signed
   * as their UTF-8 bytes ({@code null} is read as empty). {@code issuedAtMs} is Unix epoch
   * MILLISECONDS, read as an UNSIGNED 64-bit value (the proto field is {@code uint64}).
   */
  public record EnrollPopFields(
      String subjectAid, String tenant, String namespace, long issuedAtMs, String nonce) {}

  /**
   * The exact bytes {@link #enrollPop} signs: {@code frame(context) | frame(subject_aid) |
   * frame(tenant) | frame(namespace) | frame(u64le(issued_at_ms)) | frame(nonce)}, with {@code
   * frame(x) = u32le(len_bytes(x)) | x}. {@code issued_at_ms} is 8 raw little-endian bytes, not ASCII
   * decimal.
   *
   * <p>Pinned by {@code conformance/enroll_pop_v1_payload_vector.json}. Public so a caller can
   * reproduce or verify the binding without re-deriving it from prose.
   */
  public static byte[] enrollPopPayload(EnrollPopFields f) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    enrollFrame(out, ENROLL_POP_V1_CONTEXT.getBytes(StandardCharsets.UTF_8));
    enrollFrame(out, nz(f.subjectAid()));
    enrollFrame(out, nz(f.tenant()));
    enrollFrame(out, nz(f.namespace()));
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
   * — and the nonce is validated first. Prefer {@link #enrolmentProof(byte[], String, String)}, which
   * defaults {@code issuedAtMs} to now and the nonce to a fresh random one.
   */
  public static EnrollProof enrolmentProof(
      byte[] agentSeed, String tenant, String namespace, long issuedAtMs, String nonce) {
    if (agentSeed == null || agentSeed.length != 32) {
      throw new IllegalArgumentException("agent seed must be 32 bytes");
    }
    String subject = aidFromPubkey(ed25519Pub(agentSeed));
    byte[] sig =
        enrollPop(agentSeed, new EnrollPopFields(subject, tenant, namespace, issuedAtMs, nonce));
    return new EnrollProof(issuedAtMs, nonce, sig);
  }

  /**
   * This agent's consent to being enrolled under {@code tenant}/{@code namespace}: the {@code pop} an
   * operator sends with {@code EnrollTenant} (gRPC: the raw fields; REST: {@link
   * EnrollProof#toRest}). Required for enrolment by a tenant-scoped operator token. {@code issuedAtMs}
   * is now and the nonce is 16 fresh random bytes as 22 base64url characters. The counterpart of
   * Python's {@code Agent.enrolment_proof} and TypeScript's {@code Agent.enrolmentProof}.
   */
  public static EnrollProof enrolmentProof(byte[] agentSeed, String tenant, String namespace) {
    return enrolmentProof(
        agentSeed, tenant, namespace, System.currentTimeMillis(), newEnrollPopNonce());
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
}
