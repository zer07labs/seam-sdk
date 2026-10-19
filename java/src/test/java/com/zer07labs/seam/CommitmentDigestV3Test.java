package com.zer07labs.seam;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.jupiter.api.Test;

/**
 * {@code seam-commitment-digest:v3} + {@code seam-explanation-digest:v1} against the runtime's
 * reference vector ({@code conformance/commitment_digest_v3_vector.json}). Conforming iff every digest
 * is reproduced and the signed case verifies against the issuer AID. NO bless mode. Also pins the
 * self-attestation TCT shape {@code verifyTct} accepts, and nothing beside it.
 */
class CommitmentDigestV3Test {
  private static final Type MAP = new TypeToken<Map<String, Object>>() {}.getType();
  private static final long NOW_S = 1_700_000_001L;
  private static final HexFormat HEX = HexFormat.of();

  private static Map<String, Object> vector() throws Exception {
    String raw = Files.readString(Path.of("..", "conformance", "commitment_digest_v3_vector.json"));
    return new Gson().fromJson(raw, MAP);
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> cases() throws Exception {
    return (List<Map<String, Object>>) vector().get("cases");
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> caseNamed(String name) throws Exception {
    for (Map<String, Object> c : cases()) if (name.equals(c.get("name"))) return c;
    throw new AssertionError("no case " + name);
  }

  @SuppressWarnings("unchecked")
  private static SeamCrypto.Commitment commitmentOf(Map<String, Object> k) {
    return ConformanceTest.commitment((Map<String, Object>) k.get("commitment"));
  }

  @SuppressWarnings("unchecked")
  private static String signedArtifact(Map<String, Object> k) {
    List<Object> nums = (List<Object>) ((Map<String, Object>) k.get("commitment")).get("signed_artifact");
    byte[] b = new byte[nums.size()];
    for (int i = 0; i < b.length; i++) b[i] = (byte) ((Number) nums.get(i)).intValue();
    return new String(b, StandardCharsets.US_ASCII);
  }

  private static SeamCrypto.ExplanationEntry eval(Double confidence) {
    return new SeamCrypto.ExplanationEntry("evaluation", "p", "p1", "APPROVE", "", confidence, null);
  }

  private static SeamCrypto.Commitment withEntries(
      SeamCrypto.Commitment b, byte[] published, List<SeamCrypto.ExplanationEntry> entries) {
    return new SeamCrypto.Commitment(
        b.id(), b.action(), b.authority(), b.supersedes(), b.authMethod(), b.trustBasis(),
        b.committer(), published, entries);
  }

  @Test
  void everyCaseDigestIsByteExact() throws Exception {
    assertEquals(3, cases().size());
    for (Map<String, Object> k : cases()) {
      SeamCrypto.Commitment c = commitmentOf(k);
      String name = (String) k.get("name");
      assertEquals(
          k.get("explanation_digest"),
          HEX.formatHex(SeamCrypto.explanationDigest(c.explanation())),
          name + ": explanation_digest");
      // The published digest the vector carries is the same value.
      assertEquals(k.get("explanation_digest"), HEX.formatHex(c.explanationDigest()), name);
      assertEquals(k.get("commitment_digest"), SeamCrypto.seamCommitmentDigest(c), name);
      // Field 8 resolves the same from entries only, published digest only, or both.
      assertEquals(
          k.get("commitment_digest"),
          SeamCrypto.seamCommitmentDigest(withEntries(c, null, c.explanation())),
          name + ": entries only");
      assertEquals(
          k.get("commitment_digest"),
          SeamCrypto.seamCommitmentDigest(withEntries(c, c.explanationDigest(), null)),
          name + ": published digest only");
    }
  }

  @Test
  void emptyExplanationDigestMatchesSpec() {
    assertEquals(
        "eb7853dc086ef5385db8408cf35c9c984e845ccc03d269102f942eed7806ce40",
        HEX.formatHex(SeamCrypto.explanationDigest(List.of())));
  }

  @Test
  void neitherEntriesNorDigestIsTheEmptyExplanation() throws Exception {
    SeamCrypto.Commitment c = commitmentOf(caseNamed("all_empty"));
    assertEquals(
        "9238441205cd395f9507a5152e2c67f93fa83ca8d336d2ce7b8e01a385c3dd2e",
        SeamCrypto.seamCommitmentDigest(withEntries(c, null, null)));
  }

  /** v3's presence byte: absent supersedes and present-empty supersedes are different digests. */
  @Test
  void emptyAndAbsentSupersedesDiffer() throws Exception {
    SeamCrypto.Commitment absent = commitmentOf(caseNamed("all_empty"));
    SeamCrypto.Commitment empty = commitmentOf(caseNamed("empty_supersedes"));
    assertEquals(null, absent.supersedes());
    assertEquals("", empty.supersedes());
    assertNotEquals(
        SeamCrypto.seamCommitmentDigest(absent), SeamCrypto.seamCommitmentDigest(empty));
    assertEquals(
        "b7f0e7a2a14e91f0d7dc1a56781a39f7601bce4df979f3b25a58aa9d86d3263c",
        SeamCrypto.seamCommitmentDigest(empty));
  }

  @Test
  void populatedSignedArtifactVerifies() throws Exception {
    Map<String, Object> k = caseNamed("populated_signed");
    String iss = (String) vector().get("issuer_aid");
    SeamCrypto.Commitment c = commitmentOf(k);
    String jws = signedArtifact(k);
    assertTrue(SeamCrypto.verifyTct(iss, jws, c, NOW_S), "entries + published digest");
    assertTrue(
        SeamCrypto.verifyTct(iss, jws, withEntries(c, null, c.explanation()), NOW_S), "entries only");
    assertTrue(
        SeamCrypto.verifyTct(iss, jws, withEntries(c, c.explanationDigest(), null), NOW_S),
        "published digest only");
  }

  @Test
  void absentConfidenceDiffersFromStatedZero() {
    assertNotEquals(
        HEX.formatHex(SeamCrypto.explanationDigest(List.of(eval(null)))),
        HEX.formatHex(SeamCrypto.explanationDigest(List.of(eval(0.0)))));
  }

  @Test
  void nonCanonicalConfidenceIsRefused() {
    for (double bad :
        new double[] {
          -0.0, Double.NaN, 1.5, -0.1, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY
        }) {
      assertThrows(
          IllegalArgumentException.class,
          () -> SeamCrypto.explanationDigest(List.of(eval(bad))),
          "confidence " + bad + " must be refused");
    }
    // The bounds themselves are canonical.
    SeamCrypto.explanationDigest(List.of(eval(0.0), eval(1.0)));
  }

  @Test
  void unknownKindIsRefused() {
    for (String kind : new String[] {"EXPLANATION_KIND_VOTE", "Vote", "comment", ""}) {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              SeamCrypto.explanationDigest(
                  List.of(new SeamCrypto.ExplanationEntry(kind, "p", "p1", "v", "", null, null))),
          "kind " + kind + " must be refused");
    }
  }

  @Test
  void malformedExplanationFailsVerifyClosed() throws Exception {
    Map<String, Object> k = caseNamed("populated_signed");
    String iss = (String) vector().get("issuer_aid");
    SeamCrypto.Commitment c = commitmentOf(k);
    String jws = signedArtifact(k);

    // Entries that disagree with the published digest: verify false, never throw.
    List<SeamCrypto.ExplanationEntry> dropped = new ArrayList<>(c.explanation());
    dropped.remove(dropped.size() - 1);
    assertFalse(SeamCrypto.verifyTct(iss, jws, withEntries(c, c.explanationDigest(), dropped), NOW_S));
    assertThrows(
        IllegalArgumentException.class,
        () -> SeamCrypto.seamCommitmentDigest(withEntries(c, c.explanationDigest(), dropped)));

    // The genuine entries with a tampered published digest: also false.
    byte[] tampered = c.explanationDigest().clone();
    tampered[0] ^= 1;
    assertFalse(SeamCrypto.verifyTct(iss, jws, withEntries(c, tampered, c.explanation()), NOW_S));

    // A published digest of the wrong length: false.
    assertFalse(SeamCrypto.verifyTct(iss, jws, withEntries(c, new byte[31], null), NOW_S));

    // A malformed entry (unknown kind / non-canonical confidence): false.
    List<SeamCrypto.ExplanationEntry> badKind = new ArrayList<>(c.explanation());
    SeamCrypto.ExplanationEntry e = badKind.get(3);
    badKind.set(
        3,
        new SeamCrypto.ExplanationEntry(
            "EXPLANATION_KIND_VOTE", e.participant(), e.proposalId(), e.value(), e.reason(),
            e.confidence(), e.rationaleRef()));
    assertFalse(SeamCrypto.verifyTct(iss, jws, withEntries(c, null, badKind), NOW_S));
    List<SeamCrypto.ExplanationEntry> negZero = new ArrayList<>(c.explanation());
    SeamCrypto.ExplanationEntry z = negZero.get(1);
    negZero.set(
        1,
        new SeamCrypto.ExplanationEntry(
            z.kind(), z.participant(), z.proposalId(), z.value(), z.reason(), -0.0,
            z.rationaleRef()));
    assertFalse(SeamCrypto.verifyTct(iss, jws, withEntries(c, null, negZero), NOW_S));

    // Absent confidence where 0.0 was stated: a different digest, so false.
    List<SeamCrypto.ExplanationEntry> unstated = new ArrayList<>(c.explanation());
    unstated.set(
        1,
        new SeamCrypto.ExplanationEntry(
            z.kind(), z.participant(), z.proposalId(), z.value(), z.reason(), null,
            z.rationaleRef()));
    assertFalse(SeamCrypto.verifyTct(iss, jws, withEntries(c, null, unstated), NOW_S));
  }

  // -- The self-attestation shape -------------------------------------------------------------
  //
  // Tokens re-signed locally with the `tct` block's issuer seed, so a refusal below can only be
  // about the claim it changes: the well-formed control verifies with the same key and commitment.

  private static Map<String, Object> tctBlock() throws Exception {
    String raw = Files.readString(Path.of("..", "conformance", "vectors.json"));
    @SuppressWarnings("unchecked")
    Map<String, Object> t = (Map<String, Object>) new Gson().<Map<String, Object>>fromJson(raw, MAP).get("tct");
    return t;
  }

  @SuppressWarnings("unchecked")
  private static String seedHex(Map<String, Object> t) {
    return (String) ((Map<String, Object>) t.get("inputs")).get("issuer_seed_hex");
  }

  @SuppressWarnings("unchecked")
  private static SeamCrypto.Commitment tctCommitment(Map<String, Object> t) {
    return ConformanceTest.commitment(
        (Map<String, Object>) ((Map<String, Object>) t.get("inputs")).get("commitment"));
  }

  private static String b64(byte[] b) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  private static String sign(String seedHex, String payloadJson) {
    String input =
        b64("{\"alg\":\"EdDSA\",\"typ\":\"aitp-tct+jwt\"}".getBytes(StandardCharsets.UTF_8))
            + "."
            + b64(payloadJson.getBytes(StandardCharsets.UTF_8));
    byte[] msg = input.getBytes(StandardCharsets.US_ASCII);
    Ed25519Signer s = new Ed25519Signer();
    s.init(true, new Ed25519PrivateKeyParameters(HEX.parseHex(seedHex), 0));
    s.update(msg, 0, msg.length);
    return input + "." + b64(s.generateSignature());
  }

  private static Map<String, Object> statement(String digest) {
    Map<String, Object> st = new LinkedHashMap<>();
    st.put("type", SeamCrypto.COMMITMENT_STATEMENT);
    st.put("commitment_digest", digest);
    return st;
  }

  private static Map<String, Object> payload(String iss, String digest) {
    Map<String, Object> p = new LinkedHashMap<>();
    p.put("iss", iss);
    p.put("sub", iss);
    p.put("aud", iss);
    p.put("exp", 4_853_600_000L);
    p.put("grants", List.of(SeamCrypto.ATTESTATION_GRANT));
    p.put("ext", Map.of(SeamCrypto.COMMITMENT_EXT_NAMESPACE, statement(digest)));
    return p;
  }

  @Test
  void wellFormedSelfAttestationVerifies() throws Exception {
    Map<String, Object> t = tctBlock();
    SeamCrypto.Commitment c = tctCommitment(t);
    String iss = (String) t.get("issuer_aid");
    String digest = SeamCrypto.seamCommitmentDigest(c);
    assertTrue(SeamCrypto.verifyTct(iss, sign(seedHex(t), new Gson().toJson(payload(iss, digest))), c, NOW_S));
  }

  @Test
  void attestationShapeRefusals() throws Exception {
    Map<String, Object> t = tctBlock();
    SeamCrypto.Commitment c = tctCommitment(t);
    String iss = (String) t.get("issuer_aid");
    String digest = SeamCrypto.seamCommitmentDigest(c);
    String other = "aid:pubkey:ed25519:" + "B".repeat(43);

    Map<String, Consumer<Map<String, Object>>> mutations = new LinkedHashMap<>();
    mutations.put(
        "statement in grants (v2 shape)",
        p -> {
          p.remove("ext");
          p.put("grants", List.of("seam:commitment", "seam-commitment-digest:" + digest));
        });
    mutations.put(
        "extra grant",
        p -> p.put("grants", List.of(SeamCrypto.ATTESTATION_GRANT, "seam-commitment-digest:" + digest)));
    mutations.put("no grants", p -> p.remove("grants"));
    mutations.put("iss != aud", p -> p.put("aud", other));
    mutations.put("sub != iss", p -> p.put("sub", other));
    mutations.put("ext absent", p -> p.remove("ext"));
    mutations.put(
        "extra ext key",
        p -> p.put(
            "ext",
            Map.of(SeamCrypto.COMMITMENT_EXT_NAMESPACE, statement(digest), "com.example", Map.of())));
    mutations.put(
        "wrong type",
        p -> {
          Map<String, Object> st = statement(digest);
          st.put("type", "seam:other");
          p.put("ext", Map.of(SeamCrypto.COMMITMENT_EXT_NAMESPACE, st));
        });
    mutations.put(
        "extra statement field",
        p -> {
          Map<String, Object> st = statement(digest);
          st.put("x", "y");
          p.put("ext", Map.of(SeamCrypto.COMMITMENT_EXT_NAMESPACE, st));
        });
    mutations.put(
        "uppercase digest",
        p -> p.put("ext", Map.of(SeamCrypto.COMMITMENT_EXT_NAMESPACE, statement(digest.toUpperCase()))));
    mutations.put(
        "wrong digest",
        p -> p.put("ext", Map.of(SeamCrypto.COMMITMENT_EXT_NAMESPACE, statement("0".repeat(64)))));

    for (Map.Entry<String, Consumer<Map<String, Object>>> m : mutations.entrySet()) {
      Map<String, Object> p = payload(iss, digest);
      m.getValue().accept(p);
      assertFalse(
          SeamCrypto.verifyTct(iss, sign(seedHex(t), new Gson().toJson(p)), c, NOW_S),
          m.getKey() + " must be refused");
    }
  }

  /**
   * A payload whose JSON repeats a key is refused: Gson keeps one of the two, and a different parser
   * might keep the other, so the same signed bytes would mean two things.
   */
  @Test
  void duplicateKeyIsRefused() throws Exception {
    Map<String, Object> t = tctBlock();
    SeamCrypto.Commitment c = tctCommitment(t);
    String iss = (String) t.get("issuer_aid");
    String digest = SeamCrypto.seamCommitmentDigest(c);
    String head =
        "{\"iss\":\"" + iss + "\",\"sub\":\"" + iss + "\",\"aud\":\"" + iss
            + "\",\"exp\":4853600000,\"grants\":[\"aitp.attestation\"],";
    String good =
        "\"ext\":{\"com.zer07labs.seam\":{\"type\":\"seam:commitment\",\"commitment_digest\":\""
            + digest + "\"}}}";
    assertTrue(
        SeamCrypto.verifyTct(iss, sign(seedHex(t), head + good), c, NOW_S),
        "the hand-written control payload must verify");
    String zeros = "0".repeat(64);
    String decoy = "{\"type\":\"seam:commitment\",\"commitment_digest\":\"" + zeros + "\"}";
    Map<String, String> bodies =
        Map.of(
            "duplicate namespace key",
            "\"ext\":{\"com.zer07labs.seam\":" + decoy
                + ",\"com.zer07labs.seam\":{\"type\":\"seam:commitment\",\"commitment_digest\":\""
                + digest + "\"}}}",
            "duplicate statement key",
            "\"ext\":{\"com.zer07labs.seam\":{\"type\":\"seam:commitment\",\"commitment_digest\":\""
                + zeros + "\",\"commitment_digest\":\"" + digest + "\"}}}",
            "duplicate ext",
            "\"ext\":{\"com.zer07labs.seam\":" + decoy + "}," + good);
    for (Map.Entry<String, String> b : bodies.entrySet()) {
      assertFalse(
          SeamCrypto.verifyTct(iss, sign(seedHex(t), head + b.getValue()), c, NOW_S),
          b.getKey() + " must be refused");
    }
  }
}
