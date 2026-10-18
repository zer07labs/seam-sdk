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
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * {@code seam-commitment-digest:v2} + {@code seam-explanation-digest:v1} against the runtime's
 * reference vector ({@code conformance/commitment_digest_v2_vector.json}). Conforming iff every digest
 * is reproduced and the signed case verifies against the issuer AID. NO bless mode.
 */
class CommitmentDigestV2Test {
  private static final Type MAP = new TypeToken<Map<String, Object>>() {}.getType();
  private static final long NOW_S = 1_700_000_001L;
  private static final HexFormat HEX = HexFormat.of();

  private static Map<String, Object> vector() throws Exception {
    String raw = Files.readString(Path.of("..", "conformance", "commitment_digest_v2_vector.json"));
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
    assertEquals(2, cases().size());
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
        "78edca52ba1e88f13a78e5569742bfce0b51474ca840bf38a8dde414d5515784",
        SeamCrypto.seamCommitmentDigest(withEntries(c, null, null)));
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
}
