package com.zer07labs.seam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.zer07labs.seam.SeamCrypto.CommitmentDigestFields;
import com.zer07labs.seam.SeamCrypto.CommitmentTrailers;
import com.zer07labs.seam.SeamCrypto.CommitmentVersion;
import com.zer07labs.seam.SeamCrypto.ExplanationEntry;
import com.zer07labs.seam.SeamCrypto.VoterDecisionRef;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * {@code seam-commitment-digest:v6} with sealed voter records: every row of {@code
 * conformance/commitment_digest_v6_voter_vector.json} (copied byte for byte from seam-runtime,
 * seamd 0.113.0). Specs: seam-runtime {@code docs/specs/seam-commitment-digest.v6.md} and {@code
 * docs/specs/voter-verification.v1.md}. Twin of Python {@code test_commitment_digest_v6_voters.py}.
 *
 * <p>A case passes under v6 AND {@code verifyCommitmentVoters(entries, issuer, decision)} with
 * {@code voters_verified} records. A negative is refused by at least one of the two. {@code rule}
 * is advisory, so no test compares it. NO bless mode.
 */
class CommitmentDigestV6VoterTest {
  private static final HexFormat HEX = HexFormat.of();
  private static final String FILE = "commitment_digest_v6_voter_vector.json";

  private static byte[] hex(Object s) {
    return s == null ? null : HEX.parseHex((String) s);
  }

  @SuppressWarnings("unchecked")
  private static VoterDecisionRef decision(Map<String, Object> v) {
    List<String> d = (List<String>) v.get("decision");
    assertEquals(2, d.size());
    return new VoterDecisionRef(d.get(0), d.get(1));
  }

  /** The row as {@code verifyTct} reads it: the full commitment WITH its entries, plus trailers. */
  @SuppressWarnings("unchecked")
  private static SeamCrypto.Commitment commitment(Map<String, Object> row) {
    SeamCrypto.Commitment b = ConformanceTest.commitment((Map<String, Object>) row.get("commitment"));
    return new SeamCrypto.Commitment(
        b.id(), b.action(), b.authority(), b.supersedes(), b.authMethod(), b.trustBasis(),
        b.committer(), b.explanationDigest(), b.explanation(), b.selectionDigest(),
        b.certificateDigest(), b.governingDocSha256(), hex(row.get("trailers")));
  }

  private static long records(List<ExplanationEntry> entries) {
    return entries.stream().filter(e -> e.voterVerification() != null).count();
  }

  private static Map<String, Object> negative(Map<String, Object> v, String name) {
    for (Map<String, Object> r : CommitmentDigestV6Test.rows(v, "negatives")) {
      if (name.equals(r.get("name"))) return r;
    }
    throw new AssertionError("no negative " + name);
  }

  @Test
  void theVectorFileIsTheV6VoterSpec() throws Exception {
    Map<String, Object> v = CommitmentDigestV6Test.load(FILE);
    assertEquals(SeamCrypto.COMMITMENT_DIGEST_DOMAIN_V6, v.get("commitment_digest_domain"));
    assertEquals("seam-commitment-digest:v6", v.get("commitment_digest_domain"));
    assertEquals("seam-explanation-digest:v2", v.get("explanation_digest_domain"));
    assertEquals(SeamCrypto.GATE_DIGEST_DOMAIN, v.get("gate_digest_domain"));
    assertEquals("seam-gate-digest:v1", v.get("gate_digest_domain"));
    decision(v);
    Set<String> lists = new HashSet<>();
    for (Map.Entry<String, Object> e : v.entrySet()) {
      if (e.getValue() instanceof List<?>) lists.add(e.getKey());
    }
    assertEquals(Set.of("decision", "cases", "negatives"), lists);
    assertEquals(2, CommitmentDigestV6Test.rows(v, "cases").size());
    assertEquals(8, CommitmentDigestV6Test.rows(v, "negatives").size());
  }

  @Test
  void everyCaseVerifiesWithItsVoterRecords() throws Exception {
    Map<String, Object> v = CommitmentDigestV6Test.load(FILE);
    String issuer = (String) v.get("issuer_aid");
    VoterDecisionRef decision = decision(v);
    long votersVerified = ((Number) v.get("voters_verified")).longValue();
    for (Map<String, Object> k : CommitmentDigestV6Test.rows(v, "cases")) {
      String name = (String) k.get("name");
      assertEquals("v6", k.get("expect"), name);
      assertEquals(
          CommitmentVersion.V6, SeamCrypto.selectCommitmentVersion((String) k.get("ext")), name);
      SeamCrypto.Commitment c = commitment(k);
      List<ExplanationEntry> entries = c.explanation();
      assertArrayEquals(c.explanationDigest(), SeamCrypto.explanationDigest(entries), name);
      CommitmentTrailers t =
          SeamCrypto.decodeCommitmentTrailers(c.trailers(), CommitmentVersion.V6);
      assertEquals(
          k.get("commitment_digest"),
          SeamCrypto.commitmentDigest(
              CommitmentVersion.V6,
              c,
              new CommitmentDigestFields(null, t.gateDigest(), t.governingDocSha256(), t.env())),
          name);
      assertTrue(SeamCrypto.verifyTct(issuer, (String) k.get("signed_artifact"), c, 0), name);
      assertTrue(SeamCrypto.verifyCommitmentVoters(entries, issuer, decision), name);
      assertEquals(votersVerified, records(entries), name);
    }
  }

  @Test
  void everyNegativeIsRefused() throws Exception {
    Map<String, Object> v = CommitmentDigestV6Test.load(FILE);
    String issuer = (String) v.get("issuer_aid");
    VoterDecisionRef decision = decision(v);
    Set<String> cases = new HashSet<>();
    for (Map<String, Object> k : CommitmentDigestV6Test.rows(v, "cases")) {
      cases.add((String) k.get("name"));
    }
    for (Map<String, Object> n : CommitmentDigestV6Test.rows(v, "negatives")) {
      String name = (String) n.get("name");
      assertEquals("refused", n.get("expect"), name);
      assertTrue(cases.contains((String) n.get("over")), name);
      SeamCrypto.Commitment c = commitment(n);
      boolean tctOk = SeamCrypto.verifyTct(issuer, (String) n.get("signed_artifact"), c, 0);
      boolean votersOk = SeamCrypto.verifyCommitmentVoters(c.explanation(), issuer, decision);
      assertFalse(tctOk && votersOk, name);
    }
  }

  /**
   * {@code wrong_decision} is a well-signed TCT whose records name another decision: only the
   * decision the verifier knows can refuse it, so dropping that argument must let it through.
   */
  @Test
  void theDecisionBindingIsWhatRefusesWrongDecision() throws Exception {
    Map<String, Object> v = CommitmentDigestV6Test.load(FILE);
    String issuer = (String) v.get("issuer_aid");
    Map<String, Object> n = negative(v, "wrong_decision");
    SeamCrypto.Commitment c = commitment(n);
    assertTrue(SeamCrypto.verifyTct(issuer, (String) n.get("signed_artifact"), c, 0));
    assertTrue(SeamCrypto.verifyCommitmentVoters(c.explanation(), issuer));
    assertFalse(SeamCrypto.verifyCommitmentVoters(c.explanation(), issuer, decision(v)));
  }

  /**
   * The entries and their digest were rewritten together and the old TCT kept: the records still
   * re-check, so it is the commitment digest under the signature that refuses it.
   */
  @Test
  void aTamperedPublishedEntryBreaksTheSignedDigest() throws Exception {
    Map<String, Object> v = CommitmentDigestV6Test.load(FILE);
    String issuer = (String) v.get("issuer_aid");
    Map<String, Object> n = negative(v, "tampered_published_entry");
    SeamCrypto.Commitment c = commitment(n);
    assertTrue(SeamCrypto.verifyCommitmentVoters(c.explanation(), issuer, decision(v)));
    assertFalse(SeamCrypto.verifyTct(issuer, (String) n.get("signed_artifact"), c, 0));
  }
}
