package com.zer07labs.seam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * {@code seam-voter-pop-v1} (seam-sdk#359): every case of {@code
 * conformance/voter_pop_v1_payload_vector.json} byte for byte — the same bytes the independent Python
 * generator, the Python SDK and the TypeScript SDK assert — plus the sealed-record re-check against
 * the {@code vectors.json} TCT's vote.
 */
class VoterPopTest {
  private static final Type MAP = new TypeToken<Map<String, Object>>() {}.getType();
  private static final HexFormat HEX = HexFormat.of();

  @SuppressWarnings("unchecked")
  private static Map<String, Object> vector() throws Exception {
    return new Gson()
        .fromJson(
            Files.readString(Path.of("..", "conformance", "voter_pop_v1_payload_vector.json")), MAP);
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> cases() throws Exception {
    return (List<Map<String, Object>>) vector().get("cases");
  }

  private static Map<String, Object> byName(String name) throws Exception {
    for (Map<String, Object> c : cases()) if (name.equals(c.get("name"))) return c;
    throw new AssertionError("no case " + name);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> m(Map<String, Object> p, String k) {
    return (Map<String, Object>) p.get(k);
  }

  private static long l(Object o) {
    return ((Number) o).longValue();
  }

  private static SeamCrypto.VoterPopTarget target(Map<String, Object> c) {
    Map<String, Object> t = m(c, "target");
    return new SeamCrypto.VoterPopTarget(
        (String) t.get("issuer"),
        (String) t.get("tenant"),
        (String) t.get("namespace"),
        (String) t.get("session_id"),
        l(t.get("opened_at_millis")),
        (String) t.get("audience"));
  }

  @SuppressWarnings("unchecked")
  private static byte[] contentDigest(Map<String, Object> c) {
    Map<String, Object> k = m(c, "content");
    List<SeamCrypto.VoteContext> ctx = new ArrayList<>();
    for (Object o : (List<Object>) k.get("context")) {
      Map<String, Object> b = (Map<String, Object>) o;
      ctx.add(new SeamCrypto.VoteContext((String) b.get("ctx_ref"), (String) b.get("content_hash")));
    }
    List<SeamCrypto.Feature> feats = new ArrayList<>();
    for (Object o : (List<Object>) k.get("features")) {
      List<String> kv = (List<String>) o;
      feats.add(new SeamCrypto.Feature(kv.get(0), kv.get(1)));
    }
    Map<String, Object> p = (Map<String, Object>) k.get("policy");
    SeamCrypto.VotePolicyRef policy =
        p == null
            ? null
            : new SeamCrypto.VotePolicyRef(
                (String) p.get("policy_version"), HEX.parseHex((String) p.get("rules_digest_hex")));
    return SeamCrypto.voteContentDigest(
        (String) k.get("mode"),
        (String) k.get("proposal_id"),
        (String) k.get("content"),
        (List<String>) k.get("participants"),
        (List<String>) k.get("on_behalf_of"),
        ctx,
        feats,
        policy);
  }

  private static SeamCrypto.VoteEntry entry(Map<String, Object> c) {
    Map<String, Object> e = m(c, "entry");
    Object conf = e.get("confidence");
    return new SeamCrypto.VoteEntry(
        (String) e.get("kind"),
        (String) e.get("participant"),
        (String) e.get("proposal_id"),
        (String) e.get("value"),
        (String) e.get("reason"),
        conf == null ? null : ((Number) conf).doubleValue(),
        (String) e.get("rationale_ref"));
  }

  private static byte[] seed(Map<String, Object> c) {
    return HEX.parseHex((String) c.get("seed_hex"));
  }

  @Test
  void theVectorIsPopulatedAndTheDomainsMatch() throws Exception {
    Map<String, Object> v = vector();
    assertEquals(SeamCrypto.VOTER_POP_V1_DOMAIN, v.get("domain"));
    assertEquals(SeamCrypto.VOTE_CONTENT_V1_DOMAIN, v.get("content_domain"));
    assertTrue(cases().size() >= 10);
  }

  @Test
  void everyByteMatchesTheVector() throws Exception {
    for (Map<String, Object> c : cases()) {
      String n = (String) c.get("name");
      byte[] digest = contentDigest(c);
      assertEquals(c.get("content_digest_hex"), HEX.formatHex(digest), n + ": content digest");
      byte[] eb = SeamCrypto.voteEntryBytes(entry(c));
      assertEquals(c.get("entry_bytes_hex"), HEX.formatHex(eb), n + ": entry bytes");
      long issued = l(c.get("issued_at_ms"));
      long expires = l(c.get("expires_at_ms"));
      byte[] payload =
          SeamCrypto.voterPopPayload(
              target(c), (String) c.get("voter_aid"), digest, issued, expires, eb);
      assertEquals(c.get("payload_hex"), HEX.formatHex(payload), n + ": payload");
      // The cross-port gate: the bytes signed here equal the independent Python generator's.
      SeamCrypto.VoterPopProof p =
          SeamCrypto.signVoterPop(seed(c), target(c), digest, entry(c), issued, expires);
      assertEquals(c.get("voter_aid"), p.voterAid(), n + ": voter AID");
      assertEquals(c.get("signature_hex"), HEX.formatHex(p.signature()), n + ": signature");
      assertEquals(issued, p.issuedAtMs());
      assertEquals(expires, p.expiresAtMs());
      assertTrue(
          SeamCrypto.verifyVoterPop(
              target(c), p.voterAid(), digest, issued, expires, entry(c), p.signature()),
          n + ": verifies");
      assertTrue(
          SeamCrypto.verifyVoterPop(
              target(c),
              p.voterAid(),
              digest,
              issued,
              expires,
              eb,
              HEX.parseHex((String) c.get("signature_hex"))),
          n + ": the vector's signature verifies");
    }
  }

  @Test
  void theCrossPortBasicSignatureIsThePythonGeneratorsBytes() throws Exception {
    Map<String, Object> c = byName("basic");
    SeamCrypto.VoterPopProof p =
        SeamCrypto.signVoterPop(
            seed(c),
            target(c),
            HEX.parseHex((String) c.get("content_digest_hex")),
            HEX.parseHex((String) c.get("entry_bytes_hex")),
            l(c.get("issued_at_ms")),
            l(c.get("expires_at_ms")));
    assertArrayEquals(HEX.parseHex((String) c.get("signature_hex")), p.signature());
  }

  @Test
  void theOtherCasesDifferFromBasic() throws Exception {
    Map<String, Object> basic = byName("basic");
    for (Map<String, Object> c : cases()) {
      String n = (String) c.get("name");
      if (!n.startsWith("other-")) continue;
      assertNotEquals(basic.get("payload_hex"), c.get("payload_hex"), n);
      assertNotEquals(basic.get("signature_hex"), c.get("signature_hex"), n);
    }
    assertEquals(
        byName("features-order-a").get("signature_hex"),
        byName("features-order-b").get("signature_hex"));
  }

  @Test
  void aSignatureDoesNotVerifyForAnotherTarget() throws Exception {
    Map<String, Object> c = byName("basic");
    SeamCrypto.VoterPopTarget t = target(c);
    SeamCrypto.VoterPopTarget other =
        new SeamCrypto.VoterPopTarget(
            t.issuer(), t.tenant(), t.namespace(), "s-other", t.openedAtMillis(), t.audience());
    byte[] sig = HEX.parseHex((String) c.get("signature_hex"));
    byte[] digest = HEX.parseHex((String) c.get("content_digest_hex"));
    long i = l(c.get("issued_at_ms"));
    long x = l(c.get("expires_at_ms"));
    String aid = (String) c.get("voter_aid");
    assertTrue(SeamCrypto.verifyVoterPop(t, aid, digest, i, x, entry(c), sig));
    assertFalse(SeamCrypto.verifyVoterPop(other, aid, digest, i, x, entry(c), sig));
    assertFalse(SeamCrypto.verifyVoterPop(t, aid, digest, i, x + 1, entry(c), sig));
    assertFalse(SeamCrypto.verifyVoterPop(t, "not-an-aid", digest, i, x, entry(c), sig));
    assertFalse(SeamCrypto.verifyVoterPop(t, aid, new byte[31], i, x, entry(c), sig));
    assertFalse(SeamCrypto.verifyVoterPop(t, aid, digest, i, x, entry(c), new byte[63]));
  }

  @Test
  void negativeZeroConfidenceFoldsToPositiveZero() {
    byte[] neg =
        SeamCrypto.voteEntryBytes(new SeamCrypto.VoteEntry("vote", "risk", "p", "v", "", -0.0, null));
    byte[] pos =
        SeamCrypto.voteEntryBytes(new SeamCrypto.VoteEntry("vote", "risk", "p", "v", "", 0.0, null));
    assertArrayEquals(pos, neg);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SeamCrypto.voteEntryBytes(
                new SeamCrypto.VoteEntry("vote", "risk", "p", "v", "", Double.NaN, null)));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SeamCrypto.voteEntryBytes(
                new SeamCrypto.VoteEntry("Vote", "risk", "p", "v", "", null, null)));
  }

  @Test
  void aWindowTheRuntimeMustRefuseIsNeverSigned() throws Exception {
    Map<String, Object> c = byName("basic");
    byte[] digest = HEX.parseHex((String) c.get("content_digest_hex"));
    long[][] bad = {
      {1_000, 999},
      {0, SeamCrypto.VOTER_POP_MAX_LIFETIME_MS + 1},
      {-1L, 0} // 2^64-1 > 0, read unsigned
    };
    for (long[] w : bad) {
      assertThrows(
          IllegalArgumentException.class,
          () -> SeamCrypto.signVoterPop(seed(c), target(c), digest, entry(c), w[0], w[1]),
          w[0] + ".." + w[1]);
    }
    SeamCrypto.signVoterPop(
        seed(c), target(c), digest, entry(c), 0, SeamCrypto.VOTER_POP_MAX_LIFETIME_MS);
    assertThrows(
        IllegalArgumentException.class,
        () -> SeamCrypto.signVoterPop(new byte[31], target(c), digest, entry(c), 0, 1));
  }

  @Test
  void theDefaultWindowIsNowPlusFiveMinutes() throws Exception {
    Map<String, Object> c = byName("basic");
    long before = System.currentTimeMillis();
    SeamCrypto.VoterPopProof p =
        SeamCrypto.signVoterPop(
            seed(c), target(c), HEX.parseHex((String) c.get("content_digest_hex")), entry(c));
    long after = System.currentTimeMillis();
    assertTrue(p.issuedAtMs() >= before && p.issuedAtMs() <= after);
    assertEquals(SeamCrypto.VOTER_POP_DEFAULT_LIFETIME_MS, p.expiresAtMs() - p.issuedAtMs());
  }

  @Test
  @SuppressWarnings("unchecked")
  void theRestFormIsUnpaddedBase64urlWithANumericWindow() throws Exception {
    Map<String, Object> c = byName("basic");
    byte[] sig = HEX.parseHex((String) c.get("signature_hex"));
    SeamCrypto.VoterPopProof p =
        new SeamCrypto.VoterPopProof(
            (String) c.get("voter_aid"), l(c.get("issued_at_ms")), l(c.get("expires_at_ms")), sig);
    Map<String, Object> rest = SeamCrypto.voterPopToRest(p);
    Map<String, Object> pop = (Map<String, Object>) rest.get("pop");
    Map<String, Object> want = new LinkedHashMap<>();
    want.put("voter_aid", c.get("voter_aid"));
    want.put("issued_at_ms", l(c.get("issued_at_ms")));
    want.put("expires_at_ms", l(c.get("expires_at_ms")));
    want.put("signature", java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(sig));
    assertEquals(want, pop);
    assertEquals(List.of("voter_aid", "issued_at_ms", "expires_at_ms", "signature"), List.copyOf(pop.keySet()));
    assertFalse(((String) pop.get("signature")).contains("="));
    assertThrows(
        IllegalArgumentException.class,
        () -> new SeamCrypto.VoterPopProof("a", 1L << 53, 1L << 53, sig).toRest());
    // The record defends its signature bytes.
    byte[] got = p.signature();
    got[0] ^= 1;
    assertArrayEquals(sig, p.signature());
  }

  @Test
  void featuresFrameSortedARepeatedKeyIsRefusedAndThePolicySlotNeeds32Bytes() throws Exception {
    Map<String, Object> a = byName("features-order-a");
    assertEquals(a.get("content_digest_hex"), HEX.formatHex(contentDigest(byName("features-order-b"))));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SeamCrypto.voteContentDigest(
                "m",
                "p",
                "c",
                List.of(),
                List.of(),
                List.of(),
                List.of(new SeamCrypto.Feature("k", "1"), new SeamCrypto.Feature("k", "2")),
                null));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SeamCrypto.voteContentDigest(
                "m",
                "p",
                "c",
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                new SeamCrypto.VotePolicyRef("pol", new byte[31])));
    // Unsigned byte order: "é" (0xC3…) sorts after "z".
    byte[] x =
        SeamCrypto.voteContentDigest(
            "m",
            "p",
            "c",
            List.of(),
            List.of(),
            List.of(),
            List.of(new SeamCrypto.Feature("é", "1"), new SeamCrypto.Feature("z", "2")),
            null);
    byte[] y =
        SeamCrypto.voteContentDigest(
            "m",
            "p",
            "c",
            List.of(),
            List.of(),
            List.of(),
            List.of(new SeamCrypto.Feature("z", "2"), new SeamCrypto.Feature("é", "1")),
            null);
    assertArrayEquals(x, y);
  }

  // ── the sealed record re-check (verifyVoterRecord / verifyCommitmentVoters) ────────────────────

  private static Map<String, Object> tct() throws Exception {
    return m(
        new Gson().fromJson(Files.readString(Path.of("..", "conformance", "vectors.json")), MAP),
        "tct");
  }

  private static List<SeamCrypto.ExplanationEntry> entries() throws Exception {
    return ConformanceTest.commitment(m(m(tct(), "inputs"), "commitment")).explanation();
  }

  private static SeamCrypto.ExplanationEntry vote(List<SeamCrypto.ExplanationEntry> es) {
    for (SeamCrypto.ExplanationEntry e : es) if ("vote".equals(e.kind())) return e;
    throw new AssertionError("no vote");
  }

  private static SeamCrypto.ExplanationEntry withVv(
      SeamCrypto.ExplanationEntry e, SeamCrypto.VoterVerification vv) {
    return new SeamCrypto.ExplanationEntry(
        e.kind(),
        e.participant(),
        e.proposalId(),
        e.value(),
        e.reason(),
        e.confidence(),
        e.rationaleRef(),
        vv);
  }

  private static List<SeamCrypto.ExplanationEntry> swapVote(
      List<SeamCrypto.ExplanationEntry> es, SeamCrypto.ExplanationEntry replacement) {
    List<SeamCrypto.ExplanationEntry> out = new ArrayList<>();
    SeamCrypto.ExplanationEntry v = vote(es);
    for (SeamCrypto.ExplanationEntry e : es) out.add(e == v ? replacement : e);
    return out;
  }

  private static SeamCrypto.VoterVerification vvWith(
      SeamCrypto.VoterVerification v, String method, long acceptedAtMs) {
    return new SeamCrypto.VoterVerification(
        method,
        v.principal(),
        v.contentDigest(),
        v.issuedAtMs(),
        v.expiresAtMs(),
        v.signature(),
        v.signerCertificate(),
        v.tenant(),
        v.namespace(),
        v.sessionId(),
        v.openedAtMillis(),
        v.issuer(),
        v.audience(),
        acceptedAtMs);
  }

  @Test
  void theConformanceVotesSealedRecordReVerifiesAndTheCommitmentCheckPasses() throws Exception {
    List<SeamCrypto.ExplanationEntry> es = entries();
    String issuer = (String) tct().get("issuer_aid");
    SeamCrypto.ExplanationEntry v = vote(es);
    assertTrue(v.voterVerification() != null);
    assertTrue(SeamCrypto.verifyVoterRecord(v));
    assertTrue(SeamCrypto.verifyCommitmentVoters(es, issuer));
    SeamCrypto.VoterVerification vv = v.voterVerification();
    assertTrue(
        SeamCrypto.verifyCommitmentVoters(
            es, issuer, new SeamCrypto.VoterDecisionRef(vv.tenant(), vv.sessionId())));
  }

  @Test
  void theCommitmentLevelVoterCheckFailsClosed() throws Exception {
    List<SeamCrypto.ExplanationEntry> es = entries();
    String issuer = (String) tct().get("issuer_aid");
    SeamCrypto.ExplanationEntry v = vote(es);
    SeamCrypto.VoterVerification vv = v.voterVerification();
    List<SeamCrypto.ExplanationEntry> evalWithRecord = new ArrayList<>();
    for (SeamCrypto.ExplanationEntry e : es) {
      evalWithRecord.add("evaluation".equals(e.kind()) ? withVv(e, vv) : e);
    }
    assertTrue(
        es.stream().anyMatch(e -> "evaluation".equals(e.kind())),
        "the vector must carry an evaluation for the evaluation-with-record case");
    SeamCrypto.ExplanationEntry tampered =
        new SeamCrypto.ExplanationEntry(
            v.kind(),
            v.participant(),
            v.proposalId(),
            v.value(),
            v.reason() + "!",
            v.confidence(),
            v.rationaleRef(),
            vv);
    Object[][] cases = {
      {"another pinned issuer", es, "aid:pubkey:ed25519:" + "A".repeat(43), null},
      {
        "another decision's session",
        es,
        issuer,
        new SeamCrypto.VoterDecisionRef(vv.tenant(), "s-other")
      },
      {"a vote without its record", swapVote(es, withVv(v, null)), issuer, null},
      {"a tampered reason", swapVote(es, tampered), issuer, null},
      {"an evaluation with a record", evalWithRecord, issuer, null},
      {
        "a record outside its window",
        swapVote(es, withVv(v, vvWith(vv, "pop", vv.expiresAtMs() + 1))),
        issuer,
        null
      },
      {
        "a non-pop method",
        swapVote(es, withVv(v, vvWith(vv, "cp_signed", vv.acceptedAtMs()))),
        issuer,
        null
      },
    };
    for (Object[] c : cases) {
      @SuppressWarnings("unchecked")
      List<SeamCrypto.ExplanationEntry> list = (List<SeamCrypto.ExplanationEntry>) c[1];
      assertFalse(
          SeamCrypto.verifyCommitmentVoters(
              list, (String) c[2], (SeamCrypto.VoterDecisionRef) c[3]),
          (String) c[0]);
    }
  }
}
