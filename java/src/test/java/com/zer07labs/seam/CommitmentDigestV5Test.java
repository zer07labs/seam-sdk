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
import org.junit.jupiter.api.Test;

/**
 * {@code seam-commitment-digest:v5} + {@code seam-explanation-digest:v2} against the runtime's
 * reference vectors ({@code conformance/commitment_digest_v5_signed_vector.json}, and the slot vector
 * {@code conformance/commitment_digest_v5_vector.json}). Conforming iff every digest
 * is reproduced and the signed case verifies against the issuer AID. NO bless mode. Also pins the
 * self-attestation TCT shape {@code verifyTct} accepts, and nothing beside it.
 */
class CommitmentDigestV5Test {
  private static final Type MAP = new TypeToken<Map<String, Object>>() {}.getType();
  private static final long NOW_S = 1_700_000_001L;
  private static final HexFormat HEX = HexFormat.of();

  private static Map<String, Object> vector() throws Exception {
    String raw =
        Files.readString(Path.of("..", "conformance", "commitment_digest_v5_signed_vector.json"));
    return new Gson().fromJson(raw, MAP);
  }

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> slotCases() throws Exception {
    String raw = Files.readString(Path.of("..", "conformance", "commitment_digest_v5_vector.json"));
    Map<String, Object> v = new Gson().fromJson(raw, MAP);
    assertEquals(SeamCrypto.COMMITMENT_DIGEST_DOMAIN, v.get("commitment_digest_domain"));
    return (List<Map<String, Object>>) v.get("cases");
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

  /**
   * The case's commitment, with its field-9/10 slots (case-level hex, {@code null} when absent) and
   * field 11 (on the commitment in the signed vector, case-level hex in the slot vector).
   */
  @SuppressWarnings("unchecked")
  private static SeamCrypto.Commitment commitmentOf(Map<String, Object> k) {
    SeamCrypto.Commitment b = ConformanceTest.commitment((Map<String, Object>) k.get("commitment"));
    byte[] doc = ConformanceTest.vectorBytes(k, "governing_doc_sha256");
    return withSlots(
        b, ConformanceTest.vectorBytes(k, "selection_digest"),
        ConformanceTest.vectorBytes(k, "certificate_digest"),
        doc != null ? doc : b.governingDocSha256());
  }

  private static SeamCrypto.Commitment withSlots(
      SeamCrypto.Commitment b, byte[] selection, byte[] certificate) {
    return withSlots(b, selection, certificate, b.governingDocSha256());
  }

  private static SeamCrypto.Commitment withSlots(
      SeamCrypto.Commitment b, byte[] selection, byte[] certificate, byte[] doc) {
    return new SeamCrypto.Commitment(
        b.id(), b.action(), b.authority(), b.supersedes(), b.authMethod(), b.trustBasis(),
        b.committer(), b.explanationDigest(), b.explanation(), selection, certificate, doc);
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
        b.committer(), published, entries, b.selectionDigest(), b.certificateDigest(),
        b.governingDocSha256());
  }

  @Test
  void everyCaseDigestIsByteExact() throws Exception {
    assertEquals(7, cases().size());
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
        "cabe83af912ea38ef4525f5a7d8580b4c4e217417edc0c93f936d2c18c4fd8f5",
        HEX.formatHex(SeamCrypto.explanationDigest(List.of())));
  }

  @Test
  void neitherEntriesNorDigestIsTheEmptyExplanation() throws Exception {
    SeamCrypto.Commitment c = commitmentOf(caseNamed("all_empty"));
    assertEquals(
        "f31f8081790860a42529c30c4b75626213c6ad36b7c797ba172a2246eab41207",
        SeamCrypto.seamCommitmentDigest(withEntries(c, null, null)));
  }

  /** The supersedes presence byte: absent supersedes and present-empty supersedes are different digests. */
  @Test
  void emptyAndAbsentSupersedesDiffer() throws Exception {
    SeamCrypto.Commitment absent = commitmentOf(caseNamed("all_empty"));
    SeamCrypto.Commitment empty = commitmentOf(caseNamed("empty_supersedes"));
    assertEquals(null, absent.supersedes());
    assertEquals("", empty.supersedes());
    assertNotEquals(
        SeamCrypto.seamCommitmentDigest(absent), SeamCrypto.seamCommitmentDigest(empty));
    assertEquals(
        "9bf7e384a2d8b003c1cb5669b8198dcd5784401797d0897586baa87afeba4ce3",
        SeamCrypto.seamCommitmentDigest(empty));
  }

  /** Fields 9/10: each slot is bound, the two are not interchangeable, and a bad length is refused. */
  @Test
  void selectionAndCertificateSlots() throws Exception {
    SeamCrypto.Commitment none = commitmentOf(caseNamed("all_empty"));
    SeamCrypto.Commitment sel = commitmentOf(caseNamed("selection_present"));
    SeamCrypto.Commitment cert = commitmentOf(caseNamed("certificate_present"));
    SeamCrypto.Commitment both = commitmentOf(caseNamed("both_present"));
    assertEquals(null, none.selectionDigest());
    assertEquals(null, none.certificateDigest());
    java.util.Set<String> digests =
        new java.util.HashSet<>(
            List.of(
                SeamCrypto.seamCommitmentDigest(none), SeamCrypto.seamCommitmentDigest(sel),
                SeamCrypto.seamCommitmentDigest(cert), SeamCrypto.seamCommitmentDigest(both)));
    assertEquals(4, digests.size());
    // The same 32 bytes in the other slot is a different digest.
    assertNotEquals(
        SeamCrypto.seamCommitmentDigest(sel),
        SeamCrypto.seamCommitmentDigest(withSlots(sel, null, sel.selectionDigest())));
    for (int len : new int[] {0, 31, 33}) {
      byte[] bad = new byte[len];
      assertThrows(
          IllegalArgumentException.class,
          () -> SeamCrypto.seamCommitmentDigest(withSlots(none, bad, null)), "selection " + len);
      assertThrows(
          IllegalArgumentException.class,
          () -> SeamCrypto.seamCommitmentDigest(withSlots(none, null, bad)), "certificate " + len);
      assertThrows(
          IllegalArgumentException.class,
          () -> SeamCrypto.seamCommitmentDigest(withSlots(none, null, null, bad)),
          "governing_doc_sha256 " + len);
    }
  }

  /**
   * The v5 slot vector (generated independently of the runtime): every digest reproduced, from the
   * published explanation digest alone. Its {@code governing_trailer_refusals} are not exercised: they
   * pin the runtime's 0x06 trailer decoder, and this SDK never decodes sealed trailers.
   */
  @Test
  void everySlotVectorCaseIsByteExact() throws Exception {
    List<Map<String, Object>> ks = slotCases();
    assertEquals(7, ks.size());
    for (Map<String, Object> k : ks) {
      assertEquals(
          k.get("commitment_digest"), SeamCrypto.seamCommitmentDigest(commitmentOf(k)),
          (String) k.get("name"));
    }
  }

  /** Field 11: the governed signed case is bound to its document digest, and absent is not zero. */
  @Test
  void governingDocumentIsBound() throws Exception {
    SeamCrypto.Commitment governed = commitmentOf(caseNamed("populated_signed"));
    SeamCrypto.Commitment ungoverned = commitmentOf(caseNamed("populated_signed_ungoverned"));
    assertEquals(32, governed.governingDocSha256().length);
    assertEquals(null, ungoverned.governingDocSha256());
    SeamCrypto.Commitment none = commitmentOf(caseNamed("all_empty"));
    assertNotEquals(
        SeamCrypto.seamCommitmentDigest(none),
        SeamCrypto.seamCommitmentDigest(withSlots(none, null, null, new byte[32])));
    // Dropping field 11 from the governed case breaks its signature.
    SeamCrypto.Commitment stripped = withSlots(governed, null, null, null);
    assertFalse(
        SeamCrypto.verifyTct(
            (String) vector().get("issuer_aid"),
            signedArtifact(caseNamed("populated_signed")),
            stripped,
            NOW_S));
    // #420: a served Gate block or env has no v5 meaning, so the same valid v5 TCT refuses.
    String iss = (String) vector().get("issuer_aid");
    String jws = signedArtifact(caseNamed("populated_signed"));
    for (SeamCrypto.Commitment bad :
        List.of(withServed(governed, new byte[] {1}, null), withServed(governed, null, "live"))) {
      assertFalse(SeamCrypto.verifyTct(iss, jws, bad, NOW_S));
    }
  }

  private static SeamCrypto.Commitment withServed(SeamCrypto.Commitment b, byte[] gateBody, String env) {
    return new SeamCrypto.Commitment(
        b.id(), b.action(), b.authority(), b.supersedes(), b.authMethod(), b.trustBasis(),
        b.committer(), b.explanationDigest(), b.explanation(), b.selectionDigest(),
        b.certificateDigest(), b.governingDocSha256(), b.trailers(), gateBody, env);
  }

  /** A voter record with an unknown method, or a content digest that is not 32 bytes, is refused. */
  @Test
  void malformedVoterRecordIsRefused() throws Exception {
    SeamCrypto.Commitment c = commitmentOf(caseNamed("populated_signed"));
    SeamCrypto.ExplanationEntry e = c.explanation().get(3);
    SeamCrypto.VoterVerification v = e.voterVerification();
    assertEquals("pop", v.method());
    for (String method : new String[] {"POP", "VOTER_VERIFICATION_POP", "unspecified", "", null}) {
      SeamCrypto.VoterVerification bad =
          new SeamCrypto.VoterVerification(
              method, v.principal(), v.contentDigest(), v.issuedAtMs(), v.expiresAtMs(),
              v.signature(), v.signerCertificate(), v.tenant(), v.namespace(), v.sessionId(),
              v.openedAtMillis(), v.issuer(), v.audience(), v.acceptedAtMs());
      assertThrows(
          IllegalArgumentException.class,
          () -> SeamCrypto.explanationDigest(List.of(replaceVv(e, bad))),
          "method " + method);
    }
    for (byte[] digest : new byte[][] {null, new byte[0], new byte[31], new byte[33]}) {
      SeamCrypto.VoterVerification bad =
          new SeamCrypto.VoterVerification(
              v.method(), v.principal(), digest, v.issuedAtMs(), v.expiresAtMs(),
              v.signature(), v.signerCertificate(), v.tenant(), v.namespace(), v.sessionId(),
              v.openedAtMillis(), v.issuer(), v.audience(), v.acceptedAtMs());
      assertThrows(
          IllegalArgumentException.class,
          () -> SeamCrypto.explanationDigest(List.of(replaceVv(e, bad))));
    }
    // cp_signed is a known word (declared, not served): it frames, and differs from pop.
    SeamCrypto.VoterVerification cp =
        new SeamCrypto.VoterVerification(
            "cp_signed", v.principal(), v.contentDigest(), v.issuedAtMs(), v.expiresAtMs(),
            v.signature(), v.signerCertificate(), v.tenant(), v.namespace(), v.sessionId(),
            v.openedAtMillis(), v.issuer(), v.audience(), v.acceptedAtMs());
    assertNotEquals(
        HEX.formatHex(SeamCrypto.explanationDigest(List.of(e))),
        HEX.formatHex(SeamCrypto.explanationDigest(List.of(replaceVv(e, cp)))));
  }

  private static SeamCrypto.ExplanationEntry replaceVv(
      SeamCrypto.ExplanationEntry e, SeamCrypto.VoterVerification v) {
    return new SeamCrypto.ExplanationEntry(
        e.kind(), e.participant(), e.proposalId(), e.value(), e.reason(), e.confidence(),
        e.rationaleRef(), v);
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

  /**
   * S-4: the token is signed by the test seal key ({@link SealKeyTokens#SEAL_SEED}); the issuer seed
   * only certifies it (see {@link #ext}).
   */
  private static String sign(String seedHex, String payloadJson) {
    return SealKeyTokens.jws(SealKeyTokens.SEAL_SEED, payloadJson);
  }

  /** The tct block's issuer AID; the certificate names it. */
  private static String issuerOf(String seedHex) {
    return "aid:pubkey:" + b64(SealKeyTokens.pub(HEX.parseHex(seedHex)));
  }

  /** {@code ext}: the statement plus the seal-key certificate member, under the tct block's issuer. */
  private static Map<String, Object> ext(Object statement, String seedHex) {
    Map<String, Object> e = new LinkedHashMap<>();
    e.put(SeamCrypto.COMMITMENT_EXT_NAMESPACE, statement);
    e.put(
        SeamCrypto.SEAL_KEY_CERT_EXT_KEY,
        SealKeyTokens.member(HEX.parseHex(seedHex), issuerOf(seedHex)));
    return e;
  }

  private static String certJson(String seedHex) {
    return new Gson().toJson(SealKeyTokens.member(HEX.parseHex(seedHex), issuerOf(seedHex)));
  }

  private static Map<String, Object> statement(String digest) {
    Map<String, Object> st = new LinkedHashMap<>();
    st.put("type", SeamCrypto.COMMITMENT_STATEMENT);
    st.put("commitment_digest", digest);
    return st;
  }

  /** The seal-key payload: iss/sub/aud are the SEAL AID; the pinned issuer only certifies. */
  private static Map<String, Object> payload(String seedHex, String digest) {
    Map<String, Object> p = SealKeyTokens.claims(SealKeyTokens.SEAL_SEED, SealKeyTokens.IAT);
    p.put("exp", 4_853_600_000L);
    p.put("grants", List.of(SeamCrypto.ATTESTATION_GRANT));
    p.put("ext", ext(statement(digest), seedHex));
    return p;
  }

  private static Map<String, Object> withExtra(Map<String, Object> e) {
    e.put("com.example", Map.of());
    return e;
  }

  @Test
  void wellFormedSelfAttestationVerifies() throws Exception {
    Map<String, Object> t = tctBlock();
    SeamCrypto.Commitment c = tctCommitment(t);
    String iss = (String) t.get("issuer_aid");
    String digest = SeamCrypto.seamCommitmentDigest(c);
    assertTrue(SeamCrypto.verifyTct(iss, sign(seedHex(t), new Gson().toJson(payload(seedHex(t), digest))), c, NOW_S));
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
            withExtra(ext(statement(digest), seedHex(t)))));
    mutations.put(
        "wrong type",
        p -> {
          Map<String, Object> st = statement(digest);
          st.put("type", "seam:other");
          p.put("ext", ext(st, seedHex(t)));
        });
    mutations.put(
        "extra statement field",
        p -> {
          Map<String, Object> st = statement(digest);
          st.put("x", "y");
          p.put("ext", ext(st, seedHex(t)));
        });
    mutations.put(
        "uppercase digest",
        p -> p.put("ext", ext(statement(digest.toUpperCase()), seedHex(t))));
    mutations.put(
        "wrong digest",
        p -> p.put("ext", ext(statement("0".repeat(64)), seedHex(t))));

    for (Map.Entry<String, Consumer<Map<String, Object>>> m : mutations.entrySet()) {
      Map<String, Object> p = payload(seedHex(t), digest);
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
    String seal = SealKeyTokens.sealAid(SealKeyTokens.SEAL_SEED);
    String cert = ",\"com.zer07labs.seam.seal-key-cert\":" + certJson(seedHex(t));
    String head =
        "{\"iss\":\"" + seal + "\",\"sub\":\"" + seal + "\",\"aud\":\"" + seal
            + "\",\"cnf\":{\"jkt\":\"" + SealKeyTokens.jkt(SealKeyTokens.pub(SealKeyTokens.SEAL_SEED))
            + "\"},\"iat\":" + SealKeyTokens.IAT
            + ",\"exp\":4853600000,\"grants\":[\"aitp.attestation\"],";
    String good =
        "\"ext\":{\"com.zer07labs.seam\":{\"type\":\"seam:commitment\",\"commitment_digest\":\""
            + digest + "\"}" + cert + "}}";
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
                + digest + "\"}" + cert + "}}",
            "duplicate statement key",
            "\"ext\":{\"com.zer07labs.seam\":{\"type\":\"seam:commitment\",\"commitment_digest\":\""
                + zeros + "\",\"commitment_digest\":\"" + digest + "\"}" + cert + "}}",
            "duplicate ext",
            "\"ext\":{\"com.zer07labs.seam\":" + decoy + cert + "}," + good);
    for (Map.Entry<String, String> b : bodies.entrySet()) {
      assertFalse(
          SeamCrypto.verifyTct(iss, sign(seedHex(t), head + b.getValue()), c, NOW_S),
          b.getKey() + " must be refused");
    }
  }
}
