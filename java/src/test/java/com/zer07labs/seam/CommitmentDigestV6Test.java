package com.zer07labs.seam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.zer07labs.seam.SeamCrypto.CommitmentDigestFields;
import com.zer07labs.seam.SeamCrypto.CommitmentTrailers;
import com.zer07labs.seam.SeamCrypto.CommitmentVersion;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * {@code seam-commitment-digest:v6} against the runtime's vectors ({@code
 * conformance/commitment_digest_v6_vector.json} and {@code
 * conformance/commitment_digest_v6_signed_vector.json}): every row of every section. Refusal rows
 * assert the refusal only, never the rule name (the name is advisory, spec §Refusal rules). NO bless
 * mode.
 */
class CommitmentDigestV6Test {
  private static final Type MAP = new TypeToken<Map<String, Object>>() {}.getType();
  private static final HexFormat HEX = HexFormat.of();
  private static final long NOW_S = 1_767_225_601L;

  static Map<String, Object> load(String file) throws Exception {
    return new Gson().fromJson(Files.readString(Path.of("..", "conformance", file)), MAP);
  }

  @SuppressWarnings("unchecked")
  static List<Map<String, Object>> rows(Map<String, Object> v, String section) {
    List<Map<String, Object>> out = (List<Map<String, Object>>) v.get(section);
    assertFalse(out == null || out.isEmpty(), "section " + section + " is empty");
    return out;
  }

  private static byte[] hex(Object s) {
    return s == null ? null : HEX.parseHex((String) s);
  }

  private static String hex(byte[] b) {
    return b == null ? null : HEX.formatHex(b);
  }

  private static Map<String, Object> named(List<Map<String, Object>> rows, String name) {
    for (Map<String, Object> r : rows) if (name.equals(r.get("name"))) return r;
    throw new AssertionError("no row " + name);
  }

  @SuppressWarnings("unchecked")
  private static SeamCrypto.Commitment base(Map<String, Object> k) {
    return ConformanceTest.commitment((Map<String, Object>) k.get("commitment"));
  }

  private static SeamCrypto.Commitment withTrailers(SeamCrypto.Commitment b, byte[] trailers) {
    return new SeamCrypto.Commitment(
        b.id(), b.action(), b.authority(), b.supersedes(), b.authMethod(), b.trustBasis(),
        b.committer(), b.explanationDigest(), b.explanation(), b.selectionDigest(),
        b.certificateDigest(), b.governingDocSha256(), trailers);
  }

  /** The case-level field inputs of a {@code digest_only} case. */
  private static CommitmentDigestFields fields(Map<String, Object> k) {
    return new CommitmentDigestFields(
        hex(k.get("selection_digest")),
        hex(k.get("gate_digest")),
        hex(k.get("governing_doc_sha256")),
        (String) k.get("env"));
  }

  @Test
  void everyCaseReproduces() throws Exception {
    Map<String, Object> v = load("commitment_digest_v6_vector.json");
    assertEquals(SeamCrypto.COMMITMENT_DIGEST_DOMAIN_V6, v.get("commitment_digest_domain"));
    assertEquals(SeamCrypto.GATE_DIGEST_DOMAIN, v.get("gate_digest_domain"));
    List<Map<String, Object>> cases = rows(v, "cases");
    assertEquals(15, cases.size());
    for (Map<String, Object> k : cases) {
      String name = (String) k.get("name");
      SeamCrypto.Commitment c = base(k);
      CommitmentDigestFields f;
      if (Boolean.TRUE.equals(k.get("digest_only"))) {
        // Fields 9-12 are digest-function inputs only; there are no trailers to derive them from.
        assertNull(k.get("trailers"), name);
        f = fields(k);
        Object v5 = k.get("v5_commitment_digest");
        if (v5 != null) {
          assertEquals(v5, SeamCrypto.commitmentDigest(CommitmentVersion.V5, c, f), name + " v5");
        }
      } else {
        CommitmentTrailers t =
            SeamCrypto.decodeCommitmentTrailers(hex(k.get("trailers")), CommitmentVersion.V6);
        assertEquals(k.get("field_10"), hex(t.field10()), name);
        assertEquals(k.get("field_11"), hex(t.field11()), name);
        assertEquals(k.get("field_12"), hex(t.field12()), name);
        assertEquals(k.get("gate_digest"), hex(t.gateDigest()), name);
        assertEquals(k.get("governing_doc_sha256"), hex(t.governingDocSha256()), name);
        assertEquals(k.get("env"), t.env(), name);
        f =
            new CommitmentDigestFields(
                hex(k.get("selection_digest")), t.gateDigest(), t.governingDocSha256(), t.env());
      }
      assertEquals(
          k.get("commitment_digest"), SeamCrypto.commitmentDigest(CommitmentVersion.V6, c, f), name);
    }
  }

  @Test
  void digestInputRefusals() throws Exception {
    Map<String, Object> v = load("commitment_digest_v6_vector.json");
    List<Map<String, Object>> cases = rows(v, "cases");
    List<Map<String, Object>> refusals = rows(v, "digest_input_refusals");
    assertEquals(10, refusals.size());
    for (Map<String, Object> r : refusals) {
      assertEquals("v6", r.get("scheme"));
      Map<String, Object> k = named(cases, (String) r.get("base_case"));
      CommitmentDigestFields b = fields(k);
      @SuppressWarnings("unchecked")
      Map<String, Object> o = (Map<String, Object>) r.getOrDefault("override", Map.of());
      CommitmentDigestFields f =
          new CommitmentDigestFields(
              o.containsKey("selection_digest") ? hex(o.get("selection_digest")) : b.selectionDigest(),
              o.containsKey("gate_digest") ? hex(o.get("gate_digest")) : b.gateDigest(),
              o.containsKey("governing_doc_sha256")
                  ? hex(o.get("governing_doc_sha256"))
                  : b.governingDocSha256(),
              r.containsKey("env") ? (String) r.get("env") : b.env());
      assertThrows(
          IllegalArgumentException.class,
          () -> SeamCrypto.commitmentDigest(CommitmentVersion.V6, base(k), f),
          (String) r.get("name"));
    }
  }

  @Test
  void governingTrailerRefusalsUnderV6() throws Exception {
    List<Map<String, Object>> refusals =
        rows(load("commitment_digest_v6_vector.json"), "governing_trailer_refusals");
    assertEquals(17, refusals.size());
    for (Map<String, Object> r : refusals) {
      assertEquals("v6", r.get("scheme"));
      byte[] t = hex(r.get("trailers"));
      assertThrows(
          IllegalArgumentException.class,
          () -> SeamCrypto.decodeCommitmentTrailers(t, CommitmentVersion.V6),
          (String) r.get("name"));
    }
  }

  @Test
  void frameLengthOfMaxBe64RefusesAsTruncated() throws Exception {
    Map<String, Object> r =
        named(
            rows(load("commitment_digest_v6_vector.json"), "governing_trailer_refusals"),
            "env_frame_length_max_be64");
    SeamCrypto.CommitmentRefusal e =
        assertThrows(
            SeamCrypto.CommitmentRefusal.class,
            () -> SeamCrypto.decodeCommitmentTrailers(hex(r.get("trailers")), CommitmentVersion.V6));
    // Pinned here (not in the generic loop) because a signed read of 2^64-1 is -1, and the classic
    // bug is to wrap rather than refuse; the rule is the only applicable one for this input.
    assertEquals("governing_body_truncated", e.rule());
  }

  @Test
  void v5Refusals() throws Exception {
    Map<String, Object> v = load("commitment_digest_v6_vector.json");
    List<Map<String, Object>> cases = rows(v, "cases");
    List<Map<String, Object>> refusals = rows(v, "v5_refusals");
    assertEquals(6, refusals.size());
    for (Map<String, Object> r : refusals) {
      assertEquals("v5", r.get("scheme"));
      String name = (String) r.get("name");
      if (r.get("trailers") != null) {
        byte[] t = hex(r.get("trailers"));
        assertThrows(
            IllegalArgumentException.class,
            () -> SeamCrypto.decodeCommitmentTrailers(t, CommitmentVersion.V5),
            name);
      } else {
        Map<String, Object> k = named(cases, (String) r.get("base_case"));
        CommitmentDigestFields b = fields(k);
        CommitmentDigestFields f =
            new CommitmentDigestFields(
                b.selectionDigest(), b.gateDigest(), b.governingDocSha256(), (String) r.get("env"));
        assertThrows(
            IllegalArgumentException.class,
            () -> SeamCrypto.commitmentDigest(CommitmentVersion.V5, base(k), f),
            name);
      }
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void schemeFreeDecode() throws Exception {
    List<Map<String, Object>> rows = rows(load("commitment_digest_v6_vector.json"), "scheme_free");
    assertEquals(7, rows.size());
    for (Map<String, Object> r : rows) {
      assertNull(r.get("scheme"));
      String name = (String) r.get("name");
      byte[] t = hex(r.get("trailers"));
      if ("refused".equals(r.get("expect"))) {
        assertThrows(
            IllegalArgumentException.class,
            () -> SeamCrypto.decodeCommitmentTrailers(t, null),
            name);
        continue;
      }
      Map<String, Object> e = (Map<String, Object>) r.get("expect");
      CommitmentTrailers d = SeamCrypto.decodeCommitmentTrailers(t, null);
      assertEquals(e.get("field_10"), hex(d.field10()), name);
      assertEquals(e.get("field_11"), hex(d.field11()), name);
      if (e.containsKey("field_12")) assertEquals(e.get("field_12"), hex(d.field12()), name);
      Object want = e.get("governing_body_version");
      assertEquals(
          want == null ? null : ((Number) want).intValue(), d.governingBodyVersion(), name);
    }
  }

  @Test
  void statementSelection() throws Exception {
    List<Map<String, Object>> rows =
        rows(load("commitment_digest_v6_vector.json"), "statement_selection");
    assertEquals(29, rows.size());
    for (Map<String, Object> r : rows) {
      String name = (String) r.get("name");
      Object expect = r.get("expect");
      boolean viaExt = r.containsKey("ext");
      String raw = (String) (viaExt ? r.get("ext") : r.get("statement"));
      if ("refused".equals(expect)) {
        assertThrows(
            SeamCrypto.CommitmentRefusal.class,
            () -> {
              if (viaExt) SeamCrypto.selectCommitmentVersion(raw);
              else SeamCrypto.selectStatementVersion(raw);
            },
            name);
      } else {
        CommitmentVersion got =
            viaExt
                ? SeamCrypto.selectCommitmentVersion(raw)
                : SeamCrypto.selectStatementVersion(raw);
        assertEquals(expect, got.name().toLowerCase(), name);
      }
    }
  }

  @SuppressWarnings("unchecked")
  private static SeamCrypto.Commitment signedCommitment(Map<String, Object> k) {
    return withTrailers(
        ConformanceTest.commitment((Map<String, Object>) k.get("commitment")),
        hex(k.get("trailers")));
  }

  @Test
  void signedCasesVerify() throws Exception {
    Map<String, Object> v = load("commitment_digest_v6_signed_vector.json");
    String issuer = (String) v.get("issuer_aid");
    List<Map<String, Object>> cases = rows(v, "cases");
    assertEquals(3, cases.size());
    for (Map<String, Object> k : cases) {
      String name = (String) k.get("name");
      assertEquals("v6", k.get("expect"), name);
      assertEquals(
          CommitmentVersion.V6, SeamCrypto.selectCommitmentVersion((String) k.get("ext")), name);
      SeamCrypto.Commitment c = signedCommitment(k);
      CommitmentTrailers t =
          SeamCrypto.decodeCommitmentTrailers(c.trailers(), CommitmentVersion.V6);
      assertEquals(k.get("field_10"), hex(t.field10()), name);
      assertEquals(k.get("field_11"), hex(t.field11()), name);
      assertEquals(k.get("field_12"), hex(t.field12()), name);
      assertEquals(
          k.get("commitment_digest"),
          SeamCrypto.commitmentDigest(
              CommitmentVersion.V6,
              c,
              new CommitmentDigestFields(null, t.gateDigest(), t.governingDocSha256(), t.env())),
          name);
      assertTrue(SeamCrypto.verifyTct(issuer, (String) k.get("signed_artifact"), c, NOW_S), name);
      // The same TCT over the commitment with neither trailers nor a projection recomputes a
      // different v6 digest.
      if (!((String) k.get("trailers")).isEmpty()) {
        SeamCrypto.Commitment bare = served(c, null, null, null);
        assertFalse(
            SeamCrypto.verifyTct(issuer, (String) k.get("signed_artifact"), bare, NOW_S), name);
      }
    }
  }

  /** {@code b} as a served commitment: no raw trailers, the given projection beside it (#420). */
  private static SeamCrypto.Commitment served(
      SeamCrypto.Commitment b, byte[] gateBody, byte[] doc, String env) {
    return new SeamCrypto.Commitment(
        b.id(), b.action(), b.authority(), b.supersedes(), b.authMethod(), b.trustBasis(),
        b.committer(), b.explanationDigest(), b.explanation(), b.selectionDigest(),
        b.certificateDigest(), doc, null, gateBody, env);
  }

  @Test
  void servedCommitmentsVerify() throws Exception {
    Map<String, Object> v = load("commitment_digest_v6_signed_vector.json");
    String issuer = (String) v.get("issuer_aid");
    for (Map<String, Object> k : rows(v, "cases")) {
      String name = (String) k.get("name");
      String jws = (String) k.get("signed_artifact");
      SeamCrypto.Commitment c = signedCommitment(k);
      byte[] raw = c.trailers();
      byte[] gate = null;
      if (raw.length > 0 && raw[0] == 0x05) {
        int n = (raw[1] & 0xff) | (raw[2] & 0xff) << 8 | (raw[3] & 0xff) << 16 | (raw[4] & 0xff) << 24;
        gate = java.util.Arrays.copyOfRange(raw, 5, 5 + n);
      }
      CommitmentTrailers t = SeamCrypto.decodeCommitmentTrailers(raw, CommitmentVersion.V6);
      assertEquals(
          hex(raw),
          hex(SeamCrypto.servedCommitmentTrailers(gate, t.governingDocSha256(), t.env())),
          name + ": the projection rebuilds the trailers");
      SeamCrypto.Commitment s = served(c, gate, t.governingDocSha256(), t.env());
      assertTrue(SeamCrypto.verifyTct(issuer, jws, s, NOW_S), name + ": served");
      if (t.governingDocSha256() != null) {
        String flipped = "live".equals(t.env()) ? "sandbox" : "live";
        assertFalse(
            SeamCrypto.verifyTct(issuer, jws, served(c, gate, t.governingDocSha256(), flipped), NOW_S),
            name + ": flipped env");
        assertFalse(
            SeamCrypto.verifyTct(issuer, jws, served(c, gate, new byte[32], t.env()), NOW_S),
            name + ": wrong doc");
      }
      if (gate != null) {
        assertFalse(
            SeamCrypto.verifyTct(issuer, jws, served(c, null, t.governingDocSha256(), t.env()), NOW_S),
            name + ": gate dropped");
      }
      SeamCrypto.Commitment both =
          new SeamCrypto.Commitment(
              c.id(), c.action(), c.authority(), c.supersedes(), c.authMethod(), c.trustBasis(),
              c.committer(), c.explanationDigest(), c.explanation(), c.selectionDigest(),
              c.certificateDigest(), c.governingDocSha256(), raw, new byte[0], null);
      assertFalse(SeamCrypto.verifyTct(issuer, jws, both, NOW_S), name + ": projection beside trailers");
    }
  }

  @Test
  void servedCommitmentTrailersRefusals() {
    assertEquals(
        "env_without_governing_doc",
        assertThrows(SeamCrypto.CommitmentRefusal.class, () -> SeamCrypto.servedCommitmentTrailers(null, null, "live")).rule());
    assertEquals(
        "slot_length_not_32",
        assertThrows(SeamCrypto.CommitmentRefusal.class, () -> SeamCrypto.servedCommitmentTrailers(null, new byte[31], null)).rule());
    assertEquals(
        "env_not_sandbox_or_live",
        assertThrows(SeamCrypto.CommitmentRefusal.class, () -> SeamCrypto.servedCommitmentTrailers(null, new byte[32], "")).rule());
    assertEquals(
        "env_not_sandbox_or_live",
        assertThrows(SeamCrypto.CommitmentRefusal.class, () -> SeamCrypto.servedCommitmentTrailers(null, new byte[32], "Live")).rule());
  }

  @Test
  void signedNegativesAreRefused() throws Exception {
    Map<String, Object> v = load("commitment_digest_v6_signed_vector.json");
    String issuer = (String) v.get("issuer_aid");
    List<Map<String, Object>> cases = rows(v, "cases");
    List<Map<String, Object>> negatives = rows(v, "negatives");
    assertEquals(5, negatives.size());
    for (Map<String, Object> n : negatives) {
      assertEquals("refused", n.get("expect"));
      SeamCrypto.Commitment c = signedCommitment(named(cases, (String) n.get("over")));
      assertFalse(
          SeamCrypto.verifyTct(issuer, (String) n.get("signed_artifact"), c, NOW_S),
          (String) n.get("name"));
    }
  }

  @Test
  void v5StatementOverEnvCommitmentNeverRetriesUnderV6() throws Exception {
    Map<String, Object> v = load("commitment_digest_v6_signed_vector.json");
    Map<String, Object> n = named(rows(v, "negatives"), "v5_statement_over_env_commitment");
    assertEquals(
        CommitmentVersion.V5, SeamCrypto.selectCommitmentVersion((String) n.get("ext")));
    Map<String, Object> over = named(rows(v, "cases"), (String) n.get("over"));
    byte[] t = hex(over.get("trailers"));
    assertThrows(
        SeamCrypto.CommitmentRefusal.class,
        () -> SeamCrypto.decodeCommitmentTrailers(t, CommitmentVersion.V5));
  }

  @Test
  void v5CommitmentDigestIsUnchangedThroughTheVersionedEntry() throws Exception {
    // A v5 digest through commitmentDigest(V5, ...) equals the original v5 path byte for byte.
    Map<String, Object> v = load("commitment_digest_v6_vector.json");
    for (Map<String, Object> k : rows(v, "cases")) {
      if (!Boolean.TRUE.equals(k.get("digest_only"))) continue;
      CommitmentDigestFields f = fields(k);
      SeamCrypto.Commitment b = base(k);
      SeamCrypto.Commitment slotted =
          new SeamCrypto.Commitment(
              b.id(), b.action(), b.authority(), b.supersedes(), b.authMethod(), b.trustBasis(),
              b.committer(), b.explanationDigest(), b.explanation(), f.selectionDigest(),
              f.gateDigest(), f.governingDocSha256());
      assertEquals(
          SeamCrypto.seamCommitmentDigest(slotted),
          SeamCrypto.commitmentDigest(CommitmentVersion.V5, b, f),
          (String) k.get("name"));
    }
  }

  @Test
  void otherTrailerMarkersAreNotDigestInputs() {
    assertArrayEquals(
        HEX.parseHex("00"),
        SeamCrypto.decodeCommitmentTrailers(new byte[0], CommitmentVersion.V6).field10());
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SeamCrypto.decodeCommitmentTrailers(
                HEX.parseHex("0400000000"), CommitmentVersion.V6));
  }
}
