package com.zer07labs.seam;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Evidence grade: {@link SeamCrypto#verifyTctSealedAt} requires {@code iat ==
 * floor(sealedAtMs / 1000)} (S-4) and {@code jti == tctJti(decisionId, sealedAtMs)} (seam-runtime
 * 0.127.0 P4). Pinned by {@code conformance/tct_sealed_at_vector.json} (emitted by
 * {@code scripts/emit_tct_sealed_at_vector.py} over the runtime's byte-identical {@code
 * commitment_digest_v6_signed_vector.json}), the vector every SDK verifier answers. Same rule as
 * seam-verify {@code verify_tct_sealed_at} and the runtime's {@code check_commitment_sealed_for}.
 */
class TctSealedAtVectorTest {
  private static final Type MAP = new TypeToken<Map<String, Object>>() {}.getType();
  private static final BigInteger LONG_MAX = BigInteger.valueOf(Long.MAX_VALUE);

  private static Map<String, Object> load(String rel) throws Exception {
    return new Gson().fromJson(Files.readString(Path.of("..", rel)), MAP);
  }

  @Test
  @SuppressWarnings("unchecked")
  void everyCaseAnswersItsExpect() throws Exception {
    Map<String, Object> v = load("conformance/tct_sealed_at_vector.json");
    Map<String, Object> s = load((String) v.get("source"));
    Map<String, Object> k = null;
    for (Map<String, Object> r : (List<Map<String, Object>>) s.get("cases")) {
      if (v.get("over").equals(r.get("name"))) k = r;
    }
    assertTrue(k != null, "no signed case " + v.get("over"));
    String issuer = (String) s.get("issuer_aid");
    String jws = (String) k.get("signed_artifact");
    SeamCrypto.Commitment b =
        ConformanceTest.commitment((Map<String, Object>) k.get("commitment"));
    SeamCrypto.Commitment c =
        new SeamCrypto.Commitment(
            b.id(), b.action(), b.authority(), b.supersedes(), b.authMethod(), b.trustBasis(),
            b.committer(), b.explanationDigest(), b.explanation(), b.selectionDigest(),
            b.certificateDigest(), b.governingDocSha256(),
            HexFormat.of().parseHex((String) k.get("trailers")));
    assertTrue(SeamCrypto.verifyTct(issuer, jws, c, 0), "control");

    Set<String> names = new HashSet<>();
    for (Map<String, Object> row : (List<Map<String, Object>>) v.get("cases")) {
      String name = (String) row.get("name");
      names.add(name);
      boolean want = "verified".equals(row.get("expect"));
      BigInteger ms = new BigInteger((String) row.get("sealed_at_ms"));
      // A uint64 beyond Long.MAX_VALUE arrives in a Java long as its two's-complement (negative)
      // reading, which the verifier refuses: that is the runtime's beyond-i64 refusal.
      long arg = ms.compareTo(LONG_MAX) > 0 ? ms.longValue() : ms.longValueExact();
      String id = (String) row.get("decision_id");
      assertEquals(want, SeamCrypto.verifyTctSealedAt(issuer, jws, c, 0, id, arg), name);
      assertEquals(
          want,
          SeamCrypto.verifyTctSealedAt(issuer, jws, c, 0, null, id, arg),
          name + " (selection)");
    }
    for (String n :
        List.of(
            "exact_second_boundary",
            "last_ms_of_the_second",
            "iat_plus_1s_at_boundary",
            "iat_minus_1s_at_boundary",
            "replayed_onto_another_record",
            "commitment_id_is_not_the_record_id")) {
      assertTrue(names.contains(n), n);
    }
    String id = (String) v.get("decision_id");
    assertFalse(SeamCrypto.verifyTctSealedAt(issuer, jws, c, 0, id, -1L));
    long ok = Long.parseLong(
        (String) ((List<Map<String, Object>>) v.get("cases")).get(0).get("sealed_at_ms"));
    assertTrue(SeamCrypto.verifyTctSealedAt(issuer, jws, c, 0, id, ok), "the verified row");
    assertFalse(SeamCrypto.verifyTctSealedAt(issuer, jws, c, 0, (String) null, ok), "a null id");
  }

  @Test
  @SuppressWarnings("unchecked")
  void theJtiDerivationMatchesTheRuntimeKnownAnswerAndTheToken() throws Exception {
    Map<String, Object> v = load("conformance/tct_sealed_at_vector.json");
    Map<String, Object> kat = (Map<String, Object>) v.get("jti_kat");
    assertEquals(
        kat.get("jti"),
        SeamCrypto.tctJti(
            (String) kat.get("decision_id"), Long.parseLong((String) kat.get("sealed_at_ms"))));
    Map<String, Object> s = load((String) v.get("source"));
    long sealMs = ((Number) s.get("seal_ms")).longValue();
    assertEquals(v.get("jti"), SeamCrypto.tctJti((String) v.get("decision_id"), sealMs));
  }
}
