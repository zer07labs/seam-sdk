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
 * S-4 evidence grade: {@link SeamCrypto#verifyTctSealedAt} requires {@code iat ==
 * floor(sealedAtMs / 1000)}. Pinned by {@code conformance/tct_sealed_at_vector.json} (emitted by
 * {@code scripts/emit_tct_sealed_at_vector.py} over the runtime's byte-identical {@code
 * commitment_digest_v6_signed_vector.json}), the vector every SDK verifier answers. Same rule as
 * seam-verify {@code verify_tct_sealed_at} and the runtime's {@code verify_commitment_sealed_at}
 * (seam-runtime #2031).
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
      assertEquals(want, SeamCrypto.verifyTctSealedAt(issuer, jws, c, 0, arg), name);
      assertEquals(
          want, SeamCrypto.verifyTctSealedAt(issuer, jws, c, 0, null, arg), name + " (selection)");
    }
    assertTrue(names.contains("exact_second_boundary"));
    assertTrue(names.contains("iat_plus_1s_at_boundary"));
    assertTrue(names.contains("iat_minus_1s_at_boundary"));
    assertFalse(SeamCrypto.verifyTctSealedAt(issuer, jws, c, 0, -1L));
  }
}
