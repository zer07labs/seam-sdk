package com.zer07labs.seam;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Option selection (runtime 0.90.0, seam-runtime {@code docs/specs/selection-rule.v1.md}) against the
 * runtime's vendored fixture {@code conformance/selection_rule_v1_vectors.json}: the selection block
 * codec, the v5 field 9 it frames, and the {@code proposal} explanation word. This port frames the
 * digest only; the winner recompute ({@code rule_cases}, {@code sealed_cases}) is the Rust verifier's
 * and the Python SDK's, so those groups are not exercised here.
 */
class SelectionV1Test {
  private static final Type MAP = new TypeToken<Map<String, Object>>() {}.getType();
  private static final HexFormat HEX = HexFormat.of();

  private static Map<String, Object> vector() throws Exception {
    return new Gson()
        .fromJson(
            Files.readString(Path.of("..", "conformance", "selection_rule_v1_vectors.json")), MAP);
  }

  @SuppressWarnings("unchecked")
  static SeamCrypto.SelectionBlock block(Map<String, Object> b) {
    List<SeamCrypto.SelectionWeight> weights = new ArrayList<>();
    for (Map<String, Object> w : (List<Map<String, Object>>) b.get("weights")) {
      weights.add(
          new SeamCrypto.SelectionWeight(
              (String) w.get("participant"), ((Number) w.get("weight")).longValue()));
    }
    List<SeamCrypto.SelectionContext> ctx = new ArrayList<>();
    for (Map<String, Object> c : (List<Map<String, Object>>) b.get("context")) {
      ctx.add(
          new SeamCrypto.SelectionContext(
              (String) c.get("ctx_ref"), (String) c.get("content_hash")));
    }
    return new SeamCrypto.SelectionBlock(
        (String) b.get("rule"),
        ((Number) b.get("rule_version")).longValue(),
        ((Number) b.get("default_weight")).longValue(),
        weights,
        (String) b.get("tie"),
        (String) b.get("abstention"),
        ((Number) b.get("min_ballots")).longValue(),
        (String) b.get("policy_version"),
        HEX.parseHex((String) b.get("rules_digest")),
        (List<String>) b.get("participants"),
        (List<String>) b.get("on_behalf_of"),
        ctx,
        (String) b.get("winner_proposal_id"));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> codec() throws Exception {
    return (Map<String, Object>) vector().get("codec");
  }

  @Test
  @SuppressWarnings("unchecked")
  void codecBlockEncodesToTheVectorBodyDigestAndField9() throws Exception {
    Map<String, Object> c = codec();
    byte[] body = SeamCrypto.selectionBody(block((Map<String, Object>) c.get("block")));
    assertEquals(c.get("body"), HEX.formatHex(body));
    assertEquals(422, body.length);
    byte[] d = SeamCrypto.selectionDigest(body);
    assertEquals(c.get("selection_digest"), HEX.formatHex(d));
    assertEquals(c.get("field_9"), "01" + "0000000000000020" + HEX.formatHex(d));
  }

  @Test
  @SuppressWarnings("unchecked")
  void proposalWordExplanationDigestOverTheVerifiedEntries() throws Exception {
    for (Map<String, Object> s : (List<Map<String, Object>>) vector().get("sealed_cases")) {
      if (!"verified".equals(s.get("name"))) continue;
      Map<String, Object> m = new HashMap<>();
      m.put("explanation", s.get("entries"));
      SeamCrypto.Commitment c = ConformanceTest.commitment(m);
      assertEquals(
          "40a4e742ffce841dcb2deb0ee6912c590a7268068117dd593bbd11bb4f76e34c",
          HEX.formatHex(SeamCrypto.explanationDigest(c.explanation())));
      return;
    }
    throw new AssertionError("no verified sealed case");
  }

  @Test
  @SuppressWarnings("unchecked")
  void everyCommitmentDigestV5CaseWithField9FromTheBlock() throws Exception {
    Map<String, Object> v = vector();
    byte[] fromBlock =
        SeamCrypto.selectionDigest(
            SeamCrypto.selectionBody(
                block((Map<String, Object>) ((Map<String, Object>) v.get("codec")).get("block"))));
    List<Map<String, Object>> cases =
        (List<Map<String, Object>>)
            ((Map<String, Object>) v.get("commitment_digest_v5")).get("cases");
    assertEquals(3, cases.size());
    for (Map<String, Object> k : cases) {
      Map<String, Object> cm = new HashMap<>((Map<String, Object>) k.get("commitment"));
      cm.put("explanation_digest", k.get("explanation_digest"));
      SeamCrypto.Commitment b = ConformanceTest.commitment(cm);
      byte[] sel = ConformanceTest.vectorBytes(k, "selection_digest");
      if (sel != null) assertEquals(HEX.formatHex(sel), HEX.formatHex(fromBlock));
      SeamCrypto.Commitment c =
          new SeamCrypto.Commitment(
              b.id(), b.action(), b.authority(), b.supersedes(), b.authMethod(), b.trustBasis(),
              b.committer(), b.explanationDigest(), b.explanation(), sel,
              ConformanceTest.vectorBytes(k, "certificate_digest"),
              ConformanceTest.vectorBytes(k, "governing_doc_sha256"));
      assertEquals(k.get("commitment_digest"), SeamCrypto.seamCommitmentDigest(c), (String) k.get("name"));
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void aBlockTheRuntimeCouldNotHaveSealedIsRefused() throws Exception {
    SeamCrypto.SelectionBlock b = block((Map<String, Object>) codec().get("block"));
    List<SeamCrypto.SelectionBlock> bad =
        List.of(
            with(b, List.of(w("carol", 1), w("bob", 2)), b.rulesDigest(), b.winnerProposalId(), 3),
            with(b, List.of(w("bob", 1), w("bob", 2)), b.rulesDigest(), b.winnerProposalId(), 3),
            with(b, b.weights(), new byte[31], b.winnerProposalId(), 3),
            with(b, b.weights(), b.rulesDigest(), "", 3),
            with(b, b.weights(), b.rulesDigest(), b.winnerProposalId(), 1L << 32),
            with(b, List.of(w("bob", -1)), b.rulesDigest(), b.winnerProposalId(), 3));
    for (SeamCrypto.SelectionBlock x : bad) {
      assertThrows(IllegalArgumentException.class, () -> SeamCrypto.selectionBody(x));
    }
    // Ascending is by UTF-8 bytes: "Z" < "a" < "é".
    SeamCrypto.selectionBody(
        with(b, List.of(w("Z", 1), w("a", 1), w("é", 1)), b.rulesDigest(), b.winnerProposalId(), 3));
  }

  private static SeamCrypto.SelectionWeight w(String p, long n) {
    return new SeamCrypto.SelectionWeight(p, n);
  }

  private static SeamCrypto.SelectionBlock with(
      SeamCrypto.SelectionBlock b,
      List<SeamCrypto.SelectionWeight> weights,
      byte[] rules,
      String winner,
      long minBallots) {
    return new SeamCrypto.SelectionBlock(
        b.rule(), b.ruleVersion(), b.defaultWeight(), weights, b.tie(), b.abstention(), minBallots,
        b.policyVersion(), rules, b.participants(), b.onBehalfOf(), b.context(), winner);
  }
}
