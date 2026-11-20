package com.zer07labs.seam;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Base64;
import java.util.Map;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.jupiter.api.Test;

/**
 * Option selection (runtime 0.90.0, seam-runtime {@code docs/specs/selection-rule.v1.md}) against the
 * runtime's vendored fixture {@code conformance/selection_rule_v1_vectors.json}: the selection block
 * codec, the v5 field 9 it frames, the {@code proposal} explanation word, {@code decide()} over every
 * {@code rule_cases} entry and the verifier's selection steps over every {@code sealed_cases} entry,
 * by expected result name — the same groups, read the same way, as Python's
 * {@code test_selection_rule_v1.py}.
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

  @SuppressWarnings("unchecked")
  static List<SeamCrypto.ExplanationEntry> entries(Object raw) {
    List<SeamCrypto.ExplanationEntry> out = new ArrayList<>();
    for (Map<String, Object> e : (List<Map<String, Object>>) raw) {
      Map<String, Object> vv = (Map<String, Object>) e.get("voter_verification");
      // decide() only asks whether a record is present, so a rule case's stand-in record (which is
      // not a full one) is read leniently; sealed cases carry full records.
      boolean full = vv != null && vv.containsKey("accepted_at_ms");
      Object conf = e.get("confidence");
      out.add(
          new SeamCrypto.ExplanationEntry(
              (String) e.get("kind"),
              (String) e.get("participant"),
              (String) e.get("proposal_id"),
              (String) e.get("value"),
              (String) e.get("reason"),
              conf == null ? null : ((Number) conf).doubleValue(),
              (String) e.get("rationale_ref"),
              vv == null
                  ? null
                  : full
                      ? ConformanceTest.voterVerification(vv)
                      : new SeamCrypto.VoterVerification(
                          (String) vv.get("method"), (String) vv.get("principal"), null, 0, 0,
                          null, null, null, null, null, 0, null, null, 0)));
    }
    return out;
  }

  @Test
  @SuppressWarnings("unchecked")
  void everyRuleCaseThroughDecide() throws Exception {
    List<Map<String, Object>> cases = (List<Map<String, Object>>) vector().get("rule_cases");
    assertEquals(30, cases.size());
    for (Map<String, Object> k : cases) {
      String name = (String) k.get("name");
      SeamCrypto.SelectionDecision got =
          SeamCrypto.decide(block((Map<String, Object>) k.get("record")), entries(k.get("entries")));
      Map<String, Object> want = (Map<String, Object>) k.get("expect");
      assertEquals(want.get("result"), got.result(), name);
      for (Map.Entry<String, Object> f : want.entrySet()) {
        Object v = f.getValue();
        switch (f.getKey()) {
          case "result" -> {}
          case "winner_proposal_id" -> assertEquals(v, got.winnerProposalId(), name);
          case "option" -> assertEquals(v, got.option(), name);
          case "reason" -> assertEquals(v, got.reason(), name);
          case "ballots" -> assertEquals(((Number) v).longValue(), got.ballots(), name);
          case "at" -> {
            if (v == null) assertNull(got.at(), name);
            else assertEquals(((Number) v).intValue(), got.at(), name);
          }
          case "scores" -> {
            List<SeamCrypto.SelectionScore> s = new ArrayList<>();
            for (Map<String, Object> x : (List<Map<String, Object>>) v) {
              s.add(
                  new SeamCrypto.SelectionScore(
                      (String) x.get("proposal_id"), ((Number) x.get("score")).longValue()));
            }
            assertEquals(s, got.scores(), name);
          }
          default -> throw new AssertionError(name + ": unread expect field " + f.getKey());
        }
      }
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void everySealedCaseThroughVerifySelectionByName() throws Exception {
    List<Map<String, Object>> cases = (List<Map<String, Object>>) vector().get("sealed_cases");
    assertEquals(13, cases.size());
    for (Map<String, Object> k : cases) {
      String name = (String) k.get("name");
      SeamCrypto.SelectionResult got =
          SeamCrypto.verifySelection(
              block((Map<String, Object>) k.get("block")),
              entries(k.get("entries")),
              (String) k.get("action"));
      Map<String, Object> want = (Map<String, Object>) k.get("expect");
      assertEquals(want.get("result"), got.result(), name);
      if (want.containsKey("at")) {
        assertEquals(((Number) want.get("at")).intValue(), got.at(), name);
      }
      if (want.containsKey("recomputed")) assertEquals(want.get("recomputed"), got.recomputed(), name);
      if ("verified".equals(want.get("result"))) {
        assertTrue(got.ok(), name);
        assertEquals(want.get("winner_proposal_id"), got.winnerProposalId(), name);
        assertEquals(((Number) want.get("votes_linked")).intValue(), got.votesLinked(), name);
      } else {
        assertFalse(got.ok(), name);
      }
    }
  }

  // ── verifyTct wiring: a block present requires the entries and a verified selection ─────────

  private static final byte[] SEED = new byte[32];
  private static final String ISSUER =
      SeamCrypto.aidFromPubkey(new Ed25519PrivateKeyParameters(SEED, 0).generatePublicKey().getEncoded());

  private static String b64(byte[] b) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  /** A self-issued TCT over {@code c}'s v5 digest, signed by {@link #SEED}. */
  private static String tct(SeamCrypto.Commitment c) {
    String h = b64("{\"alg\":\"EdDSA\",\"typ\":\"aitp-tct+jwt\"}".getBytes(StandardCharsets.UTF_8));
    String p =
        b64(
            ("{\"iss\":\"" + ISSUER + "\",\"sub\":\"" + ISSUER + "\",\"aud\":\"" + ISSUER
                    + "\",\"exp\":9999999999,\"grants\":[\"aitp.attestation\"],"
                    + "\"ext\":{\"com.zer07labs.seam\":{\"type\":\"seam:commitment\","
                    + "\"commitment_digest\":\"" + SeamCrypto.seamCommitmentDigest(c) + "\"}}}")
                .getBytes(StandardCharsets.UTF_8));
    Ed25519Signer s = new Ed25519Signer();
    s.init(true, new Ed25519PrivateKeyParameters(SEED, 0));
    byte[] in = (h + "." + p).getBytes(StandardCharsets.US_ASCII);
    s.update(in, 0, in.length);
    return h + "." + p + "." + b64(s.generateSignature());
  }

  private static SeamCrypto.Commitment commit(
      String action, byte[] explanationDigest, List<SeamCrypto.ExplanationEntry> e, byte[] sel) {
    return new SeamCrypto.Commitment(
        "c-1", action, "tenant:acme", null, "pinned_key", "selection", "orchestrator",
        explanationDigest, e, sel, null);
  }

  @Test
  @SuppressWarnings("unchecked")
  void verifyTctRecomputesTheWinnerWhenABlockIsGivenAndFailsClosedWithoutEntries()
      throws Exception {
    Map<String, Object> v = null;
    for (Map<String, Object> s : (List<Map<String, Object>>) vector().get("sealed_cases")) {
      if ("verified".equals(s.get("name"))) v = s;
    }
    SeamCrypto.SelectionBlock blk = block((Map<String, Object>) v.get("block"));
    List<SeamCrypto.ExplanationEntry> e = entries(v.get("entries"));
    String action = (String) v.get("action");
    byte[] field9 = SeamCrypto.selectionDigest(SeamCrypto.selectionBody(blk));
    byte[] ed = SeamCrypto.explanationDigest(e);

    SeamCrypto.Commitment full = commit(action, null, e, field9);
    String jws = tct(full);
    // The sealed shape verifies, with field 9 supplied or framed from the block alone.
    assertTrue(SeamCrypto.verifyTct(ISSUER, jws, full, 0, blk));
    assertTrue(SeamCrypto.verifyTct(ISSUER, jws, commit(action, null, e, null), 0, blk));
    // No block: unchanged behaviour (digest only).
    assertTrue(SeamCrypto.verifyTct(ISSUER, jws, full, 0, null));
    assertTrue(SeamCrypto.verifyTct(ISSUER, jws, full, 0));

    // A block with only the published explanation digest cannot be checked: fail closed, even
    // though the TCT itself verifies over that commitment.
    SeamCrypto.Commitment digestOnly = commit(action, ed, null, field9);
    assertTrue(SeamCrypto.verifyTct(ISSUER, jws, digestOnly, 0));
    assertFalse(SeamCrypto.verifyTct(ISSUER, jws, digestOnly, 0, blk));

    // A field 9 that disagrees with the block is refused.
    byte[] other = field9.clone();
    other[0] ^= 1;
    assertFalse(SeamCrypto.verifyTct(ISSUER, jws, commit(action, null, e, other), 0, blk));

    // A TCT honestly signed over a tampered selection (winner flipped by a weight) is refused by
    // the recompute, not by the signature.
    Map<String, Object> tamperedCase = null;
    for (Map<String, Object> s : (List<Map<String, Object>>) vector().get("sealed_cases")) {
      if ("weight_tampered_flips_winner".equals(s.get("name"))) tamperedCase = s;
    }
    SeamCrypto.SelectionBlock bad = block((Map<String, Object>) tamperedCase.get("block"));
    List<SeamCrypto.ExplanationEntry> be = entries(tamperedCase.get("entries"));
    SeamCrypto.Commitment tampered =
        commit(
            (String) tamperedCase.get("action"),
            null,
            be,
            SeamCrypto.selectionDigest(SeamCrypto.selectionBody(bad)));
    String tj = tct(tampered);
    assertTrue(SeamCrypto.verifyTct(ISSUER, tj, tampered, 0));
    assertFalse(SeamCrypto.verifyTct(ISSUER, tj, tampered, 0, bad));
  }
}
