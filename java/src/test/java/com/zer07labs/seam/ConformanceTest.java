package com.zer07labs.seam;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.jupiter.api.Test;

/** The Java crypto shim must reproduce the Rust reference bytes exactly (conformance/vectors.json). */
class ConformanceTest {
  private static final Type MAP = new TypeToken<Map<String, Object>>() {}.getType();

  @SuppressWarnings("unchecked")
  private static Map<String, Object> vectors() throws Exception {
    // Gradle runs tests from the module dir (java/); the vectors are a sibling of it.
    String raw = Files.readString(Path.of("..", "conformance", "vectors.json"));
    return new Gson().fromJson(raw, MAP);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> m(Map<String, Object> parent, String key) {
    return (Map<String, Object>) parent.get(key);
  }

  private static byte[] hexToBytes(String s) {
    byte[] out = new byte[s.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  /** Build a commitment from a vector's JSON projection (absent confidence/rationale_ref = null). */
  @SuppressWarnings("unchecked")
  static SeamCrypto.Commitment commitment(Map<String, Object> c) {
    List<SeamCrypto.ExplanationEntry> explanation = null;
    Object rawEntries = c.get("explanation");
    if (rawEntries != null) {
      explanation = new ArrayList<>();
      for (Object o : (List<Object>) rawEntries) {
        Map<String, Object> e = (Map<String, Object>) o;
        Object conf = e.get("confidence");
        explanation.add(
            new SeamCrypto.ExplanationEntry(
                (String) e.get("kind"),
                (String) e.get("participant"),
                (String) e.get("proposal_id"),
                (String) e.get("value"),
                (String) e.get("reason"),
                conf == null ? null : ((Number) conf).doubleValue(),
                (String) e.get("rationale_ref")));
      }
    }
    byte[] published = null;
    Object rawDigest = c.get("explanation_digest");
    if (rawDigest instanceof String hexDigest) {
      published = hexToBytes(hexDigest);
    } else if (rawDigest instanceof List<?> nums) {
      published = new byte[nums.size()];
      for (int i = 0; i < nums.size(); i++) published[i] = (byte) ((Number) nums.get(i)).intValue();
    }
    return new SeamCrypto.Commitment(
        (String) c.get("id"),
        (String) c.get("action"),
        (String) c.get("authority"),
        (String) c.get("supersedes"),
        (String) c.get("auth_method"),
        (String) c.get("trust_basis"),
        (String) c.get("committer"),
        published,
        explanation);
  }

  /** {@code base} with one of the six string fields replaced — committer and explanation kept. */
  private static SeamCrypto.Commitment with(SeamCrypto.Commitment b, String field, String v) {
    return new SeamCrypto.Commitment(
        field.equals("id") ? v : b.id(),
        field.equals("action") ? v : b.action(),
        field.equals("authority") ? v : b.authority(),
        field.equals("supersedes") ? v : b.supersedes(),
        field.equals("auth_method") ? v : b.authMethod(),
        field.equals("trust_basis") ? v : b.trustBasis(),
        field.equals("committer") ? v : b.committer(),
        b.explanationDigest(),
        b.explanation());
  }

  @Test
  void pinnedKeyPresentationIsByteExact() throws Exception {
    Map<String, Object> adm = m(vectors(), "admission");
    Map<String, Object> in = m(adm, "inputs");
    SeamCrypto.Presentation got =
        SeamCrypto.buildPresentation(
            hexToBytes((String) in.get("agent_seed_hex")),
            (String) in.get("receiver_aid"),
            (String) in.get("pop_nonce"),
            ((Number) in.get("now_ms")).longValue());

    Map<String, Object> want = m(adm, "presentation");
    Map<String, Object> wd = m(want, "descriptor");
    assertEquals(want.get("sender_aid"), got.senderAid());
    assertEquals(wd.get("type"), got.descriptor().type());
    assertEquals(wd.get("subject"), got.descriptor().subject());
    assertEquals(wd.get("proof"), got.descriptor().proof());
    assertEquals(wd.get("public_key"), got.descriptor().publicKey());
    assertEquals(want.get("message_id"), got.messageId());
    assertEquals(((Number) want.get("timestamp")).longValue(), got.timestamp());
    assertEquals(want.get("pop_nonce"), got.popNonce());
  }

  @Test
  void aidDerivationMatches() throws Exception {
    Map<String, Object> adm = m(vectors(), "admission");
    byte[] seed = hexToBytes((String) m(adm, "inputs").get("agent_seed_hex"));
    // Recover the public key from the presentation's public_key field and re-derive the AID.
    SeamCrypto.Presentation p =
        SeamCrypto.buildPresentation(seed, "aid:x", "AAAA", 0); // any inputs — we only read the AID
    assertEquals(m(adm, "derived").get("sender_aid"), p.senderAid());
  }

  /** The `tct` block's digests are reproduced exactly (seam-commitment-digest:v2 KAT). */
  @Test
  void tctCommitmentDigestV2IsByteExact() throws Exception {
    Map<String, Object> t = m(vectors(), "tct");
    SeamCrypto.Commitment c = commitment(m(m(t, "inputs"), "commitment"));
    assertEquals(
        t.get("explanation_digest_hex"),
        java.util.HexFormat.of().formatHex(SeamCrypto.explanationDigest(c.explanation())));
    assertEquals(t.get("commitment_digest_hex"), SeamCrypto.seamCommitmentDigest(c));
  }

  @Test
  void tctVerifyValidAndTampered() throws Exception {
    Map<String, Object> t = m(vectors(), "tct");
    SeamCrypto.Commitment c = commitment(m(m(t, "inputs"), "commitment"));
    String iss = (String) t.get("issuer_aid");
    String jws = (String) t.get("signed_artifact_jws");
    assertTrue(SeamCrypto.verifyTct(iss, jws, c, 1_700_000_001L), "valid TCT must verify");

    SeamCrypto.Commitment tampered = with(c, "action", "ALLOW");
    assertFalse(
        SeamCrypto.verifyTct(iss, jws, tampered, 1_700_000_001L),
        "a tampered commitment must not verify");
  }

  @Test
  void tctVerifyFailsClosed() throws Exception {
    Map<String, Object> t = m(vectors(), "tct");
    SeamCrypto.Commitment c = commitment(m(m(t, "inputs"), "commitment"));
    String iss = (String) t.get("issuer_aid");
    String jws = (String) t.get("signed_artifact_jws");

    record Case(String name, String issuer, String token, long now) {}
    List<Case> cases =
        List.of(
            new Case("expired", iss, jws, 9_999_999_999L),
            new Case("not-3-parts", iss, "not.a", 1_700_000_001L),
            new Case("wrong-issuer-key", "aid:pubkey:ed25519:" + "A".repeat(43), jws, 1_700_000_001L),
            new Case("unsupported-aid", "did:web:example.com", jws, 1_700_000_001L),
            new Case("tampered-signature", iss, jws.substring(0, jws.length() - 4) + "AAAA", 1_700_000_001L));
    for (Case k : cases) {
      assertFalse(SeamCrypto.verifyTct(k.issuer(), k.token(), c, k.now()), k.name() + " must fail closed");
    }
  }

  // -- Commitment-digest framing coverage (W5.4 / G4) --------------------------------------------
  //
  // `seam-commitment-digest:v2` is implemented byte-for-byte in ALL FIVE SDK languages -- the widest
  // fan-out of any framing in this repo. Its standalone vector is
  // conformance/commitment_digest_v2_vector.json (CommitmentDigestV2Test); the `tct` block of
  // conformance/vectors.json carries the same framing. Neither is edited on this side:
  // seam-runtime's `sdk-digest-parity` job byte-diffs them against its own emitter.
  //
  // What the `tct` block adds is stronger than it looks. `verifyTct` recomputes the digest and compares it
  // to the `seam-commitment-digest:` grant inside the runtime-signed JWS, so the vector already
  // carries a runtime-produced expected value. The gap was never coverage of the digest -- it was
  // coverage of the FIELD TUPLE: the pre-existing tests tampered `action` only, so exactly one of
  // the framing inputs was proven bound.
  //
  // The difference is demonstrable, not theoretical: an implementation that silently drops
  // `supersedes` from the preimage PASSES the pre-existing KAT test (the vector's commitment has no
  // `supersedes`, so the bytes are identical) and FAILS the first test below. Verified in Go and
  // Python, where that mutation could be run directly.

  private static final long NOW_S = 1_700_000_001L;

  /**
   * Every field the commitment digest binds must actually be bound. A field dropped from the
   * preimage -- or reordered -- lets one artifact verify under another's signature, which is the
   * whole point of the digest: it attests WHO committed and HOW they authed, not just the decision.
   */
  @Test
  void commitmentDigestBindsEveryField() throws Exception {
    Map<String, Object> t = m(vectors(), "tct");
    SeamCrypto.Commitment base = commitment(m(m(t, "inputs"), "commitment"));
    String iss = (String) t.get("issuer_aid");
    String jws = (String) t.get("signed_artifact_jws");

    assertTrue(
        SeamCrypto.verifyTct(iss, jws, base, NOW_S),
        "the unmodified vector commitment must verify -- nothing below means anything otherwise");

    record Mutation(String field, SeamCrypto.Commitment commitment) {}
    List<SeamCrypto.ExplanationEntry> ex = base.explanation();
    SeamCrypto.ExplanationEntry e0 = ex.get(0);
    List<SeamCrypto.ExplanationEntry> reordered = new ArrayList<>(ex);
    java.util.Collections.swap(reordered, 0, 1);
    List<SeamCrypto.ExplanationEntry> reasonChanged = new ArrayList<>(ex);
    reasonChanged.set(
        0,
        new SeamCrypto.ExplanationEntry(
            e0.kind(), e0.participant(), e0.proposalId(), e0.value(), e0.reason() + "-x",
            e0.confidence(), e0.rationaleRef()));
    List<Mutation> mutations =
        List.of(
            new Mutation("id", with(base, "id", base.id() + "-x")),
            new Mutation("action", with(base, "action", "ALLOW")),
            new Mutation("authority", with(base, "authority", base.authority() + "-x")),
            // The vector's commitment omits `supersedes`, so absent is the branch already
            // exercised. This pins the PRESENT branch, which nothing covered: absent and present
            // must differ, or a supersession could be stripped from a sealed record undetected.
            new Mutation("supersedes (absent -> present)", with(base, "supersedes", "k-previous")),
            new Mutation("auth_method", with(base, "auth_method", base.authMethod() + "-x")),
            new Mutation("trust_basis", with(base, "trust_basis", base.trustBasis() + "-x")),
            new Mutation("committer", with(base, "committer", base.committer() + "-x")),
            new Mutation("committer (present -> absent)", with(base, "committer", null)),
            new Mutation(
                "explanation (reordered)",
                new SeamCrypto.Commitment(
                    base.id(), base.action(), base.authority(), base.supersedes(),
                    base.authMethod(), base.trustBasis(), base.committer(), null, reordered)),
            new Mutation(
                "explanation (reason)",
                new SeamCrypto.Commitment(
                    base.id(), base.action(), base.authority(), base.supersedes(),
                    base.authMethod(), base.trustBasis(), base.committer(), null, reasonChanged)),
            new Mutation(
                "explanation (dropped)",
                new SeamCrypto.Commitment(
                    base.id(), base.action(), base.authority(), base.supersedes(),
                    base.authMethod(), base.trustBasis(), base.committer(), null, List.of())));

    for (Mutation mut : mutations) {
      assertFalse(
          SeamCrypto.verifyTct(iss, jws, mut.commitment(), NOW_S),
          "changing " + mut.field() + " did not change the commitment digest -- that field is not bound");
    }
  }

  /**
   * The length prefixes are load-bearing, and this notices if someone "simplifies" them away. Both
   * seam-store and seam-trust-aitp record the reason in their own source: without an 8-byte
   * big-endian length before each field, ("a\0b","c") and ("a","b\0c") produce identical preimages,
   * letting one Commitment verify under another's TCT. The fields are arbitrary text that may
   * itself contain NUL (UTF-8 permits U+0000, and it survives the JSON/prost decision path), so
   * this is reachable rather than theoretical.
   */
  @Test
  void commitmentDigestIsInjectiveAcrossFieldBoundaries() throws Exception {
    Map<String, Object> t = m(vectors(), "tct");
    SeamCrypto.Commitment base = commitment(m(m(t, "inputs"), "commitment"));

    // Fold the id/action boundary into `id` with a NUL. Under a NUL-joined framing this collides
    // with the real commitment; under length-prefixing it cannot.
    SeamCrypto.Commitment shifted =
        with(with(base, "id", base.id() + "\u0000" + base.action()), "action", "");

    assertFalse(
        SeamCrypto.verifyTct(
            (String) t.get("issuer_aid"), (String) t.get("signed_artifact_jws"), shifted, NOW_S),
        "a boundary-shifted commitment verified -- the framing is separator-joined, not "
            + "length-prefixed, and one artifact can now verify under another's signature");
  }

  // -- Authorize call_sig v3 (#197) ------------------------------------------------------------
  //
  // conformance/call_sig_v3_payload_vector.json is the cross-language contract. NO bless mode: a
  // mismatch is a contract break (a v4 domain tag), not a stale fixture.

  @SuppressWarnings("unchecked")
  private static List<SeamCrypto.Feature> features(Object raw) {
    List<SeamCrypto.Feature> out = new ArrayList<>();
    for (Object kv : (List<Object>) raw) {
      List<String> pair = (List<String>) kv;
      out.add(new SeamCrypto.Feature(pair.get(0), pair.get(1)));
    }
    return out;
  }

  @Test
  @SuppressWarnings("unchecked")
  void callSigV3PayloadMatchesVector() throws Exception {
    Map<String, Object> v =
        new Gson()
            .fromJson(
                Files.readString(Path.of("..", "conformance", "call_sig_v3_payload_vector.json")),
                MAP);
    assertEquals(SeamCrypto.CALL_SIG_V3_CONTEXT, v.get("domain"));
    List<Map<String, Object>> cases = (List<Map<String, Object>>) v.get("cases");
    assertFalse(cases.isEmpty(), "vector is empty; every assertion below would pass vacuously");
    for (Map<String, Object> c : cases) {
      byte[] got =
          SeamCrypto.callSigV3Payload(
              new SeamCrypto.CallSigV3Fields(
                  hexToBytes((String) c.get("ticket_hex")),
                  (String) c.get("tool_input_digest"),
                  (String) c.get("tool_name"),
                  (String) c.get("agent_id"),
                  (String) c.get("subject"),
                  (List<String>) c.get("subjects"),
                  (String) c.get("client_request_id"),
                  (String) c.get("session_id"),
                  features(c.get("features"))));
      assertEquals(c.get("payload_hex"), hex(got), c.get("name") + ": " + c.get("why"));
    }
  }

  /**
   * The vector's non-ascii case has a single feature, so it cannot catch a UTF-16 sort. U+FF61
   * (UTF-8 EF BD A1) sorts BEFORE U+1F600 (F0 9F 98 80) by bytes, but AFTER it by
   * {@link String#compareTo} (0xFF61 &gt; 0xD83D). The payload must follow byte order.
   */
  @Test
  void callSigV3SortsFeaturesByUtf8Bytes() {
    String bmp = "｡";
    String astral = "😀";
    SeamCrypto.CallSigV3Fields f =
        new SeamCrypto.CallSigV3Fields(
            new byte[] {1}, "d", "t", "", "", List.of(), "", "",
            List.of(new SeamCrypto.Feature(astral, "a"), new SeamCrypto.Feature(bmp, "b")));
    String p = hex(SeamCrypto.callSigV3Payload(f));
    assertTrue(
        p.indexOf("efbda1") < p.indexOf("f09f9880"),
        "features sorted by UTF-16 code unit, not by UTF-8 bytes");
  }

  @Test
  void callSigV3SignVerifyRoundTrip() {
    byte[] seed = new byte[32];
    Arrays.fill(seed, (byte) 7);
    SeamCrypto.CallSigV3Fields f =
        new SeamCrypto.CallSigV3Fields(
            new byte[] {1, 2, 3, 4},
            "sha256:" + "00".repeat(32),
            "read_file",
            "billing-agent",
            "user-1",
            List.of("user-2", "user-3"),
            "req-0001",
            "sess-9",
            List.of(
                new SeamCrypto.Feature("region", "eu"),
                new SeamCrypto.Feature("amount_bucket", "high")));
    byte[] sig = SeamCrypto.callSigV3(seed, f);
    assertEquals(64, sig.length);

    byte[] pub = new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded();
    assertTrue(verify(pub, SeamCrypto.callSigV3Payload(f), sig), "signature must verify");

    SeamCrypto.CallSigV3Fields reordered =
        new SeamCrypto.CallSigV3Fields(
            f.ticket(), f.toolInputDigest(), f.toolName(), f.agentId(), f.subject(),
            List.of("user-3", "user-2"), f.clientRequestId(), f.sessionId(), f.features());
    assertFalse(
        verify(pub, SeamCrypto.callSigV3Payload(reordered), sig),
        "signature verified over reordered subjects -- subject order is not bound");
    assertThrows(IllegalArgumentException.class, () -> SeamCrypto.callSigV3(new byte[31], f));
  }

  private static boolean verify(byte[] pub, byte[] msg, byte[] sig) {
    Ed25519Signer v = new Ed25519Signer();
    v.init(false, new Ed25519PublicKeyParameters(pub, 0));
    v.update(msg, 0, msg.length);
    return v.verifySignature(sig);
  }

  private static String hex(byte[] b) {
    StringBuilder sb = new StringBuilder(b.length * 2);
    for (byte x : b) sb.append(String.format("%02x", x & 0xff));
    return sb.toString();
  }
}
