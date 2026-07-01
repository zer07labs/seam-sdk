package com.zer07labs.seam;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
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

  private static SeamCrypto.Commitment commitment(Map<String, Object> c) {
    return new SeamCrypto.Commitment(
        (String) c.get("id"),
        (String) c.get("action"),
        (String) c.get("authority"),
        (String) c.get("supersedes"),
        (String) c.get("auth_method"),
        (String) c.get("trust_basis"));
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

  @Test
  void tctVerifyValidAndTampered() throws Exception {
    Map<String, Object> t = m(vectors(), "tct");
    SeamCrypto.Commitment c = commitment(m(m(t, "inputs"), "commitment"));
    String iss = (String) t.get("issuer_aid");
    String jws = (String) t.get("signed_artifact_jws");
    assertTrue(SeamCrypto.verifyTct(iss, jws, c, 1_700_000_001L), "valid TCT must verify");

    SeamCrypto.Commitment tampered =
        new SeamCrypto.Commitment(
            c.id(), "ALLOW", c.authority(), c.supersedes(), c.authMethod(), c.trustBasis());
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
}
