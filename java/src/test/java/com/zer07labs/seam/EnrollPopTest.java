package com.zer07labs.seam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.jupiter.api.Test;

/**
 * The enrolment proof-of-possession (#205). conformance/enroll_pop_v1_payload_vector.json is the
 * cross-language contract. NO bless mode: a mismatch is a contract break (a v2 domain tag), not a
 * stale fixture.
 */
class EnrollPopTest {
  private static final Type MAP = new TypeToken<Map<String, Object>>() {}.getType();

  @Test
  @SuppressWarnings("unchecked")
  void enrollPopMatchesVector() throws Exception {
    Map<String, Object> v =
        new Gson()
            .fromJson(
                Files.readString(Path.of("..", "conformance", "enroll_pop_v1_payload_vector.json")),
                MAP);
    assertEquals(SeamCrypto.ENROLL_POP_V1_CONTEXT, v.get("domain"));
    List<Map<String, Object>> cases = (List<Map<String, Object>>) v.get("cases");
    assertFalse(cases.isEmpty(), "vector is empty; every assertion below would pass vacuously");
    for (Map<String, Object> c : cases) {
      String label = c.get("name") + ": " + c.get("why");
      SeamCrypto.EnrollPopFields f =
          new SeamCrypto.EnrollPopFields(
              (String) c.get("subject_aid"),
              (String) c.get("tenant"),
              (String) c.get("namespace"),
              ((Number) c.get("issued_at_ms")).longValue(),
              (String) c.get("nonce"));
      assertEquals(c.get("payload_hex"), hex(SeamCrypto.enrollPopPayload(f)), label);

      byte[] sig = SeamCrypto.enrollPop(hexToBytes((String) c.get("seed_hex")), f);
      // RAW 64 bytes — the gRPC form.
      assertArrayEquals(Base64.getUrlDecoder().decode((String) c.get("signature")), sig, label);
      // Unpadded base64url — the REST form.
      assertEquals(
          c.get("signature"), Base64.getUrlEncoder().withoutPadding().encodeToString(sig), label);
    }
  }

  @Test
  void aProofForOneTenantAndNamespaceDoesNotVerifyForAnother() {
    byte[] seed = new byte[32];
    Arrays.fill(seed, (byte) 7);
    byte[] pub = new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded();
    String aid = SeamCrypto.aidFromPubkey(pub);
    SeamCrypto.EnrollPopFields f =
        new SeamCrypto.EnrollPopFields(aid, "tenant-a", "ns-x", 1_760_000_000_000L, "n0");
    byte[] sig = SeamCrypto.enrollPop(seed, f);
    assertEquals(64, sig.length);
    assertTrue(verify(pub, SeamCrypto.enrollPopPayload(f), sig), "signature must verify");
    for (String[] tn : new String[][] {{"tenant-b", "ns-x"}, {"tenant-a", "ns-y"}, {"tenant-b", "ns-y"}}) {
      SeamCrypto.EnrollPopFields other =
          new SeamCrypto.EnrollPopFields(aid, tn[0], tn[1], f.issuedAtMs(), f.nonce());
      assertFalse(
          verify(pub, SeamCrypto.enrollPopPayload(other), sig),
          "a tenant-a/ns-x proof verified for " + tn[0] + "/" + tn[1]);
    }
  }

  @Test
  void signerRefusesBadNoncesForeignAidsAndShortSeeds() {
    byte[] seed = new byte[32];
    Arrays.fill(seed, (byte) 7);
    String aid =
        SeamCrypto.aidFromPubkey(
            new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded());
    for (String n :
        new String[] {"", "x".repeat(129), "has space", "pad=", "a+b", "a/b", "é", "a.b", null}) {
      SeamCrypto.EnrollPopFields bad = new SeamCrypto.EnrollPopFields(aid, "acme", "fraud", 1, n);
      assertThrows(
          IllegalArgumentException.class, () -> SeamCrypto.enrollPop(seed, bad), "nonce " + n);
    }
    assertDoesNotThrow(() -> SeamCrypto.validateEnrollPopNonce("x".repeat(128)));
    SeamCrypto.EnrollPopFields foreign =
        new SeamCrypto.EnrollPopFields(
            "aid:pubkey:ed25519:11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "acme", "fraud", 1, "ok");
    assertThrows(IllegalArgumentException.class, () -> SeamCrypto.enrollPop(seed, foreign));
    SeamCrypto.EnrollPopFields ok = new SeamCrypto.EnrollPopFields(aid, "acme", "fraud", 1, "ok");
    assertThrows(IllegalArgumentException.class, () -> SeamCrypto.enrollPop(new byte[31], ok));
  }

  private static boolean verify(byte[] pub, byte[] msg, byte[] sig) {
    Ed25519Signer v = new Ed25519Signer();
    v.init(false, new Ed25519PublicKeyParameters(pub, 0));
    v.update(msg, 0, msg.length);
    return v.verifySignature(sig);
  }

  private static byte[] hexToBytes(String s) {
    byte[] out = new byte[s.length() / 2];
    for (int i = 0; i < out.length; i++) {
      out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  private static String hex(byte[] b) {
    StringBuilder sb = new StringBuilder(b.length * 2);
    for (byte x : b) sb.append(String.format("%02x", x & 0xff));
    return sb.toString();
  }
}
