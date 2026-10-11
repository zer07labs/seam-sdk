package com.zer07labs.seam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.jupiter.api.Test;

/**
 * The agent-side enrolment proof and its REST form (#214), against the same shared vector as the raw
 * signer (conformance/enroll_pop_v1_payload_vector.json). The REST {@code pop} object must match the
 * vector's fields byte for byte once serialized. NO bless mode.
 */
class EnrollProofTest {
  private static final Type MAP = new TypeToken<Map<String, Object>>() {}.getType();

  @Test
  @SuppressWarnings("unchecked")
  void enrolmentProofAndRestFormMatchVector() throws Exception {
    Map<String, Object> v =
        new Gson()
            .fromJson(
                Files.readString(Path.of("..", "conformance", "enroll_pop_v1_payload_vector.json")),
                MAP);
    List<Map<String, Object>> cases = (List<Map<String, Object>>) v.get("cases");
    assertTrue(cases.size() >= 6, "the vector lost cases; it pins a wire contract");
    for (Map<String, Object> c : cases) {
      String label = c.get("name") + ": " + c.get("why");
      byte[] seed = hexToBytes((String) c.get("seed_hex"));
      long issuedAtMs = ((Number) c.get("issued_at_ms")).longValue();
      String nonce = (String) c.get("nonce");
      String signature = (String) c.get("signature");
      assertEquals(
          c.get("subject_aid"),
          SeamCrypto.aidFromPubkey(new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded()),
          label);

      SeamCrypto.EnrollProof proof =
          SeamCrypto.enrolmentProof(
              seed, (String) c.get("tenant"), (String) c.get("namespace"), issuedAtMs, nonce);
      // RAW 64 bytes — the gRPC form.
      assertEquals(64, proof.signature().length, label);
      assertArrayEquals(Base64.getUrlDecoder().decode(signature), proof.signature(), label);
      assertEquals(issuedAtMs, proof.issuedAtMs(), label);
      assertEquals(nonce, proof.nonce(), label);
      // Unpadded base64url — the REST form.
      assertEquals(signature, proof.signatureB64url(), label);
      Map<String, Object> want = new LinkedHashMap<>();
      want.put("issued_at_ms", issuedAtMs);
      want.put("nonce", nonce);
      want.put("signature", signature);
      assertEquals(want, proof.toRest(), label);
      assertEquals(
          "{\"issued_at_ms\":" + issuedAtMs + ",\"nonce\":\"" + nonce + "\",\"signature\":\"" + signature + "\"}",
          new Gson().toJson(proof.toRest()),
          label);
      // It verifies over the vector's payload.
      assertTrue(
          verify(
              new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded(),
              hexToBytes((String) c.get("payload_hex")),
              proof.signature()),
          label);
    }
  }

  @Test
  void enrolmentProofDefaultsToNowAndAFresh22CharNonce() {
    byte[] seed = new byte[32];
    for (int i = 0; i < 32; i++) seed[i] = (byte) i;
    byte[] pub = new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded();
    long before = System.currentTimeMillis();
    SeamCrypto.EnrollProof a = SeamCrypto.enrolmentProof(seed, "acme", "fraud");
    SeamCrypto.EnrollProof b = SeamCrypto.enrolmentProof(seed, "acme", "fraud");
    long after = System.currentTimeMillis();
    assertTrue(before <= a.issuedAtMs() && a.issuedAtMs() <= after);
    assertEquals(22, a.nonce().length());
    SeamCrypto.validateEnrollPopNonce(a.nonce());
    assertNotEquals(a.nonce(), b.nonce(), "the default nonce must be random per proof");
    SeamCrypto.EnrollPopFields f =
        new SeamCrypto.EnrollPopFields(
            SeamCrypto.aidFromPubkey(pub), "acme", "fraud", a.issuedAtMs(), a.nonce());
    assertTrue(verify(pub, SeamCrypto.enrollPopPayload(f), a.signature()));
  }

  @Test
  void restFormCarriesAnUnsignedIssuedAtAndTheProofIsAValue() {
    byte[] sig = new byte[64];
    Arrays.fill(sig, (byte) 1);
    SeamCrypto.EnrollProof p = new SeamCrypto.EnrollProof(-1L, "n", sig);
    assertEquals(new BigInteger("18446744073709551615"), p.toRest().get("issued_at_ms"));
    assertEquals(new SeamCrypto.EnrollProof(-1L, "n", sig.clone()), p);
    sig[0] = 2; // the proof copied its signature
    assertEquals(1, p.signature()[0]);
  }

  @Test
  void enrolmentProofRefusesBadNoncesAndShortSeeds() {
    byte[] seed = new byte[32];
    Arrays.fill(seed, (byte) 7);
    for (String n :
        new String[] {"", "x".repeat(129), "has space", "pad=", "a+b", "a/b", "é", "a.b", "ok\n", null}) {
      assertThrows(
          IllegalArgumentException.class,
          () -> SeamCrypto.enrolmentProof(seed, "acme", "fraud", 1, n),
          "nonce " + n);
    }
    assertThrows(
        IllegalArgumentException.class, () -> SeamCrypto.enrolmentProof(new byte[31], "acme", "fraud"));
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
}
