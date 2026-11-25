package com.zer07labs.seam;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/**
 * Test support: mint a commitment TCT in the S-4 seal-key shape (seam-runtime #2031). The pinned
 * issuer certifies a seal key over a window; the seal key signs the token. Built by hand here, never
 * through {@link SeamCrypto}, so a test is not checking the verifier against itself.
 */
final class SealKeyTokens {
  private SealKeyTokens() {}

  /** The seal key the tests sign with (any fixed seed). */
  static final byte[] SEAL_SEED = filled((byte) 0x5e);

  /** A window every helper token falls in: 1_700_000_000 s, 15 minutes wide. */
  static final long NOT_BEFORE_MS = 1_700_000_000_000L;
  static final long NOT_AFTER_MS = NOT_BEFORE_MS + 900_000L;
  static final long IAT = NOT_BEFORE_MS / 1000;

  static byte[] filled(byte b) {
    byte[] s = new byte[32];
    Arrays.fill(s, b);
    return s;
  }

  static String b64(byte[] b) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  static byte[] pub(byte[] seed) {
    return new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded();
  }

  static byte[] sign(byte[] seed, byte[] msg) {
    Ed25519Signer s = new Ed25519Signer();
    s.init(true, new Ed25519PrivateKeyParameters(seed, 0));
    s.update(msg, 0, msg.length);
    return s.generateSignature();
  }

  static byte[] sha256(byte[] b) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(b);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  static String sealAid(byte[] sealSeed) {
    return "aid:pubkey:" + b64(pub(sealSeed));
  }

  static String jkt(byte[] pk) {
    String jwk = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + b64(pk) + "\"}";
    return b64(sha256(jwk.getBytes(StandardCharsets.US_ASCII)));
  }

  private static void framed(java.io.ByteArrayOutputStream out, byte[] b) {
    out.writeBytes(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(b.length).array());
    out.writeBytes(b);
  }

  /** {@code framed(tag) ‖ framed(pk) ‖ le64 nb ‖ le64 na ‖ framed(issuer_aid)}. */
  static byte[] cert(byte[] sealPk, long nb, long na, String issuerAid) {
    java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
    framed(out, "seam.seal-key-cert.v1".getBytes(StandardCharsets.US_ASCII));
    framed(out, sealPk);
    out.writeBytes(ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN).putLong(nb).putLong(na).array());
    framed(out, issuerAid.getBytes(StandardCharsets.UTF_8));
    return out.toByteArray();
  }

  /** The {@code {cert, sig}} ext member over raw certificate bytes, signed by {@code issuerSeed}. */
  static Map<String, Object> member(byte[] issuerSeed, byte[] cert) {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("cert", b64(cert));
    m.put("sig", b64(sign(issuerSeed, sha256(cert))));
    return m;
  }

  /** The default member: {@link #SEAL_SEED} certified by {@code issuerSeed} under {@code issuerAid}. */
  static Map<String, Object> member(byte[] issuerSeed, String issuerAid) {
    return member(issuerSeed, cert(pub(SEAL_SEED), NOT_BEFORE_MS, NOT_AFTER_MS, issuerAid));
  }

  /** The seal-key claims ({@code ver}, {@code iss/sub/aud}, {@code cnf}, {@code iat}) for {@code sealSeed}. */
  static Map<String, Object> claims(byte[] sealSeed, long iat) {
    String aid = sealAid(sealSeed);
    Map<String, Object> p = new LinkedHashMap<>();
    p.put("ver", "aitp/0.3");
    p.put("iss", aid);
    p.put("sub", aid);
    p.put("aud", aid);
    p.put("cnf", Map.of("jkt", jkt(pub(sealSeed))));
    p.put("iat", iat);
    return p;
  }

  /** Compact JWS of {@code payloadJson} signed by {@code sealSeed}. */
  static String jws(byte[] sealSeed, String payloadJson) {
    String input =
        b64("{\"alg\":\"EdDSA\",\"typ\":\"aitp-tct+jwt\"}".getBytes(StandardCharsets.UTF_8))
            + "."
            + b64(payloadJson.getBytes(StandardCharsets.UTF_8));
    return input + "." + b64(sign(sealSeed, input.getBytes(StandardCharsets.US_ASCII)));
  }
}
