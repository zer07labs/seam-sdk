package com.zer07labs.seam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Deep-cleanup S-4 (seam-runtime #2031, runtime 0.123.0): the commitment TCT is signed by a seal key
 * the pinned issuer certifies. Pinned by {@code conformance/seal_key_cert_vector.json}; the token
 * cases are minted here by hand ({@link SealKeyTokens}) so each refusal is about one thing.
 */
class SealKeyTest {
  private static final Type MAP = new TypeToken<Map<String, Object>>() {}.getType();
  private static final HexFormat HEX = HexFormat.of();
  private static final long NOW_S = 1_700_000_001L;

  private static final byte[] ISSUER_SEED = SealKeyTokens.filled((byte) 7);
  private static final String ISSUER = "aid:pubkey:" + SealKeyTokens.b64(SealKeyTokens.pub(ISSUER_SEED));
  private static final byte[] OTHER_SEED = SealKeyTokens.filled((byte) 8);
  private static final String OTHER = "aid:pubkey:" + SealKeyTokens.b64(SealKeyTokens.pub(OTHER_SEED));
  private static final byte[] SEAL = SealKeyTokens.SEAL_SEED;
  private static final long NB = SealKeyTokens.NOT_BEFORE_MS;
  private static final long NA = SealKeyTokens.NOT_AFTER_MS;

  private static Map<String, Object> load(String name) throws Exception {
    return new Gson().fromJson(Files.readString(Path.of("..", "conformance", name)), MAP);
  }

  // ── the frozen certificate vector ──────────────────────────────────────────────────────────

  @Test
  void theSealKeyCertVectorRebuildsAndVerifies() throws Exception {
    Map<String, Object> v = load("seal_key_cert_vector.json");
    assertEquals(SeamCrypto.SEAL_KEY_CERT_DOMAIN, v.get("domain"));
    byte[] cert = HEX.parseHex((String) v.get("cert_hex"));
    byte[] sig = HEX.parseHex((String) v.get("sig_hex"));
    byte[] pk = HEX.parseHex((String) v.get("seal_pk_hex"));
    long nb = Long.parseLong(new java.math.BigDecimal(v.get("not_before_ms").toString()).toBigIntegerExact().toString());
    long na = Long.parseLong(new java.math.BigDecimal(v.get("not_after_ms").toString()).toBigIntegerExact().toString());
    String issuer = (String) v.get("issuer_aid");
    assertEquals(ISSUER, issuer, "issuer seed 7x32");
    assertArrayEquals(pk, SealKeyTokens.pub(HEX.parseHex((String) v.get("seal_seed_hex"))));
    // The encoder and an independent hand framing both give the frozen bytes.
    assertArrayEquals(cert, SeamCrypto.sealKeyCertPreimage(pk, nb, na, issuer));
    assertArrayEquals(cert, SealKeyTokens.cert(pk, nb, na, issuer));
    assertEquals(v.get("cert_digest_hex"), HEX.formatHex(SealKeyTokens.sha256(cert)));
    @SuppressWarnings("unchecked")
    Map<String, Object> member = (Map<String, Object>) v.get("ext_member");
    assertEquals(SealKeyTokens.b64(cert), member.get("cert"));
    assertEquals(SealKeyTokens.b64(sig), member.get("sig"));

    SeamCrypto.SealKeyCert f = SeamCrypto.verifySealKeyCert(issuer, cert, sig);
    assertNotNull(f, "verifies under the pin");
    assertArrayEquals(pk, f.sealPk());
    assertEquals(nb, f.notBeforeMs());
    assertEquals(na, f.notAfterMs());
    assertEquals(issuer, f.issuerAid());
    assertEquals(v.get("seal_aid"), f.sealAid());

    assertNull(SeamCrypto.verifySealKeyCert(OTHER, cert, sig), "another pinned issuer");
    for (int i = 0; i < cert.length; i++) {
      byte[] bad = cert.clone();
      bad[i] ^= 1;
      assertNull(SeamCrypto.verifySealKeyCert(issuer, bad, sig), "flipped cert byte " + i);
    }
    for (int i = 0; i < sig.length; i++) {
      byte[] bad = sig.clone();
      bad[i] ^= 1;
      assertNull(SeamCrypto.verifySealKeyCert(issuer, cert, bad), "flipped sig byte " + i);
    }
  }

  @Test
  void everyPrefixAndATrailingByteIsRefused() {
    byte[] c = SealKeyTokens.cert(SealKeyTokens.pub(SEAL), NB, NA, ISSUER);
    assertNotNull(SeamCrypto.parseSealKeyCert(c));
    for (int cut = 0; cut < c.length; cut++) {
      assertNull(SeamCrypto.parseSealKeyCert(Arrays.copyOf(c, cut)), "prefix " + cut);
    }
    assertNull(SeamCrypto.parseSealKeyCert(Arrays.copyOf(c, c.length + 1)), "trailing byte");
    assertNull(SeamCrypto.parseSealKeyCert(SealKeyTokens.cert(SealKeyTokens.pub(SEAL), 21, 20, "a")), "inverted");
    assertNull(
        SeamCrypto.parseSealKeyCert(SealKeyTokens.cert(SealKeyTokens.pub(SEAL), 0, -1L, "a")),
        "not_after beyond i64::MAX (u64::MAX)");
    assertNull(
        SeamCrypto.parseSealKeyCert(SealKeyTokens.cert(SealKeyTokens.pub(SEAL), 0, Long.MAX_VALUE, "a")),
        "wider than the cap");
    assertNull(
        SeamCrypto.parseSealKeyCert(SealKeyTokens.cert(SealKeyTokens.pub(SEAL), NB, NB + 1, "a".repeat(63))),
        "issuer AID over 62 bytes");
    assertNotNull(
        SeamCrypto.parseSealKeyCert(SealKeyTokens.cert(SealKeyTokens.pub(SEAL), NB, NB + 1, "a".repeat(62))));
    byte[] badUtf8 = SealKeyTokens.cert(SealKeyTokens.pub(SEAL), NB, NB + 1, "ab");
    badUtf8[badUtf8.length - 1] = (byte) 0xff;
    assertNull(SeamCrypto.parseSealKeyCert(badUtf8), "issuer AID not UTF-8");
    byte[] wrongTag = c.clone();
    wrongTag[4] ^= 1;
    assertNull(SeamCrypto.parseSealKeyCert(wrongTag), "wrong domain tag");
  }

  // ── token-level verification ───────────────────────────────────────────────────────────────

  /** The vectors.json tct block's commitment (its digest is what the statement binds). */
  private static SeamCrypto.Commitment commitment() throws Exception {
    @SuppressWarnings("unchecked")
    Map<String, Object> t = (Map<String, Object>) load("vectors.json").get("tct");
    @SuppressWarnings("unchecked")
    Map<String, Object> c = (Map<String, Object>) ((Map<String, Object>) t.get("inputs")).get("commitment");
    return ConformanceTest.commitment(c);
  }

  /** A token whose parts the case controls: who signs it, its claims, iat literal and ext member. */
  private static String token(
      byte[] signer, byte[] claimsSeal, String iatLiteral, Object member, String extra)
      throws Exception {
    Map<String, Object> claims = SealKeyTokens.claims(claimsSeal, 0);
    claims.remove("iat");
    String head = new Gson().toJson(claims);
    String stmt =
        "{\"type\":\"seam:commitment\",\"commitment_digest\":\""
            + SeamCrypto.seamCommitmentDigest(commitment())
            + "\"}";
    String ext =
        "{\"com.zer07labs.seam\":" + stmt
            + (member == null ? "" : ",\"" + SeamCrypto.SEAL_KEY_CERT_EXT_KEY + "\":" + new Gson().toJson(member))
            + extra
            + "}";
    String payload =
        head.substring(0, head.length() - 1)
            + (iatLiteral == null ? "" : ",\"iat\":" + iatLiteral)
            + ",\"exp\":4853600000,\"grants\":[\"aitp.attestation\"],\"ext\":" + ext + "}";
    return SealKeyTokens.jws(signer, payload);
  }

  private static boolean verify(String jws) throws Exception {
    return SeamCrypto.verifyTct(ISSUER, jws, commitment(), NOW_S);
  }

  private static Map<String, Object> member(long nb, long na) {
    return SealKeyTokens.member(ISSUER_SEED, SealKeyTokens.cert(SealKeyTokens.pub(SEAL), nb, na, ISSUER));
  }

  private static String ok(long iat, Map<String, Object> member) throws Exception {
    return token(SEAL, SEAL, Long.toString(iat), member, "");
  }

  @Test
  void theRuntimeVectorTokensVerify() throws Exception {
    @SuppressWarnings("unchecked")
    Map<String, Object> t = (Map<String, Object>) load("vectors.json").get("tct");
    assertTrue(
        SeamCrypto.verifyTct((String) t.get("issuer_aid"), (String) t.get("signed_artifact_jws"), commitment(), NOW_S),
        "vectors.json tct, signed through the runtime's seeded seal key");
    assertFalse(
        SeamCrypto.verifyTct(OTHER, (String) t.get("signed_artifact_jws"), commitment(), NOW_S),
        "another pinned issuer");
    assertTrue(verify(ok(SealKeyTokens.IAT, member(NB, NA))), "the hand-minted control");
  }

  @Test
  void anIssuerSignedTctIsRefused() throws Exception {
    // The pre-S-4 shape: iss == sub == aud == the issuer, signed by the issuer, no certificate.
    assertFalse(verify(token(ISSUER_SEED, ISSUER_SEED, Long.toString(SealKeyTokens.IAT), null, "")));
    // Same, carrying a valid certificate for another key: the signer is not the certified seal key.
    assertFalse(verify(token(ISSUER_SEED, ISSUER_SEED, Long.toString(SealKeyTokens.IAT), member(NB, NA), "")));
    // The certified seal key's claims, but the issuer signed the JWS.
    assertFalse(verify(token(ISSUER_SEED, SEAL, Long.toString(SealKeyTokens.IAT), member(NB, NA), "")));
  }

  @Test
  void aWindowOverTheCapIsRefusedAndTheCapItselfVerifies() throws Exception {
    assertTrue(verify(ok(SealKeyTokens.IAT, member(NB, NB + SeamCrypto.SEAL_KEY_MAX_WINDOW_MS))));
    assertFalse(verify(ok(SealKeyTokens.IAT, member(NB, NB + SeamCrypto.SEAL_KEY_MAX_WINDOW_MS + 1))));
    assertEquals(3_630_000L, SeamCrypto.SEAL_KEY_MAX_WINDOW_MS);
  }

  @Test
  void iatMustLieInTheWindowWithNoGrace() throws Exception {
    Map<String, Object> m = member(NB, NA);
    assertTrue(verify(ok(NB / 1000, m)), "not_before");
    assertTrue(verify(ok(NA / 1000, m)), "not_after");
    assertFalse(verify(ok(NB / 1000 - 1, m)), "one second before");
    assertFalse(verify(ok(NA / 1000 + 1, m)), "one second after");
    // A window whose edge is not on a second: iat*1000 must still be inside.
    Map<String, Object> odd = member(NB + 1, NA);
    assertFalse(verify(ok(NB / 1000, odd)), "iat*1000 one ms before not_before");
    // iat is a JSON integer, nothing else.
    for (String lit : new String[] {null, "\"1700000000\"", "1700000000.0", "1.7e9", "true", "null"}) {
      assertFalse(verify(token(SEAL, SEAL, lit, m, "")), "iat " + lit);
    }
    assertFalse(verify(ok(Long.MAX_VALUE, member(Long.MAX_VALUE - 1000, Long.MAX_VALUE))), "iat*1000 overflows");
  }

  @Test
  void theCertificateMustNameAndBeSignedByThePinnedIssuer() throws Exception {
    byte[] pk = SealKeyTokens.pub(SEAL);
    // Names another AID, signed by the pinned issuer.
    assertFalse(verify(ok(SealKeyTokens.IAT, SealKeyTokens.member(ISSUER_SEED, SealKeyTokens.cert(pk, NB, NA, OTHER)))));
    // Names the pinned AID, signed by another issuer.
    assertFalse(verify(ok(SealKeyTokens.IAT, SealKeyTokens.member(OTHER_SEED, SealKeyTokens.cert(pk, NB, NA, ISSUER)))));
    // A forger certifies their own key under their own AID: verifies only under that AID.
    String forged = ok(SealKeyTokens.IAT, SealKeyTokens.member(OTHER_SEED, SealKeyTokens.cert(pk, NB, NA, OTHER)));
    assertFalse(verify(forged));
    assertTrue(SeamCrypto.verifyTct(OTHER, forged, commitment(), NOW_S), "control: under its own pin");
    // The tagged form of the pinned key is a different AID string.
    assertFalse(SeamCrypto.verifyTct(SeamCrypto.aidFromPubkey(SealKeyTokens.pub(ISSUER_SEED)), ok(SealKeyTokens.IAT, member(NB, NA)), commitment(), NOW_S));
  }

  @Test
  void theCertificateMemberAndExtShapeAreExact() throws Exception {
    Map<String, Object> m = member(NB, NA);
    Map<String, Object> third = new LinkedHashMap<>(m);
    third.put("x", "y");
    assertFalse(verify(ok(SealKeyTokens.IAT, third)), "a third member");
    Map<String, Object> onlyCert = new LinkedHashMap<>(m);
    onlyCert.remove("sig");
    assertFalse(verify(ok(SealKeyTokens.IAT, onlyCert)), "sig missing");
    Map<String, Object> padded = new LinkedHashMap<>(m);
    padded.put("sig", Base64.getUrlEncoder().encodeToString(Base64.getUrlDecoder().decode((String) m.get("sig"))));
    assertTrue(((String) padded.get("sig")).endsWith("="));
    assertFalse(verify(ok(SealKeyTokens.IAT, padded)), "padded base64url");
    Map<String, Object> std = new LinkedHashMap<>(m);
    std.put("cert", ((String) m.get("cert")).replace('-', '+').replace('_', '/'));
    if (!std.get("cert").equals(m.get("cert"))) {
      assertFalse(verify(ok(SealKeyTokens.IAT, std)), "standard base64 alphabet");
    }
    Map<String, Object> nonCanonical = new LinkedHashMap<>(m);
    String sig = (String) m.get("sig"); // 64 bytes: 86 chars, the last carries 2 unused bits
    char last = sig.charAt(sig.length() - 1);
    nonCanonical.put("sig", sig.substring(0, sig.length() - 1) + (char) (last + 1));
    assertFalse(verify(ok(SealKeyTokens.IAT, nonCanonical)), "non-canonical trailing bits");
    Map<String, Object> notString = new LinkedHashMap<>(m);
    notString.put("cert", 1);
    assertFalse(verify(ok(SealKeyTokens.IAT, notString)), "cert not a string");
    // A certificate for another seal key than the one that signed.
    Map<String, Object> otherSeal =
        SealKeyTokens.member(ISSUER_SEED, SealKeyTokens.cert(SealKeyTokens.pub(OTHER_SEED), NB, NA, ISSUER));
    assertFalse(verify(ok(SealKeyTokens.IAT, otherSeal)), "cert for another seal key");
    // An extra ext namespace beside the two.
    assertFalse(verify(token(SEAL, SEAL, Long.toString(SealKeyTokens.IAT), m, ",\"com.example\":{}")));
    // No certificate member at all.
    assertFalse(verify(token(SEAL, SEAL, Long.toString(SealKeyTokens.IAT), null, "")));
  }

  @Test
  void trailingCertificateBytesAreRefused() throws Exception {
    byte[] c = SealKeyTokens.cert(SealKeyTokens.pub(SEAL), NB, NA, ISSUER);
    byte[] longer = Arrays.copyOf(c, c.length + 1);
    // Properly signed by the issuer, so the parser alone refuses it.
    assertFalse(verify(ok(SealKeyTokens.IAT, SealKeyTokens.member(ISSUER_SEED, longer))));
  }

  @Test
  void aSmallOrderRorKeyIsRefused() {
    byte[] identity = new byte[32];
    identity[0] = 1;
    byte[] msg = "m".getBytes();
    // R = identity, S = 0 under the identity key satisfies the cofactorless equation; strict refuses it.
    byte[] sig = Arrays.copyOf(identity, 64);
    assertFalse(SeamCrypto.ed25519VerifyStrict(identity, msg, sig));
    // A real signature whose R is replaced by a small-order encoding.
    byte[] c = SealKeyTokens.cert(SealKeyTokens.pub(SEAL), NB, NA, ISSUER);
    byte[] good = SealKeyTokens.sign(ISSUER_SEED, SealKeyTokens.sha256(c));
    assertNotNull(SeamCrypto.verifySealKeyCert(ISSUER, c, good));
    byte[] bad = good.clone();
    System.arraycopy(identity, 0, bad, 0, 32);
    assertNull(SeamCrypto.verifySealKeyCert(ISSUER, c, bad));
    // A pinned issuer whose key is small-order certifies nothing.
    String weak = "aid:pubkey:" + SealKeyTokens.b64(identity);
    byte[] wc = SealKeyTokens.cert(SealKeyTokens.pub(SEAL), NB, NA, weak);
    assertNull(SeamCrypto.verifySealKeyCert(weak, wc, sig));
  }
}
