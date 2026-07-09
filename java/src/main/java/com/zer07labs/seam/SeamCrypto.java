package com.zer07labs.seam;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Type;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/**
 * Client-side crypto for the Seam Java SDK — stock primitives (Ed25519 via Bouncy Castle + SHA-256), no
 * AITP binding. The admission proof-of-possession is Ed25519 over SHA-256 of a documented,
 * domain-separated canonical byte layout; the seed never leaves the client. Mirrors the Python/Go/TS
 * reference byte-for-byte — pinned by {@code conformance/vectors.json}.
 */
public final class SeamCrypto {
  private SeamCrypto() {}

  private static final byte[] PROOF_DOMAIN = "aitp-pinned-key-v1\0".getBytes(StandardCharsets.UTF_8);
  private static final Gson GSON = new Gson();
  private static final Type MAP = new TypeToken<Map<String, Object>>() {}.getType();

  public record Descriptor(String type, String subject, String proof, String publicKey) {}

  public record Presentation(
      String senderAid, Descriptor descriptor, String messageId, long timestamp, String popNonce) {}

  public record Commitment(
      String id,
      String action,
      String authority,
      String supersedes,
      String authMethod,
      String trustBasis) {}

  // ── base64url (no padding) ──────────────────────────────────────────────────────────────────
  private static String b64urlNoPad(byte[] b) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  private static byte[] b64urlDecode(String s) {
    int pad = (4 - s.length() % 4) % 4;
    return Base64.getUrlDecoder().decode(s + "=".repeat(pad));
  }

  private static byte[] sha256(byte[] b) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(b);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  // ── Ed25519 (Bouncy Castle) ─────────────────────────────────────────────────────────────────
  private static byte[] ed25519Pub(byte[] seed) {
    return new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded();
  }

  private static byte[] ed25519Sign(byte[] seed, byte[] msg) {
    Ed25519Signer signer = new Ed25519Signer();
    signer.init(true, new Ed25519PrivateKeyParameters(seed, 0));
    signer.update(msg, 0, msg.length);
    return signer.generateSignature();
  }

  private static boolean ed25519Verify(byte[] pub, byte[] msg, byte[] sig) {
    try {
      Ed25519Signer verifier = new Ed25519Signer();
      verifier.init(false, new Ed25519PublicKeyParameters(pub, 0));
      verifier.update(msg, 0, msg.length);
      return verifier.verifySignature(sig);
    } catch (RuntimeException e) {
      return false;
    }
  }

  /** The agent's {@code aid:pubkey:ed25519:} identity for a 32-byte Ed25519 public key. */
  public static String aidFromPubkey(byte[] pub) {
    return "aid:pubkey:ed25519:" + b64urlNoPad(pub);
  }

  private static byte[] aidToPubkey(String aid) {
    for (String p : new String[] {"aid:pubkey:ed25519:", "aid:pubkey:"}) {
      if (aid.startsWith(p)) {
        return b64urlDecode(aid.substring(p.length()));
      }
    }
    throw new IllegalArgumentException("unsupported AID form: " + aid);
  }

  /** Deterministic (no-RNG) message id: first 16 bytes of SHA-256("seam-pop-mid"||nonce) as a UUID. */
  private static String popMessageId(String popNonce) {
    byte[] h = sha256(concat("seam-pop-mid".getBytes(StandardCharsets.UTF_8),
        popNonce.getBytes(StandardCharsets.US_ASCII)));
    StringBuilder sb = new StringBuilder(36);
    for (int i = 0; i < 16; i++) {
      if (i == 4 || i == 6 || i == 8 || i == 10) sb.append('-');
      sb.append(String.format("%02x", h[i] & 0xff));
    }
    return sb.toString();
  }

  /** Build the pinned-key admission presentation the Seam server verifies. */
  public static Presentation buildPresentation(
      byte[] agentSeed, String receiverAid, String popNonce, long nowMs) {
    byte[] pub = ed25519Pub(agentSeed);
    String senderAid = aidFromPubkey(pub);
    String mid = popMessageId(popNonce);
    long timestamp = nowMs / 1000;

    ByteArrayOutputStream in = new ByteArrayOutputStream();
    in.writeBytes(PROOF_DOMAIN);
    in.writeBytes(senderAid.getBytes(StandardCharsets.UTF_8));
    in.write(0);
    in.writeBytes(receiverAid.getBytes(StandardCharsets.UTF_8));
    in.write(0);
    in.writeBytes(mid.getBytes(StandardCharsets.UTF_8));
    in.write(0);
    in.writeBytes(ByteBuffer.allocate(8).putLong(timestamp).array()); // big-endian
    in.write(0);
    in.writeBytes(b64urlDecode(popNonce));

    byte[] proof = ed25519Sign(agentSeed, sha256(in.toByteArray()));
    return new Presentation(
        senderAid,
        new Descriptor("pinned_key", senderAid, b64urlNoPad(proof), b64urlNoPad(pub)),
        mid,
        timestamp,
        popNonce);
  }

  private static String seamCommitmentDigest(Commitment c) {
    ByteArrayOutputStream h = new ByteArrayOutputStream();
    byte[][] fields = {
      "seam-commitment-digest:v1".getBytes(StandardCharsets.UTF_8),
      nz(c.id()),
      nz(c.action()),
      nz(c.authority()),
      nz(c.supersedes()),
      nz(c.authMethod()),
      nz(c.trustBasis())
    };
    for (byte[] f : fields) {
      h.writeBytes(ByteBuffer.allocate(8).putLong(f.length).array());
      h.writeBytes(f);
    }
    return hex(sha256(h.toByteArray()));
  }

  /**
   * Independently verify a sealed commitment's rooted TCT — zero server trust, stock crypto only. Any
   * malformed/forged input fails closed (returns {@code false}), never throws.
   */
  public static boolean verifyTct(String issuerAid, String tctJws, Commitment c, long nowS) {
    try {
      String[] parts = tctJws.split("\\.");
      if (parts.length != 3) return false;
      byte[] pub;
      try {
        pub = aidToPubkey(issuerAid);
      } catch (RuntimeException e) {
        return false;
      }
      if (pub.length != 32) return false;
      if (!ed25519Verify(pub, (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII),
          b64urlDecode(parts[2]))) {
        return false;
      }
      Map<String, Object> header =
          GSON.fromJson(new String(b64urlDecode(parts[0]), StandardCharsets.UTF_8), MAP);
      Map<String, Object> payload =
          GSON.fromJson(new String(b64urlDecode(parts[1]), StandardCharsets.UTF_8), MAP);
      if (!"EdDSA".equals(header.get("alg")) || !"aitp-tct+jwt".equals(header.get("typ"))) {
        return false;
      }
      if (!(issuerAid.equals(payload.get("iss"))
          && issuerAid.equals(payload.get("sub"))
          && issuerAid.equals(payload.get("aud")))) {
        return false;
      }
      Object exp = payload.get("exp");
      if (!(exp instanceof Number) || nowS >= ((Number) exp).longValue()) return false;
      String want = "seam-commitment-digest:" + seamCommitmentDigest(c);
      Object grants = payload.get("grants");
      if (!(grants instanceof List<?> list)) return false;
      for (Object g : list) {
        if (want.equals(g)) return true;
      }
      return false;
    } catch (RuntimeException e) {
      return false;
    }
  }

  // ── helpers ─────────────────────────────────────────────────────────────────────────────────
  private static byte[] nz(String s) {
    return (s == null ? "" : s).getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] out = new byte[a.length + b.length];
    System.arraycopy(a, 0, out, 0, a.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }

  private static String hex(byte[] b) {
    StringBuilder sb = new StringBuilder(b.length * 2);
    for (byte x : b) sb.append(String.format("%02x", x & 0xff));
    return sb.toString();
  }
}
