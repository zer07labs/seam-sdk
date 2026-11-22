package com.zer07labs.seam;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.zer07labs.seam.SeamCrypto.CommitmentTrailers;
import com.zer07labs.seam.SeamCrypto.CommitmentVersion;
import com.zer07labs.seam.SeamCrypto.GateBlock;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The Gate block v1 ({@code 0x05}) and {@code seam-gate-digest:v1} against {@code
 * conformance/gate_block_vector.json}: {@code cases}, {@code presence_states}, {@code
 * body_refusals} and {@code sequences}, every row. Refusal rows assert the refusal only.
 *
 * <p>{@code outage_classification} and {@code writer_refusals} are NOT tested here: they pin what the
 * runtime WRITES for an observed Gate outcome (which HTTP status seals as which reason, or refuses),
 * and this SDK is a reader only. A reader cannot see the HTTP status, so those rows have nothing to
 * assert against a decoder (Flows W2 plan, cross-port contract item 3).
 */
class GateBlockV1Test {
  private static final HexFormat HEX = HexFormat.of();

  private static Map<String, Object> vector() throws Exception {
    return CommitmentDigestV6Test.load("gate_block_vector.json");
  }

  private static byte[] hex(Object s) {
    return HEX.parseHex((String) s);
  }

  private static String hex(byte[] b) {
    return b == null ? null : HEX.formatHex(b);
  }

  private static String unsigned(long v) {
    return Long.toUnsignedString(v);
  }

  /** The test doc digest: SHA-256("seam-governing-doc:test-vector"). */
  private static byte[] testDoc() throws Exception {
    return MessageDigest.getInstance("SHA-256")
        .digest("seam-governing-doc:test-vector".getBytes(StandardCharsets.UTF_8));
  }

  /** {@code 0x06 ‖ u32le(len) ‖ 0x02 ‖ doc ‖ 0x01 ‖ F(env)}: the binding a {@code 0x05} needs. */
  private static byte[] governingV2(String env) throws Exception {
    byte[] e = env.getBytes(StandardCharsets.US_ASCII);
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    body.write(0x02);
    body.writeBytes(testDoc());
    body.write(0x01);
    body.writeBytes(ByteBuffer.allocate(8).putLong(e.length).array());
    body.writeBytes(e);
    ByteArrayOutputStream t = new ByteArrayOutputStream();
    t.write(0x06);
    t.writeBytes(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(body.size()).array());
    t.writeBytes(body.toByteArray());
    return t.toByteArray();
  }

  @Test
  @SuppressWarnings("unchecked")
  void everyCaseDecodesAndDigests() throws Exception {
    Map<String, Object> v = vector();
    assertEquals(SeamCrypto.GATE_DIGEST_DOMAIN, v.get("gate_digest_domain"));
    List<Map<String, Object>> cases = CommitmentDigestV6Test.rows(v, "cases");
    assertEquals(8, cases.size());
    for (Map<String, Object> k : cases) {
      String name = (String) k.get("name");
      byte[] body = hex(k.get("gate_body"));
      Map<String, Object> want = (Map<String, Object>) k.get("block");
      GateBlock b = SeamCrypto.decodeGateBody(body);
      assertEquals(want.get("status"), b.status(), name);
      assertEquals(want.get("attempt_id"), b.attemptId(), name);
      assertEquals(want.get("domain"), b.domain(), name);
      assertEquals(want.get("flow_id"), b.flowId(), name);
      assertEquals(want.get("env"), b.env(), name);
      assertEquals(want.get("timeout_ms"), unsigned(b.timeoutMs()), name);
      assertEquals(want.get("on_outage"), b.onOutage(), name);
      assertEquals(want.get("requested_at_ms"), unsigned(b.requestedAtMs()), name);
      if ("answered".equals(b.status())) {
        assertEquals(want.get("receipt_jcs"), b.receiptJcs(), name);
        assertEquals(want.get("key_id"), b.keyId(), name);
        assertEquals(want.get("signature"), hex(b.signature()), name);
        assertEquals(want.get("certificate_jcs"), b.certificateJcs(), name);
        assertNull(b.reason(), name);
        assertNull(b.givenUpAtMs(), name);
      } else {
        assertEquals(want.get("reason"), b.reason(), name);
        assertEquals(want.get("given_up_at_ms"), unsigned(b.givenUpAtMs()), name);
        assertNull(b.receiptJcs(), name);
        assertNull(b.signature(), name);
      }
      byte[] digest = SeamCrypto.gateDigest(body);
      assertEquals(k.get("gate_digest"), hex(digest), name);
      byte[] tag = SeamCrypto.GATE_DIGEST_DOMAIN.getBytes(StandardCharsets.US_ASCII);
      ByteArrayOutputStream prefix = new ByteArrayOutputStream();
      prefix.writeBytes(ByteBuffer.allocate(8).putLong(tag.length).array());
      prefix.writeBytes(tag);
      assertEquals(k.get("gate_digest_preimage_prefix"), hex(prefix.toByteArray()), name);
      // The trailer frames the body; decoded beside its 0x06 v2 binding, field 10 is the digest.
      byte[] trailer = hex(k.get("trailer"));
      ByteArrayOutputStream framed = new ByteArrayOutputStream();
      framed.write(0x05);
      framed.writeBytes(
          ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(body.length).array());
      framed.writeBytes(body);
      assertEquals(hex(trailer), hex(framed.toByteArray()), name);
      ByteArrayOutputStream seq = new ByteArrayOutputStream();
      seq.writeBytes(trailer);
      seq.writeBytes(governingV2(b.env()));
      CommitmentTrailers t =
          SeamCrypto.decodeCommitmentTrailers(seq.toByteArray(), CommitmentVersion.V6);
      assertEquals(k.get("field_10"), hex(t.field10()), name);
    }
  }

  @Test
  void presenceStates() throws Exception {
    List<Map<String, Object>> rows = CommitmentDigestV6Test.rows(vector(), "presence_states");
    assertEquals(3, rows.size());
    for (Map<String, Object> r : rows) {
      String name = (String) r.get("name");
      ByteArrayOutputStream seq = new ByteArrayOutputStream();
      if (r.get("trailer") != null) {
        byte[] trailer = hex(r.get("trailer"));
        byte[] body = java.util.Arrays.copyOfRange(trailer, 5, trailer.length);
        seq.writeBytes(trailer);
        seq.writeBytes(governingV2(SeamCrypto.decodeGateBody(body).env()));
      }
      CommitmentTrailers t =
          SeamCrypto.decodeCommitmentTrailers(seq.toByteArray(), CommitmentVersion.V6);
      assertEquals(r.get("field_10"), hex(t.field10()), name);
    }
  }

  @Test
  void bodyRefusals() throws Exception {
    List<Map<String, Object>> rows = CommitmentDigestV6Test.rows(vector(), "body_refusals");
    assertEquals(36, rows.size());
    for (Map<String, Object> r : rows) {
      assertEquals("refused", r.get("expect"));
      String name = (String) r.get("name");
      byte[] body = hex(r.get("gate_body"));
      assertThrows(
          SeamCrypto.CommitmentRefusal.class, () -> SeamCrypto.decodeGateBody(body), name);
      assertThrows(SeamCrypto.CommitmentRefusal.class, () -> SeamCrypto.gateDigest(body), name);
    }
  }

  @Test
  void frameLengthOfMaxBe64RefusesAsTruncated() throws Exception {
    for (Map<String, Object> r : CommitmentDigestV6Test.rows(vector(), "body_refusals")) {
      if (!"frame_length_max_be64".equals(r.get("name"))) continue;
      SeamCrypto.CommitmentRefusal e =
          assertThrows(
              SeamCrypto.CommitmentRefusal.class,
              () -> SeamCrypto.decodeGateBody(hex(r.get("gate_body"))));
      assertEquals("gate_body_truncated", e.rule());
      return;
    }
    throw new AssertionError("no frame_length_max_be64 row");
  }

  @Test
  @SuppressWarnings("unchecked")
  void sequencesUnderV6() throws Exception {
    List<Map<String, Object>> rows = CommitmentDigestV6Test.rows(vector(), "sequences");
    assertEquals(13, rows.size());
    for (Map<String, Object> r : rows) {
      assertEquals("v6", r.get("scheme"));
      String name = (String) r.get("name");
      byte[] t = hex(r.get("trailers"));
      if ("refused".equals(r.get("expect"))) {
        assertThrows(
            IllegalArgumentException.class,
            () -> SeamCrypto.decodeCommitmentTrailers(t, CommitmentVersion.V6),
            name);
        continue;
      }
      Map<String, Object> e = (Map<String, Object>) r.get("expect");
      CommitmentTrailers d = SeamCrypto.decodeCommitmentTrailers(t, CommitmentVersion.V6);
      assertEquals(e.get("field_10"), hex(d.field10()), name);
      assertEquals(e.get("field_11"), hex(d.field11()), name);
      assertEquals(e.get("field_12"), hex(d.field12()), name);
    }
  }
}
