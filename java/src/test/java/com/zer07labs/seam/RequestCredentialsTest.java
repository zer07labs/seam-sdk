package com.zer07labs.seam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.junit.jupiter.api.Test;

/** The {@code seam-request-call-v1} credential (#508) and the bound-agent default (#202). */
class RequestCredentialsTest {
  private static final Type MAP = new TypeToken<Map<String, Object>>() {}.getType();
  private static final String GET_DECISION = "/seam.api.v1.SeamCoordination/GetDecision";
  private static final String SUBMIT_VOTE = "/seam.api.v1.SeamCoordination/SubmitVote";

  @Test
  @SuppressWarnings("unchecked")
  void requestSigPayloadMatchesVector() throws Exception {
    Map<String, Object> v =
        new Gson()
            .fromJson(
                Files.readString(Path.of("..", "conformance", "request_sig_payload_vector.json")),
                MAP);
    assertEquals(SeamCrypto.REQUEST_SIG_CONTEXT, v.get("domain"));
    List<Map<String, Object>> cases = (List<Map<String, Object>>) v.get("cases");
    assertFalse(cases.isEmpty(), "vector is empty");
    HexFormat hex = HexFormat.of();
    for (Map<String, Object> c : cases) {
      String label = c.get("name") + ": " + c.get("why");
      byte[] payload =
          SeamCrypto.requestSigPayload(
              hex.parseHex((String) c.get("ticket_hex")),
              (String) c.get("rpc_full_name"),
              (String) c.get("resource_id"),
              (String) c.get("body_digest"));
      assertEquals(c.get("payload_hex"), hex.formatHex(payload), label);
      if (c.containsKey("body_input_hex")) {
        assertEquals(
            c.get("body_digest"),
            SeamCrypto.bodyDigest(hex.parseHex((String) c.get("body_input_hex"))),
            label);
      }
    }
  }

  private static Agent agentOf(int b) {
    byte[] s = new byte[32];
    Arrays.fill(s, (byte) b);
    return new Agent(s);
  }

  private static RequestCredentials.TicketSource recording(List<String> asked) {
    return a -> {
      asked.add(a.aid());
      return ("ticket-for-" + a.aid()).getBytes(StandardCharsets.UTF_8);
    };
  }

  private static boolean verifies(
      Agent a, Map<String, byte[]> md, String rpc, String resourceId, String digest) {
    byte[] pub = new Ed25519PrivateKeyParameters(a.seed(), 0).generatePublicKey().getEncoded();
    byte[] msg =
        SeamCrypto.requestSigPayload(md.get(RequestCredentials.TICKET_KEY), rpc, resourceId, digest);
    Ed25519Signer v = new Ed25519Signer();
    v.init(false, new Ed25519PublicKeyParameters(pub, 0));
    v.update(msg, 0, msg.length);
    return v.verifySignature(md.get(RequestCredentials.CALL_SIG_KEY));
  }

  @Test
  void boundAgentCredentialIsAttachedByDefault() {
    Agent bound = agentOf(1);
    List<String> asked = new ArrayList<>();
    Map<String, byte[]> md =
        new RequestCredentials(bound, recording(asked)).metadata(null, GET_DECISION, "dec:1", null);
    assertEquals(2, md.size());
    assertArrayEquals(
        ("ticket-for-" + bound.aid()).getBytes(StandardCharsets.UTF_8),
        md.get(RequestCredentials.TICKET_KEY));
    assertTrue(verifies(bound, md, GET_DECISION, "dec:1", ""));
    assertEquals(List.of(bound.aid()), asked);
  }

  @Test
  void explicitCredentialWinsOverTheBoundAgent() {
    Agent bound = agentOf(1);
    Agent explicit = agentOf(2);
    List<String> asked = new ArrayList<>();
    byte[] body = {0x0a, 0x01, 0x78};
    Map<String, byte[]> md =
        new RequestCredentials(bound, recording(asked)).metadata(explicit, SUBMIT_VOTE, "", body);
    String digest = SeamCrypto.bodyDigest(body);
    assertTrue(verifies(explicit, md, SUBMIT_VOTE, "", digest), "explicit credential did not sign");
    assertFalse(verifies(bound, md, SUBMIT_VOTE, "", digest), "bound agent signed instead");
    assertEquals(List.of(explicit.aid()), asked);
  }

  @Test
  void noAgentMeansNoCredential() {
    List<String> asked = new ArrayList<>();
    RequestCredentials unbound = new RequestCredentials(null, recording(asked));
    assertTrue(unbound.metadata(null, GET_DECISION, "dec:1", null).isEmpty());
    assertTrue(asked.isEmpty(), "an unbound client admitted anyway");
    // Opt-in per call still works on an unbound instance, as before #202.
    assertEquals(2, unbound.metadata(agentOf(3), GET_DECISION, "dec:1", null).size());
  }
}
