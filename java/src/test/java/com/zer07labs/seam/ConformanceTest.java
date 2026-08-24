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

  // -- Commitment-digest framing coverage (W5.4 / G4) --------------------------------------------
  //
  // `seam-commitment-digest:v1` is implemented byte-for-byte in ALL FIVE SDK languages -- the widest
  // fan-out of any framing in this repo -- and has no vector section of its own. It cannot get one
  // here either: seam-runtime's `sdk-digest-parity` job byte-diffs the whole of
  // conformance/vectors.json against its own emitter, so a block added on this side turns the
  // runtime's CI red. A vector for it must originate there.
  //
  // What IS available is stronger than it looks. `verifyTct` recomputes the digest and compares it
  // to the `seam-commitment-digest:` grant inside the runtime-signed JWS, so the vector already
  // carries a runtime-produced expected value. The gap was never coverage of the digest -- it was
  // coverage of the FIELD TUPLE: the pre-existing tests tampered `action` only, so exactly one of
  // the seven framing inputs was proven bound.
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
    List<Mutation> mutations =
        List.of(
            new Mutation(
                "id",
                new SeamCrypto.Commitment(
                    base.id() + "-x", base.action(), base.authority(),
                    base.supersedes(), base.authMethod(), base.trustBasis())),
            new Mutation(
                "action",
                new SeamCrypto.Commitment(
                    base.id(), "ALLOW", base.authority(),
                    base.supersedes(), base.authMethod(), base.trustBasis())),
            new Mutation(
                "authority",
                new SeamCrypto.Commitment(
                    base.id(), base.action(), base.authority() + "-x",
                    base.supersedes(), base.authMethod(), base.trustBasis())),
            // The vector's commitment omits `supersedes`, so absent is the branch already
            // exercised. This pins the PRESENT branch, which nothing covered: absent and present
            // must differ, or a supersession could be stripped from a sealed record undetected.
            new Mutation(
                "supersedes (absent -> present)",
                new SeamCrypto.Commitment(
                    base.id(), base.action(), base.authority(),
                    "k-previous", base.authMethod(), base.trustBasis())),
            new Mutation(
                "auth_method",
                new SeamCrypto.Commitment(
                    base.id(), base.action(), base.authority(),
                    base.supersedes(), base.authMethod() + "-x", base.trustBasis())),
            new Mutation(
                "trust_basis",
                new SeamCrypto.Commitment(
                    base.id(), base.action(), base.authority(),
                    base.supersedes(), base.authMethod(), base.trustBasis() + "-x")));

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
        new SeamCrypto.Commitment(
            base.id() + "\u0000" + base.action(), "", base.authority(),
            base.supersedes(), base.authMethod(), base.trustBasis());

    assertFalse(
        SeamCrypto.verifyTct(
            (String) t.get("issuer_aid"), (String) t.get("signed_artifact_jws"), shifted, NOW_S),
        "a boundary-shifted commitment verified -- the framing is separator-joined, not "
            + "length-prefixed, and one artifact can now verify under another's signature");
  }
}
