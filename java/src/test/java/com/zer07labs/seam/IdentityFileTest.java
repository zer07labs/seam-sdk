package com.zer07labs.seam;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** seam-sdk#201 — mirrors python/tests/test_identity_file.py. */
class IdentityFileTest {
  private static final String AGENT_ID = "ap-clerk";
  private static final String TENANT = "acme";
  private static final String ENDPOINT = "seam.example:443";

  private static boolean posix() {
    return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
  }

  private static IdentityFile.Created create(Path p) {
    return IdentityFile.create(p, AGENT_ID, TENANT, ENDPOINT);
  }

  @Test
  void generateIs32FreshCsprngBytes() {
    Agent a = Agent.generate();
    Agent b = Agent.generate();
    assertEquals(32, a.seed().length);
    assertFalse(java.util.Arrays.equals(a.seed(), b.seed()));
    assertNotEquals(a.aid(), b.aid());
  }

  @Test
  void roundTripAidEquality(@TempDir Path dir) {
    IdentityFile.Created c = create(dir.resolve("id.json"));
    IdentityFile.LoadedIdentity loaded = IdentityFile.load(c.path());
    assertEquals(c.aid(), loaded.aid());
    assertEquals(c.aid(), loaded.agent().aid());
    assertEquals(AGENT_ID, loaded.agentId());
    assertEquals(TENANT, loaded.tenant());
    assertEquals(ENDPOINT, loaded.endpoint());
  }

  @Test
  void createNeverReturnsTheSeed(@TempDir Path dir) throws Exception {
    IdentityFile.Created c = create(dir.resolve("id.json"));
    String seedHex = seedHexOf(c.path());
    assertFalse(c.toString().contains(seedHex));
    // The record's components are exactly (path, aid): there is no seed to reach.
    assertEquals(2, IdentityFile.Created.class.getRecordComponents().length);
  }

  @Test
  void toStringNeverPrintsTheSeed(@TempDir Path dir) throws Exception {
    IdentityFile.Created c = create(dir.resolve("id.json"));
    IdentityFile.LoadedIdentity loaded = IdentityFile.load(c.path());
    String seedHex = seedHexOf(c.path());
    assertFalse(loaded.toString().toLowerCase().contains(seedHex));
    assertFalse(loaded.agent().toString().toLowerCase().contains(seedHex));
    assertTrue(loaded.toString().contains(c.aid()));
  }

  @Test
  void fileIsSchemaV1WithTheAdaptersFieldNames(@TempDir Path dir) throws Exception {
    Path p = create(dir.resolve("id.json")).path();
    JsonObject data = JsonParser.parseString(Files.readString(p)).getAsJsonObject();
    assertEquals(
        List.of("version", "seed_hex", "agent_id", "tenant", "endpoint", "aid"),
        new ArrayList<>(data.keySet()));
    assertEquals(1, data.get("version").getAsInt());
    assertEquals(64, data.get("seed_hex").getAsString().length());
  }

  @Test
  void modeIs0600UnderUmask0(@TempDir Path dir) throws Exception {
    assumeTrue(posix(), "POSIX file modes");
    // The JVM cannot change its own umask, so the create runs in a child JVM started under umask 0.
    Path p = dir.resolve("id.json");
    String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
    Process proc =
        new ProcessBuilder(
                "/bin/sh",
                "-c",
                "umask 000 && exec \"$0\" -cp \"$1\" com.zer07labs.seam.IdentityFileTest\\$UmaskProbe \"$2\"",
                java,
                System.getProperty("java.class.path"),
                p.toString())
            .inheritIO()
            .start();
    assertEquals(0, proc.waitFor(), "child create failed");
    assertEquals(
        "rw-------",
        PosixFilePermissions.toString(Files.getPosixFilePermissions(p, LinkOption.NOFOLLOW_LINKS)));
  }

  /** Child-JVM entry point for {@link #modeIs0600UnderUmask0}. */
  static final class UmaskProbe {
    public static void main(String[] args) {
      IdentityFile.create(Path.of(args[0]), AGENT_ID, TENANT, ENDPOINT);
    }
  }

  @Test
  void secondCreateRefusesAndLeavesBytesUnchanged(@TempDir Path dir) throws Exception {
    Path p = create(dir.resolve("id.json")).path();
    byte[] before = Files.readAllBytes(p);
    IdentityFileError e = assertThrows(IdentityFileError.class, () -> create(p));
    assertTrue(e.getMessage().contains("refusing to overwrite"), e.getMessage());
    assertArrayEquals(before, Files.readAllBytes(p));
  }

  @Test
  void symlinkAtTheTargetIsRefused(@TempDir Path root) throws Exception {
    assumeTrue(posix(), "symlinks");
    for (boolean dangling : new boolean[] {false, true}) {
      Path dir = Files.createDirectory(root.resolve("d" + dangling));
      Path target = dir.resolve("elsewhere.json");
      if (!dangling) Files.writeString(target, "untouched");
      Path link = Files.createSymbolicLink(dir.resolve("id.json"), target);
      IdentityFileError e = assertThrows(IdentityFileError.class, () -> create(link));
      assertTrue(e.getMessage().contains("refusing to overwrite"), e.getMessage());
      assertTrue(Files.isSymbolicLink(link));
      if (dangling) {
        assertFalse(Files.exists(target));
      } else {
        assertEquals("untouched", Files.readString(target));
      }
    }
  }

  @Test
  void noTempFileIsLeftBehind(@TempDir Path dir) throws Exception {
    Path p = create(dir.resolve("id.json")).path();
    assertThrows(IdentityFileError.class, () -> create(p));
    try (Stream<Path> s = Files.list(dir)) {
      assertEquals(List.of("id.json"), s.map(x -> x.getFileName().toString()).toList());
    }
  }

  @Test
  void emptyFieldIsRefusedBeforeAnythingIsWritten(@TempDir Path dir) throws Exception {
    String[][] cases = {
      {"agent_id", "", TENANT, ENDPOINT},
      {"tenant", AGENT_ID, "", ENDPOINT},
      {"endpoint", AGENT_ID, TENANT, ""},
    };
    for (String[] c : cases) {
      IdentityFileError e =
          assertThrows(
              IdentityFileError.class,
              () -> IdentityFile.create(dir.resolve("id.json"), c[1], c[2], c[3]));
      assertTrue(e.getMessage().contains(c[0]), e.getMessage());
      try (Stream<Path> s = Files.list(dir)) {
        assertEquals(0, s.count());
      }
    }
  }

  @Test
  void anExistingAdaptersFileStillLoads(@TempDir Path dir) throws Exception {
    byte[] seed = new byte[32];
    for (int i = 0; i < 32; i++) seed[i] = (byte) i;
    Path p = dir.resolve("partner.json");
    Files.writeString(
        p,
        "{\"version\": 1, \"seed_hex\": \""
            + HexFormat.of().formatHex(seed)
            + "\", \"agent_id\": \"qa-confirm\", \"tenant\": \"t1\", \"endpoint\": \"localhost:50051\","
            + " \"comment\": \"extra keys are ignored\"}");
    IdentityFile.LoadedIdentity loaded = IdentityFile.load(p);
    assertArrayEquals(seed, loaded.agent().seed());
    assertEquals(new Agent(seed).aid(), loaded.aid());
  }

  @Test
  void nullPathFallsBackToTheEnvPointer(@TempDir Path dir) {
    // The JVM cannot set its own environment; load(null) reads $SEAM_BOOTSTRAP_FILE, and this pins
    // the refusal when it is unset plus the resolved-path half of the same code path.
    assumeTrue(System.getenv(IdentityFile.ENV_POINTER) == null, "SEAM_BOOTSTRAP_FILE is set");
    IdentityFileError e = assertThrows(IdentityFileError.class, () -> IdentityFile.load());
    assertTrue(e.getMessage().contains(IdentityFile.ENV_POINTER), e.getMessage());
    IdentityFile.Created c = create(dir.resolve("id.json"));
    assertEquals(c.aid(), IdentityFile.loadResolved(c.path()).aid());
  }

  @Test
  void malformedFilesAreLoud(@TempDir Path dir) throws Exception {
    String[][] cases = {
      {"{\"version\": 2}", "version"},
      {"{\"version\": 1, \"seed_hex\": \"ab\"}", "64 hex"},
      {"{\"version\": 1, \"seed_hex\": \"" + "zz".repeat(32) + "\"}", "not valid hex"},
      {
        "{\"version\": 1, \"seed_hex\": \"" + "ab".repeat(32) + "\", \"agent_id\": \"a\", \"tenant\": \"t\"}",
        "endpoint"
      },
      {"[1, 2]", "JSON object"},
      {"{not json", "not valid JSON"},
    };
    int i = 0;
    for (String[] c : cases) {
      Path p = dir.resolve("bad" + i++ + ".json");
      Files.writeString(p, c[0]);
      IdentityFileError e = assertThrows(IdentityFileError.class, () -> IdentityFile.load(p));
      assertTrue(e.getMessage().contains(c[1]), c[0] + " -> " + e.getMessage());
    }
  }

  @Test
  void missingFileIsLoud(@TempDir Path dir) {
    IdentityFileError e =
        assertThrows(IdentityFileError.class, () -> IdentityFile.load(dir.resolve("nope.json")));
    assertTrue(e.getMessage().contains("not found"), e.getMessage());
  }

  // seam-sdk#274 (D-AID-RECORD): a created file records its AID; a recorded aid is verified on load.

  private static final String FIXTURE_SEED_HEX =
      "ddc1524b29efe5bc1b9e9ea141b2a4740ba3e4d52f781afa3c1ffb3a3970580c";
  private static final String FIXTURE_AID =
      "aid:pubkey:ed25519:9x_uM2PCzXE8pt6di2RwwKCkod7W5kctdLdoIVtKep4";

  @Test
  void createdFileRecordsTheReturnedAid(@TempDir Path dir) throws Exception {
    IdentityFile.Created c = create(dir.resolve("id.json"));
    JsonObject data = JsonParser.parseString(Files.readString(c.path())).getAsJsonObject();
    assertEquals(c.aid(), data.get("aid").getAsString());
    assertEquals(c.aid(), new Agent(HexFormat.of().parseHex(seedHexOf(c.path()))).aid());
  }

  private static Path writeWithAid(Path dir, String name, String aidJson) throws Exception {
    Path p = dir.resolve(name + ".json");
    Files.writeString(
        p,
        "{\"version\": 1, \"seed_hex\": \""
            + FIXTURE_SEED_HEX
            + "\", \"agent_id\": \"a\", \"tenant\": \"t\", \"endpoint\": \"e:1\", \"aid\": "
            + aidJson
            + "}");
    return p;
  }

  @Test
  void aBadRecordedAidIsRefused(@TempDir Path dir) throws Exception {
    byte[] other = new byte[32];
    for (int i = 0; i < 32; i++) other[i] = (byte) i;
    String trimmed = FIXTURE_AID.substring(0, FIXTURE_AID.length() - 1);
    String[][] cases = {
      {"mismatch", "\"" + new Agent(other).aid() + "\"", "recorded aid does not match seed_hex"},
      {"short", "\"" + trimmed + "\"", "aid is malformed"},
      {"long", "\"" + FIXTURE_AID + "A\"", "aid is malformed"},
      {"wrong-alg", "\"" + FIXTURE_AID.replace("ed25519", "ed448") + "\"", "aid is malformed"},
      {"non-b64url", "\"" + trimmed + "=\"", "aid is malformed"},
      {"empty", "\"\"", "aid is malformed"},
      {"null", "null", "aid is malformed"},
      {"number", "42", "aid is malformed"},
      {"list", "[\"" + FIXTURE_AID + "\"]", "aid is malformed"},
    };
    for (String[] c : cases) {
      Path p = writeWithAid(dir, c[0], c[1]);
      IdentityFileError e = assertThrows(IdentityFileError.class, () -> IdentityFile.load(p));
      assertEquals(c[2], e.getMessage(), c[0]);
    }
  }

  @Test
  void aMatchingRecordedAidLoads(@TempDir Path dir) throws Exception {
    Path p = writeWithAid(dir, "ok", "\"" + FIXTURE_AID + "\"");
    assertEquals(FIXTURE_AID, IdentityFile.load(p).aid());
  }

  @Test
  void theSharedAidFixtureLoadsWithItsRecordedAid() throws Exception {
    // Written by Python's create_identity_file (seam-sdk#274); the TS suite pins its bytes.
    Path p = Path.of("..", "ts", "tests", "fixtures", "identity_v1_aid_python.json");
    JsonObject data = JsonParser.parseString(Files.readString(p)).getAsJsonObject();
    assertEquals(FIXTURE_AID, data.get("aid").getAsString());
    IdentityFile.LoadedIdentity loaded = IdentityFile.load(p);
    assertEquals(FIXTURE_AID, loaded.aid());
    assertEquals(FIXTURE_SEED_HEX, HexFormat.of().formatHex(loaded.agent().seed()));
    assertEquals("ap-clerk", loaded.agentId());
    assertEquals("acm\u00e9", loaded.tenant());
    assertEquals("seam.example:443", loaded.endpoint());
  }

  @Test
  void aLegacyFileWithoutAidLoadsUnchanged(@TempDir Path dir) throws Exception {
    Path p = dir.resolve("legacy.json");
    Files.writeString(
        p,
        "{\"version\": 1, \"seed_hex\": \""
            + FIXTURE_SEED_HEX
            + "\", \"agent_id\": \"ap-clerk\", \"tenant\": \"acme\", \"endpoint\": \"seam.example:443\"}");
    assertEquals(FIXTURE_AID, IdentityFile.load(p).aid());
  }

  private static String seedHexOf(Path p) throws Exception {
    return JsonParser.parseString(Files.readString(p))
        .getAsJsonObject()
        .get("seed_hex")
        .getAsString();
  }
}
