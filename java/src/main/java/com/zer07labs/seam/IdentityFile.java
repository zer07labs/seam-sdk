package com.zer07labs.seam;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;

/**
 * Identity custody (seam-sdk#201): create and load the schema-v1 bootstrap file. Mirrors Python's
 * {@code seam_sdk/identity.py}, which owns the schema:
 *
 * <pre>{"version": 1, "seed_hex": "&lt;64 hex&gt;", "agent_id": "...", "tenant": "...", "endpoint": "host:port",
 *  "aid": "aid:pubkey:ed25519:&lt;43 b64url&gt;"}</pre>
 *
 * <p>{@code aid} is optional (seam-sdk#274, D-AID-RECORD): {@link #create} records the derived AID as
 * the last key, and the schema version stays 1. A file without it loads unchanged. When it is present,
 * {@link #load} verifies it against the AID derived from {@code seed_hex} and refuses a wrong shape or
 * a mismatch. Every loader since #201 ignores unknown keys, so such a file also loads in older
 * releases.
 *
 * <p>Unknown extra keys are ignored on load. One JSON file plus one env pointer ({@value #ENV_POINTER}).
 * The seed leaves this class in exactly one direction: from disk into an {@link Agent} on load. {@link
 * #loadFacts} (seam-sdk#274) reads the same file's public facts and returns no signing capability at
 * all. Both loaders run one shared validator, so they refuse the same bad file with the same message.
 */
public final class IdentityFile {
  private IdentityFile() {}

  public static final String ENV_POINTER = "SEAM_BOOTSTRAP_FILE";
  public static final int SCHEMA_VERSION = 1;

  private static final SecureRandom RNG = new SecureRandom();
  // The shape of a recorded aid: the Ed25519 AID form, 32 bytes as unpadded b64url.
  private static final Pattern AID_SHAPE = Pattern.compile("aid:pubkey:ed25519:[A-Za-z0-9_-]{43}");
  // A seed is exactly 64 ASCII hex digits: no whitespace, no sign, no 0x.
  private static final Pattern SEED_SHAPE = Pattern.compile("[0-9a-fA-F]{64}");

  /**
   * The one place a seed is hex-decoded on load. Package-private and mutable only so tests can prove
   * {@link #loadFacts} never calls it on a file that records {@code aid}; its input has passed the
   * shared validator.
   */
  static volatile Function<String, byte[]> seedDecoder = hex -> HexFormat.of().parseHex(hex);
  private static final Set<PosixFilePermission> OWNER_RW = PosixFilePermissions.fromString("rw-------");

  /** What {@link #create} returns: the path written and the new agent's AID — never the seed. */
  public record Created(Path path, String aid) {}

  /**
   * The process identity loaded from a bootstrap file. The seed is held only inside {@code agent},
   * and {@link #toString} omits it.
   */
  public record LoadedIdentity(Agent agent, String agentId, String tenant, String endpoint) {
    public String aid() {
      return agent.aid();
    }

    @Override
    public String toString() {
      return "LoadedIdentity(aid="
          + aid()
          + ", agentId="
          + agentId
          + ", tenant="
          + tenant
          + ", endpoint="
          + endpoint
          + ")";
    }
  }

  /**
   * The public facts of a bootstrap file: no seed, no {@link Agent}, no signing capability. Returned by
   * {@link #loadFacts}.
   *
   * <p>The four fields are the file's <b>claims</b>; the verifier is {@link #load}. In particular
   * {@code aid} is the file's recorded {@code aid} when it has one, unverified against the seed.
   */
  public record IdentityFacts(String agentId, String tenant, String endpoint, String aid) {
    @Override
    public String toString() {
      return "IdentityFacts(agentId="
          + agentId
          + ", tenant="
          + tenant
          + ", endpoint="
          + endpoint
          + ", aid="
          + aid
          + ")";
    }
  }

  // What the shared validator hands both loaders: seed_hex as an opaque, shape-checked string, and the
  // recorded aid (null when the file has none).
  private record Validated(
      String seedHex, String agentId, String tenant, String endpoint, String aid) {}

  /** Load the process identity from {@code $SEAM_BOOTSTRAP_FILE}. */
  public static LoadedIdentity load() {
    return load(null);
  }

  /**
   * Load the process identity from {@code path}, or {@code $SEAM_BOOTSTRAP_FILE} when null.
   *
   * <p>A recorded {@code aid} is verified, not trusted: it must have the AID shape (else {@code "aid
   * is malformed"}) and equal the AID derived from {@code seed_hex} (else {@code "recorded aid does
   * not match seed_hex"}). A file without {@code aid} loads as before.
   */
  public static LoadedIdentity load(Path path) {
    Path resolved = path;
    if (resolved == null) {
      String env = System.getenv(ENV_POINTER);
      if (env != null && !env.isEmpty()) resolved = Path.of(env);
    }
    return loadResolved(resolved);
  }

  // Package-private seam so tests can exercise the env fallback without mutating the process env.
  static LoadedIdentity loadResolved(Path resolved) {
    Validated v = readAndValidate(resolved);
    Agent agent = new Agent(decodeSeed(v.seedHex()));
    if (v.aid() != null && !v.aid().equals(agent.aid())) {
      throw new IdentityFileError("recorded aid does not match seed_hex");
    }
    return new LoadedIdentity(agent, v.agentId(), v.tenant(), v.endpoint());
  }

  /** Read the public facts of the bootstrap file at {@code $SEAM_BOOTSTRAP_FILE}. */
  public static IdentityFacts loadFacts() {
    return loadFacts(null);
  }

  /**
   * Read the public facts of the bootstrap file at {@code path}, or {@code $SEAM_BOOTSTRAP_FILE} when
   * null (seam-sdk#274).
   *
   * <p>For a consumer that shows who an agent is but never signs as it. It runs the <b>same checks, in
   * the same order, with the same messages</b> as {@link #load} (one shared validator), so a file one
   * refuses the other refuses identically. It never constructs an {@link Agent} and returns no seed, no
   * key and no signing capability.
   *
   * <p>{@code aid} is always set:
   *
   * <ul>
   *   <li><b>The file records {@code aid}</b> (every file written since #274): it is returned as the
   *       file's <b>claim</b>, shape-checked but <b>not</b> verified against {@code seed_hex}, and the
   *       seed is never hex-decoded. A hand-edited {@code aid} that does not match its seed is returned
   *       here, and refused by {@link #load}, which is the verifier.
   *   <li><b>A legacy file without {@code aid}</b>: it is derived transiently from the seed. The public
   *       key is computed and encoded; only the string is returned.
   * </ul>
   *
   * <p>"Seed-free" therefore means no signing capability returned, and no seed decode on a file that
   * records {@code aid}. It does not mean the seed is never read: parsing the JSON reads it as text.
   *
   * @throws IdentityFileError on any refusal
   */
  public static IdentityFacts loadFacts(Path path) {
    Path resolved = path;
    if (resolved == null) {
      String env = System.getenv(ENV_POINTER);
      if (env != null && !env.isEmpty()) resolved = Path.of(env);
    }
    return loadFactsResolved(resolved);
  }

  // Package-private seam, as loadResolved.
  static IdentityFacts loadFactsResolved(Path resolved) {
    Validated v = readAndValidate(resolved);
    String aid = v.aid();
    if (aid == null) {
      byte[] seed = decodeSeed(v.seedHex());
      try {
        aid =
            SeamCrypto.aidFromPubkey(
                new Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().getEncoded());
      } finally {
        // Best-effort hygiene: the key parameters hold their own copy, which is not reachable here.
        Arrays.fill(seed, (byte) 0);
      }
    }
    return new IdentityFacts(v.agentId(), v.tenant(), v.endpoint(), aid);
  }

  private static byte[] decodeSeed(String seedHex) {
    try {
      return seedDecoder.apply(seedHex);
    } catch (IllegalArgumentException e) {
      throw new IdentityFileError("seed_hex is not valid hex", e);
    }
  }

  // The one validator both loaders run (D-FACTS-CHECKS): same checks, same order, same messages. No
  // seed bytes are produced here.
  private static Validated readAndValidate(Path resolved) {
    if (resolved == null) {
      throw new IdentityFileError(
          "no bootstrap file: pass a path or set $"
              + ENV_POINTER
              + " (one JSON + env pointer is the custody contract)");
    }
    String text;
    try {
      text = Files.readString(resolved, StandardCharsets.UTF_8);
    } catch (NoSuchFileException e) {
      throw new IdentityFileError("bootstrap file not found: " + resolved, e);
    } catch (IOException e) {
      throw new IdentityFileError("cannot read bootstrap file " + resolved + ": " + e, e);
    }
    JsonElement top;
    try {
      top = JsonParser.parseString(text);
    } catch (JsonParseException e) {
      throw new IdentityFileError(
          "bootstrap file is not valid JSON: " + resolved + ": " + e.getMessage(), e);
    }
    if (!top.isJsonObject()) {
      throw new IdentityFileError("bootstrap file is not a JSON object: " + resolved);
    }
    JsonObject data = top.getAsJsonObject();

    JsonElement version = data.get("version");
    if (!(version instanceof JsonPrimitive p && p.isNumber() && p.getAsDouble() == SCHEMA_VERSION)) {
      throw new IdentityFileError(
          "bootstrap schema version " + version + " unsupported (want " + SCHEMA_VERSION + ")");
    }
    String seedHex = stringOrNull(data.get("seed_hex"));
    if (seedHex == null || seedHex.length() != 64) {
      throw new IdentityFileError("seed_hex must be exactly 64 hex chars (a 32-byte Ed25519 seed)");
    }
    if (!SEED_SHAPE.matcher(seedHex).matches()) {
      throw new IdentityFileError("seed_hex is not valid hex");
    }

    Map<String, String> fields = new LinkedHashMap<>();
    List<String> missing = new ArrayList<>();
    for (String k : List.of("agent_id", "tenant", "endpoint")) {
      String v = stringOrNull(data.get(k));
      if (v == null || v.isEmpty()) missing.add(k);
      fields.put(k, v);
    }
    if (!missing.isEmpty()) {
      throw new IdentityFileError(
          "bootstrap file missing required field(s): " + String.join(", ", missing));
    }
    boolean hasAid = data.has("aid");
    String recordedAid = stringOrNull(data.get("aid"));
    if (hasAid && (recordedAid == null || !AID_SHAPE.matcher(recordedAid).matches())) {
      throw new IdentityFileError("aid is malformed");
    }
    return new Validated(
        seedHex, fields.get("agent_id"), fields.get("tenant"), fields.get("endpoint"), recordedAid);
  }

  private static String stringOrNull(JsonElement e) {
    return e instanceof JsonPrimitive p && p.isString() ? p.getAsString() : null;
  }

  /**
   * Generate a new agent identity and write it to {@code path} as a schema-v1 bootstrap file. Returns
   * {@code (path, aid)}; the seed is never returned — load the file with {@link #load} in the process
   * that will use it. The file also records that {@code aid} as its last key, so the public identity
   * can be read back without the seed.
   *
   * <p>The write is atomic and never clobbers. The bytes go to a sibling temp file created with {@code
   * CREATE_NEW} (O_CREAT|O_EXCL) and {@code NOFOLLOW_LINKS} at mode 0600 — the mode is set at creation
   * and re-applied afterwards so the umask cannot widen it — are forced to disk ({@code fsync}), and
   * are then published with {@link Files#createLink}, which fails if anything — a file, a directory, a
   * symlink — already exists at {@code path}. The temp name is then deleted and the directory forced.
   * A reader never sees a partial file, and an existing file is left byte-for-byte unchanged.
   *
   * <p>Platform gaps versus Python: NIO has no {@code fchmod}, so the 0600 re-apply is by path
   * (through {@code NOFOLLOW_LINKS}) on the temp file this call just created under a random name. On a
   * file system without POSIX attributes (Windows) the temp file is created without a mode and the
   * re-apply is skipped, as Python's {@code os.fchmod} is absent there. A file system without hard
   * links refuses loudly rather than falling back to a clobbering rename.
   *
   * @throws IdentityFileError on any refusal
   */
  public static Created create(Path path, String agentId, String tenant, String endpoint) {
    String[][] required = {{"agent_id", agentId}, {"tenant", tenant}, {"endpoint", endpoint}};
    for (String[] f : required) {
      if (f[1] == null || f[1].isEmpty()) {
        throw new IdentityFileError(f[0] + " must be a non-empty string");
      }
    }
    Agent agent = Agent.generate();
    Map<String, Object> doc = new LinkedHashMap<>();
    doc.put("version", SCHEMA_VERSION);
    doc.put("seed_hex", HexFormat.of().formatHex(agent.seed()));
    doc.put("agent_id", agentId);
    doc.put("tenant", tenant);
    doc.put("endpoint", endpoint);
    doc.put("aid", agent.aid());
    byte[] body =
        (new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(doc) + "\n")
            .getBytes(StandardCharsets.UTF_8);

    Path dir = path.toAbsolutePath().getParent();
    byte[] nonce = new byte[8];
    RNG.nextBytes(nonce);
    Path tmp =
        dir.resolve("." + path.getFileName() + "." + HexFormat.of().formatHex(nonce) + ".tmp");
    boolean posix = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");

    Set<OpenOption> opts =
        Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
    FileAttribute<?>[] attrs =
        posix
            ? new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(OWNER_RW)}
            : new FileAttribute<?>[0];
    SeekableByteChannel ch;
    try {
      ch = Files.newByteChannel(tmp, opts, attrs);
    } catch (IOException e) {
      // Not ours to delete: CREATE_NEW refused, so whatever is at `tmp` predates this call.
      throw new IdentityFileError("cannot create bootstrap file in " + dir + ": " + e, e);
    }
    try {
      try (ch) {
        if (posix) {
          Files.getFileAttributeView(tmp, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS)
              .setPermissions(OWNER_RW);
        }
        ByteBuffer buf = ByteBuffer.wrap(body);
        while (buf.hasRemaining()) ch.write(buf);
        ((FileChannel) ch).force(true);
      } catch (IOException e) {
        throw new IdentityFileError("cannot write bootstrap file in " + dir + ": " + e, e);
      }
      try {
        Files.createLink(path, tmp);
      } catch (FileAlreadyExistsException e) {
        throw new IdentityFileError("refusing to overwrite existing path: " + path, e);
      } catch (IOException | UnsupportedOperationException e) {
        throw new IdentityFileError("cannot publish bootstrap file " + path + ": " + e, e);
      }
    } finally {
      try {
        Files.deleteIfExists(tmp);
      } catch (IOException ignored) {
        // best effort, as Python's unlink in `finally`
      }
    }
    if (posix) fsyncDir(dir);
    return new Created(path, agent.aid());
  }

  private static void fsyncDir(Path dir) {
    try (FileChannel ch = FileChannel.open(dir, StandardOpenOption.READ)) {
      ch.force(true);
    } catch (IOException e) {
      throw new IdentityFileError("cannot fsync " + dir + ": " + e, e);
    }
  }
}
