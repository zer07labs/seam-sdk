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
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Identity custody (seam-sdk#201): create and load the schema-v1 bootstrap file. Mirrors Python's
 * {@code seam_sdk/identity.py}, which owns the schema:
 *
 * <pre>{"version": 1, "seed_hex": "&lt;64 hex&gt;", "agent_id": "...", "tenant": "...", "endpoint": "host:port"}</pre>
 *
 * Unknown extra keys are ignored on load. One JSON file plus one env pointer ({@value #ENV_POINTER}).
 * The seed leaves this class in exactly one direction: from disk into an {@link Agent} on load.
 */
public final class IdentityFile {
  private IdentityFile() {}

  public static final String ENV_POINTER = "SEAM_BOOTSTRAP_FILE";
  public static final int SCHEMA_VERSION = 1;

  private static final SecureRandom RNG = new SecureRandom();
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

  /** Load the process identity from {@code $SEAM_BOOTSTRAP_FILE}. */
  public static LoadedIdentity load() {
    return load(null);
  }

  /** Load the process identity from {@code path}, or {@code $SEAM_BOOTSTRAP_FILE} when null. */
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
    byte[] seed;
    try {
      seed = HexFormat.of().parseHex(seedHex);
    } catch (IllegalArgumentException e) {
      throw new IdentityFileError("seed_hex is not valid hex", e);
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
    return new LoadedIdentity(
        new Agent(seed), fields.get("agent_id"), fields.get("tenant"), fields.get("endpoint"));
  }

  private static String stringOrNull(JsonElement e) {
    return e instanceof JsonPrimitive p && p.isString() ? p.getAsString() : null;
  }

  /**
   * Generate a new agent identity and write it to {@code path} as a schema-v1 bootstrap file. Returns
   * {@code (path, aid)}; the seed is never returned — load the file with {@link #load} in the process
   * that will use it.
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
