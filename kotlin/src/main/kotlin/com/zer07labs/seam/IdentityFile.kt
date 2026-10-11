package com.zer07labs.seam

import com.google.gson.GsonBuilder
import com.google.gson.JsonElement
import com.google.gson.JsonParseException
import com.google.gson.JsonParser
import com.google.gson.JsonPrimitive
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.channels.SeekableByteChannel
import java.nio.file.FileAlreadyExistsException
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.NoSuchFileException
import java.nio.file.OpenOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.FileAttribute
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom
import java.util.HexFormat

/**
 * The bootstrap file is missing, malformed, fails validation, or cannot be created. Always loud.
 * Named for parity with Python's `IdentityFileError` (seam-sdk#201); an unchecked exception, not a
 * `java.lang.Error`.
 */
class IdentityFileError(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/**
 * The process identity loaded from a bootstrap file. The seed is held only inside [agent]; [toString]
 * omits it.
 */
data class LoadedIdentity(val agent: Agent, val agentId: String, val tenant: String, val endpoint: String) {
    val aid: String get() = agent.aid

    override fun toString(): String =
        "LoadedIdentity(aid=$aid, agentId=$agentId, tenant=$tenant, endpoint=$endpoint)"
}

/**
 * Identity custody (seam-sdk#201): create and load the schema-v1 bootstrap file. Mirrors Python's
 * `seam_sdk/identity.py`, which owns the schema:
 *
 * ```
 * {"version": 1, "seed_hex": "<64 hex>", "agent_id": "...", "tenant": "...", "endpoint": "host:port"}
 * ```
 *
 * Unknown extra keys are ignored on load. One JSON file plus one env pointer ([ENV_POINTER]). The seed
 * leaves this object in exactly one direction: from disk into an [Agent] on load.
 */
object IdentityFile {
    const val ENV_POINTER = "SEAM_BOOTSTRAP_FILE"
    const val SCHEMA_VERSION = 1

    private val rng = SecureRandom()
    private val ownerRw = PosixFilePermissions.fromString("rw-------")

    /**
     * Load the process identity from [path], or from `$SEAM_BOOTSTRAP_FILE` when [path] is `null`.
     *
     * @throws IdentityFileError on any refusal
     */
    fun load(path: Path? = null): LoadedIdentity =
        loadResolved(path ?: System.getenv(ENV_POINTER)?.takeIf { it.isNotEmpty() }?.let { Path.of(it) })

    // Internal seam so tests can exercise the env fallback without mutating the process env.
    internal fun loadResolved(resolved: Path?): LoadedIdentity {
        if (resolved == null) {
            throw IdentityFileError(
                "no bootstrap file: pass a path or set \$$ENV_POINTER (one JSON + env pointer is the custody contract)",
            )
        }
        val text = try {
            Files.readString(resolved, Charsets.UTF_8)
        } catch (e: NoSuchFileException) {
            throw IdentityFileError("bootstrap file not found: $resolved", e)
        } catch (e: IOException) {
            throw IdentityFileError("cannot read bootstrap file $resolved: $e", e)
        }
        val top = try {
            JsonParser.parseString(text)
        } catch (e: JsonParseException) {
            throw IdentityFileError("bootstrap file is not valid JSON: $resolved: ${e.message}", e)
        }
        if (!top.isJsonObject) throw IdentityFileError("bootstrap file is not a JSON object: $resolved")
        val data = top.asJsonObject

        val version = data.get("version")
        if (!(version is JsonPrimitive && version.isNumber && version.asDouble == SCHEMA_VERSION.toDouble())) {
            throw IdentityFileError("bootstrap schema version $version unsupported (want $SCHEMA_VERSION)")
        }
        val seedHex = stringOrNull(data.get("seed_hex"))
        if (seedHex == null || seedHex.length != 64) {
            throw IdentityFileError("seed_hex must be exactly 64 hex chars (a 32-byte Ed25519 seed)")
        }
        val seed = try {
            HexFormat.of().parseHex(seedHex)
        } catch (e: IllegalArgumentException) {
            throw IdentityFileError("seed_hex is not valid hex", e)
        }
        val fields = listOf("agent_id", "tenant", "endpoint").associateWith { stringOrNull(data.get(it)) }
        val missing = fields.filterValues { it.isNullOrEmpty() }.keys
        if (missing.isNotEmpty()) {
            throw IdentityFileError("bootstrap file missing required field(s): ${missing.joinToString(", ")}")
        }
        return LoadedIdentity(Agent(seed), fields["agent_id"]!!, fields["tenant"]!!, fields["endpoint"]!!)
    }

    private fun stringOrNull(e: JsonElement?): String? =
        if (e is JsonPrimitive && e.isString) e.asString else null

    /** What [create] returns: the path written and the new agent's AID — never the seed. */
    data class Created(val path: Path, val aid: String)

    /**
     * Generate a new agent identity and write it to [path] as a schema-v1 bootstrap file. Returns
     * `(path, aid)`; the seed is never returned — load the file with [load] in the process that will use it.
     *
     * The write is atomic and never clobbers. The bytes go to a sibling temp file created with
     * `CREATE_NEW` (O_CREAT|O_EXCL) and `NOFOLLOW_LINKS` at mode 0600 — set at creation and re-applied
     * afterwards so the umask cannot widen it — are forced to disk (`fsync`), and are then published with
     * [Files.createLink], which fails if anything — a file, a directory, a symlink — already exists at
     * [path]. The temp name is then deleted and the directory forced. A reader never sees a partial file,
     * and an existing file is left byte-for-byte unchanged.
     *
     * Platform gaps versus Python: NIO has no `fchmod`, so the 0600 re-apply is by path (through
     * `NOFOLLOW_LINKS`) on the temp file this call just created under a random name. On a file system
     * without POSIX attributes (Windows) the temp file is created without a mode and the re-apply is
     * skipped, as Python's `os.fchmod` is absent there. A file system without hard links refuses loudly
     * rather than falling back to a clobbering rename.
     *
     * @throws IdentityFileError on any refusal
     */
    fun create(path: Path, agentId: String, tenant: String, endpoint: String): Created {
        for ((name, value) in listOf("agent_id" to agentId, "tenant" to tenant, "endpoint" to endpoint)) {
            if (value.isEmpty()) throw IdentityFileError("$name must be a non-empty string")
        }
        val agent = Agent.generate()
        val doc = linkedMapOf<String, Any>(
            "version" to SCHEMA_VERSION,
            "seed_hex" to HexFormat.of().formatHex(agent.seed()),
            "agent_id" to agentId,
            "tenant" to tenant,
            "endpoint" to endpoint,
        )
        val body = (GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(doc) + "\n")
            .toByteArray(Charsets.UTF_8)

        val dir = path.toAbsolutePath().parent
        val nonce = ByteArray(8).also { rng.nextBytes(it) }
        val tmp = dir.resolve(".${path.fileName}.${HexFormat.of().formatHex(nonce)}.tmp")
        val posix = "posix" in FileSystems.getDefault().supportedFileAttributeViews()

        val opts: Set<OpenOption> =
            setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)
        val attrs: Array<FileAttribute<*>> =
            if (posix) arrayOf(PosixFilePermissions.asFileAttribute(ownerRw)) else emptyArray()
        val ch: SeekableByteChannel = try {
            Files.newByteChannel(tmp, opts, *attrs)
        } catch (e: IOException) {
            // Not ours to delete: CREATE_NEW refused, so whatever is at `tmp` predates this call.
            throw IdentityFileError("cannot create bootstrap file in $dir: $e", e)
        }
        try {
            try {
                ch.use {
                    if (posix) {
                        Files.getFileAttributeView(tmp, PosixFileAttributeView::class.java, LinkOption.NOFOLLOW_LINKS)
                            .setPermissions(ownerRw)
                    }
                    val buf = ByteBuffer.wrap(body)
                    while (buf.hasRemaining()) it.write(buf)
                    (it as FileChannel).force(true)
                }
            } catch (e: IOException) {
                throw IdentityFileError("cannot write bootstrap file in $dir: $e", e)
            }
            try {
                Files.createLink(path, tmp)
            } catch (e: FileAlreadyExistsException) {
                throw IdentityFileError("refusing to overwrite existing path: $path", e)
            } catch (e: IOException) {
                throw IdentityFileError("cannot publish bootstrap file $path: $e", e)
            } catch (e: UnsupportedOperationException) {
                throw IdentityFileError("cannot publish bootstrap file $path: $e", e)
            }
        } finally {
            try {
                Files.deleteIfExists(tmp)
            } catch (_: IOException) {
                // best effort, as Python's unlink in `finally`
            }
        }
        if (posix) {
            try {
                FileChannel.open(dir, StandardOpenOption.READ).use { it.force(true) }
            } catch (e: IOException) {
                throw IdentityFileError("cannot fsync $dir: $e", e)
            }
        }
        return Created(path, agent.aid)
    }
}
