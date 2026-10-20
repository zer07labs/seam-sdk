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
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters

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
 * The public facts of a bootstrap file: no seed, no [Agent], no signing capability. Returned by
 * [IdentityFile.loadFacts] (seam-sdk#274).
 *
 * The four fields are the file's **claims**; the verifier is [IdentityFile.load]. In particular [aid] is
 * the file's recorded `aid` when it has one, unverified against the seed.
 */
data class IdentityFacts(val agentId: String, val tenant: String, val endpoint: String, val aid: String)

/**
 * Identity custody (seam-sdk#201): create and load the schema-v1 bootstrap file. Mirrors Python's
 * `seam_sdk/identity.py`, which owns the schema:
 *
 * ```
 * {"version": 1, "seed_hex": "<64 hex>", "agent_id": "...", "tenant": "...", "endpoint": "host:port",
 *  "aid": "aid:pubkey:ed25519:<43 b64url>"}
 * ```
 *
 * `aid` is optional (seam-sdk#274, D-AID-RECORD): [create] records the derived AID as the last key, and
 * the schema version stays 1. A file without it loads unchanged. When it is present, [load] verifies it
 * against the AID derived from `seed_hex` and refuses a wrong shape or a mismatch. Every loader since
 * #201 ignores unknown keys, so such a file also loads in older releases.
 *
 * Unknown extra keys are ignored on load. One JSON file plus one env pointer ([ENV_POINTER]). The seed
 * leaves this object in exactly one direction: from disk into an [Agent] on load. [loadFacts]
 * (seam-sdk#274) reads the same file's public facts and returns no signing capability at all. Both
 * loaders run one shared validator, so they refuse the same bad file with the same message.
 */
object IdentityFile {
    const val ENV_POINTER = "SEAM_BOOTSTRAP_FILE"
    const val SCHEMA_VERSION = 1

    private val rng = SecureRandom()

    // The shape of a recorded aid: the Ed25519 AID form, 32 bytes as unpadded b64url.
    private val aidShape = Regex("aid:pubkey:ed25519:[A-Za-z0-9_-]{43}")

    // A seed is exactly 64 ASCII hex digits: no whitespace, no sign, no 0x.
    private val seedShape = Regex("[0-9a-fA-F]{64}")

    /**
     * The one place a seed is hex-decoded on load. Internal and mutable only so tests can prove
     * [loadFacts] never calls it on a file that records `aid`; its input has passed the shared validator.
     */
    @Volatile
    internal var seedDecoder: (String) -> ByteArray = { HexFormat.of().parseHex(it) }

    // What the shared validator hands both loaders: seed_hex as an opaque, shape-checked string, and the
    // recorded aid (null when the file has none).
    private class Validated(
        val seedHex: String,
        val agentId: String,
        val tenant: String,
        val endpoint: String,
        val aid: String?,
    )
    private val ownerRw = PosixFilePermissions.fromString("rw-------")

    /**
     * Load the process identity from [path], or from `$SEAM_BOOTSTRAP_FILE` when [path] is `null`.
     *
     * A recorded `aid` is verified, not trusted: it must have the AID shape (else `"aid is malformed"`)
     * and equal the AID derived from `seed_hex` (else `"recorded aid does not match seed_hex"`). A file
     * without `aid` loads as before.
     *
     * @throws IdentityFileError on any refusal
     */
    fun load(path: Path? = null): LoadedIdentity =
        loadResolved(path ?: System.getenv(ENV_POINTER)?.takeIf { it.isNotEmpty() }?.let { Path.of(it) })

    // Internal seam so tests can exercise the env fallback without mutating the process env.
    internal fun loadResolved(resolved: Path?): LoadedIdentity {
        val v = readAndValidate(resolved)
        val agent = Agent(decodeSeed(v.seedHex))
        if (v.aid != null && v.aid != agent.aid) {
            throw IdentityFileError("recorded aid does not match seed_hex")
        }
        return LoadedIdentity(agent, v.agentId, v.tenant, v.endpoint)
    }

    /**
     * Read the public facts of the bootstrap file at [path], or `$SEAM_BOOTSTRAP_FILE` when [path] is
     * `null` (seam-sdk#274).
     *
     * For a consumer that shows who an agent is but never signs as it. It runs the **same checks, in the
     * same order, with the same messages** as [load] (one shared validator), so a file one refuses the
     * other refuses identically. It never constructs an [Agent] and returns no seed, no key and no
     * signing capability.
     *
     * [IdentityFacts.aid] is always set:
     * - **The file records `aid`** (every file written since #274): it is returned as the file's
     *   **claim**, shape-checked but **not** verified against `seed_hex`, and the seed is never
     *   hex-decoded. A hand-edited `aid` that does not match its seed is returned here, and refused by
     *   [load], which is the verifier.
     * - **A legacy file without `aid`**: it is derived transiently from the seed. The public key is
     *   computed and encoded; only the string is returned.
     *
     * "Seed-free" therefore means no signing capability returned, and no seed decode on a file that
     * records `aid`. It does not mean the seed is never read: parsing the JSON reads it as text.
     *
     * @throws IdentityFileError on any refusal
     */
    fun loadFacts(path: Path? = null): IdentityFacts =
        loadFactsResolved(path ?: System.getenv(ENV_POINTER)?.takeIf { it.isNotEmpty() }?.let { Path.of(it) })

    // Internal seam, as loadResolved.
    internal fun loadFactsResolved(resolved: Path?): IdentityFacts {
        val v = readAndValidate(resolved)
        val aid = v.aid ?: run {
            val seed = decodeSeed(v.seedHex)
            try {
                SeamCrypto.aidFromPubkey(Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded)
            } finally {
                // Best-effort hygiene: the key parameters hold their own copy, which is not reachable here.
                seed.fill(0)
            }
        }
        return IdentityFacts(v.agentId, v.tenant, v.endpoint, aid)
    }

    private fun decodeSeed(seedHex: String): ByteArray = try {
        seedDecoder(seedHex)
    } catch (e: IllegalArgumentException) {
        throw IdentityFileError("seed_hex is not valid hex", e)
    }

    // The one validator both loaders run (D-FACTS-CHECKS): same checks, same order, same messages. No
    // seed bytes are produced here.
    private fun readAndValidate(resolved: Path?): Validated {
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
        if (!seedShape.matches(seedHex)) throw IdentityFileError("seed_hex is not valid hex")
        val fields = listOf("agent_id", "tenant", "endpoint").associateWith { stringOrNull(data.get(it)) }
        val missing = fields.filterValues { it.isNullOrEmpty() }.keys
        if (missing.isNotEmpty()) {
            throw IdentityFileError("bootstrap file missing required field(s): ${missing.joinToString(", ")}")
        }
        val hasAid = data.has("aid")
        val recordedAid = stringOrNull(data.get("aid"))
        if (hasAid && (recordedAid == null || !aidShape.matches(recordedAid))) {
            throw IdentityFileError("aid is malformed")
        }
        return Validated(seedHex, fields["agent_id"]!!, fields["tenant"]!!, fields["endpoint"]!!, recordedAid)
    }

    private fun stringOrNull(e: JsonElement?): String? =
        if (e is JsonPrimitive && e.isString) e.asString else null

    /** What [create] returns: the path written and the new agent's AID — never the seed. */
    data class Created(val path: Path, val aid: String)

    /**
     * Generate a new agent identity and write it to [path] as a schema-v1 bootstrap file. Returns
     * `(path, aid)`; the seed is never returned — load the file with [load] in the process that will use it.
     * The file also records that `aid` as its last key, so the public identity can be read back without
     * the seed.
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
            "aid" to agent.aid,
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
