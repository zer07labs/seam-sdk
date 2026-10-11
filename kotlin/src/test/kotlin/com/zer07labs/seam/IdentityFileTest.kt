package com.zer07labs.seam

import com.google.gson.JsonParser
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.HexFormat
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.name
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.io.TempDir

private const val AGENT_ID = "ap-clerk"
private const val TENANT = "acme"
private const val ENDPOINT = "seam.example:443"

/** Child-JVM entry point for [IdentityFileTest.modeIs0600UnderUmask0]. */
object UmaskProbe {
    @JvmStatic
    fun main(args: Array<String>) {
        IdentityFile.create(Path.of(args[0]), AGENT_ID, TENANT, ENDPOINT)
    }
}

/** seam-sdk#201 — mirrors python/tests/test_identity_file.py. */
class IdentityFileTest {
    private fun posix() = "posix" in FileSystems.getDefault().supportedFileAttributeViews()

    private fun create(p: Path) = IdentityFile.create(p, AGENT_ID, TENANT, ENDPOINT)

    private fun seedHexOf(p: Path) =
        JsonParser.parseString(Files.readString(p)).asJsonObject.get("seed_hex").asString

    @Test
    fun generateIs32FreshCsprngBytes() {
        val a = Agent.generate()
        val b = Agent.generate()
        assertEquals(32, a.seed().size)
        assertFalse(a.seed().contentEquals(b.seed()))
        assertNotEquals(a.aid, b.aid)
    }

    @Test
    fun roundTripAidEquality(@TempDir dir: Path) {
        val c = create(dir.resolve("id.json"))
        val loaded = IdentityFile.load(c.path)
        assertEquals(c.aid, loaded.aid)
        assertEquals(c.aid, loaded.agent.aid)
        assertEquals(Triple(AGENT_ID, TENANT, ENDPOINT), Triple(loaded.agentId, loaded.tenant, loaded.endpoint))
    }

    @Test
    fun createNeverReturnsTheSeed(@TempDir dir: Path) {
        val c = create(dir.resolve("id.json"))
        assertFalse(c.toString().contains(seedHexOf(c.path)))
        val (_, aid) = c // exactly (path, aid): there is no seed component to reach
        assertEquals(c.aid, aid)
    }

    @Test
    fun toStringNeverPrintsTheSeed(@TempDir dir: Path) {
        val c = create(dir.resolve("id.json"))
        val loaded = IdentityFile.load(c.path)
        val seedHex = seedHexOf(c.path)
        assertFalse(loaded.toString().lowercase().contains(seedHex))
        assertFalse(loaded.agent.toString().lowercase().contains(seedHex))
        assertTrue(loaded.toString().contains(c.aid))
    }

    @Test
    fun fileIsSchemaV1WithTheAdaptersFieldNames(@TempDir dir: Path) {
        val p = create(dir.resolve("id.json")).path
        val data = JsonParser.parseString(Files.readString(p)).asJsonObject
        assertEquals(listOf("version", "seed_hex", "agent_id", "tenant", "endpoint"), data.keySet().toList())
        assertEquals(1, data.get("version").asInt)
        assertEquals(64, data.get("seed_hex").asString.length)
    }

    @Test
    fun modeIs0600UnderUmask0(@TempDir dir: Path) {
        assumeTrue(posix(), "POSIX file modes")
        // The JVM cannot change its own umask, so the create runs in a child JVM started under umask 0.
        val p = dir.resolve("id.json")
        val java = Path.of(System.getProperty("java.home"), "bin", "java").toString()
        val proc = ProcessBuilder(
            "/bin/sh", "-c",
            "umask 000 && exec \"\$0\" -cp \"\$1\" com.zer07labs.seam.UmaskProbe \"\$2\"",
            java, System.getProperty("java.class.path"), p.toString(),
        ).inheritIO().start()
        assertEquals(0, proc.waitFor(), "child create failed")
        assertEquals(
            "rw-------",
            PosixFilePermissions.toString(Files.getPosixFilePermissions(p, LinkOption.NOFOLLOW_LINKS)),
        )
    }

    @Test
    fun secondCreateRefusesAndLeavesBytesUnchanged(@TempDir dir: Path) {
        val p = create(dir.resolve("id.json")).path
        val before = Files.readAllBytes(p)
        val e = assertThrows<IdentityFileError> { create(p) }
        assertTrue(e.message!!.contains("refusing to overwrite"), e.message)
        assertArrayEquals(before, Files.readAllBytes(p))
    }

    @Test
    fun symlinkAtTheTargetIsRefused(@TempDir root: Path) {
        assumeTrue(posix(), "symlinks")
        for (dangling in listOf(false, true)) {
            val dir = Files.createDirectory(root.resolve("d$dangling"))
            val target = dir.resolve("elsewhere.json")
            if (!dangling) Files.writeString(target, "untouched")
            val link = Files.createSymbolicLink(dir.resolve("id.json"), target)
            val e = assertThrows<IdentityFileError> { create(link) }
            assertTrue(e.message!!.contains("refusing to overwrite"), e.message)
            assertTrue(Files.isSymbolicLink(link))
            if (dangling) assertFalse(Files.exists(target)) else assertEquals("untouched", Files.readString(target))
        }
    }

    @Test
    fun noTempFileIsLeftBehind(@TempDir dir: Path) {
        val p = create(dir.resolve("id.json")).path
        assertThrows<IdentityFileError> { create(p) }
        assertEquals(listOf("id.json"), dir.listDirectoryEntries().map { it.name })
    }

    @Test
    fun emptyFieldIsRefusedBeforeAnythingIsWritten(@TempDir dir: Path) {
        for ((field, args) in listOf(
            "agent_id" to listOf("", TENANT, ENDPOINT),
            "tenant" to listOf(AGENT_ID, "", ENDPOINT),
            "endpoint" to listOf(AGENT_ID, TENANT, ""),
        )) {
            val e = assertThrows<IdentityFileError> {
                IdentityFile.create(dir.resolve("id.json"), args[0], args[1], args[2])
            }
            assertTrue(e.message!!.contains(field), e.message)
            assertTrue(dir.listDirectoryEntries().isEmpty())
        }
    }

    @Test
    fun anExistingAdaptersFileStillLoads(@TempDir dir: Path) {
        val seed = ByteArray(32) { it.toByte() }
        val p = dir.resolve("partner.json")
        Files.writeString(
            p,
            """{"version": 1, "seed_hex": "${HexFormat.of().formatHex(seed)}", "agent_id": "qa-confirm", """ +
                """"tenant": "t1", "endpoint": "localhost:50051", "comment": "extra keys are ignored"}""",
        )
        val loaded = IdentityFile.load(p)
        assertArrayEquals(seed, loaded.agent.seed())
        assertEquals(Agent(seed).aid, loaded.aid)
    }

    @Test
    fun nullPathFallsBackToTheEnvPointer(@TempDir dir: Path) {
        // The JVM cannot set its own environment; load() reads $SEAM_BOOTSTRAP_FILE, and this pins the
        // refusal when it is unset plus the resolved-path half of the same code path.
        assumeTrue(System.getenv(IdentityFile.ENV_POINTER) == null, "SEAM_BOOTSTRAP_FILE is set")
        val e = assertThrows<IdentityFileError> { IdentityFile.load() }
        assertTrue(e.message!!.contains(IdentityFile.ENV_POINTER), e.message)
        val c = create(dir.resolve("id.json"))
        assertEquals(c.aid, IdentityFile.loadResolved(c.path).aid)
    }

    @Test
    fun malformedFilesAreLoud(@TempDir dir: Path) {
        val cases = listOf(
            """{"version": 2}""" to "version",
            """{"version": 1, "seed_hex": "ab"}""" to "64 hex",
            """{"version": 1, "seed_hex": "${"zz".repeat(32)}"}""" to "not valid hex",
            """{"version": 1, "seed_hex": "${"ab".repeat(32)}", "agent_id": "a", "tenant": "t"}""" to "endpoint",
            "[1, 2]" to "JSON object",
            "{not json" to "not valid JSON",
        )
        cases.forEachIndexed { i, (body, want) ->
            val p = dir.resolve("bad$i.json")
            Files.writeString(p, body)
            val e = assertThrows<IdentityFileError> { IdentityFile.load(p) }
            assertTrue(e.message!!.contains(want), "$body -> ${e.message}")
        }
    }

    @Test
    fun missingFileIsLoud(@TempDir dir: Path) {
        val e = assertThrows<IdentityFileError> { IdentityFile.load(dir.resolve("nope.json")) }
        assertTrue(e.message!!.contains("not found"), e.message)
    }
}
