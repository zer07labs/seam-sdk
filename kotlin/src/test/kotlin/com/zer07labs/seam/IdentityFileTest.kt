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
private const val FIXTURE_SEED_HEX = "ddc1524b29efe5bc1b9e9ea141b2a4740ba3e4d52f781afa3c1ffb3a3970580c"
private const val FIXTURE_AID = "aid:pubkey:ed25519:9x_uM2PCzXE8pt6di2RwwKCkod7W5kctdLdoIVtKep4"

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
        assertEquals(
            listOf("version", "seed_hex", "agent_id", "tenant", "endpoint", "aid"),
            data.keySet().toList(),
        )
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

    // seam-sdk#274 (D-AID-RECORD): a created file records its AID; a recorded aid is verified on load.

    @Test
    fun createdFileRecordsTheReturnedAid(@TempDir dir: Path) {
        val c = create(dir.resolve("id.json"))
        val data = JsonParser.parseString(Files.readString(c.path)).asJsonObject
        assertEquals(c.aid, data.get("aid").asString)
        assertEquals(c.aid, Agent(HexFormat.of().parseHex(seedHexOf(c.path))).aid)
    }

    private fun writeWithAid(dir: Path, name: String, aidJson: String): Path {
        val p = dir.resolve("$name.json")
        Files.writeString(
            p,
            """{"version": 1, "seed_hex": "$FIXTURE_SEED_HEX", "agent_id": "a", "tenant": "t", """ +
                """"endpoint": "e:1", "aid": $aidJson}""",
        )
        return p
    }

    @Test
    fun aBadRecordedAidIsRefused(@TempDir dir: Path) {
        val other = Agent(ByteArray(32) { it.toByte() }).aid
        val trimmed = FIXTURE_AID.dropLast(1)
        val cases = listOf(
            Triple("mismatch", "\"$other\"", "recorded aid does not match seed_hex"),
            Triple("short", "\"$trimmed\"", "aid is malformed"),
            Triple("long", "\"${FIXTURE_AID}A\"", "aid is malformed"),
            Triple("wrong-alg", "\"${FIXTURE_AID.replace("ed25519", "ed448")}\"", "aid is malformed"),
            Triple("non-b64url", "\"$trimmed=\"", "aid is malformed"),
            Triple("empty", "\"\"", "aid is malformed"),
            Triple("null", "null", "aid is malformed"),
            Triple("number", "42", "aid is malformed"),
            Triple("list", "[\"$FIXTURE_AID\"]", "aid is malformed"),
        )
        for ((name, aidJson, want) in cases) {
            val p = writeWithAid(dir, name, aidJson)
            val e = assertThrows<IdentityFileError> { IdentityFile.load(p) }
            assertEquals(want, e.message, name)
        }
    }

    @Test
    fun aMatchingRecordedAidLoads(@TempDir dir: Path) {
        val p = writeWithAid(dir, "ok", "\"$FIXTURE_AID\"")
        assertEquals(FIXTURE_AID, IdentityFile.load(p).aid)
    }

    @Test
    fun theSharedAidFixtureLoadsWithItsRecordedAid() {
        // Written by Python's create_identity_file (seam-sdk#274); the TS suite pins its bytes.
        val p = Path.of("..", "ts", "tests", "fixtures", "identity_v1_aid_python.json")
        assertEquals(FIXTURE_AID, JsonParser.parseString(Files.readString(p)).asJsonObject.get("aid").asString)
        val loaded = IdentityFile.load(p)
        assertEquals(FIXTURE_AID, loaded.aid)
        assertEquals(FIXTURE_SEED_HEX, HexFormat.of().formatHex(loaded.agent.seed()))
        assertEquals("ap-clerk", loaded.agentId)
        assertEquals("acm\u00e9", loaded.tenant)
        assertEquals("seam.example:443", loaded.endpoint)
    }

    @Test
    fun aLegacyFileWithoutAidLoadsUnchanged(@TempDir dir: Path) {
        val p = dir.resolve("legacy.json")
        Files.writeString(
            p,
            """{"version": 1, "seed_hex": "$FIXTURE_SEED_HEX", "agent_id": "ap-clerk", "tenant": "acme", """ +
                """"endpoint": "seam.example:443"}""",
        )
        assertEquals(FIXTURE_AID, IdentityFile.load(p).aid)
    }

    // seam-sdk#274 (D-FACTS-API, D-LEGACY-AID, D-FACTS-CHECKS): the seed-free facts loader.

    private val legacyFixture = Path.of("..", "ts", "tests", "fixtures", "identity_v1_python.json")
    private val aidFixture = Path.of("..", "ts", "tests", "fixtures", "identity_v1_aid_python.json")
    private val hex64 = Regex("[0-9a-fA-F]{64}")

    private fun factsOf(f: IdentityFacts) = listOf(f.agentId, f.tenant, f.endpoint, f.aid)

    private fun factsOf(l: LoadedIdentity) = listOf(l.agentId, l.tenant, l.endpoint, l.aid)

    @Test
    fun identityFactsCarryNoSigningCapability() {
        // Criterion 1: exactly the four String properties; the rendering carries no seed.
        val ctor = IdentityFacts::class.java.declaredConstructors.single()
        assertEquals(List(4) { String::class.java }, ctor.parameterTypes.toList())
        assertEquals(
            listOf("agentId", "tenant", "endpoint", "aid"),
            IdentityFacts::class.java.declaredFields.filterNot { java.lang.reflect.Modifier.isStatic(it.modifiers) }
                .map { it.name },
        )
        for (p in listOf(legacyFixture, aidFixture)) {
            val rendered = IdentityFile.loadFacts(p).toString()
            assertFalse(hex64.containsMatchIn(rendered), rendered)
            assertTrue(rendered.contains(FIXTURE_AID), rendered)
        }
    }

    @Test
    fun aFileThatRecordsAidIsServedWithoutDecodingTheSeed() {
        // Criterion 2: the hooked decoder refuses; loadFacts never calls it on a file that records aid.
        val saved = IdentityFile.seedDecoder
        var calls = 0
        IdentityFile.seedDecoder = { calls++; throw IllegalStateException("seed decoded") }
        try {
            assertEquals(
                listOf("ap-clerk", "acmé", "seam.example:443", FIXTURE_AID),
                factsOf(IdentityFile.loadFacts(aidFixture)),
            )
            assertEquals(0, calls)
            val full = assertThrows<IllegalStateException> { IdentityFile.load(aidFixture) }
            assertEquals("seed decoded", full.message)
            assertEquals(1, calls)
            // A legacy file has no recorded aid, so deriving one necessarily decodes the seed.
            assertThrows<IllegalStateException> { IdentityFile.loadFacts(legacyFixture) }
            assertEquals(2, calls)
        } finally {
            IdentityFile.seedDecoder = saved
        }
    }

    @Test
    fun identityFactsAgreeWithTheFullLoaderOnEveryField(@TempDir dir: Path) {
        // Criterion 4: legacy, recorded-aid, freshly created and adapters-shaped files.
        val seed = ByteArray(32) { it.toByte() }
        val partner = dir.resolve("partner.json")
        Files.writeString(
            partner,
            """{"version": 1, "seed_hex": "${HexFormat.of().formatHex(seed)}", "agent_id": "qa-confirm", """ +
                """"tenant": "t1", "endpoint": "localhost:50051", "comment": "extra keys are ignored"}""",
        )
        val created = create(dir.resolve("created.json")).path
        for (p in listOf(legacyFixture, aidFixture, created, partner)) {
            assertEquals(factsOf(IdentityFile.load(p)), factsOf(IdentityFile.loadFacts(p)), p.toString())
        }
        assertEquals(FIXTURE_AID, IdentityFile.loadFacts(legacyFixture).aid)
    }

    @Test
    fun identityFactsFallBackToTheEnvPointer(@TempDir dir: Path) {
        assumeTrue(System.getenv(IdentityFile.ENV_POINTER) == null, "SEAM_BOOTSTRAP_FILE is set")
        assertSameRefusal(null, null)
        val c = create(dir.resolve("id.json"))
        assertEquals(c.aid, IdentityFile.loadFactsResolved(c.path).aid)
    }

    @Test
    fun aMismatchedRecordedAidIsAClaimToFactsAndARefusalToTheFullLoader(@TempDir dir: Path) {
        val other = Agent(ByteArray(32) { it.toByte() }).aid
        val p = writeWithAid(dir, "mismatch", "\"$other\"")
        assertEquals(other, IdentityFile.loadFacts(p).aid)
        val e = assertThrows<IdentityFileError> { IdentityFile.load(p) }
        assertEquals("recorded aid does not match seed_hex", e.message)
    }

    // Both loaders refuse with the same message; want null skips the exact-message check.
    private fun assertSameRefusal(p: Path?, want: String?) {
        val full = assertThrows<IdentityFileError> { IdentityFile.load(p) }
        val facts = assertThrows<IdentityFileError> { IdentityFile.loadFacts(p) }
        assertEquals(full.message, facts.message, p.toString())
        if (want != null) assertEquals(want, full.message, p.toString())
    }

    @Test
    fun bothLoadersRefuseABadFileIdentically(@TempDir dir: Path) {
        // Criterion 3 (D-FACTS-CHECKS).
        val seedLen = "seed_hex must be exactly 64 hex chars (a 32-byte Ed25519 seed)"
        val notHex = "seed_hex is not valid hex"
        val seed = "ab".repeat(32)
        val cases = listOf(
            """{"version": 2}""" to "bootstrap schema version 2 unsupported (want 1)",
            """{"version": 1, "seed_hex": "ab"}""" to seedLen,
            """{"version": 1}""" to seedLen,
            """{"version": 1, "seed_hex": 7}""" to seedLen,
            """{"version": 1, "seed_hex": "${"zz".repeat(32)}"}""" to notHex,
            """{"version": 1, "seed_hex": "${"00 ".repeat(21)}0"}""" to notHex,
            """{"version": 1, "seed_hex": "${"00".repeat(31)}  "}""" to notHex,
            """{"version": 1, "seed_hex": "0x${"00".repeat(31)}"}""" to notHex,
            """{"version": 1, "seed_hex": "$seed", "agent_id": "a", "tenant": "t"}""" to
                "bootstrap file missing required field(s): endpoint",
            """{"version": 1, "seed_hex": "$seed"}""" to
                "bootstrap file missing required field(s): agent_id, tenant, endpoint",
            "[1, 2]" to null,
            "{not json" to null,
        )
        var i = 0
        for ((body, want) in cases) {
            val p = dir.resolve("bad${i++}.json")
            Files.writeString(p, body)
            assertSameRefusal(p, want)
        }
        for (aid in listOf("\"${FIXTURE_AID.dropLast(1)}\"", "\"\"", "null", "42")) {
            assertSameRefusal(writeWithAid(dir, "aid${i++}", aid), "aid is malformed")
        }
        val missing = dir.resolve("nope.json")
        assertSameRefusal(missing, "bootstrap file not found: $missing")
    }
}
