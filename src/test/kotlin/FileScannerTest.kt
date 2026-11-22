package scanner

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class FileScannerTest {

    private fun tempDir(): File = Files.createTempDirectory("scan-test").toFile().also { it.deleteOnExit() }

    @Test
    fun detectsGithubToken() {
        val dir = tempDir()
        File(dir, "config.txt").writeText("token_value=ghp_" + "a".repeat(36) + "\n")
        val findings = FileScanner().scan(dir)
        assertTrue(findings.any { it.rule == "GitHub token" && it.line == 1 })
    }

    @Test
    fun detectsDoubleExtension() {
        val dir = tempDir()
        File(dir, "invoice.pdf.exe").writeText("x")
        val findings = FileScanner().scan(dir)
        assertTrue(findings.any { it.rule == "double-extension" })
    }

    @Test
    fun detectsKnownBadHash() {
        val dir = tempDir()
        val f = File(dir, "sample.txt").apply { writeText("hello") }
        val hash = FileScanner.sha256(f)
        val findings = FileScanner(setOf(hash)).scan(dir)
        assertTrue(findings.any { it.rule == "known-bad-hash" && it.severity == Severity.CRITICAL })
    }

    @Test
    fun cleanFileHasNoFindings() {
        val dir = tempDir()
        File(dir, "notes.txt").writeText("just some harmless notes\n")
        assertEquals(0, FileScanner().scan(dir).size)
    }
}
