package scanner

import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest

class FileScanner(
    private val knownBadHashes: Set<String> = emptySet(),
    private val maxContentBytes: Long = 5L * 1024 * 1024,
) {

    fun scan(root: File): List<Finding> {
        val findings = mutableListOf<Finding>()
        root.walkTopDown()
            .onEnter { it == root || it.name !in Rules.skipDirs }
            .filter { it.isFile }
            .forEach { findings += scanFile(it, root) }
        return findings
    }

    fun scanFile(file: File, root: File): List<Finding> {
        val out = mutableListOf<Finding>()
        val rel = if (root.isDirectory) file.relativeTo(root).path else file.name

        fun add(line: Int?, rule: String, severity: Severity, detail: String) {
            out += Finding(rel, line, rule, severity, detail)
        }

        val ext = file.extension.lowercase()

        // 1) File name checks
        if (Rules.doubleExtension.containsMatchIn(file.name)) {
            add(null, "double-extension", Severity.HIGH, "Deceptive double extension: ${file.name}")
        } else if (ext in Rules.riskyExtensions) {
            add(null, "risky-extension", Severity.LOW, "Executable or script file type (.$ext)")
        }

        // 2) Permissions (POSIX only)
        try {
            val perms = Files.getPosixFilePermissions(file.toPath())
            if (PosixFilePermission.OTHERS_WRITE in perms) {
                add(null, "world-writable", Severity.MEDIUM, "File is writable by everyone")
            }
        } catch (_: UnsupportedOperationException) {
            // Not a POSIX file system (e.g. Windows) - skip.
        } catch (_: Exception) {
        }

        // 3) Known-bad hash match
        if (knownBadHashes.isNotEmpty()) {
            val hash = sha256(file)
            if (hash in knownBadHashes) {
                add(null, "known-bad-hash", Severity.CRITICAL, "SHA-256 matches a known-bad hash: $hash")
            }
        }

        // 4) Header sniffing
        val head = try {
            file.inputStream().use { it.readNBytes(8000) }
        } catch (_: Exception) {
            add(null, "unreadable", Severity.LOW, "Could not read file")
            return out
        }
        val isBinary = head.any { it == 0.toByte() }

        if (ext !in Rules.binaryExtensions && looksLikeExecutable(head)) {
            add(null, "disguised-executable", Severity.MEDIUM, "Executable header found in a .$ext file")
        }

        // 5) Content scan for text files
        if (!isBinary && file.length() <= maxContentBytes) {
            file.bufferedReader().useLines { lines ->
                lines.forEachIndexed { index, rawLine ->
                    val line = rawLine.take(2000)
                    val number = index + 1
                    for (rule in Rules.secretRules) {
                        rule.regex.find(line)?.let {
                            add(number, rule.name, rule.severity, "Possible ${rule.name}: ${mask(it.value)}")
                        }
                    }
                    for (rule in Rules.suspiciousCodeRules) {
                        if (rule.regex.containsMatchIn(line)) {
                            add(number, rule.name, rule.severity, "Suspicious pattern: ${rule.name}")
                        }
                    }
                }
            }
        }
        return out
    }

    private fun looksLikeExecutable(head: ByteArray): Boolean {
        if (head.size < 4) return false
        val mz = head[0] == 0x4D.toByte() && head[1] == 0x5A.toByte()
        val elf = head[0] == 0x7F.toByte() && head[1] == 'E'.code.toByte() &&
            head[2] == 'L'.code.toByte() && head[3] == 'F'.code.toByte()
        return mz || elf
    }

    private fun mask(value: String) = value.take(4) + "****"

    companion object {
        fun sha256(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(8192)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    digest.update(buffer, 0, n)
                }
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }
    }
}
