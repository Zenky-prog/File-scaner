package scanner

import java.io.File
import kotlin.system.exitProcess

private const val USAGE = """
Usage: scanner <path> [options]

Options:
  --hashes <file>     Text file of known-bad SHA-256 hashes (one per line)
  --json              Print the report as JSON
  --fail-on <LEVEL>   Exit with code 1 if a finding >= LEVEL exists
                      (LOW | MEDIUM | HIGH | CRITICAL, default: HIGH)
  --help              Show this help
"""

fun main(args: Array<String>) {
    if (args.isEmpty() || "--help" in args) {
        println(USAGE.trimIndent())
        exitProcess(if (args.isEmpty()) 2 else 0)
    }

    var path: String? = null
    var hashesFile: String? = null
    var json = false
    var failOn = Severity.HIGH

    var i = 0
    while (i < args.size) {
        when (val a = args[i]) {
            "--json" -> json = true
            "--hashes" -> hashesFile = args.getOrNull(++i) ?: fail("--hashes needs a file")
            "--fail-on" -> {
                val v = args.getOrNull(++i) ?: fail("--fail-on needs a level")
                failOn = runCatching { Severity.valueOf(v.uppercase()) }.getOrNull()
                    ?: fail("Unknown level: $v")
            }
            else -> if (a.startsWith("--")) fail("Unknown option: $a") else path = a
        }
        i++
    }

    val root = File(path ?: fail("Missing <path>"))
    if (!root.exists()) fail("Path does not exist: ${root.path}")

    val badHashes = hashesFile?.let { f ->
        File(f).readLines()
            .map { it.trim().lowercase() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .toSet()
    } ?: emptySet()

    val findings = FileScanner(badHashes).scan(root)
    println(if (json) Report.json(findings) else Report.text(findings))

    exitProcess(if (findings.any { it.severity >= failOn }) 1 else 0)
}

private fun fail(message: String): Nothing {
    System.err.println("Error: $message")
    exitProcess(2)
}
