package scanner

enum class Severity { LOW, MEDIUM, HIGH, CRITICAL }

data class Finding(
    val file: String,
    val line: Int?,
    val rule: String,
    val severity: Severity,
    val detail: String,
)

data class ContentRule(val name: String, val regex: Regex, val severity: Severity)

object Rules {
    /** Hard-coded secrets and credentials. */
    val secretRules = listOf(
        ContentRule("AWS access key", Regex("""AKIA[0-9A-Z]{16}"""), Severity.HIGH),
        ContentRule("GitHub token", Regex("""gh[pousr]_[A-Za-z0-9]{36,}"""), Severity.CRITICAL),
        ContentRule("Slack token", Regex("""xox[baprs]-[A-Za-z0-9-]{10,}"""), Severity.HIGH),
        ContentRule("Google API key", Regex("""AIza[0-9A-Za-z_\-]{35}"""), Severity.HIGH),
        ContentRule(
            "Private key",
            Regex("""-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"""),
            Severity.CRITICAL,
        ),
        ContentRule(
            "Hard-coded credential",
            Regex("""(?i)(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*["'][^"'\s]{8,}["']"""),
            Severity.MEDIUM,
        ),
    )

    /** Risky code patterns commonly seen in malicious or unsafe scripts. */
    val suspiciousCodeRules = listOf(
        ContentRule("Pipe download to shell", Regex("""(?i)(curl|wget)[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh"""), Severity.MEDIUM),
        ContentRule("Encoded PowerShell", Regex("""(?i)powershell[^\n]*\s-(enc|encodedcommand)\b"""), Severity.HIGH),
        ContentRule("Base64 eval", Regex("""(?i)eval\s*\(\s*(atob|base64_decode|base64\.b64decode)"""), Severity.HIGH),
        ContentRule("Runtime exec", Regex("""Runtime\.getRuntime\(\)\.exec"""), Severity.LOW),
        ContentRule("Reverse shell hint", Regex("""(?i)(/dev/tcp/|nc\s+(-e|-c)\s|bash\s+-i\s+>&)"""), Severity.HIGH),
    )

    val riskyExtensions = setOf("exe", "dll", "scr", "bat", "cmd", "vbs", "ps1", "msi", "com")

    /** Executables that legitimately carry a binary header. */
    val binaryExtensions = setOf("exe", "dll", "scr", "so", "dylib", "bin", "o", "a", "sys", "msi", "com")

    val doubleExtension =
        Regex("""(?i)\.(pdf|docx?|xlsx?|jpe?g|png|gif|txt)\.(exe|bat|cmd|scr|js|vbs|ps1)$""")

    val skipDirs = setOf(".git", "node_modules", "build", ".gradle", ".idea")
}
