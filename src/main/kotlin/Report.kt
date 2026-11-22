package scanner

object Report {
    fun text(findings: List<Finding>): String {
        if (findings.isEmpty()) return "No findings. \u2705"
        val sb = StringBuilder()
        findings.sortedByDescending { it.severity }.forEach {
            val loc = it.line?.let { l -> ":$l" } ?: ""
            sb.appendLine("[${it.severity}] ${it.file}$loc  (${it.rule})")
            sb.appendLine("    ${it.detail}")
        }
        sb.appendLine()
        sb.append("Total: ${findings.size} | ")
        sb.append(Severity.entries.reversed().joinToString(", ") { s -> "$s=${findings.count { it.severity == s }}" })
        return sb.toString()
    }

    fun json(findings: List<Finding>): String {
        val items = findings.joinToString(",\n") {
            """  {"file": ${q(it.file)}, "line": ${it.line ?: "null"}, "rule": ${q(it.rule)}, "severity": "${it.severity}", "detail": ${q(it.detail)}}"""
        }
        return "[\n$items\n]"
    }

    private fun q(s: String): String {
        val sb = StringBuilder("\"")
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> if (c < ' ') sb.append("\\u%04x".format(c.code)) else sb.append(c)
            }
        }
        return sb.append('"').toString()
    }
}
