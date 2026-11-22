package com.python.doctorg.domain.engine

import com.python.doctorg.data.remote.FeedUpdateManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.zip.ZipFile
import javax.inject.Inject
import javax.inject.Singleton

data class YaraRule(
    val name: String,
    val description: String,
    val severity: String,
    val patterns: List<String>,
    val minMatches: Int
)

data class YaraMatch(
    val ruleName: String,
    val severity: String,
    val description: String,
    val matchedStrings: List<String>
)

@Singleton
class YaraRuleEngine @Inject constructor(
    private val feedUpdateManager: FeedUpdateManager
) {
    @Volatile
    private var cachedRules: List<YaraRule> = emptyList()

    fun loadRules(forceReload: Boolean = false): List<YaraRule> {
        if (cachedRules.isNotEmpty() && !forceReload) return cachedRules
        val raw = feedUpdateManager.readLatestOrBundledAsset("yara_rules.yar")
        cachedRules = parseRules(raw)
        return cachedRules
    }

    fun parseRules(rawText: String): List<YaraRule> = Companion.parseRules(rawText)

    fun scanText(content: String, rules: List<YaraRule> = loadRules()): List<YaraMatch> =
        Companion.scanText(content, rules)

    companion object {
        fun parseRules(rawText: String): List<YaraRule> {
            val rules = mutableListOf<YaraRule>()
            val headerRegex = Regex("""rule\s+([A-Za-z0-9_]+)\s*\{""")
            val strRegex = Regex("""\$[A-Za-z0-9_]+\s*=\s*"((?:\\.|[^"\\])+)"""")
            val descRegex = Regex("""description\s*=\s*"((?:\\.|[^"\\])+)"""")
            val sevRegex = Regex("""severity\s*=\s*"((?:\\.|[^"\\])+)"""")
            val condRegex = Regex("""(\d+)\s+of\s+them""")

            var searchPos = 0
            while (searchPos < rawText.length) {
                val match = headerRegex.find(rawText, searchPos) ?: break
                val name = match.groupValues[1]
                val bodyStart = match.range.last + 1

                var depth = 1
                var inQuotes = false
                var escaped = false
                var idx = bodyStart
                while (idx < rawText.length && depth > 0) {
                    val ch = rawText[idx]
                    if (inQuotes) {
                        if (escaped) {
                            escaped = false
                        } else if (ch == '\\') {
                            escaped = true
                        } else if (ch == '"') {
                            inQuotes = false
                        }
                    } else {
                        when (ch) {
                            '"' -> inQuotes = true
                            '{' -> depth++
                            '}' -> depth--
                        }
                    }
                    idx++
                }
                if (depth != 0) break

                val body = rawText.substring(bodyStart, idx - 1)
                searchPos = idx

                val patterns = strRegex.findAll(body).map { unescapeYaraString(it.groupValues[1]) }.toList()
                if (patterns.isEmpty()) continue
                val desc = descRegex.find(body)?.groupValues?.get(1)?.let(::unescapeYaraString)
                    ?: "Matched YARA rule $name"
                val sev = sevRegex.find(body)?.groupValues?.get(1)?.let(::unescapeYaraString)
                    ?: "SUSPICIOUS"
                val minMatches = condRegex.find(body)?.groupValues?.get(1)?.toIntOrNull()
                    ?: patterns.size.coerceAtMost(2)
                rules.add(YaraRule(name, desc, sev, patterns, minMatches.coerceIn(1, patterns.size)))
            }
            return rules
        }

        private fun unescapeYaraString(raw: String): String {
            val sb = StringBuilder(raw.length)
            var i = 0
            while (i < raw.length) {
                val c = raw[i]
                if (c == '\\' && i + 1 < raw.length) {
                    when (val next = raw[i + 1]) {
                        '\\' -> sb.append('\\')
                        '"' -> sb.append('"')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        else -> {
                            sb.append('\\')
                            sb.append(next)
                        }
                    }
                    i += 2
                } else {
                    sb.append(c)
                    i++
                }
            }
            return sb.toString()
        }

        fun scanText(content: String, rules: List<YaraRule>): List<YaraMatch> {
            if (content.isEmpty()) return emptyList()
            val lower = content.lowercase()
            return rules.mapNotNull { rule ->
                val hits = rule.patterns.filter { p -> lower.contains(p.lowercase()) }
                if (hits.size >= rule.minMatches) {
                    YaraMatch(rule.name, rule.severity, rule.description, hits)
                } else {
                    null
                }
            }
        }
    }

    /**
     * Streaming bounded-memory YARA scan across APK manifest, DEX string chunks, and text resources.
     */
    suspend fun scanApkFile(apkFile: File, maxBytesToRead: Int = 2 * 1024 * 1024): List<YaraMatch> =
        withContext(Dispatchers.IO) {
            val rules = loadRules()
            if (rules.isEmpty() || !apkFile.exists() || !apkFile.canRead()) return@withContext emptyList()
            val matchedByRule = mutableMapOf<String, MutableSet<String>>()
            var bytesReadTotal = 0

            runCatching {
                ZipFile(apkFile).use { zip ->
                    val entries = zip.entries()
                    while (entries.hasMoreElements() && bytesReadTotal < maxBytesToRead) {
                        val entry = entries.nextElement()
                        if (entry.isDirectory) continue
                        val name = entry.name.lowercase()
                        val relevant = name == "androidmanifest.xml" ||
                            name.endsWith(".dex") ||
                            name.endsWith(".xml") ||
                            name.endsWith(".txt") ||
                            name.endsWith(".json")
                        if (!relevant) continue

                        val buffer = ByteArray(16 * 1024)
                        zip.getInputStream(entry).use { stream ->
                            var read = stream.read(buffer)
                            while (read != -1 && bytesReadTotal < maxBytesToRead) {
                                bytesReadTotal += read
                                val chunk = String(buffer, 0, read, Charsets.ISO_8859_1).lowercase()
                                for (rule in rules) {
                                    val set = matchedByRule.getOrPut(rule.name) { mutableSetOf() }
                                    for (pattern in rule.patterns) {
                                        if (pattern !in set && chunk.contains(pattern.lowercase())) {
                                            set.add(pattern)
                                        }
                                    }
                                }
                                read = stream.read(buffer)
                            }
                        }
                    }
                }
            }.onFailure {
                // Non-ZIP plain file (e.g., EICAR test file or script)
                runCatching {
                    val sample = apkFile.inputStream().use {
                        val buf = ByteArray(minOf(apkFile.length().toInt().coerceAtLeast(0), 65_536))
                        val n = it.read(buf)
                        if (n > 0) String(buf, 0, n, Charsets.ISO_8859_1) else ""
                    }
                    return@withContext scanText(sample, rules)
                }
            }

            rules.mapNotNull { rule ->
                val hits = matchedByRule[rule.name].orEmpty()
                if (hits.size >= rule.minMatches) {
                    YaraMatch(rule.name, rule.severity, rule.description, hits.toList())
                } else {
                    null
                }
            }
        }
}
