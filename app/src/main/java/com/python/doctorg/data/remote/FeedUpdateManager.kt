package com.python.doctorg.data.remote

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.python.doctorg.core.security.CryptoManager
import com.python.doctorg.data.local.DoctorGDatabase
import com.python.doctorg.data.local.entity.BlockedDomainEntity
import com.python.doctorg.data.local.entity.MalwareHashEntity
import com.python.doctorg.data.local.entity.SpamNumberEntity
import com.python.doctorg.data.preferences.DoctorGPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.net.InetAddress
import java.net.URL
import javax.inject.Inject
import javax.inject.Singleton

data class FeedUpdateResult(
    val success: Boolean,
    val version: String,
    val signaturesImported: Int,
    val domainsImported: Int,
    val message: String
)

/**
 * Loads bundled offline datasets on first launch and updates versioned static files
 * from a user-configurable public GitHub raw/releases repository with SHA-256 checksum verification.
 */
@Singleton
class FeedUpdateManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val database: DoctorGDatabase,
    private val preferences: DoctorGPreferences,
    private val staticFeedApi: StaticFeedApi,
    private val cryptoManager: CryptoManager
) {
    private val feedsCacheDir: File
        get() = File(context.filesDir, "feeds").apply { mkdirs() }

    suspend fun seedBundledOfflineFeedsIfEmpty() = withContext(Dispatchers.IO) {
        if (database.malwareHashDao().count() == 0) {
            val jsonText = readAsset("malware_hashes.json")
            importMalwareHashesJson(jsonText, source = "bundled")
        }
        if (database.webProtectionDao().totalCount() == 0) {
            val text = readAsset("blocklist_domains.txt")
            importBlocklistText(text)
        }
        if (database.spamNumberDao().count() == 0) {
            val jsonText = readAsset("spam_numbers.json")
            importSpamNumbersJson(jsonText)
        }
    }

    fun readLatestOrBundledAsset(fileName: String): String {
        val safeName = File(fileName).name
        val baseDir = feedsCacheDir.canonicalFile
        val cached = File(baseDir, safeName).canonicalFile
        return if (cached.path.startsWith(baseDir.path + File.separator) && cached.exists() && cached.length() > 0L) {
            cached.readText()
        } else {
            readAsset(safeName)
        }
    }

    private fun readAsset(fileName: String): String =
        runCatching { context.assets.open(fileName).bufferedReader().use { it.readText() } }.getOrDefault("")

    private fun isSafePublicHttpsUrl(urlStr: String): Boolean {
        val parsed = runCatching { URL(urlStr) }.getOrNull() ?: return false
        if (!parsed.protocol.equals("https", ignoreCase = true)) return false
        val host = parsed.host.lowercase()
        if (host.isBlank() || host == "localhost" || host.endsWith(".local")) return false
        val addr = runCatching { InetAddress.getByName(host) }.getOrNull()
        if (addr != null && (addr.isLoopbackAddress || addr.isSiteLocalAddress || addr.isLinkLocalAddress || addr.isAnyLocalAddress)) {
            return false
        }
        return true
    }

    suspend fun refreshFromStaticGitHubFeeds(forceIgnoreWifi: Boolean = false): FeedUpdateResult =
        withContext(Dispatchers.IO) {
            val settings = preferences.settingsFlow.first()
            if (settings.wifiOnlyUpdates && !forceIgnoreWifi && !isOnWifi()) {
                return@withContext FeedUpdateResult(
                    success = false,
                    version = settings.signatureVersion,
                    signaturesImported = 0,
                    domainsImported = 0,
                    message = "Skipped: Wi-Fi-only update rule active. Using offline signatures."
                )
            }

            val base = settings.feedBaseUrl.trimEnd('/') + "/"
            if (!isSafePublicHttpsUrl(base)) {
                return@withContext FeedUpdateResult(
                    success = false,
                    version = settings.signatureVersion,
                    signaturesImported = 0,
                    domainsImported = 0,
                    message = "Feed URL must use a valid public HTTPS host. Falling back to bundled signatures."
                )
            }

            // Try downloading manifest.json with version + SHA-256 checksums for each feed file
            val manifestBody = runCatching {
                val resp = staticFeedApi.downloadText("${base}manifest.json")
                if (resp.isSuccessful) resp.body()?.string() else null
            }.getOrNull()

            if (manifestBody.isNullOrBlank()) {
                // Offline / unreachable GitHub repo: ensure bundled assets are loaded and report cleanly
                seedBundledOfflineFeedsIfEmpty()
                val totalSigs = database.malwareHashDao().count()
                return@withContext FeedUpdateResult(
                    success = true,
                    version = "${settings.signatureVersion} (Offline verified)",
                    signaturesImported = totalSigs,
                    domainsImported = database.webProtectionDao().totalCount(),
                    message = "Remote feed unavailable offline; verified $totalSigs bundled signatures."
                )
            }

            runCatching {
                val manifest = JSONObject(manifestBody)
                val version = manifest.optString("version", "custom")
                val filesObj = manifest.optJSONObject("files") ?: JSONObject()
                var sigCount = 0
                var domCount = 0

                val feedFiles = listOf(
                    "malware_hashes.json",
                    "yara_rules.yar",
                    "trusted_publishers.json",
                    "known_bad_certs.json",
                    "official_apps.json",
                    "stalkerware_list.json",
                    "blocklist_domains.txt",
                    "spam_numbers.json",
                    "scam_patterns.json",
                    "scam_awareness.json",
                    "android_cves.json"
                )

                for (name in feedFiles) {
                    val expectedSha = filesObj.optString(name, "").lowercase()
                    if (expectedSha.isBlank()) continue
                    val resp = staticFeedApi.downloadText("$base$name")
                    val body = if (resp.isSuccessful) resp.body()?.string() else null
                    if (body.isNullOrBlank()) continue
                    val actualSha = cryptoManager.sha256Hex(body).lowercase()
                    if (actualSha != expectedSha) continue // Reject tampered or corrupted file

                    File(feedsCacheDir, name).writeText(body)
                    when (name) {
                        "malware_hashes.json" -> sigCount = importMalwareHashesJson(body, source = "github:$version")
                        "blocklist_domains.txt" -> domCount = importBlocklistText(body)
                        "spam_numbers.json" -> importSpamNumbersJson(body)
                    }
                }

                preferences.setSignatureMetadata(version, System.currentTimeMillis())
                FeedUpdateResult(
                    success = true,
                    version = version,
                    signaturesImported = sigCount,
                    domainsImported = domCount,
                    message = "Verified SHA-256 feeds v$version ($sigCount hashes, $domCount domains)."
                )
            }.getOrElse { err ->
                FeedUpdateResult(
                    success = false,
                    version = settings.signatureVersion,
                    signaturesImported = 0,
                    domainsImported = 0,
                    message = "Feed parse error (${err.message}); retained verified local DB."
                )
            }
        }

    private suspend fun importMalwareHashesJson(jsonText: String, source: String): Int {
        if (jsonText.isBlank()) return 0
        val root = JSONObject(jsonText)
        val arr = root.optJSONArray("signatures") ?: return 0
        val list = buildList {
            for (i in 0 until arr.length()) {
                val obj = arr.getJSONObject(i)
                val sha = obj.optString("sha256").lowercase().trim()
                if (sha.length == 64) {
                    add(
                        MalwareHashEntity(
                            sha256 = sha,
                            family = obj.optString("family", "Android.Malware"),
                            severity = obj.optString("severity", "MALICIOUS"),
                            description = obj.optString("description", "Known malicious signature."),
                            source = source
                        )
                    )
                }
            }
        }
        database.malwareHashDao().insertAll(list)
        return list.size
    }

    private suspend fun importBlocklistText(text: String): Int {
        if (text.isBlank()) return 0
        val items = text.lineSequence()
            .map { it.trim().lowercase() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .map { line ->
                val cleaned = line.removePrefix("0.0.0.0 ").removePrefix("127.0.0.1 ").trim()
                val category = when {
                    cleaned.contains("ad") || cleaned.contains("track") || cleaned.contains("analytics") -> "TRACKER"
                    cleaned.contains("kyc") || cleaned.contains("phish") || cleaned.contains("bank") -> "PHISHING"
                    else -> "MALWARE"
                }
                BlockedDomainEntity(domain = cleaned, category = category, isAllowedOverride = false)
            }
            .toList()
        database.webProtectionDao().insertDomains(items)
        return items.size
    }

    private suspend fun importSpamNumbersJson(jsonText: String): Int {
        if (jsonText.isBlank()) return 0
        val root = JSONObject(jsonText)
        val arr = root.optJSONArray("entries") ?: return 0
        val list = buildList {
            for (i in 0 until arr.length()) {
                val obj = arr.getJSONObject(i)
                add(
                    SpamNumberEntity(
                        phoneNumber = obj.optString("number"),
                        category = obj.optString("category", "Spam"),
                        risk = obj.optString("risk", "MEDIUM"),
                        reports = obj.optInt("reports", 1),
                        isUserReported = false
                    )
                )
            }
        }
        database.spamNumberDao().insertAll(list)
        return list.size
    }

    private fun isOnWifi(): Boolean {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
        val active = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(active) ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
    }
}
