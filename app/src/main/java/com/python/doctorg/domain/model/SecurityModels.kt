package com.python.doctorg.domain.model

import android.util.Log
import com.python.doctorg.BuildConfig

enum class ThreatLevel { TRUSTED, SAFE, NEEDS_REVIEW, SUSPICIOUS, MALICIOUS }

enum class TrustTier { TRUSTED_SYSTEM, VERIFIED_PUBLISHER, PLAY_STORE, UNKNOWN }

enum class SignalKind { TRUST, HARD, SOFT }

data class VerdictSignal(
    val kind: SignalKind,
    val category: String,
    val message: String
)

enum class ScanMode { QUICK, FULL }

enum class ScanLifecycleState { IDLE, RUNNING, PAUSED, COMPLETED, CANCELLED }

data class AppScanFinding(
    val id: String,
    val name: String,
    val packageName: String?,
    val filePath: String?,
    val sha256: String,
    val threatLevel: ThreatLevel,
    val riskScore: Int, // 0..100
    val mlProbability: Float?, // null when offline TFLite model is unavailable/disabled
    val installerSource: String,
    val isSideloaded: Boolean,
    val isHiddenApp: Boolean,
    val isSystemApp: Boolean,
    val isUpdatedSystemApp: Boolean = false,
    val targetSdk: Int,
    val reasons: List<String>,
    val signals: List<VerdictSignal> = emptyList(),
    val trustTier: TrustTier = TrustTier.UNKNOWN,
    val trustLabel: String? = null,
    val yaraMatches: List<String> = emptyList(),
    val staticIndicators: List<String> = emptyList(),
    val virusTotalMalicious: Int? = null,
    val isExcluded: Boolean = false
)

data class DeviceTamperingFinding(
    val indicator: String,
    val detected: Boolean,
    val severity: ThreatLevel,
    val explanation: String
)

data class CveFinding(
    val cveId: String,
    val severity: String,
    val title: String,
    val advice: String,
    val isVulnerable: Boolean
)

data class DeviceSecurityAudit(
    val hasScreenLock: Boolean,
    val androidVersionLabel: String,
    val securityPatchLevel: String,
    val usbDebuggingEnabled: Boolean,
    val developerOptionsEnabled: Boolean,
    val activeAccessibilityServices: List<String>,
    val activeDeviceAdmins: List<String>,
    val activeOverlayApps: List<String>,
    val activeRemoteAccessApps: List<String>,
    val tamperingFindings: List<DeviceTamperingFinding>,
    val cveFindings: List<CveFinding>,
    val wifiSummary: String
)

data class ScanProgressState(
    val mode: ScanMode = ScanMode.QUICK,
    val lifecycle: ScanLifecycleState = ScanLifecycleState.IDLE,
    val stageName: String = "Ready",
    val percent: Int = 0,
    val currentItem: String = "",
    val elapsedMs: Long = 0L,
    val estimatedRemainingMs: Long = 0L,
    val findings: List<AppScanFinding> = emptyList(),
    val skippedStages: List<Pair<String, String>> = emptyList(), // stage -> permission needed
    val deviceAudit: DeviceSecurityAudit? = null,
    val securityScore: Int = 88,
    val recommendedFixes: List<String> = emptyList()
) {
    val trustedCount: Int get() = findings.count { it.threatLevel == ThreatLevel.TRUSTED }
    val safeCount: Int get() = findings.count { it.threatLevel == ThreatLevel.SAFE }
    val needsReviewCount: Int get() = findings.count { it.threatLevel == ThreatLevel.NEEDS_REVIEW }
    val suspiciousCount: Int get() = findings.count { it.threatLevel == ThreatLevel.SUSPICIOUS }
    val maliciousCount: Int get() = findings.count { it.threatLevel == ThreatLevel.MALICIOUS }
}

data class ScamSmsResult(
    val inputText: String,
    val riskScore: Int, // 0..100
    val verdict: ThreatLevel,
    val mlProbability: Float,
    val matchedReasons: List<String>,
    val extractedUrls: List<String>
)

data class LocalizedGuideContent(
    val title: String,
    val description: String,
    val redFlags: List<String>,
    val whatToDo: List<String>
)

data class ScamAwarenessCard(
    val id: String,
    val i18n: Map<String, LocalizedGuideContent>
) {
    /**
     * Resolves localized guide content for [languageTag] (e.g. "hi", "ur", "bn", "ta", "en")
     * with field-level fallback to English and debug-build logging when any field falls back.
     */
    fun resolve(languageTag: String): LocalizedGuideContent {
        val baseLang = languageTag.lowercase().substringBefore("-").substringBefore("_").ifBlank { "en" }
        val en = i18n["en"] ?: i18n.values.firstOrNull() ?: LocalizedGuideContent("", "", emptyList(), emptyList())
        if (baseLang == "en") return en

        val loc = i18n[baseLang]
        fun fallbackWarn(field: String) {
            if (BuildConfig.DEBUG) {
                runCatching { Log.w("ScamAwareness", "Missing '$field' for card '$id' in locale '$baseLang'; falling back to English.") }
            }
        }

        val title = loc?.title?.takeIf { it.isNotBlank() } ?: run { fallbackWarn("title"); en.title }
        val description = loc?.description?.takeIf { it.isNotBlank() } ?: run { fallbackWarn("description"); en.description }
        val redFlags = loc?.redFlags?.takeIf { it.isNotEmpty() } ?: run { fallbackWarn("redFlags"); en.redFlags }
        val whatToDo = loc?.whatToDo?.takeIf { it.isNotEmpty() } ?: run { fallbackWarn("whatToDo"); en.whatToDo }
        return LocalizedGuideContent(title, description, redFlags, whatToDo)
    }
}

data class WifiSecurityAudit(
    val ssid: String,
    val bssid: String,
    val rssiDbm: Int,
    val linkSpeedMbps: Int,
    val securityType: String,
    val gatewayIp: String,
    val arpSpoofingSuspected: Boolean,
    val evilTwinSuspected: Boolean,
    val warnings: List<String>,
    val isSafe: Boolean
)

data class LanDevice(
    val ipAddress: String,
    val macAddress: String,
    val hostname: String,
    val vendor: String,
    val isReachable: Boolean
)

data class PasswordHealthItem(
    val id: Long,
    val title: String,
    val strengthScore: Int,
    val isWeak: Boolean,
    val isReused: Boolean,
    val isOld: Boolean,
    val hibpBreachCount: Int?
)

data class PasswordHealthReport(
    val overallScore: Int,
    val totalPasswords: Int,
    val weakCount: Int,
    val reusedCount: Int,
    val oldCount: Int,
    val leakedCount: Int,
    val items: List<PasswordHealthItem>,
    val suggestions: List<String>
)

data class AccountCheckupItem(
    val provider: String,
    val subtitle: String,
    val checkupUrl: String,
    val steps: List<String>
)

data class AppUsageStat(
    val packageName: String,
    val appName: String,
    val wifiBytes: Long,
    val mobileBytes: Long
)
