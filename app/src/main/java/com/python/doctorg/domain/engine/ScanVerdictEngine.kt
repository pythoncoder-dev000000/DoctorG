package com.python.doctorg.domain.engine

import com.python.doctorg.domain.model.SignalKind
import com.python.doctorg.domain.model.ThreatLevel
import com.python.doctorg.domain.model.TrustTier
import com.python.doctorg.domain.model.VerdictSignal
import kotlin.math.max
import kotlin.math.min

data class TrustedPublisherEntry(
    val packageName: String,
    val displayName: String,
    val certSha256: List<String>,
    val publisher: String,
    val category: String
)

data class AppVerdictInput(
    val packageName: String,
    val appName: String,
    val apkPath: String,
    val isFlagSystem: Boolean,
    val isFlagUpdatedSystemApp: Boolean,
    val signingCertSha256s: List<String>,
    val installerPackageName: String,
    val hasLauncherIcon: Boolean,
    val permissions: Set<String>,
    val isDeviceAdmin: Boolean,
    val hasActiveAccessibility: Boolean,
    val targetSdk: Int,
    val isExcludedByUser: Boolean = false,
    // Hard evidence inputs
    val knownMalwareFamily: String? = null,
    val knownMalwareDescription: String? = null,
    val yaraMaliciousRules: List<String> = emptyList(),
    val virusTotalMaliciousCount: Int? = null,
    val virusTotalThreshold: Int = ScanVerdictEngine.DEFAULT_VT_THRESHOLD,
    val knownBadCerts: Map<String, String> = emptyMap(),
    // Soft evidence inputs
    val yaraWarningRules: List<String> = emptyList(),
    val staticIndicators: List<String> = emptyList(),
    val hasSuspiciousStaticCode: Boolean = false,
    val mlProbability: Float? = null, // null when offline TFLite model is unavailable
    val appChangeSignals: List<String> = emptyList(),
    val stalkerwareSignal: String? = null,
    val trustedPublishers: List<TrustedPublisherEntry> = emptyList()
)

data class AppVerdictResult(
    val threatLevel: ThreatLevel,
    val trustTier: TrustTier,
    val trustLabel: String?,
    val riskScore: Int,
    val signals: List<VerdictSignal>,
    val isSideloaded: Boolean,
    val isHiddenApp: Boolean,
    val isSystemApp: Boolean
) {
    val reasons: List<String>
        get() = signals.map { it.message }
}

/**
 * Shared, deterministic, unit-testable verdict engine used by Quick Scan, Full Scan,
 * and single-APK inspection.
 *
 * Enforces strict separation between:
 * - Trust Tiers (Tier 1 System, Tier 2 Verified Publisher, Tier 3 Play Store), evaluated BEFORE scoring
 * - Hard Evidence (only source of MALICIOUS verdicts)
 * - Independent Soft Signals (single -> at most NEEDS_REVIEW; >=2 independent -> at most SUSPICIOUS;
 *   never escalates Tier 1 / Tier 2 apps).
 */
object ScanVerdictEngine {

    const val CURRENT_SCORING_VERSION = 2
    const val DEFAULT_VT_THRESHOLD = 5
    const val ML_CONFIDENCE_THRESHOLD = 0.80f
    const val LOOKALIKE_SIMILARITY_THRESHOLD = 0.88

    private val SYSTEM_PARTITION_PREFIXES = listOf(
        "/system/",
        "/product/",
        "/system_ext/",
        "/vendor/",
        "/apex/",
        "/odm/",
        "/system_dlkm/"
    )

    private val PLAY_STORE_INSTALLERS = setOf(
        "com.android.vending",
        "com.google.android.feedback"
    )

    fun isSystemPartitionPath(apkPath: String): Boolean {
        val normalized = apkPath.trim()
        return SYSTEM_PARTITION_PREFIXES.any { normalized.startsWith(it) }
    }

    /**
     * Evaluates Trust Tier BEFORE any risk scoring.
     */
    fun resolveTrustTier(
        packageName: String,
        apkPath: String,
        isFlagSystem: Boolean,
        isFlagUpdatedSystemApp: Boolean,
        signingCertSha256s: List<String>,
        installerPackageName: String,
        trustedPublishers: List<TrustedPublisherEntry>
    ): Pair<TrustTier, String?> {
        val normalizedCerts = signingCertSha256s.map { it.lowercase().trim() }.filter { it.length == 64 }
        val hasValidCert = normalizedCerts.isNotEmpty()
        val inSystemPartition = isSystemPartitionPath(apkPath)

        // Tier 1: Trusted system app
        // On Android, factory system apps live under /system, /product, /system_ext, /vendor, /apex;
        // OTA-updated system apps (e.g. Google Play services, Chrome) carry FLAG_UPDATED_SYSTEM_APP
        // because Android PackageManager verified the update signature against the system partition APK.
        val isTrustedSystem = hasValidCert && (
            (isFlagSystem && inSystemPartition) ||
                (isFlagUpdatedSystemApp && (inSystemPartition || apkPath.startsWith("/data/app/")))
            )
        if (isTrustedSystem) {
            return TrustTier.TRUSTED_SYSTEM to "Trusted: System app"
        }

        // Tier 2: Verified publisher (requires BOTH packageName AND non-empty certSha256 match,
        // supporting Android P+ signing certificate lineage / rotation history)
        val matchedPublisher = trustedPublishers.firstOrNull { entry ->
            entry.packageName.equals(packageName, ignoreCase = true) &&
                entry.certSha256.isNotEmpty() &&
                entry.certSha256.any { trustedHash ->
                    val clean = trustedHash.lowercase().trim()
                    clean.length == 64 && clean in normalizedCerts
                }
        }
        if (matchedPublisher != null) {
            return TrustTier.VERIFIED_PUBLISHER to "Verified: ${matchedPublisher.publisher}"
        }

        // Tier 3: Installed via Google Play Store (reduces risk score, does not exempt)
        if (installerPackageName in PLAY_STORE_INSTALLERS) {
            return TrustTier.PLAY_STORE to "Installed from Google Play Store"
        }

        return TrustTier.UNKNOWN to null
    }

    /**
     * Fixed Fake/Clone App Detector:
     * Flags an app as a lookalike ONLY when ALL are true:
     * 1. App is NOT Tier 1 (system) and NOT Tier 2 (verified publisher)
     * 2. Package name is NOT the official package name
     * 3. Normalized label similarity to an official app is very high (>= 0.88 Jaro-Winkler or exact match)
     * 4. Signing certificate does NOT match the official app's certificate
     *
     * Never matches by prefix or single generic token (e.g. "google").
     */
    fun detectLookalike(
        appName: String,
        packageName: String,
        signingCertSha256s: List<String>,
        trustTier: TrustTier,
        trustedPublishers: List<TrustedPublisherEntry>
    ): String? {
        if (trustTier == TrustTier.TRUSTED_SYSTEM || trustTier == TrustTier.VERIFIED_PUBLISHER) {
            return null
        }
        val normalizedPkg = packageName.lowercase().trim()
        val normalizedLabel = normalizeLabel(appName)
        if (normalizedLabel.length < 4) return null
        val normalizedCerts = signingCertSha256s.map { it.lowercase().trim() }.filter { it.length == 64 }.toSet()

        var bestMatchSim = 0.0
        var bestMatchReason: String? = null

        for (official in trustedPublishers) {
            val officialPkg = official.packageName.lowercase().trim()
            val officialCerts = official.certSha256.map { it.lowercase().trim() }.filter { it.length == 64 }.toSet()

            // Condition: same official package name
            if (normalizedPkg == officialPkg) {
                if (officialCerts.isNotEmpty() && normalizedCerts.isNotEmpty() && normalizedCerts.none { it in officialCerts }) {
                    return "Signing certificate mismatch for ${official.displayName}: installed under official package ($packageName) but signed by a different certificate than ${official.publisher}."
                }
                return null
            }

            // If we have official certs and the candidate shares a signing cert with the official publisher,
            // it's a legitimate sibling app from the same developer — never a lookalike.
            if (officialCerts.isNotEmpty() && normalizedCerts.any { it in officialCerts }) {
                continue
            }

            // Compare full normalized label against official displayName and clean base name
            // (stripping parentheticals like "(GPay)"). Require BOTH high Jaro-Winkler (>= 0.88)
            // AND high normalized Levenshtein (>= 0.80) so shared prefixes (e.g. "Google ...")
            // never cause false matches between unrelated apps of different lengths.
            val candidateNames = buildOfficialCompareNames(official.displayName)
            val bestSim = candidateNames.maxOfOrNull { ref ->
                val jw = jaroWinklerSimilarity(normalizedLabel, ref)
                val lev = normalizedLevenshteinSimilarity(normalizedLabel, ref)
                if (jw >= LOOKALIKE_SIMILARITY_THRESHOLD && lev >= 0.80) (jw + lev) / 2.0 else 0.0
            } ?: 0.0
            if (bestSim > bestMatchSim) {
                bestMatchSim = bestSim
                val certReason = if (officialCerts.isNotEmpty()) {
                    "and different signing certificate from the real ${official.displayName}"
                } else {
                    "and unverified signing certificate"
                }
                bestMatchReason = "Lookalike resembling ${official.displayName}: different package name ($packageName) $certReason."
            }
        }
        return bestMatchReason
    }

    fun evaluate(
        input: AppVerdictInput,
        permissionRiskAnalyzer: PermissionRiskAnalyzer
    ): AppVerdictResult {
        val (trustTier, trustLabel) = resolveTrustTier(
            packageName = input.packageName,
            apkPath = input.apkPath,
            isFlagSystem = input.isFlagSystem,
            isFlagUpdatedSystemApp = input.isFlagUpdatedSystemApp,
            signingCertSha256s = input.signingCertSha256s,
            installerPackageName = input.installerPackageName,
            trustedPublishers = input.trustedPublishers
        )

        val isSystemApp = input.isFlagSystem || input.isFlagUpdatedSystemApp
        val isTier1Or2 = trustTier == TrustTier.TRUSTED_SYSTEM || trustTier == TrustTier.VERIFIED_PUBLISHER
        val isPlayStore = trustTier == TrustTier.PLAY_STORE
        val isSideloaded = !isSystemApp && !isTier1Or2 && !isPlayStore
        val isHiddenApp = !isSystemApp && !input.hasLauncherIcon

        val signals = mutableListOf<VerdictSignal>()
        if (trustLabel != null && isTier1Or2) {
            val detail = when (trustTier) {
                TrustTier.TRUSTED_SYSTEM -> "$trustLabel (verified system partition component with valid signing certificate)"
                TrustTier.VERIFIED_PUBLISHER -> "$trustLabel (package name and signing certificate SHA-256 verified)"
                TrustTier.PLAY_STORE, TrustTier.UNKNOWN -> trustLabel
            }
            signals.add(VerdictSignal(SignalKind.TRUST, "TRUST_TIER", detail))
        }

        // --- HARD EVIDENCE (only source of MALICIOUS; checked even for Tier 1/2) ---
        if (!input.knownMalwareFamily.isNullOrBlank()) {
            val desc = input.knownMalwareDescription?.takeIf { it.isNotBlank() }?.let { " — $it" }.orEmpty()
            signals.add(
                VerdictSignal(
                    SignalKind.HARD,
                    "MALWARE_HASH",
                    "Known malware SHA-256 hash match: ${input.knownMalwareFamily}$desc"
                )
            )
        }
        input.yaraMaliciousRules.forEach { rule ->
            signals.add(
                VerdictSignal(
                    SignalKind.HARD,
                    "YARA_MALICIOUS",
                    "Confirmed malicious YARA rule matched: $rule"
                )
            )
        }
        val vtCount = input.virusTotalMaliciousCount ?: 0
        val vtThreshold = input.virusTotalThreshold.coerceAtLeast(1)
        if (vtCount >= vtThreshold) {
            signals.add(
                VerdictSignal(
                    SignalKind.HARD,
                    "VIRUSTOTAL",
                    "VirusTotal multi-engine detection: $vtCount engines flagged malicious (threshold $vtThreshold+)"
                )
            )
        }
        val matchedBadCert = input.signingCertSha256s
            .map { it.lowercase().trim() }
            .firstNotNullOfOrNull { hash -> input.knownBadCerts[hash]?.let { name -> hash to name } }
        if (matchedBadCert != null) {
            signals.add(
                VerdictSignal(
                    SignalKind.HARD,
                    "BAD_CERT",
                    "Signed by known-malicious certificate: ${matchedBadCert.second}"
                )
            )
        }

        val hasHardEvidence = signals.any { it.kind == SignalKind.HARD }

        // User exclusion only overrides non-hard findings (hard malware evidence is still surfaced clearly,
        // or user explicitly trusted non-hard signals)
        if (input.isExcludedByUser && !hasHardEvidence) {
            return AppVerdictResult(
                threatLevel = ThreatLevel.TRUSTED,
                trustTier = trustTier,
                trustLabel = "Trusted: Ignored by user",
                riskScore = 0,
                signals = listOf(
                    VerdictSignal(
                        SignalKind.TRUST,
                        "USER_EXCLUSION",
                        "Trusted by you in DoctorG Settings (reversible at any time)"
                    )
                ),
                isSideloaded = isSideloaded,
                isHiddenApp = isHiddenApp,
                isSystemApp = isSystemApp
            )
        }

        if (hasHardEvidence) {
            return AppVerdictResult(
                threatLevel = ThreatLevel.MALICIOUS,
                trustTier = trustTier,
                trustLabel = trustLabel,
                riskScore = 95,
                signals = signals,
                isSideloaded = isSideloaded,
                isHiddenApp = isHiddenApp,
                isSystemApp = isSystemApp
            )
        }

        // Tier 1 & Tier 2 apps with NO hard evidence are NEVER flagged as Malicious or Suspicious
        // due to permissions, ML, or lookalike heuristics.
        if (isTier1Or2) {
            return AppVerdictResult(
                threatLevel = ThreatLevel.TRUSTED,
                trustTier = trustTier,
                trustLabel = trustLabel,
                riskScore = 0,
                signals = signals,
                isSideloaded = false,
                isHiddenApp = false,
                isSystemApp = isSystemApp
            )
        }

        // --- SOFT SIGNALS (for non-Tier-1/2 apps only) ---
        var softScore = 0

        // Soft 1: Permission risk (sensitive permissions gated to sideloaded / hidden / unknown apps)
        val permReport = permissionRiskAnalyzer.analyzePermissions(
            permissions = input.permissions,
            isSideloaded = isSideloaded,
            isHiddenApp = isHiddenApp,
            isDeviceAdmin = input.isDeviceAdmin,
            hasActiveAccessibility = input.hasActiveAccessibility,
            targetSdk = input.targetSdk,
            isSystemOrVerified = false,
            isPlayStoreApp = isPlayStore
        )
        if (permReport.score >= 25 && permReport.reasons.isNotEmpty()) {
            softScore += permReport.score
            permReport.reasons.forEach { reason ->
                signals.add(VerdictSignal(SignalKind.SOFT, "PERMISSION_RISK", reason))
            }
        } else if (isSideloaded) {
            // Sideloaded install source is a mild independent soft signal (not enough alone for Suspicious)
            softScore += 15
            signals.add(
                VerdictSignal(
                    SignalKind.SOFT,
                    "INSTALL_SOURCE",
                    "Installed outside Google Play Store (sideloaded / unknown installer)"
                )
            )
        }

        // Soft 2: Fixed Fake / Lookalike App Detector
        val lookalikeMsg = detectLookalike(
            appName = input.appName,
            packageName = input.packageName,
            signingCertSha256s = input.signingCertSha256s,
            trustTier = trustTier,
            trustedPublishers = input.trustedPublishers
        )
        if (lookalikeMsg != null) {
            softScore += 40
            signals.add(VerdictSignal(SignalKind.SOFT, "LOOKALIKE", lookalikeMsg))
        }

        // Soft 3: Static APK / YARA warning indicators
        if (input.yaraWarningRules.isNotEmpty()) {
            softScore += 20
            input.yaraWarningRules.forEach { rule ->
                signals.add(VerdictSignal(SignalKind.SOFT, "STATIC_ANALYSIS", "YARA heuristic indicator: $rule"))
            }
        }
        if (input.hasSuspiciousStaticCode && isSideloaded) {
            softScore += 18
            signals.add(
                VerdictSignal(
                    SignalKind.SOFT,
                    "STATIC_ANALYSIS",
                    "Sideloaded APK uses dynamic code loading or shell execution APIs"
                )
            )
        }

        // Soft 4: Calibrated On-Device ML Classifier (ONLY when real .tflite model is loaded and >= 0.80)
        val mlProb = input.mlProbability
        if (mlProb != null && mlProb >= ML_CONFIDENCE_THRESHOLD) {
            softScore += 20
            signals.add(
                VerdictSignal(
                    SignalKind.SOFT,
                    "ML_ANOMALY",
                    "On-device ML classifier supporting signal (${(mlProb * 100).toInt()}% confidence)"
                )
            )
        }

        // Soft 5: App Change Monitor baseline delta
        if (input.appChangeSignals.isNotEmpty()) {
            softScore += 25
            input.appChangeSignals.forEach { delta ->
                signals.add(VerdictSignal(SignalKind.SOFT, "APP_CHANGE", delta))
            }
        }

        // Soft 6: Stalkerware / spyware heuristic
        if (!input.stalkerwareSignal.isNullOrBlank()) {
            softScore += 35
            signals.add(VerdictSignal(SignalKind.SOFT, "STALKERWARE", input.stalkerwareSignal))
        }

        // Tier 3 (Play Store) risk-score reduction (does not exempt, reduces soft noise)
        if (isPlayStore) {
            softScore = (softScore - 20).coerceAtLeast(0)
            if (trustLabel != null) {
                signals.add(VerdictSignal(SignalKind.TRUST, "PLAY_STORE", trustLabel))
            }
        }

        val independentSoftCategories = signals
            .filter { it.kind == SignalKind.SOFT }
            .map { it.category }
            .distinct()
            .size

        // Strict verdict ceiling: soft signals ALONE can NEVER produce MALICIOUS.
        // >= 2 independent soft signals -> SUSPICIOUS
        // 1 independent soft signal -> NEEDS_REVIEW (or SAFE if Play Store reduced risk score to 0)
        // 0 soft signals -> SAFE
        val verdict = when {
            independentSoftCategories >= 2 -> ThreatLevel.SUSPICIOUS
            independentSoftCategories == 1 && (!isPlayStore || softScore >= 20) -> ThreatLevel.NEEDS_REVIEW
            else -> ThreatLevel.SAFE
        }

        val clampedScore = when (verdict) {
            ThreatLevel.SAFE -> softScore.coerceIn(0, 19)
            ThreatLevel.NEEDS_REVIEW -> softScore.coerceIn(20, 49)
            ThreatLevel.SUSPICIOUS -> softScore.coerceIn(50, 79)
            ThreatLevel.TRUSTED -> 0
            ThreatLevel.MALICIOUS -> 95
        }

        if (signals.none { it.kind == SignalKind.SOFT || it.kind == SignalKind.HARD }) {
            signals.add(
                VerdictSignal(
                    SignalKind.TRUST,
                    "CLEAN",
                    "No hard malware evidence or suspicious signals detected"
                )
            )
        }

        return AppVerdictResult(
            threatLevel = verdict,
            trustTier = trustTier,
            trustLabel = trustLabel,
            riskScore = clampedScore,
            signals = signals,
            isSideloaded = isSideloaded,
            isHiddenApp = isHiddenApp,
            isSystemApp = isSystemApp
        )
    }

    internal fun normalizeLabel(label: String): String =
        label.lowercase()
            .replace(Regex("[^a-z0-9\\s]"), " ")
            .replace(Regex("\\s+"), " ")
            .trim()

    private fun buildOfficialCompareNames(displayName: String): List<String> {
        val results = linkedSetOf<String>()
        val full = normalizeLabel(displayName)
        if (full.length >= 4) results.add(full)
        val withoutParens = normalizeLabel(displayName.replace(Regex("\\([^)]*\\)"), " "))
        if (withoutParens.length >= 4) results.add(withoutParens)
        val insideParens = Regex("\\(([^)]+)\\)").find(displayName)?.groupValues?.getOrNull(1)
            ?.let { normalizeLabel(it) }
        if (!insideParens.isNullOrBlank() && insideParens.length >= 4) {
            results.add(insideParens)
        }
        return results.toList()
    }

    /**
     * Standard Jaro-Winkler similarity in [0.0, 1.0].
     */
    internal fun jaroWinklerSimilarity(s1: String, s2: String): Double {
        if (s1 == s2) return 1.0
        if (s1.isEmpty() || s2.isEmpty()) return 0.0

        val matchDistance = max(s1.length, s2.length) / 2 - 1
        val s1Matches = BooleanArray(s1.length)
        val s2Matches = BooleanArray(s2.length)

        var matches = 0
        for (i in s1.indices) {
            val start = max(0, i - matchDistance)
            val end = min(i + matchDistance + 1, s2.length)
            for (j in start until end) {
                if (s2Matches[j]) continue
                if (s1[i] != s2[j]) continue
                s1Matches[i] = true
                s2Matches[j] = true
                matches++
                break
            }
        }
        if (matches == 0) return 0.0

        var t = 0
        var k = 0
        for (i in s1.indices) {
            if (!s1Matches[i]) continue
            while (!s2Matches[k]) k++
            if (s1[i] != s2[k]) t++
            k++
        }

        val m = matches.toDouble()
        val jaro = (m / s1.length + m / s2.length + (m - t / 2.0) / m) / 3.0

        var prefix = 0
        for (i in 0 until min(4, min(s1.length, s2.length))) {
            if (s1[i] == s2[i]) prefix++ else break
        }
        return jaro + prefix * 0.1 * (1.0 - jaro)
    }

    /**
     * Normalized Levenshtein similarity in [0.0, 1.0], preventing prefix-skewed matches
     * across strings of significantly different length.
     */
    internal fun normalizedLevenshteinSimilarity(s1: String, s2: String): Double {
        if (s1 == s2) return 1.0
        val maxLen = max(s1.length, s2.length)
        if (maxLen == 0) return 1.0
        var prev = IntArray(s2.length + 1) { it }
        var curr = IntArray(s2.length + 1)
        for (i in 1..s1.length) {
            curr[0] = i
            for (j in 1..s2.length) {
                val cost = if (s1[i - 1] == s2[j - 1]) 0 else 1
                curr[j] = min(min(curr[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost)
            }
            val tmp = prev
            prev = curr
            curr = tmp
        }
        return 1.0 - (prev[s2.length].toDouble() / maxLen.toDouble())
    }
}
