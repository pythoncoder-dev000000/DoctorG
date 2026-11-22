package com.python.doctorg.domain.engine

import android.Manifest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.zip.ZipFile
import javax.inject.Inject
import javax.inject.Singleton

data class PermissionRiskReport(
    val score: Int, // 0..100 (soft signal only; never sufficient for MALICIOUS alone)
    val reasons: List<String>
)

data class StaticApkReport(
    val indicators: List<String>,
    val hasDexClassLoader: Boolean,
    val hasRuntimeExec: Boolean,
    val hasReflection: Boolean,
    val hasCleartextTraffic: Boolean,
    val hardcodedUrls: List<String>,
    val hasObfuscation: Boolean,
    val hasCertPinningHint: Boolean
)

@Singleton
class PermissionRiskAnalyzer @Inject constructor() {

    /**
     * Evaluates permission combinations as a SOFT risk signal.
     *
     * Rules:
     * - Tier 1 (system) and Tier 2 (verified publisher) apps are never penalized for permissions.
     * - Device Admin, Background Location + Camera/Mic, and Accessibility are ONLY risk signals
     *   for non-system, non-verified apps that are sideloaded, have no launcher icon, or are unknown.
     */
    fun analyzePermissions(
        permissions: Set<String>,
        isSideloaded: Boolean,
        isHiddenApp: Boolean,
        isDeviceAdmin: Boolean,
        hasActiveAccessibility: Boolean,
        targetSdk: Int,
        isSystemOrVerified: Boolean = false,
        isPlayStoreApp: Boolean = false
    ): PermissionRiskReport {
        if (isSystemOrVerified) {
            return PermissionRiskReport(score = 0, reasons = emptyList())
        }

        var score = 0
        val reasons = mutableListOf<String>()

        val isUntrustedOriginOrHidden = isSideloaded || isHiddenApp || !isPlayStoreApp

        val hasSms = permissions.contains(Manifest.permission.READ_SMS) ||
            permissions.contains(Manifest.permission.RECEIVE_SMS) ||
            permissions.contains(Manifest.permission.SEND_SMS)
        val hasOverlay = permissions.contains(Manifest.permission.SYSTEM_ALERT_WINDOW)
        val hasInstall = permissions.contains(Manifest.permission.REQUEST_INSTALL_PACKAGES)
        val hasContacts = permissions.contains(Manifest.permission.READ_CONTACTS)
        val hasInternet = permissions.contains(Manifest.permission.INTERNET)
        val hasBgLocation = permissions.contains("android.permission.ACCESS_BACKGROUND_LOCATION")
        val hasCameraOrMic = permissions.contains(Manifest.permission.CAMERA) ||
            permissions.contains(Manifest.permission.RECORD_AUDIO)
        val hasAccessibilityPerm = hasActiveAccessibility ||
            permissions.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")

        if (hasSms && hasAccessibilityPerm && isUntrustedOriginOrHidden) {
            score += 38
            reasons.add("High-risk permission combo on sideloaded/unknown app: SMS + Accessibility Service")
        }
        if (hasOverlay && hasInstall && isUntrustedOriginOrHidden) {
            score += 32
            reasons.add("High-risk permission combo on sideloaded/unknown app: Screen Overlay + Install Packages")
        }
        if (isDeviceAdmin && isUntrustedOriginOrHidden) {
            score += 22
            reasons.add("Active Device Administrator privilege on sideloaded/unknown app")
        }
        if (hasContacts && hasInternet && isSideloaded) {
            score += 18
            reasons.add("Sideloaded app reads Contacts with Internet access")
        }
        if (hasBgLocation && hasCameraOrMic && isUntrustedOriginOrHidden) {
            score += 20
            reasons.add("Background Location combined with Camera/Microphone access on sideloaded/unknown app")
        }
        if (hasAccessibilityPerm && !hasSms && isUntrustedOriginOrHidden && (isSideloaded || isHiddenApp)) {
            score += 20
            reasons.add("Active Accessibility privilege on sideloaded or hidden app")
        }
        if (isSideloaded) {
            score += 15
            reasons.add("Installed outside Google Play Store (sideloaded)")
        }
        if (isHiddenApp) {
            score += 24
            reasons.add("Hidden app: no launcher icon registered")
        }
        if (targetSdk in 1..28 && isUntrustedOriginOrHidden) {
            score += 12
            reasons.add("Outdated targetSdk ($targetSdk) bypasses modern Android permission restrictions")
        }

        return PermissionRiskReport(
            score = score.coerceIn(0, 100),
            reasons = reasons
        )
    }

    /**
     * Static APK inspection reading manifest/DEX slices with bounded RAM usage.
     */
    suspend fun inspectApkStatic(apkFile: File, maxBytes: Int = 1_500_000): StaticApkReport =
        withContext(Dispatchers.IO) {
            if (!apkFile.exists() || !apkFile.canRead()) {
                return@withContext StaticApkReport(emptyList(), false, false, false, false, emptyList(), false, false)
            }
            var dexLoader = false
            var runtimeExec = false
            var reflection = false
            var cleartext = false
            var certPinning = false
            var shortClassCount = 0
            val urls = linkedSetOf<String>()
            val urlRegex = Regex("""https?://[a-zA-Z0-9._\-]{4,80}(?:/[a-zA-Z0-9._\-/?=&%]*)?""")

            var totalRead = 0
            runCatching {
                ZipFile(apkFile).use { zip ->
                    val entries = zip.entries()
                    while (entries.hasMoreElements() && totalRead < maxBytes) {
                        val entry = entries.nextElement()
                        val name = entry.name
                        if (name.endsWith(".dex") || name == "AndroidManifest.xml" || name.contains("network_security_config")) {
                            val buf = ByteArray(16 * 1024)
                            zip.getInputStream(entry).use { input ->
                                var n = input.read(buf)
                                while (n != -1 && totalRead < maxBytes) {
                                    totalRead += n
                                    val chunk = String(buf, 0, n, Charsets.ISO_8859_1)
                                    if (!dexLoader && (chunk.contains("DexClassLoader") || chunk.contains("InMemoryDexClassLoader"))) {
                                        dexLoader = true
                                    }
                                    if (!runtimeExec && (chunk.contains("Runtime;->exec") || chunk.contains("ProcessBuilder"))) {
                                        runtimeExec = true
                                    }
                                    if (!reflection && chunk.contains("java/lang/reflect/Method")) {
                                        reflection = true
                                    }
                                    if (!cleartext && (chunk.contains("cleartextTrafficPermitted=\"true\"") || chunk.contains("http://"))) {
                                        cleartext = true
                                    }
                                    if (!certPinning && (chunk.contains("CertificatePinner") || chunk.contains("pin-set"))) {
                                        certPinning = true
                                    }
                                    if (chunk.contains("La/a;") || chunk.contains("Lb/a;") || chunk.contains("Lo/a;")) {
                                        shortClassCount++
                                    }
                                    if (urls.size < 8) {
                                        urlRegex.findAll(chunk).take(4).forEach { m ->
                                            val candidate = m.value
                                            if (!candidate.contains("schemas.android.com") && !candidate.contains("www.w3.org")) {
                                                urls.add(candidate)
                                            }
                                        }
                                    }
                                    n = input.read(buf)
                                }
                            }
                        }
                    }
                }
            }

            val indicators = mutableListOf<String>()
            if (dexLoader) indicators.add("Dynamic code loading API (DexClassLoader)")
            if (runtimeExec) indicators.add("Shell command execution API (Runtime.exec / ProcessBuilder)")
            if (reflection) indicators.add("Reflective method invocation detected")
            if (cleartext) indicators.add("Insecure HTTP / cleartext traffic indicator")
            if (shortClassCount >= 2) indicators.add("Heavy name obfuscation detected")
            if (urls.isNotEmpty()) indicators.add("Hardcoded endpoints found (${urls.size})")
            if (certPinning) indicators.add("Certificate pinning detected (positive hardening)")

            StaticApkReport(
                indicators = indicators,
                hasDexClassLoader = dexLoader,
                hasRuntimeExec = runtimeExec,
                hasReflection = reflection,
                hasCleartextTraffic = cleartext,
                hardcodedUrls = urls.toList(),
                hasObfuscation = shortClassCount >= 2,
                hasCertPinningHint = certPinning
            )
        }
}
