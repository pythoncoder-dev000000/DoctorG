package com.python.doctorg.domain.engine

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import android.provider.Settings
import com.python.doctorg.core.security.CryptoManager
import com.python.doctorg.data.remote.FeedUpdateManager
import com.python.doctorg.domain.model.CveFinding
import com.python.doctorg.domain.model.DeviceSecurityAudit
import com.python.doctorg.domain.model.DeviceTamperingFinding
import com.python.doctorg.domain.model.ThreatLevel
import com.python.doctorg.domain.model.TrustTier
import dagger.hilt.android.qualifiers.ApplicationContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

data class OfficialAppEntry(
    val name: String,
    val packageName: String,
    val certSha256: String,
    val category: String
)

data class StalkerwareConfig(
    val knownPackages: Set<String>,
    val keywords: List<String>,
    val safetyGuidance: List<String>
)

@Singleton
class DeviceAuditEngine @Inject constructor(
    @ApplicationContext private val context: Context,
    private val feedUpdateManager: FeedUpdateManager,
    private val cryptoManager: CryptoManager
) {
    private val remoteAccessPackages = setOf(
        "com.anydesk.anydeskandroid",
        "com.teamviewer.teamviewer.market.mobile",
        "com.teamviewer.quicksupport.market",
        "com.carriez.flutter_hbb", // RustDesk
        "com.sand.airdroid",
        "com.rsupport.mvagent"
    )

    val bankingAndUpiPackages = setOf(
        "com.google.android.apps.nbu.paisa.user",
        "com.phonepe.app",
        "net.one97.paytm",
        "in.org.npci.upiapp",
        "com.sbi.lotusintouch",
        "com.snapwork.hdfc",
        "com.csam.icici.bank.imobile",
        "com.axis.mobile"
    )

    fun loadTrustedPublishers(): List<TrustedPublisherEntry> {
        val raw = feedUpdateManager.readLatestOrBundledAsset("trusted_publishers.json")
        if (raw.isNotBlank()) {
            val parsed = parseTrustedPublishersJson(raw)
            if (parsed.isNotEmpty()) return parsed
        }
        // Fallback to legacy official_apps.json if trusted_publishers.json is empty
        return loadOfficialApps().map { o ->
            TrustedPublisherEntry(
                packageName = o.packageName,
                displayName = o.name,
                certSha256 = if (o.certSha256.length == 64) listOf(o.certSha256.lowercase()) else emptyList(),
                publisher = o.name,
                category = o.category
            )
        }
    }

    fun loadKnownBadCerts(): Map<String, String> {
        val raw = feedUpdateManager.readLatestOrBundledAsset("known_bad_certs.json")
        if (raw.isBlank()) return emptyMap()
        return runCatching {
            val arr = JSONObject(raw).optJSONArray("certificates") ?: return@runCatching emptyMap()
            buildMap {
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    val hash = o.optString("sha256").lowercase().trim()
                    if (hash.length == 64) {
                        put(hash, o.optString("family", "Known Malicious Certificate"))
                    }
                }
            }
        }.getOrDefault(emptyMap())
    }

    fun loadOfficialApps(): List<OfficialAppEntry> {
        val raw = feedUpdateManager.readLatestOrBundledAsset("official_apps.json")
        if (raw.isBlank()) return emptyList()
        return runCatching {
            val arr = JSONObject(raw).optJSONArray("apps") ?: return@runCatching emptyList()
            buildList {
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    add(
                        OfficialAppEntry(
                            name = o.optString("name"),
                            packageName = o.optString("packageName"),
                            certSha256 = o.optString("certSha256").lowercase(),
                            category = o.optString("category")
                        )
                    )
                }
            }
        }.getOrDefault(emptyList())
    }

    fun loadStalkerwareConfig(): StalkerwareConfig {
        val raw = feedUpdateManager.readLatestOrBundledAsset("stalkerware_list.json")
        if (raw.isBlank()) return StalkerwareConfig(emptySet(), emptyList(), emptyList())
        return runCatching {
            val root = JSONObject(raw)
            val pkgs = root.optJSONArray("knownPackages")?.let { arr ->
                (0 until arr.length()).map { arr.getString(it).lowercase() }.toSet()
            } ?: emptySet()
            val kw = root.optJSONArray("keywords")?.let { arr ->
                (0 until arr.length()).map { arr.getString(it).lowercase() }
            } ?: emptyList()
            val guide = root.optJSONArray("safetyGuidance")?.let { arr ->
                (0 until arr.length()).map { arr.getString(it) }
            } ?: emptyList()
            StalkerwareConfig(pkgs, kw, guide)
        }.getOrDefault(StalkerwareConfig(emptySet(), emptyList(), emptyList()))
    }

    /**
     * Extracts ALL signing certificate SHA-256 fingerprints for [pkgInfo], including
     * Android P+ `signingCertificateHistory` so key rotation / lineage is handled properly.
     */
    fun extractSigningCertSha256List(pkgInfo: PackageInfo): List<String> {
        val certs = linkedSetOf<String>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signingInfo = pkgInfo.signingInfo
            if (signingInfo != null) {
                signingInfo.apkContentsSigners?.forEach { sig ->
                    certs.add(cryptoManager.sha256Bytes(sig.toByteArray()).joinToString("") { "%02x".format(it) })
                }
                if (signingInfo.hasPastSigningCertificates()) {
                    signingInfo.signingCertificateHistory?.forEach { sig ->
                        certs.add(cryptoManager.sha256Bytes(sig.toByteArray()).joinToString("") { "%02x".format(it) })
                    }
                }
            }
        } else {
            @Suppress("DEPRECATION")
            pkgInfo.signatures?.forEach { sig ->
                certs.add(cryptoManager.sha256Bytes(sig.toByteArray()).joinToString("") { "%02x".format(it) })
            }
        }
        return certs.toList()
    }

    fun extractSigningCertSha256(pkgInfo: PackageInfo): String =
        extractSigningCertSha256List(pkgInfo).firstOrNull().orEmpty()

    /**
     * Exports real SHA-256 signing certificates for seeded publishers currently installed on this
     * device so the user can populate `assets/trusted_publishers.json` from a clean device.
     */
    fun exportInstalledTrustedCertsJson(): String {
        val pm = context.packageManager
        val seeded = loadTrustedPublishers()
        val arr = JSONArray()
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            @Suppress("DEPRECATION")
            PackageManager.GET_SIGNATURES
        }
        seeded.forEach { entry ->
            val pkgInfo = runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getPackageInfo(entry.packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(entry.packageName, flags)
                }
            }.getOrNull() ?: return@forEach

            val hashes = extractSigningCertSha256List(pkgInfo)
            if (hashes.isNotEmpty()) {
                val obj = JSONObject().apply {
                    put("packageName", entry.packageName)
                    put("displayName", entry.displayName)
                    put("certSha256", JSONArray(hashes))
                    put("publisher", entry.publisher)
                    put("category", entry.category)
                }
                arr.put(obj)
            }
        }
        return JSONObject().apply {
            put("schemaVersion", 1)
            put("version", "device-extracted")
            put("publishers", arr)
        }.toString(2)
    }

    fun detectCloneOrFakeApp(
        appName: String,
        packageName: String,
        signingCertSha256s: List<String>,
        trustTier: TrustTier,
        trustedPublishers: List<TrustedPublisherEntry>
    ): String? = ScanVerdictEngine.detectLookalike(
        appName = appName,
        packageName = packageName,
        signingCertSha256s = signingCertSha256s,
        trustTier = trustTier,
        trustedPublishers = trustedPublishers
    )

    fun detectDeviceTampering(): List<DeviceTamperingFinding> {
        val suPaths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/data/local/xbin/su", "/data/local/bin/su", "/su/bin/su"
        )
        val hasSuBinary = suPaths.any { File(it).exists() }
        val hasMagisk = listOf("/sbin/.magisk", "/data/adb/magisk", "/data/adb/ksu").any { File(it).exists() } ||
            isPackageInstalled("com.topjohnwu.magisk")
        val hasXposed = isPackageInstalled("de.robv.android.xposed.installer") ||
            isPackageInstalled("org.lsposed.manager") ||
            File("/system/framework/XposedBridge.jar").exists()
        val hasFrida = listOf("/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server").any { File(it).exists() }
        val isEmulator = Build.FINGERPRINT.startsWith("generic") ||
            Build.MODEL.contains("Emulator", ignoreCase = true) ||
            Build.MODEL.contains("Android SDK built for", ignoreCase = true) ||
            Build.PRODUCT.contains("sdk_gphone", ignoreCase = true)
        val isDebugger = Debug.isDebuggerConnected() || Debug.waitingForDebugger()
        val testKeys = Build.TAGS?.contains("test-keys") == true

        return listOf(
            DeviceTamperingFinding(
                indicator = "Root / su Binary",
                detected = hasSuBinary,
                severity = if (hasSuBinary) ThreatLevel.SUSPICIOUS else ThreatLevel.SAFE,
                explanation = if (hasSuBinary) "Elevated root binary detected; apps could bypass Android sandbox." else "No root su binaries detected."
            ),
            DeviceTamperingFinding(
                indicator = "Magisk / KernelSU",
                detected = hasMagisk,
                severity = if (hasMagisk) ThreatLevel.SUSPICIOUS else ThreatLevel.SAFE,
                explanation = if (hasMagisk) "Systemless root framework (Magisk/KernelSU) detected." else "No Magisk or KernelSU artifacts found."
            ),
            DeviceTamperingFinding(
                indicator = "Xposed / LSPosed Hooking",
                detected = hasXposed,
                severity = if (hasXposed) ThreatLevel.MALICIOUS else ThreatLevel.SAFE,
                explanation = if (hasXposed) "Runtime hooking framework can intercept banking credentials and PINs." else "No Xposed or LSPosed framework detected."
            ),
            DeviceTamperingFinding(
                indicator = "Frida Instrumentation",
                detected = hasFrida,
                severity = if (hasFrida) ThreatLevel.MALICIOUS else ThreatLevel.SAFE,
                explanation = if (hasFrida) "Frida server binary detected in temporary directory." else "No Frida instrumentation artifacts found."
            ),
            DeviceTamperingFinding(
                indicator = "Unlocked / Test-Keys Build",
                detected = testKeys,
                severity = if (testKeys) ThreatLevel.SUSPICIOUS else ThreatLevel.SAFE,
                explanation = if (testKeys) "OS signed with test-keys (custom ROM or unlocked bootloader indicator)." else "OS signed with release keys."
            ),
            DeviceTamperingFinding(
                indicator = "Active Debugger",
                detected = isDebugger,
                severity = if (isDebugger) ThreatLevel.SUSPICIOUS else ThreatLevel.SAFE,
                explanation = if (isDebugger) "A debugger is attached to DoctorG." else "No active debugger attached."
            ),
            DeviceTamperingFinding(
                indicator = "Emulator Environment",
                detected = isEmulator,
                severity = if (isEmulator) ThreatLevel.SUSPICIOUS else ThreatLevel.SAFE,
                explanation = if (isEmulator) "Running inside an Android emulator / virtualized environment." else "Physical Android hardware detected."
            )
        )
    }

    fun checkCves(): List<CveFinding> {
        val raw = feedUpdateManager.readLatestOrBundledAsset("android_cves.json")
        if (raw.isBlank()) return emptyList()
        val patch = Build.VERSION.SECURITY_PATCH.ifBlank { "2024-01-01" }
        val api = Build.VERSION.SDK_INT

        return runCatching {
            val arr = JSONObject(raw).optJSONArray("cves") ?: return@runCatching emptyList()
            buildList {
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    val maxPatch = o.optString("maxVulnerablePatch", "2024-01-01")
                    val minApi = o.optInt("minApi", 26)
                    val maxApi = o.optInt("maxApi", 36)
                    val vulnerable = api in minApi..maxApi && patch <= maxPatch
                    add(
                        CveFinding(
                            cveId = o.optString("cveId"),
                            severity = o.optString("severity", "HIGH"),
                            title = o.optString("title"),
                            advice = o.optString("advice"),
                            isVulnerable = vulnerable
                        )
                    )
                }
            }
        }.getOrDefault(emptyList())
    }

    fun getActiveAccessibilityServices(): List<String> {
        val enabled = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ).orEmpty()
        if (enabled.isBlank()) return emptyList()
        return enabled.split(":").map { it.substringBefore("/") }.distinct().filter { it.isNotBlank() }
    }

    fun getActiveDeviceAdmins(): List<String> {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager ?: return emptyList()
        return dpm.activeAdmins?.map { it.packageName }?.distinct().orEmpty()
    }

    fun getInstalledRemoteAccessApps(): List<String> =
        remoteAccessPackages.filter { isPackageInstalled(it) }

    fun performFullDeviceAudit(wifiSummary: String): DeviceSecurityAudit {
        val km = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        val hasLock = km?.isDeviceSecure == true
        val adbEnabled = Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        val devOpts = Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1

        val overlayApps = runCatching {
            val pm = context.packageManager
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
                .filter { pkg ->
                    pkg.requestedPermissions?.contains(android.Manifest.permission.SYSTEM_ALERT_WINDOW) == true &&
                        (pkg.applicationInfo?.flags?.and(android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0)
                }
                .map { it.packageName }
                .take(15)
        }.getOrDefault(emptyList())

        return DeviceSecurityAudit(
            hasScreenLock = hasLock,
            androidVersionLabel = "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
            securityPatchLevel = Build.VERSION.SECURITY_PATCH.ifBlank { "Unknown" },
            usbDebuggingEnabled = adbEnabled,
            developerOptionsEnabled = devOpts,
            activeAccessibilityServices = getActiveAccessibilityServices(),
            activeDeviceAdmins = getActiveDeviceAdmins(),
            activeOverlayApps = overlayApps,
            activeRemoteAccessApps = getInstalledRemoteAccessApps(),
            tamperingFindings = detectDeviceTampering(),
            cveFindings = checkCves(),
            wifiSummary = wifiSummary
        )
    }

    fun isPackageInstalled(pkg: String): Boolean = runCatching {
        context.packageManager.getPackageInfo(pkg, 0)
        true
    }.getOrDefault(false)

    companion object {
        fun parseTrustedPublishersJson(raw: String): List<TrustedPublisherEntry> {
            if (raw.isBlank()) return emptyList()
            return runCatching {
                val arr = JSONObject(raw).optJSONArray("publishers") ?: return@runCatching emptyList()
                buildList {
                    for (i in 0 until arr.length()) {
                        val o = arr.getJSONObject(i)
                        val pkg = o.optString("packageName").trim()
                        if (pkg.isBlank()) continue
                        val certs = buildList {
                            val certArr = o.optJSONArray("certSha256")
                            if (certArr != null) {
                                for (j in 0 until certArr.length()) {
                                    val c = certArr.optString(j).lowercase().trim()
                                    if (c.length == 64) add(c)
                                }
                            }
                        }
                        add(
                            TrustedPublisherEntry(
                                packageName = pkg,
                                displayName = o.optString("displayName", pkg),
                                certSha256 = certs,
                                publisher = o.optString("publisher", o.optString("displayName", pkg)),
                                category = o.optString("category", "General")
                            )
                        )
                    }
                }
            }.getOrDefault(emptyList())
        }
    }
}
