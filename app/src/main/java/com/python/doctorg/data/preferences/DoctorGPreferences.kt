package com.python.doctorg.data.preferences

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.python.doctorg.core.security.CryptoManager
import com.python.doctorg.ui.theme.ThemeMode
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

private val Context.doctorGDataStore: DataStore<Preferences> by preferencesDataStore(name = "doctorg_prefs")

enum class ScanIntensity { LOW, BALANCED, FAST }

enum class DnsProvider(val label: String, val ip: String) {
    CLOUDFLARE_FAMILY("Cloudflare Family (Malware+Adult)", "1.1.1.3"),
    QUAD9("Quad9 (Malware Blocking)", "9.9.9.9"),
    GOOGLE("Google Public DNS", "8.8.8.8"),
    CUSTOM("Custom DNS", "1.1.1.1")
}

data class DoctorGSettings(
    val onboardingCompleted: Boolean = false,
    val privacyPolicyAccepted: Boolean = false,
    val themeMode: ThemeMode = ThemeMode.SYSTEM,
    val dynamicColor: Boolean = true,
    val highContrast: Boolean = false,
    val largeTextMode: Boolean = false,
    val lightweightMode: Boolean = false,
    val scanIntensity: ScanIntensity = ScanIntensity.BALANCED,
    val wifiOnlyUpdates: Boolean = true,
    val feedBaseUrl: String = "https://raw.githubusercontent.com/doctorg-security/doctorg-feeds/main/",
    val dnsProvider: DnsProvider = DnsProvider.QUAD9,
    val customDnsIp: String = "1.1.1.1",
    val dailyQuickScanEnabled: Boolean = true,
    val weeklyFullScanEnabled: Boolean = true,
    val realTimeInstallScanEnabled: Boolean = true,
    val vpnAutoStart: Boolean = false,
    val appLockEnabled: Boolean = false,
    val appLockFakeCrash: Boolean = false,
    val appLockSelfProtect: Boolean = false,
    val appLockBiometric: Boolean = false,
    val lockedPackages: Set<String> = emptySet(),
    val lastSecurityScore: Int = 88,
    val lastSignatureUpdateMs: Long = 0L,
    val signatureVersion: String = "2026.11.01 (Bundled)",
    val monthlyDataLimitMb: Int = 5000,
    val lastPermissionPromptMs: Long = 0L,
    val hasVirusTotalKey: Boolean = false,
    val hasSafeBrowsingKey: Boolean = false,
    val hasAppLockPin: Boolean = false,
    val virusTotalThreshold: Int = 5,
    val lastScoringVersion: Int = 0,
    val appLanguageTag: String = ""
)

@Singleton
class DoctorGPreferences @Inject constructor(
    @ApplicationContext private val context: Context,
    private val cryptoManager: CryptoManager
) {
    private object Keys {
        val ONBOARDING_COMPLETED = booleanPreferencesKey("onboarding_completed")
        val PRIVACY_ACCEPTED = booleanPreferencesKey("privacy_accepted")
        val THEME_MODE = stringPreferencesKey("theme_mode")
        val DYNAMIC_COLOR = booleanPreferencesKey("dynamic_color")
        val HIGH_CONTRAST = booleanPreferencesKey("high_contrast")
        val LARGE_TEXT = booleanPreferencesKey("large_text")
        val LIGHTWEIGHT_MODE = booleanPreferencesKey("lightweight_mode")
        val SCAN_INTENSITY = stringPreferencesKey("scan_intensity")
        val WIFI_ONLY_UPDATES = booleanPreferencesKey("wifi_only_updates")
        val FEED_BASE_URL = stringPreferencesKey("feed_base_url")
        val DNS_PROVIDER = stringPreferencesKey("dns_provider")
        val CUSTOM_DNS_IP = stringPreferencesKey("custom_dns_ip")
        val DAILY_QUICK_SCAN = booleanPreferencesKey("daily_quick_scan")
        val WEEKLY_FULL_SCAN = booleanPreferencesKey("weekly_full_scan")
        val REALTIME_INSTALL_SCAN = booleanPreferencesKey("realtime_install_scan")
        val VPN_AUTO_START = booleanPreferencesKey("vpn_auto_start")
        val APPLOCK_ENABLED = booleanPreferencesKey("applock_enabled")
        val APPLOCK_FAKE_CRASH = booleanPreferencesKey("applock_fake_crash")
        val APPLOCK_SELF_PROTECT = booleanPreferencesKey("applock_self_protect")
        val APPLOCK_BIOMETRIC = booleanPreferencesKey("applock_biometric")
        val APPLOCK_PIN_HASH = stringPreferencesKey("applock_pin_hash")
        val LOCKED_PACKAGES = stringSetPreferencesKey("locked_packages")
        val LAST_SCORE = intPreferencesKey("last_security_score")
        val LAST_SIG_UPDATE = longPreferencesKey("last_sig_update_ms")
        val SIG_VERSION = stringPreferencesKey("sig_version")
        val MONTHLY_DATA_LIMIT_MB = intPreferencesKey("monthly_data_limit_mb")
        val LAST_PERM_PROMPT_MS = longPreferencesKey("last_perm_prompt_ms")
        val VT_API_KEY_ENC = stringPreferencesKey("vt_api_key_enc")
        val SB_API_KEY_ENC = stringPreferencesKey("sb_api_key_enc")
        val VT_THRESHOLD = intPreferencesKey("vt_malicious_threshold")
        val LAST_SCORING_VERSION = intPreferencesKey("last_scoring_version")
        val APP_LANGUAGE_TAG = stringPreferencesKey("app_language_tag")
    }

    val settingsFlow: Flow<DoctorGSettings> = context.doctorGDataStore.data.map { p ->
        DoctorGSettings(
            onboardingCompleted = p[Keys.ONBOARDING_COMPLETED] ?: false,
            privacyPolicyAccepted = p[Keys.PRIVACY_ACCEPTED] ?: false,
            themeMode = runCatching { ThemeMode.valueOf(p[Keys.THEME_MODE] ?: "SYSTEM") }.getOrDefault(ThemeMode.SYSTEM),
            dynamicColor = p[Keys.DYNAMIC_COLOR] ?: true,
            highContrast = p[Keys.HIGH_CONTRAST] ?: false,
            largeTextMode = p[Keys.LARGE_TEXT] ?: false,
            lightweightMode = p[Keys.LIGHTWEIGHT_MODE] ?: false,
            scanIntensity = runCatching { ScanIntensity.valueOf(p[Keys.SCAN_INTENSITY] ?: "BALANCED") }.getOrDefault(ScanIntensity.BALANCED),
            wifiOnlyUpdates = p[Keys.WIFI_ONLY_UPDATES] ?: true,
            feedBaseUrl = p[Keys.FEED_BASE_URL] ?: "https://raw.githubusercontent.com/doctorg-security/doctorg-feeds/main/",
            dnsProvider = runCatching { DnsProvider.valueOf(p[Keys.DNS_PROVIDER] ?: "QUAD9") }.getOrDefault(DnsProvider.QUAD9),
            customDnsIp = p[Keys.CUSTOM_DNS_IP] ?: "1.1.1.1",
            dailyQuickScanEnabled = p[Keys.DAILY_QUICK_SCAN] ?: true,
            weeklyFullScanEnabled = p[Keys.WEEKLY_FULL_SCAN] ?: true,
            realTimeInstallScanEnabled = p[Keys.REALTIME_INSTALL_SCAN] ?: true,
            vpnAutoStart = p[Keys.VPN_AUTO_START] ?: false,
            appLockEnabled = p[Keys.APPLOCK_ENABLED] ?: false,
            appLockFakeCrash = p[Keys.APPLOCK_FAKE_CRASH] ?: false,
            appLockSelfProtect = p[Keys.APPLOCK_SELF_PROTECT] ?: false,
            appLockBiometric = p[Keys.APPLOCK_BIOMETRIC] ?: false,
            lockedPackages = p[Keys.LOCKED_PACKAGES] ?: emptySet(),
            lastSecurityScore = p[Keys.LAST_SCORE] ?: 88,
            lastSignatureUpdateMs = p[Keys.LAST_SIG_UPDATE] ?: 0L,
            signatureVersion = p[Keys.SIG_VERSION] ?: "2026.11.01 (Bundled)",
            monthlyDataLimitMb = p[Keys.MONTHLY_DATA_LIMIT_MB] ?: 5000,
            lastPermissionPromptMs = p[Keys.LAST_PERM_PROMPT_MS] ?: 0L,
            hasVirusTotalKey = !p[Keys.VT_API_KEY_ENC].isNullOrBlank(),
            hasSafeBrowsingKey = !p[Keys.SB_API_KEY_ENC].isNullOrBlank(),
            hasAppLockPin = !p[Keys.APPLOCK_PIN_HASH].isNullOrBlank(),
            virusTotalThreshold = (p[Keys.VT_THRESHOLD] ?: 5).coerceIn(1, 30),
            lastScoringVersion = p[Keys.LAST_SCORING_VERSION] ?: 0,
            appLanguageTag = p[Keys.APP_LANGUAGE_TAG] ?: ""
        )
    }

    suspend fun completeOnboarding(privacyAccepted: Boolean) {
        context.doctorGDataStore.edit {
            it[Keys.PRIVACY_ACCEPTED] = privacyAccepted
            it[Keys.ONBOARDING_COMPLETED] = true
        }
    }

    suspend fun setThemeMode(mode: ThemeMode) = context.doctorGDataStore.edit { it[Keys.THEME_MODE] = mode.name }
    suspend fun setDynamicColor(enabled: Boolean) = context.doctorGDataStore.edit { it[Keys.DYNAMIC_COLOR] = enabled }
    suspend fun setHighContrast(enabled: Boolean) = context.doctorGDataStore.edit { it[Keys.HIGH_CONTRAST] = enabled }
    suspend fun setLargeTextMode(enabled: Boolean) = context.doctorGDataStore.edit { it[Keys.LARGE_TEXT] = enabled }
    suspend fun setLightweightMode(enabled: Boolean) = context.doctorGDataStore.edit { it[Keys.LIGHTWEIGHT_MODE] = enabled }
    suspend fun setScanIntensity(intensity: ScanIntensity) = context.doctorGDataStore.edit { it[Keys.SCAN_INTENSITY] = intensity.name }
    suspend fun setWifiOnlyUpdates(enabled: Boolean) = context.doctorGDataStore.edit { it[Keys.WIFI_ONLY_UPDATES] = enabled }
    suspend fun setFeedBaseUrl(url: String) = context.doctorGDataStore.edit { it[Keys.FEED_BASE_URL] = url.trim() }
    suspend fun setDnsProvider(provider: DnsProvider, customIp: String? = null) = context.doctorGDataStore.edit {
        it[Keys.DNS_PROVIDER] = provider.name
        if (customIp != null) it[Keys.CUSTOM_DNS_IP] = customIp.trim()
    }
    suspend fun setScheduledScans(dailyQuick: Boolean, weeklyFull: Boolean) = context.doctorGDataStore.edit {
        it[Keys.DAILY_QUICK_SCAN] = dailyQuick
        it[Keys.WEEKLY_FULL_SCAN] = weeklyFull
    }
    suspend fun setRealTimeInstallScan(enabled: Boolean) = context.doctorGDataStore.edit { it[Keys.REALTIME_INSTALL_SCAN] = enabled }
    suspend fun setVpnAutoStart(enabled: Boolean) = context.doctorGDataStore.edit { it[Keys.VPN_AUTO_START] = enabled }
    suspend fun setLastSecurityScore(score: Int) = context.doctorGDataStore.edit { it[Keys.LAST_SCORE] = score.coerceIn(0, 100) }
    suspend fun setSignatureMetadata(version: String, updatedMs: Long) = context.doctorGDataStore.edit {
        it[Keys.SIG_VERSION] = version
        it[Keys.LAST_SIG_UPDATE] = updatedMs
    }
    suspend fun setMonthlyDataLimitMb(mb: Int) = context.doctorGDataStore.edit { it[Keys.MONTHLY_DATA_LIMIT_MB] = mb.coerceAtLeast(100) }
    suspend fun setVirusTotalThreshold(threshold: Int) = context.doctorGDataStore.edit { it[Keys.VT_THRESHOLD] = threshold.coerceIn(1, 30) }
    suspend fun setLastScoringVersion(version: Int) = context.doctorGDataStore.edit { it[Keys.LAST_SCORING_VERSION] = version }
    suspend fun setAppLanguageTag(tag: String) = context.doctorGDataStore.edit { it[Keys.APP_LANGUAGE_TAG] = tag.trim().lowercase() }
    suspend fun recordPermissionPromptNow() = context.doctorGDataStore.edit { it[Keys.LAST_PERM_PROMPT_MS] = System.currentTimeMillis() }

    suspend fun canNagPermissionToday(): Boolean {
        val last = settingsFlow.first().lastPermissionPromptMs
        return System.currentTimeMillis() - last > 24L * 60L * 60L * 1000L
    }

    suspend fun saveVirusTotalApiKey(plainKey: String) = context.doctorGDataStore.edit {
        it[Keys.VT_API_KEY_ENC] = if (plainKey.isBlank()) "" else cryptoManager.encryptString(plainKey.trim())
    }

    suspend fun getVirusTotalApiKey(): String {
        val enc = context.doctorGDataStore.data.first()[Keys.VT_API_KEY_ENC].orEmpty()
        return cryptoManager.decryptString(enc)
    }

    suspend fun saveSafeBrowsingApiKey(plainKey: String) = context.doctorGDataStore.edit {
        it[Keys.SB_API_KEY_ENC] = if (plainKey.isBlank()) "" else cryptoManager.encryptString(plainKey.trim())
    }

    suspend fun getSafeBrowsingApiKey(): String {
        val enc = context.doctorGDataStore.data.first()[Keys.SB_API_KEY_ENC].orEmpty()
        return cryptoManager.decryptString(enc)
    }

    suspend fun setAppLockPin(pin: String) = context.doctorGDataStore.edit {
        it[Keys.APPLOCK_PIN_HASH] = cryptoManager.hashSecretPin(pin)
        it[Keys.APPLOCK_ENABLED] = true
    }

    suspend fun verifyAppLockPin(pin: String): Boolean {
        val hash = context.doctorGDataStore.data.first()[Keys.APPLOCK_PIN_HASH].orEmpty()
        return hash.isNotBlank() && cryptoManager.verifySecretPin(pin, hash)
    }

    suspend fun updateAppLockOptions(
        enabled: Boolean? = null,
        fakeCrash: Boolean? = null,
        selfProtect: Boolean? = null,
        biometric: Boolean? = null
    ) = context.doctorGDataStore.edit {
        if (enabled != null) it[Keys.APPLOCK_ENABLED] = enabled
        if (fakeCrash != null) it[Keys.APPLOCK_FAKE_CRASH] = fakeCrash
        if (selfProtect != null) it[Keys.APPLOCK_SELF_PROTECT] = selfProtect
        if (biometric != null) it[Keys.APPLOCK_BIOMETRIC] = biometric
    }

    suspend fun toggleLockedPackage(packageName: String) = context.doctorGDataStore.edit {
        val current = (it[Keys.LOCKED_PACKAGES] ?: emptySet()).toMutableSet()
        if (!current.add(packageName)) current.remove(packageName)
        it[Keys.LOCKED_PACKAGES] = current
    }
}
