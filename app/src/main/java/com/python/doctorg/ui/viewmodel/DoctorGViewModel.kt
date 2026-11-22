package com.python.doctorg.ui.viewmodel

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.util.Base64
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.content.FileProvider
import androidx.core.content.edit
import androidx.core.net.toUri
import androidx.core.os.LocaleListCompat
import androidx.glance.appwidget.updateAll
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.python.doctorg.core.adaptive.DeviceCapabilities
import com.python.doctorg.core.adaptive.DeviceCapabilityChecker
import com.python.doctorg.core.permissions.DoctorGPermissionId
import com.python.doctorg.core.permissions.PermissionItemStatus
import com.python.doctorg.core.permissions.PermissionManager
import com.python.doctorg.core.security.CryptoManager
import com.python.doctorg.data.local.DoctorGDatabase
import com.python.doctorg.data.local.entity.BlockedDomainEntity
import com.python.doctorg.data.local.entity.BlockedEventEntity
import com.python.doctorg.data.local.entity.ExcludedAppEntity
import com.python.doctorg.data.local.entity.FirewallRuleEntity
import com.python.doctorg.data.local.entity.QuarantineItemEntity
import com.python.doctorg.data.local.entity.SpamNumberEntity
import com.python.doctorg.data.local.vault.TotpAccountEntity
import com.python.doctorg.data.local.vault.VaultDatabase
import com.python.doctorg.data.local.vault.VaultItemEntity
import com.python.doctorg.data.preferences.DnsProvider
import com.python.doctorg.data.preferences.DoctorGPreferences
import com.python.doctorg.data.preferences.DoctorGSettings
import com.python.doctorg.data.preferences.ScanIntensity
import com.python.doctorg.data.remote.FeedUpdateManager
import com.python.doctorg.data.remote.VirusTotalApi
import com.python.doctorg.data.remote.VirusTotalRateLimiter
import com.python.doctorg.domain.engine.BleTrackerDetector
import com.python.doctorg.domain.engine.DeviceAuditEngine
import com.python.doctorg.domain.engine.MalwareScanEngine
import com.python.doctorg.domain.engine.NetworkToolsEngine
import com.python.doctorg.domain.engine.PasswordHealthEngine
import com.python.doctorg.domain.engine.QuarantineManager
import com.python.doctorg.domain.engine.SafetyLocationSirenEngine
import com.python.doctorg.domain.engine.ScanVerdictEngine
import com.python.doctorg.domain.engine.ScamSmsClassifier
import com.python.doctorg.domain.model.SignalKind
import com.python.doctorg.domain.model.VerdictSignal
import com.python.doctorg.domain.model.AccountCheckupItem
import com.python.doctorg.domain.model.AppScanFinding
import com.python.doctorg.domain.model.AppUsageStat
import com.python.doctorg.domain.model.DeviceSecurityAudit
import com.python.doctorg.domain.model.LanDevice
import com.python.doctorg.domain.model.PasswordHealthReport
import com.python.doctorg.domain.model.ScanLifecycleState
import com.python.doctorg.domain.model.ScanMode
import com.python.doctorg.domain.model.ScanProgressState
import com.python.doctorg.domain.model.ScamAwarenessCard
import com.python.doctorg.domain.model.ScamSmsResult
import com.python.doctorg.domain.model.ThreatLevel
import com.python.doctorg.domain.model.WifiSecurityAudit
import com.python.doctorg.service.AppLockMonitorService
import com.python.doctorg.service.DoctorGVpnService
import com.python.doctorg.service.FullScanForegroundService
import com.python.doctorg.service.ScanCoordinator
import com.python.doctorg.ui.theme.ThemeMode
import com.python.doctorg.widget.DoctorGWidget
import com.python.doctorg.worker.DoctorGWorkScheduler
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import javax.inject.Inject

data class PrivacyPermissionGroup(
    val permissionLabel: String,
    val permissionKey: String,
    val apps: List<Pair<String, String>> // packageName to appName
)

data class LinkCheckVerdict(
    val url: String,
    val isSafe: Boolean,
    val reason: String
)

@HiltViewModel
class DoctorGViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val database: DoctorGDatabase,
    private val vaultDatabase: VaultDatabase,
    private val preferences: DoctorGPreferences,
    private val permissionManager: PermissionManager,
    private val cryptoManager: CryptoManager,
    private val scanEngine: MalwareScanEngine,
    private val scanCoordinator: ScanCoordinator,
    private val deviceAuditEngine: DeviceAuditEngine,
    private val feedUpdateManager: FeedUpdateManager,
    private val scamSmsClassifier: ScamSmsClassifier,
    private val networkToolsEngine: NetworkToolsEngine,
    private val quarantineManager: QuarantineManager,
    private val bleTrackerDetector: BleTrackerDetector,
    private val safetyEngine: SafetyLocationSirenEngine,
    private val passwordHealthEngine: PasswordHealthEngine,
    private val workScheduler: DoctorGWorkScheduler,
    private val virusTotalApi: VirusTotalApi,
    private val vtRateLimiter: VirusTotalRateLimiter
) : ViewModel() {

    val settings: StateFlow<DoctorGSettings> = preferences.settingsFlow
        .stateIn(viewModelScope, SharingStarted.Eagerly, DoctorGSettings())

    val scanState: StateFlow<ScanProgressState> = scanCoordinator.state
    val isVpnRunning: StateFlow<Boolean> = DoctorGVpnService.isRunning
    val isAppLockServiceRunning: StateFlow<Boolean> = AppLockMonitorService.isRunning

    val signatureCount = database.malwareHashDao().observeCount()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)
    val scanHistory = database.scanHistoryDao().observeHistory()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    val excludedApps = database.excludedAppDao().observeAll()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    val quarantineItems = database.quarantineDao().observeItems()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    val blocklistCount = database.webProtectionDao().observeBlocklistCount()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)
    val blockedEventCount = database.webProtectionDao().observeBlockedEventCount()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)
    val blockedEvents = database.webProtectionDao().observeBlockedEvents()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    val allowlistDomains = database.webProtectionDao().observeAllowlist()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    val firewallRules = database.firewallDao().observeRules()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    val spamNumbers = database.spamNumberDao().observeAll()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    val trackerSightings = database.trackerSightingDao().observeAll()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    val appBaselines = database.appBaselineDao().observeAll()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val vaultItems = vaultDatabase.vaultDao().observeVaultItems()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    val totpAccounts = vaultDatabase.vaultDao().observeTotpAccounts()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val _permissions = MutableStateFlow(permissionManager.getAllStatuses())
    val permissions: StateFlow<List<PermissionItemStatus>> = _permissions.asStateFlow()

    private val _capabilities = MutableStateFlow(DeviceCapabilityChecker.inspect(context))
    val capabilities: StateFlow<DeviceCapabilities> = _capabilities.asStateFlow()

    private val _deviceAudit = MutableStateFlow<DeviceSecurityAudit?>(null)
    val deviceAudit: StateFlow<DeviceSecurityAudit?> = _deviceAudit.asStateFlow()

    private val _wifiAudit = MutableStateFlow<WifiSecurityAudit?>(null)
    val wifiAudit: StateFlow<WifiSecurityAudit?> = _wifiAudit.asStateFlow()

    private val _lanDevices = MutableStateFlow<List<LanDevice>>(emptyList())
    val lanDevices: StateFlow<List<LanDevice>> = _lanDevices.asStateFlow()

    private val _networkToolOutput = MutableStateFlow("")
    val networkToolOutput: StateFlow<String> = _networkToolOutput.asStateFlow()

    private val _dataUsageStats = MutableStateFlow<List<AppUsageStat>>(emptyList())
    val dataUsageStats: StateFlow<List<AppUsageStat>> = _dataUsageStats.asStateFlow()

    private val _linkCheckVerdict = MutableStateFlow<LinkCheckVerdict?>(null)
    val linkCheckVerdict: StateFlow<LinkCheckVerdict?> = _linkCheckVerdict.asStateFlow()

    private val _scamSmsResult = MutableStateFlow<ScamSmsResult?>(null)
    val scamSmsResult: StateFlow<ScamSmsResult?> = _scamSmsResult.asStateFlow()

    private val _awarenessCards = MutableStateFlow<List<ScamAwarenessCard>>(emptyList())
    val awarenessCards: StateFlow<List<ScamAwarenessCard>> = _awarenessCards.asStateFlow()

    private val _passwordHealth = MutableStateFlow<PasswordHealthReport?>(null)
    val passwordHealth: StateFlow<PasswordHealthReport?> = _passwordHealth.asStateFlow()

    private val _privacyGroups = MutableStateFlow<List<PrivacyPermissionGroup>>(emptyList())
    val privacyGroups: StateFlow<List<PrivacyPermissionGroup>> = _privacyGroups.asStateFlow()

    private val _statusBanner = MutableStateFlow<String?>(null)
    val statusBanner: StateFlow<String?> = _statusBanner.asStateFlow()

    private val _bleStatus = MutableStateFlow("Idle — tap Start BLE Scan to detect nearby AirTag, Tile or SmartTag trackers.")
    val bleStatus: StateFlow<String> = _bleStatus.asStateFlow()

    private val _sirenActive = MutableStateFlow(false)
    val sirenActive: StateFlow<Boolean> = _sirenActive.asStateFlow()

    private val _locationText = MutableStateFlow("Tap Fetch Location to test GPS/LocationManager.")
    val locationText: StateFlow<String> = _locationText.asStateFlow()

    private val _isDoctorGUnlocked = MutableStateFlow(false)
    val isDoctorGUnlocked: StateFlow<Boolean> = _isDoctorGUnlocked.asStateFlow()

    private var quickScanJob: Job? = null

    val accountCheckups: List<AccountCheckupItem> = passwordHealthEngine.getAccountSecurityCheckups()
    val stalkerwareSafetyGuidance: List<String> = deviceAuditEngine.loadStalkerwareConfig().safetyGuidance

    init {
        viewModelScope.launch(Dispatchers.IO) {
            feedUpdateManager.seedBundledOfflineFeedsIfEmpty()
            _awarenessCards.value = scamSmsClassifier.loadAwarenessCards()
            _deviceAudit.value = deviceAuditEngine.performFullDeviceAudit("Not scanned yet")
            seedFirewallAppListIfEmpty()
            refreshPrivacyAdvisor()

            // Invalidate pre-v2 cached scan history on scoring engine upgrade and re-scan
            val currentSettings = preferences.settingsFlow.first()
            if (currentSettings.lastScoringVersion < ScanVerdictEngine.CURRENT_SCORING_VERSION) {
                database.scanHistoryDao().deleteOlderScoringVersions(ScanVerdictEngine.CURRENT_SCORING_VERSION)
                preferences.setLastScoringVersion(ScanVerdictEngine.CURRENT_SCORING_VERSION)
                preferences.setLastSecurityScore(95)
                if (currentSettings.onboardingCompleted) {
                    withContext(Dispatchers.Main) { startQuickScan() }
                }
            }
        }
    }

    fun clearStatusBanner() {
        _statusBanner.value = null
    }

    fun refreshPermissionsOnResume() {
        _permissions.value = permissionManager.getAllStatuses()
        _capabilities.value = DeviceCapabilityChecker.inspect(context)
    }

    fun buildSpecialPermissionIntent(id: DoctorGPermissionId): Intent =
        permissionManager.buildSpecialSettingsIntent(id)

    fun buildAppDetailsIntent(): Intent = permissionManager.buildAppDetailsSettingsIntent()

    fun completeOnboarding(accepted: Boolean) {
        viewModelScope.launch {
            preferences.completeOnboarding(accepted)
        }
    }

    // --- SCANNING ---
    fun startQuickScan() {
        if (scanState.value.lifecycle == ScanLifecycleState.RUNNING) return
        scanCoordinator.resetFlags()
        quickScanJob?.cancel()
        quickScanJob = viewModelScope.launch {
            val result = scanEngine.runQuickScan(
                onProgress = { scanCoordinator.update(it) },
                isCancelled = { scanCoordinator.cancelled }
            )
            updateWidgetCache(result.securityScore)
            _statusBanner.value = "Quick Scan complete: ${result.trustedCount} Trusted, ${result.safeCount} Safe, ${result.needsReviewCount} Needs Review, ${result.suspiciousCount} Suspicious, ${result.maliciousCount} Malicious."
        }
    }

    fun startFullScan() {
        FullScanForegroundService.start(context)
        _statusBanner.value = "Full Scan started in Foreground Service (pausable & resumable)."
    }

    fun pauseFullScan() = FullScanForegroundService.sendControl(context, FullScanForegroundService.ACTION_PAUSE)
    fun resumeFullScan() = FullScanForegroundService.sendControl(context, FullScanForegroundService.ACTION_RESUME)
    fun cancelScan() {
        scanCoordinator.requestCancel()
        quickScanJob?.cancel()
        if (scanState.value.mode == ScanMode.FULL) {
            FullScanForegroundService.sendControl(context, FullScanForegroundService.ACTION_CANCEL)
        }
    }

    fun excludeAppFromScans(finding: AppScanFinding) {
        val pkg = finding.packageName ?: return
        viewModelScope.launch {
            database.excludedAppDao().add(ExcludedAppEntity(pkg, finding.name))
            val current = scanState.value
            val updatedFindings = current.findings.map { item ->
                if (item.packageName == pkg && item.signals.none { it.kind == SignalKind.HARD }) {
                    val trustSignal = VerdictSignal(
                        SignalKind.TRUST,
                        "USER_EXCLUSION",
                        "Trusted by you in DoctorG Settings (reversible at any time)"
                    )
                    item.copy(
                        threatLevel = ThreatLevel.TRUSTED,
                        riskScore = 0,
                        isExcluded = true,
                        trustLabel = "Trusted: Ignored by user",
                        signals = listOf(trustSignal),
                        reasons = listOf(trustSignal.message)
                    )
                } else {
                    item
                }
            }
            scanCoordinator.update(current.copy(findings = updatedFindings))
            _statusBanner.value = "Added ${finding.name} to Trusted Apps (reversible in Settings)."
        }
    }

    fun removeExcludedApp(pkg: String) {
        viewModelScope.launch {
            database.excludedAppDao().remove(pkg)
            _statusBanner.value = "Removed $pkg from Trusted Apps. Run a scan to re-evaluate."
        }
    }

    fun quarantineFinding(finding: AppScanFinding) {
        val path = finding.filePath ?: return
        viewModelScope.launch {
            val res = quarantineManager.quarantineFile(File(path), finding.reasons.firstOrNull() ?: "Suspicious file")
            _statusBanner.value = res.fold(
                onSuccess = { "Moved ${it.originalName} to Encrypted Quarantine Vault." },
                onFailure = { "Cannot quarantine system/protected APK directly (${it.message}). Use Uninstall instead." }
            )
        }
    }

    fun restoreQuarantineItem(item: QuarantineItemEntity) {
        viewModelScope.launch {
            val res = quarantineManager.restoreItem(item)
            _statusBanner.value = res.fold(
                onSuccess = { "Restored to ${it.absolutePath}" },
                onFailure = { "Restore failed: ${it.message}" }
            )
        }
    }

    fun deleteQuarantineItem(item: QuarantineItemEntity) {
        viewModelScope.launch {
            quarantineManager.deletePermanently(item)
            _statusBanner.value = "Permanently wiped ${item.originalName}."
        }
    }

    fun exportCurrentScanPdf(onShareIntent: (Intent) -> Unit) {
        viewModelScope.launch {
            val pdfFile = scanEngine.exportPdfReport(scanState.value)
            val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", pdfFile)
            val share = Intent(Intent.ACTION_SEND).apply {
                type = "application/pdf"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "DoctorG Security Report")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            _statusBanner.value = "Saved PDF report: ${pdfFile.name}"
            onShareIntent(Intent.createChooser(share, "Share DoctorG PDF Report"))
        }
    }

    fun refreshDeviceAudit() {
        viewModelScope.launch(Dispatchers.IO) {
            val wifi = runCatching { networkToolsEngine.auditCurrentWifi() }.getOrNull()
            _wifiAudit.value = wifi
            _deviceAudit.value = deviceAuditEngine.performFullDeviceAudit(wifi?.let { "${it.ssid} (${it.securityType})" } ?: "Unavailable")
        }
    }

    fun updateSignatureFeeds(forceIgnoreWifi: Boolean = true) {
        viewModelScope.launch {
            val res = feedUpdateManager.refreshFromStaticGitHubFeeds(forceIgnoreWifi)
            _awarenessCards.value = scamSmsClassifier.loadAwarenessCards()
            _statusBanner.value = res.message
        }
    }

    // --- BLE TRACKER DETECTOR ---
    fun startBleTrackerScan() {
        bleTrackerDetector.startScan { status -> _bleStatus.value = status }
    }

    fun stopBleTrackerScan() {
        bleTrackerDetector.stopScan()
        _bleStatus.value = "BLE tracker scan stopped."
    }

    fun clearTrackerSightings() {
        viewModelScope.launch { database.trackerSightingDao().clearAll() }
    }

    // --- WEB, VPN, FIREWALL & NETWORK TOOLS ---
    fun startVpnProtection() {
        DoctorGVpnService.start(context)
        _statusBanner.value = "DoctorG local on-device DNS VPN shield enabled."
    }

    fun stopVpnProtection() {
        DoctorGVpnService.stop(context)
        _statusBanner.value = "Web Protection VPN paused."
    }

    fun addAllowlistDomain(domain: String) {
        val clean = domain.trim().lowercase().removePrefix("https://").removePrefix("http://").substringBefore("/")
        if (clean.isBlank()) return
        viewModelScope.launch {
            database.webProtectionDao().upsertDomain(BlockedDomainEntity(clean, "ALLOWLIST", isAllowedOverride = true))
            _statusBanner.value = "Added $clean to Web Protection allowlist."
        }
    }

    fun removeAllowlistDomain(domain: String) {
        viewModelScope.launch { database.webProtectionDao().deleteDomain(domain) }
    }

    fun checkUrlSafety(rawUrl: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val normalized = rawUrl.trim()
            if (normalized.isBlank()) return@launch
            val lower = normalized.lowercase()
            if (lower.startsWith("javascript:") || lower.startsWith("file:") || lower.startsWith("data:")) {
                _linkCheckVerdict.value = LinkCheckVerdict(normalized, false, "BLOCKED: Unsafe URI scheme (${lower.substringBefore(":")}:).")
                return@launch
            }
            val withScheme = if (lower.startsWith("https://") || lower.startsWith("http://")) normalized else "https://$normalized"
            val uri = runCatching { withScheme.toUri() }.getOrNull()
            val host = uri?.host?.lowercase().orEmpty()
            if (host.isBlank()) {
                _linkCheckVerdict.value = LinkCheckVerdict(normalized, false, "Malformed URL or missing hostname.")
                return@launch
            }
            var current = host
            while (current.contains(".")) {
                val blockHit = database.webProtectionDao().findDomain(current)
                if (blockHit != null) {
                    if (!blockHit.isAllowedOverride) {
                        database.webProtectionDao().logBlockedEvent(
                            BlockedEventEntity(domainOrUrl = normalized, source = "LINK_CHECKER", reason = "Matched ${blockHit.category} blocklist")
                        )
                        _linkCheckVerdict.value = LinkCheckVerdict(normalized, false, "BLOCKED: Matched local ${blockHit.category} list ($current).")
                        return@launch
                    }
                    break
                }
                current = current.substringAfter(".")
            }
            // Optional VirusTotal URL lookup if API key configured
            val vtKey = preferences.getVirusTotalApiKey()
            if (vtKey.isNotBlank() && vtRateLimiter.tryAcquire()) {
                val urlId = Base64.encodeToString(withScheme.toByteArray(), Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
                val mal = runCatching {
                    virusTotalApi.lookupUrl(urlId, vtKey).body()?.data?.attributes?.lastAnalysisStats?.malicious
                }.getOrNull()
                if (mal != null && mal > 0) {
                    _linkCheckVerdict.value = LinkCheckVerdict(normalized, false, "DANGEROUS: Flagged by $mal VirusTotal engines.")
                    return@launch
                }
            }
            val suspiciousTld = listOf(".xyz", ".top", ".click", ".ru", ".tk").any { host.endsWith(it) }
            val verdict = if (suspiciousTld || uri?.scheme == "http") {
                LinkCheckVerdict(normalized, false, "CAUTION: Unencrypted HTTP or high-abuse TLD ($host).")
            } else {
                LinkCheckVerdict(normalized, true, "SAFE: Not found in DoctorG phishing/malware blocklists ($host).")
            }
            _linkCheckVerdict.value = verdict
        }
    }

    suspend fun isUrlBlockedForBrowser(url: String): Boolean = withContext(Dispatchers.IO) {
        val host = runCatching { url.toUri().host?.lowercase().orEmpty() }.getOrDefault("")
        if (host.isBlank()) return@withContext false
        var current = host
        while (current.contains(".")) {
            val match = database.webProtectionDao().findDomain(current)
            if (match != null) {
                if (!match.isAllowedOverride) {
                    database.webProtectionDao().logBlockedEvent(
                        BlockedEventEntity(domainOrUrl = url, source = "SAFE_BROWSER", reason = "Blocked ${match.category}")
                    )
                    return@withContext true
                }
                return@withContext false
            }
            current = current.substringAfter(".")
        }
        false
    }

    fun toggleFirewallRule(rule: FirewallRuleEntity, blockWifi: Boolean, blockMobile: Boolean) {
        viewModelScope.launch {
            database.firewallDao().upsert(rule.copy(blockWifi = blockWifi, blockMobile = blockMobile))
        }
    }

    fun runWifiAudit() {
        viewModelScope.launch {
            _wifiAudit.value = networkToolsEngine.auditCurrentWifi()
        }
    }

    fun runPing(host: String) {
        viewModelScope.launch {
            _networkToolOutput.value = "Running ping on $host..."
            _networkToolOutput.value = networkToolsEngine.pingHost(host)
        }
    }

    fun runTraceroute(host: String) {
        viewModelScope.launch {
            _networkToolOutput.value = "Running traceroute on $host..."
            _networkToolOutput.value = networkToolsEngine.tracerouteHost(host)
        }
    }

    fun runPortScan(host: String) {
        viewModelScope.launch {
            _networkToolOutput.value = "Scanning common TCP ports on $host..."
            val open = networkToolsEngine.scanCommonPorts(host)
            _networkToolOutput.value = if (open.isEmpty()) {
                "No common open ports detected on $host."
            } else {
                "Open ports on $host:\n" + open.joinToString("\n") { "• Port ${it.first} (${it.second})" }
            }
        }
    }

    fun runLanScan() {
        viewModelScope.launch {
            _networkToolOutput.value = "Scanning local Wi-Fi subnet..."
            val devices = networkToolsEngine.scanLanDevices()
            _lanDevices.value = devices
            _networkToolOutput.value = "Discovered ${devices.size} device(s) on your Wi-Fi network."
        }
    }

    fun runSpeedTest() {
        viewModelScope.launch {
            _networkToolOutput.value = "Measuring download throughput..."
            val (mbps, latency) = networkToolsEngine.runSpeedTestMbps()
            _networkToolOutput.value = if (mbps > 0.0) {
                "Speed Test: %.2f Mbps • Response time: %d ms".format(mbps, latency)
            } else {
                "Speed test unreachable (device appears offline)."
            }
        }
    }

    fun refreshDataUsage() {
        viewModelScope.launch {
            _dataUsageStats.value = networkToolsEngine.queryAppDataUsageLast30Days()
        }
    }

    // --- SCAM SHIELD (INDIA) ---
    fun analyzeScamSms(text: String) {
        viewModelScope.launch(Dispatchers.Default) {
            _scamSmsResult.value = scamSmsClassifier.classifySms(text, settings.value.lightweightMode)
        }
    }

    fun reportSpamNumber(number: String, category: String) {
        val cleaned = number.trim()
        if (cleaned.length < 6) return
        viewModelScope.launch {
            database.spamNumberDao().upsert(
                SpamNumberEntity(
                    phoneNumber = cleaned,
                    category = category.ifBlank { "User Reported Scam" },
                    risk = "HIGH",
                    reports = 1,
                    isUserReported = true
                )
            )
            _statusBanner.value = "Added $cleaned to local Scam Call blocklist."
        }
    }

    // --- PRIVACY, VAULT, 2FA & APP LOCK ---
    fun addVaultItem(type: String, title: String, usernameOrMeta: String, secretContent: String, websiteOrPath: String) {
        viewModelScope.launch {
            vaultDatabase.vaultDao().upsertVaultItem(
                VaultItemEntity(
                    type = type,
                    title = title.trim(),
                    usernameOrMeta = usernameOrMeta.trim(),
                    secretContent = secretContent,
                    websiteOrPath = websiteOrPath.trim()
                )
            )
            _statusBanner.value = "Encrypted and saved '$title' in SQLCipher Vault."
        }
    }

    fun deleteVaultItem(id: Long) {
        viewModelScope.launch { vaultDatabase.vaultDao().deleteVaultItem(id) }
    }

    fun generatePassword(): String = cryptoManager.generateStrongPassword()

    fun runPasswordHealthCheck(checkHibpOnline: Boolean) {
        viewModelScope.launch {
            val passwords = vaultDatabase.vaultDao().getAllPasswords()
            _passwordHealth.value = passwordHealthEngine.analyzePasswords(passwords, checkHibpOnline)
        }
    }

    fun addTotpAccount(issuer: String, accountName: String, rawSecretOrUri: String) {
        val (parsedIssuer, parsedAccount, parsedSecret) = parseOtpAuthOrManual(issuer, accountName, rawSecretOrUri)
        if (parsedSecret.isBlank()) {
            _statusBanner.value = "Invalid Base32 TOTP secret."
            return
        }
        viewModelScope.launch {
            vaultDatabase.vaultDao().upsertTotpAccount(
                TotpAccountEntity(
                    issuer = parsedIssuer.ifBlank { "Account" },
                    accountName = parsedAccount.ifBlank { "2FA" },
                    secretBase32 = parsedSecret
                )
            )
            _statusBanner.value = "Added 2FA Authenticator entry for $parsedIssuer."
        }
    }

    fun deleteTotpAccount(id: Long) {
        viewModelScope.launch { vaultDatabase.vaultDao().deleteTotpAccount(id) }
    }

    fun generateTotpCode(secretBase32: String, nowMs: Long): String =
        cryptoManager.generateTotp(secretBase32, nowMs)

    fun totpRemainingSeconds(nowMs: Long): Int = cryptoManager.totpRemainingSeconds(nowMs)

    fun exportEncryptedTotpBackup(password: String): String {
        val accounts = totpAccounts.value
        val arr = JSONArray()
        accounts.forEach { a ->
            arr.put(JSONObject().apply {
                put("issuer", a.issuer)
                put("account", a.accountName)
                put("secret", a.secretBase32)
            })
        }
        val encrypted = cryptoManager.encryptWithPassword(arr.toString().toByteArray(), password)
        return Base64.encodeToString(encrypted, Base64.NO_WRAP)
    }

    fun importEncryptedTotpBackup(encodedBlob: String, password: String) {
        viewModelScope.launch {
            runCatching {
                val plain = cryptoManager.decryptWithPassword(Base64.decode(encodedBlob.trim(), Base64.NO_WRAP), password)
                val arr = JSONArray(String(plain))
                var imported = 0
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    val secret = o.optString("secret").trim()
                    if (secret.isBlank()) continue
                    vaultDatabase.vaultDao().upsertTotpAccount(
                        TotpAccountEntity(
                            issuer = o.optString("issuer").ifBlank { "Account" },
                            accountName = o.optString("account").ifBlank { "2FA" },
                            secretBase32 = secret
                        )
                    )
                    imported++
                }
                _statusBanner.value = "Imported $imported encrypted 2FA account(s)."
            }.onFailure {
                _statusBanner.value = "Import failed: wrong password or corrupted backup."
            }
        }
    }

    fun saveAppLockPin(pin: String) {
        viewModelScope.launch {
            preferences.setAppLockPin(pin)
            _isDoctorGUnlocked.value = true
            _statusBanner.value = "App Lock PIN securely hashed and stored."
        }
    }

    fun verifyPinAndUnlock(pin: String, onResult: (Boolean) -> Unit) {
        viewModelScope.launch {
            val ok = preferences.verifyAppLockPin(pin)
            if (ok) _isDoctorGUnlocked.value = true
            onResult(ok)
        }
    }

    fun markUnlockedByBiometric() {
        _isDoctorGUnlocked.value = true
    }

    fun updateAppLockOptions(
        enabled: Boolean? = null,
        fakeCrash: Boolean? = null,
        selfProtect: Boolean? = null,
        biometric: Boolean? = null
    ) {
        viewModelScope.launch {
            preferences.updateAppLockOptions(enabled, fakeCrash, selfProtect, biometric)
            if (enabled == true) AppLockMonitorService.start(context)
            else if (enabled == false) AppLockMonitorService.stop(context)
        }
    }

    fun toggleLockedApp(packageName: String) {
        viewModelScope.launch { preferences.toggleLockedPackage(packageName) }
    }

    fun refreshPrivacyAdvisor() {
        viewModelScope.launch(Dispatchers.IO) {
            val pm = context.packageManager
            val packages = runCatching { pm.getInstalledPackages(PackageManager.GET_PERMISSIONS) }.getOrDefault(emptyList())
                .filter { (it.applicationInfo?.flags?.and(ApplicationInfo.FLAG_SYSTEM) == 0) }
            val definitions = listOf(
                "Camera" to android.Manifest.permission.CAMERA,
                "Microphone" to android.Manifest.permission.RECORD_AUDIO,
                "Location" to android.Manifest.permission.ACCESS_FINE_LOCATION,
                "SMS" to android.Manifest.permission.READ_SMS,
                "Contacts" to android.Manifest.permission.READ_CONTACTS
            )
            _privacyGroups.value = definitions.map { (label, perm) ->
                val apps = packages.filter { it.requestedPermissions?.contains(perm) == true }
                    .map { it.packageName to (it.applicationInfo?.loadLabel(pm)?.toString() ?: it.packageName) }
                    .sortedBy { it.second }
                PrivacyPermissionGroup(label, perm, apps)
            }
        }
    }

    // --- SETTINGS & SAFETY TOOLS ---
    fun setThemeMode(mode: ThemeMode) = viewModelScope.launch { preferences.setThemeMode(mode) }
    fun setDynamicColor(enabled: Boolean) = viewModelScope.launch { preferences.setDynamicColor(enabled) }
    fun setHighContrast(enabled: Boolean) = viewModelScope.launch { preferences.setHighContrast(enabled) }
    fun setLargeTextMode(enabled: Boolean) = viewModelScope.launch { preferences.setLargeTextMode(enabled) }
    fun setLightweightMode(enabled: Boolean) = viewModelScope.launch { preferences.setLightweightMode(enabled) }
    fun setScanIntensity(intensity: ScanIntensity) = viewModelScope.launch { preferences.setScanIntensity(intensity) }
    fun setWifiOnlyUpdates(enabled: Boolean) = viewModelScope.launch {
        preferences.setWifiOnlyUpdates(enabled)
        workScheduler.syncSchedules(preferences.settingsFlow.first())
    }
    fun setFeedBaseUrl(url: String) = viewModelScope.launch { preferences.setFeedBaseUrl(url) }
    fun setDnsProvider(provider: DnsProvider, customIp: String? = null) = viewModelScope.launch {
        preferences.setDnsProvider(provider, customIp)
    }
    fun setScheduledScans(dailyQuick: Boolean, weeklyFull: Boolean) = viewModelScope.launch {
        preferences.setScheduledScans(dailyQuick, weeklyFull)
        workScheduler.syncSchedules(preferences.settingsFlow.first())
    }
    fun setRealTimeInstallScan(enabled: Boolean) = viewModelScope.launch { preferences.setRealTimeInstallScan(enabled) }
    fun saveVirusTotalKey(key: String) = viewModelScope.launch {
        preferences.saveVirusTotalApiKey(key)
        _statusBanner.value = if (key.isBlank()) "VirusTotal API key cleared." else "VirusTotal key encrypted in Keystore."
    }
    fun saveSafeBrowsingKey(key: String) = viewModelScope.launch {
        preferences.saveSafeBrowsingApiKey(key)
        _statusBanner.value = if (key.isBlank()) "Safe Browsing API key cleared." else "Safe Browsing key encrypted in Keystore."
    }

    fun setVirusTotalThreshold(threshold: Int) = viewModelScope.launch {
        preferences.setVirusTotalThreshold(threshold)
        _statusBanner.value = "VirusTotal malicious threshold updated to $threshold+ engines."
    }

    fun setAppLanguageTag(langTag: String) = viewModelScope.launch {
        val normalized = langTag.trim().lowercase()
        preferences.setAppLanguageTag(normalized)
        withContext(Dispatchers.Main) {
            val locales = if (normalized.isBlank()) {
                LocaleListCompat.getEmptyLocaleList()
            } else {
                LocaleListCompat.forLanguageTags(normalized)
            }
            AppCompatDelegate.setApplicationLocales(locales)
        }
    }

    fun exportInstalledTrustedCertsJson(): String =
        deviceAuditEngine.exportInstalledTrustedCertsJson()

    fun toggleSiren() {
        if (_sirenActive.value) {
            safetyEngine.stopSiren()
            _sirenActive.value = false
        } else {
            safetyEngine.startSiren()
            _sirenActive.value = true
        }
    }

    fun speakSafetyAlert() {
        safetyEngine.speakAlert("DoctorG security alert. Check your device status and stay safe.")
    }

    fun fetchLocation() {
        safetyEngine.fetchCurrentLocation { _locationText.value = it }
    }

    private suspend fun seedFirewallAppListIfEmpty() {
        val existing = database.firewallDao().observeRules().first()
        if (existing.isNotEmpty()) return
        val pm = context.packageManager
        val userApps = runCatching {
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
                .filter { (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 && it.packageName != context.packageName }
                .take(25)
        }.getOrDefault(emptyList())
        userApps.forEach { app ->
            database.firewallDao().upsert(
                FirewallRuleEntity(
                    packageName = app.packageName,
                    appName = app.loadLabel(pm).toString(),
                    blockWifi = false,
                    blockMobile = false
                )
            )
        }
    }

    private fun parseOtpAuthOrManual(issuer: String, account: String, raw: String): Triple<String, String, String> {
        val trimmed = raw.trim()
        if (trimmed.startsWith("otpauth://", ignoreCase = true)) {
            val uri = trimmed.toUri()
            val secret = uri.getQueryParameter("secret").orEmpty()
            val uriIssuer = uri.getQueryParameter("issuer") ?: uri.path?.trim('/')?.substringBefore(":") ?: issuer
            val uriAccount = uri.path?.trim('/')?.substringAfter(":", account) ?: account
            return Triple(uriIssuer, uriAccount, secret)
        }
        return Triple(issuer, account, trimmed)
    }

    private fun updateWidgetCache(score: Int) {
        context.getSharedPreferences("doctorg_widget_cache", Context.MODE_PRIVATE)
            .edit { putInt("last_score", score) }
        viewModelScope.launch {
            runCatching { DoctorGWidget().updateAll(context) }
        }
    }
}
