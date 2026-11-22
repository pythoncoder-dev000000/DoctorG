package com.python.doctorg

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.VpnLock
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Radar
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.VpnLock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.adaptive.navigationsuite.NavigationSuiteScaffold
import androidx.compose.material3.windowsizeclass.ExperimentalMaterial3WindowSizeClassApi
import androidx.compose.material3.windowsizeclass.WindowWidthSizeClass
import androidx.compose.material3.windowsizeclass.calculateWindowSizeClass
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.fragment.app.FragmentActivity
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.python.doctorg.core.adaptive.FoldPosture
import com.python.doctorg.core.adaptive.rememberFoldPosture
import com.python.doctorg.core.permissions.DoctorGPermissionId
import com.python.doctorg.core.permissions.PermissionItemStatus
import com.python.doctorg.core.permissions.PermissionKind
import com.python.doctorg.ui.screens.home.HomeScreen
import com.python.doctorg.ui.screens.onboarding.OnboardingScreen
import com.python.doctorg.ui.screens.privacy.PrivacyScreen
import com.python.doctorg.ui.screens.scan.ScanScreen
import com.python.doctorg.ui.screens.settings.ToolsSettingsScreen
import com.python.doctorg.ui.screens.web.WebNetworkScreen
import com.python.doctorg.ui.theme.DoctorGTheme
import com.python.doctorg.ui.viewmodel.DoctorGViewModel
import dagger.hilt.android.AndroidEntryPoint

enum class DoctorGDestination(
    val labelRes: Int,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector
) {
    HOME(R.string.nav_home, Icons.Filled.Home, Icons.Outlined.Home),
    SCAN(R.string.nav_scan, Icons.Filled.Radar, Icons.Outlined.Radar),
    WEB(R.string.nav_web, Icons.Filled.VpnLock, Icons.Outlined.VpnLock),
    PRIVACY(R.string.nav_privacy, Icons.Filled.Lock, Icons.Outlined.Lock),
    SETTINGS(R.string.nav_settings, Icons.Filled.Settings, Icons.Outlined.Settings)
}

@AndroidEntryPoint
class MainActivity : AppCompatActivity() {

    @OptIn(ExperimentalMaterial3WindowSizeClassApi::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        installSplashScreen()
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            val viewModel: DoctorGViewModel = hiltViewModel()
            val settings by viewModel.settings.collectAsStateWithLifecycle()
            val windowSizeClass = calculateWindowSizeClass(this)
            val foldPosture by rememberFoldPosture(this)

            DoctorGTheme(
                themeMode = settings.themeMode,
                dynamicColor = settings.dynamicColor,
                highContrast = settings.highContrast,
                largeTextMode = settings.largeTextMode,
                languageTag = settings.appLanguageTag
            ) {
                DoctorGAppShell(
                    activity = this,
                    viewModel = viewModel,
                    widthSizeClass = windowSizeClass.widthSizeClass,
                    foldPosture = foldPosture,
                    onFlagSecureChange = { secure ->
                        if (secure) {
                            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
                        } else {
                            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                        }
                    },
                    onPromptBiometric = { onSuccess -> launchBiometricPrompt(onSuccess) }
                )
            }
        }
    }

    private fun launchBiometricPrompt(onSuccess: () -> Unit) {
        val executor = ContextCompat.getMainExecutor(this)
        val prompt = BiometricPrompt(
            this,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onSuccess()
                }
            }
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock DoctorG")
            .setSubtitle("Verify your identity to access DoctorG Vault & App Lock")
            .setNegativeButtonText("Use PIN")
            .build()
        runCatching { prompt.authenticate(info) }
    }
}

@Composable
private fun DoctorGAppShell(
    activity: FragmentActivity,
    viewModel: DoctorGViewModel,
    widthSizeClass: WindowWidthSizeClass,
    foldPosture: FoldPosture,
    onFlagSecureChange: (Boolean) -> Unit,
    onPromptBiometric: (onSuccess: () -> Unit) -> Unit
) {
    val settings by viewModel.settings.collectAsStateWithLifecycle()
    val permissions by viewModel.permissions.collectAsStateWithLifecycle()
    val capabilities by viewModel.capabilities.collectAsStateWithLifecycle()
    val scanState by viewModel.scanState.collectAsStateWithLifecycle()
    val scanHistory by viewModel.scanHistory.collectAsStateWithLifecycle()
    val signatureCount by viewModel.signatureCount.collectAsStateWithLifecycle()
    val excludedApps by viewModel.excludedApps.collectAsStateWithLifecycle()
    val quarantineItems by viewModel.quarantineItems.collectAsStateWithLifecycle()
    val trackerSightings by viewModel.trackerSightings.collectAsStateWithLifecycle()
    val appBaselines by viewModel.appBaselines.collectAsStateWithLifecycle()
    val deviceAudit by viewModel.deviceAudit.collectAsStateWithLifecycle()
    val isVpnRunning by viewModel.isVpnRunning.collectAsStateWithLifecycle()
    val isAppLockRunning by viewModel.isAppLockServiceRunning.collectAsStateWithLifecycle()
    val blocklistCount by viewModel.blocklistCount.collectAsStateWithLifecycle()
    val blockedEventCount by viewModel.blockedEventCount.collectAsStateWithLifecycle()
    val blockedEvents by viewModel.blockedEvents.collectAsStateWithLifecycle()
    val allowlistDomains by viewModel.allowlistDomains.collectAsStateWithLifecycle()
    val firewallRules by viewModel.firewallRules.collectAsStateWithLifecycle()
    val linkVerdict by viewModel.linkCheckVerdict.collectAsStateWithLifecycle()
    val wifiAudit by viewModel.wifiAudit.collectAsStateWithLifecycle()
    val lanDevices by viewModel.lanDevices.collectAsStateWithLifecycle()
    val networkOutput by viewModel.networkToolOutput.collectAsStateWithLifecycle()
    val dataUsageStats by viewModel.dataUsageStats.collectAsStateWithLifecycle()
    val scamSmsResult by viewModel.scamSmsResult.collectAsStateWithLifecycle()
    val awarenessCards by viewModel.awarenessCards.collectAsStateWithLifecycle()
    val spamNumbers by viewModel.spamNumbers.collectAsStateWithLifecycle()
    val vaultItems by viewModel.vaultItems.collectAsStateWithLifecycle()
    val totpAccounts by viewModel.totpAccounts.collectAsStateWithLifecycle()
    val passwordHealth by viewModel.passwordHealth.collectAsStateWithLifecycle()
    val privacyGroups by viewModel.privacyGroups.collectAsStateWithLifecycle()
    val statusBanner by viewModel.statusBanner.collectAsStateWithLifecycle()
    val bleStatus by viewModel.bleStatus.collectAsStateWithLifecycle()
    val sirenActive by viewModel.sirenActive.collectAsStateWithLifecycle()
    val locationText by viewModel.locationText.collectAsStateWithLifecycle()
    val isDoctorGUnlocked by viewModel.isDoctorGUnlocked.collectAsStateWithLifecycle()

    var currentDestination by rememberSaveable { mutableStateOf(DoctorGDestination.HOME) }
    var rationalePermission by remember { mutableStateOf<PermissionItemStatus?>(null) }
    val snackbarHostState = remember { SnackbarHostState() }

    val isWideScreen = widthSizeClass != WindowWidthSizeClass.Compact
    val isTwoPane = widthSizeClass == WindowWidthSizeClass.Expanded || foldPosture is FoldPosture.Book

    // Re-check all permissions whenever user returns from Android Settings
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        viewModel.refreshPermissionsOnResume()
    }

    // Apply FLAG_SECURE screenshot blocking automatically on Privacy / Vault screen
    LaunchedEffect(currentDestination) {
        onFlagSecureChange(currentDestination == DoctorGDestination.PRIVACY)
    }

    LaunchedEffect(statusBanner) {
        statusBanner?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.clearStatusBanner()
        }
    }

    val runtimePermLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {
        viewModel.refreshPermissionsOnResume()
    }

    val vpnConsentLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res ->
        if (res.resultCode == android.app.Activity.RESULT_OK) {
            viewModel.startVpnProtection()
        }
        viewModel.refreshPermissionsOnResume()
    }

    val settingsReturnLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        viewModel.refreshPermissionsOnResume()
    }

    fun executePermissionRequest(perm: PermissionItemStatus) {
        if (perm.kind == PermissionKind.RUNTIME && perm.runtimePermission != null) {
            runtimePermLauncher.launch(perm.runtimePermission)
        } else if (perm.id == DoctorGPermissionId.VPN_CONSENT) {
            val prep = VpnService.prepare(activity)
            if (prep != null) vpnConsentLauncher.launch(prep)
            else viewModel.startVpnProtection()
        } else {
            runCatching {
                settingsReturnLauncher.launch(viewModel.buildSpecialPermissionIntent(perm.id))
            }.onFailure {
                runCatching { settingsReturnLauncher.launch(viewModel.buildAppDetailsIntent()) }
            }
        }
    }

    // Just-in-time explanation dialog shown BEFORE any Android permission popup
    rationalePermission?.let { perm ->
        AlertDialog(
            onDismissRequest = { rationalePermission = null },
            title = { Text("Allow ${perm.title}?") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(perm.whyNeeded, style = MaterialTheme.typography.bodyMedium)
                    Text("What stays private: ${perm.privacyGuarantee}", style = MaterialTheme.typography.bodySmall)
                    Text("Without it: ${perm.dependentFeatures} will stay disabled; all other DoctorG features keep working.", style = MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton = {
                Button(onClick = {
                    val target = perm
                    rationalePermission = null
                    executePermissionRequest(target)
                }) { Text("Continue") }
            },
            dismissButton = {
                TextButton(onClick = { rationalePermission = null }) { Text("Not Now") }
            }
        )
    }

    // First-run Onboarding (shows Privacy Policy before any permission)
    if (!settings.onboardingCompleted) {
        OnboardingScreen(
            permissions = permissions,
            onRequestPermission = { rationalePermission = it },
            onFinishOnboarding = { viewModel.completeOnboarding(accepted = true) }
        )
        return
    }

    // Optional DoctorG Self-Lock Gate
    if (settings.appLockSelfProtect && settings.hasAppLockPin && !isDoctorGUnlocked) {
        var pinAttempt by rememberSaveable { mutableStateOf("") }
        var pinError by rememberSaveable { mutableStateOf(false) }

        Surface(modifier = Modifier.fillMaxSize().safeDrawingPadding()) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(
                    modifier = Modifier.widthIn(max = 360.dp).padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Image(
                        painter = painterResource(R.drawable.doctorg_logo),
                        contentDescription = "DoctorG Logo",
                        modifier = Modifier.size(84.dp)
                    )
                    Text("DoctorG Locked", style = MaterialTheme.typography.headlineSmall)
                    OutlinedTextField(
                        value = pinAttempt,
                        onValueChange = { pinAttempt = it; pinError = false },
                        label = { Text("Enter DoctorG PIN") },
                        visualTransformation = PasswordVisualTransformation(),
                        isError = pinError,
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Button(
                        onClick = {
                            viewModel.verifyPinAndUnlock(pinAttempt) { ok ->
                                if (!ok) pinError = true
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) { Text("Unlock") }
                    if (settings.appLockBiometric && capabilities.hasBiometric) {
                        OutlinedButton(
                            onClick = { onPromptBiometric { viewModel.markUnlockedByBiometric() } },
                            modifier = Modifier.fillMaxWidth()
                        ) { Text("Unlock with Biometrics") }
                    }
                }
            }
        }
        return
    }

    // Main Adaptive NavigationSuiteScaffold (Bottom Bar on Compact, Rail on Medium, Drawer/Rail on Expanded)
    NavigationSuiteScaffold(
        navigationSuiteItems = {
            DoctorGDestination.entries.forEach { dest ->
                val selected = currentDestination == dest
                item(
                    selected = selected,
                    onClick = { currentDestination = dest },
                    icon = {
                        Icon(
                            imageVector = if (selected) dest.selectedIcon else dest.unselectedIcon,
                            contentDescription = stringResource(dest.labelRes)
                        )
                    },
                    label = { Text(stringResource(dest.labelRes)) }
                )
            }
        }
    ) {
        Scaffold(
            snackbarHost = { SnackbarHost(snackbarHostState) }
        ) { innerPadding ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
            ) {
                when (currentDestination) {
                    DoctorGDestination.HOME -> HomeScreen(
                        settings = settings,
                        scanState = scanState,
                        scanHistory = scanHistory,
                        signatureCount = signatureCount,
                        blockedCount = blockedEventCount,
                        isVpnRunning = isVpnRunning,
                        isAppLockRunning = isAppLockRunning,
                        permissions = permissions,
                        isWideScreen = isWideScreen,
                        onQuickScan = {
                            currentDestination = DoctorGDestination.SCAN
                            viewModel.startQuickScan()
                        },
                        onFullScan = {
                            currentDestination = DoctorGDestination.SCAN
                            viewModel.startFullScan()
                        },
                        onNavigateToScan = { currentDestination = DoctorGDestination.SCAN },
                        onNavigateToWeb = { currentDestination = DoctorGDestination.WEB },
                        onNavigateToPrivacy = { currentDestination = DoctorGDestination.PRIVACY },
                        onNavigateToSettings = { currentDestination = DoctorGDestination.SETTINGS },
                        onUpdateSignatures = { viewModel.updateSignatureFeeds(true) }
                    )

                    DoctorGDestination.SCAN -> ScanScreen(
                        settings = settings,
                        scanState = scanState,
                        deviceAudit = deviceAudit,
                        signatureCount = signatureCount,
                        excludedApps = excludedApps,
                        quarantineItems = quarantineItems,
                        trackerSightings = trackerSightings,
                        appBaselines = appBaselines,
                        bleStatus = bleStatus,
                        stalkerwareGuidance = viewModel.stalkerwareSafetyGuidance,
                        capabilities = capabilities,
                        isTwoPane = isTwoPane,
                        onQuickScan = { viewModel.startQuickScan() },
                        onFullScan = { viewModel.startFullScan() },
                        onPauseScan = { viewModel.pauseFullScan() },
                        onResumeScan = { viewModel.resumeFullScan() },
                        onCancelScan = { viewModel.cancelScan() },
                        onExcludeApp = { viewModel.excludeAppFromScans(it) },
                        onRemoveExclusion = { viewModel.removeExcludedApp(it) },
                        onQuarantineFinding = { viewModel.quarantineFinding(it) },
                        onRestoreQuarantine = { viewModel.restoreQuarantineItem(it) },
                        onDeleteQuarantine = { viewModel.deleteQuarantineItem(it) },
                        onExportPdf = {
                            viewModel.exportCurrentScanPdf { shareIntent ->
                                runCatching { activity.startActivity(shareIntent) }
                            }
                        },
                        onRefreshDeviceAudit = { viewModel.refreshDeviceAudit() },
                        onUpdateSignatures = { viewModel.updateSignatureFeeds(true) },
                        onStartBleScan = {
                            val blePerm = permissions.firstOrNull { it.id == DoctorGPermissionId.BLUETOOTH_SCAN }
                            if (blePerm != null && !blePerm.isGranted) rationalePermission = blePerm
                            else viewModel.startBleTrackerScan()
                        },
                        onStopBleScan = { viewModel.stopBleTrackerScan() },
                        onClearTrackers = { viewModel.clearTrackerSightings() },
                        onOpenPermissions = { currentDestination = DoctorGDestination.SETTINGS }
                    )

                    DoctorGDestination.WEB -> WebNetworkScreen(
                        settings = settings,
                        capabilities = capabilities,
                        isVpnRunning = isVpnRunning,
                        blocklistCount = blocklistCount,
                        blockedEvents = blockedEvents,
                        allowlistDomains = allowlistDomains,
                        firewallRules = firewallRules,
                        linkVerdict = linkVerdict,
                        wifiAudit = wifiAudit,
                        lanDevices = lanDevices,
                        networkToolOutput = networkOutput,
                        dataUsageStats = dataUsageStats,
                        scamSmsResult = scamSmsResult,
                        awarenessCards = awarenessCards,
                        spamNumbers = spamNumbers,
                        hasCameraPermission = permissions.firstOrNull { it.id == DoctorGPermissionId.CAMERA }?.isGranted == true,
                        isUrlBlocked = { viewModel.isUrlBlockedForBrowser(it) },
                        onToggleVpn = { enable ->
                            if (enable) {
                                val prep = VpnService.prepare(activity)
                                if (prep != null) {
                                    rationalePermission = permissions.firstOrNull { it.id == DoctorGPermissionId.VPN_CONSENT }
                                } else {
                                    viewModel.startVpnProtection()
                                }
                            } else {
                                viewModel.stopVpnProtection()
                            }
                        },
                        onSelectDns = { p, custom -> viewModel.setDnsProvider(p, custom) },
                        onAddAllowlist = { viewModel.addAllowlistDomain(it) },
                        onRemoveAllowlist = { viewModel.removeAllowlistDomain(it) },
                        onToggleFirewall = { r, w, m -> viewModel.toggleFirewallRule(r, w, m) },
                        onCheckUrl = { viewModel.checkUrlSafety(it) },
                        onRequestCameraPermission = {
                            rationalePermission = permissions.firstOrNull { it.id == DoctorGPermissionId.CAMERA }
                        },
                        onRunWifiAudit = { viewModel.runWifiAudit() },
                        onPing = { viewModel.runPing(it) },
                        onTraceroute = { viewModel.runTraceroute(it) },
                        onPortScan = { viewModel.runPortScan(it) },
                        onLanScan = { viewModel.runLanScan() },
                        onSpeedTest = { viewModel.runSpeedTest() },
                        onRefreshDataUsage = { viewModel.refreshDataUsage() },
                        onAnalyzeScamSms = { viewModel.analyzeScamSms(it) },
                        onReportSpamNumber = { num, cat -> viewModel.reportSpamNumber(num, cat) },
                        onChangeAppLanguage = { viewModel.setAppLanguageTag(it) }
                    )

                    DoctorGDestination.PRIVACY -> PrivacyScreen(
                        settings = settings,
                        capabilities = capabilities,
                        vaultItems = vaultItems,
                        totpAccounts = totpAccounts,
                        passwordHealth = passwordHealth,
                        privacyGroups = privacyGroups,
                        accountCheckups = viewModel.accountCheckups,
                        installedApps = firewallRules,
                        isAppLockRunning = isAppLockRunning,
                        isTwoPane = isTwoPane,
                        onAddVaultItem = { t, title, u, s, w -> viewModel.addVaultItem(t, title, u, s, w) },
                        onDeleteVaultItem = { viewModel.deleteVaultItem(it) },
                        onGeneratePassword = { viewModel.generatePassword() },
                        onRunPasswordHealth = { viewModel.runPasswordHealthCheck(it) },
                        onAddTotpAccount = { i, a, s -> viewModel.addTotpAccount(i, a, s) },
                        onDeleteTotpAccount = { viewModel.deleteTotpAccount(it) },
                        onGenerateTotp = { s, now -> viewModel.generateTotpCode(s, now) },
                        onTotpRemainingSeconds = { now -> viewModel.totpRemainingSeconds(now) },
                        onExportTotpBackup = { pwd -> viewModel.exportEncryptedTotpBackup(pwd) },
                        onImportTotpBackup = { blob, pwd -> viewModel.importEncryptedTotpBackup(blob, pwd) },
                        onSaveAppLockPin = { viewModel.saveAppLockPin(it) },
                        onUpdateAppLockOptions = { en, fc, sp, bio -> viewModel.updateAppLockOptions(en, fc, sp, bio) },
                        onToggleLockedApp = { viewModel.toggleLockedApp(it) },
                        onPromptBiometric = { onPromptBiometric { viewModel.markUnlockedByBiometric() } },
                        onRefreshPrivacyAdvisor = { viewModel.refreshPrivacyAdvisor() }
                    )

                    DoctorGDestination.SETTINGS -> ToolsSettingsScreen(
                        settings = settings,
                        permissions = permissions,
                        capabilities = capabilities,
                        foldPosture = foldPosture,
                        sirenActive = sirenActive,
                        locationText = locationText,
                        onRequestPermission = { rationalePermission = it },
                        onOpenAppSettings = {
                            runCatching { settingsReturnLauncher.launch(viewModel.buildAppDetailsIntent()) }
                        },
                        onSetThemeMode = { viewModel.setThemeMode(it) },
                        onSetDynamicColor = { viewModel.setDynamicColor(it) },
                        onSetHighContrast = { viewModel.setHighContrast(it) },
                        onSetLargeText = { viewModel.setLargeTextMode(it) },
                        onSetLightweight = { viewModel.setLightweightMode(it) },
                        onSetScanIntensity = { viewModel.setScanIntensity(it) },
                        onSetScheduledScans = { d, w -> viewModel.setScheduledScans(d, w) },
                        onSetRealTimeInstall = { viewModel.setRealTimeInstallScan(it) },
                        onSetWifiOnlyUpdates = { viewModel.setWifiOnlyUpdates(it) },
                        onSaveFeedBaseUrl = { viewModel.setFeedBaseUrl(it) },
                        onSaveVirusTotalKey = { viewModel.saveVirusTotalKey(it) },
                        onSaveSafeBrowsingKey = { viewModel.saveSafeBrowsingKey(it) },
                        onToggleSiren = { viewModel.toggleSiren() },
                        onSpeakAlert = { viewModel.speakSafetyAlert() },
                        onFetchLocation = {
                            val locPerm = permissions.firstOrNull { it.id == DoctorGPermissionId.LOCATION }
                            if (locPerm != null && !locPerm.isGranted) rationalePermission = locPerm
                            else viewModel.fetchLocation()
                        },
                        excludedApps = excludedApps,
                        onRemoveExclusion = { viewModel.removeExcludedApp(it) },
                        onSetVirusTotalThreshold = { viewModel.setVirusTotalThreshold(it) },
                        onSetAppLanguage = { viewModel.setAppLanguageTag(it) },
                        onExportTrustedCerts = { viewModel.exportInstalledTrustedCertsJson() }
                    )
                }
            }
        }
    }
}
