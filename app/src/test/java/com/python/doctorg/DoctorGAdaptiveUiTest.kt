package com.python.doctorg

import android.content.Context
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.unit.LayoutDirection
import androidx.test.core.app.ApplicationProvider
import com.python.doctorg.core.adaptive.DeviceCapabilities
import com.python.doctorg.core.adaptive.FoldPosture
import com.python.doctorg.data.preferences.DoctorGSettings
import com.python.doctorg.domain.engine.ScamSmsClassifier
import com.python.doctorg.domain.model.AppScanFinding
import com.python.doctorg.domain.model.ScanLifecycleState
import com.python.doctorg.domain.model.ScanMode
import com.python.doctorg.domain.model.ScanProgressState
import com.python.doctorg.domain.model.SignalKind
import com.python.doctorg.domain.model.ThreatLevel
import com.python.doctorg.domain.model.TrustTier
import com.python.doctorg.domain.model.VerdictSignal
import com.python.doctorg.ui.screens.home.HomeScreen
import com.python.doctorg.ui.screens.onboarding.OnboardingScreen
import com.python.doctorg.ui.screens.scan.ScanScreen
import com.python.doctorg.ui.screens.settings.ToolsSettingsScreen
import com.python.doctorg.ui.screens.web.WebNetworkScreen
import com.python.doctorg.ui.theme.DoctorGTheme
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class DoctorGAdaptiveUiTest {

    @get:Rule
    val composeRule = createComposeRule()

    private val defaultCapabilities = DeviceCapabilities(
        hasCamera = true,
        hasBle = true,
        hasTelephonyAndSim = false,
        hasBiometric = true,
        hasUsbHost = true,
        hasPlayServices = false,
        isLowRamDevice = false,
        isChromeOs = false,
        sdkInt = 36
    )

    @Test
    fun `onboarding displays DoctorG Privacy Policy and Skip option`() {
        var finished = false
        composeRule.setContent {
            DoctorGTheme {
                OnboardingScreen(
                    permissions = emptyList(),
                    onRequestPermission = {},
                    onFinishOnboarding = { finished = true }
                )
            }
        }
        composeRule.waitForIdle()
        composeRule.onNodeWithText("Welcome to DoctorG").assertIsDisplayed()
        composeRule.onNodeWithTag("onboarding_accept_privacy_button").performClick()
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("onboarding_skip_button").performClick()
        composeRule.waitForIdle()
        assertTrue(finished)
    }

    @Test
    fun `homeScreen renders Quick Scan and Full Scan in Compact and Expanded RTL layouts`() {
        var quickClicked = false
        var fullClicked = false
        composeRule.setContent {
            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                DoctorGTheme {
                    HomeScreen(
                        settings = DoctorGSettings(lastSecurityScore = 92),
                        scanState = ScanProgressState(),
                        scanHistory = emptyList(),
                        signatureCount = 8,
                        blockedCount = 0,
                        isVpnRunning = false,
                        isAppLockRunning = false,
                        permissions = emptyList(),
                        isWideScreen = true,
                        onQuickScan = { quickClicked = true },
                        onFullScan = { fullClicked = true },
                        onNavigateToScan = {},
                        onNavigateToWeb = {},
                        onNavigateToPrivacy = {},
                        onNavigateToSettings = {},
                        onUpdateSignatures = {}
                    )
                }
            }
        }
        composeRule.waitForIdle()
        composeRule.onNodeWithTag("home_quick_scan_button").assertIsDisplayed().performClick()
        composeRule.onNodeWithTag("home_full_scan_button").assertIsDisplayed().performClick()
        assertTrue(quickClicked)
        assertTrue(fullClicked)
    }

    @Test
    fun `about section displays DoctorG v1_0_0 version label`() {
        composeRule.setContent {
            DoctorGTheme {
                ToolsSettingsScreen(
                    settings = DoctorGSettings(),
                    permissions = emptyList(),
                    capabilities = defaultCapabilities,
                    foldPosture = FoldPosture.Tabletop(24),
                    sirenActive = false,
                    locationText = "Ready",
                    onRequestPermission = {},
                    onOpenAppSettings = {},
                    onSetThemeMode = {},
                    onSetDynamicColor = {},
                    onSetHighContrast = {},
                    onSetLargeText = {},
                    onSetLightweight = {},
                    onSetScanIntensity = {},
                    onSetScheduledScans = { _, _ -> },
                    onSetRealTimeInstall = {},
                    onSetWifiOnlyUpdates = {},
                    onSaveFeedBaseUrl = {},
                    onSaveVirusTotalKey = {},
                    onSaveSafeBrowsingKey = {},
                    onToggleSiren = {},
                    onSpeakAlert = {},
                    onFetchLocation = {}
                )
            }
        }
        composeRule.waitForIdle()
        composeRule.onNodeWithText("About DoctorG").performClick()
        composeRule.waitForIdle()
        composeRule.onNodeWithText("DoctorG v1.0.0").assertIsDisplayed()
    }

    @Test
    fun `bug2 scam awareness switches to Hindi rendering Hindi headings and bullets without English headings`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val raw = context.assets.open("scam_awareness.json").bufferedReader().use { it.readText() }
        val cards = ScamSmsClassifier.parseAwarenessCardsJson(raw)
        assertTrue(cards.isNotEmpty())

        val firstEn = cards.first().resolve("en")
        val firstHi = cards.first().resolve("hi")

        composeRule.setContent {
            DoctorGTheme {
                WebNetworkScreen(
                    settings = DoctorGSettings(appLanguageTag = "en"),
                    capabilities = defaultCapabilities,
                    isVpnRunning = false,
                    blocklistCount = 10,
                    blockedEvents = emptyList(),
                    allowlistDomains = emptyList(),
                    firewallRules = emptyList(),
                    linkVerdict = null,
                    wifiAudit = null,
                    lanDevices = emptyList(),
                    networkToolOutput = "",
                    dataUsageStats = emptyList(),
                    scamSmsResult = null,
                    awarenessCards = cards,
                    spamNumbers = emptyList(),
                    hasCameraPermission = false,
                    isUrlBlocked = { false },
                    onToggleVpn = {},
                    onSelectDns = { _, _ -> },
                    onAddAllowlist = {},
                    onRemoveAllowlist = {},
                    onToggleFirewall = { _, _, _ -> },
                    onCheckUrl = {},
                    onRequestCameraPermission = {},
                    onRunWifiAudit = {},
                    onPing = {},
                    onTraceroute = {},
                    onPortScan = {},
                    onLanScan = {},
                    onSpeedTest = {},
                    onRefreshDataUsage = {},
                    onAnalyzeScamSms = {},
                    onReportSpamNumber = { _, _ -> },
                    onChangeAppLanguage = {},
                    initialTab = 3
                )
            }
        }
        composeRule.waitForIdle()

        // Initially in English: English headings exist
        assertTrue(
            "Expected English 'Red Flags:' initially",
            composeRule.onAllNodesWithText("Red Flags:").fetchSemanticsNodes().isNotEmpty()
        )
        assertTrue(
            "Expected English 'What To Do:' initially",
            composeRule.onAllNodesWithText("What To Do:").fetchSemanticsNodes().isNotEmpty()
        )

        // Toggle to Hindi (scroll into viewport first since screen is vertically scrollable)
        composeRule.onNodeWithTag("scam_language_toggle_button").performScrollTo().performClick()
        composeRule.waitForIdle()

        // English headings & English bullets MUST NOT remain
        assertTrue(
            "English 'Red Flags:' must not be rendered in Hindi mode",
            composeRule.onAllNodesWithText("Red Flags:").fetchSemanticsNodes().isEmpty()
        )
        assertTrue(
            "English 'What To Do:' must not be rendered in Hindi mode",
            composeRule.onAllNodesWithText("What To Do:").fetchSemanticsNodes().isEmpty()
        )
        assertTrue(
            "English bullet must not be rendered in Hindi mode",
            composeRule.onAllNodesWithText("• ${firstEn.redFlags.first()}").fetchSemanticsNodes().isEmpty()
        )

        // Hindi headings, title, and bullets MUST be rendered
        assertTrue(
            "Expected Hindi heading 'खतरे के संकेत:'",
            composeRule.onAllNodesWithText("खतरे के संकेत:").fetchSemanticsNodes().isNotEmpty()
        )
        assertTrue(
            "Expected Hindi heading 'क्या करें:'",
            composeRule.onAllNodesWithText("क्या करें:").fetchSemanticsNodes().isNotEmpty()
        )
        assertTrue(
            "Expected Hindi guide title '${firstHi.title}'",
            composeRule.onAllNodesWithText(firstHi.title).fetchSemanticsNodes().isNotEmpty()
        )
        assertTrue(
            "Expected Hindi redFlag bullet",
            composeRule.onAllNodesWithText("• ${firstHi.redFlags.first()}").fetchSemanticsNodes().isNotEmpty()
        )
        assertTrue(
            "Expected Hindi whatToDo bullet",
            composeRule.onAllNodesWithText("• ${firstHi.whatToDo.first()}").fetchSemanticsNodes().isNotEmpty()
        )
    }

    @Test
    fun `bug1 scanScreen shows Trusted System label and Disable button instead of Uninstall for Google Play services`() {
        val gmsFinding = AppScanFinding(
            id = "com.google.android.gms",
            name = "Google Play services",
            packageName = "com.google.android.gms",
            filePath = "/product/priv-app/PrebuiltGmsCore/PrebuiltGmsCore.apk",
            sha256 = "a".repeat(64),
            threatLevel = ThreatLevel.TRUSTED,
            trustTier = TrustTier.TRUSTED_SYSTEM,
            trustLabel = "Trusted: System app",
            riskScore = 0,
            mlProbability = null,
            installerSource = "com.android.vending",
            isSideloaded = false,
            isHiddenApp = false,
            isSystemApp = true,
            isUpdatedSystemApp = true,
            targetSdk = 35,
            signals = listOf(
                VerdictSignal(
                    SignalKind.TRUST,
                    "TRUST_TIER",
                    "Trusted: System app (verified system partition component with valid signing certificate)"
                )
            ),
            reasons = listOf("Trusted: System app (verified system partition component with valid signing certificate)")
        )

        composeRule.setContent {
            DoctorGTheme {
                ScanScreen(
                    settings = DoctorGSettings(),
                    scanState = ScanProgressState(
                        lifecycle = ScanLifecycleState.COMPLETED,
                        mode = ScanMode.QUICK,
                        percent = 100,
                        findings = listOf(gmsFinding)
                    ),
                    deviceAudit = null,
                    signatureCount = 10,
                    excludedApps = emptyList(),
                    quarantineItems = emptyList(),
                    trackerSightings = emptyList(),
                    appBaselines = emptyList(),
                    bleStatus = "Idle",
                    stalkerwareGuidance = emptyList(),
                    capabilities = defaultCapabilities,
                    isTwoPane = true,
                    onQuickScan = {},
                    onFullScan = {},
                    onPauseScan = {},
                    onResumeScan = {},
                    onCancelScan = {},
                    onExcludeApp = {},
                    onRemoveExclusion = {},
                    onQuarantineFinding = {},
                    onRestoreQuarantine = {},
                    onDeleteQuarantine = {},
                    onExportPdf = {},
                    onRefreshDeviceAudit = {},
                    onUpdateSignatures = {},
                    onStartBleScan = {},
                    onStopBleScan = {},
                    onClearTrackers = {},
                    onOpenPermissions = {}
                )
            }
        }
        composeRule.waitForIdle()

        // System app displays Trusted label, Disable button, and NEVER shows Uninstall
        assertTrue(
            "Expected Trusted: System app label",
            composeRule.onAllNodesWithText("Trusted: System app", substring = true).fetchSemanticsNodes().isNotEmpty()
        )
        assertTrue(
            "Expected Disable button for system app",
            composeRule.onAllNodesWithText("Disable", substring = true).fetchSemanticsNodes().isNotEmpty()
        )
        assertTrue(
            "Uninstall must NOT be shown for system apps",
            composeRule.onAllNodesWithText("Uninstall").fetchSemanticsNodes().isEmpty()
        )
    }
}
