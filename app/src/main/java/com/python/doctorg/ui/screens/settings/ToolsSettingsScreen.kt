package com.python.doctorg.ui.screens.settings

import android.os.Build
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BatteryChargingFull
import androidx.compose.material.icons.filled.Campaign
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.LocationOn
import androidx.compose.material.icons.filled.RecordVoiceOver
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.python.doctorg.BuildConfig
import com.python.doctorg.R
import com.python.doctorg.core.adaptive.DeviceCapabilities
import com.python.doctorg.core.adaptive.FoldPosture
import com.python.doctorg.core.adaptive.OemPowerHelper
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import com.python.doctorg.core.permissions.PermissionItemStatus
import com.python.doctorg.data.local.entity.ExcludedAppEntity
import com.python.doctorg.data.preferences.DoctorGSettings
import com.python.doctorg.data.preferences.ScanIntensity
import com.python.doctorg.ui.components.DoctorGBrandHeader
import com.python.doctorg.ui.theme.DoctorGColors
import com.python.doctorg.ui.theme.JetBrainsMonoFontFamily
import com.python.doctorg.ui.theme.ThemeMode

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ToolsSettingsScreen(
    settings: DoctorGSettings,
    permissions: List<PermissionItemStatus>,
    capabilities: DeviceCapabilities,
    foldPosture: FoldPosture,
    sirenActive: Boolean,
    locationText: String,
    onRequestPermission: (PermissionItemStatus) -> Unit,
    onOpenAppSettings: () -> Unit,
    onSetThemeMode: (ThemeMode) -> Unit,
    onSetDynamicColor: (Boolean) -> Unit,
    onSetHighContrast: (Boolean) -> Unit,
    onSetLargeText: (Boolean) -> Unit,
    onSetLightweight: (Boolean) -> Unit,
    onSetScanIntensity: (ScanIntensity) -> Unit,
    onSetScheduledScans: (Boolean, Boolean) -> Unit,
    onSetRealTimeInstall: (Boolean) -> Unit,
    onSetWifiOnlyUpdates: (Boolean) -> Unit,
    onSaveFeedBaseUrl: (String) -> Unit,
    onSaveVirusTotalKey: (String) -> Unit,
    onSaveSafeBrowsingKey: (String) -> Unit,
    onToggleSiren: () -> Unit,
    onSpeakAlert: () -> Unit,
    onFetchLocation: () -> Unit,
    excludedApps: List<ExcludedAppEntity> = emptyList(),
    onRemoveExclusion: (String) -> Unit = {},
    onSetVirusTotalThreshold: (Int) -> Unit = {},
    onSetAppLanguage: (String) -> Unit = {},
    onExportTrustedCerts: () -> String = { "" }
) {
    val context = LocalContext.current
    var activeSection by rememberSaveable { mutableIntStateOf(0) }
    var feedUrlInput by rememberSaveable(settings.feedBaseUrl) { mutableStateOf(settings.feedBaseUrl) }
    var vtKeyInput by rememberSaveable { mutableStateOf("") }
    var sbKeyInput by rememberSaveable { mutableStateOf("") }
    var exportedCertsPreview by rememberSaveable { mutableStateOf("") }

    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(
            modifier = Modifier
                .widthIn(max = 1040.dp)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(bottom = 28.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            DoctorGBrandHeader(subtitle = "Permissions, OEM Helper, Safety Tools & About")

            FlowRow(
                modifier = Modifier.padding(horizontal = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                listOf("Permissions", "Keep Running & Tools", "Settings & Feeds", "About DoctorG").forEachIndexed { idx, label ->
                    FilterChip(selected = activeSection == idx, onClick = { activeSection = idx }, label = { Text(label) })
                }
            }

            when (activeSection) {
                0 -> {
                    Column(
                        modifier = Modifier.padding(horizontal = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Text("Permissions Checklist (User Always in Control)", style = MaterialTheme.typography.titleLarge)
                        Text(
                            "DoctorG checks every permission on resume and degrades gracefully if denied. For Android 13+ sideloaded installs needing Notification Access, open App Info > three-dot menu > Allow restricted settings.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        OutlinedButton(onClick = onOpenAppSettings) {
                            Icon(Icons.Filled.Settings, contentDescription = null, modifier = Modifier.size(16.dp))
                            Text(" Open DoctorG System App Info")
                        }
                        permissions.forEach { perm ->
                            OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(perm.title, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                                        if (!perm.isSupportedOnThisAndroid) {
                                            Text(perm.unsupportedReason ?: "Not supported on API ${Build.VERSION.SDK_INT}", style = MaterialTheme.typography.labelSmall)
                                        } else if (perm.isGranted) {
                                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                                Icon(Icons.Filled.CheckCircle, contentDescription = "Allowed", tint = DoctorGColors.SafeEmerald, modifier = Modifier.size(18.dp))
                                                Text("Allowed", style = MaterialTheme.typography.labelMedium, color = DoctorGColors.SafeEmerald)
                                            }
                                        } else {
                                            Button(onClick = { onRequestPermission(perm) }) {
                                                Text("Allow")
                                            }
                                        }
                                    }
                                    Text("Features: ${perm.dependentFeatures}", style = MaterialTheme.typography.bodySmall)
                                    Text("Privacy: ${perm.privacyGuarantee}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.secondary)
                                    if (perm.needsRestrictedSettingsGuide && !perm.isGranted) {
                                        Text(
                                            "Android 13+ Tip: If Android shows 'Restricted setting', tap App Info > ⋮ (top right) > Allow restricted settings.",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.tertiary
                                        )
                                    }
                                }
                            }
                        }
                    }
                }

                1 -> {
                    val oemGuidance = OemPowerHelper.getGuidanceForCurrentDevice(context)
                    Column(
                        modifier = Modifier.padding(horizontal = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Icon(Icons.Filled.BatteryChargingFull, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                                    Text("Keep DoctorG Running (${oemGuidance.manufacturerName})", style = MaterialTheme.typography.titleMedium)
                                }
                                oemGuidance.steps.forEachIndexed { idx, step ->
                                    Text("${idx + 1}. $step", style = MaterialTheme.typography.bodySmall)
                                }
                                Button(onClick = { OemPowerHelper.launchBestSettingsIntent(context) }) {
                                    Text("Open OEM Power / Autostart Settings")
                                }
                            }
                        }

                        // Tabletop-ready Safety Siren, TTS & Play-Services-free Location
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Text(
                                    text = if (foldPosture is FoldPosture.Tabletop) {
                                        "Emergency Siren & Safety Tools (Tabletop Posture Active)"
                                    } else {
                                        "Emergency Siren, TTS & Offline Location Tool"
                                    },
                                    style = MaterialTheme.typography.titleMedium
                                )
                                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                                    Button(
                                        onClick = onToggleSiren,
                                        colors = ButtonDefaults.buttonColors(
                                            containerColor = if (sirenActive) DoctorGColors.DangerCrimsonDark else MaterialTheme.colorScheme.primary
                                        ),
                                        modifier = Modifier.weight(1f).height(52.dp)
                                    ) {
                                        Icon(Icons.Filled.Campaign, contentDescription = null, modifier = Modifier.size(18.dp))
                                        Text(if (sirenActive) " Stop Siren" else " Sound Siren")
                                    }
                                    FilledTonalButton(
                                        onClick = onSpeakAlert,
                                        modifier = Modifier.weight(1f).height(52.dp)
                                    ) {
                                        Icon(Icons.Filled.RecordVoiceOver, contentDescription = null, modifier = Modifier.size(18.dp))
                                        Text(" Speak Alert")
                                    }
                                }
                                Text(locationText, style = MaterialTheme.typography.bodySmall)
                                OutlinedButton(onClick = onFetchLocation) {
                                    Icon(Icons.Filled.LocationOn, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Text(" Fetch Device Location (Platform Fallback)")
                                }
                            }
                        }
                    }
                }

                2 -> {
                    Column(
                        modifier = Modifier.padding(horizontal = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Text("Appearance & Accessibility", style = MaterialTheme.typography.titleMedium)
                                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    ThemeMode.entries.forEach { mode ->
                                        FilterChip(selected = settings.themeMode == mode, onClick = { onSetThemeMode(mode) }, label = { Text(mode.name) })
                                    }
                                }
                                ToggleRow("Material You Dynamic Color (Android 12+)", settings.dynamicColor, onSetDynamicColor)
                                ToggleRow("High-Contrast Accessibility Mode", settings.highContrast, onSetHighContrast)
                                ToggleRow("Large-Text Readability Boost", settings.largeTextMode, onSetLargeText)
                                ToggleRow("Lightweight Mode (Low-RAM / Android Go)", settings.lightweightMode, onSetLightweight)
                                Text("App & Scam Guides Language", style = MaterialTheme.typography.titleSmall)
                                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                    listOf(
                                        "" to "System",
                                        "en" to "English",
                                        "hi" to "हिन्दी",
                                        "ur" to "اردو",
                                        "bn" to "বাংলা",
                                        "ta" to "தமிழ்"
                                    ).forEach { (tag, label) ->
                                        FilterChip(
                                            selected = settings.appLanguageTag == tag,
                                            onClick = { onSetAppLanguage(tag) },
                                            label = { Text(label) }
                                        )
                                    }
                                }
                            }
                        }

                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                Text("Scanning & Scheduling", style = MaterialTheme.typography.titleMedium)
                                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    ScanIntensity.entries.forEach { level ->
                                        FilterChip(selected = settings.scanIntensity == level, onClick = { onSetScanIntensity(level) }, label = { Text("Intensity: ${level.name}") })
                                    }
                                }
                                Text(
                                    "VirusTotal Hard-Evidence Threshold (${settings.virusTotalThreshold}+ engines for Malicious)",
                                    style = MaterialTheme.typography.bodySmall
                                )
                                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    listOf(3, 5, 8, 10).forEach { threshold ->
                                        FilterChip(
                                            selected = settings.virusTotalThreshold == threshold,
                                            onClick = { onSetVirusTotalThreshold(threshold) },
                                            label = { Text("$threshold+ engines") }
                                        )
                                    }
                                }
                                ToggleRow("Real-time Scan-on-Install", settings.realTimeInstallScanEnabled, onSetRealTimeInstall)
                                ToggleRow("Scheduled Daily Quick Scan", settings.dailyQuickScanEnabled) { onSetScheduledScans(it, settings.weeklyFullScanEnabled) }
                                ToggleRow("Scheduled Weekly Full Scan (Charging + Wi-Fi)", settings.weeklyFullScanEnabled) { onSetScheduledScans(settings.dailyQuickScanEnabled, it) }
                                ToggleRow("Wi-Fi-Only Feed Updates", settings.wifiOnlyUpdates, onSetWifiOnlyUpdates)
                            }
                        }

                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text("Trusted / Ignored Apps (${excludedApps.size})", style = MaterialTheme.typography.titleMedium)
                                if (excludedApps.isEmpty()) {
                                    Text(
                                        "No user-trusted scan exclusions yet. Apps marked 'Trust / Ignore' in Scan Results appear here and can be restored anytime.",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                } else {
                                    excludedApps.forEach { ex ->
                                        OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                                            Row(
                                                modifier = Modifier
                                                    .fillMaxWidth()
                                                    .padding(12.dp),
                                                horizontalArrangement = Arrangement.SpaceBetween,
                                                verticalAlignment = Alignment.CenterVertically
                                            ) {
                                                Column(modifier = Modifier.weight(1f)) {
                                                    Text(ex.appName, style = MaterialTheme.typography.titleSmall)
                                                    Text(ex.packageName, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                                }
                                                OutlinedButton(onClick = { onRemoveExclusion(ex.packageName) }) {
                                                    Text("Restore")
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text("Static GitHub Feeds & Optional User API Keys", style = MaterialTheme.typography.titleMedium)
                                OutlinedTextField(
                                    value = feedUrlInput,
                                    onValueChange = { feedUrlInput = it },
                                    label = { Text("GitHub Raw Feed Base URL (HTTPS)") },
                                    modifier = Modifier.fillMaxWidth(),
                                    singleLine = true
                                )
                                Button(onClick = { onSaveFeedBaseUrl(feedUrlInput) }) { Text("Save Feed URL") }

                                OutlinedTextField(
                                    value = vtKeyInput,
                                    onValueChange = { vtKeyInput = it },
                                    label = { Text(if (settings.hasVirusTotalKey) "VirusTotal API Key (Saved in Keystore)" else "Optional VirusTotal v3 API Key (Hashes only)") },
                                    visualTransformation = PasswordVisualTransformation(),
                                    modifier = Modifier.fillMaxWidth(),
                                    singleLine = true
                                )
                                OutlinedButton(onClick = { onSaveVirusTotalKey(vtKeyInput); vtKeyInput = "" }) { Text("Save / Clear VirusTotal Key") }

                                OutlinedTextField(
                                    value = sbKeyInput,
                                    onValueChange = { sbKeyInput = it },
                                    label = { Text(if (settings.hasSafeBrowsingKey) "Safe Browsing Key (Saved in Keystore)" else "Optional Google Safe Browsing API Key") },
                                    visualTransformation = PasswordVisualTransformation(),
                                    modifier = Modifier.fillMaxWidth(),
                                    singleLine = true
                                )
                                OutlinedButton(onClick = { onSaveSafeBrowsingKey(sbKeyInput); sbKeyInput = "" }) { Text("Save / Clear Safe Browsing Key") }
                            }
                        }
                    }
                }

                else -> {
                    Column(
                        modifier = Modifier.padding(horizontal = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(20.dp),
                                horizontalAlignment = Alignment.CenterHorizontally,
                                verticalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Surface(shape = RoundedCornerShape(22.dp), color = DoctorGColors.BrandNavy) {
                                    Image(
                                        painter = painterResource(R.drawable.doctorg_logo),
                                        contentDescription = "DoctorG Logo",
                                        modifier = Modifier
                                            .size(92.dp)
                                            .padding(6.dp)
                                    )
                                }
                                Text(
                                    text = "DoctorG v${BuildConfig.VERSION_NAME}",
                                    style = MaterialTheme.typography.headlineMedium,
                                    modifier = Modifier.testTag("about_version_text")
                                )
                                Text(
                                    text = "Package: ${BuildConfig.APPLICATION_ID} • Open-Source Offline Security Suite",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Text(
                                    text = "No monetization • No ads • No analytics • No Firebase • 100% private",
                                    style = MaterialTheme.typography.labelMedium,
                                    color = DoctorGColors.SafeEmerald
                                )
                            }
                        }

                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text(stringResource(R.string.privacy_policy_title), style = MaterialTheme.typography.titleMedium)
                                Text(stringResource(R.string.privacy_policy_body), style = MaterialTheme.typography.bodySmall)
                            }
                        }

                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                    Icon(Icons.Filled.Shield, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                                    Text("Device Hardware & Compatibility Telemetry", style = MaterialTheme.typography.titleMedium)
                                }
                                Text("Android API: ${capabilities.sdkInt} (${Build.VERSION.RELEASE}) • Low-RAM Mode: ${capabilities.isLowRamDevice}", style = MaterialTheme.typography.bodySmall)
                                Text("Camera: ${capabilities.hasCamera} • BLE: ${capabilities.hasBle} • SIM/Telephony: ${capabilities.hasTelephonyAndSim}", style = MaterialTheme.typography.bodySmall)
                                Text("Biometric: ${capabilities.hasBiometric} • USB Host: ${capabilities.hasUsbHost} • Play Services: ${capabilities.hasPlayServices}", style = MaterialTheme.typography.bodySmall)
                                if (!capabilities.hasPlayServices) {
                                    Text("Running in 100% Google-Play-Services-free mode (LocationManager fallback active).", style = MaterialTheme.typography.labelSmall, color = DoctorGColors.SafeEmerald)
                                }
                            }
                        }

                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text("Trusted Publisher Certificate Extractor", style = MaterialTheme.typography.titleMedium)
                                Text(
                                    "Extract real SHA-256 signing certificates (including key-rotation lineage) from major apps installed on this clean device to populate assets/trusted_publishers.json.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                OutlinedButton(
                                    onClick = {
                                        val json = onExportTrustedCerts()
                                        exportedCertsPreview = json
                                        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                                        cm?.setPrimaryClip(ClipData.newPlainText("trusted_publishers.json", json))
                                    }
                                ) {
                                    Text("Extract & Copy Installed Certs JSON")
                                }
                                if (exportedCertsPreview.isNotBlank()) {
                                    Text(
                                        text = exportedCertsPreview.take(900),
                                        style = MaterialTheme.typography.labelSmall,
                                        fontFamily = JetBrainsMonoFontFamily
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ToggleRow(label: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}
