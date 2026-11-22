package com.python.doctorg.ui.screens.scan

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Intent
import android.provider.Settings
import androidx.core.net.toUri
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
import androidx.compose.material.icons.automirrored.filled.BluetoothSearching
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PictureAsPdf
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Update
import androidx.compose.material.icons.filled.Workspaces
import com.python.doctorg.receiver.DoctorGDeviceAdminReceiver
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.python.doctorg.R
import com.python.doctorg.core.adaptive.DeviceCapabilities
import com.python.doctorg.data.local.entity.AppBaselineEntity
import com.python.doctorg.data.local.entity.ExcludedAppEntity
import com.python.doctorg.data.local.entity.QuarantineItemEntity
import com.python.doctorg.data.local.entity.TrackerSightingEntity
import com.python.doctorg.data.preferences.DoctorGSettings
import com.python.doctorg.domain.model.AppScanFinding
import com.python.doctorg.domain.model.DeviceSecurityAudit
import com.python.doctorg.domain.model.ScanLifecycleState
import com.python.doctorg.domain.model.ScanMode
import com.python.doctorg.domain.model.ScanProgressState
import com.python.doctorg.domain.model.SignalKind
import com.python.doctorg.domain.model.ThreatLevel
import com.python.doctorg.ui.components.AdaptiveTwoPaneContainer
import com.python.doctorg.ui.components.DoctorGBrandHeader
import com.python.doctorg.ui.components.ThreatBadge
import com.python.doctorg.ui.theme.DoctorGColors
import com.python.doctorg.ui.theme.JetBrainsMonoFontFamily

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ScanScreen(
    settings: DoctorGSettings,
    scanState: ScanProgressState,
    deviceAudit: DeviceSecurityAudit?,
    signatureCount: Int,
    excludedApps: List<ExcludedAppEntity>,
    quarantineItems: List<QuarantineItemEntity>,
    trackerSightings: List<TrackerSightingEntity>,
    appBaselines: List<AppBaselineEntity>,
    bleStatus: String,
    stalkerwareGuidance: List<String>,
    capabilities: DeviceCapabilities,
    isTwoPane: Boolean,
    onQuickScan: () -> Unit,
    onFullScan: () -> Unit,
    onPauseScan: () -> Unit,
    onResumeScan: () -> Unit,
    onCancelScan: () -> Unit,
    onExcludeApp: (AppScanFinding) -> Unit,
    onRemoveExclusion: (String) -> Unit,
    onQuarantineFinding: (AppScanFinding) -> Unit,
    onRestoreQuarantine: (QuarantineItemEntity) -> Unit,
    onDeleteQuarantine: (QuarantineItemEntity) -> Unit,
    onExportPdf: () -> Unit,
    onRefreshDeviceAudit: () -> Unit,
    onUpdateSignatures: () -> Unit,
    onStartBleScan: () -> Unit,
    onStopBleScan: () -> Unit,
    onClearTrackers: () -> Unit,
    onOpenPermissions: () -> Unit
) {
    val context = LocalContext.current
    var activeSection by rememberSaveable { mutableIntStateOf(0) }
    var selectedFindingId by rememberSaveable { mutableStateOf<String?>(null) }
    var filterMode by rememberSaveable { mutableStateOf("ALL") }

    val filteredFindings = scanState.findings.filter {
        when (filterMode) {
            "MALICIOUS" -> it.threatLevel == ThreatLevel.MALICIOUS
            "SUSPICIOUS" -> it.threatLevel == ThreatLevel.SUSPICIOUS
            "NEEDS_REVIEW" -> it.threatLevel == ThreatLevel.NEEDS_REVIEW
            "SAFE" -> it.threatLevel == ThreatLevel.SAFE
            "TRUSTED" -> it.threatLevel == ThreatLevel.TRUSTED
            else -> true
        }
    }
    val selectedFinding = filteredFindings.firstOrNull { it.id == selectedFindingId }
        ?: filteredFindings.firstOrNull()

    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(
            modifier = Modifier
                .widthIn(max = 1120.dp)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(bottom = 28.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            DoctorGBrandHeader(subtitle = "Malware & Threat Protection ($signatureCount hashes)")

            // Sub-section selector chips
            FlowRow(
                modifier = Modifier.padding(horizontal = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                listOf("Scanner", "Device Audit & CVEs", "Quarantine & Monitor", "Trackers & Feeds").forEachIndexed { idx, label ->
                    FilterChip(
                        selected = activeSection == idx,
                        onClick = { activeSection = idx },
                        label = { Text(label) }
                    )
                }
            }

            when (activeSection) {
                0 -> {
                    // Big Quick Scan / Full Scan Bar
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp),
                        shape = RoundedCornerShape(20.dp)
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                Button(
                                    onClick = onQuickScan,
                                    enabled = scanState.lifecycle != ScanLifecycleState.RUNNING,
                                    modifier = Modifier
                                        .weight(1f)
                                        .height(50.dp)
                                        .testTag("scan_quick_button")
                                ) {
                                    Icon(Icons.Filled.Radar, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(Modifier.size(6.dp))
                                    Text(stringResource(R.string.action_quick_scan))
                                }
                                FilledTonalButton(
                                    onClick = onFullScan,
                                    enabled = scanState.lifecycle != ScanLifecycleState.RUNNING,
                                    modifier = Modifier
                                        .weight(1f)
                                        .height(50.dp)
                                        .testTag("scan_full_button")
                                ) {
                                    Icon(Icons.Filled.Shield, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(Modifier.size(6.dp))
                                    Text(stringResource(R.string.action_full_scan))
                                }
                            }

                            // Live Staged Progress UI
                            if (scanState.lifecycle == ScanLifecycleState.RUNNING || scanState.lifecycle == ScanLifecycleState.PAUSED) {
                                Text(scanState.stageName, style = MaterialTheme.typography.titleSmall)
                                LinearProgressIndicator(
                                    progress = { scanState.percent / 100f },
                                    modifier = Modifier.fillMaxWidth()
                                )
                                Text(
                                    text = "${scanState.percent}% • ${scanState.currentItem} • Elapsed ${scanState.elapsedMs / 1000}s • ETA ${scanState.estimatedRemainingMs / 1000}s",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                                    if (scanState.mode == ScanMode.FULL) {
                                        if (scanState.lifecycle == ScanLifecycleState.PAUSED) {
                                            Button(onClick = onResumeScan) {
                                                Icon(Icons.Filled.PlayArrow, contentDescription = null)
                                                Text(stringResource(R.string.action_resume))
                                            }
                                        } else {
                                            OutlinedButton(onClick = onPauseScan) {
                                                Icon(Icons.Filled.Pause, contentDescription = null)
                                                Text(stringResource(R.string.action_pause))
                                            }
                                        }
                                    }
                                    OutlinedButton(onClick = onCancelScan) {
                                        Icon(Icons.Filled.Stop, contentDescription = null)
                                        Text(stringResource(R.string.action_cancel))
                                    }
                                }
                            }

                            // Verdict Banner + PDF Export + Full Scan Suggestion
                            if (scanState.findings.isNotEmpty() || scanState.lifecycle == ScanLifecycleState.COMPLETED) {
                                FlowRow(
                                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                                    verticalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    FilterChip(selected = filterMode == "ALL", onClick = { filterMode = "ALL" }, label = { Text("All (${scanState.findings.size})") })
                                    FilterChip(selected = filterMode == "MALICIOUS", onClick = { filterMode = "MALICIOUS" }, label = { Text("Malicious (${scanState.maliciousCount})") })
                                    FilterChip(selected = filterMode == "SUSPICIOUS", onClick = { filterMode = "SUSPICIOUS" }, label = { Text("Suspicious (${scanState.suspiciousCount})") })
                                    FilterChip(selected = filterMode == "NEEDS_REVIEW", onClick = { filterMode = "NEEDS_REVIEW" }, label = { Text("Review (${scanState.needsReviewCount})") })
                                    FilterChip(selected = filterMode == "SAFE", onClick = { filterMode = "SAFE" }, label = { Text("Safe (${scanState.safeCount})") })
                                    FilterChip(selected = filterMode == "TRUSTED", onClick = { filterMode = "TRUSTED" }, label = { Text("Trusted (${scanState.trustedCount})") })
                                }

                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    OutlinedButton(
                                        onClick = onExportPdf,
                                        modifier = Modifier.testTag("export_pdf_button")
                                    ) {
                                        Icon(Icons.Filled.PictureAsPdf, contentDescription = null, modifier = Modifier.size(16.dp))
                                        Spacer(Modifier.size(6.dp))
                                        Text(stringResource(R.string.action_export_pdf))
                                    }
                                    if (scanState.mode == ScanMode.QUICK && (scanState.suspiciousCount > 0 || scanState.maliciousCount > 0)) {
                                        Button(onClick = onFullScan) {
                                            Text("Run Full Scan")
                                        }
                                    }
                                }
                            }

                            // Skipped permission stages with one-tap Allow
                            scanState.skippedStages.forEach { (stage, perm) ->
                                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer)) {
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(12.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text("Skipped: permission not allowed", style = MaterialTheme.typography.labelLarge)
                                            Text("$stage requires $perm", style = MaterialTheme.typography.bodySmall)
                                        }
                                        OutlinedButton(onClick = onOpenPermissions) { Text("Allow") }
                                    }
                                }
                            }
                        }
                    }

                    // Adaptive Two-Pane Scan Results List + App Detail
                    if (filteredFindings.isNotEmpty()) {
                        AdaptiveTwoPaneContainer(
                            isTwoPane = isTwoPane,
                            modifier = Modifier.padding(horizontal = 16.dp),
                            listPane = {
                                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Text("Scan Findings", style = MaterialTheme.typography.titleMedium)
                                    filteredFindings.take(40).forEach { item ->
                                        OutlinedCard(
                                            onClick = { selectedFindingId = item.id },
                                            modifier = Modifier.fillMaxWidth()
                                        ) {
                                            Row(
                                                modifier = Modifier
                                                    .fillMaxWidth()
                                                    .padding(12.dp),
                                                verticalAlignment = Alignment.CenterVertically,
                                                horizontalArrangement = Arrangement.SpaceBetween
                                            ) {
                                                Column(modifier = Modifier.weight(1f)) {
                                                    Text(item.name, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                                    Text(
                                                        item.packageName ?: item.filePath.orEmpty(),
                                                        style = MaterialTheme.typography.bodySmall,
                                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                        maxLines = 1,
                                                        overflow = TextOverflow.Ellipsis
                                                    )
                                                }
                                                ThreatBadge(item.threatLevel)
                                            }
                                        }
                                    }
                                }
                            },
                            detailPane = {
                                selectedFinding?.let { f ->
                                    Card(
                                        modifier = Modifier.fillMaxWidth(),
                                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                                    ) {
                                        Column(
                                            modifier = Modifier.padding(16.dp),
                                            verticalArrangement = Arrangement.spacedBy(8.dp)
                                        ) {
                                            Row(
                                                modifier = Modifier.fillMaxWidth(),
                                                horizontalArrangement = Arrangement.SpaceBetween,
                                                verticalAlignment = Alignment.CenterVertically
                                            ) {
                                                Text(f.name, style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
                                                ThreatBadge(f.threatLevel)
                                            }
                                            f.trustLabel?.let { trust ->
                                                Text(
                                                    text = trust,
                                                    style = MaterialTheme.typography.labelLarge,
                                                    color = DoctorGColors.SafeEmeraldDark
                                                )
                                            }
                                            val mlText = f.mlProbability?.let { prob ->
                                                "ML Supporting Score: ${(prob * 100).toInt()}%"
                                            } ?: "ML Model: Disabled (no offline .tflite model)"
                                            Text("Risk Score: ${f.riskScore}/100 • $mlText", style = MaterialTheme.typography.titleSmall)
                                            Text("Source: ${f.installerSource} • targetSdk ${f.targetSdk}", style = MaterialTheme.typography.bodySmall)
                                            if (f.sha256.isNotBlank()) {
                                                Text("SHA-256: ${f.sha256.take(40)}...", style = MaterialTheme.typography.labelSmall, fontFamily = JetBrainsMonoFontFamily)
                                            }
                                            f.virusTotalMalicious?.let { vt ->
                                                Text("VirusTotal Hash Check: $vt engines flagged (threshold ${settings.virusTotalThreshold}+)", style = MaterialTheme.typography.bodySmall)
                                            }
                                            if (f.yaraMatches.isNotEmpty()) {
                                                Text("YARA Matches: ${f.yaraMatches.joinToString()}", style = MaterialTheme.typography.bodySmall, color = DoctorGColors.DangerCrimson)
                                            }
                                            Text("Why?", style = MaterialTheme.typography.titleSmall)
                                            if (f.signals.isNotEmpty()) {
                                                f.signals.forEach { sig ->
                                                    val tag = when (sig.kind) {
                                                        SignalKind.HARD -> "[Hard]"
                                                        SignalKind.SOFT -> "[Soft]"
                                                        SignalKind.TRUST -> "[Trust]"
                                                    }
                                                    val sigColor = when (sig.kind) {
                                                        SignalKind.HARD -> MaterialTheme.colorScheme.error
                                                        SignalKind.SOFT -> MaterialTheme.colorScheme.onSurface
                                                        SignalKind.TRUST -> DoctorGColors.SafeEmeraldDark
                                                    }
                                                    Text("• $tag ${sig.message}", style = MaterialTheme.typography.bodySmall, color = sigColor)
                                                }
                                            } else {
                                                f.reasons.forEach { r ->
                                                    Text("• $r", style = MaterialTheme.typography.bodySmall)
                                                }
                                            }
                                            if (f.staticIndicators.isNotEmpty()) {
                                                Text("Static APK Analysis:", style = MaterialTheme.typography.titleSmall)
                                                f.staticIndicators.forEach { ind ->
                                                    Text("• [Soft] $ind", style = MaterialTheme.typography.bodySmall)
                                                }
                                            }

                                            if (f.isSystemApp) {
                                                Card(
                                                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer)
                                                ) {
                                                    Text(
                                                        text = "System component warning: Disabling or removing system apps can break core Android features or cause your phone to malfunction.",
                                                        style = MaterialTheme.typography.bodySmall,
                                                        modifier = Modifier.padding(10.dp)
                                                    )
                                                }
                                            }

                                            FlowRow(
                                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                                verticalArrangement = Arrangement.spacedBy(8.dp)
                                            ) {
                                                f.packageName?.let { pkg ->
                                                    if (f.isSystemApp) {
                                                        OutlinedButton(
                                                            onClick = {
                                                                val appInfoIntent = Intent(
                                                                    Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                                                    "package:$pkg".toUri()
                                                                )
                                                                runCatching { context.startActivity(appInfoIntent) }
                                                            },
                                                            modifier = Modifier.testTag("scan_disable_system_app_button")
                                                        ) { Text("Disable") }
                                                    } else {
                                                        Button(
                                                            onClick = {
                                                                val uninstall = Intent(Intent.ACTION_DELETE, "package:$pkg".toUri())
                                                                runCatching { context.startActivity(uninstall) }
                                                            },
                                                            modifier = Modifier.testTag("scan_uninstall_app_button")
                                                        ) { Text("Uninstall") }
                                                    }
                                                    if (!f.isExcluded) {
                                                        OutlinedButton(
                                                            onClick = { onExcludeApp(f) },
                                                            modifier = Modifier.testTag("scan_trust_ignore_button")
                                                        ) { Text("Trust / Ignore") }
                                                    } else {
                                                        OutlinedButton(
                                                            onClick = { onRemoveExclusion(pkg) }
                                                        ) { Text("Restore Scanning") }
                                                    }
                                                }
                                                if (f.filePath != null && !f.isSystemApp) {
                                                    FilledTonalButton(onClick = { onQuarantineFinding(f) }) { Text("Quarantine") }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        )
                    }
                }

                1 -> {
                    // Device Security Audit, Tampering, Overlays, Remote-Access, CVEs & Work Profile Sandbox
                    Column(
                        modifier = Modifier.padding(horizontal = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text("Device Security & Tampering", style = MaterialTheme.typography.titleLarge)
                            FilledTonalButton(onClick = onRefreshDeviceAudit) { Text("Re-Audit") }
                        }

                        deviceAudit?.let { audit ->
                            Card(modifier = Modifier.fillMaxWidth()) {
                                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                    Text("${audit.androidVersionLabel} • Patch ${audit.securityPatchLevel}", style = MaterialTheme.typography.titleSmall)
                                    Text("Screen Lock: ${if (audit.hasScreenLock) "Protected" else "MISSING!"} • USB Debugging: ${if (audit.usbDebuggingEnabled) "ON (Risk)" else "Off"}", style = MaterialTheme.typography.bodySmall)
                                    Text("Active Accessibility Services: ${audit.activeAccessibilityServices.ifEmpty { listOf("None") }.joinToString()}", style = MaterialTheme.typography.bodySmall)
                                    Text("Active Device Admins: ${audit.activeDeviceAdmins.ifEmpty { listOf("None") }.joinToString()}", style = MaterialTheme.typography.bodySmall)
                                    Text("Remote-Access / Screen-Share Apps: ${audit.activeRemoteAccessApps.ifEmpty { listOf("None installed") }.joinToString()}", style = MaterialTheme.typography.bodySmall)
                                    Text("Overlay-Capable User Apps: ${audit.activeOverlayApps.size}", style = MaterialTheme.typography.bodySmall)
                                }
                            }

                            Text("Tampering Indicators (Root, Magisk, Xposed, Frida)", style = MaterialTheme.typography.titleMedium)
                            audit.tamperingFindings.forEach { t ->
                                OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(12.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Column(modifier = Modifier.weight(1f)) {
                                            Text(t.indicator, style = MaterialTheme.typography.titleSmall)
                                            Text(t.explanation, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                        }
                                        ThreatBadge(t.severity)
                                    }
                                }
                            }

                            Text("Android CVE Patch Check", style = MaterialTheme.typography.titleMedium)
                            audit.cveFindings.forEach { cve ->
                                Card(modifier = Modifier.fillMaxWidth()) {
                                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween
                                        ) {
                                            Text("${cve.cveId} (${cve.severity})", style = MaterialTheme.typography.titleSmall, fontFamily = JetBrainsMonoFontFamily)
                                            ThreatBadge(if (cve.isVulnerable) ThreatLevel.MALICIOUS else ThreatLevel.SAFE)
                                        }
                                        Text(cve.title, style = MaterialTheme.typography.bodySmall)
                                        if (cve.isVulnerable) {
                                            Text("Fix: ${cve.advice}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                                        }
                                    }
                                }
                            }
                        }

                        // Isolated Work Profile Sandbox Launcher
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Icon(Icons.Filled.Workspaces, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                                    Text("App Sandbox / Work Profile Isolation", style = MaterialTheme.typography.titleMedium)
                                }
                                Text(
                                    "Isolate untrusted or suspicious apps inside an Android Managed Work Profile (Shelter/Insular-style) so they cannot read your personal contacts, photos, or SMS.",
                                    style = MaterialTheme.typography.bodySmall
                                )
                                OutlinedButton(onClick = {
                                    val adminComponent = ComponentName(context, DoctorGDeviceAdminReceiver::class.java)
                                    val provision = Intent(DevicePolicyManager.ACTION_PROVISION_MANAGED_PROFILE).apply {
                                        putExtra(DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME, adminComponent)
                                    }
                                    runCatching { context.startActivity(provision) }
                                }) {
                                    Text("Configure Isolated Work Profile")
                                }
                            }
                        }
                    }
                }

                2 -> {
                    // Quarantine Vault, Trusted Exclusions & App Change Monitor
                    Column(
                        modifier = Modifier.padding(horizontal = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Text("Encrypted Quarantine Vault (${quarantineItems.size})", style = MaterialTheme.typography.titleLarge)
                        if (quarantineItems.isEmpty()) {
                            Card(modifier = Modifier.fillMaxWidth()) {
                                Text(
                                    "No files in quarantine. Suspicious APKs or downloads quarantined by DoctorG are AES-256-GCM encrypted here.",
                                    modifier = Modifier.padding(16.dp),
                                    style = MaterialTheme.typography.bodyMedium
                                )
                            }
                        } else {
                            quarantineItems.forEach { item ->
                                Card(modifier = Modifier.fillMaxWidth()) {
                                    Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                        Text(item.originalName, style = MaterialTheme.typography.titleSmall)
                                        Text("Threat: ${item.threatName}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                                        Text("SHA-256: ${item.sha256.take(32)}...", style = MaterialTheme.typography.labelSmall, fontFamily = JetBrainsMonoFontFamily)
                                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                            OutlinedButton(onClick = { onRestoreQuarantine(item) }) {
                                                Icon(Icons.Filled.Restore, contentDescription = null, modifier = Modifier.size(16.dp))
                                                Text(" Restore")
                                            }
                                            Button(onClick = { onDeleteQuarantine(item) }) {
                                                Icon(Icons.Filled.Delete, contentDescription = null, modifier = Modifier.size(16.dp))
                                                Text(" Wipe")
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        Text("Trusted Apps / Scan Exclusions (${excludedApps.size})", style = MaterialTheme.typography.titleMedium)
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
                                        Text(ex.packageName, style = MaterialTheme.typography.bodySmall)
                                    }
                                    OutlinedButton(onClick = { onRemoveExclusion(ex.packageName) }) { Text("Remove") }
                                }
                            }
                        }

                        Text("App Change Monitor Baselines (${appBaselines.size} tracked)", style = MaterialTheme.typography.titleMedium)
                        appBaselines.take(8).forEach { base ->
                            OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                                Column(modifier = Modifier.padding(12.dp)) {
                                    Text("${base.appName} (v${base.versionCode})", style = MaterialTheme.typography.titleSmall)
                                    Text("Cert: ${base.certSha256.take(28)}...", style = MaterialTheme.typography.labelSmall, fontFamily = JetBrainsMonoFontFamily)
                                }
                            }
                        }
                    }
                }

                else -> {
                    // BLE Tracker Detector, Stalkerware Safety Guidance & Signature DB Updater
                    Column(
                        modifier = Modifier.padding(horizontal = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Icon(Icons.Filled.Update, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                                    Text("Offline Signature & Rule Updater", style = MaterialTheme.typography.titleMedium)
                                }
                                Text("Version: ${settings.signatureVersion} • $signatureCount malware SHA-256 hashes", style = MaterialTheme.typography.bodySmall)
                                Text("Feed Repo: ${settings.feedBaseUrl}", style = MaterialTheme.typography.labelSmall)
                                Button(onClick = onUpdateSignatures) {
                                    Text(stringResource(R.string.action_update_signatures))
                                }
                            }
                        }

                        if (capabilities.hasBle) {
                            Card(modifier = Modifier.fillMaxWidth()) {
                                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Icon(Icons.AutoMirrored.Filled.BluetoothSearching, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                                        Text("BLE Unknown Tracker Detector", style = MaterialTheme.typography.titleMedium)
                                    }
                                    Text(bleStatus, style = MaterialTheme.typography.bodySmall)
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Button(onClick = onStartBleScan) { Text("Start BLE Scan") }
                                        OutlinedButton(onClick = onStopBleScan) { Text("Stop") }
                                        if (trackerSightings.isNotEmpty()) {
                                            OutlinedButton(onClick = onClearTrackers) { Text("Clear Log") }
                                        }
                                    }
                                    trackerSightings.forEach { t ->
                                        val mins = ((t.lastSeenMs - t.firstSeenMs) / 60_000L).coerceAtLeast(0)
                                        OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                                            Column(modifier = Modifier.padding(12.dp)) {
                                                Text("${t.trackerType} • ${t.macAddress}", style = MaterialTheme.typography.titleSmall)
                                                Text("Found nearby for $mins min • Signal ${t.rssi} dBm • Seen ${t.sightingsCount}x", style = MaterialTheme.typography.bodySmall)
                                                Text("Disable tip: Twist counter-clockwise to remove CR2032 battery (AirTag/SmartTag).", style = MaterialTheme.typography.labelSmall)
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text("Stalkerware / Spyware Safety Guide", style = MaterialTheme.typography.titleMedium)
                                stalkerwareGuidance.forEach { tip ->
                                    Text("• $tip", style = MaterialTheme.typography.bodySmall)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
