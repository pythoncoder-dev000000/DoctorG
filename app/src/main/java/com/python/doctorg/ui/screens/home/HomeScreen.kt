package com.python.doctorg.ui.screens.home

import androidx.compose.foundation.background
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
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PhonelinkLock
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.ReportProblem
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Update
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.VpnLock
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.python.doctorg.R
import com.python.doctorg.core.permissions.PermissionItemStatus
import com.python.doctorg.data.local.entity.ScanHistoryEntity
import com.python.doctorg.data.preferences.DoctorGSettings
import com.python.doctorg.domain.model.ScanLifecycleState
import com.python.doctorg.domain.model.ScanProgressState
import com.python.doctorg.ui.components.DoctorGBrandHeader
import com.python.doctorg.ui.components.SecurityScoreGauge
import com.python.doctorg.ui.components.StatusPill
import com.python.doctorg.ui.theme.DoctorGColors
import java.text.DateFormat
import java.util.Date

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun HomeScreen(
    settings: DoctorGSettings,
    scanState: ScanProgressState,
    scanHistory: List<ScanHistoryEntity>,
    signatureCount: Int,
    blockedCount: Int,
    isVpnRunning: Boolean,
    isAppLockRunning: Boolean,
    permissions: List<PermissionItemStatus>,
    isWideScreen: Boolean,
    onQuickScan: () -> Unit,
    onFullScan: () -> Unit,
    onNavigateToScan: () -> Unit,
    onNavigateToWeb: () -> Unit,
    onNavigateToPrivacy: () -> Unit,
    onNavigateToSettings: () -> Unit,
    onUpdateSignatures: () -> Unit
) {
    val activeScore = if (scanState.lifecycle == ScanLifecycleState.COMPLETED) {
        scanState.securityScore
    } else {
        settings.lastSecurityScore
    }
    val statusLabel = when {
        activeScore >= 85 -> "Strong Protection"
        activeScore >= 60 -> "Review Recommended"
        else -> "Action Needed"
    }
    val grantedCount = permissions.count { it.isGranted }

    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.TopCenter
    ) {
        Column(
            modifier = Modifier
                .widthIn(max = 1040.dp)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            DoctorGBrandHeader(
                subtitle = "Offline Security • $signatureCount Signatures",
                trailing = {
                    StatusPill(
                        label = "Offline Ready",
                        active = true,
                        icon = Icons.Filled.VerifiedUser
                    )
                }
            )

            // Hero Telemetry Card + Big Quick Scan / Full Scan Actions
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            Brush.linearGradient(
                                listOf(
                                    DoctorGColors.BrandNavy.copy(alpha = 0.08f),
                                    DoctorGColors.BrandCyan.copy(alpha = 0.06f)
                                )
                            )
                        )
                        .padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    if (isWideScreen) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(24.dp)
                        ) {
                            SecurityScoreGauge(
                                score = activeScore,
                                statusLabel = statusLabel,
                                lightweightMode = settings.lightweightMode
                            )
                            Column(
                                modifier = Modifier.weight(1f),
                                verticalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                Text("Device Health Overview", style = MaterialTheme.typography.headlineSmall)
                                Text(
                                    text = if (scanState.lifecycle == ScanLifecycleState.RUNNING) {
                                        "${scanState.stageName} • ${scanState.percent}%"
                                    } else {
                                        "Zero cloud uploads. Real-time install guard, YARA rules, local DNS filter, and encrypted SQLCipher vault."
                                    },
                                    style = MaterialTheme.typography.bodyMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                ScanActionButtonsRow(onQuickScan = onQuickScan, onFullScan = onFullScan)
                            }
                        }
                    } else {
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(14.dp)
                        ) {
                            SecurityScoreGauge(
                                score = activeScore,
                                statusLabel = statusLabel,
                                lightweightMode = settings.lightweightMode
                            )
                            if (scanState.lifecycle == ScanLifecycleState.RUNNING) {
                                Text(
                                    text = "${scanState.stageName} (${scanState.percent}%)",
                                    style = MaterialTheme.typography.titleSmall,
                                    color = MaterialTheme.colorScheme.primary
                                )
                            }
                            ScanActionButtonsRow(onQuickScan = onQuickScan, onFullScan = onFullScan)
                        }
                    }

                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        StatusPill(label = if (isVpnRunning) "Web VPN On ($blockedCount)" else "Web VPN Off", active = isVpnRunning, icon = Icons.Filled.VpnLock)
                        StatusPill(label = if (isAppLockRunning) "App Lock & UPI Guard" else "App Lock Idle", active = isAppLockRunning, icon = Icons.Filled.PhonelinkLock)
                        StatusPill(label = "Real-Time Install", active = settings.realTimeInstallScanEnabled, icon = Icons.Filled.Security)
                        StatusPill(label = "Permissions $grantedCount/${permissions.size}", active = grantedCount >= 4, icon = Icons.Filled.Shield)
                    }
                }
            }

            // Quick Security Hubs Grid
            Column(
                modifier = Modifier.padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text("Security Modules", style = MaterialTheme.typography.titleLarge)
                val shortcuts = listOf(
                    HomeShortcut("Permissions", "$grantedCount/${permissions.size} allowed", Icons.Filled.VerifiedUser, onNavigateToSettings),
                    HomeShortcut("Keep Running", "OEM battery guide", Icons.Filled.BatteryChargingFull, onNavigateToSettings),
                    HomeShortcut("Scam Shield", "SMS, Call & 1930", Icons.Filled.ReportProblem, onNavigateToWeb),
                    HomeShortcut("Secure Vault", "SQLCipher AES-256", Icons.Filled.Lock, onNavigateToPrivacy),
                    HomeShortcut("2FA Auth", "Offline TOTP codes", Icons.Filled.VpnKey, onNavigateToPrivacy),
                    HomeShortcut("Signatures", settings.signatureVersion.take(18), Icons.Filled.Update, onUpdateSignatures)
                )

                val columns = if (isWideScreen) 3 else 2
                shortcuts.chunked(columns).forEach { rowItems ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        rowItems.forEach { item ->
                            OutlinedCard(
                                onClick = item.onClick,
                                modifier = Modifier.weight(1f)
                            ) {
                                Column(
                                    modifier = Modifier.padding(14.dp),
                                    verticalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    Icon(
                                        item.icon,
                                        contentDescription = item.title,
                                        tint = MaterialTheme.colorScheme.primary,
                                        modifier = Modifier.size(22.dp)
                                    )
                                    Text(item.title, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    Text(item.subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                }
                            }
                        }
                        repeat(columns - rowItems.size) { Spacer(Modifier.weight(1f)) }
                    }
                }
            }

            // Recent Scan History
            Column(
                modifier = Modifier.padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Recent Scans", style = MaterialTheme.typography.titleLarge)
                    FilledTonalButton(onClick = onNavigateToScan) {
                        Text("Open Scanner")
                    }
                }
                if (scanHistory.isEmpty()) {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier.padding(16.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Icon(Icons.Filled.Radar, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                            Text(
                                "No scans recorded yet. Tap Quick Scan for a fast <1 minute offline audit.",
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                    }
                } else {
                    scanHistory.take(3).forEach { entry ->
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(14.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text("${entry.mode} SCAN • Score ${entry.securityScore}/100", style = MaterialTheme.typography.titleSmall)
                                    Text(
                                        "${entry.scannedItems} checked • ${entry.maliciousCount} malicious • ${entry.suspiciousCount} suspicious",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                    Text(
                                        DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(entry.timestampMs)),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                Icon(Icons.Filled.Key, contentDescription = null, tint = DoctorGColors.SafeEmerald)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ScanActionButtonsRow(
    onQuickScan: () -> Unit,
    onFullScan: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Button(
            onClick = onQuickScan,
            modifier = Modifier
                .weight(1f)
                .height(54.dp)
                .testTag("home_quick_scan_button"),
            shape = RoundedCornerShape(16.dp),
            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary)
        ) {
            Icon(Icons.Filled.Radar, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.size(8.dp))
            Text(stringResource(R.string.action_quick_scan), maxLines = 1)
        }
        FilledTonalButton(
            onClick = onFullScan,
            modifier = Modifier
                .weight(1f)
                .height(54.dp)
                .testTag("home_full_scan_button"),
            shape = RoundedCornerShape(16.dp)
        ) {
            Icon(Icons.Filled.Shield, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.size(8.dp))
            Text(stringResource(R.string.action_full_scan), maxLines = 1)
        }
    }
}

private data class HomeShortcut(
    val title: String,
    val subtitle: String,
    val icon: ImageVector,
    val onClick: () -> Unit
)
