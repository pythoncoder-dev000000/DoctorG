package com.python.doctorg.ui.screens.web

import android.annotation.SuppressLint
import android.content.Intent
import android.content.res.Configuration
import android.webkit.CookieManager
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.annotation.OptIn as AndroidxOptIn
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview as CameraPreview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.runtime.DisposableEffect
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
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Report
import androidx.compose.material.icons.filled.VpnLock
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.common.InputImage
import com.python.doctorg.R
import com.python.doctorg.core.adaptive.DeviceCapabilities
import java.util.Locale
import com.python.doctorg.data.local.entity.BlockedDomainEntity
import com.python.doctorg.data.local.entity.BlockedEventEntity
import com.python.doctorg.data.local.entity.FirewallRuleEntity
import com.python.doctorg.data.local.entity.SpamNumberEntity
import com.python.doctorg.data.preferences.DnsProvider
import com.python.doctorg.data.preferences.DoctorGSettings
import com.python.doctorg.domain.model.AppUsageStat
import com.python.doctorg.domain.model.LanDevice
import com.python.doctorg.domain.model.ScamAwarenessCard
import com.python.doctorg.domain.model.ScamSmsResult
import com.python.doctorg.domain.model.WifiSecurityAudit
import com.python.doctorg.ui.components.DoctorGBrandHeader
import com.python.doctorg.ui.components.StatusPill
import com.python.doctorg.ui.components.ThreatBadge
import com.python.doctorg.ui.theme.DoctorGColors
import com.python.doctorg.ui.theme.JetBrainsMonoFontFamily
import com.python.doctorg.ui.viewmodel.LinkCheckVerdict
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.util.concurrent.Executors

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun WebNetworkScreen(
    settings: DoctorGSettings,
    capabilities: DeviceCapabilities,
    isVpnRunning: Boolean,
    blocklistCount: Int,
    blockedEvents: List<BlockedEventEntity>,
    allowlistDomains: List<BlockedDomainEntity>,
    firewallRules: List<FirewallRuleEntity>,
    linkVerdict: LinkCheckVerdict?,
    wifiAudit: WifiSecurityAudit?,
    lanDevices: List<LanDevice>,
    networkToolOutput: String,
    dataUsageStats: List<AppUsageStat>,
    scamSmsResult: ScamSmsResult?,
    awarenessCards: List<ScamAwarenessCard>,
    spamNumbers: List<SpamNumberEntity>,
    hasCameraPermission: Boolean,
    isUrlBlocked: suspend (String) -> Boolean,
    onToggleVpn: (Boolean) -> Unit,
    onSelectDns: (DnsProvider, String?) -> Unit,
    onAddAllowlist: (String) -> Unit,
    onRemoveAllowlist: (String) -> Unit,
    onToggleFirewall: (FirewallRuleEntity, Boolean, Boolean) -> Unit,
    onCheckUrl: (String) -> Unit,
    onRequestCameraPermission: () -> Unit,
    onRunWifiAudit: () -> Unit,
    onPing: (String) -> Unit,
    onTraceroute: (String) -> Unit,
    onPortScan: (String) -> Unit,
    onLanScan: () -> Unit,
    onSpeedTest: () -> Unit,
    onRefreshDataUsage: () -> Unit,
    onAnalyzeScamSms: (String) -> Unit,
    onReportSpamNumber: (String, String) -> Unit,
    onChangeAppLanguage: (String) -> Unit = {},
    initialTab: Int = 0
) {
    val context = LocalContext.current
    var activeTab by rememberSaveable { mutableIntStateOf(initialTab) }

    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(
            modifier = Modifier
                .widthIn(max = 1120.dp)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(bottom = 28.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            DoctorGBrandHeader(subtitle = "Web Shield, Network Tools & India Scam Guard")

            FlowRow(
                modifier = Modifier.padding(horizontal = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                listOf("Web VPN & Firewall", "Safe Browser & QR", "Wi-Fi & Net Tools", "Scam Shield (India)").forEachIndexed { idx, label ->
                    FilterChip(
                        selected = activeTab == idx,
                        onClick = { activeTab = idx },
                        label = { Text(label) }
                    )
                }
            }

            when (activeTab) {
                0 -> WebVpnAndFirewallTab(
                    settings = settings,
                    isVpnRunning = isVpnRunning,
                    blocklistCount = blocklistCount,
                    blockedEvents = blockedEvents,
                    allowlistDomains = allowlistDomains,
                    firewallRules = firewallRules,
                    onToggleVpn = onToggleVpn,
                    onSelectDns = onSelectDns,
                    onAddAllowlist = onAddAllowlist,
                    onRemoveAllowlist = onRemoveAllowlist,
                    onToggleFirewall = onToggleFirewall
                )

                1 -> SafeBrowserAndQrTab(
                    capabilities = capabilities,
                    hasCameraPermission = hasCameraPermission,
                    linkVerdict = linkVerdict,
                    isUrlBlocked = isUrlBlocked,
                    onCheckUrl = onCheckUrl,
                    onRequestCameraPermission = onRequestCameraPermission
                )

                2 -> NetworkToolsTab(
                    wifiAudit = wifiAudit,
                    lanDevices = lanDevices,
                    networkToolOutput = networkToolOutput,
                    dataUsageStats = dataUsageStats,
                    onRunWifiAudit = onRunWifiAudit,
                    onPing = onPing,
                    onTraceroute = onTraceroute,
                    onPortScan = onPortScan,
                    onLanScan = onLanScan,
                    onSpeedTest = onSpeedTest,
                    onRefreshDataUsage = onRefreshDataUsage
                )

                else -> ScamShieldIndiaTab(
                    settings = settings,
                    capabilities = capabilities,
                    scamSmsResult = scamSmsResult,
                    awarenessCards = awarenessCards,
                    spamNumbers = spamNumbers,
                    onAnalyzeScamSms = onAnalyzeScamSms,
                    onReportSpamNumber = onReportSpamNumber,
                    onChangeAppLanguage = onChangeAppLanguage,
                    onDial1930 = {
                        runCatching {
                            context.startActivity(Intent(Intent.ACTION_DIAL, "tel:1930".toUri()))
                        }
                    },
                    onOpenCyberCrimePortal = {
                        runCatching {
                            context.startActivity(Intent(Intent.ACTION_VIEW, "https://cybercrime.gov.in".toUri()))
                        }
                    }
                )
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun WebVpnAndFirewallTab(
    settings: DoctorGSettings,
    isVpnRunning: Boolean,
    blocklistCount: Int,
    blockedEvents: List<BlockedEventEntity>,
    allowlistDomains: List<BlockedDomainEntity>,
    firewallRules: List<FirewallRuleEntity>,
    onToggleVpn: (Boolean) -> Unit,
    onSelectDns: (DnsProvider, String?) -> Unit,
    onAddAllowlist: (String) -> Unit,
    onRemoveAllowlist: (String) -> Unit,
    onToggleFirewall: (FirewallRuleEntity, Boolean, Boolean) -> Unit
) {
    var allowInput by rememberSaveable { mutableStateOf("") }
    var customDnsInput by rememberSaveable { mutableStateOf(settings.customDnsIp) }

    Column(
        modifier = Modifier.padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Icon(Icons.Filled.VpnLock, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                        Column {
                            Text("Local On-Device Web Protection VPN", style = MaterialTheme.typography.titleMedium)
                            Text("Zero external VPN server • $blocklistCount blocked domains", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    Switch(
                        checked = isVpnRunning,
                        onCheckedChange = onToggleVpn,
                        modifier = Modifier.testTag("web_vpn_switch")
                    )
                }
                StatusPill(
                    label = if (isVpnRunning) "Active • ${blockedEvents.size} blocked events logged" else "Paused • Tap switch to filter phishing/malware DNS",
                    active = isVpnRunning
                )
            }
        }

        // DNS Switcher
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Filled.Dns, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Text("Secure DNS Switcher", style = MaterialTheme.typography.titleMedium)
                }
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    DnsProvider.entries.forEach { provider ->
                        FilterChip(
                            selected = settings.dnsProvider == provider,
                            onClick = { onSelectDns(provider, customDnsInput) },
                            label = { Text("${provider.label} (${provider.ip})") }
                        )
                    }
                }
                if (settings.dnsProvider == DnsProvider.CUSTOM) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                        OutlinedTextField(
                            value = customDnsInput,
                            onValueChange = { customDnsInput = it },
                            label = { Text("Custom DNS IP") },
                            modifier = Modifier.weight(1f),
                            singleLine = true
                        )
                        Button(onClick = { onSelectDns(DnsProvider.CUSTOM, customDnsInput) }) { Text("Save") }
                    }
                }
            }
        }

        // Allowlist
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Domain Allowlist (${allowlistDomains.size})", style = MaterialTheme.typography.titleMedium)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = allowInput,
                        onValueChange = { allowInput = it },
                        label = { Text("example.com") },
                        modifier = Modifier.weight(1f),
                        singleLine = true
                    )
                    Button(onClick = { onAddAllowlist(allowInput); allowInput = "" }) { Text("Allow") }
                }
                allowlistDomains.forEach { item ->
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(item.domain, style = MaterialTheme.typography.bodyMedium, fontFamily = JetBrainsMonoFontFamily)
                        OutlinedButton(onClick = { onRemoveAllowlist(item.domain) }) { Text("Remove") }
                    }
                }
            }
        }

        // Recent Blocked Log
        if (blockedEvents.isNotEmpty()) {
            Text("Recent Blocked Threats (${blockedEvents.size})", style = MaterialTheme.typography.titleMedium)
            blockedEvents.take(8).forEach { ev ->
                OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(ev.domainOrUrl, style = MaterialTheme.typography.titleSmall, fontFamily = JetBrainsMonoFontFamily)
                        Text("${ev.source} • ${ev.reason}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                }
            }
        }

        // Per-App Firewall
        Text("Per-App Firewall Mode (Wi-Fi / Mobile)", style = MaterialTheme.typography.titleMedium)
        firewallRules.take(15).forEach { rule ->
            OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(rule.appName, style = MaterialTheme.typography.titleSmall)
                        Text(rule.packageName, style = MaterialTheme.typography.labelSmall)
                    }
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("Block Wi-Fi", style = MaterialTheme.typography.labelSmall)
                        Switch(checked = rule.blockWifi, onCheckedChange = { onToggleFirewall(rule, it, rule.blockMobile) })
                        Text("Mob", style = MaterialTheme.typography.labelSmall)
                        Switch(checked = rule.blockMobile, onCheckedChange = { onToggleFirewall(rule, rule.blockWifi, it) })
                    }
                }
            }
        }
    }
}

@SuppressLint("SetJavaScriptEnabled")
@Composable
private fun SafeBrowserAndQrTab(
    capabilities: DeviceCapabilities,
    hasCameraPermission: Boolean,
    linkVerdict: LinkCheckVerdict?,
    isUrlBlocked: suspend (String) -> Boolean,
    onCheckUrl: (String) -> Unit,
    onRequestCameraPermission: () -> Unit
) {
    val scope = rememberCoroutineScope()
    val lifecycleOwner = LocalLifecycleOwner.current
    var urlInput by rememberSaveable { mutableStateOf("https://testsafebrowsing.appspot.com") }
    var browserUrl by rememberSaveable { mutableStateOf("https://duckduckgo.com") }
    var blockedWarningUrl by rememberSaveable { mutableStateOf<String?>(null) }
    var trackersBlockedCount by rememberSaveable { mutableIntStateOf(0) }
    var showQrScanner by rememberSaveable { mutableStateOf(false) }

    Column(
        modifier = Modifier.padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Link Checker
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Filled.Link, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Text("Link Safety Checker", style = MaterialTheme.typography.titleMedium)
                }
                OutlinedTextField(
                    value = urlInput,
                    onValueChange = { urlInput = it },
                    label = { Text("Paste suspicious URL to inspect") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { onCheckUrl(urlInput) }, modifier = Modifier.testTag("link_check_button")) {
                        Text("Check Link")
                    }
                    OutlinedButton(onClick = {
                        scope.launch {
                            val trimmed = urlInput.trim()
                            val lower = trimmed.lowercase()
                            if (lower.startsWith("javascript:") || lower.startsWith("file:") || lower.startsWith("data:")) {
                                blockedWarningUrl = trimmed
                                return@launch
                            }
                            val target = if (lower.startsWith("https://") || lower.startsWith("http://")) trimmed else "https://$trimmed"
                            if (isUrlBlocked(target)) {
                                blockedWarningUrl = target
                            } else {
                                blockedWarningUrl = null
                                browserUrl = target
                            }
                        }
                    }) {
                        Text("Open in Safe Browser")
                    }
                }
                linkVerdict?.let { v ->
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = if (v.isSafe) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.errorContainer
                        )
                    ) {
                        Text(v.reason, modifier = Modifier.padding(12.dp), style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }

        // CameraX + ML Kit QR Code Scanner (auto-hidden if device has no camera)
        if (capabilities.hasCamera) {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Icon(Icons.Filled.QrCodeScanner, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                            Text("Safe QR Code Scanner", style = MaterialTheme.typography.titleMedium)
                        }
                        FilledTonalButton(onClick = {
                            if (hasCameraPermission) showQrScanner = !showQrScanner
                            else onRequestCameraPermission()
                        }) {
                            Text(if (showQrScanner) "Close Camera" else "Scan QR")
                        }
                    }
                    if (showQrScanner && hasCameraPermission) {
                        QrScannerPreviewBox(
                            lifecycleOwner = lifecycleOwner,
                            onQrDetected = { raw ->
                                urlInput = raw
                                onCheckUrl(raw)
                                showQrScanner = false
                            }
                        )
                    }
                }
            }
        }

        // Hardened In-App Safe Browser
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("DoctorG Safe Browser (Private Mode • $trackersBlockedCount trackers blocked)", style = MaterialTheme.typography.titleMedium)
                if (blockedWarningUrl != null) {
                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
                        Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text("PHISHING / MALWARE BLOCKED BY DOCTORG", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onErrorContainer)
                            Text("Blocked URL: $blockedWarningUrl", style = MaterialTheme.typography.bodySmall)
                            OutlinedButton(onClick = { blockedWarningUrl = null }) { Text("Go Back Safely") }
                        }
                    }
                } else {
                    AndroidView(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(260.dp),
                        factory = { ctx ->
                            WebView(ctx).apply {
                                settings.javaScriptEnabled = false // Safe-by-default; prevents drive-by XSS
                                settings.domStorageEnabled = false
                                settings.allowFileAccess = false
                                settings.allowContentAccess = false
                                settings.mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
                                settings.safeBrowsingEnabled = true
                                CookieManager.getInstance().setAcceptThirdPartyCookies(this, false)
                                webViewClient = object : WebViewClient() {
                                    override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                                        val target = request?.url?.toString().orEmpty()
                                        if (!target.startsWith("https://", ignoreCase = true) && !target.startsWith("http://", ignoreCase = true)) {
                                            return true
                                        }
                                        val blocked = runBlocking(Dispatchers.IO) { isUrlBlocked(target) }
                                        if (blocked) {
                                            trackersBlockedCount++
                                            blockedWarningUrl = target
                                            return true
                                        }
                                        return false
                                    }
                                }
                                loadUrl(browserUrl)
                            }
                        },
                        update = { webView ->
                            if (webView.url != browserUrl) webView.loadUrl(browserUrl)
                        },
                        onRelease = { webView ->
                            webView.stopLoading()
                            webView.destroy()
                        }
                    )
                }
            }
        }
    }
}

@AndroidxOptIn(ExperimentalGetImage::class)
@Composable
private fun QrScannerPreviewBox(
    lifecycleOwner: androidx.lifecycle.LifecycleOwner,
    onQrDetected: (String) -> Unit
) {
    val context = LocalContext.current
    val executor = remember { Executors.newSingleThreadExecutor() }
    val scanner = remember { BarcodeScanning.getClient() }
    var boundProvider by remember { mutableStateOf<ProcessCameraProvider?>(null) }

    DisposableEffect(Unit) {
        onDispose {
            runCatching { boundProvider?.unbindAll() }
            runCatching { scanner.close() }
            runCatching { executor.shutdown() }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(220.dp)
    ) {
        AndroidView(
            modifier = Modifier.fillMaxSize(),
            factory = { ctx ->
                val previewView = PreviewView(ctx)
                val cameraProviderFuture = ProcessCameraProvider.getInstance(ctx)
                cameraProviderFuture.addListener({
                    runCatching {
                        val provider = cameraProviderFuture.get()
                        boundProvider = provider
                        val preview = CameraPreview.Builder().build().also {
                            it.surfaceProvider = previewView.surfaceProvider
                        }
                        val analysis = ImageAnalysis.Builder()
                            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                            .build()
                        analysis.setAnalyzer(executor) { imageProxy ->
                            val mediaImg = imageProxy.image
                            if (mediaImg != null) {
                                val input = InputImage.fromMediaImage(mediaImg, imageProxy.imageInfo.rotationDegrees)
                                scanner.process(input)
                                    .addOnSuccessListener { barcodes ->
                                        val raw = barcodes.firstOrNull()?.rawValue
                                        if (!raw.isNullOrBlank()) {
                                            onQrDetected(raw)
                                        }
                                    }
                                    .addOnCompleteListener { imageProxy.close() }
                            } else {
                                imageProxy.close()
                            }
                        }
                        provider.unbindAll()
                        provider.bindToLifecycle(lifecycleOwner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
                    }
                }, ContextCompat.getMainExecutor(ctx))
                previewView
            }
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun NetworkToolsTab(
    wifiAudit: WifiSecurityAudit?,
    lanDevices: List<LanDevice>,
    networkToolOutput: String,
    dataUsageStats: List<AppUsageStat>,
    onRunWifiAudit: () -> Unit,
    onPing: (String) -> Unit,
    onTraceroute: (String) -> Unit,
    onPortScan: (String) -> Unit,
    onLanScan: () -> Unit,
    onSpeedTest: () -> Unit,
    onRefreshDataUsage: () -> Unit
) {
    var hostInput by rememberSaveable { mutableStateOf("1.1.1.1") }

    Column(
        modifier = Modifier.padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Icon(Icons.Filled.Wifi, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                        Text("Wi-Fi Security Audit", style = MaterialTheme.typography.titleMedium)
                    }
                    Button(onClick = onRunWifiAudit) { Text("Audit Wi-Fi") }
                }
                wifiAudit?.let { w ->
                    Text("SSID: ${w.ssid} • Security: ${w.securityType}", style = MaterialTheme.typography.titleSmall)
                    Text("Signal: ${w.rssiDbm} dBm • Link: ${w.linkSpeedMbps} Mbps • Gateway: ${w.gatewayIp}", style = MaterialTheme.typography.bodySmall)
                    Text("ARP Spoofing: ${if (w.arpSpoofingSuspected) "SUSPECTED!" else "Clean"} • Evil-Twin: ${if (w.evilTwinSuspected) "SUSPECTED!" else "Clean"}", style = MaterialTheme.typography.bodySmall)
                    w.warnings.forEach { warn -> Text("• $warn", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Filled.NetworkCheck, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Text("Network Diagnostics Suite", style = MaterialTheme.typography.titleMedium)
                }
                OutlinedTextField(
                    value = hostInput,
                    onValueChange = { hostInput = it },
                    label = { Text("Host or IP (Ping / Traceroute / Port Scan)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilledTonalButton(onClick = { onPing(hostInput) }) { Text("Ping") }
                    FilledTonalButton(onClick = { onTraceroute(hostInput) }) { Text("Traceroute") }
                    FilledTonalButton(onClick = { onPortScan(hostInput) }) { Text("Port Scan") }
                    FilledTonalButton(onClick = onLanScan) { Text("Who is on my Wi-Fi") }
                    FilledTonalButton(onClick = onSpeedTest) { Text("Speed Test") }
                    FilledTonalButton(onClick = onRefreshDataUsage) { Text("Data Usage") }
                }
                if (networkToolOutput.isNotBlank()) {
                    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
                        Text(
                            networkToolOutput,
                            modifier = Modifier.padding(12.dp),
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = JetBrainsMonoFontFamily
                        )
                    }
                }
            }
        }

        if (lanDevices.isNotEmpty()) {
            Text("LAN Devices (${lanDevices.size})", style = MaterialTheme.typography.titleMedium)
            lanDevices.forEach { dev ->
                OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text("${dev.ipAddress} — ${dev.vendor}", style = MaterialTheme.typography.titleSmall, fontFamily = JetBrainsMonoFontFamily)
                        Text("Host: ${dev.hostname} • MAC: ${dev.macAddress}", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }

        if (dataUsageStats.isNotEmpty()) {
            Text("30-Day App Data Usage", style = MaterialTheme.typography.titleMedium)
            dataUsageStats.take(10).forEach { stat ->
                OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(stat.appName, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                        Text(
                            "Wi-Fi ${stat.wifiBytes / (1024 * 1024)} MB • Mob ${stat.mobileBytes / (1024 * 1024)} MB",
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ScamShieldIndiaTab(
    settings: DoctorGSettings,
    capabilities: DeviceCapabilities,
    scamSmsResult: ScamSmsResult?,
    awarenessCards: List<ScamAwarenessCard>,
    spamNumbers: List<SpamNumberEntity>,
    onAnalyzeScamSms: (String) -> Unit,
    onReportSpamNumber: (String, String) -> Unit,
    onChangeAppLanguage: (String) -> Unit,
    onDial1930: () -> Unit,
    onOpenCyberCrimePortal: () -> Unit
) {
    val baseContext = LocalContext.current
    val supportedLanguages = remember {
        listOf(
            "en" to R.string.lang_name_en,
            "hi" to R.string.lang_name_hi,
            "ur" to R.string.lang_name_ur,
            "bn" to R.string.lang_name_bn,
            "ta" to R.string.lang_name_ta
        )
    }

    val initialLang = remember(settings.appLanguageTag) {
        val pref = settings.appLanguageTag.lowercase().substringBefore("-")
        if (pref in setOf("en", "hi", "ur", "bn", "ta")) {
            pref
        } else {
            val sys = Locale.getDefault().language.lowercase()
            if (sys in setOf("en", "hi", "ur", "bn", "ta")) sys else "en"
        }
    }
    var selectedLang by rememberSaveable(initialLang) { mutableStateOf(initialLang) }

    // Create a localized Context immediately on state change so all Android string resources
    // recompose without requiring an activity restart.
    val localizedContext = remember(baseContext, selectedLang) {
        val locale = Locale.forLanguageTag(selectedLang)
        val cfg = Configuration(baseContext.resources.configuration)
        cfg.setLocale(locale)
        cfg.setLocales(android.os.LocaleList(locale))
        baseContext.createConfigurationContext(cfg)
    }
    val localizedRes = localizedContext.resources
    val layoutDirection = if (selectedLang == "ur") LayoutDirection.Rtl else LayoutDirection.Ltr

    var smsInput by rememberSaveable { mutableStateOf("URGENT: Your SBI YONO KYC expired. Update PAN at http://sbi-yono-kyc-alert.top or account will be blocked tonight. Share OTP.") }
    var spamNumberInput by rememberSaveable { mutableStateOf("") }
    var spamCategoryInput by rememberSaveable { mutableStateOf("Fake KYC / UPI Scam") }
    val checklistState = remember { mutableStateListOf(false, false, false, false) }

    val evidenceItems = remember(localizedRes) {
        listOf(
            localizedRes.getString(R.string.scam_evidence_item_1),
            localizedRes.getString(R.string.scam_evidence_item_2),
            localizedRes.getString(R.string.scam_evidence_item_3),
            localizedRes.getString(R.string.scam_evidence_item_4)
        )
    }

    val currentLangLabel = localizedRes.getString(
        supportedLanguages.firstOrNull { it.first == selectedLang }?.second ?: R.string.lang_name_en
    )
    val toggleTargetLang = if (selectedLang == "hi") "en" else "hi"
    val toggleTargetLabel = localizedRes.getString(
        if (toggleTargetLang == "hi") R.string.lang_name_hi else R.string.lang_name_en
    )

    CompositionLocalProvider(LocalLayoutDirection provides layoutDirection) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Cyber Crime Helpline 1930 Card (localized)
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
            ) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        localizedRes.getString(R.string.scam_helpline_title),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onErrorContainer
                    )
                    Text(
                        localizedRes.getString(R.string.scam_helpline_subtitle),
                        style = MaterialTheme.typography.bodySmall
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Button(
                            onClick = onDial1930,
                            colors = ButtonDefaults.buttonColors(containerColor = DoctorGColors.DangerCrimsonDark),
                            modifier = Modifier.testTag("dial_1930_button")
                        ) {
                            Icon(Icons.Filled.Call, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.size(6.dp))
                            Text(localizedRes.getString(R.string.scam_dial_1930))
                        }
                        OutlinedButton(onClick = onOpenCyberCrimePortal) {
                            Text("cybercrime.gov.in")
                        }
                    }
                }
            }

            // On-Device Scam SMS Classifier (English / Hindi / Hinglish)
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Icon(Icons.Filled.Report, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                        Text("On-Device Scam SMS Classifier (EN / HI / Hinglish)", style = MaterialTheme.typography.titleMedium)
                    }
                    OutlinedTextField(
                        value = smsInput,
                        onValueChange = { smsInput = it },
                        label = { Text("Paste any suspicious SMS or WhatsApp message") },
                        modifier = Modifier.fillMaxWidth(),
                        minLines = 2
                    )
                    Button(
                        onClick = { onAnalyzeScamSms(smsInput) },
                        modifier = Modifier.testTag("analyze_scam_sms_button")
                    ) {
                        Text("Analyze Scam Risk Offline")
                    }
                    scamSmsResult?.let { res ->
                        OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text("Scam Score: ${res.riskScore}/100 (ML ${(res.mlProbability * 100).toInt()}%)", style = MaterialTheme.typography.titleSmall)
                                    ThreatBadge(res.verdict)
                                }
                                res.matchedReasons.forEach { reason ->
                                    Text("• $reason", style = MaterialTheme.typography.bodySmall)
                                }
                            }
                        }
                    }
                }
            }

            // Scam Call Warning List
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Scam Call Guard & Local Spam List (${spamNumbers.size})", style = MaterialTheme.typography.titleMedium)
                    if (!capabilities.hasTelephonyAndSim) {
                        Text("No active SIM detected — manual spam reporting stays available for reference.", style = MaterialTheme.typography.bodySmall)
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(
                            value = spamNumberInput,
                            onValueChange = { spamNumberInput = it },
                            label = { Text("+91 number") },
                            modifier = Modifier.weight(1f),
                            singleLine = true
                        )
                        Button(onClick = { onReportSpamNumber(spamNumberInput, spamCategoryInput); spamNumberInput = "" }) {
                            Text("Report")
                        }
                    }
                    spamNumbers.take(5).forEach { s ->
                        Text("• ${s.phoneNumber} — ${s.category} (${s.reports} reports)", style = MaterialTheme.typography.bodySmall, fontFamily = JetBrainsMonoFontFamily)
                    }
                }
            }

            // Fully Localized Scam Awareness Guides + Clear Language Switcher
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = localizedRes.getString(R.string.scam_guides_title),
                            style = MaterialTheme.typography.titleLarge,
                            modifier = Modifier.testTag("scam_guides_title")
                        )
                        Text(
                            text = localizedRes.getString(R.string.scam_language_current, currentLangLabel),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    FilledTonalButton(
                        onClick = {
                            selectedLang = toggleTargetLang
                            onChangeAppLanguage(toggleTargetLang)
                        },
                        modifier = Modifier.testTag("scam_language_toggle_button")
                    ) {
                        Text(localizedRes.getString(R.string.scam_language_switch_to, toggleTargetLabel))
                    }
                }

                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    supportedLanguages.forEach { (code, nameRes) ->
                        FilterChip(
                            selected = selectedLang == code,
                            onClick = {
                                selectedLang = code
                                onChangeAppLanguage(code)
                            },
                            label = { Text(localizedRes.getString(nameRes)) },
                            modifier = Modifier.testTag("scam_lang_chip_$code")
                        )
                    }
                }
            }

            if (awarenessCards.isEmpty()) {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = localizedRes.getString(R.string.scam_guides_empty),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(16.dp)
                    )
                }
            } else {
                val redFlagsHeading = localizedRes.getString(R.string.scam_red_flags_heading)
                val whatToDoHeading = localizedRes.getString(R.string.scam_what_to_do_heading)

                awarenessCards.forEach { card ->
                    val content = remember(card, selectedLang) { card.resolve(selectedLang) }
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(
                            modifier = Modifier.padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Text(
                                text = content.title,
                                style = MaterialTheme.typography.titleMedium,
                                modifier = Modifier.testTag("scam_card_title_${card.id}")
                            )
                            Text(
                                text = content.description,
                                style = MaterialTheme.typography.bodySmall
                            )
                            Text(
                                text = redFlagsHeading,
                                style = MaterialTheme.typography.labelLarge,
                                color = MaterialTheme.colorScheme.error,
                                modifier = Modifier.testTag("scam_card_red_flags_heading_${card.id}")
                            )
                            content.redFlags.forEach { flag ->
                                Text("• $flag", style = MaterialTheme.typography.bodySmall)
                            }
                            Text(
                                text = whatToDoHeading,
                                style = MaterialTheme.typography.labelLarge,
                                color = DoctorGColors.SafeEmeraldDark,
                                modifier = Modifier.testTag("scam_card_what_to_do_heading_${card.id}")
                            )
                            content.whatToDo.forEach { step ->
                                Text("• $step", style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                }
            }

            // Localized Evidence Checklist before reporting
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        localizedRes.getString(R.string.scam_evidence_checklist_title),
                        style = MaterialTheme.typography.titleMedium
                    )
                    evidenceItems.forEachIndexed { idx, label ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = checklistState[idx], onCheckedChange = { checklistState[idx] = it })
                            Text(label, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }
    }
}
