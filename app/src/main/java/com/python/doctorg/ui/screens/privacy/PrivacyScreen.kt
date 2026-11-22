package com.python.doctorg.ui.screens.privacy

import android.content.Intent
import android.provider.Settings
import androidx.core.net.toUri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PhonelinkLock
import androidx.compose.material.icons.filled.PhotoLibrary
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.python.doctorg.core.adaptive.DeviceCapabilities
import com.python.doctorg.data.local.entity.FirewallRuleEntity
import com.python.doctorg.data.local.vault.TotpAccountEntity
import com.python.doctorg.data.local.vault.VaultItemEntity
import com.python.doctorg.data.preferences.DoctorGSettings
import com.python.doctorg.domain.model.AccountCheckupItem
import com.python.doctorg.domain.model.PasswordHealthReport
import com.python.doctorg.ui.components.AdaptiveTwoPaneContainer
import com.python.doctorg.ui.components.DoctorGBrandHeader
import com.python.doctorg.ui.components.StatusPill
import com.python.doctorg.ui.theme.DoctorGColors
import com.python.doctorg.ui.theme.JetBrainsMonoFontFamily
import com.python.doctorg.ui.viewmodel.PrivacyPermissionGroup
import kotlinx.coroutines.delay

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun PrivacyScreen(
    settings: DoctorGSettings,
    capabilities: DeviceCapabilities,
    vaultItems: List<VaultItemEntity>,
    totpAccounts: List<TotpAccountEntity>,
    passwordHealth: PasswordHealthReport?,
    privacyGroups: List<PrivacyPermissionGroup>,
    accountCheckups: List<AccountCheckupItem>,
    installedApps: List<FirewallRuleEntity>,
    isAppLockRunning: Boolean,
    isTwoPane: Boolean,
    onAddVaultItem: (String, String, String, String, String) -> Unit,
    onDeleteVaultItem: (Long) -> Unit,
    onGeneratePassword: () -> String,
    onRunPasswordHealth: (Boolean) -> Unit,
    onAddTotpAccount: (String, String, String) -> Unit,
    onDeleteTotpAccount: (Long) -> Unit,
    onGenerateTotp: (String, Long) -> String,
    onTotpRemainingSeconds: (Long) -> Int,
    onExportTotpBackup: (String) -> String,
    onImportTotpBackup: (String, String) -> Unit,
    onSaveAppLockPin: (String) -> Unit,
    onUpdateAppLockOptions: (Boolean?, Boolean?, Boolean?, Boolean?) -> Unit,
    onToggleLockedApp: (String) -> Unit,
    onPromptBiometric: () -> Unit,
    onRefreshPrivacyAdvisor: () -> Unit
) {
    var activeTab by rememberSaveable { mutableIntStateOf(0) }

    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(
            modifier = Modifier
                .widthIn(max = 1120.dp)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(bottom = 28.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            DoctorGBrandHeader(
                subtitle = "SQLCipher Vault, 2FA Auth, App Lock & Privacy",
                trailing = {
                    StatusPill(label = "FLAG_SECURE", active = true, icon = Icons.Filled.Lock)
                }
            )

            FlowRow(
                modifier = Modifier.padding(horizontal = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                listOf("Secure Vault", "2FA Authenticator", "App Lock", "Privacy & Accounts").forEachIndexed { idx, label ->
                    FilterChip(
                        selected = activeTab == idx,
                        onClick = { activeTab = idx },
                        label = { Text(label) }
                    )
                }
            }

            when (activeTab) {
                0 -> SecureVaultTab(
                    vaultItems = vaultItems,
                    passwordHealth = passwordHealth,
                    isTwoPane = isTwoPane,
                    onAddVaultItem = onAddVaultItem,
                    onDeleteVaultItem = onDeleteVaultItem,
                    onGeneratePassword = onGeneratePassword,
                    onRunPasswordHealth = onRunPasswordHealth
                )

                1 -> TotpAuthenticatorTab(
                    accounts = totpAccounts,
                    onAddAccount = onAddTotpAccount,
                    onDeleteAccount = onDeleteTotpAccount,
                    onGenerateTotp = onGenerateTotp,
                    onRemainingSeconds = onTotpRemainingSeconds,
                    onExportBackup = onExportTotpBackup,
                    onImportBackup = onImportTotpBackup
                )

                2 -> AppLockTab(
                    settings = settings,
                    capabilities = capabilities,
                    installedApps = installedApps,
                    isAppLockRunning = isAppLockRunning,
                    onSavePin = onSaveAppLockPin,
                    onUpdateOptions = onUpdateAppLockOptions,
                    onToggleLockedApp = onToggleLockedApp,
                    onPromptBiometric = onPromptBiometric
                )

                else -> PrivacyAdvisorAndAccountsTab(
                    privacyGroups = privacyGroups,
                    accountCheckups = accountCheckups,
                    onRefreshAdvisor = onRefreshPrivacyAdvisor
                )
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun SecureVaultTab(
    vaultItems: List<VaultItemEntity>,
    passwordHealth: PasswordHealthReport?,
    isTwoPane: Boolean,
    onAddVaultItem: (String, String, String, String, String) -> Unit,
    onDeleteVaultItem: (Long) -> Unit,
    onGeneratePassword: () -> String,
    onRunPasswordHealth: (Boolean) -> Unit
) {
    val clipboard = LocalClipboardManager.current
    var itemType by rememberSaveable { mutableStateOf("PASSWORD") }
    var title by rememberSaveable { mutableStateOf("") }
    var username by rememberSaveable { mutableStateOf("") }
    var secret by rememberSaveable { mutableStateOf("") }
    var website by rememberSaveable { mutableStateOf("") }
    var selectedItemId by rememberSaveable { mutableStateOf<Long?>(null) }

    // Zero-permission Android Photo Picker for importing private photos into Vault
    val photoPicker = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        if (uri != null) {
            onAddVaultItem("FILE", "Private Photo", "Android Photo Picker", uri.toString(), uri.lastPathSegment ?: "photo")
        }
    }

    val selectedItem = vaultItems.firstOrNull { it.id == selectedItemId } ?: vaultItems.firstOrNull()

    Column(
        modifier = Modifier.padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Add to SQLCipher 256-bit Vault", style = MaterialTheme.typography.titleMedium)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf("PASSWORD", "NOTE", "FILE").forEach { t ->
                        FilterChip(selected = itemType == t, onClick = { itemType = t }, label = { Text(t) })
                    }
                }
                OutlinedTextField(
                    value = title,
                    onValueChange = { title = it },
                    label = { Text("Title (e.g., HDFC NetBanking, Wi-Fi Recovery)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
                if (itemType == "PASSWORD") {
                    OutlinedTextField(
                        value = username,
                        onValueChange = { username = it },
                        label = { Text("Username / Email") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                }
                OutlinedTextField(
                    value = secret,
                    onValueChange = { secret = it },
                    label = { Text(if (itemType == "PASSWORD") "Password" else "Encrypted Content") },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = if (itemType == "NOTE") 3 else 1
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (itemType == "PASSWORD") {
                        OutlinedButton(onClick = { secret = onGeneratePassword() }) {
                            Icon(Icons.Filled.Key, contentDescription = null, modifier = Modifier.size(16.dp))
                            Text(" Generate Strong")
                        }
                    }
                    if (itemType == "FILE") {
                        OutlinedButton(onClick = {
                            photoPicker.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
                        }) {
                            Icon(Icons.Filled.PhotoLibrary, contentDescription = null, modifier = Modifier.size(16.dp))
                            Text(" Pick Photo")
                        }
                    }
                    Button(
                        onClick = {
                            if (title.isNotBlank() && secret.isNotBlank()) {
                                onAddVaultItem(itemType, title, username, secret, website)
                                title = ""; username = ""; secret = ""; website = ""
                            }
                        },
                        modifier = Modifier.testTag("vault_save_button")
                    ) {
                        Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(16.dp))
                        Text(" Save Encrypted")
                    }
                }
            }
        }

        // Password Health Report (Offline + optional HIBP k-anonymity)
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Password Health Report (HIBP k-Anonymity)", style = MaterialTheme.typography.titleMedium)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilledTonalButton(onClick = { onRunPasswordHealth(false) }) { Text("Offline Audit") }
                    OutlinedButton(onClick = { onRunPasswordHealth(true) }) { Text("Audit + HIBP Breach Check") }
                }
                passwordHealth?.let { report ->
                    Text(
                        "Score: ${report.overallScore}/100 • Weak: ${report.weakCount} • Reused: ${report.reusedCount} • Old: ${report.oldCount} • Leaked: ${report.leakedCount}",
                        style = MaterialTheme.typography.titleSmall
                    )
                    report.suggestions.forEach { s -> Text("• $s", style = MaterialTheme.typography.bodySmall) }
                }
            }
        }

        // Adaptive Two-Pane Vault List + Detail
        if (vaultItems.isNotEmpty()) {
            AdaptiveTwoPaneContainer(
                isTwoPane = isTwoPane,
                listPane = {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Stored Vault Items (${vaultItems.size})", style = MaterialTheme.typography.titleMedium)
                        vaultItems.forEach { item ->
                            OutlinedCard(
                                onClick = { selectedItemId = item.id },
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(12.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(item.title, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                        Text("${item.type} • ${item.usernameOrMeta}", style = MaterialTheme.typography.bodySmall)
                                    }
                                    IconButton(onClick = { onDeleteVaultItem(item.id) }) {
                                        Icon(Icons.Filled.Delete, contentDescription = "Delete vault item")
                                    }
                                }
                            }
                        }
                    }
                },
                detailPane = {
                    selectedItem?.let { item ->
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text(item.title, style = MaterialTheme.typography.titleLarge)
                                Text("Type: ${item.type} • Account: ${item.usernameOrMeta.ifBlank { "N/A" }}", style = MaterialTheme.typography.bodySmall)
                                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
                                    Text(
                                        item.secretContent,
                                        modifier = Modifier.padding(12.dp),
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontFamily = JetBrainsMonoFontFamily
                                    )
                                }
                                OutlinedButton(onClick = { clipboard.setText(AnnotatedString(item.secretContent)) }) {
                                    Icon(Icons.Filled.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                                    Text(" Copy Secret")
                                }
                            }
                        }
                    }
                }
            )
        }
    }
}

@Composable
private fun TotpAuthenticatorTab(
    accounts: List<TotpAccountEntity>,
    onAddAccount: (String, String, String) -> Unit,
    onDeleteAccount: (Long) -> Unit,
    onGenerateTotp: (String, Long) -> String,
    onRemainingSeconds: (Long) -> Int,
    onExportBackup: (String) -> String,
    onImportBackup: (String, String) -> Unit
) {
    val clipboard = LocalClipboardManager.current
    var nowMs by rememberSaveable { mutableLongStateOf(System.currentTimeMillis()) }
    var issuer by rememberSaveable { mutableStateOf("") }
    var accountName by rememberSaveable { mutableStateOf("") }
    var secretOrUri by rememberSaveable { mutableStateOf("") }
    var backupPassword by rememberSaveable { mutableStateOf("") }
    var backupBlob by rememberSaveable { mutableStateOf("") }

    LaunchedEffect(Unit) {
        while (true) {
            nowMs = System.currentTimeMillis()
            delay(1000L)
        }
    }

    val remaining = onRemainingSeconds(nowMs)

    Column(
        modifier = Modifier.padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Add 2FA Authenticator Account (RFC 6238 TOTP)", style = MaterialTheme.typography.titleMedium)
                OutlinedTextField(value = issuer, onValueChange = { issuer = it }, label = { Text("Issuer (e.g., GitHub, Google)") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                OutlinedTextField(value = accountName, onValueChange = { accountName = it }, label = { Text("Account Email / Label") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                OutlinedTextField(value = secretOrUri, onValueChange = { secretOrUri = it }, label = { Text("Base32 Secret Key or otpauth:// URI") }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                Button(
                    onClick = {
                        if (secretOrUri.isNotBlank()) {
                            onAddAccount(issuer, accountName, secretOrUri)
                            issuer = ""; accountName = ""; secretOrUri = ""
                        }
                    },
                    modifier = Modifier.testTag("add_totp_button")
                ) {
                    Text("Add 2FA Code")
                }
            }
        }

        if (accounts.isNotEmpty()) {
            LinearProgressIndicator(
                progress = { remaining / 30f },
                modifier = Modifier.fillMaxWidth()
            )
            Text("Refreshes in ${remaining}s", style = MaterialTheme.typography.labelSmall)
        }

        accounts.forEach { acc ->
            val code = onGenerateTotp(acc.secretBase32, nowMs)
            val formatted = if (code.length == 6) "${code.take(3)} ${code.drop(3)}" else code
            Card(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(14.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(acc.issuer, style = MaterialTheme.typography.titleSmall)
                        Text(acc.accountName, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text(formatted, style = MaterialTheme.typography.headlineMedium, fontFamily = JetBrainsMonoFontFamily, color = DoctorGColors.SafeEmerald)
                    }
                    Row {
                        IconButton(onClick = { clipboard.setText(AnnotatedString(code)) }) {
                            Icon(Icons.Filled.ContentCopy, contentDescription = "Copy 2FA code")
                        }
                        IconButton(onClick = { onDeleteAccount(acc.id) }) {
                            Icon(Icons.Filled.Delete, contentDescription = "Delete 2FA account")
                        }
                    }
                }
            }
        }

        // Encrypted 2FA Export / Import
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Encrypted 2FA Backup (AES-256-GCM)", style = MaterialTheme.typography.titleMedium)
                OutlinedTextField(
                    value = backupPassword,
                    onValueChange = { backupPassword = it },
                    label = { Text("Backup Passphrase") },
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
                OutlinedTextField(
                    value = backupBlob,
                    onValueChange = { backupBlob = it },
                    label = { Text("Encrypted Backup String") },
                    modifier = Modifier.fillMaxWidth(),
                    maxLines = 3
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = {
                        if (backupPassword.length >= 6) backupBlob = onExportBackup(backupPassword)
                    }) { Text("Export Encrypted") }
                    Button(onClick = {
                        if (backupPassword.length >= 6 && backupBlob.isNotBlank()) onImportBackup(backupBlob, backupPassword)
                    }) { Text("Import Backup") }
                }
            }
        }
    }
}

@Composable
private fun AppLockTab(
    settings: DoctorGSettings,
    capabilities: DeviceCapabilities,
    installedApps: List<FirewallRuleEntity>,
    isAppLockRunning: Boolean,
    onSavePin: (String) -> Unit,
    onUpdateOptions: (Boolean?, Boolean?, Boolean?, Boolean?) -> Unit,
    onToggleLockedApp: (String) -> Unit,
    onPromptBiometric: () -> Unit
) {
    var pinInput by rememberSaveable { mutableStateOf("") }

    Column(
        modifier = Modifier.padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Icon(Icons.Filled.PhonelinkLock, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                    Text("App Lock, Intruder Selfie & UPI Fraud Guard", style = MaterialTheme.typography.titleMedium)
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Text("Active App Lock & UPI Guard Service", style = MaterialTheme.typography.bodyMedium)
                    Switch(checked = isAppLockRunning, onCheckedChange = { onUpdateOptions(it, null, null, null) })
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Text("Protect DoctorG itself on launch", style = MaterialTheme.typography.bodyMedium)
                    Switch(checked = settings.appLockSelfProtect, onCheckedChange = { onUpdateOptions(null, null, it, null) })
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Text("Fake-Crash disguise mode", style = MaterialTheme.typography.bodyMedium)
                    Switch(checked = settings.appLockFakeCrash, onCheckedChange = { onUpdateOptions(null, it, null, null) })
                }
                if (capabilities.hasBiometric) {
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                        Text("Unlock with BiometricPrompt", style = MaterialTheme.typography.bodyMedium)
                        Switch(checked = settings.appLockBiometric, onCheckedChange = { onUpdateOptions(null, null, null, it) })
                    }
                    OutlinedButton(onClick = onPromptBiometric) {
                        Icon(Icons.Filled.Fingerprint, contentDescription = null, modifier = Modifier.size(16.dp))
                        Text(" Test Biometric Prompt")
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = pinInput,
                        onValueChange = { pinInput = it.filter { ch -> ch.isDigit() }.take(8) },
                        label = { Text(if (settings.hasAppLockPin) "Change 4-8 Digit PIN" else "Set 4-8 Digit PIN") },
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.weight(1f),
                        singleLine = true
                    )
                    Button(onClick = { if (pinInput.length >= 4) { onSavePin(pinInput); pinInput = "" } }) {
                        Text("Save PIN")
                    }
                }
                Text(
                    "Intruder Selfie: captures front-camera photo to private encrypted storage after 3 failed PIN entries (requires Camera permission when enabled).",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        Text("Select Apps to Protect (${settings.lockedPackages.size} locked)", style = MaterialTheme.typography.titleMedium)
        installedApps.take(15).forEach { app ->
            val locked = app.packageName in settings.lockedPackages
            OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(app.appName, style = MaterialTheme.typography.titleSmall)
                        Text(app.packageName, style = MaterialTheme.typography.labelSmall)
                    }
                    Switch(checked = locked, onCheckedChange = { onToggleLockedApp(app.packageName) })
                }
            }
        }
    }
}

@Composable
private fun PrivacyAdvisorAndAccountsTab(
    privacyGroups: List<PrivacyPermissionGroup>,
    accountCheckups: List<AccountCheckupItem>,
    onRefreshAdvisor: () -> Unit
) {
    val context = LocalContext.current

    Column(
        modifier = Modifier.padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("Privacy Advisor (Sensitive Permissions)", style = MaterialTheme.typography.titleLarge)
            FilledTonalButton(onClick = onRefreshAdvisor) { Text("Refresh") }
        }
        Text(
            "Tip: Tap any app below to open Android App Info > Permissions and switch Camera, Mic, or Location to 'Ask every time' or 'Only while using the app'.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        privacyGroups.forEach { group ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("${group.permissionLabel} (${group.apps.size} user apps)", style = MaterialTheme.typography.titleSmall)
                    if (group.apps.isEmpty()) {
                        Text("No third-party apps request ${group.permissionLabel}.", style = MaterialTheme.typography.bodySmall)
                    } else {
                        group.apps.take(6).forEach { (pkg, name) ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(name, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                                OutlinedButton(onClick = {
                                    val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, "package:$pkg".toUri())
                                    runCatching { context.startActivity(intent) }
                                }) { Text("Review") }
                            }
                        }
                    }
                }
            }
        }

        Spacer(Modifier.height(4.dp))
        Text("Account Security Checkup Guides", style = MaterialTheme.typography.titleLarge)
        accountCheckups.forEach { acc ->
            OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Icon(Icons.Filled.VerifiedUser, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                        Column(modifier = Modifier.weight(1f)) {
                            Text(acc.provider, style = MaterialTheme.typography.titleSmall)
                            Text(acc.subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        FilledTonalButton(onClick = {
                            runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, acc.checkupUrl.toUri())) }
                        }) { Text("Open") }
                    }
                    acc.steps.forEach { step -> Text("• $step", style = MaterialTheme.typography.bodySmall) }
                }
            }
        }
    }
}
