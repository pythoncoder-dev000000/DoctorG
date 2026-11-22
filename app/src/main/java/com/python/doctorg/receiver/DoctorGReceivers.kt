package com.python.doctorg.receiver

import android.app.admin.DeviceAdminReceiver
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Environment
import android.os.UserManager
import com.python.doctorg.core.notifications.DoctorGNotifications
import com.python.doctorg.data.preferences.DoctorGPreferences
import com.python.doctorg.domain.engine.MalwareScanEngine
import com.python.doctorg.domain.model.ThreatLevel
import com.python.doctorg.service.AppLockMonitorService
import com.python.doctorg.service.DoctorGVpnService
import com.python.doctorg.worker.DoctorGWorkScheduler
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import java.io.File
import javax.inject.Inject

@AndroidEntryPoint
class BootCompletedReceiver : BroadcastReceiver() {
    @Inject lateinit var preferences: DoctorGPreferences
    @Inject lateinit var workScheduler: DoctorGWorkScheduler

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED && action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        val userManager = context.getSystemService(Context.USER_SERVICE) as? UserManager
        if (userManager != null && !userManager.isUserUnlocked) return

        val pending = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val settings = preferences.settingsFlow.first()
                workScheduler.syncSchedules(settings)
                if (settings.vpnAutoStart && VpnService.prepare(context) == null) {
                    runCatching { DoctorGVpnService.start(context) }
                }
                if (settings.appLockEnabled) {
                    runCatching { AppLockMonitorService.start(context) }
                }
            } finally {
                pending.finish()
            }
        }
    }
}

@AndroidEntryPoint
class PackageInstallReceiver : BroadcastReceiver() {
    @Inject lateinit var preferences: DoctorGPreferences
    @Inject lateinit var scanEngine: MalwareScanEngine
    @Inject lateinit var notifications: DoctorGNotifications

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_PACKAGE_ADDED && action != Intent.ACTION_PACKAGE_REPLACED) return
        if (action == Intent.ACTION_PACKAGE_ADDED && intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) {
            return // Avoid duplicate scan; ACTION_PACKAGE_REPLACED will fire next
        }
        val pkg = intent.data?.schemeSpecificPart ?: return
        if (pkg == context.packageName) return
        val pending = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val settings = preferences.settingsFlow.first()
                if (!settings.realTimeInstallScanEnabled) return@launch
                val finding = scanEngine.scanInstalledPackage(pkg) ?: return@launch
                if (finding.threatLevel == ThreatLevel.MALICIOUS || finding.threatLevel == ThreatLevel.SUSPICIOUS) {
                    notifications.postThreatAlert(
                        idOffset = pkg.hashCode() and 0xFF,
                        title = "Real-Time Install Alert: ${finding.threatLevel}",
                        message = "Newly installed/updated package $pkg flagged (Risk ${finding.riskScore}/100): ${finding.reasons.firstOrNull().orEmpty()}"
                    )
                }
            } finally {
                pending.finish()
            }
        }
    }
}

@AndroidEntryPoint
class UsbStorageReceiver : BroadcastReceiver() {
    @Inject lateinit var scanEngine: MalwareScanEngine
    @Inject lateinit var notifications: DoctorGNotifications

    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            "android.hardware.usb.action.USB_STATE" -> {
                val connected = intent.getBooleanExtra("connected", false)
                val mtpOrPtp = intent.getBooleanExtra("mtp", false) ||
                    intent.getBooleanExtra("ptp", false) ||
                    intent.getBooleanExtra("adb", false)
                if (connected && mtpOrPtp) {
                    notifications.postThreatAlert(
                        idOffset = 70,
                        title = "Juice-Jacking Protection Alert",
                        message = "USB data transfer mode is active while connected! If using a public charger, switch USB mode to 'Charge Only'."
                    )
                }
            }
            Intent.ACTION_MEDIA_MOUNTED, "android.hardware.usb.action.USB_DEVICE_ATTACHED" -> {
                val mountPath = intent.data?.path ?: Environment.getExternalStorageDirectory().absolutePath
                val pending = goAsync()
                CoroutineScope(Dispatchers.IO).launch {
                    try {
                        val root = File(mountPath).canonicalFile
                        val privateDataPath = context.filesDir.parentFile?.canonicalPath.orEmpty()
                        if (privateDataPath.isNotBlank() && root.path.startsWith(privateDataPath)) return@launch
                        if (root.exists() && root.canRead()) {
                            val suspicious = root.walkTopDown().maxDepth(2)
                                .filter { it.isFile && (it.name.endsWith(".apk", true) || it.name.equals("autorun.inf", true)) }
                                .take(10)
                                .toList()
                                .map { scanEngine.scanSingleFile(it) }
                                .filter { it.threatLevel == ThreatLevel.MALICIOUS || it.threatLevel == ThreatLevel.SUSPICIOUS }
                            if (suspicious.isNotEmpty()) {
                                notifications.postThreatAlert(
                                    idOffset = 71,
                                    title = "USB / SD Card Threat Found",
                                    message = "DoctorG found ${suspicious.size} suspicious file(s) on mounted storage (${suspicious.first().name})."
                                )
                            }
                        }
                    } finally {
                        pending.finish()
                    }
                }
            }
        }
    }
}

class DoctorGDeviceAdminReceiver : DeviceAdminReceiver() {
    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
    }

    override fun onDisabled(context: Context, intent: Intent) {
        super.onDisabled(context, intent)
    }
}
