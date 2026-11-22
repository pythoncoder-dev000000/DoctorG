package com.python.doctorg.service

import android.app.Service
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.media.AudioManager
import android.os.Build
import android.os.IBinder
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.python.doctorg.core.notifications.DoctorGNotifications
import com.python.doctorg.core.permissions.PermissionManager
import com.python.doctorg.data.preferences.DoctorGPreferences
import com.python.doctorg.domain.engine.DeviceAuditEngine
import com.python.doctorg.domain.engine.RansomwareHoneypotManager
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Foreground protection service combining:
 * 1. App Lock foreground app detection (UsageStatsManager)
 * 2. UPI / Payment Fraud Guard (alerts when banking/UPI opens while remote-access, overlay, or call is active)
 * 3. Ransomware Honeypot & Safe Download real-time folder monitoring
 */
@AndroidEntryPoint
class AppLockMonitorService : Service() {

    @Inject lateinit var preferences: DoctorGPreferences
    @Inject lateinit var permissionManager: PermissionManager
    @Inject lateinit var deviceAuditEngine: DeviceAuditEngine
    @Inject lateinit var ransomwareHoneypotManager: RansomwareHoneypotManager
    @Inject lateinit var notifications: DoctorGNotifications

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var monitorJob: Job? = null
    private var lastAlertedPkg = ""
    private var lastAlertTimeMs = 0L

    companion object {
        const val ACTION_START = "com.python.doctorg.action.GUARD_START"
        const val ACTION_STOP = "com.python.doctorg.action.GUARD_STOP"

        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning.asStateFlow()

        fun start(context: Context) {
            val intent = Intent(context, AppLockMonitorService::class.java).setAction(ACTION_START)
            ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context) {
            if (!_isRunning.value) return
            runCatching { context.startService(Intent(context, AppLockMonitorService::class.java).setAction(ACTION_STOP)) }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            ransomwareHoneypotManager.stopProtection()
            monitorJob?.cancel()
            _isRunning.value = false
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        val fgsType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(
            this,
            DoctorGNotifications.ID_APPLOCK,
            notifications.buildAppLockNotification(0),
            fgsType
        )

        if (monitorJob?.isActive == true) return START_STICKY
        _isRunning.value = true
        ransomwareHoneypotManager.startProtection()

        monitorJob = scope.launch {
            val initial = preferences.settingsFlow.first()
            notifications.notifyOngoing(
                DoctorGNotifications.ID_APPLOCK,
                notifications.buildAppLockNotification(initial.lockedPackages.size)
            )
            while (isActive) {
                if (permissionManager.isUsageAccessGranted()) {
                    val fgPkg = queryForegroundPackage()
                    if (fgPkg != null && fgPkg != packageName) {
                        val settings = preferences.settingsFlow.first()
                        val now = System.currentTimeMillis()
                        if (fgPkg != lastAlertedPkg || now - lastAlertTimeMs > 20_000L) {
                            // UPI / Payment Fraud Guard
                            if (fgPkg in deviceAuditEngine.bankingAndUpiPackages) {
                                val remoteApps = deviceAuditEngine.getInstalledRemoteAccessApps()
                                val audioMgr = getSystemService(Context.AUDIO_SERVICE) as? AudioManager
                                val inCall = audioMgr?.mode == AudioManager.MODE_IN_CALL ||
                                    audioMgr?.mode == AudioManager.MODE_IN_COMMUNICATION
                                val activeA11y = deviceAuditEngine.getActiveAccessibilityServices()
                                if (remoteApps.isNotEmpty() || inCall || activeA11y.isNotEmpty()) {
                                    val reasons = buildList {
                                        if (inCall) add("phone/VoIP call active")
                                        if (remoteApps.isNotEmpty()) add("remote-access app installed (${remoteApps.first()})")
                                        if (activeA11y.isNotEmpty()) add("${activeA11y.size} accessibility service(s) active")
                                    }.joinToString(", ")
                                    notifications.postThreatAlert(
                                        idOffset = 30,
                                        title = "UPI / Payment Fraud Warning",
                                        message = "Banking/UPI app opened while $reasons. Never enter your UPI PIN while on a call or screen-sharing!"
                                    )
                                    lastAlertedPkg = fgPkg
                                    lastAlertTimeMs = now
                                }
                            } else if (settings.appLockEnabled && fgPkg in settings.lockedPackages) {
                                notifications.postThreatAlert(
                                    idOffset = 31,
                                    title = "App Lock Triggered",
                                    message = "Protected app ($fgPkg) accessed. Verify with DoctorG PIN or Biometrics."
                                )
                                lastAlertedPkg = fgPkg
                                lastAlertTimeMs = now
                            }
                        }
                    }
                }
                delay(2_000L)
            }
        }
        return START_STICKY
    }

    private fun queryForegroundPackage(): String? {
        val usm = getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager ?: return null
        val end = System.currentTimeMillis()
        val events = usm.queryEvents(end - 6_000L, end)
        val event = UsageEvents.Event()
        var lastPkg: String? = null
        while (events.hasNextEvent()) {
            events.getNextEvent(event)
            if (event.eventType == UsageEvents.Event.ACTIVITY_RESUMED) {
                lastPkg = event.packageName
            }
        }
        return lastPkg
    }

    override fun onDestroy() {
        _isRunning.value = false
        ransomwareHoneypotManager.stopProtection()
        scope.cancel()
        super.onDestroy()
    }
}
