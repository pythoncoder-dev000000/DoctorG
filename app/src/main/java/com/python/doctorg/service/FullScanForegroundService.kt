package com.python.doctorg.service

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.python.doctorg.core.notifications.DoctorGNotifications
import com.python.doctorg.domain.engine.MalwareScanEngine
import com.python.doctorg.domain.engine.NetworkToolsEngine
import com.python.doctorg.domain.model.ScanLifecycleState
import com.python.doctorg.domain.model.ScanMode
import com.python.doctorg.domain.model.ScanProgressState
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ScanCoordinator @Inject constructor() {
    private val _state = MutableStateFlow(ScanProgressState())
    val state: StateFlow<ScanProgressState> = _state.asStateFlow()

    @Volatile
    var paused: Boolean = false

    @Volatile
    var cancelled: Boolean = false

    fun update(newState: ScanProgressState) {
        _state.value = newState
    }

    fun requestPause() {
        paused = true
        _state.value = _state.value.copy(lifecycle = ScanLifecycleState.PAUSED)
    }

    fun requestResume() {
        paused = false
        if (_state.value.lifecycle == ScanLifecycleState.PAUSED) {
            _state.value = _state.value.copy(lifecycle = ScanLifecycleState.RUNNING)
        }
    }

    fun requestCancel() {
        cancelled = true
        paused = false
    }

    fun resetFlags() {
        paused = false
        cancelled = false
    }
}

@AndroidEntryPoint
class FullScanForegroundService : Service() {

    @Inject lateinit var scanEngine: MalwareScanEngine
    @Inject lateinit var networkToolsEngine: NetworkToolsEngine
    @Inject lateinit var notifications: DoctorGNotifications
    @Inject lateinit var coordinator: ScanCoordinator

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var scanJob: Job? = null

    companion object {
        const val ACTION_START = "com.python.doctorg.action.FULL_SCAN_START"
        const val ACTION_PAUSE = "com.python.doctorg.action.FULL_SCAN_PAUSE"
        const val ACTION_RESUME = "com.python.doctorg.action.FULL_SCAN_RESUME"
        const val ACTION_CANCEL = "com.python.doctorg.action.FULL_SCAN_CANCEL"

        fun start(context: Context) {
            val intent = Intent(context, FullScanForegroundService::class.java).setAction(ACTION_START)
            ContextCompat.startForegroundService(context, intent)
        }

        fun sendControl(context: Context, action: String) {
            val intent = Intent(context, FullScanForegroundService::class.java).setAction(action)
            runCatching { context.startService(intent) }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_PAUSE -> {
                coordinator.requestPause()
                notifications.notifyOngoing(
                    DoctorGNotifications.ID_FULL_SCAN,
                    notifications.buildFullScanNotification(coordinator.state.value.stageName, coordinator.state.value.percent, paused = true)
                )
            }
            ACTION_RESUME -> {
                coordinator.requestResume()
                notifications.notifyOngoing(
                    DoctorGNotifications.ID_FULL_SCAN,
                    notifications.buildFullScanNotification(coordinator.state.value.stageName, coordinator.state.value.percent, paused = false)
                )
            }
            ACTION_CANCEL -> {
                coordinator.requestCancel()
                scanJob?.cancel()
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            else -> {
                if (scanJob?.isActive == true) return START_STICKY
                coordinator.resetFlags()
                val fgsType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
                } else {
                    0
                }
                ServiceCompat.startForeground(
                    this,
                    DoctorGNotifications.ID_FULL_SCAN,
                    notifications.buildFullScanNotification("Initializing DoctorG Full Scan...", 2, paused = false),
                    fgsType
                )
                scanJob = scope.launch {
                    val wifiAudit = runCatching { networkToolsEngine.auditCurrentWifi() }.getOrNull()
                    val wifiSummary = wifiAudit?.let { "${it.ssid} (${it.securityType})" } ?: "Unavailable"
                    val finalState = scanEngine.runFullScan(
                        wifiSummary = wifiSummary,
                        onProgress = { progress ->
                            coordinator.update(progress)
                            val n = notifications.buildFullScanNotification(
                                progress.stageName,
                                progress.percent,
                                paused = progress.lifecycle == ScanLifecycleState.PAUSED
                            )
                            notifications.notifyOngoing(DoctorGNotifications.ID_FULL_SCAN, n)
                        },
                        isPaused = { coordinator.paused },
                        isCancelled = { coordinator.cancelled }
                    )
                    coordinator.update(finalState)
                    if (finalState.lifecycle == ScanLifecycleState.COMPLETED) {
                        notifications.postThreatAlert(
                            idOffset = 1,
                            title = "Full Scan Complete (Score ${finalState.securityScore}/100)",
                            message = "Scanned ${finalState.findings.size} items • ${finalState.maliciousCount} malicious, ${finalState.suspiciousCount} suspicious."
                        )
                    }
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
