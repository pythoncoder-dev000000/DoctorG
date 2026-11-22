package com.python.doctorg.worker

import android.content.Context
import androidx.hilt.work.HiltWorker
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.python.doctorg.core.notifications.DoctorGNotifications
import com.python.doctorg.data.preferences.DoctorGSettings
import com.python.doctorg.data.remote.FeedUpdateManager
import com.python.doctorg.domain.engine.MalwareScanEngine
import com.python.doctorg.domain.engine.NetworkToolsEngine
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

@HiltWorker
class SignatureUpdateWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val feedUpdateManager: FeedUpdateManager
) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result {
        feedUpdateManager.refreshFromStaticGitHubFeeds(forceIgnoreWifi = false)
        return Result.success()
    }
}

@HiltWorker
class ScheduledQuickScanWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val scanEngine: MalwareScanEngine,
    private val notifications: DoctorGNotifications
) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result {
        val result = scanEngine.runQuickScan(onProgress = {})
        if (result.maliciousCount > 0 || result.suspiciousCount > 0) {
            notifications.postThreatAlert(
                idOffset = 80,
                title = "Scheduled Quick Scan Found Risks",
                message = "${result.maliciousCount} malicious, ${result.suspiciousCount} suspicious items need review."
            )
        }
        return Result.success()
    }
}

@HiltWorker
class ScheduledFullScanWorker @AssistedInject constructor(
    @Assisted appContext: Context,
    @Assisted params: WorkerParameters,
    private val scanEngine: MalwareScanEngine,
    private val networkToolsEngine: NetworkToolsEngine,
    private val notifications: DoctorGNotifications
) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result {
        val wifi = runCatching { networkToolsEngine.auditCurrentWifi().ssid }.getOrDefault("Wi-Fi")
        val result = scanEngine.runFullScan(
            wifiSummary = wifi,
            onProgress = {},
            isPaused = { false },
            isCancelled = { isStopped }
        )
        notifications.postThreatAlert(
            idOffset = 81,
            title = "Weekly Full Scan Score: ${result.securityScore}/100",
            message = "Checked ${result.findings.size} items • ${result.maliciousCount} malicious, ${result.suspiciousCount} suspicious."
        )
        return Result.success()
    }
}

@Singleton
class DoctorGWorkScheduler @Inject constructor(
    private val workManager: WorkManager
) {
    fun syncSchedules(settings: DoctorGSettings) {
        val feedConstraints = Constraints.Builder()
            .setRequiredNetworkType(if (settings.wifiOnlyUpdates) NetworkType.UNMETERED else NetworkType.CONNECTED)
            .setRequiresBatteryNotLow(true)
            .build()
        val feedReq = PeriodicWorkRequestBuilder<SignatureUpdateWorker>(1, TimeUnit.DAYS)
            .setConstraints(feedConstraints)
            .build()
        workManager.enqueueUniquePeriodicWork("doctorg_daily_feeds", ExistingPeriodicWorkPolicy.UPDATE, feedReq)

        if (settings.dailyQuickScanEnabled) {
            val quickConstraints = Constraints.Builder().setRequiresBatteryNotLow(true).build()
            val quickReq = PeriodicWorkRequestBuilder<ScheduledQuickScanWorker>(1, TimeUnit.DAYS)
                .setConstraints(quickConstraints)
                .build()
            workManager.enqueueUniquePeriodicWork("doctorg_daily_quick_scan", ExistingPeriodicWorkPolicy.UPDATE, quickReq)
        } else {
            workManager.cancelUniqueWork("doctorg_daily_quick_scan")
        }

        if (settings.weeklyFullScanEnabled) {
            val fullConstraints = Constraints.Builder()
                .setRequiresCharging(true)
                .setRequiredNetworkType(NetworkType.UNMETERED)
                .build()
            val fullReq = PeriodicWorkRequestBuilder<ScheduledFullScanWorker>(7, TimeUnit.DAYS)
                .setConstraints(fullConstraints)
                .build()
            workManager.enqueueUniquePeriodicWork("doctorg_weekly_full_scan", ExistingPeriodicWorkPolicy.UPDATE, fullReq)
        } else {
            workManager.cancelUniqueWork("doctorg_weekly_full_scan")
        }
    }
}
