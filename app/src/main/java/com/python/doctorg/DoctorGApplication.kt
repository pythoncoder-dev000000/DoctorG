package com.python.doctorg

import android.app.Application
import androidx.hilt.work.HiltWorkerFactory
import androidx.work.Configuration
import com.python.doctorg.core.notifications.DoctorGNotifications
import com.python.doctorg.data.preferences.DoctorGPreferences
import com.python.doctorg.data.remote.FeedUpdateManager
import com.python.doctorg.worker.DoctorGWorkScheduler
import dagger.hilt.android.HiltAndroidApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltAndroidApp
class DoctorGApplication : Application(), Configuration.Provider {

    @Inject lateinit var workerFactory: HiltWorkerFactory
    @Inject lateinit var notifications: DoctorGNotifications
    @Inject lateinit var feedUpdateManager: FeedUpdateManager
    @Inject lateinit var preferences: DoctorGPreferences
    @Inject lateinit var workScheduler: DoctorGWorkScheduler

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder()
            .setWorkerFactory(workerFactory)
            .build()

    override fun onCreate() {
        super.onCreate()
        notifications.createChannels()
        appScope.launch {
            feedUpdateManager.seedBundledOfflineFeedsIfEmpty()
            val settings = preferences.settingsFlow.first()
            workScheduler.syncSchedules(settings)
        }
    }
}
