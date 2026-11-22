package com.python.doctorg.core.notifications

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.python.doctorg.MainActivity
import com.python.doctorg.R
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class DoctorGNotifications @Inject constructor(
    @ApplicationContext private val context: Context
) {
    companion object {
        const val CHANNEL_SCAN = "doctorg_scan_channel"
        const val CHANNEL_ALERTS = "doctorg_alerts_channel"
        const val CHANNEL_VPN = "doctorg_vpn_channel"
        const val CHANNEL_APPLOCK = "doctorg_applock_channel"

        const val ID_FULL_SCAN = 1001
        const val ID_VPN = 1002
        const val ID_APPLOCK = 1003
        const val ID_THREAT_BASE = 2000
    }

    fun createChannels() {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channels = listOf(
            NotificationChannel(
                CHANNEL_SCAN,
                context.getString(R.string.notif_channel_scan),
                NotificationManager.IMPORTANCE_LOW
            ),
            NotificationChannel(
                CHANNEL_ALERTS,
                context.getString(R.string.notif_channel_alerts),
                NotificationManager.IMPORTANCE_HIGH
            ),
            NotificationChannel(
                CHANNEL_VPN,
                context.getString(R.string.notif_channel_vpn),
                NotificationManager.IMPORTANCE_LOW
            ),
            NotificationChannel(
                CHANNEL_APPLOCK,
                context.getString(R.string.notif_channel_applock),
                NotificationManager.IMPORTANCE_LOW
            )
        )
        nm.createNotificationChannels(channels)
    }

    private fun mainPendingIntent(): PendingIntent {
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        return PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    fun buildFullScanNotification(
        stage: String,
        percent: Int,
        paused: Boolean
    ): Notification {
        val title = if (paused) "DoctorG Full Scan Paused" else context.getString(R.string.notif_full_scan_title)
        return NotificationCompat.Builder(context, CHANNEL_SCAN)
            .setSmallIcon(R.drawable.ic_launcher_monochrome)
            .setContentTitle(title)
            .setContentText("$stage ($percent%)")
            .setProgress(100, percent.coerceIn(0, 100), false)
            .setOngoing(!paused)
            .setContentIntent(mainPendingIntent())
            .build()
    }

    fun buildVpnNotification(blockedCount: Int, dnsLabel: String): Notification {
        return NotificationCompat.Builder(context, CHANNEL_VPN)
            .setSmallIcon(R.drawable.ic_launcher_monochrome)
            .setContentTitle(context.getString(R.string.notif_vpn_title))
            .setContentText("DNS: $dnsLabel • Blocked $blockedCount threats locally")
            .setOngoing(true)
            .setContentIntent(mainPendingIntent())
            .build()
    }

    fun buildAppLockNotification(protectedCount: Int): Notification {
        val text = if (protectedCount > 0) {
            "Guarding $protectedCount locked apps, UPI fraud & downloads"
        } else {
            context.getString(R.string.notif_applock_body)
        }
        return NotificationCompat.Builder(context, CHANNEL_APPLOCK)
            .setSmallIcon(R.drawable.ic_launcher_monochrome)
            .setContentTitle(context.getString(R.string.notif_applock_title))
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(mainPendingIntent())
            .build()
    }

    fun notifyOngoing(notificationId: Int, notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        runCatching {
            NotificationManagerCompat.from(context).notify(notificationId, notification)
        }
    }

    fun postThreatAlert(idOffset: Int, title: String, message: String) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        val notification = NotificationCompat.Builder(context, CHANNEL_ALERTS)
            .setSmallIcon(R.drawable.ic_launcher_monochrome)
            .setContentTitle("DoctorG: $title")
            .setContentText(message)
            .setStyle(NotificationCompat.BigTextStyle().bigText(message))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(mainPendingIntent())
            .build()
        runCatching {
            NotificationManagerCompat.from(context).notify(ID_THREAT_BASE + idOffset, notification)
        }
    }
}
