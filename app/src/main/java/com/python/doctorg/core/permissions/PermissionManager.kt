package com.python.doctorg.core.permissions

import android.Manifest
import android.app.AlarmManager
import android.app.AppOpsManager
import android.app.NotificationManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Environment
import android.os.PowerManager
import android.os.Process
import android.provider.Settings
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import com.python.doctorg.receiver.DoctorGDeviceAdminReceiver
import com.python.doctorg.service.PhishingNotificationListenerService
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

enum class DoctorGPermissionId {
    NOTIFICATIONS,
    ALL_FILES_ACCESS,
    USAGE_ACCESS,
    DISPLAY_OVER_APPS,
    VPN_CONSENT,
    NOTIFICATION_LISTENER,
    BATTERY_OPTIMIZATION,
    CAMERA,
    BLUETOOTH_SCAN,
    LOCATION,
    SMS_READ,
    PHONE_STATE,
    DEVICE_ADMIN,
    DND_ACCESS,
    INSTALL_UNKNOWN_APPS,
    EXACT_ALARMS,
    ACCESSIBILITY_INFO
}

enum class PermissionKind { RUNTIME, SPECIAL }

data class PermissionItemStatus(
    val id: DoctorGPermissionId,
    val title: String,
    val dependentFeatures: String,
    val whyNeeded: String,
    val privacyGuarantee: String,
    val kind: PermissionKind,
    val runtimePermission: String? = null,
    val isGranted: Boolean,
    val isSupportedOnThisAndroid: Boolean = true,
    val unsupportedReason: String? = null,
    val needsRestrictedSettingsGuide: Boolean = false
)

@Singleton
class PermissionManager @Inject constructor(
    @ApplicationContext private val context: Context
) {
    fun getAllStatuses(): List<PermissionItemStatus> = listOf(
        PermissionItemStatus(
            id = DoctorGPermissionId.NOTIFICATIONS,
            title = "Notifications",
            dependentFeatures = "Full Scan progress, real-time install alerts, phishing & tracker warnings",
            whyNeeded = "Displays live Full Scan progress and alerts you immediately if a threat is found.",
            privacyGuarantee = "All alerts are generated locally on-device.",
            kind = PermissionKind.RUNTIME,
            runtimePermission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) Manifest.permission.POST_NOTIFICATIONS else null,
            isGranted = isNotificationsGranted()
        ),
        PermissionItemStatus(
            id = DoctorGPermissionId.ALL_FILES_ACCESS,
            title = "All-Files Storage Access",
            dependentFeatures = "Full Scan APK/DEX/ZIP storage sweep, USB/SD scanner, Ransomware Shield, Safe Downloads",
            whyNeeded = "Required on Android 11+ to scan Downloads, WhatsApp, Telegram, and SD/OTG folders for malicious APKs.",
            privacyGuarantee = "Files are hashed and inspected locally using streaming 8KB reads. Zero files ever leave your device.",
            kind = PermissionKind.SPECIAL,
            isGranted = isAllFilesGranted(),
            isSupportedOnThisAndroid = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R,
            unsupportedReason = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) "Not needed separately on Android 8–10" else null
        ),
        PermissionItemStatus(
            id = DoctorGPermissionId.USAGE_ACCESS,
            title = "Usage Access",
            dependentFeatures = "App Lock foreground guard, UPI / Payment Fraud Guard, Data Usage Monitor",
            whyNeeded = "Detects which app is currently on screen so DoctorG can lock private apps or warn during UPI sessions.",
            privacyGuarantee = "Foreground app events stay in RAM and are never recorded or transmitted.",
            kind = PermissionKind.SPECIAL,
            isGranted = isUsageAccessGranted()
        ),
        PermissionItemStatus(
            id = DoctorGPermissionId.DISPLAY_OVER_APPS,
            title = "Display Over Other Apps",
            dependentFeatures = "App Lock screen, Scam Call caller-ID banner, UPI fraud warning overlay",
            whyNeeded = "Allows DoctorG to show lock screens and urgent payment-scam warnings over active apps.",
            privacyGuarantee = "Overlay draws only when you enable App Lock or receive a high-risk call.",
            kind = PermissionKind.SPECIAL,
            isGranted = Settings.canDrawOverlays(context)
        ),
        PermissionItemStatus(
            id = DoctorGPermissionId.VPN_CONSENT,
            title = "Local VPN Protection",
            dependentFeatures = "Web Protection DNS filter, Ad/Tracker blocker, Per-App Firewall",
            whyNeeded = "Creates a loopback VPN on your phone to block phishing and malware domains locally.",
            privacyGuarantee = "No external VPN server is used; traffic never leaves your device through DoctorG.",
            kind = PermissionKind.SPECIAL,
            isGranted = VpnService.prepare(context) == null
        ),
        PermissionItemStatus(
            id = DoctorGPermissionId.NOTIFICATION_LISTENER,
            title = "Notification Access",
            dependentFeatures = "Phishing link detection in WhatsApp, Telegram & SMS notifications",
            whyNeeded = "Inspects URLs inside incoming message notifications against the local phishing blocklist.",
            privacyGuarantee = "Only URL patterns are checked in memory; message text is never saved or uploaded.",
            kind = PermissionKind.SPECIAL,
            isGranted = isNotificationListenerGranted(),
            needsRestrictedSettingsGuide = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
        ),
        PermissionItemStatus(
            id = DoctorGPermissionId.BATTERY_OPTIMIZATION,
            title = "Unrestricted Battery",
            dependentFeatures = "Continuous Web Protection VPN, App Lock, scheduled weekly Full Scans",
            whyNeeded = "Prevents aggressive OEM battery managers from killing DoctorG's background shield.",
            privacyGuarantee = "DoctorG uses battery-aware scheduling and idle-friendly listeners.",
            kind = PermissionKind.SPECIAL,
            isGranted = isBatteryOptimizationIgnored()
        ),
        PermissionItemStatus(
            id = DoctorGPermissionId.CAMERA,
            title = "Camera",
            dependentFeatures = "Safe QR Code Scanner, 2FA QR import, App Lock Intruder Selfie",
            whyNeeded = "Scans QR codes safely before opening links and captures intruder photos after 3 failed PIN attempts.",
            privacyGuarantee = "Camera frames are processed locally via ML Kit; intruder photos stay in private encrypted storage.",
            kind = PermissionKind.RUNTIME,
            runtimePermission = Manifest.permission.CAMERA,
            isGranted = isRuntimeGranted(Manifest.permission.CAMERA)
        ),
        PermissionItemStatus(
            id = DoctorGPermissionId.BLUETOOTH_SCAN,
            title = "Nearby Bluetooth Scan",
            dependentFeatures = "BLE Tracker Detector (AirTag, Tile, Samsung SmartTag)",
            whyNeeded = "Detects unknown Bluetooth beacons travelling with you over time.",
            privacyGuarantee = "Marked neverForLocation on Android 12+; sighting logs stay strictly on-device.",
            kind = PermissionKind.RUNTIME,
            runtimePermission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) Manifest.permission.BLUETOOTH_SCAN else Manifest.permission.ACCESS_FINE_LOCATION,
            isGranted = isBleScanGranted()
        ),
        PermissionItemStatus(
            id = DoctorGPermissionId.LOCATION,
            title = "Location",
            dependentFeatures = "Wi-Fi SSID/Evil-Twin audit, BLE scan (Android 8–11), Safety Location tool",
            whyNeeded = "Android requires Location permission to read the connected Wi-Fi SSID and scan nearby BLE beacons on Android 8–11.",
            privacyGuarantee = "Coordinates are never tracked or shared externally.",
            kind = PermissionKind.RUNTIME,
            runtimePermission = Manifest.permission.ACCESS_FINE_LOCATION,
            isGranted = isRuntimeGranted(Manifest.permission.ACCESS_FINE_LOCATION)
        ),
        PermissionItemStatus(
            id = DoctorGPermissionId.SMS_READ,
            title = "SMS Inspection (Optional)",
            dependentFeatures = "On-device Scam SMS Classifier & Phishing SMS link guard",
            whyNeeded = "Allows DoctorG to classify suspicious KYC/OTP/courier texts offline.",
            privacyGuarantee = "You can also paste any SMS manually into Scam Shield without granting SMS permission.",
            kind = PermissionKind.RUNTIME,
            runtimePermission = Manifest.permission.READ_SMS,
            isGranted = isRuntimeGranted(Manifest.permission.READ_SMS)
        ),
        PermissionItemStatus(
            id = DoctorGPermissionId.PHONE_STATE,
            title = "Phone Call State",
            dependentFeatures = "UPI / Payment Fraud Guard during active unknown calls",
            whyNeeded = "Detects whether a phone call is in progress when you open a banking or UPI app.",
            privacyGuarantee = "Calls are never recorded; only active call state is checked.",
            kind = PermissionKind.RUNTIME,
            runtimePermission = Manifest.permission.READ_PHONE_STATE,
            isGranted = isRuntimeGranted(Manifest.permission.READ_PHONE_STATE)
        ),
        PermissionItemStatus(
            id = DoctorGPermissionId.DEVICE_ADMIN,
            title = "Device Admin (Optional)",
            dependentFeatures = "Work Profile Sandbox & anti-tamper lock",
            whyNeeded = "Enables isolated Work Profile sandboxing and tamper-lock capabilities.",
            privacyGuarantee = "Can be revoked at any time from Settings > Device Admin Apps.",
            kind = PermissionKind.SPECIAL,
            isGranted = isDeviceAdminActive()
        ),
        PermissionItemStatus(
            id = DoctorGPermissionId.DND_ACCESS,
            title = "Do Not Disturb Access",
            dependentFeatures = "Emergency Tabletop Siren override",
            whyNeeded = "Lets the manual Safety Siren sound at full volume even when the phone is muted.",
            privacyGuarantee = "Only triggered when you explicitly tap the Safety Siren button.",
            kind = PermissionKind.SPECIAL,
            isGranted = isDndAccessGranted()
        ),
        PermissionItemStatus(
            id = DoctorGPermissionId.INSTALL_UNKNOWN_APPS,
            title = "Install Unknown Apps Handoff",
            dependentFeatures = "APK Pre-install Scanner handoff to Android package installer",
            whyNeeded = "Allows DoctorG to hand off a verified safe APK to the Android installer after scanning.",
            privacyGuarantee = "DoctorG never silently installs apps; the Android system installer always asks for your confirmation.",
            kind = PermissionKind.SPECIAL,
            isGranted = context.packageManager.canRequestPackageInstalls()
        ),
        PermissionItemStatus(
            id = DoctorGPermissionId.EXACT_ALARMS,
            title = "Exact Alarms",
            dependentFeatures = "Precise scheduled Quick & Full Scans",
            whyNeeded = "Ensures scheduled nightly security checks run reliably on Android 12+.",
            privacyGuarantee = "Used solely for your configured scan schedules.",
            kind = PermissionKind.SPECIAL,
            isGranted = isExactAlarmGranted(),
            isSupportedOnThisAndroid = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
        ),
        PermissionItemStatus(
            id = DoctorGPermissionId.ACCESSIBILITY_INFO,
            title = "Accessibility Settings Inspection",
            dependentFeatures = "Review & disable abusive third-party Accessibility Services",
            whyNeeded = "Opens system Accessibility settings so you can disable suspicious services detected by DoctorG.",
            privacyGuarantee = "DoctorG itself does NOT require an Accessibility Service to run.",
            kind = PermissionKind.SPECIAL,
            isGranted = true,
            needsRestrictedSettingsGuide = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
        )
    )

    fun isRuntimeGranted(permission: String): Boolean =
        ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED

    fun isNotificationsGranted(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            isRuntimeGranted(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            true
        }

    fun isAllFilesGranted(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            true
        }

    fun isUsageAccessGranted(): Boolean {
        val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager ?: return false
        @Suppress("DEPRECATION")
        val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            appOps.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName)
        } else {
            appOps.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName)
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }

    fun isNotificationListenerGranted(): Boolean {
        val flat = Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners").orEmpty()
        val cn = ComponentName(context, PhishingNotificationListenerService::class.java).flattenToString()
        return flat.contains(cn) || flat.contains(context.packageName)
    }

    fun isBatteryOptimizationIgnored(): Boolean {
        val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager ?: return false
        return pm.isIgnoringBatteryOptimizations(context.packageName)
    }

    fun isBleScanGranted(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            isRuntimeGranted(Manifest.permission.BLUETOOTH_SCAN)
        } else {
            isRuntimeGranted(Manifest.permission.ACCESS_FINE_LOCATION)
        }

    fun isDeviceAdminActive(): Boolean {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager ?: return false
        return dpm.isAdminActive(ComponentName(context, DoctorGDeviceAdminReceiver::class.java))
    }

    fun isDndAccessGranted(): Boolean {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return false
        return nm.isNotificationPolicyAccessGranted
    }

    fun isExactAlarmGranted(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return true
        val am = context.getSystemService(Context.ALARM_SERVICE) as? AlarmManager ?: return false
        return am.canScheduleExactAlarms()
    }

    fun buildSpecialSettingsIntent(id: DoctorGPermissionId): Intent {
        val pkgUri = "package:${context.packageName}".toUri()
        return when (id) {
            DoctorGPermissionId.ALL_FILES_ACCESS -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, pkgUri)
            } else {
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, pkgUri)
            }
            DoctorGPermissionId.USAGE_ACCESS -> Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)
            DoctorGPermissionId.DISPLAY_OVER_APPS -> Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, pkgUri)
            DoctorGPermissionId.VPN_CONSENT -> VpnService.prepare(context) ?: Intent(Settings.ACTION_VPN_SETTINGS)
            DoctorGPermissionId.NOTIFICATION_LISTENER -> Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
            DoctorGPermissionId.BATTERY_OPTIMIZATION -> Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
            DoctorGPermissionId.DEVICE_ADMIN -> Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
                putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, ComponentName(context, DoctorGDeviceAdminReceiver::class.java))
                putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, "Optional: enables DoctorG anti-tamper lock and Work Profile Sandbox.")
            }
            DoctorGPermissionId.DND_ACCESS -> Intent(Settings.ACTION_NOTIFICATION_POLICY_ACCESS_SETTINGS)
            DoctorGPermissionId.INSTALL_UNKNOWN_APPS -> Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, pkgUri)
            DoctorGPermissionId.EXACT_ALARMS -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                Intent(Settings.ACTION_REQUEST_SCHEDULE_EXACT_ALARM, pkgUri)
            } else {
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, pkgUri)
            }
            DoctorGPermissionId.ACCESSIBILITY_INFO -> Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
            else -> Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, pkgUri)
        }
    }

    fun buildAppDetailsSettingsIntent(): Intent =
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, "package:${context.packageName}".toUri())
}
