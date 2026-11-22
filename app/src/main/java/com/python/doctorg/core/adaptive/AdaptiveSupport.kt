package com.python.doctorg.core.adaptive

import android.app.Activity
import android.app.ActivityManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.telephony.TelephonyManager
import androidx.biometric.BiometricManager
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.State
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.window.layout.FoldingFeature
import androidx.window.layout.WindowInfoTracker
import kotlinx.coroutines.flow.collectLatest

sealed interface FoldPosture {
    data object Flat : FoldPosture
    data class Book(val hingeBoundsWidthPx: Int) : FoldPosture
    data class Tabletop(val hingeBoundsHeightPx: Int) : FoldPosture
}

@Composable
fun rememberFoldPosture(activity: Activity?): State<FoldPosture> {
    val posture = remember { mutableStateOf<FoldPosture>(FoldPosture.Flat) }
    LaunchedEffect(activity) {
        if (activity == null) return@LaunchedEffect
        runCatching {
            WindowInfoTracker.getOrCreate(activity)
                .windowLayoutInfo(activity)
                .collectLatest { layoutInfo ->
                    val foldingFeature = layoutInfo.displayFeatures
                        .filterIsInstance<FoldingFeature>()
                        .firstOrNull()
                    posture.value = when {
                        foldingFeature == null -> FoldPosture.Flat
                        foldingFeature.state == FoldingFeature.State.HALF_OPENED &&
                            foldingFeature.orientation == FoldingFeature.Orientation.HORIZONTAL ->
                            FoldPosture.Tabletop(foldingFeature.bounds.height())
                        foldingFeature.isSeparating &&
                            foldingFeature.orientation == FoldingFeature.Orientation.VERTICAL ->
                            FoldPosture.Book(foldingFeature.bounds.width())
                        else -> FoldPosture.Flat
                    }
                }
        }
    }
    return posture
}

data class DeviceCapabilities(
    val hasCamera: Boolean,
    val hasBle: Boolean,
    val hasTelephonyAndSim: Boolean,
    val hasBiometric: Boolean,
    val hasUsbHost: Boolean,
    val hasPlayServices: Boolean,
    val isLowRamDevice: Boolean,
    val isChromeOs: Boolean,
    val sdkInt: Int
)

object DeviceCapabilityChecker {
    fun inspect(context: Context): DeviceCapabilities {
        val pm = context.packageManager
        val hasCamera = pm.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)
        val hasBle = pm.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE)
        val hasTelephonyFeature = pm.hasSystemFeature(PackageManager.FEATURE_TELEPHONY)
        val telephony = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
        val hasSim = hasTelephonyFeature && telephony?.simState == TelephonyManager.SIM_STATE_READY
        val hasBiometric = BiometricManager.from(context).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.BIOMETRIC_WEAK
        ) == BiometricManager.BIOMETRIC_SUCCESS
        val hasUsbHost = pm.hasSystemFeature(PackageManager.FEATURE_USB_HOST)
        val hasPlayServices = runCatching {
            pm.getPackageInfo("com.google.android.gms", 0)
            true
        }.getOrDefault(false)
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
        val isLowRam = am?.isLowRamDevice == true
        val isChromeOs = pm.hasSystemFeature("org.chromium.arc") ||
            pm.hasSystemFeature("org.chromium.arc.device_management")

        return DeviceCapabilities(
            hasCamera = hasCamera,
            hasBle = hasBle,
            hasTelephonyAndSim = hasSim,
            hasBiometric = hasBiometric,
            hasUsbHost = hasUsbHost,
            hasPlayServices = hasPlayServices,
            isLowRamDevice = isLowRam,
            isChromeOs = isChromeOs,
            sdkInt = Build.VERSION.SDK_INT
        )
    }
}

data class OemGuidance(
    val manufacturerName: String,
    val steps: List<String>,
    val primaryIntents: List<Intent>
)

object OemPowerHelper {
    fun getGuidanceForCurrentDevice(context: Context): OemGuidance {
        val brand = Build.MANUFACTURER.lowercase()
        val fallbackBattery = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
        val appDetails = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.fromParts("package", context.packageName, null)
        }

        return when {
            brand.contains("xiaomi") || brand.contains("redmi") || brand.contains("poco") -> OemGuidance(
                manufacturerName = "Xiaomi / MIUI / HyperOS",
                steps = listOf(
                    "Open Security > Permissions > Autostart and enable DoctorG.",
                    "Go to App Info > Battery Saver and choose 'No restrictions'.",
                    "In Recent Apps, long-press DoctorG and tap the Lock icon so HyperOS keeps real-time protection running."
                ),
                primaryIntents = listOf(
                    Intent().setComponent(ComponentName("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity")),
                    fallbackBattery,
                    appDetails
                )
            )
            brand.contains("oppo") || brand.contains("realme") || brand.contains("oneplus") -> OemGuidance(
                manufacturerName = "Oppo / ColorOS / Realme / OnePlus",
                steps = listOf(
                    "Open Settings > Apps > App Management > DoctorG > Battery Usage.",
                    "Enable 'Allow foreground activity', 'Allow background activity', and 'Allow auto-launch'.",
                    "Disable 'Pause app activity if unused'."
                ),
                primaryIntents = listOf(
                    Intent().setComponent(ComponentName("com.coloros.safecenter", "com.coloros.safecenter.permission.startup.StartupAppListActivity")),
                    Intent().setComponent(ComponentName("com.oplus.battery", "com.oplus.powermanager.fuelgaue.PowerUsageModelActivity")),
                    fallbackBattery,
                    appDetails
                )
            )
            brand.contains("vivo") || brand.contains("iqoo") -> OemGuidance(
                manufacturerName = "Vivo / iQOO (Funtouch / OriginOS)",
                steps = listOf(
                    "Open iManager > App Manager > Autostart Manager and enable DoctorG.",
                    "Go to Settings > Battery > Background power consumption management > DoctorG > High background power usage."
                ),
                primaryIntents = listOf(
                    Intent().setComponent(ComponentName("com.iqoo.secure", "com.iqoo.secure.ui.phoneoptimize.AddWhiteListActivity")),
                    Intent().setComponent(ComponentName("com.vivo.permissionmanager", "com.vivo.permissionmanager.activity.BgStartUpManagerActivity")),
                    fallbackBattery,
                    appDetails
                )
            )
            brand.contains("samsung") -> OemGuidance(
                manufacturerName = "Samsung (One UI)",
                steps = listOf(
                    "Open Settings > Battery > Background usage limits > Never auto sleeping apps > add DoctorG.",
                    "In App Info > Battery, set DoctorG to 'Unrestricted'."
                ),
                primaryIntents = listOf(
                    Intent().setComponent(ComponentName("com.samsung.android.lool", "com.samsung.android.sm.battery.ui.BatteryActivity")),
                    fallbackBattery,
                    appDetails
                )
            )
            brand.contains("huawei") || brand.contains("honor") -> OemGuidance(
                manufacturerName = "Huawei / Honor (EMUI / MagicOS)",
                steps = listOf(
                    "Open Settings > Battery > App launch > find DoctorG.",
                    "Switch off 'Manage automatically' and enable Auto-launch, Secondary launch, and Run in background."
                ),
                primaryIntents = listOf(
                    Intent().setComponent(ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity")),
                    fallbackBattery,
                    appDetails
                )
            )
            else -> OemGuidance(
                manufacturerName = Build.MANUFACTURER.ifBlank { "Android Device" },
                steps = listOf(
                    "Open Battery Optimization settings and set DoctorG to 'Unrestricted' or 'Don't optimize'.",
                    "Keep notifications enabled so DoctorG can show Full Scan progress and real-time threat alerts."
                ),
                primaryIntents = listOf(fallbackBattery, appDetails)
            )
        }
    }

    fun launchBestSettingsIntent(context: Context): Boolean {
        val guidance = getGuidanceForCurrentDevice(context)
        for (intent in guidance.primaryIntents) {
            val resolved = intent.resolveActivity(context.packageManager)
            if (resolved != null) {
                runCatching {
                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    context.startActivity(intent)
                    return true
                }
            }
        }
        return false
    }
}
