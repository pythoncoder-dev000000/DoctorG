package com.python.doctorg.domain.engine

import android.annotation.SuppressLint
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.content.Context
import android.location.Location
import android.location.LocationManager
import android.media.AudioManager
import android.media.ToneGenerator
import android.os.Build
import android.os.Environment
import android.os.FileObserver
import android.speech.tts.TextToSpeech
import com.google.android.gms.location.LocationServices
import com.python.doctorg.core.adaptive.DeviceCapabilityChecker
import com.python.doctorg.core.notifications.DoctorGNotifications
import com.python.doctorg.core.permissions.PermissionManager
import com.python.doctorg.core.security.CryptoManager
import com.python.doctorg.data.local.DoctorGDatabase
import com.python.doctorg.data.local.entity.QuarantineItemEntity
import com.python.doctorg.data.local.entity.TrackerSightingEntity
import com.python.doctorg.data.local.vault.VaultItemEntity
import com.python.doctorg.data.remote.HibpRangeApi
import com.python.doctorg.domain.model.AccountCheckupItem
import com.python.doctorg.domain.model.PasswordHealthItem
import com.python.doctorg.domain.model.PasswordHealthReport
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.Locale
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Quarantine Vault: moves suspicious files into an AES-256-GCM encrypted isolated folder,
 * with canonical path-confinement validation on restore or permanent deletion.
 */
@Singleton
class QuarantineManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val cryptoManager: CryptoManager,
    private val database: DoctorGDatabase
) {
    private val quarantineDir: File
        get() = File(context.filesDir, "quarantine").apply { mkdirs() }

    suspend fun quarantineFile(sourceFile: File, threatName: String): Result<QuarantineItemEntity> =
        withContext(Dispatchers.IO) {
            runCatching {
                require(sourceFile.exists() && sourceFile.isFile) { "Target file not accessible" }
                require(sourceFile.length() <= 25L * 1024L * 1024L) { "File exceeds 25 MB quarantine limit — uninstall or delete directly" }
                val sha = cryptoManager.sha256File(sourceFile)
                val encryptedName = "q_${UUID.randomUUID()}.dgq"
                val dest = File(quarantineDir, encryptedName).canonicalFile
                require(dest.path.startsWith(quarantineDir.canonicalPath + File.separator)) { "Path boundary violation" }

                val rawBytes = sourceFile.readBytes()
                dest.writeBytes(cryptoManager.encryptBytes(rawBytes))
                sourceFile.delete()

                val entity = QuarantineItemEntity(
                    originalName = sourceFile.name,
                    originalPath = sourceFile.absolutePath,
                    encryptedFileName = encryptedName,
                    sha256 = sha,
                    threatName = threatName,
                    sizeBytes = rawBytes.size.toLong()
                )
                database.quarantineDao().insert(entity)
                entity
            }
        }

    suspend fun restoreItem(item: QuarantineItemEntity): Result<File> = withContext(Dispatchers.IO) {
        runCatching {
            val encFile = File(quarantineDir, item.encryptedFileName).canonicalFile
            require(encFile.path.startsWith(quarantineDir.canonicalPath + File.separator)) { "Invalid quarantine path" }
            val restoredDir = File(context.filesDir, "restored").apply { mkdirs() }
            val out = File(restoredDir, item.originalName.replace(Regex("[^A-Za-z0-9._-]"), "_")).canonicalFile
            require(out.path.startsWith(restoredDir.canonicalPath + File.separator)) { "Invalid restore path" }
            out.writeBytes(cryptoManager.decryptBytes(encFile.readBytes()))
            encFile.delete()
            database.quarantineDao().deleteById(item.id)
            out
        }
    }

    suspend fun deletePermanently(item: QuarantineItemEntity) = withContext(Dispatchers.IO) {
        val encFile = File(quarantineDir, item.encryptedFileName).canonicalFile
        if (encFile.path.startsWith(quarantineDir.canonicalPath + File.separator)) {
            encFile.delete()
        }
        database.quarantineDao().deleteById(item.id)
    }
}

/**
 * Ransomware Shield (FileObserver + hidden honeypot decoy) & Safe Download Watcher.
 */
@Singleton
class RansomwareHoneypotManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val notifications: DoctorGNotifications
) {
    private val observers = mutableListOf<FileObserver>()
    private var rapidEventCount = 0
    private var lastEventWindowMs = 0L

    fun startProtection() {
        stopProtection()
        val honeypotDir = File(context.filesDir, "honeypot_decoy").apply { mkdirs() }
        val decoyFile = File(honeypotDir, ".doctorg_decoy_vault_doc.pdf")
        if (!decoyFile.exists()) {
            decoyFile.writeText("DoctorG Ransomware Honeypot Decoy — Do not modify.")
        }

        val watchDirs = buildList {
            add(honeypotDir)
            val downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            if (downloads.exists() && downloads.canRead()) add(downloads)
        }

        watchDirs.forEach { dir ->
            val obs = createObserver(dir, isHoneypot = dir == honeypotDir)
            obs.startWatching()
            observers.add(obs)
        }
    }

    fun stopProtection() {
        observers.forEach { runCatching { it.stopWatching() } }
        observers.clear()
    }

    private fun createObserver(dir: File, isHoneypot: Boolean): FileObserver {
        val mask = FileObserver.MODIFY or FileObserver.MOVED_TO or FileObserver.CREATE or FileObserver.DELETE
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            object : FileObserver(dir, mask) {
                override fun onEvent(event: Int, path: String?) = handleFsEvent(dir, path, isHoneypot)
            }
        } else {
            @Suppress("DEPRECATION")
            object : FileObserver(dir.absolutePath, mask) {
                override fun onEvent(event: Int, path: String?) = handleFsEvent(dir, path, isHoneypot)
            }
        }
    }

    private fun handleFsEvent(dir: File, path: String?, isHoneypot: Boolean) {
        if (path.isNullOrBlank()) return
        if (isHoneypot && path.contains("doctorg_decoy")) {
            notifications.postThreatAlert(
                idOffset = 50,
                title = "Ransomware Honeypot Triggered!",
                message = "An unknown process attempted to access or modify DoctorG's protected decoy file ($path)."
            )
            return
        }
        val now = System.currentTimeMillis()
        if (now - lastEventWindowMs > 5_000L) {
            lastEventWindowMs = now
            rapidEventCount = 1
        } else {
            rapidEventCount++
            if (rapidEventCount >= 12) {
                notifications.postThreatAlert(
                    idOffset = 51,
                    title = "Mass File Modification Alert",
                    message = "Rapid file changes detected in ${dir.name} ($rapidEventCount events in 5s). Check for ransomware."
                )
                rapidEventCount = 0
            }
        }
        val lower = path.lowercase()
        if (lower.endsWith(".apk") || lower.endsWith(".dex") || Regex("""\.(pdf|jpg|doc)\.(apk|exe)$""").containsMatchIn(lower)) {
            notifications.postThreatAlert(
                idOffset = 52,
                title = "Safe Download Scanner",
                message = "New executable or APK detected in ${dir.name}: $path. Open DoctorG to scan before installing."
            )
        }
    }
}

/**
 * BLE Tracker Detector: scans for AirTag / Apple Find My (0x004C / 0x12), Tile (0xFEED),
 * and Samsung SmartTag (0xFD5A), logging persistent proximity duration.
 */
@Singleton
class BleTrackerDetector @Inject constructor(
    @ApplicationContext private val context: Context,
    private val database: DoctorGDatabase,
    private val permissionManager: PermissionManager,
    private val notifications: DoctorGNotifications
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var scanCallback: ScanCallback? = null

    @SuppressLint("MissingPermission")
    fun startScan(onStatus: (String) -> Unit) {
        if (!DeviceCapabilityChecker.inspect(context).hasBle) {
            onStatus("Bluetooth Low Energy hardware not present on this device.")
            return
        }
        if (!permissionManager.isBleScanGranted()) {
            onStatus("Needs Nearby Bluetooth Scan permission.")
            return
        }
        val bm = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val scanner = bm?.adapter?.bluetoothLeScanner
        if (scanner == null) {
            onStatus("Turn on Bluetooth to scan for nearby AirTag / Tile / SmartTag trackers.")
            return
        }
        stopScan()
        val cb = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                val record = result.scanRecord ?: return
                val appleData = record.getManufacturerSpecificData(0x004C)
                val isAirTag = appleData != null && appleData.isNotEmpty() && appleData[0] == 0x12.toByte()
                val uuids = record.serviceUuids?.map { it.uuid.toString().uppercase() }.orEmpty()
                val isTile = uuids.any { it.contains("FEED") }
                val isSmartTag = uuids.any { it.contains("FD5A") }

                val type = when {
                    isAirTag -> "Apple AirTag / Find My"
                    isTile -> "Tile Tracker"
                    isSmartTag -> "Samsung SmartTag"
                    else -> return
                }
                val mac = result.device?.address ?: "UNKNOWN"
                val now = System.currentTimeMillis()
                scope.launch {
                    val existing = database.trackerSightingDao().find(mac)
                    val updated = if (existing == null) {
                        TrackerSightingEntity(mac, type, now, now, result.rssi, 1)
                    } else {
                        existing.copy(
                            lastSeenMs = now,
                            rssi = result.rssi,
                            sightingsCount = existing.sightingsCount + 1
                        )
                    }
                    database.trackerSightingDao().upsert(updated)
                    val minutes = (updated.lastSeenMs - updated.firstSeenMs) / 60_000L
                    if (minutes >= 5) {
                        notifications.postThreatAlert(
                            idOffset = 60,
                            title = "Unknown Tracker Following You",
                            message = "$type ($mac) detected nearby for $minutes minutes. Open DoctorG for disable steps."
                        )
                    }
                }
            }
        }
        scanCallback = cb
        runCatching {
            scanner.startScan(cb)
            onStatus("Scanning nearby BLE beacons for AirTag, Tile & SmartTag...")
        }.onFailure {
            onStatus("BLE scan unavailable: ${it.message}")
        }
    }

    @SuppressLint("MissingPermission")
    fun stopScan() {
        val bm = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        scanCallback?.let { cb ->
            runCatching { bm?.adapter?.bluetoothLeScanner?.stopScan(cb) }
        }
        scanCallback = null
    }
}

/**
 * Safety Siren, TextToSpeech spoken alert, and Location lookup with automatic fallback
 * from FusedLocationProvider (when Play Services exists) to Android LocationManager (no Play Services needed).
 */
@Singleton
class SafetyLocationSirenEngine @Inject constructor(
    @ApplicationContext private val context: Context,
    private val permissionManager: PermissionManager
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var sirenJob: Job? = null
    private var tts: TextToSpeech? = null
    @Volatile
    private var ttsReady = false

    fun startSiren() {
        stopSiren()
        sirenJob = scope.launch {
            val tone = runCatching { ToneGenerator(AudioManager.STREAM_ALARM, 100) }.getOrNull()
            try {
                while (isActive) {
                    tone?.startTone(ToneGenerator.TONE_CDMA_EMERGENCY_RINGBACK, 700)
                    delay(850L)
                }
            } finally {
                tone?.release()
            }
        }
    }

    fun stopSiren() {
        sirenJob?.cancel()
        sirenJob = null
    }

    fun speakAlert(text: String) {
        if (tts == null) {
            tts = TextToSpeech(context) { status ->
                if (status == TextToSpeech.SUCCESS) {
                    ttsReady = true
                    tts?.language = Locale.getDefault()
                    runCatching { tts?.speak(text, TextToSpeech.QUEUE_FLUSH, null, "doctorg_alert") }
                }
            }
        } else if (ttsReady) {
            runCatching { tts?.speak(text, TextToSpeech.QUEUE_FLUSH, null, "doctorg_alert") }
        }
    }

    @SuppressLint("MissingPermission")
    fun fetchCurrentLocation(onResult: (String) -> Unit) {
        if (!permissionManager.isRuntimeGranted(android.Manifest.permission.ACCESS_FINE_LOCATION) &&
            !permissionManager.isRuntimeGranted(android.Manifest.permission.ACCESS_COARSE_LOCATION)
        ) {
            onResult("Location permission not granted. Allow Location to inspect coordinates.")
            return
        }
        val caps = DeviceCapabilityChecker.inspect(context)
        if (caps.hasPlayServices) {
            runCatching {
                LocationServices.getFusedLocationProviderClient(context).lastLocation
                    .addOnSuccessListener { loc ->
                        if (loc != null) onResult(formatLocation(loc, "FusedLocation"))
                        else fetchPlatformLocation(onResult)
                    }
                    .addOnFailureListener { fetchPlatformLocation(onResult) }
            }.onFailure { fetchPlatformLocation(onResult) }
        } else {
            fetchPlatformLocation(onResult)
        }
    }

    @SuppressLint("MissingPermission")
    private fun fetchPlatformLocation(onResult: (String) -> Unit) {
        val lm = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
        val loc = runCatching {
            lm?.getLastKnownLocation(LocationManager.GPS_PROVIDER)
                ?: lm?.getLastKnownLocation(LocationManager.NETWORK_PROVIDER)
        }.getOrNull()
        if (loc != null) {
            onResult(formatLocation(loc, "Android LocationManager (No Play Services needed)"))
        } else {
            onResult("Waiting for GPS/network fix (using platform LocationManager fallback).")
        }
    }

    private fun formatLocation(loc: Location, provider: String): String =
        "Lat %.5f, Lon %.5f (±%.0fm) via %s".format(loc.latitude, loc.longitude, loc.accuracy, provider)
}

/**
 * Vault Password Health Report using offline strength/reuse/age checks plus optional
 * Have I Been Pwned k-anonymity API (sends ONLY the first 5 characters of SHA-1).
 */
@Singleton
class PasswordHealthEngine @Inject constructor(
    private val cryptoManager: CryptoManager,
    private val hibpRangeApi: HibpRangeApi
) {
    suspend fun analyzePasswords(
        passwords: List<VaultItemEntity>,
        checkHibpOnline: Boolean
    ): PasswordHealthReport = withContext(Dispatchers.IO) {
        if (passwords.isEmpty()) {
            return@withContext PasswordHealthReport(
                overallScore = 100,
                totalPasswords = 0,
                weakCount = 0,
                reusedCount = 0,
                oldCount = 0,
                leakedCount = 0,
                items = emptyList(),
                suggestions = listOf("Add passwords to your SQLCipher Vault to generate a Password Health Report.")
            )
        }
        val now = System.currentTimeMillis()
        val ninetyDaysMs = 90L * 24L * 60L * 60L * 1000L
        val countsBySecret = passwords.groupingBy { it.secretContent }.eachCount()

        val items = passwords.map { item ->
            val strength = cryptoManager.evaluatePasswordStrength(item.secretContent)
            val isWeak = strength < 60
            val isReused = (countsBySecret[item.secretContent] ?: 0) > 1
            val isOld = (now - item.updatedAtMs) > ninetyDaysMs
            val breachCount = if (checkHibpOnline && item.secretContent.isNotBlank()) {
                queryHibpKAnonymity(item.secretContent)
            } else {
                null
            }
            PasswordHealthItem(item.id, item.title, strength, isWeak, isReused, isOld, breachCount)
        }

        val weakCount = items.count { it.isWeak }
        val reusedCount = items.count { it.isReused }
        val oldCount = items.count { it.isOld }
        val leakedCount = items.count { (it.hibpBreachCount ?: 0) > 0 }
        val score = (100 - weakCount * 15 - reusedCount * 15 - oldCount * 6 - leakedCount * 25).coerceIn(5, 100)

        val suggestions = buildList {
            if (leakedCount > 0) add("Change $leakedCount leaked password(s) found in public breach databases immediately.")
            if (reusedCount > 0) add("Replace $reusedCount reused password(s) with unique 18-character passwords.")
            if (weakCount > 0) add("Strengthen $weakCount weak password(s) using DoctorG's Password Generator.")
            if (oldCount > 0) add("Rotate $oldCount password(s) older than 90 days.")
            if (isEmpty()) add("All vault passwords look strong and unique!")
        }

        PasswordHealthReport(score, items.size, weakCount, reusedCount, oldCount, leakedCount, items, suggestions)
    }

    private suspend fun queryHibpKAnonymity(password: String): Int? = runCatching {
        val sha1 = cryptoManager.sha1HexUpper(password)
        val prefix = sha1.take(5)
        val suffix = sha1.drop(5)
        val resp = hibpRangeApi.queryPasswordHashPrefix(prefix)
        val body = if (resp.isSuccessful) resp.body()?.string().orEmpty() else return null
        val matchLine = body.lineSequence().firstOrNull { it.startsWith(suffix, ignoreCase = true) }
        matchLine?.substringAfter(":")?.trim()?.toIntOrNull() ?: 0
    }.getOrNull()

    fun getAccountSecurityCheckups(): List<AccountCheckupItem> = listOf(
        AccountCheckupItem(
            provider = "Google Account",
            subtitle = "Review devices, 2-Step Verification & third-party app access",
            checkupUrl = "https://myaccount.google.com/security-checkup",
            steps = listOf("Remove unrecognized devices.", "Enable Passkeys or DoctorG 2FA Authenticator.", "Audit connected third-party apps.")
        ),
        AccountCheckupItem(
            provider = "Meta / Instagram / WhatsApp",
            subtitle = "Check linked devices & WhatsApp Two-Step PIN",
            checkupUrl = "https://accountscenter.meta.com/password_and_security",
            steps = listOf("In WhatsApp > Linked Devices, log out unknown sessions.", "Enable 6-digit Two-Step Verification PIN.", "Turn on login alerts in Meta Accounts Center.")
        ),
        AccountCheckupItem(
            provider = "Microsoft Account",
            subtitle = "Sign-in activity & authenticator verification",
            checkupUrl = "https://account.live.com/Activity",
            steps = listOf("Review recent sign-in locations.", "Enable TOTP 2FA using DoctorG Authenticator.")
        ),
        AccountCheckupItem(
            provider = "Apple Account",
            subtitle = "Trusted devices & Recovery Key audit",
            checkupUrl = "https://appleid.apple.com",
            steps = listOf("Verify trusted devices list.", "Confirm Two-Factor Authentication is enabled.")
        ),
        AccountCheckupItem(
            provider = "Telegram",
            subtitle = "Active sessions & Cloud Password",
            checkupUrl = "https://telegram.org/faq#q-how-does-2-step-verification-work",
            steps = listOf("Open Telegram Settings > Devices and terminate unknown sessions.", "Enable Two-Step Verification password.")
        )
    )
}
