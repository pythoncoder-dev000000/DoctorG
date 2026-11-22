package com.python.doctorg.data.local.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "malware_hashes")
data class MalwareHashEntity(
    @PrimaryKey val sha256: String,
    val family: String,
    val severity: String,
    val description: String,
    val source: String = "bundled",
    val updatedAtMs: Long = System.currentTimeMillis()
)

@Entity(tableName = "virustotal_cache")
data class VirusTotalCacheEntity(
    @PrimaryKey val sha256: String,
    val maliciousCount: Int,
    val suspiciousCount: Int,
    val harmlessCount: Int,
    val queriedAtMs: Long
)

@Entity(tableName = "scan_history")
data class ScanHistoryEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val mode: String, // QUICK or FULL
    val timestampMs: Long,
    val durationMs: Long,
    val securityScore: Int,
    val scannedItems: Int,
    val safeCount: Int,
    val suspiciousCount: Int,
    val maliciousCount: Int,
    val skippedStagesCsv: String,
    val summaryNotes: String,
    val scoringVersion: Int = 2
)

@Entity(tableName = "app_baselines")
data class AppBaselineEntity(
    @PrimaryKey val packageName: String,
    val appName: String,
    val versionCode: Long,
    val certSha256: String,
    val permissionsCsv: String,
    val lastCheckedMs: Long
)

@Entity(tableName = "excluded_apps")
data class ExcludedAppEntity(
    @PrimaryKey val packageName: String,
    val appName: String,
    val addedAtMs: Long = System.currentTimeMillis()
)

@Entity(tableName = "blocked_domains")
data class BlockedDomainEntity(
    @PrimaryKey val domain: String,
    val category: String, // MALWARE, PHISHING, TRACKER, ALLOWLIST
    val isAllowedOverride: Boolean = false
)

@Entity(tableName = "blocked_events")
data class BlockedEventEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val domainOrUrl: String,
    val source: String, // VPN_DNS, SAFE_BROWSER, SMS_LINK, NOTIFICATION_LINK
    val reason: String,
    val timestampMs: Long = System.currentTimeMillis()
)

@Entity(tableName = "firewall_rules")
data class FirewallRuleEntity(
    @PrimaryKey val packageName: String,
    val appName: String,
    val blockWifi: Boolean = false,
    val blockMobile: Boolean = false
)

@Entity(tableName = "quarantine_items")
data class QuarantineItemEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val originalName: String,
    val originalPath: String,
    val encryptedFileName: String,
    val sha256: String,
    val threatName: String,
    val sizeBytes: Long,
    val quarantinedAtMs: Long = System.currentTimeMillis()
)

@Entity(tableName = "spam_numbers")
data class SpamNumberEntity(
    @PrimaryKey val phoneNumber: String,
    val category: String,
    val risk: String,
    val reports: Int,
    val isUserReported: Boolean = false
)

@Entity(tableName = "tracker_sightings")
data class TrackerSightingEntity(
    @PrimaryKey val macAddress: String,
    val trackerType: String, // AirTag / FindMy, Tile, Samsung SmartTag, Unknown BLE
    val firstSeenMs: Long,
    val lastSeenMs: Long,
    val rssi: Int,
    val sightingsCount: Int
)
