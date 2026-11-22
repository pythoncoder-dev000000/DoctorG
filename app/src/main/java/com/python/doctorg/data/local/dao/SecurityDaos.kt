package com.python.doctorg.data.local.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.python.doctorg.data.local.entity.AppBaselineEntity
import com.python.doctorg.data.local.entity.BlockedDomainEntity
import com.python.doctorg.data.local.entity.BlockedEventEntity
import com.python.doctorg.data.local.entity.ExcludedAppEntity
import com.python.doctorg.data.local.entity.FirewallRuleEntity
import com.python.doctorg.data.local.entity.MalwareHashEntity
import com.python.doctorg.data.local.entity.QuarantineItemEntity
import com.python.doctorg.data.local.entity.ScanHistoryEntity
import com.python.doctorg.data.local.entity.SpamNumberEntity
import com.python.doctorg.data.local.entity.TrackerSightingEntity
import com.python.doctorg.data.local.entity.VirusTotalCacheEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface MalwareHashDao {
    @Query("SELECT * FROM malware_hashes WHERE sha256 = :sha256 LIMIT 1")
    suspend fun findByHash(sha256: String): MalwareHashEntity?

    @Query("SELECT COUNT(*) FROM malware_hashes")
    fun observeCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM malware_hashes")
    suspend fun count(): Int

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(items: List<MalwareHashEntity>)
}

@Dao
interface VirusTotalCacheDao {
    @Query("SELECT * FROM virustotal_cache WHERE sha256 = :sha256 LIMIT 1")
    suspend fun get(sha256: String): VirusTotalCacheEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun put(item: VirusTotalCacheEntity)
}

@Dao
interface ScanHistoryDao {
    @Query("SELECT * FROM scan_history ORDER BY timestampMs DESC LIMIT 50")
    fun observeHistory(): Flow<List<ScanHistoryEntity>>

    @Query("SELECT * FROM scan_history ORDER BY timestampMs DESC LIMIT 1")
    fun observeLatest(): Flow<ScanHistoryEntity?>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entry: ScanHistoryEntity): Long

    @Query("DELETE FROM scan_history WHERE scoringVersion < :minVersion")
    suspend fun deleteOlderScoringVersions(minVersion: Int)
}

@Dao
interface AppBaselineDao {
    @Query("SELECT * FROM app_baselines")
    fun observeAll(): Flow<List<AppBaselineEntity>>

    @Query("SELECT * FROM app_baselines WHERE packageName = :pkg LIMIT 1")
    suspend fun get(pkg: String): AppBaselineEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(item: AppBaselineEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(items: List<AppBaselineEntity>)
}

@Dao
interface ExcludedAppDao {
    @Query("SELECT * FROM excluded_apps ORDER BY appName ASC")
    fun observeAll(): Flow<List<ExcludedAppEntity>>

    @Query("SELECT packageName FROM excluded_apps")
    suspend fun getAllPackages(): List<String>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun add(item: ExcludedAppEntity)

    @Query("DELETE FROM excluded_apps WHERE packageName = :pkg")
    suspend fun remove(pkg: String)
}

@Dao
interface WebProtectionDao {
    @Query("SELECT * FROM blocked_domains WHERE domain = :domain LIMIT 1")
    suspend fun findDomain(domain: String): BlockedDomainEntity?

    @Query("SELECT * FROM blocked_domains WHERE isAllowedOverride = 1 ORDER BY domain ASC")
    fun observeAllowlist(): Flow<List<BlockedDomainEntity>>

    @Query("SELECT COUNT(*) FROM blocked_domains WHERE isAllowedOverride = 0")
    fun observeBlocklistCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM blocked_domains")
    suspend fun totalCount(): Int

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertDomains(items: List<BlockedDomainEntity>)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertDomain(item: BlockedDomainEntity)

    @Query("DELETE FROM blocked_domains WHERE domain = :domain")
    suspend fun deleteDomain(domain: String)

    @Query("SELECT * FROM blocked_events ORDER BY timestampMs DESC LIMIT 100")
    fun observeBlockedEvents(): Flow<List<BlockedEventEntity>>

    @Query("SELECT COUNT(*) FROM blocked_events")
    fun observeBlockedEventCount(): Flow<Int>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun logBlockedEvent(event: BlockedEventEntity)

    @Query("DELETE FROM blocked_events")
    suspend fun clearEvents()
}

@Dao
interface FirewallDao {
    @Query("SELECT * FROM firewall_rules ORDER BY appName ASC")
    fun observeRules(): Flow<List<FirewallRuleEntity>>

    @Query("SELECT * FROM firewall_rules WHERE blockWifi = 1 OR blockMobile = 1")
    suspend fun getActiveBlockedRules(): List<FirewallRuleEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(rule: FirewallRuleEntity)
}

@Dao
interface QuarantineDao {
    @Query("SELECT * FROM quarantine_items ORDER BY quarantinedAtMs DESC")
    fun observeItems(): Flow<List<QuarantineItemEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(item: QuarantineItemEntity)

    @Query("DELETE FROM quarantine_items WHERE id = :id")
    suspend fun deleteById(id: Long)
}

@Dao
interface SpamNumberDao {
    @Query("SELECT * FROM spam_numbers ORDER BY reports DESC")
    fun observeAll(): Flow<List<SpamNumberEntity>>

    @Query("SELECT * FROM spam_numbers WHERE phoneNumber = :number LIMIT 1")
    suspend fun find(number: String): SpamNumberEntity?

    @Query("SELECT COUNT(*) FROM spam_numbers")
    suspend fun count(): Int

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(items: List<SpamNumberEntity>)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(item: SpamNumberEntity)
}

@Dao
interface TrackerSightingDao {
    @Query("SELECT * FROM tracker_sightings ORDER BY lastSeenMs DESC")
    fun observeAll(): Flow<List<TrackerSightingEntity>>

    @Query("SELECT * FROM tracker_sightings WHERE macAddress = :mac LIMIT 1")
    suspend fun find(mac: String): TrackerSightingEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(item: TrackerSightingEntity)

    @Query("DELETE FROM tracker_sightings")
    suspend fun clearAll()
}
