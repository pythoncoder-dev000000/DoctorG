package com.python.doctorg.data.local

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.python.doctorg.data.local.dao.AppBaselineDao
import com.python.doctorg.data.local.dao.ExcludedAppDao
import com.python.doctorg.data.local.dao.FirewallDao
import com.python.doctorg.data.local.dao.MalwareHashDao
import com.python.doctorg.data.local.dao.QuarantineDao
import com.python.doctorg.data.local.dao.ScanHistoryDao
import com.python.doctorg.data.local.dao.SpamNumberDao
import com.python.doctorg.data.local.dao.TrackerSightingDao
import com.python.doctorg.data.local.dao.VirusTotalCacheDao
import com.python.doctorg.data.local.dao.WebProtectionDao
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

@Database(
    entities = [
        MalwareHashEntity::class,
        VirusTotalCacheEntity::class,
        ScanHistoryEntity::class,
        AppBaselineEntity::class,
        ExcludedAppEntity::class,
        BlockedDomainEntity::class,
        BlockedEventEntity::class,
        FirewallRuleEntity::class,
        QuarantineItemEntity::class,
        SpamNumberEntity::class,
        TrackerSightingEntity::class
    ],
    version = 2,
    exportSchema = false
)
abstract class DoctorGDatabase : RoomDatabase() {
    abstract fun malwareHashDao(): MalwareHashDao
    abstract fun virusTotalCacheDao(): VirusTotalCacheDao
    abstract fun scanHistoryDao(): ScanHistoryDao
    abstract fun appBaselineDao(): AppBaselineDao
    abstract fun excludedAppDao(): ExcludedAppDao
    abstract fun webProtectionDao(): WebProtectionDao
    abstract fun firewallDao(): FirewallDao
    abstract fun quarantineDao(): QuarantineDao
    abstract fun spamNumberDao(): SpamNumberDao
    abstract fun trackerSightingDao(): TrackerSightingDao

    companion object {
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE scan_history ADD COLUMN scoringVersion INTEGER NOT NULL DEFAULT 1")
                db.execSQL("DELETE FROM scan_history WHERE scoringVersion < 2")
            }
        }
    }
}
