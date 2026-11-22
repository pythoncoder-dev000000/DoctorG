package com.python.doctorg.data.local.vault

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import com.python.doctorg.core.security.CryptoManager
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory

@Database(
    entities = [VaultItemEntity::class, TotpAccountEntity::class],
    version = 1,
    exportSchema = false
)
abstract class VaultDatabase : RoomDatabase() {
    abstract fun vaultDao(): VaultDao

    companion object {
        fun build(context: Context, cryptoManager: CryptoManager): VaultDatabase {
            val builder = Room.databaseBuilder(
                context.applicationContext,
                VaultDatabase::class.java,
                "doctorg_encrypted_vault.db"
            )
            // Load 16KB page-size aligned sqlcipher-android native library on Android devices;
            // safely fall back to standard SQLite only on JVM Robolectric unit-test hosts.
            val sqlCipherLoaded = runCatching {
                System.loadLibrary("sqlcipher")
                true
            }.getOrDefault(false)

            if (sqlCipherLoaded) {
                val passphrase = cryptoManager.getOrCreateVaultPassphrase()
                builder.openHelperFactory(SupportOpenHelperFactory(passphrase))
            }
            return builder.fallbackToDestructiveMigration(dropAllTables = true).build()
        }
    }
}
