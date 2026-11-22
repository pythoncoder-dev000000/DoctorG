package com.python.doctorg.data.local.vault

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "vault_items")
data class VaultItemEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val type: String, // PASSWORD, NOTE, FILE
    val title: String,
    val usernameOrMeta: String = "",
    val secretContent: String = "", // password or note body (encrypted at rest by SQLCipher + Keystore)
    val websiteOrPath: String = "",
    val createdAtMs: Long = System.currentTimeMillis(),
    val updatedAtMs: Long = System.currentTimeMillis()
)

@Entity(tableName = "totp_accounts")
data class TotpAccountEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val issuer: String,
    val accountName: String,
    val secretBase32: String,
    val periodSeconds: Int = 30,
    val digits: Int = 6,
    val createdAtMs: Long = System.currentTimeMillis()
)

@Dao
interface VaultDao {
    @Query("SELECT * FROM vault_items ORDER BY updatedAtMs DESC")
    fun observeVaultItems(): Flow<List<VaultItemEntity>>

    @Query("SELECT * FROM vault_items WHERE type = 'PASSWORD' ORDER BY updatedAtMs DESC")
    suspend fun getAllPasswords(): List<VaultItemEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertVaultItem(item: VaultItemEntity): Long

    @Query("DELETE FROM vault_items WHERE id = :id")
    suspend fun deleteVaultItem(id: Long)

    @Query("SELECT * FROM totp_accounts ORDER BY issuer ASC, accountName ASC")
    fun observeTotpAccounts(): Flow<List<TotpAccountEntity>>

    @Query("SELECT * FROM totp_accounts")
    suspend fun getAllTotpAccounts(): List<TotpAccountEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertTotpAccount(account: TotpAccountEntity): Long

    @Query("DELETE FROM totp_accounts WHERE id = :id")
    suspend fun deleteTotpAccount(id: Long)
}
