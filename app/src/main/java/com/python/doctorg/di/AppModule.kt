package com.python.doctorg.di

import android.content.Context
import androidx.room.Room
import androidx.work.WorkManager
import com.python.doctorg.core.security.CryptoManager
import com.python.doctorg.data.local.DoctorGDatabase
import com.python.doctorg.data.local.vault.VaultDatabase
import com.python.doctorg.data.remote.HibpRangeApi
import com.python.doctorg.data.remote.StaticFeedApi
import com.python.doctorg.data.remote.VirusTotalApi
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import okhttp3.OkHttpClient
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import java.util.concurrent.TimeUnit
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideDoctorGDatabase(@ApplicationContext context: Context): DoctorGDatabase =
        Room.databaseBuilder(context, DoctorGDatabase::class.java, "doctorg_security.db")
            .addMigrations(DoctorGDatabase.MIGRATION_1_2)
            .fallbackToDestructiveMigration(dropAllTables = true)
            .build()

    @Provides
    @Singleton
    fun provideVaultDatabase(
        @ApplicationContext context: Context,
        cryptoManager: CryptoManager
    ): VaultDatabase = VaultDatabase.build(context, cryptoManager)

    @Provides
    @Singleton
    fun provideOkHttpClient(): OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .writeTimeout(15, TimeUnit.SECONDS)
        .build()

    @Provides
    @Singleton
    fun provideMoshi(): Moshi = Moshi.Builder()
        .addLast(KotlinJsonAdapterFactory())
        .build()

    @Provides
    @Singleton
    fun provideVirusTotalApi(okHttp: OkHttpClient, moshi: Moshi): VirusTotalApi =
        Retrofit.Builder()
            .baseUrl("https://www.virustotal.com/")
            .client(okHttp)
            .addConverterFactory(MoshiConverterFactory.create(moshi))
            .build()
            .create(VirusTotalApi::class.java)

    @Provides
    @Singleton
    fun provideHibpRangeApi(okHttp: OkHttpClient): HibpRangeApi =
        Retrofit.Builder()
            .baseUrl("https://api.pwnedpasswords.com/")
            .client(okHttp)
            .build()
            .create(HibpRangeApi::class.java)

    @Provides
    @Singleton
    fun provideStaticFeedApi(okHttp: OkHttpClient): StaticFeedApi =
        Retrofit.Builder()
            .baseUrl("https://raw.githubusercontent.com/")
            .client(okHttp)
            .build()
            .create(StaticFeedApi::class.java)

    @Provides
    @Singleton
    fun provideWorkManager(@ApplicationContext context: Context): WorkManager =
        WorkManager.getInstance(context)
}
