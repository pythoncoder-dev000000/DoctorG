package com.python.doctorg.data.remote

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import okhttp3.ResponseBody
import retrofit2.Response
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.Path
import retrofit2.http.Url
import java.util.ArrayDeque
import javax.inject.Inject
import javax.inject.Singleton

@JsonClass(generateAdapter = true)
data class VirusTotalFileResponse(
    val data: VirusTotalFileData? = null
)

@JsonClass(generateAdapter = true)
data class VirusTotalFileData(
    val attributes: VirusTotalAttributes? = null
)

@JsonClass(generateAdapter = true)
data class VirusTotalAttributes(
    @Json(name = "last_analysis_stats") val lastAnalysisStats: VirusTotalAnalysisStats? = null
)

@JsonClass(generateAdapter = true)
data class VirusTotalAnalysisStats(
    val malicious: Int = 0,
    val suspicious: Int = 0,
    val harmless: Int = 0,
    val undetected: Int = 0
)

interface VirusTotalApi {
    @GET("api/v3/files/{hash}")
    suspend fun lookupFileHash(
        @Path("hash") sha256: String,
        @Header("x-apikey") apiKey: String
    ): Response<VirusTotalFileResponse>

    @GET("api/v3/urls/{urlId}")
    suspend fun lookupUrl(
        @Path("urlId") base64UrlId: String,
        @Header("x-apikey") apiKey: String
    ): Response<VirusTotalFileResponse>
}

interface HibpRangeApi {
    @GET("range/{prefix}")
    suspend fun queryPasswordHashPrefix(
        @Path("prefix") sha1Prefix5: String,
        @Header("Add-Padding") addPadding: String = "true"
    ): Response<ResponseBody>
}

interface StaticFeedApi {
    @GET
    suspend fun downloadText(@Url rawUrl: String): Response<ResponseBody>
}

/**
 * Enforces VirusTotal Free Tier limits strictly on-device:
 * max 4 requests/minute and 500 requests/day. Only SHA-256 hashes are ever transmitted.
 */
@Singleton
class VirusTotalRateLimiter @Inject constructor() {
    private val mutex = Mutex()
    private val minuteWindow = ArrayDeque<Long>()
    private var dayBucketStartMs: Long = System.currentTimeMillis()
    private var dayCount: Int = 0

    suspend fun tryAcquire(): Boolean = mutex.withLock {
        val now = System.currentTimeMillis()
        if (now - dayBucketStartMs >= 24L * 60L * 60L * 1000L) {
            dayBucketStartMs = now
            dayCount = 0
        }
        while (true) {
            val oldest = minuteWindow.peekFirst() ?: break
            if (now - oldest >= 60_000L) {
                minuteWindow.removeFirst()
            } else {
                break
            }
        }
        if (minuteWindow.size >= 4 || dayCount >= 500) {
            return false
        }
        minuteWindow.addLast(now)
        dayCount++
        true
    }

    suspend fun remainingToday(): Int = mutex.withLock { (500 - dayCount).coerceAtLeast(0) }
}
