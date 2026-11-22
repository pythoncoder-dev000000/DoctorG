package com.python.doctorg.domain.engine

import android.content.Context
import com.python.doctorg.data.remote.FeedUpdateManager
import com.python.doctorg.domain.model.LocalizedGuideContent
import com.python.doctorg.domain.model.ScamAwarenessCard
import com.python.doctorg.domain.model.ScamSmsResult
import com.python.doctorg.domain.model.ThreatLevel
import dagger.hilt.android.qualifiers.ApplicationContext
import org.json.JSONObject
import org.tensorflow.lite.Interpreter
import java.io.File
import java.io.FileInputStream
import java.nio.channels.FileChannel
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.math.exp

data class ScamPatternRule(
    val id: String,
    val label: String,
    val weight: Int,
    val regex: Regex
)

/**
 * India-focused 100% on-device Scam SMS Classifier supporting English, Hindi, and Hinglish.
 * Uses LiteRT (scam_sms_classifier.tflite) when bundled, fused with GitHub-updatable regex rules.
 */
@Singleton
class ScamSmsClassifier @Inject constructor(
    @ApplicationContext private val context: Context,
    private val feedUpdateManager: FeedUpdateManager
) {
    private var interpreter: Interpreter? = null
    private var attemptedLoad = false
    private val urlRegex = Regex("""https?://[^\s]+|www\.[^\s]+""", RegexOption.IGNORE_CASE)

    fun loadPatterns(): List<ScamPatternRule> {
        val raw = feedUpdateManager.readLatestOrBundledAsset("scam_patterns.json")
        if (raw.isBlank()) return emptyList()
        return runCatching {
            val arr = JSONObject(raw).optJSONArray("rules") ?: return@runCatching emptyList()
            buildList {
                for (i in 0 until arr.length()) {
                    val o = arr.getJSONObject(i)
                    add(
                        ScamPatternRule(
                            id = o.optString("id"),
                            label = o.optString("label"),
                            weight = o.optInt("weight", 25),
                            regex = Regex(o.optString("pattern"))
                        )
                    )
                }
            }
        }.getOrDefault(emptyList())
    }

    fun loadAwarenessCards(): List<ScamAwarenessCard> {
        val raw = feedUpdateManager.readLatestOrBundledAsset("scam_awareness.json")
        return parseAwarenessCardsJson(raw)
    }

    fun classifySms(message: String, lightweightMode: Boolean = false): ScamSmsResult {
        val patterns = loadPatterns()
        val matchedReasons = mutableListOf<String>()
        var ruleScore = 0
        for (rule in patterns) {
            if (rule.regex.containsMatchIn(message)) {
                ruleScore += rule.weight
                matchedReasons.add(rule.label)
            }
        }
        val urls = urlRegex.findAll(message).map { it.value }.toList()
        val features = extractFeatures(message, urls)
        val mlProb = predictWithModelOrFallback(features, lightweightMode)
        val blendedScore = maxOf(ruleScore, (mlProb * 100).toInt()).coerceIn(0, 100)

        val verdict = when {
            blendedScore >= 60 -> ThreatLevel.MALICIOUS
            blendedScore >= 30 -> ThreatLevel.SUSPICIOUS
            else -> ThreatLevel.SAFE
        }

        return ScamSmsResult(
            inputText = message,
            riskScore = blendedScore,
            verdict = verdict,
            mlProbability = mlProb,
            matchedReasons = matchedReasons.ifEmpty {
                if (verdict == ThreatLevel.SAFE) listOf("No Indian scam patterns detected") else listOf("Elevated scam text pattern probability")
            },
            extractedUrls = urls
        )
    }

    private fun extractFeatures(text: String, urls: List<String>): FloatArray {
        val lower = text.lowercase()
        return floatArrayOf(
            if (lower.contains("kyc") || lower.contains("pan") || lower.contains("khata")) 1f else 0f,
            if (lower.contains("share otp") || lower.contains("otp bataye") || lower.contains("upi pin")) 1f else 0f,
            if (lower.contains("urgent") || lower.contains("blocked") || lower.contains("tonight") || lower.contains("turant")) 1f else 0f,
            if (lower.contains("digital arrest") || lower.contains("cbi") || lower.contains("trai") || lower.contains("warrant")) 1f else 0f,
            if (lower.contains("parcel") || lower.contains("courier") || lower.contains("customs") || lower.contains("india post")) 1f else 0f,
            if (lower.contains("lottery") || lower.contains("kbc") || lower.contains("jeete") || lower.contains("won rs")) 1f else 0f,
            if (lower.contains("work from home") || lower.contains("telegram") || lower.contains("daily income")) 1f else 0f,
            if (lower.contains("electricity") || lower.contains("bijli")) 1f else 0f,
            if (urls.isNotEmpty()) 1f else 0f,
            if (urls.any { it.contains("bit.ly") || it.contains(".xyz") || it.contains(".top") || it.contains(".click") }) 1f else 0f,
            if (Regex("""(\+91|0)?[6-9]\d{9}""").containsMatchIn(lower)) 1f else 0f,
            if (Regex("""(rs\.?|inr|₹)\s*\d+""").containsMatchIn(lower)) 1f else 0f
        )
    }

    private fun predictWithModelOrFallback(features: FloatArray, lightweightMode: Boolean): Float {
        if (!lightweightMode) {
            if (!attemptedLoad) {
                attemptedLoad = true
                interpreter = runCatching {
                    val file = File(context.filesDir, "feeds/scam_sms_classifier.tflite")
                    val buf = if (file.exists()) {
                        FileInputStream(file).use { it.channel.map(FileChannel.MapMode.READ_ONLY, 0, file.length()) }
                    } else {
                        context.assets.openFd("scam_sms_classifier.tflite").use { afd ->
                            FileInputStream(afd.fileDescriptor).use { it.channel.map(FileChannel.MapMode.READ_ONLY, afd.startOffset, afd.declaredLength) }
                        }
                    }
                    Interpreter(buf)
                }.getOrNull()
            }
            interpreter?.let { tflite ->
                val p = runCatching {
                    val out = Array(1) { FloatArray(1) }
                    tflite.run(arrayOf(features), out)
                    out[0][0].coerceIn(0f, 1f)
                }.getOrNull()
                if (p != null) return p
            }
        }
        val w = floatArrayOf(1.5f, 2.0f, 0.9f, 2.1f, 1.4f, 1.4f, 1.3f, 1.4f, 0.4f, 1.2f, 0.5f, 0.3f)
        var z = -2.4f
        for (i in features.indices) z += features[i] * w[i]
        return (1.0 / (1.0 + exp(-z.toDouble()))).toFloat().coerceIn(0f, 1f)
    }

    companion object {
        /**
         * Parses `scam_awareness.json` schema v2 (`i18n` map per card) with transparent
         * migration fallback for legacy schema v1 (`titleEn`/`titleHi`/`summaryEn`/`summaryHi`).
         */
        fun parseAwarenessCardsJson(raw: String): List<ScamAwarenessCard> {
            if (raw.isBlank()) return emptyList()
            return runCatching {
                val root = JSONObject(raw)
                val arr = root.optJSONArray("cards") ?: return@runCatching emptyList()
                buildList {
                    for (i in 0 until arr.length()) {
                        val o = arr.getJSONObject(i)
                        val id = o.optString("id")
                        val i18nObj = o.optJSONObject("i18n")
                        if (i18nObj != null) {
                            val map = linkedMapOf<String, LocalizedGuideContent>()
                            val keys = i18nObj.keys()
                            while (keys.hasNext()) {
                                val lang = keys.next().lowercase()
                                val locObj = i18nObj.optJSONObject(lang) ?: continue
                                val flags = locObj.optJSONArray("redFlags")
                                    ?.let { a -> (0 until a.length()).map { a.getString(it) }.filter { it.isNotBlank() } }
                                    .orEmpty()
                                val actions = locObj.optJSONArray("whatToDo")
                                    ?.let { a -> (0 until a.length()).map { a.getString(it) }.filter { it.isNotBlank() } }
                                    .orEmpty()
                                map[lang] = LocalizedGuideContent(
                                    title = locObj.optString("title"),
                                    description = locObj.optString("description"),
                                    redFlags = flags,
                                    whatToDo = actions
                                )
                            }
                            add(ScamAwarenessCard(id = id, i18n = map))
                        } else {
                            // Legacy schema v1 migration fallback
                            val flags = o.optJSONArray("redFlags")
                                ?.let { a -> (0 until a.length()).map { a.getString(it) } }
                                .orEmpty()
                            val actions = o.optJSONArray("whatToDo")
                                ?.let { a -> (0 until a.length()).map { a.getString(it) } }
                                .orEmpty()
                            val map = linkedMapOf<String, LocalizedGuideContent>()
                            map["en"] = LocalizedGuideContent(
                                title = o.optString("titleEn"),
                                description = o.optString("summaryEn"),
                                redFlags = flags,
                                whatToDo = actions
                            )
                            val titleHi = o.optString("titleHi")
                            val summaryHi = o.optString("summaryHi")
                            if (titleHi.isNotBlank() || summaryHi.isNotBlank()) {
                                map["hi"] = LocalizedGuideContent(
                                    title = titleHi,
                                    description = summaryHi,
                                    redFlags = emptyList(),
                                    whatToDo = emptyList()
                                )
                            }
                            add(ScamAwarenessCard(id = id, i18n = map))
                        }
                    }
                }
            }.getOrDefault(emptyList())
        }
    }
}
