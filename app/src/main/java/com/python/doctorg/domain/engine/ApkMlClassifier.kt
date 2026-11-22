package com.python.doctorg.domain.engine

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import org.tensorflow.lite.Interpreter
import java.io.File
import java.io.FileInputStream
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel
import javax.inject.Inject
import javax.inject.Singleton

data class ApkFeatureVector(
    val hasReceiveSms: Boolean = false,
    val hasSendSms: Boolean = false,
    val hasReadSms: Boolean = false,
    val hasAccessibility: Boolean = false,
    val hasOverlay: Boolean = false,
    val hasInstallPackages: Boolean = false,
    val hasDeviceAdmin: Boolean = false,
    val hasReadContacts: Boolean = false,
    val hasInternet: Boolean = false,
    val hasBackgroundLocation: Boolean = false,
    val hasCameraOrMic: Boolean = false,
    val hasDexClassLoader: Boolean = false,
    val hasRuntimeExec: Boolean = false,
    val isSideloaded: Boolean = false,
    val isHiddenNoLauncher: Boolean = false,
    val hasOldTargetSdk: Boolean = false
) {
    fun toFloatArray(): FloatArray = floatArrayOf(
        if (hasReceiveSms) 1f else 0f,
        if (hasSendSms) 1f else 0f,
        if (hasReadSms) 1f else 0f,
        if (hasAccessibility) 1f else 0f,
        if (hasOverlay) 1f else 0f,
        if (hasInstallPackages) 1f else 0f,
        if (hasDeviceAdmin) 1f else 0f,
        if (hasReadContacts) 1f else 0f,
        if (hasInternet) 1f else 0f,
        if (hasBackgroundLocation) 1f else 0f,
        if (hasCameraOrMic) 1f else 0f,
        if (hasDexClassLoader) 1f else 0f,
        if (hasRuntimeExec) 1f else 0f,
        if (isSideloaded) 1f else 0f,
        if (isHiddenNoLauncher) 1f else 0f,
        if (hasOldTargetSdk) 1f else 0f
    )
}

/**
 * On-device APK malware classifier using LiteRT (16KB page-size compatible TensorFlow Lite).
 *
 * Supporting soft signal ONLY:
 * - Loads `apk_malware_classifier.tflite` from updated feeds or bundled assets.
 * - If the `.tflite` model file is missing, invalid, or lightweight mode is enabled,
 *   cleanly disables the ML signal by returning `null` instead of fabricating a score.
 */
@Singleton
class ApkMlClassifier @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val modelName = "apk_malware_classifier.tflite"
    private var interpreter: Interpreter? = null
    private var loadAttempted = false

    val isTfliteModelLoaded: Boolean
        get() {
            ensureLoaded()
            return interpreter != null
        }

    private fun ensureLoaded() {
        if (loadAttempted) return
        loadAttempted = true
        interpreter = runCatching {
            val buffer = loadModelBuffer() ?: return@runCatching null
            Interpreter(buffer, Interpreter.Options().setNumThreads(2))
        }.getOrNull()
    }

    private fun loadModelBuffer(): MappedByteBuffer? {
        val updatedFile = File(context.filesDir, "feeds/$modelName")
        if (updatedFile.exists() && updatedFile.length() > 0L) {
            return runCatching {
                FileInputStream(updatedFile).use { fis ->
                    fis.channel.map(FileChannel.MapMode.READ_ONLY, 0, updatedFile.length())
                }
            }.getOrNull()
        }
        return runCatching {
            context.assets.openFd(modelName).use { afd ->
                FileInputStream(afd.fileDescriptor).use { fis ->
                    fis.channel.map(FileChannel.MapMode.READ_ONLY, afd.startOffset, afd.declaredLength)
                }
            }
        }.getOrNull()
    }

    /**
     * Returns a calibrated probability in [0f, 1f] ONLY when a verified `.tflite` model
     * is loaded and inference succeeds; returns `null` when unavailable or disabled.
     */
    fun predictMalwareProbability(features: ApkFeatureVector, lightweightMode: Boolean = false): Float? {
        if (lightweightMode) return null
        ensureLoaded()
        val tflite = interpreter ?: return null
        val input = features.toFloatArray()
        if (input.any { it.isNaN() || it.isInfinite() }) return null
        return runCatching {
            val out = Array(1) { FloatArray(1) }
            tflite.run(arrayOf(input), out)
            val prob = out[0][0]
            if (prob.isNaN() || prob.isInfinite()) null else prob.coerceIn(0f, 1f)
        }.getOrNull()
    }
}
