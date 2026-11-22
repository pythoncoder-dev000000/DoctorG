package com.python.doctorg.service

import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.telecom.Call
import android.telecom.CallScreeningService
import androidx.core.net.toUri
import com.python.doctorg.core.notifications.DoctorGNotifications
import com.python.doctorg.data.local.DoctorGDatabase
import com.python.doctorg.data.local.entity.BlockedEventEntity
import com.python.doctorg.domain.engine.ScamSmsClassifier
import com.python.doctorg.domain.model.ThreatLevel
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Opt-in NotificationListenerService inspecting URLs and scam patterns in incoming
 * SMS, WhatsApp, and Telegram notifications entirely on-device.
 */
@AndroidEntryPoint
class PhishingNotificationListenerService : NotificationListenerService() {

    @Inject lateinit var database: DoctorGDatabase
    @Inject lateinit var scamSmsClassifier: ScamSmsClassifier
    @Inject lateinit var notifications: DoctorGNotifications

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val monitoredMessengers = setOf(
        "com.whatsapp",
        "com.whatsapp.w4b",
        "org.telegram.messenger",
        "com.google.android.apps.messaging",
        "com.samsung.android.messaging"
    )
    private val urlRegex = Regex("""https?://[^\s]+""", RegexOption.IGNORE_CASE)

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        if (sbn == null || sbn.packageName == packageName) return
        if (sbn.packageName !in monitoredMessengers) return
        val extras = sbn.notification?.extras ?: return
        val text = listOfNotNull(
            extras.getCharSequence("android.title")?.toString(),
            extras.getCharSequence("android.text")?.toString(),
            extras.getCharSequence("android.bigText")?.toString()
        ).joinToString(" ")
        if (text.isBlank()) return

        scope.launch {
            val urls = urlRegex.findAll(text).map { it.value }.toList()
            for (url in urls) {
                val host = runCatching { url.toUri().host?.lowercase().orEmpty() }.getOrDefault("")
                if (host.isNotBlank()) {
                    var current = host
                    var blocked = false
                    while (current.contains(".")) {
                        val match = database.webProtectionDao().findDomain(current)
                        if (match != null) {
                            blocked = !match.isAllowedOverride
                            break
                        }
                        current = current.substringAfter(".")
                    }
                    if (blocked) {
                        database.webProtectionDao().logBlockedEvent(
                            BlockedEventEntity(
                                domainOrUrl = url,
                                source = "NOTIFICATION_LINK",
                                reason = "Phishing/malicious link in ${sbn.packageName}"
                            )
                        )
                        notifications.postThreatAlert(
                            idOffset = 40,
                            title = "Phishing Link Detected!",
                            message = "Blocked dangerous URL ($host) received in a message notification. Do not tap it."
                        )
                    }
                }
            }

            val smsAnalysis = scamSmsClassifier.classifySms(text)
            if (smsAnalysis.verdict == ThreatLevel.MALICIOUS) {
                notifications.postThreatAlert(
                    idOffset = 41,
                    title = "High-Risk Scam Message",
                    message = "Detected ${smsAnalysis.matchedReasons.joinToString(", ")} (Risk ${smsAnalysis.riskScore}%)."
                )
            }
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}

/**
 * Opt-in CallScreeningService checking unknown incoming calls against local & GitHub spam DBs.
 */
@AndroidEntryPoint
class ScamCallScreeningService : CallScreeningService() {

    @Inject lateinit var database: DoctorGDatabase
    @Inject lateinit var notifications: DoctorGNotifications

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onScreenCall(callDetails: Call.Details) {
        val number = callDetails.handle?.schemeSpecificPart.orEmpty()
        if (number.isBlank()) {
            respondToCall(callDetails, CallResponse.Builder().build())
            return
        }
        scope.launch {
            val builder = CallResponse.Builder()
            runCatching {
                val normalized = number.replace(Regex("[\\s\\-()]"), "")
                val spam = database.spamNumberDao().find(number)
                    ?: database.spamNumberDao().find(normalized)
                if (spam != null && spam.risk == "HIGH") {
                    builder.setDisallowCall(false) // Warn user without silently dropping unless configured
                        .setSkipNotification(false)
                    notifications.postThreatAlert(
                        idOffset = 45,
                        title = "Suspected Scam Call: $number",
                        message = "${spam.category} (${spam.reports} reports). Do not share OTPs, UPI PINs, or install AnyDesk!"
                    )
                }
            }
            respondToCall(callDetails, builder.build())
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
