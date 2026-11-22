package com.python.doctorg.service

import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.python.doctorg.core.notifications.DoctorGNotifications
import com.python.doctorg.data.local.DoctorGDatabase
import com.python.doctorg.data.local.entity.BlockedEventEntity
import com.python.doctorg.data.preferences.DnsProvider
import com.python.doctorg.data.preferences.DoctorGPreferences
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import javax.inject.Inject

/**
 * Local-only On-Device VPN Service for Web Protection DNS filtering and Per-App Firewall.
 * Traffic never leaves the device to any custom VPN server; allowed DNS queries forward directly
 * to the user's selected DNS resolver (Quad9, Cloudflare Family, Google, or Custom).
 */
@AndroidEntryPoint
class DoctorGVpnService : VpnService() {

    @Inject lateinit var database: DoctorGDatabase
    @Inject lateinit var preferences: DoctorGPreferences
    @Inject lateinit var notifications: DoctorGNotifications

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var packetLoopJob: Job? = null
    private var blockedThisSession = 0

    companion object {
        const val ACTION_START = "com.python.doctorg.action.VPN_START"
        const val ACTION_STOP = "com.python.doctorg.action.VPN_STOP"

        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning.asStateFlow()

        fun start(context: Context) {
            val intent = Intent(context, DoctorGVpnService::class.java).setAction(ACTION_START)
            ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context) {
            if (!_isRunning.value) return
            val intent = Intent(context, DoctorGVpnService::class.java).setAction(ACTION_STOP)
            runCatching { context.startService(intent) }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }
        val fgsType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(
            this,
            DoctorGNotifications.ID_VPN,
            notifications.buildVpnNotification(blockedThisSession, "Local DNS"),
            fgsType
        )
        startVpn()
        return START_STICKY
    }

    private fun startVpn() {
        if (packetLoopJob?.isActive == true) return
        scope.launch {
            val settings = preferences.settingsFlow.first()
            val upstreamDns = if (settings.dnsProvider == DnsProvider.CUSTOM) {
                settings.customDnsIp.ifBlank { "1.1.1.1" }
            } else {
                settings.dnsProvider.ip
            }

            notifications.notifyOngoing(
                DoctorGNotifications.ID_VPN,
                notifications.buildVpnNotification(blockedThisSession, settings.dnsProvider.label)
            )

            val builder = Builder()
                .setSession("DoctorG Web Protection")
                .addAddress("10.89.0.2", 32)
                .addDnsServer("10.89.0.1")
                .addRoute("10.89.0.1", 32)
                .setBlocking(true)

            // Apply per-app firewall exclusions / blocks cleanly
            val blockedRules = database.firewallDao().getActiveBlockedRules()
            if (blockedRules.isNotEmpty()) {
                builder.addRoute("0.0.0.0", 0)
                blockedRules.forEach { rule ->
                    runCatching { builder.addAllowedApplication(rule.packageName) }
                }
            } else {
                runCatching { builder.addDisallowedApplication(packageName) }
            }

            vpnInterface = runCatching { builder.establish() }.getOrNull()
            if (vpnInterface == null) {
                _isRunning.value = false
                stopSelf()
                return@launch
            }
            _isRunning.value = true
            preferences.setVpnAutoStart(true)

            packetLoopJob = launch {
                runDnsInspectionLoop(vpnInterface!!, upstreamDns, settings.dnsProvider.label)
            }
        }
    }

    private suspend fun runDnsInspectionLoop(pfd: ParcelFileDescriptor, upstreamDns: String, dnsLabel: String) {
        val input = FileInputStream(pfd.fileDescriptor)
        val output = FileOutputStream(pfd.fileDescriptor)
        val packet = ByteArray(4096)

        while (scope.isActive && _isRunning.value) {
            val length = runCatching { input.read(packet) }.getOrDefault(-1)
            if (length <= 28) continue
            val version = (packet[0].toInt() shr 4) and 0xF
            val protocol = packet[9].toInt() and 0xFF
            if (version != 4 || protocol != 17) continue // IPv4 UDP

            val ihl = (packet[0].toInt() and 0x0F) * 4
            if (length <= ihl + 8 + 12) continue
            val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
            if (dstPort != 53) continue

            val dnsOffset = ihl + 8
            val dnsLen = length - dnsOffset
            val dnsPayload = packet.copyOfRange(dnsOffset, dnsOffset + dnsLen)
            val queriedDomain = parseDnsQueryName(dnsPayload)?.lowercase().orEmpty()
            if (queriedDomain.isBlank()) continue

            val blocked = isDomainBlocked(queriedDomain)
            val responseDns = if (blocked) {
                blockedThisSession++
                database.webProtectionDao().logBlockedEvent(
                    BlockedEventEntity(
                        domainOrUrl = queriedDomain,
                        source = "VPN_DNS",
                        reason = "Blocked by DoctorG local DNS filter"
                    )
                )
                notifications.notifyOngoing(
                    DoctorGNotifications.ID_VPN,
                    notifications.buildVpnNotification(blockedThisSession, dnsLabel)
                )
                buildNxDomainResponse(dnsPayload)
            } else {
                forwardDnsUpstream(dnsPayload, upstreamDns) ?: continue
            }

            val ipUdpReply = wrapIpv4UdpReply(packet, ihl, responseDns)
            runCatching { output.write(ipUdpReply) }
        }
    }

    private suspend fun isDomainBlocked(domain: String): Boolean {
        val dao = database.webProtectionDao()
        var current = domain
        while (current.contains(".")) {
            val match = dao.findDomain(current)
            if (match != null) return !match.isAllowedOverride
            current = current.substringAfter(".")
        }
        return false
    }

    private fun parseDnsQueryName(dns: ByteArray): String? {
        if (dns.size < 13) return null
        val labels = mutableListOf<String>()
        var idx = 12
        while (idx < dns.size) {
            val len = dns[idx].toInt() and 0xFF
            if (len == 0) break
            if (idx + 1 + len > dns.size) return null
            labels.add(String(dns, idx + 1, len, Charsets.US_ASCII))
            idx += 1 + len
        }
        return labels.joinToString(".")
    }

    private fun buildNxDomainResponse(query: ByteArray): ByteArray {
        val resp = query.copyOf()
        if (resp.size >= 12) {
            resp[2] = ((resp[2].toInt() or 0x80) and 0xFF).toByte() // QR=1 response
            resp[3] = ((resp[3].toInt() and 0xF0) or 0x83).toByte() // RA=1, RCODE=3 NXDOMAIN
            for (i in 6 until 12) resp[i] = 0 // Zero ANCOUNT, NSCOUNT, ARCOUNT
        }
        return resp
    }

    private fun forwardDnsUpstream(query: ByteArray, upstreamIp: String): ByteArray? = runCatching {
        DatagramSocket().use { socket ->
            protect(socket)
            socket.soTimeout = 2500
            val req = DatagramPacket(query, query.size, InetAddress.getByName(upstreamIp), 53)
            socket.send(req)
            val buf = ByteArray(1500)
            val resp = DatagramPacket(buf, buf.size)
            socket.receive(resp)
            buf.copyOf(resp.length)
        }
    }.getOrNull()

    private fun wrapIpv4UdpReply(requestPacket: ByteArray, ihl: Int, dnsPayload: ByteArray): ByteArray {
        val totalLen = 20 + 8 + dnsPayload.size
        val out = ByteArray(totalLen)
        out[0] = 0x45.toByte()
        out[2] = ((totalLen shr 8) and 0xFF).toByte()
        out[3] = (totalLen and 0xFF).toByte()
        out[8] = 64.toByte() // TTL
        out[9] = 17.toByte() // UDP
        // Swap src and dst IP
        System.arraycopy(requestPacket, 16, out, 12, 4)
        System.arraycopy(requestPacket, 12, out, 16, 4)
        // IPv4 header checksum
        var sum = 0
        for (i in 0 until 20 step 2) {
            sum += ((out[i].toInt() and 0xFF) shl 8) or (out[i + 1].toInt() and 0xFF)
        }
        while ((sum ushr 16) != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        val csum = sum.inv() and 0xFFFF
        out[10] = ((csum shr 8) and 0xFF).toByte()
        out[11] = (csum and 0xFF).toByte()

        // Swap UDP ports
        out[20] = requestPacket[ihl + 2]
        out[21] = requestPacket[ihl + 3]
        out[22] = requestPacket[ihl]
        out[23] = requestPacket[ihl + 1]
        val udpLen = 8 + dnsPayload.size
        out[24] = ((udpLen shr 8) and 0xFF).toByte()
        out[25] = (udpLen and 0xFF).toByte()
        System.arraycopy(dnsPayload, 0, out, 28, dnsPayload.size)
        return out
    }

    private fun stopVpn() {
        _isRunning.value = false
        packetLoopJob?.cancel()
        runCatching { vpnInterface?.close() }
        vpnInterface = null
        scope.launch { preferences.setVpnAutoStart(false) }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        _isRunning.value = false
        runCatching { vpnInterface?.close() }
        scope.cancel()
        super.onDestroy()
    }
}
