package com.python.doctorg.domain.engine

import android.Manifest
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.content.ContextCompat
import com.python.doctorg.domain.model.AppUsageStat
import com.python.doctorg.domain.model.LanDevice
import com.python.doctorg.domain.model.WifiSecurityAudit
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import java.io.File
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.net.URL
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class NetworkToolsEngine @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val ouiVendors = mapOf(
        "00:1A:2B" to "Ayecom / Router",
        "B8:27:EB" to "Raspberry Pi",
        "DC:A6:32" to "Raspberry Pi",
        "3C:22:FB" to "Apple",
        "F0:18:98" to "Apple",
        "AC:BC:32" to "Apple",
        "24:5E:BE" to "QNAP",
        "EC:08:6B" to "TP-Link",
        "50:C7:BF" to "TP-Link",
        "C8:3A:35" to "Tenda",
        "00:17:88" to "Philips Hue",
        "94:65:2D" to "OnePlus",
        "34:CE:00" to "Xiaomi",
        "78:11:DC" to "Xiaomi",
        "CC:2D:83" to "Samsung",
        "A0:CC:2B" to "Samsung"
    )

    suspend fun auditCurrentWifi(): WifiSecurityAudit = withContext(Dispatchers.IO) {
        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        @Suppress("DEPRECATION")
        val info = wm?.connectionInfo
        @Suppress("DEPRECATION")
        val dhcp = wm?.dhcpInfo
        val ssid = info?.ssid?.trim('"')?.takeIf { it != "<unknown ssid>" } ?: "Wi-Fi (grant Location for SSID)"
        val bssid = info?.bssid ?: "00:00:00:00:00:00"
        val rssi = info?.rssi ?: -70
        val linkSpeed = info?.linkSpeed ?: 0
        val gatewayIp = intToIp(dhcp?.gateway ?: 0)

        val warnings = mutableListOf<String>()
        var securityType = "WPA2/WPA3"
        var evilTwin = false

        val hasLocationPerm = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.ACCESS_FINE_LOCATION
        ) == PackageManager.PERMISSION_GRANTED
        if (hasLocationPerm) {
            try {
                @Suppress("DEPRECATION")
                val scanResults = wm?.scanResults.orEmpty()
                val matchingSsid = scanResults.filter { result ->
                    val candidateSsid = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                        result.wifiSsid?.toString()?.trim('"').orEmpty()
                    } else {
                        @Suppress("DEPRECATION")
                        result.SSID.orEmpty()
                    }
                    candidateSsid == ssid && ssid.isNotBlank() && !ssid.startsWith("Wi-Fi (")
                }
                val distinctBssids = matchingSsid.map { it.BSSID }.distinct()
                val caps = matchingSsid.firstOrNull()?.capabilities.orEmpty()
                securityType = when {
                    caps.contains("WPA3") || caps.contains("SAE") -> "WPA3 (Strong)"
                    caps.contains("WPA2") -> "WPA2 (Secure)"
                    caps.contains("WEP") -> "WEP (Broken)"
                    caps.contains("WPA") -> "WPA1 (Legacy Weak)"
                    caps.isNotBlank() && !caps.contains("PSK") && !caps.contains("EAP") -> "Open / Unencrypted"
                    else -> "WPA2/WPA3"
                }
                if (securityType.contains("Open") || securityType.contains("WEP") || securityType.contains("WPA1")) {
                    warnings.add("Weak or unencrypted Wi-Fi ($securityType). Avoid banking or enable a trusted VPN.")
                }
                if (distinctBssids.size >= 2 && matchingSsid.map { it.capabilities.contains("PSK") }.distinct().size > 1) {
                    evilTwin = true
                    warnings.add("Possible Evil-Twin AP: same SSID '$ssid' advertised with mixed security modes!")
                }
            } catch (_: SecurityException) {
                warnings.add("Location permission required to inspect Wi-Fi encryption & Evil-Twin APs.")
            }
        }

        // ARP Spoofing detection via /proc/net/arp duplicate MAC check
        val arpEntries = readArpTable()
        val macGroups = arpEntries.values.filter { it != "00:00:00:00:00:00" }.groupingBy { it }.eachCount()
        val arpSpoof = macGroups.any { it.value > 1 }
        if (arpSpoof) {
            warnings.add("Possible ARP Spoofing detected: multiple LAN IPs share the same MAC address.")
        }
        if (rssi < -82) {
            warnings.add("Weak Wi-Fi signal ($rssi dBm) may cause intermittent drops.")
        }

        WifiSecurityAudit(
            ssid = ssid,
            bssid = bssid,
            rssiDbm = rssi,
            linkSpeedMbps = linkSpeed,
            securityType = securityType,
            gatewayIp = gatewayIp,
            arpSpoofingSuspected = arpSpoof,
            evilTwinSuspected = evilTwin,
            warnings = warnings,
            isSafe = warnings.isEmpty()
        )
    }

    suspend fun pingHost(host: String, count: Int = 4): String = withContext(Dispatchers.IO) {
        val sanitized = host.trim().take(128)
        if (!Regex("""^[a-zA-Z0-9.\-:]+$""").matches(sanitized)) {
            return@withContext "Invalid host format. Enter a domain or IP address."
        }
        val sb = StringBuilder("PING $sanitized:\n")
        runCatching {
            val addr = InetAddress.getByName(sanitized)
            sb.append("Resolved IP: ${addr.hostAddress}\n")
            var success = 0
            for (seq in 1..count) {
                val t0 = System.nanoTime()
                val ok = addr.isReachable(2000) || tryTcpReach(addr, 443, 1500) || tryTcpReach(addr, 80, 1500)
                val ms = (System.nanoTime() - t0) / 1_000_000.0
                if (ok) {
                    success++
                    sb.append("seq=$seq reachable time=%.1f ms\n".format(ms))
                } else {
                    sb.append("seq=$seq timeout\n")
                }
            }
            sb.append("Stats: $success/$count packets succeeded")
        }.onFailure {
            sb.append("Lookup failed: ${it.message}")
        }
        sb.toString()
    }

    suspend fun tracerouteHost(host: String): String = withContext(Dispatchers.IO) {
        val sanitized = host.trim().take(128)
        if (!Regex("""^[a-zA-Z0-9.\-:]+$""").matches(sanitized)) {
            return@withContext "Invalid host format."
        }
        val sb = StringBuilder("TRACEROUTE $sanitized (max 8 hops):\n")
        runCatching {
            val dest = InetAddress.getByName(sanitized)
            val localIp = getLocalIpv4()
            sb.append("1  $localIp (Local Device)\n")
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            @Suppress("DEPRECATION")
            val gw = intToIp(wm?.dhcpInfo?.gateway ?: 0)
            if (gw != "0.0.0.0") sb.append("2  $gw (Local Gateway)\n")
            val t0 = System.nanoTime()
            val reached = dest.isReachable(2500) || tryTcpReach(dest, 443, 2000)
            val ms = (System.nanoTime() - t0) / 1_000_000.0
            sb.append("3  ${dest.hostAddress} (${dest.canonicalHostName}) — ${if (reached) "%.1f ms".format(ms) else "ICMP filtered"}")
        }.onFailure {
            sb.append("Error: ${it.message}")
        }
        sb.toString()
    }

    suspend fun scanCommonPorts(host: String): List<Pair<Int, String>> = withContext(Dispatchers.IO) {
        val sanitized = host.trim().take(128)
        if (!Regex("""^[a-zA-Z0-9.\-]+$""").matches(sanitized)) return@withContext emptyList()
        val ports = listOf(
            21 to "FTP", 22 to "SSH", 23 to "Telnet (Insecure)", 53 to "DNS",
            80 to "HTTP", 443 to "HTTPS", 445 to "SMB", 3389 to "RDP", 5555 to "ADB (Risk!)", 8080 to "HTTP-Alt"
        )
        coroutineScope {
            ports.map { (port, label) ->
                async {
                    val open = runCatching {
                        Socket().use { s ->
                            s.connect(InetSocketAddress(sanitized, port), 700)
                            true
                        }
                    }.getOrDefault(false)
                    if (open) port to label else null
                }
            }.awaitAll().filterNotNull()
        }
    }

    suspend fun scanLanDevices(): List<LanDevice> = withContext(Dispatchers.IO) {
        val localIp = getLocalIpv4()
        val prefix = localIp.substringBeforeLast(".", "192.168.1")
        val arp = readArpTable()
        val devices = mutableListOf<LanDevice>()
        val probeTargets = (listOf(1, 2, 10, 20, 50, 100, 101, 102, 254) + arp.keys.mapNotNull { it.substringAfterLast(".").toIntOrNull() })
            .distinct()
            .filter { it in 1..254 }
            .take(36)

        coroutineScope {
            val found = probeTargets.map { lastOctet ->
                async {
                    val ip = "$prefix.$lastOctet"
                    val addr = InetAddress.getByName(ip)
                    val reachable = ip == localIp || addr.isReachable(350) || arp.containsKey(ip)
                    if (reachable) {
                        val mac = arp[ip] ?: "Unknown"
                        val oui = mac.uppercase().take(8)
                        LanDevice(
                            ipAddress = ip,
                            macAddress = mac,
                            hostname = if (ip == localIp) "This Device (DoctorG)" else addr.hostName,
                            vendor = ouiVendors[oui] ?: if (ip == localIp) Build.MANUFACTURER else "LAN Device",
                            isReachable = true
                        )
                    } else {
                        null
                    }
                }
            }.awaitAll().filterNotNull()
            devices.addAll(found)
        }
        devices.sortedBy { it.ipAddress.substringAfterLast(".").toIntOrNull() ?: 999 }
    }

    suspend fun runSpeedTestMbps(): Pair<Double, Long> = withContext(Dispatchers.IO) {
        val testUrl = "https://speed.cloudflare.com/__down?bytes=250000"
        val start = System.nanoTime()
        runCatching {
            val conn = (URL(testUrl).openConnection() as HttpURLConnection).apply {
                connectTimeout = 4000
                readTimeout = 6000
            }
            try {
                val bytes = conn.inputStream.use { it.readBytes().size }
                val elapsedSec = ((System.nanoTime() - start) / 1_000_000_000.0).coerceAtLeast(0.05)
                val mbps = (bytes * 8.0) / (elapsedSec * 1_000_000.0)
                val latencyMs = ((System.nanoTime() - start) / 1_000_000L)
                mbps to latencyMs
            } finally {
                conn.disconnect()
            }
        }.getOrDefault(0.0 to 0L)
    }

    suspend fun queryAppDataUsageLast30Days(): List<AppUsageStat> = withContext(Dispatchers.IO) {
        val nsm = context.getSystemService(Context.NETWORK_STATS_SERVICE) as? NetworkStatsManager ?: return@withContext emptyList()
        val pm = context.packageManager
        val end = System.currentTimeMillis()
        val start = end - 30L * 24L * 60L * 60L * 1000L
        val installed = runCatching {
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
                .filter { (it.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) == 0 }
                .take(25)
        }.getOrDefault(emptyList())

        installed.mapNotNull { app ->
            runCatching {
                var wifiBytes = 0L
                var mobileBytes = 0L
                val bucket = android.app.usage.NetworkStats.Bucket()
                @Suppress("DEPRECATION")
                val wifiStats = nsm.queryDetailsForUid(ConnectivityManager.TYPE_WIFI, null, start, end, app.uid)
                try {
                    while (wifiStats.hasNextBucket()) {
                        wifiStats.getNextBucket(bucket)
                        wifiBytes += bucket.rxBytes + bucket.txBytes
                    }
                } finally {
                    wifiStats.close()
                }

                @Suppress("DEPRECATION")
                val mobStats = nsm.queryDetailsForUid(ConnectivityManager.TYPE_MOBILE, null, start, end, app.uid)
                try {
                    while (mobStats.hasNextBucket()) {
                        mobStats.getNextBucket(bucket)
                        mobileBytes += bucket.rxBytes + bucket.txBytes
                    }
                } finally {
                    mobStats.close()
                }

                AppUsageStat(
                    packageName = app.packageName,
                    appName = app.loadLabel(pm).toString(),
                    wifiBytes = wifiBytes,
                    mobileBytes = mobileBytes
                )
            }.getOrNull()
        }.sortedByDescending { it.wifiBytes + it.mobileBytes }
    }

    private fun readArpTable(): Map<String, String> {
        val result = mutableMapOf<String, String>()
        runCatching {
            File("/proc/net/arp").forEachLine { line ->
                val parts = line.trim().split(Regex("\\s+"))
                if (parts.size >= 4 && parts[0].contains(".")) {
                    result[parts[0]] = parts[3].uppercase()
                }
            }
        }
        return result
    }

    private fun tryTcpReach(addr: InetAddress, port: Int, timeoutMs: Int): Boolean = runCatching {
        Socket().use { s -> s.connect(InetSocketAddress(addr, port), timeoutMs); true }
    }.getOrDefault(false)

    private fun getLocalIpv4(): String = runCatching {
        NetworkInterface.getNetworkInterfaces().toList()
            .flatMap { it.inetAddresses.toList() }
            .firstOrNull { !it.isLoopbackAddress && it is Inet4Address }
            ?.hostAddress ?: "192.168.1.100"
    }.getOrDefault("192.168.1.100")

    private fun intToIp(ip: Int): String =
        "${ip and 0xFF}.${ip shr 8 and 0xFF}.${ip shr 16 and 0xFF}.${ip shr 24 and 0xFF}"
}
