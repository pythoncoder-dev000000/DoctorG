package com.python.doctorg.feature.scan

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import com.python.doctorg.R
import com.python.doctorg.domain.engine.MalwareScanEngine
import com.python.doctorg.domain.model.AppScanFinding
import com.python.doctorg.domain.model.ThreatLevel
import com.python.doctorg.ui.theme.DoctorGTheme
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject

/**
 * APK Pre-install Scanner: intercepts `.apk` files opened from file managers or browsers,
 * runs DoctorG's SHA-256 + YARA + Static APK + ML scan before installation, shows the verdict,
 * and hands off safely to the Android system package installer only if the user proceeds.
 */
@AndroidEntryPoint
class ApkPreInstallActivity : ComponentActivity() {

    @Inject lateinit var scanEngine: MalwareScanEngine

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val apkUri: Uri? = intent?.data

        setContent {
            DoctorGTheme {
                var finding by remember { mutableStateOf<AppScanFinding?>(null) }
                var errorMsg by remember { mutableStateOf<String?>(null) }

                LaunchedEffect(apkUri) {
                    if (apkUri == null) {
                        errorMsg = "No APK file URI provided."
                        return@LaunchedEffect
                    }
                    withContext(Dispatchers.IO) {
                        val tempApk = File(cacheDir, "preinstall_inspect_${System.currentTimeMillis()}.apk")
                        try {
                            val stream = contentResolver.openInputStream(apkUri)
                                ?: error("Cannot open APK input stream.")
                            val maxApkBytes = 250L * 1024L * 1024L
                            var copied = 0L
                            stream.use { input ->
                                tempApk.outputStream().use { out ->
                                    val buf = ByteArray(16 * 1024)
                                    var n = input.read(buf)
                                    while (n != -1) {
                                        copied += n
                                        require(copied <= maxApkBytes) { "APK exceeds 250 MB inspection limit." }
                                        out.write(buf, 0, n)
                                        n = input.read(buf)
                                    }
                                }
                            }
                            require(copied > 0L) { "APK file is empty." }
                            finding = scanEngine.scanSingleFile(tempApk)
                        } catch (t: Throwable) {
                            errorMsg = "Unable to inspect APK: ${t.message}"
                        } finally {
                            tempApk.delete()
                        }
                    }
                }

                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(innerPadding)
                            .padding(20.dp)
                            .verticalScroll(rememberScrollState()),
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Image(
                                painter = painterResource(R.drawable.doctorg_logo),
                                contentDescription = "DoctorG Logo",
                                modifier = Modifier.size(44.dp)
                            )
                            Column {
                                Text("DoctorG APK Pre-Install Scanner", style = MaterialTheme.typography.titleLarge)
                                Text("100% On-Device Inspection", style = MaterialTheme.typography.bodySmall)
                            }
                        }

                        when {
                            errorMsg != null -> Text(errorMsg!!, color = MaterialTheme.colorScheme.error)
                            finding == null -> {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                                ) {
                                    CircularProgressIndicator(modifier = Modifier.size(24.dp))
                                    Text("Computing SHA-256, YARA rules, DEX APIs & ML score...")
                                }
                            }
                            else -> {
                                val res = finding!!
                                Card(modifier = Modifier.fillMaxWidth()) {
                                    Column(
                                        modifier = Modifier.padding(16.dp),
                                        verticalArrangement = Arrangement.spacedBy(8.dp)
                                    ) {
                                        Text(
                                            text = "Verdict: ${res.threatLevel.name.replace('_', ' ')} (Risk ${res.riskScore}/100)",
                                            style = MaterialTheme.typography.titleMedium,
                                            color = when (res.threatLevel) {
                                                ThreatLevel.TRUSTED, ThreatLevel.SAFE -> MaterialTheme.colorScheme.secondary
                                                ThreatLevel.NEEDS_REVIEW, ThreatLevel.SUSPICIOUS -> MaterialTheme.colorScheme.tertiary
                                                ThreatLevel.MALICIOUS -> MaterialTheme.colorScheme.error
                                            }
                                        )
                                        Text("SHA-256: ${res.sha256.take(32)}...", style = MaterialTheme.typography.labelSmall)
                                        res.reasons.forEach { reason ->
                                            Text("• $reason", style = MaterialTheme.typography.bodyMedium)
                                        }
                                    }
                                }

                                Spacer(Modifier.height(8.dp))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                                ) {
                                    OutlinedButton(
                                        onClick = { finish() },
                                        modifier = Modifier.weight(1f)
                                    ) { Text("Block & Close") }

                                    Button(
                                        onClick = {
                                            apkUri?.let { handOffToSystemInstaller(it) }
                                            finish()
                                        },
                                        modifier = Modifier.weight(1f)
                                    ) {
                                        Text(
                                            if (res.threatLevel == ThreatLevel.SAFE || res.threatLevel == ThreatLevel.TRUSTED) {
                                                "Proceed to Install"
                                            } else {
                                                "Install Anyway"
                                            }
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private fun handOffToSystemInstaller(uri: Uri) {
        if (uri.scheme.equals("file", ignoreCase = true)) {
            return // Avoid FileUriExposedException on Android 8+; system file managers pass content:// URIs
        }
        val viewIntent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
            setPackage("com.google.android.packageinstaller")
        }
        val launched = runCatching { startActivity(viewIntent); true }.getOrDefault(false)
        if (!launched) {
            val aospIntent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/vnd.android.package-archive")
                flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
                setPackage("com.android.packageinstaller")
            }
            val launchedAosp = runCatching { startActivity(aospIntent); true }.getOrDefault(false)
            if (!launchedAosp) {
                @Suppress("DEPRECATION")
                val fallback = Intent(Intent.ACTION_INSTALL_PACKAGE).apply {
                    data = uri
                    flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
                }
                runCatching { startActivity(fallback) }
            }
        }
    }
}
