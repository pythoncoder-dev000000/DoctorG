package com.python.doctorg.ui.screens.onboarding

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.python.doctorg.R
import com.python.doctorg.core.permissions.PermissionItemStatus
import com.python.doctorg.ui.theme.DoctorGColors

@Composable
fun OnboardingScreen(
    permissions: List<PermissionItemStatus>,
    onRequestPermission: (PermissionItemStatus) -> Unit,
    onFinishOnboarding: () -> Unit
) {
    var step by rememberSaveable { mutableIntStateOf(0) }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    listOf(
                        DoctorGColors.BrandNavy,
                        MaterialTheme.colorScheme.background
                    )
                )
            )
            .safeDrawingPadding(),
        contentAlignment = Alignment.TopCenter
    ) {
        Column(
            modifier = Modifier
                .widthIn(max = 640.dp)
                .fillMaxSize()
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Column(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                if (step == 0) {
                    // Step 1: DoctorG Identity & Privacy Policy BEFORE any permission request
                    Spacer(Modifier.height(8.dp))
                    Surface(
                        shape = RoundedCornerShape(24.dp),
                        color = DoctorGColors.BrandNavy,
                        shadowElevation = 6.dp,
                        modifier = Modifier.align(Alignment.CenterHorizontally)
                    ) {
                        Image(
                            painter = painterResource(R.drawable.doctorg_logo),
                            contentDescription = "DoctorG Logo",
                            modifier = Modifier
                                .size(116.dp)
                                .padding(8.dp)
                        )
                    }

                    Text(
                        text = "Welcome to DoctorG",
                        style = MaterialTheme.typography.displayMedium,
                        color = MaterialTheme.colorScheme.onPrimary,
                        modifier = Modifier.align(Alignment.CenterHorizontally)
                    )
                    Text(
                        text = stringResource(R.string.app_tagline),
                        style = MaterialTheme.typography.titleMedium,
                        color = DoctorGColors.BrandCyan,
                        modifier = Modifier.align(Alignment.CenterHorizontally)
                    )

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                    ) {
                        Column(
                            modifier = Modifier.padding(18.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Icon(Icons.Filled.Lock, contentDescription = null, tint = DoctorGColors.SafeEmerald)
                                Text(
                                    text = stringResource(R.string.privacy_policy_title),
                                    style = MaterialTheme.typography.titleMedium
                                )
                            }
                            Text(
                                text = stringResource(R.string.privacy_policy_body),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                text = "• No personal data, SMS, contacts, or files are ever uploaded.\n" +
                                    "• Every permission is optional and asked only when you enable a feature.\n" +
                                    "• No ads, no analytics, no accounts, no premium paywalls.",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                } else {
                    // Step 2: Optional Permissions Checklist with clear Skip button
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Icon(Icons.Filled.VerifiedUser, contentDescription = null, tint = DoctorGColors.BrandCyan)
                        Column {
                            Text(
                                text = "Optional Permissions Checklist",
                                style = MaterialTheme.typography.headlineSmall,
                                color = MaterialTheme.colorScheme.onPrimary
                            )
                            Text(
                                text = "You are always in control. Grant only what you need, or skip and allow later.",
                                style = MaterialTheme.typography.bodySmall,
                                color = DoctorGColors.BrandCyan
                            )
                        }
                    }

                    permissions.take(6).forEach { perm ->
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(14.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(12.dp)
                            ) {
                                Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                    Text(perm.title, style = MaterialTheme.typography.titleSmall)
                                    Text(perm.dependentFeatures, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                                if (perm.isGranted) {
                                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                        Icon(Icons.Filled.CheckCircle, contentDescription = "Allowed", tint = DoctorGColors.SafeEmerald, modifier = Modifier.size(18.dp))
                                        Text("Allowed", style = MaterialTheme.typography.labelMedium, color = DoctorGColors.SafeEmerald)
                                    }
                                } else {
                                    OutlinedButton(onClick = { onRequestPermission(perm) }) {
                                        Text("Allow")
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (step == 0) {
                Button(
                    onClick = { step = 1 },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(52.dp)
                        .testTag("onboarding_accept_privacy_button")
                ) {
                    Text("Accept Privacy Policy & Continue")
                }
            } else {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedButton(
                        onClick = onFinishOnboarding,
                        modifier = Modifier
                            .weight(1f)
                            .height(50.dp)
                            .testTag("onboarding_skip_button")
                    ) {
                        Text(stringResource(R.string.action_skip_for_now))
                    }
                    Button(
                        onClick = onFinishOnboarding,
                        modifier = Modifier
                            .weight(1f)
                            .height(50.dp)
                            .testTag("onboarding_finish_button")
                    ) {
                        Text("Open DoctorG")
                    }
                }
            }
        }
    }
}
