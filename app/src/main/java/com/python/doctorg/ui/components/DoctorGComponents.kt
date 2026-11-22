package com.python.doctorg.ui.components

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Dangerous
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.python.doctorg.R
import com.python.doctorg.domain.model.ThreatLevel
import com.python.doctorg.ui.theme.DoctorGColors
import com.python.doctorg.ui.theme.DoctorGTheme
import com.python.doctorg.ui.theme.JetBrainsMonoFontFamily

@Composable
fun DoctorGBrandHeader(
    subtitle: String,
    modifier: Modifier = Modifier,
    trailing: @Composable (() -> Unit)? = null
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            modifier = Modifier.weight(1f)
        ) {
            Surface(
                shape = RoundedCornerShape(14.dp),
                color = DoctorGColors.BrandNavy,
                shadowElevation = 2.dp
            ) {
                Image(
                    painter = painterResource(R.drawable.doctorg_logo),
                    contentDescription = "DoctorG Logo",
                    modifier = Modifier
                        .size(44.dp)
                        .padding(3.dp)
                )
            }
            Column {
                Text(
                    text = "DoctorG",
                    style = MaterialTheme.typography.titleLarge,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
        trailing?.invoke()
    }
}

@Composable
fun SecurityScoreGauge(
    score: Int,
    statusLabel: String,
    lightweightMode: Boolean = false,
    modifier: Modifier = Modifier
) {
    val targetFraction = (score.coerceIn(0, 100) / 100f)
    val animatedFraction by animateFloatAsState(
        targetValue = targetFraction,
        animationSpec = spring(dampingRatio = 0.8f, stiffness = 240f),
        label = "score_ring"
    )
    val sweepFraction = if (lightweightMode) targetFraction else animatedFraction

    val activeColor = when {
        score >= 80 -> DoctorGColors.SafeEmerald
        score >= 55 -> DoctorGColors.WarningAmber
        else -> DoctorGColors.DangerCrimson
    }
    val trackColor = MaterialTheme.colorScheme.surfaceVariant

    Box(
        modifier = modifier
            .size(156.dp)
            .semantics { contentDescription = "DoctorG security score $score out of 100, $statusLabel" },
        contentAlignment = Alignment.Center
    ) {
        Canvas(modifier = Modifier.size(156.dp)) {
            val stroke = 14.dp.toPx()
            val inset = stroke / 2f
            val arcSize = Size(size.width - stroke, size.height - stroke)
            val topLeft = Offset(inset, inset)
            drawArc(
                color = trackColor,
                startAngle = 140f,
                sweepAngle = 260f,
                useCenter = false,
                topLeft = topLeft,
                size = arcSize,
                style = Stroke(width = stroke, cap = StrokeCap.Round)
            )
            drawArc(
                brush = Brush.sweepGradient(listOf(DoctorGColors.BrandCyan, activeColor, activeColor)),
                startAngle = 140f,
                sweepAngle = 260f * sweepFraction,
                useCenter = false,
                topLeft = topLeft,
                size = arcSize,
                style = Stroke(width = stroke, cap = StrokeCap.Round)
            )
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                text = "$score",
                style = MaterialTheme.typography.displayMedium,
                color = activeColor,
                fontFamily = JetBrainsMonoFontFamily
            )
            Text(
                text = statusLabel,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun ThreatBadge(level: ThreatLevel, modifier: Modifier = Modifier) {
    val (bg, fg, icon, label) = when (level) {
        ThreatLevel.TRUSTED -> Quad(
            MaterialTheme.colorScheme.primaryContainer,
            MaterialTheme.colorScheme.onPrimaryContainer,
            Icons.Filled.VerifiedUser,
            "TRUSTED"
        )
        ThreatLevel.SAFE -> Quad(
            MaterialTheme.colorScheme.secondaryContainer,
            MaterialTheme.colorScheme.onSecondaryContainer,
            Icons.Filled.CheckCircle,
            "SAFE"
        )
        ThreatLevel.NEEDS_REVIEW -> Quad(
            MaterialTheme.colorScheme.surfaceVariant,
            MaterialTheme.colorScheme.onSurfaceVariant,
            Icons.Filled.Info,
            "NEEDS REVIEW"
        )
        ThreatLevel.SUSPICIOUS -> Quad(
            MaterialTheme.colorScheme.tertiaryContainer,
            MaterialTheme.colorScheme.onTertiaryContainer,
            Icons.Filled.Warning,
            "SUSPICIOUS"
        )
        ThreatLevel.MALICIOUS -> Quad(
            MaterialTheme.colorScheme.errorContainer,
            MaterialTheme.colorScheme.onErrorContainer,
            Icons.Filled.Dangerous,
            "MALICIOUS"
        )
    }
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(999.dp),
        color = bg
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Icon(icon, contentDescription = label, tint = fg, modifier = Modifier.size(14.dp))
            Text(label, style = MaterialTheme.typography.labelSmall, color = fg, fontWeight = FontWeight.Bold)
        }
    }
}

private data class Quad<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)

@Composable
fun StatusPill(
    label: String,
    active: Boolean,
    icon: ImageVector = Icons.Filled.Shield,
    modifier: Modifier = Modifier
) {
    val bg = if (active) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.surfaceVariant
    val fg = if (active) MaterialTheme.colorScheme.onSecondaryContainer else MaterialTheme.colorScheme.onSurfaceVariant
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(999.dp),
        color = bg
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(if (active) DoctorGColors.SafeEmerald else DoctorGColors.WarningAmber)
            )
            Icon(icon, contentDescription = null, tint = fg, modifier = Modifier.size(15.dp))
            Text(label, style = MaterialTheme.typography.labelMedium, color = fg, maxLines = 1)
        }
    }
}

@Composable
fun JustInTimePermissionCard(
    title: String,
    explanation: String,
    privacyNote: String,
    actionLabel: String = "Allow Permission",
    onAllow: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.55f)),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.tertiary.copy(alpha = 0.4f))
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurface)
            Text(explanation, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text("Privacy: $privacyNote", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.secondary)
            Button(onClick = onAllow) {
                Text(actionLabel)
            }
        }
    }
}

/**
 * Adaptive Two-Pane List-Detail layout:
 * - Expanded screens / Book-mode foldables: side-by-side list + detail pane (avoiding hinge overlap)
 * - Compact / Medium screens: clean single-pane flow
 */
@Composable
fun AdaptiveTwoPaneContainer(
    isTwoPane: Boolean,
    listPane: @Composable () -> Unit,
    detailPane: @Composable () -> Unit,
    modifier: Modifier = Modifier
) {
    if (isTwoPane) {
        Row(
            modifier = modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Box(modifier = Modifier.weight(1f)) { listPane() }
            Box(modifier = Modifier.weight(1f)) { detailPane() }
        }
    } else {
        Column(
            modifier = modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            listPane()
            detailPane()
        }
    }
}

@Preview(name = "Phone Compact", widthDp = 390, heightDp = 844, showBackground = true)
@Preview(name = "Phone Landscape", widthDp = 844, heightDp = 390, showBackground = true)
@Preview(name = "Foldable Book", widthDp = 673, heightDp = 841, showBackground = true)
@Preview(name = "Tablet Expanded", widthDp = 1280, heightDp = 800, showBackground = true)
@Composable
private fun DoctorGHeaderAndGaugePreview() {
    DoctorGTheme {
        Surface {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                DoctorGBrandHeader(subtitle = "Offline Security Suite")
                SecurityScoreGauge(score = 94, statusLabel = "Protected")
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    ThreatBadge(ThreatLevel.SAFE)
                    ThreatBadge(ThreatLevel.SUSPICIOUS)
                    ThreatBadge(ThreatLevel.MALICIOUS)
                }
            }
        }
    }
}
