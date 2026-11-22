package com.python.doctorg.widget

import android.content.Context
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.glance.Button
import androidx.glance.GlanceId
import androidx.glance.GlanceModifier
import androidx.glance.action.actionStartActivity
import androidx.glance.appwidget.GlanceAppWidget
import androidx.glance.appwidget.GlanceAppWidgetReceiver
import androidx.glance.appwidget.provideContent
import androidx.glance.background
import androidx.glance.layout.Alignment
import androidx.glance.layout.Column
import androidx.glance.layout.Row
import androidx.glance.layout.Spacer
import androidx.glance.layout.fillMaxSize
import androidx.glance.layout.fillMaxWidth
import androidx.glance.layout.height
import androidx.glance.layout.padding
import androidx.glance.text.FontWeight
import androidx.glance.text.Text
import androidx.glance.text.TextStyle
import androidx.glance.unit.ColorProvider
import com.python.doctorg.MainActivity
import kotlinx.coroutines.flow.first

class DoctorGWidget : GlanceAppWidget() {
    override suspend fun provideGlance(context: Context, id: GlanceId) {
        val score = runCatching {
            val prefs = context.getSharedPreferences("doctorg_widget_cache", Context.MODE_PRIVATE)
            prefs.getInt("last_score", 88)
        }.getOrDefault(88)

        provideContent {
            DoctorGWidgetContent(score = score)
        }
    }
}

@Composable
private fun DoctorGWidgetContent(score: Int) {
    Column(
        modifier = GlanceModifier
            .fillMaxSize()
            .background(Color(0xFF0F143A))
            .padding(14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Row(
            modifier = GlanceModifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = GlanceModifier.defaultWeight()) {
                Text(
                    text = "DoctorG Shield",
                    style = TextStyle(
                        color = ColorProvider(Color.White),
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Bold
                    )
                )
                Text(
                    text = if (score >= 80) "Protected Offline" else "Action Needed",
                    style = TextStyle(
                        color = ColorProvider(Color(0xFF2DD4FF)),
                        fontSize = 12.sp
                    )
                )
            }
            Text(
                text = "$score%",
                style = TextStyle(
                    color = ColorProvider(if (score >= 80) Color(0xFF00C48C) else Color(0xFFFFB020)),
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold
                )
            )
        }
        Spacer(modifier = GlanceModifier.height(10.dp))
        Button(
            text = "Open DoctorG Quick Scan",
            onClick = actionStartActivity<MainActivity>(),
            modifier = GlanceModifier.fillMaxWidth()
        )
    }
}

class DoctorGWidgetReceiver : GlanceAppWidgetReceiver() {
    override val glanceAppWidget: GlanceAppWidget = DoctorGWidget()
}
