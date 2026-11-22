package com.python.doctorg.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.python.doctorg.R

val SpaceGroteskFontFamily = FontFamily(
    Font(R.font.space_grotesk, FontWeight.Normal),
    Font(R.font.space_grotesk, FontWeight.Medium),
    Font(R.font.space_grotesk, FontWeight.SemiBold),
    Font(R.font.space_grotesk, FontWeight.Bold)
)

val PlusJakartaSansFontFamily = FontFamily(
    Font(R.font.plus_jakarta_sans, FontWeight.Normal),
    Font(R.font.plus_jakarta_sans, FontWeight.Medium),
    Font(R.font.plus_jakarta_sans, FontWeight.SemiBold),
    Font(R.font.plus_jakarta_sans, FontWeight.Bold)
)

val JetBrainsMonoFontFamily = FontFamily(
    Font(R.font.jetbrains_mono, FontWeight.Normal),
    Font(R.font.jetbrains_mono, FontWeight.Medium),
    Font(R.font.jetbrains_mono, FontWeight.Bold)
)

/**
 * Builds DoctorG's Material 3 Typography.
 * When rendering Devanagari (Hindi), Urdu (Nastaliq/Naskh), Bengali, or Tamil scripts,
 * [useSystemScriptFallback] switches display/body fonts to Android's native Noto Sans
 * system fallback (`FontFamily.Default`) and applies generous line heights so tall matras,
 * ascenders, and diacritics are never clipped.
 */
fun buildDoctorGTypography(
    largeTextBoost: Boolean = false,
    useSystemScriptFallback: Boolean = false
): Typography {
    val scale = if (largeTextBoost) 1.15f else 1.0f
    val lineScale = if (useSystemScriptFallback) 1.22f else 1.0f
    val displayFamily = if (useSystemScriptFallback) FontFamily.Default else SpaceGroteskFontFamily
    val bodyFamily = if (useSystemScriptFallback) FontFamily.Default else PlusJakartaSansFontFamily

    return Typography(
        displayLarge = TextStyle(
            fontFamily = displayFamily,
            fontWeight = FontWeight.Bold,
            fontSize = (40 * scale).sp,
            lineHeight = (48 * scale * lineScale).sp,
            letterSpacing = if (useSystemScriptFallback) 0.sp else (-0.5).sp
        ),
        displayMedium = TextStyle(
            fontFamily = displayFamily,
            fontWeight = FontWeight.Bold,
            fontSize = (32 * scale).sp,
            lineHeight = (40 * scale * lineScale).sp,
            letterSpacing = if (useSystemScriptFallback) 0.sp else (-0.25).sp
        ),
        headlineLarge = TextStyle(
            fontFamily = displayFamily,
            fontWeight = FontWeight.Bold,
            fontSize = (26 * scale).sp,
            lineHeight = (34 * scale * lineScale).sp
        ),
        headlineMedium = TextStyle(
            fontFamily = displayFamily,
            fontWeight = FontWeight.SemiBold,
            fontSize = (22 * scale).sp,
            lineHeight = (30 * scale * lineScale).sp
        ),
        headlineSmall = TextStyle(
            fontFamily = displayFamily,
            fontWeight = FontWeight.SemiBold,
            fontSize = (19 * scale).sp,
            lineHeight = (27 * scale * lineScale).sp
        ),
        titleLarge = TextStyle(
            fontFamily = displayFamily,
            fontWeight = FontWeight.SemiBold,
            fontSize = (18 * scale).sp,
            lineHeight = (26 * scale * lineScale).sp
        ),
        titleMedium = TextStyle(
            fontFamily = bodyFamily,
            fontWeight = FontWeight.SemiBold,
            fontSize = (16 * scale).sp,
            lineHeight = (24 * scale * lineScale).sp,
            letterSpacing = if (useSystemScriptFallback) 0.sp else 0.1.sp
        ),
        titleSmall = TextStyle(
            fontFamily = bodyFamily,
            fontWeight = FontWeight.SemiBold,
            fontSize = (14 * scale).sp,
            lineHeight = (21 * scale * lineScale).sp,
            letterSpacing = if (useSystemScriptFallback) 0.sp else 0.1.sp
        ),
        bodyLarge = TextStyle(
            fontFamily = bodyFamily,
            fontWeight = FontWeight.Normal,
            fontSize = (15 * scale).sp,
            lineHeight = (23 * scale * lineScale).sp
        ),
        bodyMedium = TextStyle(
            fontFamily = bodyFamily,
            fontWeight = FontWeight.Normal,
            fontSize = (14 * scale).sp,
            lineHeight = (21 * scale * lineScale).sp
        ),
        bodySmall = TextStyle(
            fontFamily = bodyFamily,
            fontWeight = FontWeight.Normal,
            fontSize = (12.5f * scale).sp,
            lineHeight = (19 * scale * lineScale).sp
        ),
        labelLarge = TextStyle(
            fontFamily = bodyFamily,
            fontWeight = FontWeight.SemiBold,
            fontSize = (14 * scale).sp,
            lineHeight = (21 * scale * lineScale).sp,
            letterSpacing = if (useSystemScriptFallback) 0.sp else 0.1.sp
        ),
        labelMedium = TextStyle(
            fontFamily = bodyFamily,
            fontWeight = FontWeight.Medium,
            fontSize = (12 * scale).sp,
            lineHeight = (18 * scale * lineScale).sp,
            letterSpacing = if (useSystemScriptFallback) 0.sp else 0.25.sp
        ),
        labelSmall = TextStyle(
            fontFamily = JetBrainsMonoFontFamily,
            fontWeight = FontWeight.Medium,
            fontSize = (11 * scale).sp,
            lineHeight = (16 * scale * lineScale).sp,
            letterSpacing = 0.2.sp
        )
    )
}
