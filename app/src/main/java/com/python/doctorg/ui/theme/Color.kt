package com.python.doctorg.ui.theme

import androidx.compose.ui.graphics.Color

/**
 * Centralized color tokens for DoctorG.
 * Aesthetic: Precision Clinical Cyber-Defense (Midnight Indigo + Diagnostic Emerald + Telemetry Cyan).
 */
object DoctorGColors {
    // Core Brand Palette (aligned with doctorg_logo.png background #0F143A)
    val BrandNavy = Color(0xFF0F143A)
    val BrandNavyDeep = Color(0xFF090D24)
    val BrandNavySurface = Color(0xFF141B46)
    val BrandNavyElevated = Color(0xFF1D275E)
    val BrandCobalt = Color(0xFF2855D6)
    val BrandCyan = Color(0xFF2DD4FF)

    // Semantic Security Status Palette
    val SafeEmerald = Color(0xFF00C48C)
    val SafeEmeraldDark = Color(0xFF008F66)
    val SafeEmeraldContainerLight = Color(0xFFD7F8EC)
    val SafeEmeraldContainerDark = Color(0xFF073B2D)

    val WarningAmber = Color(0xFFFFB020)
    val WarningAmberDark = Color(0xFFB57200)
    val WarningAmberContainerLight = Color(0xFFFFF1D6)
    val WarningAmberContainerDark = Color(0xFF422C04)

    val DangerCrimson = Color(0xFFFF4757)
    val DangerCrimsonDark = Color(0xFFB81D2C)
    val DangerCrimsonContainerLight = Color(0xFFFFE0E3)
    val DangerCrimsonContainerDark = Color(0xFF4B0F18)

    // Light Theme Surfaces & Text
    val LightBackground = Color(0xFFF4F7FD)
    val LightSurface = Color(0xFFFFFFFF)
    val LightSurfaceVariant = Color(0xFFE8EEF9)
    val LightOnBackground = Color(0xFF0F143A)
    val LightOnSurface = Color(0xFF10183A)
    val LightOnSurfaceVariant = Color(0xFF485376)
    val LightOutline = Color(0xFFC7D0E4)
    val LightPrimaryContainer = Color(0xFFDDE6FF)
    val LightOnPrimaryContainer = Color(0xFF0C2260)
    val LightSecondaryContainer = Color(0xFFD6F7FF)
    val LightOnSecondaryContainer = Color(0xFF003647)

    // Dark Theme Surfaces & Text
    val DarkBackground = Color(0xFF080C1F)
    val DarkSurface = Color(0xFF101633)
    val DarkSurfaceVariant = Color(0xFF1B234A)
    val DarkOnBackground = Color(0xFFF0F4FF)
    val DarkOnSurface = Color(0xFFECF1FF)
    val DarkOnSurfaceVariant = Color(0xFFA7B3D6)
    val DarkOutline = Color(0xFF33406E)
    val DarkPrimary = Color(0xFF7CA4FF)
    val DarkOnPrimary = Color(0xFF081B4F)
    val DarkPrimaryContainer = Color(0xFF1A3482)
    val DarkOnPrimaryContainer = Color(0xFFDDE6FF)
    val DarkSecondaryContainer = Color(0xFF004E64)
    val DarkOnSecondaryContainer = Color(0xFFB6F2FF)

    // High-Contrast Accessibility Overrides
    val HighContrastLightBackground = Color(0xFFFFFFFF)
    val HighContrastLightSurface = Color(0xFFFFFFFF)
    val HighContrastLightText = Color(0xFF000000)
    val HighContrastLightPrimary = Color(0xFF00248F)

    val HighContrastDarkBackground = Color(0xFF000000)
    val HighContrastDarkSurface = Color(0xFF0A0D1C)
    val HighContrastDarkText = Color(0xFFFFFFFF)
    val HighContrastDarkPrimary = Color(0xFF66E0FF)
}
