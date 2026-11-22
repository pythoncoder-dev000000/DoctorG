package com.python.doctorg.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp

enum class ThemeMode { SYSTEM, LIGHT, DARK }

private val DoctorGLightColorScheme = lightColorScheme(
    primary = DoctorGColors.BrandCobalt,
    onPrimary = DoctorGColors.LightSurface,
    primaryContainer = DoctorGColors.LightPrimaryContainer,
    onPrimaryContainer = DoctorGColors.LightOnPrimaryContainer,
    secondary = DoctorGColors.SafeEmeraldDark,
    onSecondary = DoctorGColors.LightSurface,
    secondaryContainer = DoctorGColors.SafeEmeraldContainerLight,
    onSecondaryContainer = DoctorGColors.SafeEmeraldDark,
    tertiary = DoctorGColors.WarningAmberDark,
    onTertiary = DoctorGColors.LightSurface,
    tertiaryContainer = DoctorGColors.WarningAmberContainerLight,
    onTertiaryContainer = DoctorGColors.WarningAmberDark,
    error = DoctorGColors.DangerCrimsonDark,
    onError = DoctorGColors.LightSurface,
    errorContainer = DoctorGColors.DangerCrimsonContainerLight,
    onErrorContainer = DoctorGColors.DangerCrimsonDark,
    background = DoctorGColors.LightBackground,
    onBackground = DoctorGColors.LightOnBackground,
    surface = DoctorGColors.LightSurface,
    onSurface = DoctorGColors.LightOnSurface,
    surfaceVariant = DoctorGColors.LightSurfaceVariant,
    onSurfaceVariant = DoctorGColors.LightOnSurfaceVariant,
    outline = DoctorGColors.LightOutline
)

private val DoctorGDarkColorScheme = darkColorScheme(
    primary = DoctorGColors.DarkPrimary,
    onPrimary = DoctorGColors.DarkOnPrimary,
    primaryContainer = DoctorGColors.DarkPrimaryContainer,
    onPrimaryContainer = DoctorGColors.DarkOnPrimaryContainer,
    secondary = DoctorGColors.SafeEmerald,
    onSecondary = DoctorGColors.BrandNavyDeep,
    secondaryContainer = DoctorGColors.SafeEmeraldContainerDark,
    onSecondaryContainer = DoctorGColors.SafeEmerald,
    tertiary = DoctorGColors.WarningAmber,
    onTertiary = DoctorGColors.BrandNavyDeep,
    tertiaryContainer = DoctorGColors.WarningAmberContainerDark,
    onTertiaryContainer = DoctorGColors.WarningAmber,
    error = DoctorGColors.DangerCrimson,
    onError = DoctorGColors.BrandNavyDeep,
    errorContainer = DoctorGColors.DangerCrimsonContainerDark,
    onErrorContainer = DoctorGColors.DangerCrimson,
    background = DoctorGColors.DarkBackground,
    onBackground = DoctorGColors.DarkOnBackground,
    surface = DoctorGColors.DarkSurface,
    onSurface = DoctorGColors.DarkOnSurface,
    surfaceVariant = DoctorGColors.DarkSurfaceVariant,
    onSurfaceVariant = DoctorGColors.DarkOnSurfaceVariant,
    outline = DoctorGColors.DarkOutline
)

private val DoctorGHighContrastLight = DoctorGLightColorScheme.copy(
    primary = DoctorGColors.HighContrastLightPrimary,
    background = DoctorGColors.HighContrastLightBackground,
    surface = DoctorGColors.HighContrastLightSurface,
    onBackground = DoctorGColors.HighContrastLightText,
    onSurface = DoctorGColors.HighContrastLightText,
    outline = DoctorGColors.HighContrastLightText
)

private val DoctorGHighContrastDark = DoctorGDarkColorScheme.copy(
    primary = DoctorGColors.HighContrastDarkPrimary,
    background = DoctorGColors.HighContrastDarkBackground,
    surface = DoctorGColors.HighContrastDarkSurface,
    onBackground = DoctorGColors.HighContrastDarkText,
    onSurface = DoctorGColors.HighContrastDarkText,
    outline = DoctorGColors.HighContrastDarkText
)

val DoctorGShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(22.dp),
    extraLarge = RoundedCornerShape(28.dp)
)

@Composable
fun DoctorGTheme(
    themeMode: ThemeMode = ThemeMode.SYSTEM,
    dynamicColor: Boolean = true,
    highContrast: Boolean = false,
    largeTextMode: Boolean = false,
    languageTag: String = "",
    content: @Composable () -> Unit
) {
    val systemDark = isSystemInDarkTheme()
    val useDark = when (themeMode) {
        ThemeMode.SYSTEM -> systemDark
        ThemeMode.LIGHT -> false
        ThemeMode.DARK -> true
    }

    val colorScheme = when {
        highContrast && useDark -> DoctorGHighContrastDark
        highContrast && !useDark -> DoctorGHighContrastLight
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (useDark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        useDark -> DoctorGDarkColorScheme
        else -> DoctorGLightColorScheme
    }

    val effectiveLang = languageTag.ifBlank { java.util.Locale.getDefault().language }.lowercase()
    val useScriptFallback = effectiveLang.startsWith("hi") ||
        effectiveLang.startsWith("ur") ||
        effectiveLang.startsWith("bn") ||
        effectiveLang.startsWith("ta")

    MaterialTheme(
        colorScheme = colorScheme,
        typography = buildDoctorGTypography(
            largeTextBoost = largeTextMode,
            useSystemScriptFallback = useScriptFallback
        ),
        shapes = DoctorGShapes,
        content = content
    )
}
