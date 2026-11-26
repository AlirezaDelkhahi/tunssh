package dev.tunssh.android.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

object TunSshColors {
    val BgCanvas = Color(0xFF0B0F17)
    val BgSurface = Color(0xFF131A26)
    val BgElevated = Color(0xFF182232)
    val BgInset = Color(0xFF0E141F)
    val BorderSubtle = Color(0xFF1E293B)
    val BorderStrong = Color(0xFF334155)

    val TextPrimary = Color(0xFFF8FAFC)
    val TextMuted = Color(0xFF94A3B8)
    val TextSubtle = Color(0xFF64748B)

    val AccentBlue = Color(0xFF3B82F6)
    val AccentBlueHover = Color(0xFF2563EB)
    val ConnectedGreen = Color(0xFF22C55E)
    val WarningAmber = Color(0xFFF59E0B)
    val ErrorRed = Color(0xFFEF4444)
    val DisconnectedSlate = Color(0xFF64748B)
}

private val TunSshDarkColorScheme = darkColorScheme(
    primary = TunSshColors.AccentBlue,
    onPrimary = Color.White,
    primaryContainer = TunSshColors.AccentBlueHover,
    onPrimaryContainer = TunSshColors.TextPrimary,
    secondary = TunSshColors.ConnectedGreen,
    onSecondary = Color(0xFF052E16),
    secondaryContainer = TunSshColors.BgElevated,
    onSecondaryContainer = TunSshColors.TextPrimary,
    tertiary = TunSshColors.WarningAmber,
    onTertiary = Color(0xFF451A03),
    background = TunSshColors.BgCanvas,
    onBackground = TunSshColors.TextPrimary,
    surface = TunSshColors.BgSurface,
    onSurface = TunSshColors.TextPrimary,
    surfaceVariant = TunSshColors.BgElevated,
    onSurfaceVariant = TunSshColors.TextMuted,
    outline = TunSshColors.BorderStrong,
    outlineVariant = TunSshColors.BorderSubtle,
    error = TunSshColors.ErrorRed,
    onError = Color.White,
    errorContainer = Color(0xFF450A0A),
    onErrorContainer = Color(0xFFFCA5A5),
)

private val TunSshTypography = Typography(
    titleLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 20.sp,
        lineHeight = 26.sp,
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 16.sp,
        lineHeight = 22.sp,
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
    bodySmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 16.sp,
    ),
    labelMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Medium,
        fontSize = 12.sp,
        lineHeight = 16.sp,
    ),
)

@Composable
fun TunSshTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = TunSshDarkColorScheme,
        typography = TunSshTypography,
        content = content,
    )
}
