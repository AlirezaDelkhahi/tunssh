package dev.tunssh.android.ui

import java.util.Locale

data class PassphraseStrength(
    val score: Int,
    val label: String,
)

object FormatUtils {

    fun formatBytes(bytes: Long): String {
        if (bytes <= 0L) return "0 B"
        val units = arrayOf("B", "KB", "MB", "GB", "TB")
        var value = bytes.toDouble()
        var idx = 0
        while (value >= 1024.0 && idx < units.lastIndex) {
            value /= 1024.0
            idx++
        }
        val formatted = when {
            idx == 0 -> String.format(Locale.US, "%.0f", value)
            value >= 100.0 -> String.format(Locale.US, "%.0f", value)
            value >= 10.0 -> String.format(Locale.US, "%.1f", value)
            else -> String.format(Locale.US, "%.2f", value)
        }
        return "$formatted ${units[idx]}"
    }

    fun formatRate(bytesPerSec: Long): String {
        if (bytesPerSec <= 0L) return "0 KB/s"
        if (bytesPerSec < 1024L) return "$bytesPerSec B/s"
        val kb = bytesPerSec / 1024.0
        if (kb < 1024.0) {
            val formatted = if (kb >= 100.0) {
                String.format(Locale.US, "%.0f", kb)
            } else {
                String.format(Locale.US, "%.1f", kb)
            }
            return "$formatted KB/s"
        }
        val mb = kb / 1024.0
        val formatted = when {
            mb >= 100.0 -> String.format(Locale.US, "%.0f", mb)
            mb >= 10.0 -> String.format(Locale.US, "%.1f", mb)
            else -> String.format(Locale.US, "%.2f", mb)
        }
        return "$formatted MB/s"
    }

    fun formatDuration(totalSeconds: Long): String {
        if (totalSeconds <= 0L) return "00:00:00"
        val hours = totalSeconds / 3600L
        val minutes = (totalSeconds % 3600L) / 60L
        val seconds = totalSeconds % 60L
        return String.format(Locale.US, "%02d:%02d:%02d", hours, minutes, seconds)
    }

    fun formatLogTime(isoTimestamp: String): String {
        if (isoTimestamp.isBlank()) return "--:--:--"
        val tIndex = isoTimestamp.indexOf('T')
        if (tIndex >= 0 && isoTimestamp.length >= tIndex + 9) {
            return isoTimestamp.substring(tIndex + 1, tIndex + 9)
        }
        return isoTimestamp.take(8)
    }

    fun evaluatePassphraseStrength(passphrase: String): PassphraseStrength {
        if (passphrase.isEmpty()) return PassphraseStrength(0, "Empty")
        var points = 0
        if (passphrase.length >= 8) points++
        if (passphrase.length >= 12) points++
        if (passphrase.any { it.isLowerCase() } && passphrase.any { it.isUpperCase() }) points++
        if (passphrase.any { it.isDigit() }) points++
        if (passphrase.any { !it.isLetterOrDigit() }) points++

        return when {
            passphrase.length < 6 || points <= 1 -> PassphraseStrength(1, "Weak")
            points == 2 -> PassphraseStrength(2, "Fair")
            points == 3 || points == 4 -> PassphraseStrength(3, "Good")
            else -> PassphraseStrength(4, "Strong")
        }
    }
}
