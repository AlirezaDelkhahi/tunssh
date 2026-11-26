package dev.tunssh.android.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.GppBad
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.tunssh.android.model.HostKeyPromptDTO
import dev.tunssh.android.ui.theme.TunSshColors

@Composable
fun HostKeyDialog(
    prompt: HostKeyPromptDTO,
    onTrustAndConnect: (HostKeyPromptDTO) -> Unit,
    onForgetAndReconnect: (HostKeyPromptDTO) -> Unit,
    onCancel: () -> Unit,
    onCopied: () -> Unit,
) {
    val clipboard = LocalClipboardManager.current

    if (prompt.mismatch) {
        AlertDialog(
            onDismissRequest = onCancel,
            containerColor = TunSshColors.BgSurface,
            icon = {
                Icon(
                    imageVector = Icons.Rounded.GppBad,
                    contentDescription = null,
                    tint = TunSshColors.ErrorRed,
                    modifier = Modifier.size(32.dp),
                )
            },
            title = {
                Text(
                    text = "Host Key Mismatch — Possible MITM",
                    color = TunSshColors.ErrorRed,
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "${prompt.host}:${prompt.port}",
                        style = MaterialTheme.typography.bodyMedium.copy(
                            fontFamily = FontFamily.Monospace,
                        ),
                        color = TunSshColors.TextPrimary,
                    )
                    Surface(
                        color = TunSshColors.ErrorRed.copy(alpha = 0.12f),
                        shape = RoundedCornerShape(8.dp),
                        border = BorderStroke(1.dp, TunSshColors.ErrorRed.copy(alpha = 0.4f)),
                    ) {
                        Text(
                            text = "The remote SSH server presented a different host key than the one pinned for this profile. Do NOT re-trust unless you intentionally rebuilt or rotated keys on your VPS.",
                            style = MaterialTheme.typography.bodySmall,
                            color = TunSshColors.TextPrimary,
                            modifier = Modifier.padding(10.dp),
                        )
                    }

                    FingerprintBox(
                        title = "Expected SHA-256 (Pinned)",
                        algorithm = prompt.expectedAlgorithm.ifBlank { "unknown" },
                        sha256 = prompt.expectedSha256.ifBlank { "Unavailable" },
                        highlightDanger = false,
                        onCopy = null,
                    )

                    FingerprintBox(
                        title = "Received SHA-256 (Remote)",
                        algorithm = prompt.algorithm,
                        sha256 = prompt.sha256,
                        highlightDanger = true,
                        onCopy = {
                            clipboard.setText(AnnotatedString(prompt.sha256))
                            onCopied()
                        },
                    )
                }
            },
            confirmButton = {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Button(
                        onClick = onCancel,
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = TunSshColors.AccentBlue),
                    ) {
                        Text("Abort Connection")
                    }
                    OutlinedButton(
                        onClick = { onForgetAndReconnect(prompt) },
                        modifier = Modifier.fillMaxWidth(),
                        border = BorderStroke(1.dp, TunSshColors.ErrorRed.copy(alpha = 0.6f)),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = TunSshColors.ErrorRed),
                    ) {
                        Text("Forget & Re-trust Host Key")
                    }
                }
            },
        )
    } else {
        AlertDialog(
            onDismissRequest = onCancel,
            containerColor = TunSshColors.BgSurface,
            icon = {
                Icon(
                    imageVector = Icons.Rounded.VerifiedUser,
                    contentDescription = null,
                    tint = TunSshColors.ConnectedGreen,
                    modifier = Modifier.size(32.dp),
                )
            },
            title = {
                Text(
                    text = "Verify Server Host Key",
                    color = TunSshColors.TextPrimary,
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "${prompt.host}:${prompt.port}",
                        style = MaterialTheme.typography.bodyMedium.copy(
                            fontFamily = FontFamily.Monospace,
                        ),
                        color = TunSshColors.AccentBlue,
                    )
                    Text(
                        text = "First time connecting to this server. Confirm the SHA-256 fingerprint matches your VPS before pinning it for future connections.",
                        style = MaterialTheme.typography.bodySmall,
                        color = TunSshColors.TextMuted,
                    )
                    FingerprintBox(
                        title = "Server Fingerprint",
                        algorithm = prompt.algorithm,
                        sha256 = prompt.sha256,
                        highlightDanger = false,
                        onCopy = {
                            clipboard.setText(AnnotatedString(prompt.sha256))
                            onCopied()
                        },
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = { onTrustAndConnect(prompt) },
                    colors = ButtonDefaults.buttonColors(containerColor = TunSshColors.ConnectedGreen),
                ) {
                    Text("Trust & Connect", color = TunSshColors.BgCanvas)
                }
            },
            dismissButton = {
                TextButton(onClick = onCancel) {
                    Text("Cancel", color = TunSshColors.TextMuted)
                }
            },
        )
    }
}

@Composable
private fun FingerprintBox(
    title: String,
    algorithm: String,
    sha256: String,
    highlightDanger: Boolean,
    onCopy: (() -> Unit)?,
) {
    val borderColor = if (highlightDanger) {
        TunSshColors.ErrorRed.copy(alpha = 0.5f)
    } else {
        TunSshColors.BorderSubtle
    }
    Surface(
        color = TunSshColors.BgInset,
        shape = RoundedCornerShape(8.dp),
        border = BorderStroke(1.dp, borderColor),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(10.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "$title ($algorithm)",
                    style = MaterialTheme.typography.labelMedium,
                    color = if (highlightDanger) TunSshColors.ErrorRed else TunSshColors.TextMuted,
                    modifier = Modifier.weight(1f),
                )
                if (onCopy != null) {
                    TextButton(onClick = onCopy) {
                        Icon(
                            imageVector = Icons.Rounded.ContentCopy,
                            contentDescription = "Copy fingerprint",
                            modifier = Modifier.size(14.dp),
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Copy")
                    }
                }
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = sha256,
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                color = TunSshColors.TextPrimary,
            )
        }
    }
}
