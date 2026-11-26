package dev.tunssh.android.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Image
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import dev.tunssh.android.model.Profile
import dev.tunssh.android.model.ShareLinkMetaDTO
import dev.tunssh.android.model.ShareMode
import dev.tunssh.android.ui.FormatUtils
import dev.tunssh.android.ui.QrCodeUtils
import dev.tunssh.android.ui.theme.TunSshColors
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ShareDialog(
    profiles: List<Profile>,
    activeProfileId: String?,
    initialImportUri: String?,
    scannedUri: String? = null,
    onConsumeScannedUri: () -> Unit = {},
    onRequestScanQrCamera: () -> Unit = {},
    onRequestPickQrImage: () -> Unit = {},
    onInspect: suspend (String) -> ShareLinkMetaDTO,
    onExport: suspend (profileId: String, passphrase: String, allowPlain: Boolean) -> String,
    onImport: suspend (link: String, passphrase: String, allowPlain: Boolean) -> Profile,
    onShareViaSystemSheet: (String) -> Unit,
    onCopied: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current

    var tab by remember {
        mutableStateOf(
            if (!initialImportUri.isNullOrBlank() || profiles.isEmpty()) "import" else "export",
        )
    }

    // Export state
    var selectedProfileId by remember(activeProfileId, profiles) {
        mutableStateOf(activeProfileId ?: profiles.firstOrNull()?.id.orEmpty())
    }
    var profileDropdownOpen by remember { mutableStateOf(false) }
    var exportPassphrase by remember { mutableStateOf("") }
    var showExportPass by remember { mutableStateOf(false) }
    var allowPlainExport by remember { mutableStateOf(false) }
    var generatedLink by remember { mutableStateOf("") }
    var exportBusy by remember { mutableStateOf(false) }
    var exportError by remember { mutableStateOf<String?>(null) }

    // Import state
    var importUri by remember(initialImportUri) { mutableStateOf(initialImportUri.orEmpty()) }
    var inspectMeta by remember { mutableStateOf<ShareLinkMetaDTO?>(null) }
    var inspectError by remember { mutableStateOf<String?>(null) }
    var importPassphrase by remember { mutableStateOf("") }
    var showImportPass by remember { mutableStateOf(false) }
    var allowPlainImport by remember { mutableStateOf(false) }
    var importBusy by remember { mutableStateOf(false) }
    var importError by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(scannedUri) {
        val uri = scannedUri?.trim()
        if (!uri.isNullOrEmpty()) {
            tab = "import"
            importUri = uri
            importError = null
            onConsumeScannedUri()
        }
    }

    LaunchedEffect(importUri) {
        val trimmed = importUri.trim()
        if (trimmed.isEmpty()) {
            inspectMeta = null
            inspectError = null
            return@LaunchedEffect
        }
        runCatching { onInspect(trimmed) }
            .onSuccess { meta ->
                inspectMeta = meta
                inspectError = null
            }
            .onFailure { err ->
                inspectMeta = null
                inspectError = err.message ?: "Invalid sshtun:// link"
            }
    }

    val selectedProfile = profiles.firstOrNull { it.id == selectedProfileId } ?: profiles.firstOrNull()
    val strength = FormatUtils.evaluatePassphraseStrength(exportPassphrase)

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = TunSshColors.BgSurface,
        title = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Share Profile", color = TunSshColors.TextPrimary)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = tab == "export",
                        onClick = { tab = "export" },
                        enabled = profiles.isNotEmpty(),
                        label = { Text("Export") },
                    )
                    FilterChip(
                        selected = tab == "import",
                        onClick = { tab = "import" },
                        label = { Text("Import") },
                    )
                }
            }
        },
        text = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (tab == "export") {
                    if (profiles.isEmpty()) {
                        Text(
                            text = "Create a profile first to export an sshtun://v1/ share link.",
                            color = TunSshColors.TextMuted,
                        )
                    } else {
                        ExposedDropdownMenuBox(
                            expanded = profileDropdownOpen,
                            onExpandedChange = { profileDropdownOpen = it },
                        ) {
                            OutlinedTextField(
                                value = selectedProfile?.let { "${it.name} (${it.host}:${it.port})" }.orEmpty(),
                                onValueChange = {},
                                readOnly = true,
                                label = { Text("Profile") },
                                trailingIcon = {
                                    ExposedDropdownMenuDefaults.TrailingIcon(expanded = profileDropdownOpen)
                                },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .menuAnchor(MenuAnchorType.PrimaryNotEditable),
                            )
                            ExposedDropdownMenu(
                                expanded = profileDropdownOpen,
                                onDismissRequest = { profileDropdownOpen = false },
                            ) {
                                profiles.forEach { p ->
                                    DropdownMenuItem(
                                        text = { Text("${p.name} (${p.host}:${p.port})") },
                                        onClick = {
                                            selectedProfileId = p.id
                                            generatedLink = ""
                                            exportError = null
                                            profileDropdownOpen = false
                                        },
                                    )
                                }
                            }
                        }

                        OutlinedTextField(
                            value = exportPassphrase,
                            onValueChange = {
                                exportPassphrase = it
                                exportError = null
                            },
                            label = { Text("Encryption Passphrase") },
                            placeholder = { Text("Recommended: 12+ characters") },
                            singleLine = true,
                            visualTransformation = if (showExportPass) {
                                VisualTransformation.None
                            } else {
                                PasswordVisualTransformation()
                            },
                            trailingIcon = {
                                IconButton(onClick = { showExportPass = !showExportPass }) {
                                    Icon(
                                        imageVector = if (showExportPass) {
                                            Icons.Rounded.VisibilityOff
                                        } else {
                                            Icons.Rounded.Visibility
                                        },
                                        contentDescription = "Toggle passphrase visibility",
                                    )
                                }
                            },
                            modifier = Modifier.fillMaxWidth(),
                        )

                        if (exportPassphrase.isNotEmpty()) {
                            val strengthColor = when (strength.score) {
                                1 -> TunSshColors.ErrorRed
                                2 -> TunSshColors.WarningAmber
                                3 -> TunSshColors.AccentBlue
                                else -> TunSshColors.ConnectedGreen
                            }
                            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                LinearProgressIndicator(
                                    progress = { strength.score / 4f },
                                    color = strengthColor,
                                    trackColor = TunSshColors.BgInset,
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                Text(
                                    text = "Passphrase strength: ${strength.label}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = strengthColor,
                                )
                            }
                        }

                        if (exportPassphrase.isEmpty()) {
                            Surface(
                                color = TunSshColors.WarningAmber.copy(alpha = 0.1f),
                                shape = RoundedCornerShape(8.dp),
                                border = BorderStroke(1.dp, TunSshColors.WarningAmber.copy(alpha = 0.4f)),
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable { allowPlainExport = !allowPlainExport }
                                        .padding(8.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Checkbox(
                                        checked = allowPlainExport,
                                        onCheckedChange = { allowPlainExport = it },
                                    )
                                    Column {
                                        Text(
                                            text = "Allow unencrypted plain link (unsafe)",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = TunSshColors.WarningAmber,
                                        )
                                        Text(
                                            text = "Anyone holding the link can read your SSH credentials.",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = TunSshColors.TextMuted,
                                        )
                                    }
                                }
                            }
                        }

                        Button(
                            onClick = {
                                val targetId = selectedProfile?.id ?: return@Button
                                exportBusy = true
                                exportError = null
                                scope.launch {
                                    runCatching {
                                        onExport(targetId, exportPassphrase, allowPlainExport)
                                    }.onSuccess { link ->
                                        generatedLink = link
                                    }.onFailure { err ->
                                        exportError = err.message ?: "Failed to generate share link"
                                    }
                                    exportBusy = false
                                }
                            },
                            enabled = !exportBusy && (exportPassphrase.isNotEmpty() || allowPlainExport),
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(containerColor = TunSshColors.AccentBlue),
                        ) {
                            Text(if (exportBusy) "Generating..." else "Generate sshtun://v1/ Link")
                        }

                        if (exportError != null) {
                            Text(
                                text = exportError!!,
                                style = MaterialTheme.typography.bodySmall,
                                color = TunSshColors.ErrorRed,
                            )
                        }

                        if (generatedLink.isNotEmpty()) {
                            val qrBitmap = remember(generatedLink) {
                                QrCodeUtils.encodeQrBitmap(generatedLink)
                            }
                            Surface(
                                color = TunSshColors.BgInset,
                                shape = RoundedCornerShape(8.dp),
                                border = BorderStroke(1.dp, TunSshColors.BorderSubtle),
                            ) {
                                Column(
                                    modifier = Modifier.padding(10.dp),
                                    verticalArrangement = Arrangement.spacedBy(8.dp),
                                ) {
                                    if (qrBitmap != null) {
                                        Box(
                                            modifier = Modifier.fillMaxWidth(),
                                            contentAlignment = Alignment.Center,
                                        ) {
                                            Surface(
                                                color = Color.White,
                                                shape = RoundedCornerShape(12.dp),
                                                modifier = Modifier.size(200.dp),
                                            ) {
                                                Image(
                                                    bitmap = qrBitmap.asImageBitmap(),
                                                    contentDescription = "Profile share QR code",
                                                    modifier = Modifier
                                                        .fillMaxWidth()
                                                        .padding(10.dp),
                                                )
                                            }
                                        }
                                    } else {
                                        Text(
                                            text = "Link exceeds QR capacity (${QrCodeUtils.MAX_QR_BYTES} bytes). Use Copy or Share text instead.",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = TunSshColors.TextMuted,
                                        )
                                    }
                                    Text(
                                        text = generatedLink,
                                        style = MaterialTheme.typography.bodySmall.copy(
                                            fontFamily = FontFamily.Monospace,
                                        ),
                                        color = TunSshColors.TextPrimary,
                                        maxLines = 4,
                                    )
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        OutlinedButton(
                                            onClick = {
                                                clipboard.setText(AnnotatedString(generatedLink))
                                                onCopied("Share link copied")
                                            },
                                            modifier = Modifier.weight(1f),
                                        ) {
                                            Icon(
                                                imageVector = Icons.Rounded.ContentCopy,
                                                contentDescription = null,
                                                modifier = Modifier.size(16.dp),
                                            )
                                            Spacer(modifier = Modifier.width(6.dp))
                                            Text("Copy")
                                        }
                                        Button(
                                            onClick = { onShareViaSystemSheet(generatedLink) },
                                            modifier = Modifier.weight(1f),
                                            colors = ButtonDefaults.buttonColors(
                                                containerColor = TunSshColors.ConnectedGreen,
                                            ),
                                        ) {
                                            Icon(
                                                imageVector = Icons.Rounded.Share,
                                                contentDescription = null,
                                                tint = TunSshColors.BgCanvas,
                                                modifier = Modifier.size(16.dp),
                                            )
                                            Spacer(modifier = Modifier.width(6.dp))
                                            Text("Share", color = TunSshColors.BgCanvas)
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        OutlinedButton(
                            onClick = onRequestScanQrCamera,
                            modifier = Modifier.weight(1f),
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.QrCodeScanner,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp),
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Scan Camera QR")
                        }
                        OutlinedButton(
                            onClick = onRequestPickQrImage,
                            modifier = Modifier.weight(1f),
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.Image,
                                contentDescription = null,
                                modifier = Modifier.size(16.dp),
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("QR Image")
                        }
                    }

                    OutlinedTextField(
                        value = importUri,
                        onValueChange = {
                            importUri = it
                            importError = null
                        },
                        label = { Text("Share Link (sshtun://v1/...)") },
                        placeholder = { Text("sshtun://v1/...") },
                        minLines = 3,
                        maxLines = 5,
                        textStyle = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace,
                        ),
                        modifier = Modifier.fillMaxWidth(),
                    )

                    if (inspectError != null) {
                        Text(
                            text = inspectError!!,
                            style = MaterialTheme.typography.bodySmall,
                            color = TunSshColors.ErrorRed,
                        )
                    }

                    inspectMeta?.let { meta ->
                        val isPlain = meta.mode == ShareMode.PLAIN
                        Surface(
                            color = if (isPlain) {
                                TunSshColors.WarningAmber.copy(alpha = 0.12f)
                            } else {
                                TunSshColors.AccentBlue.copy(alpha = 0.12f)
                            },
                            shape = RoundedCornerShape(8.dp),
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(10.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                if (isPlain) {
                                    Icon(
                                        imageVector = Icons.Rounded.Warning,
                                        contentDescription = null,
                                        tint = TunSshColors.WarningAmber,
                                        modifier = Modifier.size(18.dp),
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                }
                                Text(
                                    text = buildString {
                                        append(if (isPlain) "Unencrypted plain link" else "Encrypted link (Argon2id + AES-GCM)")
                                        if (meta.hasHostKey) append(" • Includes pinned host key")
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                    color = TunSshColors.TextPrimary,
                                )
                            }
                        }

                        if (!isPlain) {
                            OutlinedTextField(
                                value = importPassphrase,
                                onValueChange = {
                                    importPassphrase = it
                                    importError = null
                                },
                                label = { Text("Decryption Passphrase") },
                                singleLine = true,
                                visualTransformation = if (showImportPass) {
                                    VisualTransformation.None
                                } else {
                                    PasswordVisualTransformation()
                                },
                                trailingIcon = {
                                    IconButton(onClick = { showImportPass = !showImportPass }) {
                                        Icon(
                                            imageVector = if (showImportPass) {
                                                Icons.Rounded.VisibilityOff
                                            } else {
                                                Icons.Rounded.Visibility
                                            },
                                            contentDescription = "Toggle passphrase visibility",
                                        )
                                    }
                                },
                                modifier = Modifier.fillMaxWidth(),
                            )
                        } else {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { allowPlainImport = !allowPlainImport },
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Checkbox(
                                    checked = allowPlainImport,
                                    onCheckedChange = { allowPlainImport = it },
                                )
                                Text(
                                    text = "I understand this link is unencrypted and want to import it.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = TunSshColors.TextMuted,
                                )
                            }
                        }
                    }

                    if (importError != null) {
                        Text(
                            text = importError!!,
                            style = MaterialTheme.typography.bodySmall,
                            color = TunSshColors.ErrorRed,
                        )
                    }

                    val canImport = inspectMeta != null && !importBusy && (
                        (inspectMeta!!.mode == ShareMode.ENCRYPTED && importPassphrase.isNotEmpty()) ||
                            (inspectMeta!!.mode == ShareMode.PLAIN && allowPlainImport)
                        )

                    Button(
                        onClick = {
                            importBusy = true
                            importError = null
                            scope.launch {
                                runCatching {
                                    onImport(importUri.trim(), importPassphrase, allowPlainImport)
                                }.onSuccess {
                                    onDismiss()
                                }.onFailure { err ->
                                    importError = err.message ?: "Failed to import link"
                                }
                                importBusy = false
                            }
                        },
                        enabled = canImport,
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = TunSshColors.AccentBlue),
                    ) {
                        Text(if (importBusy) "Importing..." else "Import Profile")
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Close", color = TunSshColors.TextMuted)
            }
        },
    )
}
